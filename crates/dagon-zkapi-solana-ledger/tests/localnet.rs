//! Explicit local-validator integration test of the concession-exit lifecycle.
//!
//! Start the profile-bound validator with `scripts/localnet/stack.mjs`, then run:
//! `cargo test --release -p dagon-zkapi-solana-ledger --test localnet -- --ignored --nocapture`.
//!
//! Threats exercised against the real SBF program, real Groth16 proofs and the
//! production ledger transaction builder:
//! - withheld successor: an honest escape with `c = b` is paid `B - b`, and
//!   request evidence at the escaped nullifier can neither defeat nor raise it;
//! - stale escape: evidence at `N⁺` defeats it, `N` is flagged challenged,
//!   `N⁺` is released and reusable by the newest state;
//! - under-concession: evidence at `N` raises `c` up to the request's bound;
//! - front-run deposit: a root change between preparation and submission of
//!   an escape has no effect (exits are leaf-bound and root-free);
//! - pause: exits, deposits and expired claims are blocked while paused,
//!   disputes and finalization are not, and re-pausing needs the cooldown;
//! - replay/double-spend of `N` and `N⁺`, F7 pre-funded nullifier PDAs, and
//!   permissionless retirement of a closed note's leaf;
//! - treasury griefing: exits pay only the user and accrue the operator share
//!   in the vault; anyone can later sweep it to the pinned treasury.

use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anchor_lang::{AccountDeserialize, InstructionData, ToAccountMetas};
use base64::Engine;
use dagon_zkapi_ledger::{
    ChallengeRequest, ClaimExpiredRequest, CreditLedger, DepositRequest, FinalizeEscapeRequest,
    LedgerAccount, LedgerCommitment, LedgerNullifierStatus, PreparedLedgerOperation,
    RaiseConcessionRequest, RetireClosedLeafRequest, WithdrawalRequest,
};
use dagon_zkapi_profile::{NetworkIdentity, SharedProfile, IDENTITY_SCHEMA};
use dagon_zkapi_solana_ledger::{SolanaCreditLedger, SolanaLedgerConfig};
use dagon_zkapi_vault as vault_program;
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_hash::Hash;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use vault_program::VaultError;
use zkapi_core::merkle::MerkleTree;
use zkapi_core::v2 as core;
use zkapi_indexerd::{IndexerService, SolanaAccountPoller, SolanaPollerConfig, TreeMirror};
use zkapi_proof::compact::{
    add_blindings, balance_commitment, rerandomize, CompactSigner, RequestProver,
    RequestWitnessData, WithdrawalProver, WithdrawalWitnessData,
};
use zkapi_types::wire::Groth16ProofWire;
use zkapi_types::{
    solana_destination_binding, Felt252, RequestPublicInputsV2, SchnorrSignature,
    WithdrawalPublicInputsV2, MERKLE_DEPTH, PROTOCOL_VERSION,
};

/// Lamports per note: covers the profile's request charge cap, the smallest
/// request bound the server signs, with room for the charges below.
const DEPOSIT: u128 = 25_000_000;

fn browser_exit(funding: &Value, kind: &str, mut body: Value) -> PreparedLedgerOperation {
    use std::io::Write;
    use std::process::{Command, Stdio};
    if let Some(public) = body.get_mut("public_inputs") {
        public["chain_id"] = funding["chain_id"].clone();
    }
    let mut child = Command::new("node")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../sdk/test/helpers/prepare-solana-exit.mjs"
        ))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("localnet requires Node for the production browser exit codec");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            &serde_json::to_vec(&json!({ "funding": funding, "kind": kind, "body": body }))
                .unwrap(),
        )
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "browser exit: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

struct Rpc {
    url: String,
    client: reqwest::Client,
}

impl Rpc {
    fn new(url: String) -> Self {
        Self {
            url,
            client: reqwest::Client::new(),
        }
    }

    async fn raw_call(&self, method: &str, params: Value) -> Value {
        let response: Value = self
            .client
            .post(&self.url)
            .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["id"], 1);
        response
    }

    async fn call<T: DeserializeOwned>(&self, method: &str, params: Value) -> T {
        let response = self.raw_call(method, params).await;
        assert!(response.get("error").is_none(), "RPC {method}: {response}");
        serde_json::from_value(response["result"].clone()).unwrap()
    }

    async fn latest_blockhash(&self) -> Hash {
        let result: Value = self
            .call("getLatestBlockhash", json!([{"commitment":"confirmed"}]))
            .await;
        Hash::from_str(result["value"]["blockhash"].as_str().unwrap()).unwrap()
    }

    async fn instruction_message(&self, instruction: Instruction, signer: &Keypair) -> Vec<u8> {
        Message::new_with_blockhash(
            &[
                ComputeBudgetInstruction::request_heap_frame(128 * 1_024),
                ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
                instruction,
            ],
            Some(&signer.pubkey()),
            &self.latest_blockhash().await,
        )
        .serialize()
    }

    async fn send_instruction(&self, instruction: Instruction, signer: &Keypair) -> String {
        let message = self.instruction_message(instruction, signer).await;
        self.send_message(message, signer).await
    }

    /// Submit with preflight; return the RPC error instead of panicking.
    async fn try_send_message(&self, message: Vec<u8>, signer: &Keypair) -> Result<String, Value> {
        let signature = signer.sign_message(&message);
        let mut transaction = Vec::with_capacity(1 + 64 + message.len());
        transaction.push(1);
        transaction.extend_from_slice(signature.as_ref());
        transaction.extend_from_slice(&message);
        let encoded = base64::engine::general_purpose::STANDARD.encode(transaction);
        let response = self
            .raw_call(
                "sendTransaction",
                json!([encoded, {
                    "encoding":"base64",
                    "skipPreflight":false,
                    "preflightCommitment":"confirmed"
                }]),
            )
            .await;
        if let Some(error) = response.get("error") {
            return Err(error.clone());
        }
        let signature: String = serde_json::from_value(response["result"].clone()).unwrap();
        self.wait_confirmed(&signature).await;
        Ok(signature)
    }

    async fn send_message(&self, message: Vec<u8>, signer: &Keypair) -> String {
        self.try_send_message(message, signer)
            .await
            .unwrap_or_else(|error| panic!("transaction rejected: {error}"))
    }

    /// Send every prepared transaction; return the last (vault) result.
    async fn try_send_operation(
        &self,
        operation: PreparedLedgerOperation,
        signer: &Keypair,
    ) -> Result<String, Value> {
        let count = operation.transactions.len();
        assert!(count > 0);
        let mut last = None;
        for (index, transaction) in operation.transactions.into_iter().enumerate() {
            assert_eq!(
                transaction.required_signers,
                vec![LedgerAccount::new(signer.pubkey().to_bytes())]
            );
            if index + 1 == count {
                last = Some(self.try_send_message(transaction.bytes, signer).await);
            } else {
                self.send_message(transaction.bytes, signer).await;
            }
        }
        last.unwrap()
    }

    async fn send_operation(&self, operation: PreparedLedgerOperation, signer: &Keypair) -> String {
        self.try_send_operation(operation, signer)
            .await
            .unwrap_or_else(|error| panic!("operation rejected: {error}"))
    }

    async fn account_value(&self, address: Pubkey) -> Option<Value> {
        let result: Value = self
            .call(
                "getAccountInfo",
                json!([address.to_string(), {"encoding":"base64","commitment":"confirmed"}]),
            )
            .await;
        result
            .get("value")
            .filter(|value| !value.is_null())
            .cloned()
    }

    async fn anchor_account<T: AccountDeserialize>(&self, address: Pubkey) -> T {
        let value = self
            .account_value(address)
            .await
            .unwrap_or_else(|| panic!("account {address} does not exist"));
        assert_eq!(
            value["owner"].as_str(),
            Some(vault_program::ID.to_string().as_str())
        );
        let encoded = value["data"][0].as_str().unwrap();
        let data = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap();
        T::try_deserialize(&mut data.as_slice()).unwrap()
    }

    async fn balance(&self, address: Pubkey) -> u64 {
        let result: Value = self
            .call(
                "getBalance",
                json!([address.to_string(), {"commitment":"confirmed"}]),
            )
            .await;
        result["value"].as_u64().unwrap()
    }

    async fn block_time(&self) -> u64 {
        let slot: u64 = self
            .call("getSlot", json!([{"commitment":"confirmed"}]))
            .await;
        let time: Option<i64> = self.call("getBlockTime", json!([slot])).await;
        u64::try_from(time.unwrap()).unwrap()
    }

    async fn wait_until_after(&self, deadline: u64) {
        for _ in 0..480 {
            if self.block_time().await > deadline {
                return;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        panic!("validator clock did not pass {deadline}");
    }

    async fn wait_confirmed(&self, signature: &str) {
        for _ in 0..80 {
            let status: Value = self
                .call(
                    "getSignatureStatuses",
                    json!([[signature], {"searchTransactionHistory":true}]),
                )
                .await;
            let value = &status["value"][0];
            if !value.is_null() {
                assert!(value["err"].is_null(), "transaction failed: {value}");
                if matches!(
                    value["confirmationStatus"].as_str(),
                    Some("confirmed" | "finalized")
                ) {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("transaction {signature} was not confirmed");
    }

    async fn wait_finalized(&self, signature: &str) {
        for _ in 0..320 {
            let status: Value = self
                .call(
                    "getSignatureStatuses",
                    json!([[signature], {"searchTransactionHistory":true}]),
                )
                .await;
            let value = &status["value"][0];
            if !value.is_null() {
                assert!(value["err"].is_null(), "transaction failed: {value}");
                if value["confirmationStatus"].as_str() == Some("finalized") {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        panic!("transaction {signature} was not finalized");
    }

    async fn compute_units(&self, signature: &str) -> u64 {
        let transaction: Value = self
            .call(
                "getTransaction",
                json!([signature, {"commitment":"confirmed","maxSupportedTransactionVersion":0}]),
            )
            .await;
        transaction["meta"]["computeUnitsConsumed"]
            .as_u64()
            .unwrap()
    }

    /// A plain System transfer anyone can make to any address, including a
    /// program PDA that the program has not created yet (F7).
    async fn fund_address(&self, address: Pubkey, lamports: u64, signer: &Keypair) {
        let mut data = vec![2, 0, 0, 0];
        data.extend_from_slice(&lamports.to_le_bytes());
        let transfer = Instruction {
            program_id: anchor_lang::system_program::ID,
            accounts: vec![
                AccountMeta::new(signer.pubkey(), true),
                AccountMeta::new(address, false),
            ],
            data,
        };
        self.send_instruction(transfer, signer).await;
    }

    async fn airdrop(&self, address: Pubkey, lamports: u64) {
        let signature: String = self
            .call("requestAirdrop", json!([address.to_string(), lamports]))
            .await;
        self.wait_confirmed(&signature).await;
    }
}

/// The vault custom error a failed preflight reported.
fn custom_error(error: &Value) -> Option<u32> {
    error["data"]["err"]["InstructionError"][1]["Custom"]
        .as_u64()
        .and_then(|code| u32::try_from(code).ok())
}

fn assert_vault_error(result: Result<String, Value>, expected: VaultError, context: &str) {
    let error = result.expect_err(context);
    let expected_code: u32 = expected.into();
    assert_eq!(
        custom_error(&error),
        Some(expected_code),
        "{context}: expected {expected_code}, got {error}"
    );
}

#[derive(Clone)]
struct PrivateNoteState {
    note_id: u32,
    secret: Felt252,
    expiry: u64,
    balance: u128,
    blinding: Felt252,
    anchor: Felt252,
    prev_anchor: Felt252,
    signature: Option<SchnorrSignature>,
}

struct Wallet<'a> {
    ledger: &'a SolanaCreditLedger,
    state_signer: &'a CompactSigner,
    clearance_signer: &'a CompactSigner,
    request_prover: &'a RequestProver,
    withdrawal_prover: &'a WithdrawalProver,
}

impl PrivateNoteState {
    fn genesis(note_id: u32, secret: Felt252, expiry: u64) -> Self {
        Self {
            note_id,
            secret,
            expiry,
            balance: DEPOSIT,
            blinding: Felt252::from_u64(7),
            anchor: core::GENESIS_ANCHOR,
            prev_anchor: Felt252::ZERO,
            signature: None,
        }
    }

    fn leaf(&self) -> Felt252 {
        core::note_leaf(
            self.note_id,
            &core::registration_commitment(&self.secret),
            DEPOSIT,
            self.expiry,
        )
    }

    fn nullifier(&self) -> Felt252 {
        core::nullifier(&self.secret, self.note_id, &self.anchor)
    }

    fn successor_nullifier(&self) -> Felt252 {
        core::successor_nullifier(&self.secret, self.note_id, &self.nullifier())
    }
}

impl Wallet<'_> {
    /// The operator-signed successor of a served request at `previous`,
    /// at the derived anchor `next_anchor(N)`.
    fn advance(&self, previous: &PrivateNoteState, charge: u128) -> PrivateNoteState {
        let deployment = self.ledger.deployment();
        let mut next = previous.clone();
        next.prev_anchor = previous.anchor;
        next.anchor = core::next_anchor(&previous.nullifier());
        next.balance -= charge;
        next.blinding = add_blindings(&previous.blinding, &Felt252::from_u64(9));
        let commitment = balance_commitment(next.balance, &next.blinding, &next.leaf());
        next.signature = Some(self.state_signer.sign(&core::state_message(
            PROTOCOL_VERSION,
            deployment.chain_id,
            &deployment.protocol_binding,
            &commitment.x,
            &commitment.y,
            &next.anchor,
        )));
        next
    }

    /// A request proof at `note`; the vault never checks its root, so a
    /// single-leaf tree stands in for the server's recent-roots window.
    fn request(
        &self,
        note: &PrivateNoteState,
        solvency_bound: u128,
    ) -> (RequestPublicInputsV2, Groth16ProofWire) {
        let deployment = self.ledger.deployment();
        let state_key = self.state_signer.public_key();
        let context = Felt252::from_u64(9001);
        let rerandomization = Felt252::from_u64(9);
        let nullifier = note.nullifier();
        let leaf = note.leaf();
        let mut tree = MerkleTree::new();
        tree.set_leaf(note.note_id, leaf);
        let siblings: [Felt252; MERKLE_DEPTH] = tree.get_siblings(note.note_id);
        let anonymous = rerandomize(
            &balance_commitment(note.balance, &note.blinding, &leaf),
            &rerandomization,
        )
        .unwrap();
        let public = RequestPublicInputsV2 {
            protocol_version: PROTOCOL_VERSION,
            chain_id: deployment.chain_id,
            contract_address: deployment.protocol_binding,
            active_root: tree.root(),
            state_signing_key_x: state_key.x,
            state_signing_key_y: state_key.y,
            request_time: note.expiry,
            solvency_bound,
            request_nullifier: nullifier,
            authorization_tag: core::authorization_tag(&nullifier, &context),
            anonymous_commitment_x: anonymous.x,
            anonymous_commitment_y: anonymous.y,
        };
        let proof = self
            .request_prover
            .prove(
                &public,
                RequestWitnessData {
                    secret: note.secret,
                    request_context: context,
                    note_id: note.note_id,
                    deposit_amount: DEPOSIT,
                    expiry: note.expiry,
                    merkle_siblings: siblings,
                    current_balance: note.balance,
                    current_blinding: note.blinding,
                    rerandomization,
                    current_anchor: note.anchor,
                    prev_anchor: note.prev_anchor,
                    state_signature: note.signature,
                },
            )
            .unwrap();
        (public, proof)
    }

    fn withdrawal(
        &self,
        note: &PrivateNoteState,
        destination: Pubkey,
        conceded: u128,
        has_clearance: bool,
        valid_until: u64,
    ) -> (WithdrawalPublicInputsV2, Groth16ProofWire) {
        let deployment = self.ledger.deployment();
        let state_key = self.state_signer.public_key();
        let clearance_key = self.clearance_signer.public_key();
        let nullifier = note.nullifier();
        let public = WithdrawalPublicInputsV2 {
            protocol_version: PROTOCOL_VERSION,
            chain_id: deployment.chain_id,
            contract_address: deployment.protocol_binding,
            registration: core::registration_commitment(&note.secret),
            state_signing_key_x: state_key.x,
            state_signing_key_y: state_key.y,
            clearance_signing_key_x: clearance_key.x,
            clearance_signing_key_y: clearance_key.y,
            note_id: note.note_id,
            deposit_amount: DEPOSIT,
            expiry_ts: note.expiry,
            final_balance: note.balance - conceded,
            destination: solana_destination_binding(&destination.to_bytes()),
            withdrawal_nullifier: nullifier,
            has_clearance,
            next_nullifier: if has_clearance {
                Felt252::ZERO
            } else {
                note.successor_nullifier()
            },
            conceded,
            valid_until,
        };
        let proof = self
            .withdrawal_prover
            .prove(
                &public,
                WithdrawalWitnessData {
                    secret: note.secret,
                    current_balance: note.balance,
                    final_blinding: note.blinding,
                    current_anchor: note.anchor,
                    prev_anchor: note.prev_anchor,
                    state_signature: note.signature,
                    clearance_signature: has_clearance.then(|| {
                        self.clearance_signer.sign(&core::clearance_message(
                            PROTOCOL_VERSION,
                            deployment.chain_id,
                            &deployment.protocol_binding,
                            &nullifier,
                        ))
                    }),
                },
            )
            .unwrap();
        (public, proof)
    }
}

fn request_inputs(value: &RequestPublicInputsV2) -> vault_program::RequestInputs {
    vault_program::RequestInputs {
        protocol_version: value.protocol_version,
        chain_id: value.chain_id,
        contract_address: *value.contract_address.as_bytes(),
        active_root: *value.active_root.as_bytes(),
        state_signing_key_x: *value.state_signing_key_x.as_bytes(),
        state_signing_key_y: *value.state_signing_key_y.as_bytes(),
        request_time: value.request_time,
        solvency_bound: value.solvency_bound,
        request_nullifier: *value.request_nullifier.as_bytes(),
        authorization_tag: *value.authorization_tag.as_bytes(),
        anonymous_commitment_x: *value.anonymous_commitment_x.as_bytes(),
        anonymous_commitment_y: *value.anonymous_commitment_y.as_bytes(),
    }
}

fn proof_bytes(proof: &Groth16ProofWire) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(&proof.proof)
        .unwrap()
}

fn nullifier_address(vault: Pubkey, nullifier: Felt252) -> Pubkey {
    Pubkey::find_program_address(
        &[b"nullifier", vault.as_ref(), nullifier.as_bytes()],
        &vault_program::ID,
    )
    .0
}

fn note_address(vault: Pubkey, note_id: u32) -> Pubkey {
    Pubkey::find_program_address(
        &[b"note", vault.as_ref(), &note_id.to_le_bytes()],
        &vault_program::ID,
    )
    .0
}

fn pending_address(vault: Pubkey, note_id: u32) -> Pubkey {
    Pubkey::find_program_address(
        &[b"pending", vault.as_ref(), &note_id.to_le_bytes()],
        &vault_program::ID,
    )
    .0
}

async fn wait_indexed(
    poller: &SolanaAccountPoller,
    service: &IndexerService,
    next_note_id: u32,
    root: Felt252,
    leaves: &[Felt252],
) {
    let mut last_error = None;
    for _ in 0..120 {
        if let Err(error) = poller.poll_once(service).await {
            last_error = Some(error.to_string());
        }
        let snapshot = service.get_snapshot();
        if service.is_ready()
            && snapshot.next_note_id == next_note_id
            && snapshot.root == root
            && snapshot.leaves == leaves
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!(
        "indexer did not reach expected finalized state; last error: {last_error:?}; snapshot: {:?}",
        service.get_snapshot()
    );
}

#[tokio::test]
#[ignore = "requires an explicit local Solana validator with the vault program loaded"]
async fn concession_exit_lifecycle_on_localnet() {
    let rpc_url =
        std::env::var("DAGON_SOLANA_RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:8899".into());
    let rpc = Rpc::new(rpc_url.clone());
    let authority = Keypair::new();
    let treasury = Keypair::new().pubkey();
    let destination = Keypair::new().pubkey();
    let payer = LedgerAccount::new(authority.pubkey().to_bytes());
    let destination_account = LedgerAccount::new(destination.to_bytes());
    let state_signer = CompactSigner::from_seed(&Felt252::from_u64(101));
    let clearance_signer = CompactSigner::from_seed(&Felt252::from_u64(102));
    let setup = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../protocol/setup/v2");
    let request_prover = RequestProver::load(&setup).unwrap();
    let withdrawal_prover = WithdrawalProver::load(&setup).unwrap();
    let mut compute_units = Vec::new();

    rpc.airdrop(authority.pubkey(), 20_000_000_000).await;
    rpc.airdrop(destination, 1_000_000_000).await;

    let genesis: String = rpc.call("getGenesisHash", json!([])).await;
    let genesis_hash = Hash::from_str(&genesis).unwrap().to_bytes();
    let (vault, _) =
        Pubkey::find_program_address(&[b"vault", authority.pubkey().as_ref()], &vault_program::ID);
    // This is the sole test-only override reader. No binary reads this file:
    // server startup requires the shared profile's challenge period, and its
    // settlement/challenger timing inequality independently rejects 40 seconds.
    let mut profile = SharedProfile::embedded().clone();
    let overrides: Value = serde_json::from_str(include_str!(
        "../../../solana/profile/localnet-test-overrides.json"
    ))
    .unwrap();
    profile.vault.challenge_period_seconds =
        overrides["challenge_period_seconds"].as_u64().unwrap();
    let identity = NetworkIdentity {
        schema: IDENTITY_SCHEMA.into(),
        network: "localnet".into(),
        genesis_hash: genesis.clone(),
        vault_authority: Some(authority.pubkey().to_string()),
        vault_state: Some(vault.to_string()),
        treasury: Some(treasury.to_string()),
        pyth_price_account: NetworkIdentity::mainnet().pyth_price_account,
    };
    let resolved = identity.resolve(&profile).unwrap();
    let initialize = dagon_zkapi_deploy::initialize_instruction(
        &profile,
        &identity,
        &state_signer,
        &clearance_signer,
    )
    .unwrap();
    rpc.send_instruction(initialize, &authority).await;
    let set_paused = |paused: bool| Instruction {
        program_id: vault_program::ID,
        accounts: vault_program::accounts::SetPaused {
            vault,
            authority: authority.pubkey(),
        }
        .to_account_metas(None),
        data: vault_program::instruction::SetPaused { paused }.data(),
    };

    let ledger = SolanaCreditLedger::new(SolanaLedgerConfig {
        rpc_url: rpc_url.clone(),
        indexer_url: None,
        network: "localnet".into(),
        program_id: vault_program::ID.to_bytes(),
        vault_state: vault.to_bytes(),
        genesis_hash,
    })
    .unwrap();
    let browser_funding = json!({
        "billing_asset": "native_sol", "ledger_backend": "dagon.solana.groth16.v1",
        "billing_unit": "lamports", "base_units_per_asset": "1000000000",
        "chain_id": ledger.deployment().chain_id.to_string(),
        "contract_address": format!("0x{:0>64}", ledger.deployment().protocol_binding.to_hex().trim_start_matches("0x")),
        "program_id": vault_program::ID.to_string(), "vault_state": vault.to_string(),
        "genesis_hash": genesis, "network": "localnet", "wallet_standard_chain": "solana:localnet",
        "rpc_url": rpc_url, "protocol_server_url": "http://127.0.0.1:1",
        "pyth_receiver_program": profile.pyth.receiver_program,
        "pyth_price_account": identity.pyth_price_account,
        "pyth_feed_id": profile.pyth.feed_id,
        "pyth_max_age_seconds": profile.pyth.max_age_seconds,
        "pyth_max_confidence_bps": profile.pyth.max_confidence_bps
    });
    let wallet = Wallet {
        ledger: &ledger,
        state_signer: &state_signer,
        clearance_signer: &clearance_signer,
        request_prover: &request_prover,
        withdrawal_prover: &withdrawal_prover,
    };
    let service = IndexerService::new_syncing(Arc::new(RwLock::new(TreeMirror::new())));
    let poller = SolanaAccountPoller::new(SolanaPollerConfig::from_identity(
        rpc_url, &profile, &resolved,
    ))
    .unwrap();
    let mut tree = MerkleTree::new();
    let deposit = |note_id: u32, secret: Felt252, zero_path: [Felt252; MERKLE_DEPTH]| {
        let ledger = &ledger;
        async move {
            ledger
                .prepare_deposit(DepositRequest {
                    payer,
                    expected_note_id: note_id,
                    commitment: core::registration_commitment(&secret),
                    amount: DEPOSIT,
                    zero_path,
                })
                .await
                .unwrap()
        }
    };

    // ---- Note A: mutual close keeps the leaf; permissionless retirement.
    let secret_a = Felt252::from_u64(42);
    let operation = deposit(0, secret_a, tree.get_siblings(0)).await;
    assert!(operation.transactions.len() >= 3, "deposits stay staged");
    let signature = rpc.send_operation(operation, &authority).await;
    compute_units.push(("deposit execute", rpc.compute_units(&signature).await));
    rpc.wait_finalized(&signature).await;
    let note_a: vault_program::NoteState = rpc.anchor_account(note_address(vault, 0)).await;
    let a0 = PrivateNoteState::genesis(0, secret_a, note_a.expiry);
    tree.set_leaf(0, a0.leaf());
    assert_eq!(
        ledger
            .state(LedgerCommitment::Confirmed)
            .await
            .unwrap()
            .root,
        tree.root()
    );
    let valid_until = rpc.block_time().await + 3_600;

    let a1 = wallet.advance(&a0, 40_000);
    let (close_public, close_proof) = wallet.withdrawal(&a1, destination, 0, true, valid_until);
    let close_nullifier = close_public.withdrawal_nullifier;
    let close_request = WithdrawalRequest {
        payer,
        destination: destination_account,
        public_inputs: close_public,
        proof: close_proof,
    };
    let (destination_before, treasury_before) =
        (rpc.balance(destination).await, rpc.balance(treasury).await);
    let accrued = |vault_state: vault_program::VaultState| vault_state.treasury_accrued;
    let operation = browser_exit(
        &browser_funding,
        "mutual",
        json!({
            "payer": authority.pubkey().to_string(), "destination": destination.to_string(),
            "public_inputs": close_request.public_inputs, "proof": close_request.proof
        }),
    );
    assert_eq!(
        operation.transactions.len(),
        1,
        "close is one direct transaction"
    );
    let signature = rpc.send_operation(operation, &authority).await;
    compute_units.push(("close", rpc.compute_units(&signature).await));
    assert_eq!(
        u128::from(rpc.balance(destination).await - destination_before),
        DEPOSIT - 40_000
    );
    // The operator share accrues in the vault; exits never touch the treasury.
    assert_eq!(rpc.balance(treasury).await, treasury_before);
    assert_eq!(accrued(rpc.anchor_account(vault).await), 40_000);
    let sweeper = Keypair::new();
    rpc.airdrop(sweeper.pubkey(), 100_000_000).await;
    let sweep = || async {
        ledger
            .prepare_withdraw_treasury(LedgerAccount::new(sweeper.pubkey().to_bytes()))
            .await
            .unwrap()
    };
    // Sweeping a share below the rent-exempt minimum into the unfunded
    // treasury fails (rent) without losing the debt.
    assert!(rpc
        .try_send_operation(sweep().await, &sweeper)
        .await
        .is_err());
    assert_eq!(accrued(rpc.anchor_account(vault).await), 40_000);
    let closed: vault_program::NoteState = rpc.anchor_account(note_address(vault, 0)).await;
    assert_eq!(closed.status, vault_program::NOTE_STATUS_CLOSED);
    assert_eq!(
        ledger
            .state(LedgerCommitment::Confirmed)
            .await
            .unwrap()
            .root,
        tree.root(),
        "a closed note keeps its leaf until retired"
    );
    assert_eq!(
        ledger
            .nullifier_status(close_nullifier, LedgerCommitment::Confirmed)
            .await
            .unwrap(),
        LedgerNullifierStatus::Used
    );
    // Replaying the close cannot pay twice.
    assert!(ledger.prepare_close(close_request).await.is_err());

    let live = ledger.path(0, false, LedgerCommitment::Tip).await.unwrap();
    assert_eq!(live.leaf, a0.leaf());
    let operation = ledger
        .prepare_retire_closed_leaf(RetireClosedLeafRequest {
            payer,
            note_id: 0,
            siblings: live.siblings,
        })
        .await
        .unwrap();
    assert_eq!(operation.transactions.len(), 1);
    let signature = rpc.send_operation(operation, &authority).await;
    compute_units.push(("retire_closed_leaf", rpc.compute_units(&signature).await));
    rpc.wait_finalized(&signature).await;
    tree.set_leaf(0, Felt252::ZERO);
    assert_eq!(
        ledger
            .state(LedgerCommitment::Confirmed)
            .await
            .unwrap()
            .root,
        tree.root()
    );
    let retired: vault_program::NoteState = rpc.anchor_account(note_address(vault, 0)).await;
    assert_eq!(retired.status, vault_program::NOTE_STATUS_RETIRED);
    assert!(ledger
        .prepare_retire_closed_leaf(RetireClosedLeafRequest {
            payer,
            note_id: 0,
            siblings: live.siblings,
        })
        .await
        .is_err());
    wait_indexed(&poller, &service, 1, tree.root(), &[Felt252::ZERO]).await;
    eprintln!("note A: close paid B, leaf retired permissionlessly");

    // ---- Note B: withheld successor. The user released request R1 at S1
    // with bound b, the operator withheld S2, and the user escapes from S1
    // conceding exactly c = b.
    let secret_b = Felt252::from_u64(43);
    let signature = rpc
        .send_operation(deposit(1, secret_b, tree.get_siblings(1)).await, &authority)
        .await;
    rpc.wait_finalized(&signature).await;
    let note_b: vault_program::NoteState = rpc.anchor_account(note_address(vault, 1)).await;
    let b0 = PrivateNoteState::genesis(1, secret_b, note_b.expiry);
    tree.set_leaf(1, b0.leaf());
    let b1 = wallet.advance(&b0, 40_000);
    // The server signs no request bound below the profile's request charge cap.
    let bound_b = u128::from(profile.vault.request_charge_cap);
    let (b_request, b_request_proof) = wallet.request(&b1, bound_b);
    let (b_escape, b_escape_proof) =
        wallet.withdrawal(&b1, destination, bound_b, false, valid_until);
    let (b_n, b_next) = (b_escape.withdrawal_nullifier, b_escape.next_nullifier);
    assert_eq!(b_request.request_nullifier, b_n);
    assert_eq!(b_next, b1.successor_nullifier());
    // A destination finalize could never credit would lock the operator share
    // with the note Pending forever: a reserved key the runtime demotes to
    // read-only, or the vault itself. Both are refused at escape time.
    for (uncreditable, label) in [
        (
            anchor_lang::system_program::ID,
            "escape to the read-only System program",
        ),
        (vault, "escape to the vault"),
    ] {
        let (public_inputs, proof) =
            wallet.withdrawal(&b1, uncreditable, bound_b, false, valid_until);
        assert_vault_error(
            rpc.try_send_operation(
                ledger
                    .prepare_escape(WithdrawalRequest {
                        payer,
                        destination: LedgerAccount::new(uncreditable.to_bytes()),
                        public_inputs,
                        proof,
                    })
                    .await
                    .unwrap(),
                &authority,
            )
            .await,
            VaultError::DestinationNotCreditable,
            label,
        );
    }

    // F7: anyone can pre-fund both nullifier PDAs; the escape still lands.
    let rent_floor: u64 = rpc
        .call("getMinimumBalanceForRentExemption", json!([0]))
        .await;
    for nullifier in [b_n, b_next] {
        rpc.fund_address(nullifier_address(vault, nullifier), rent_floor, &authority)
            .await;
        assert_eq!(
            ledger
                .nullifier_status(nullifier, LedgerCommitment::Confirmed)
                .await
                .unwrap(),
            LedgerNullifierStatus::Unused,
            "a funded System PDA is not a spent nullifier"
        );
    }
    let escape_b = browser_exit(
        &browser_funding,
        "escape",
        json!({
            "payer": authority.pubkey().to_string(), "destination": destination.to_string(),
            "public_inputs": b_escape, "proof": b_escape_proof
        }),
    );
    assert_eq!(
        escape_b.transactions.len(),
        1,
        "escape is one direct transaction"
    );

    // FRONT-RUN: an unrelated deposit (note C) changes the root after the
    // escape was prepared and signed. Leaf-bound exits do not care.
    let secret_c = Felt252::from_u64(44);
    let signature = rpc
        .send_operation(deposit(2, secret_c, tree.get_siblings(2)).await, &authority)
        .await;
    rpc.wait_finalized(&signature).await;
    let note_c: vault_program::NoteState = rpc.anchor_account(note_address(vault, 2)).await;
    let c0 = PrivateNoteState::genesis(2, secret_c, note_c.expiry);
    tree.set_leaf(2, c0.leaf());
    assert_eq!(
        ledger
            .state(LedgerCommitment::Confirmed)
            .await
            .unwrap()
            .root,
        tree.root()
    );
    let signature = rpc.send_operation(escape_b, &authority).await;
    compute_units.push((
        "escape (pre-funded N and N+)",
        rpc.compute_units(&signature).await,
    ));
    eprintln!("note B escape landed after a front-running deposit");
    assert_eq!(
        ledger
            .state(LedgerCommitment::Confirmed)
            .await
            .unwrap()
            .root,
        tree.root(),
        "an escape does not touch the tree"
    );
    for nullifier in [b_n, b_next] {
        assert_eq!(
            ledger
                .nullifier_status(nullifier, LedgerCommitment::Confirmed)
                .await
                .unwrap(),
            LedgerNullifierStatus::Used
        );
    }
    let pending = ledger
        .pending_escapes(LedgerCommitment::Confirmed)
        .await
        .unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(
        (
            pending[0].note_id,
            pending[0].nullifier,
            pending[0].next_nullifier
        ),
        (1, b_n, b_next)
    );
    assert_eq!(
        (pending[0].state_balance, pending[0].conceded),
        (b1.balance, bound_b)
    );
    let b_deadline = pending[0].deadline;
    // Replaying the escape proof cannot open a second exit.
    let replay = ledger
        .prepare_escape(WithdrawalRequest {
            payer,
            destination: destination_account,
            public_inputs: b_escape,
            proof: b_escape_proof,
        })
        .await;
    assert!(
        replay.is_err(),
        "pending note must reject a replayed escape"
    );

    // The operator holds R1 (at N), but that proves nothing about S2: it can
    // neither defeat the escape nor raise c beyond the bound already conceded.
    assert!(matches!(
        ledger
            .prepare_challenge(ChallengeRequest {
                payer,
                note_id: 1,
                public_inputs: b_request.clone(),
                proof: b_request_proof.clone(),
            })
            .await,
        Err(dagon_zkapi_ledger::LedgerError::Rejected(_))
    ));
    assert!(matches!(
        ledger
            .prepare_raise_concession(RaiseConcessionRequest {
                payer,
                note_id: 1,
                public_inputs: b_request.clone(),
                proof: b_request_proof.clone(),
                amount: DEPOSIT,
            })
            .await,
        Err(dagon_zkapi_ledger::LedgerError::Rejected(_))
    ));
    // The program enforces the same rule against a raw transaction.
    let evidence = |public: &RequestPublicInputsV2, proof: &Groth16ProofWire| {
        vault_program::ChallengePayload {
            note_id: 1,
            public_inputs: request_inputs(public),
            proof: proof_bytes(proof),
        }
    };
    let raw_defeat = Instruction {
        program_id: vault_program::ID,
        accounts: vault_program::accounts::ExecuteChallenge {
            vault,
            note: note_address(vault, 1),
            pending: pending_address(vault, 1),
            used_nullifier: nullifier_address(vault, b_n),
            next_nullifier: nullifier_address(vault, b_next),
            payer: authority.pubkey(),
        }
        .to_account_metas(None),
        data: vault_program::instruction::ExecuteChallenge {
            note_id: 1,
            payload: evidence(&b_request, &b_request_proof),
        }
        .data(),
    };
    let message = rpc.instruction_message(raw_defeat, &authority).await;
    assert_vault_error(
        rpc.try_send_message(message, &authority).await,
        VaultError::NotSuccessorNullifier,
        "withheld: evidence at N cannot defeat",
    );
    let raw_raise = Instruction {
        program_id: vault_program::ID,
        accounts: vault_program::accounts::RaiseEscapeConcession {
            vault,
            note: note_address(vault, 1),
            pending: pending_address(vault, 1),
            payer: authority.pubkey(),
        }
        .to_account_metas(None),
        data: vault_program::instruction::RaiseEscapeConcession {
            note_id: 1,
            payload: evidence(&b_request, &b_request_proof),
            amount: DEPOSIT,
        }
        .data(),
    };
    let message = rpc.instruction_message(raw_raise, &authority).await;
    assert_vault_error(
        rpc.try_send_message(message, &authority).await,
        VaultError::ConcessionNotRaised,
        "withheld: a raise is capped by the bound already conceded",
    );

    // ---- Note C: a cheater spent S1 (R1 at N1) and S2 (R2 at N2), then
    // escapes stale from S1 with c = 0.
    let c1 = wallet.advance(&c0, 20_000);
    let c2 = wallet.advance(&c1, 20_000);
    let (c_r1, c_r1_proof) = wallet.request(&c1, 20_000);
    let (c_r2, c_r2_proof) = wallet.request(&c2, 20_000);
    let (c_stale, c_stale_proof) = wallet.withdrawal(&c1, destination, 0, false, valid_until);
    let (c_older, c_older_proof) = wallet.withdrawal(&c0, destination, 0, false, valid_until);
    let (c_newest, c_newest_proof) = wallet.withdrawal(&c2, destination, 0, false, valid_until);
    let (c_n1, c_n2) = (c_stale.withdrawal_nullifier, c_stale.next_nullifier);
    assert_eq!(
        (c_r1.request_nullifier, c_r2.request_nullifier),
        (c_n1, c_n2)
    );
    assert_eq!(c_older.next_nullifier, c_n1);
    assert_eq!(c_newest.withdrawal_nullifier, c_n2);
    let c_escape =
        |public: &WithdrawalPublicInputsV2, proof: &Groth16ProofWire| WithdrawalRequest {
            payer,
            destination: destination_account,
            public_inputs: public.clone(),
            proof: proof.clone(),
        };
    let signature = rpc
        .send_operation(
            ledger
                .prepare_escape(c_escape(&c_stale, &c_stale_proof))
                .await
                .unwrap(),
            &authority,
        )
        .await;
    rpc.wait_confirmed(&signature).await;
    eprintln!("note C stale escape landed");

    // ---- PAUSE: disputes and finalization stay open; exits, deposits and
    // expired claims are blocked.
    let signature = rpc.send_instruction(set_paused(true), &authority).await;
    compute_units.push(("set_paused(true)", rpc.compute_units(&signature).await));

    // Under-concession: R1 (at the escaped N1, bound 20k) raises c to 15k.
    let operation = ledger
        .prepare_raise_concession(RaiseConcessionRequest {
            payer,
            note_id: 2,
            public_inputs: c_r1.clone(),
            proof: c_r1_proof.clone(),
            amount: 15_000,
        })
        .await
        .unwrap();
    assert_eq!(operation.transactions.len(), 1);
    let signature = rpc.send_operation(operation, &authority).await;
    compute_units.push(("raise (while paused)", rpc.compute_units(&signature).await));
    let raised: vault_program::PendingWithdrawal =
        rpc.anchor_account(pending_address(vault, 2)).await;
    assert_eq!(
        (raised.conceded, raised.final_balance, raised.state_balance),
        (15_000, (DEPOSIT - 35_000) as u64, (DEPOSIT - 20_000) as u64)
    );

    // Stale escape: R2 spends the successor N2 and defeats the exit.
    let operation = ledger
        .prepare_challenge(ChallengeRequest {
            payer,
            note_id: 2,
            public_inputs: c_r2,
            proof: c_r2_proof,
        })
        .await
        .unwrap();
    assert_eq!(operation.transactions.len(), 1);
    let challenger_before = rpc.balance(authority.pubkey()).await;
    let signature = rpc.send_operation(operation, &authority).await;
    compute_units.push(("defeat (while paused)", rpc.compute_units(&signature).await));
    assert!(
        rpc.balance(authority.pubkey()).await > challenger_before,
        "the closed pending account's rent pays the challenger's fee"
    );
    let defeated: vault_program::NoteState = rpc.anchor_account(note_address(vault, 2)).await;
    assert_eq!(defeated.status, vault_program::NOTE_STATUS_ACTIVE);
    assert!(defeated.claimable_after >= defeated.expiry);
    assert!(rpc.account_value(pending_address(vault, 2)).await.is_none());
    assert_eq!(
        ledger
            .nullifier_status(c_n1, LedgerCommitment::Confirmed)
            .await
            .unwrap(),
        LedgerNullifierStatus::Used,
        "the defeated nullifier is challenged forever"
    );
    assert_eq!(
        ledger
            .nullifier_status(c_n2, LedgerCommitment::Confirmed)
            .await
            .unwrap(),
        LedgerNullifierStatus::Unused,
        "the successor nullifier is released"
    );
    let n1_account: vault_program::UsedNullifier =
        rpc.anchor_account(nullifier_address(vault, c_n1)).await;
    let n2_account: vault_program::UsedNullifier =
        rpc.anchor_account(nullifier_address(vault, c_n2)).await;
    assert_eq!(
        (n1_account.status, n2_account.status),
        (
            vault_program::NULLIFIER_CHALLENGED,
            vault_program::NULLIFIER_RELEASED
        )
    );
    assert_eq!(
        ledger
            .state(LedgerCommitment::Confirmed)
            .await
            .unwrap()
            .root,
        tree.root(),
        "disputes never touch the tree"
    );

    // Blocked while paused: the newest-state escape, a deposit, and an
    // expired-claim sweep (Paused is checked before expiry).
    assert_vault_error(
        rpc.try_send_operation(
            ledger
                .prepare_escape(c_escape(&c_newest, &c_newest_proof))
                .await
                .unwrap(),
            &authority,
        )
        .await,
        VaultError::Paused,
        "escape while paused",
    );
    assert_vault_error(
        rpc.try_send_operation(
            ledger
                .prepare_claim_expired(ClaimExpiredRequest { payer, note_id: 2 })
                .await
                .unwrap(),
            &authority,
        )
        .await,
        VaultError::Paused,
        "claim_expired while paused",
    );
    assert_vault_error(
        rpc.try_send_operation(
            deposit(3, Felt252::from_u64(45), tree.get_siblings(3)).await,
            &authority,
        )
        .await,
        VaultError::Paused,
        "deposit while paused",
    );

    // Finalization of the withheld escape is open while paused: B − b.
    rpc.wait_until_after(b_deadline).await;
    // The pending account's rent is refunded to the destination, not the caller.
    let (destination_before, treasury_before, b_pending_rent) = (
        rpc.balance(destination).await,
        rpc.balance(treasury).await,
        rpc.balance(pending_address(vault, 1)).await,
    );
    assert!(b_pending_rent > 0);
    let signature = rpc
        .send_operation(
            browser_exit(
                &browser_funding,
                "finalize",
                json!({
                    "payer": authority.pubkey().to_string(), "note_id": 1
                }),
            ),
            &authority,
        )
        .await;
    compute_units.push((
        "finalize (while paused)",
        rpc.compute_units(&signature).await,
    ));
    assert_eq!(
        u128::from(rpc.balance(destination).await - destination_before),
        b1.balance - bound_b + u128::from(b_pending_rent),
        "withheld successor: the honest user is paid B - b (plus the escape's pending rent)"
    );
    assert_eq!(rpc.balance(pending_address(vault, 1)).await, 0);
    assert_eq!(rpc.balance(treasury).await, treasury_before);
    assert_eq!(
        u128::from(accrued(rpc.anchor_account(vault).await)),
        40_000 + DEPOSIT - (b1.balance - bound_b)
    );
    let finalized: vault_program::NoteState = rpc.anchor_account(note_address(vault, 1)).await;
    assert_eq!(finalized.status, vault_program::NOTE_STATUS_CLOSED);
    assert!(ledger
        .prepare_finalize_escape(FinalizeEscapeRequest { payer, note_id: 1 })
        .await
        .is_err());

    // Unpause; an immediate re-pause is refused (bounded pause cooldown).
    rpc.send_instruction(set_paused(false), &authority).await;
    let message = rpc.instruction_message(set_paused(true), &authority).await;
    assert_vault_error(
        rpc.try_send_message(message, &authority).await,
        VaultError::PauseCooldown,
        "re-pause inside the cooldown",
    );
    // Unpaused, the same sweep now fails only on expiry.
    assert_vault_error(
        rpc.try_send_operation(
            ledger
                .prepare_claim_expired(ClaimExpiredRequest { payer, note_id: 2 })
                .await
                .unwrap(),
            &authority,
        )
        .await,
        VaultError::NoteNotExpired,
        "claim_expired before claimableAt",
    );

    // Re-escape matrix for the cheater: replaying N1 and escaping from S0
    // (whose successor N1 is challenged) both revert cheaply.
    assert_vault_error(
        rpc.try_send_operation(
            ledger
                .prepare_escape(c_escape(&c_stale, &c_stale_proof))
                .await
                .unwrap(),
            &authority,
        )
        .await,
        VaultError::ReplayedNullifier,
        "replayed defeated nullifier N",
    );
    assert_vault_error(
        rpc.try_send_operation(
            ledger
                .prepare_escape(c_escape(&c_older, &c_older_proof))
                .await
                .unwrap(),
            &authority,
        )
        .await,
        VaultError::SupersededState,
        "escape whose successor N+ is challenged",
    );
    // The newest state reuses the released N2 and is judged on its own.
    let signature = rpc
        .send_operation(
            ledger
                .prepare_escape(c_escape(&c_newest, &c_newest_proof))
                .await
                .unwrap(),
            &authority,
        )
        .await;
    compute_units.push((
        "escape (released N reused)",
        rpc.compute_units(&signature).await,
    ));
    for nullifier in [c_n2, c_newest.next_nullifier] {
        assert_eq!(
            ledger
                .nullifier_status(nullifier, LedgerCommitment::Confirmed)
                .await
                .unwrap(),
            LedgerNullifierStatus::Used
        );
    }
    let pending = ledger
        .pending_escapes(LedgerCommitment::Confirmed)
        .await
        .unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!((pending[0].note_id, pending[0].nullifier), (2, c_n2));
    rpc.wait_until_after(pending[0].deadline).await;
    let destination_before = rpc.balance(destination).await;
    let c_pending_rent = rpc.balance(pending_address(vault, 2)).await;
    assert!(c_pending_rent > 0);
    let signature = rpc
        .send_operation(
            ledger
                .prepare_finalize_escape(FinalizeEscapeRequest { payer, note_id: 2 })
                .await
                .unwrap(),
            &authority,
        )
        .await;
    rpc.wait_finalized(&signature).await;
    assert_eq!(
        u128::from(rpc.balance(destination).await - destination_before),
        c2.balance + u128::from(c_pending_rent)
    );

    let vault_state: vault_program::VaultState = rpc.anchor_account(vault).await;
    assert_eq!(vault_state.total_credits, 0);
    let owed = 40_000 + (DEPOSIT - (b1.balance - bound_b)) + (DEPOSIT - c2.balance);
    assert_eq!(u128::from(vault_state.treasury_accrued), owed);
    // The treasury account never existed (zero lamports) during every exit
    // above: a drained or unreachable treasury cannot block user payouts.
    assert_eq!(rpc.balance(treasury).await, 0);
    // The accrued share now includes a concession of a whole minimum lease,
    // above the rent-exempt minimum: anyone may sweep it, even into the
    // never-funded treasury account.
    let signature = rpc.send_operation(sweep().await, &sweeper).await;
    compute_units.push(("withdraw_treasury", rpc.compute_units(&signature).await));
    assert_eq!(u128::from(rpc.balance(treasury).await), owed);
    assert_eq!(accrued(rpc.anchor_account(vault).await), 0);
    assert!(ledger
        .prepare_withdraw_treasury(LedgerAccount::new(sweeper.pubkey().to_bytes()))
        .await
        .is_err());
    assert!(ledger
        .pending_escapes(LedgerCommitment::Confirmed)
        .await
        .unwrap()
        .is_empty());
    // Closed notes B and C keep their leaves until someone retires them.
    let final_state = ledger.state(LedgerCommitment::Finalized).await.unwrap();
    assert_eq!(final_state.next_note_id, 3);
    assert_eq!(final_state.root, tree.root());
    wait_indexed(
        &poller,
        &service,
        3,
        tree.root(),
        &[Felt252::ZERO, b0.leaf(), c0.leaf()],
    )
    .await;

    for (name, units) in &compute_units {
        eprintln!("CU {name}: {units}");
    }
}
