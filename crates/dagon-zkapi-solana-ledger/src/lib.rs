//! Production Solana implementation of the Dagon zkAPI [`CreditLedger`].
//!
//! Deposits carry an insertion proof too large for one packet, so they are
//! serialized into an authenticated operation buffer over multiple
//! transactions and consumed by one atomic vault instruction. Exits are
//! leaf-bound and root-free, so escape, close, defeat, raise, finalize, claim
//! and closed-leaf retirement are each one direct transaction.

use std::str::FromStr;
use std::sync::{Arc, OnceLock};

use anchor_lang::{
    solana_program::bpf_loader_upgradeable::{self, UpgradeableLoaderState},
    AccountDeserialize, AnchorSerialize, InstructionData, Space, ToAccountMetas,
};
use base64::Engine;
use dagon_zkapi_ledger::*;
use dagon_zkapi_vault as vault_program;
use rand::RngCore;
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_hash::Hash;
use solana_instruction::Instruction;
use solana_message::Message;
use solana_pubkey::Pubkey;
use zkapi_core::v2 as core;
use zkapi_proof::compact::SolanaTransitionProver;
use zkapi_types::wire::{Groth16ProofWire, ProofBackendWire};
use zkapi_types::{
    solana_chain_id, solana_deployment_binding, solana_destination_matches, Felt252,
    RequestPublicInputsV2, SolanaMerkleTransitionInputs, WithdrawalPublicInputsV2,
    PROTOCOL_VERSION,
};

pub const MESSAGE_FORMAT: &str = "solana-legacy-message-v1";
pub const SIGNED_TRANSACTION_FORMAT: &str = "solana-legacy-transaction-v1";
const OPERATION_CHUNK_BYTES: usize = 700;
const OPERATION_LIFETIME_SLOTS: u64 = 2_000;
const KIND_DEPOSIT: u8 = 1;
const MAX_RPC_RESPONSE_BYTES: usize = 1_048_576;
const ACCOUNT_PAGE_SIZE: u32 = 100;
const HASH_COMPUTE_UNITS: u32 = 1_400_000;
const HASH_HEAP_BYTES: u32 = 128 * 1_024;
const EXPIRY_BUCKET_SECONDS: u64 = 86_400;
const TRANSITION_PROVING_KEY: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../protocol/setup/solana-transition-v1/transition.pk"
));

#[derive(Debug, Clone)]
pub struct SolanaLedgerConfig {
    pub rpc_url: String,
    pub indexer_url: Option<String>,
    pub network: String,
    pub program_id: [u8; 32],
    pub vault_state: [u8; 32],
    pub genesis_hash: [u8; 32],
}

pub struct SolanaCreditLedger {
    config: SolanaLedgerConfig,
    deployment: LedgerDeployment,
    program_id: Pubkey,
    vault: Pubkey,
    http: reqwest::Client,
    transition_prover: Arc<SolanaTransitionProver>,
}

/// Finalized vault metadata required to bind normal server startup to the
/// authoritative Solana deployment.
///
/// Values are returned only after the ledger has verified the pinned cluster,
/// account owner, vault PDA/bump, version, chain ID, and protocol binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolanaVaultRuntimeView {
    pub state: LedgerState,
    pub paused: bool,
    pub request_charge_cap: u64,
    /// The vault's escape challenge period in seconds.
    pub challenge_period: u64,
    pub state_signing_key_x: Felt252,
    pub state_signing_key_y: Felt252,
    pub clearance_signing_key_x: Felt252,
    pub clearance_signing_key_y: Felt252,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SolanaAccountSnapshot {
    data: Vec<u8>,
    owner: Pubkey,
    executable: bool,
    observed_slot: u64,
}

impl SolanaCreditLedger {
    pub fn new(config: SolanaLedgerConfig) -> Result<Self, LedgerError> {
        validate_service_url("Solana RPC", &config.rpc_url)?;
        if let Some(indexer) = config.indexer_url.as_deref() {
            validate_service_url("Solana indexer", indexer)?;
        }
        if config.network.trim().is_empty()
            || config.program_id == [0; 32]
            || config.vault_state == [0; 32]
            || config.genesis_hash == [0; 32]
        {
            return Err(LedgerError::InvalidData(
                "Solana deployment identity must be nonzero and named".into(),
            ));
        }
        let program_id = Pubkey::new_from_array(config.program_id);
        let vault = Pubkey::new_from_array(config.vault_state);
        let binding = solana_deployment_binding(
            &config.program_id,
            &config.vault_state,
            &config.genesis_hash,
        );
        let chain_id = solana_chain_id(&config.genesis_hash);
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| LedgerError::InvalidData(error.to_string()))?;
        let transition_prover = shared_transition_prover()?;
        Ok(Self {
            deployment: LedgerDeployment {
                backend: "dagon.solana.groth16.v1".into(),
                network: config.network.clone(),
                chain_id,
                protocol_binding: binding,
                vault: LedgerAccount::new(config.vault_state),
                asset: LedgerAsset {
                    symbol: "SOL".into(),
                    decimals: 9,
                    mint: None,
                },
            },
            config,
            program_id,
            vault,
            http,
            transition_prover,
        })
    }

    /// Read the authoritative finalized vault metadata used by server startup.
    ///
    /// This deliberately reuses the same cluster, owner, Anchor decoding, PDA,
    /// and deployment checks as all other ledger reads instead of exposing raw
    /// account bytes to the server.
    pub async fn finalized_vault(&self) -> Result<SolanaVaultRuntimeView, LedgerError> {
        let commitment = LedgerCommitment::Finalized;
        let (vault, slot) = self.vault_account(commitment).await?;
        runtime_view(vault, slot, commitment)
    }

    /// Verify that the pinned program is an executable loader-v3 deployment
    /// whose upgrade authority has been permanently revoked.
    ///
    /// This is deliberately separate from [`Self::finalized_vault`]: vault
    /// identity and deployed-code immutability are independent startup gates.
    /// Both accounts are read at finalized commitment from the pinned cluster.
    pub async fn assert_immutable_program(&self) -> Result<(), LedgerError> {
        self.assert_cluster().await?;
        let commitment = LedgerCommitment::Finalized;
        let program = self
            .account_snapshot(self.program_id, commitment)
            .await?
            .ok_or_else(|| {
                LedgerError::DeploymentMismatch(format!(
                    "program account {} does not exist",
                    self.program_id
                ))
            })?;
        let program_data_address = immutable_program_data_address(self.program_id, &program)?;
        let program_data = self
            .account_snapshot(program_data_address, commitment)
            .await?
            .ok_or_else(|| {
                LedgerError::DeploymentMismatch(format!(
                    "program-data account {program_data_address} does not exist"
                ))
            })?;
        assert_immutable_program_data(program_data_address, &program_data)
    }

    /// Build an owner-signed transaction that closes an abandoned staged
    /// operation and returns its rent to that owner.
    pub async fn prepare_cancel_operation(
        &self,
        payer: LedgerAccount,
        operation_id: [u8; 32],
    ) -> Result<PreparedLedgerOperation, LedgerError> {
        let payer = account_pubkey(payer);
        let (operation, _) = operation_address(self.vault, payer, operation_id, self.program_id);
        let instruction = Instruction {
            program_id: self.program_id,
            accounts: vault_program::accounts::CancelOperation {
                vault: self.vault,
                operation,
                owner: payer,
            }
            .to_account_metas(None),
            data: vault_program::instruction::CancelOperation {}.data(),
        };
        self.direct_operation(payer, instruction).await
    }

    /// Build a transaction, payable by anyone, that sweeps the operator share
    /// accrued in the vault to the pinned treasury. Exits never touch the
    /// treasury account, so a treasury that cannot receive lamports cannot
    /// block a user's payout.
    pub async fn prepare_withdraw_treasury(
        &self,
        payer: LedgerAccount,
    ) -> Result<PreparedLedgerOperation, LedgerError> {
        let payer = account_pubkey(payer);
        let (vault, _) = self.vault_account(LedgerCommitment::Tip).await?;
        if vault.treasury_accrued == 0 {
            return Err(LedgerError::Rejected("no treasury share has accrued".into()));
        }
        let instruction = Instruction {
            program_id: self.program_id,
            accounts: vault_program::accounts::WithdrawTreasury {
                vault: self.vault,
                treasury: vault.treasury,
            }
            .to_account_metas(None),
            data: vault_program::instruction::WithdrawTreasury {}.data(),
        };
        self.direct_operation(payer, instruction).await
    }

    async fn rpc<T: DeserializeOwned>(
        &self,
        method: &str,
        params: Value,
    ) -> Result<T, LedgerError> {
        let mut response = self
            .http
            .post(&self.config.rpc_url)
            .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
            .send()
            .await
            .map_err(|error| LedgerError::Unavailable(error.to_string()))?;
        if !response.status().is_success() {
            return Err(LedgerError::Unavailable(format!(
                "Solana RPC returned {}",
                response.status()
            )));
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RPC_RESPONSE_BYTES as u64)
        {
            return Err(LedgerError::InvalidData(
                "Solana RPC response exceeds the ledger limit".into(),
            ));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| LedgerError::Unavailable(error.to_string()))?
        {
            if body.len().saturating_add(chunk.len()) > MAX_RPC_RESPONSE_BYTES {
                return Err(LedgerError::InvalidData(
                    "Solana RPC response exceeds the ledger limit".into(),
                ));
            }
            body.extend_from_slice(&chunk);
        }
        let value: Value = serde_json::from_slice(&body)
            .map_err(|error| LedgerError::InvalidData(error.to_string()))?;
        if value.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
            || value.get("id").and_then(Value::as_u64) != Some(1)
        {
            return Err(LedgerError::InvalidData(
                "Solana RPC response identity mismatch".into(),
            ));
        }
        if let Some(error) = value.get("error") {
            // A simulation failure means this send was not broadcast. Keep
            // transport/node errors ambiguous, but let challengers replace a
            // stale-root proof immediately instead of awaiting blockhash expiry.
            // AlreadyProcessed means an earlier send of these bytes landed, and
            // BlockhashNotFound can come from a lagging node: neither proves
            // the signed plan unusable, so both keep the ambiguous recovery path.
            let simulation_error = &error["data"]["err"];
            if method == "sendTransaction"
                && error["code"].as_i64() == Some(-32002)
                && !simulation_error.is_null()
                && !matches!(
                    simulation_error.as_str(),
                    Some("AlreadyProcessed" | "BlockhashNotFound")
                )
            {
                return Err(LedgerError::Rejected(format!(
                    "Solana transaction preflight failed: {error}"
                )));
            }
            return Err(LedgerError::Unavailable(format!(
                "Solana RPC {method} failed: {error}"
            )));
        }
        serde_json::from_value(
            value
                .get("result")
                .cloned()
                .ok_or_else(|| LedgerError::InvalidData("Solana RPC result missing".into()))?,
        )
        .map_err(|error| LedgerError::InvalidData(error.to_string()))
    }

    async fn assert_cluster(&self) -> Result<(), LedgerError> {
        let encoded: String = self.rpc("getGenesisHash", json!([])).await?;
        let actual = Hash::from_str(&encoded)
            .map_err(|error| LedgerError::InvalidData(error.to_string()))?;
        if actual.to_bytes() != self.config.genesis_hash {
            return Err(LedgerError::DeploymentMismatch(
                "Solana RPC genesis hash does not match the pinned cluster".into(),
            ));
        }
        Ok(())
    }

    async fn account_snapshot(
        &self,
        address: Pubkey,
        commitment: LedgerCommitment,
    ) -> Result<Option<SolanaAccountSnapshot>, LedgerError> {
        let result: Value = self
            .rpc(
                "getAccountInfo",
                json!([
                    address.to_string(),
                    {"encoding":"base64","commitment":commitment_name(commitment)}
                ]),
            )
            .await?;
        let slot = result["context"]["slot"]
            .as_u64()
            .ok_or_else(|| LedgerError::InvalidData("account context lacks slot".into()))?;
        let Some(value) = result.get("value").filter(|value| !value.is_null()) else {
            return Ok(None);
        };
        let owner = value["owner"]
            .as_str()
            .ok_or_else(|| LedgerError::InvalidData("account owner missing".into()))?;
        let owner =
            Pubkey::from_str(owner).map_err(|error| LedgerError::InvalidData(error.to_string()))?;
        let executable = value["executable"]
            .as_bool()
            .ok_or_else(|| LedgerError::InvalidData("account executable flag missing".into()))?;
        let data = value["data"]
            .as_array()
            .ok_or_else(|| LedgerError::InvalidData("account data missing".into()))?;
        if data.get(1).and_then(Value::as_str) != Some("base64") {
            return Err(LedgerError::InvalidData(
                "account data is not base64 encoded".into(),
            ));
        }
        let encoded = data
            .first()
            .and_then(Value::as_str)
            .ok_or_else(|| LedgerError::InvalidData("account data missing".into()))?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|error| LedgerError::InvalidData(error.to_string()))?;
        Ok(Some(SolanaAccountSnapshot {
            data: bytes,
            owner,
            executable,
            observed_slot: slot,
        }))
    }

    async fn anchor_account<T: AccountDeserialize>(
        &self,
        address: Pubkey,
        commitment: LedgerCommitment,
    ) -> Result<(T, u64), LedgerError> {
        self.optional_anchor_account(address, commitment)
            .await?
            .ok_or_else(|| LedgerError::InvalidData(format!("account {address} does not exist")))
    }

    async fn optional_anchor_account<T: AccountDeserialize>(
        &self,
        address: Pubkey,
        commitment: LedgerCommitment,
    ) -> Result<Option<(T, u64)>, LedgerError> {
        let Some(snapshot) = self.account_snapshot(address, commitment).await? else {
            return Ok(None);
        };
        Ok(Some((self.decode_owned(address, &snapshot)?, snapshot.observed_slot)))
    }

    fn decode_owned<T: AccountDeserialize>(
        &self,
        address: Pubkey,
        snapshot: &SolanaAccountSnapshot,
    ) -> Result<T, LedgerError> {
        if snapshot.owner != self.program_id {
            return Err(LedgerError::DeploymentMismatch(format!(
                "account {address} is owned by {}",
                snapshot.owner
            )));
        }
        if snapshot.executable {
            return Err(LedgerError::DeploymentMismatch(format!(
                "data account {address} is unexpectedly executable"
            )));
        }
        let mut slice = snapshot.data.as_slice();
        T::try_deserialize(&mut slice).map_err(|error| LedgerError::InvalidData(error.to_string()))
    }

    async fn vault_account(
        &self,
        commitment: LedgerCommitment,
    ) -> Result<(vault_program::VaultState, u64), LedgerError> {
        self.assert_cluster().await?;
        let (vault, slot): (vault_program::VaultState, u64) =
            self.anchor_account(self.vault, commitment).await?;
        let (expected_vault, expected_bump) =
            Pubkey::find_program_address(&[b"vault", vault.authority.as_ref()], &self.program_id);
        if vault.version != vault_program::VAULT_VERSION
            || self.vault != expected_vault
            || vault.bump != expected_bump
            || vault.genesis_hash != self.config.genesis_hash
            || vault.chain_id != self.deployment.chain_id
            || vault.protocol_binding != *self.deployment.protocol_binding.as_bytes()
        {
            return Err(LedgerError::DeploymentMismatch(
                "vault account does not match the pinned cluster/deployment".into(),
            ));
        }
        Ok((vault, slot))
    }

    async fn latest_blockhash(&self) -> Result<(Hash, u64), LedgerError> {
        self.assert_cluster().await?;
        let result: Value = self
            .rpc("getLatestBlockhash", json!([{"commitment":"confirmed"}]))
            .await?;
        let blockhash = result["value"]["blockhash"]
            .as_str()
            .ok_or_else(|| LedgerError::InvalidData("latest blockhash missing".into()))?;
        let last_valid = result["value"]["lastValidBlockHeight"]
            .as_u64()
            .ok_or_else(|| LedgerError::InvalidData("last valid block height missing".into()))?;
        Ok((
            Hash::from_str(blockhash)
                .map_err(|error| LedgerError::InvalidData(error.to_string()))?,
            last_valid,
        ))
    }

    async fn current_slot(&self) -> Result<u64, LedgerError> {
        self.rpc("getSlot", json!([{"commitment":"confirmed"}]))
            .await
    }

    async fn block_time(&self, slot: u64) -> Result<u64, LedgerError> {
        let time: Option<i64> = self.rpc("getBlockTime", json!([slot])).await?;
        let time = time.ok_or_else(|| {
            LedgerError::Unavailable(format!("Solana block time is unavailable for slot {slot}"))
        })?;
        u64::try_from(time)
            .map_err(|_| LedgerError::InvalidData("Solana block time is negative".into()))
    }

    async fn note_account(
        &self,
        note_id: u32,
        commitment: LedgerCommitment,
    ) -> Result<vault_program::NoteState, LedgerError> {
        let (address, expected_bump) = note_address(self.vault, note_id, self.program_id);
        let (note, _): (vault_program::NoteState, u64) =
            self.anchor_account(address, commitment).await?;
        if note.vault != self.vault || note.note_id != note_id || note.bump != expected_bump {
            return Err(LedgerError::DeploymentMismatch(
                "note account does not match its canonical PDA".into(),
            ));
        }
        Ok(note)
    }

    async fn account_page(
        &self,
        addresses: &[(Pubkey, u8)],
        commitment: LedgerCommitment,
        min_slot: u64,
    ) -> Result<(u64, Vec<Option<Value>>), LedgerError> {
        let mut result: Value = self.rpc(
            "getMultipleAccounts",
            json!([
                addresses.iter().map(|(address, _)| address.to_string()).collect::<Vec<_>>(),
                {"encoding": "base64", "commitment": commitment_name(commitment),
                 "minContextSlot": min_slot}
            ]),
        ).await?;
        let slot = result["context"]["slot"].as_u64().ok_or_else(|| {
            LedgerError::InvalidData("account page lacks context slot".into())
        })?;
        let accounts: Vec<Option<Value>> = serde_json::from_value(result["value"].take())
            .map_err(|error| LedgerError::InvalidData(error.to_string()))?;
        if slot < min_slot || accounts.len() != addresses.len() {
            return Err(LedgerError::InvalidData("stale or incomplete account page".into()));
        }
        Ok((slot, accounts))
    }

    /// Transaction witnesses must use the live tree, not wait for the public
    /// finalized indexer to catch up. As in the indexer, reconstruct all notes
    /// and accept the snapshot only when it matches an authoritative vault root.
    async fn live_snapshot(
        &self,
        commitment: LedgerCommitment,
    ) -> Result<LedgerSnapshot, LedgerError> {
        let (vault, mut slot) = self.vault_account(commitment).await?;
        // Never reserve from next_note_id: process at most 100 accounts/1 MiB
        // per RPC and grow the dense snapshot only as each page is validated.
        let mut leaves = Vec::new();
        let mut tree = zkapi_core::merkle::MerkleTree::new();
        let expected_owner = self.program_id.to_string();
        let mut start = 0;
        while start < vault.next_note_id {
            let end = start.saturating_add(ACCOUNT_PAGE_SIZE).min(vault.next_note_id);
            let addresses: Vec<_> = (start..end)
                .map(|id| note_address(self.vault, id, self.program_id)).collect();
            let (page_slot, accounts) = self.account_page(&addresses, commitment, slot).await?;
            slot = page_slot;
            for ((note_id, (_, bump)), account) in (start..end).zip(addresses).zip(accounts) {
                let leaf = if let Some(account) = account.filter(|value| !is_unclaimed_pda(value)) {
                    let note: vault_program::NoteState =
                        decode_scanned_account(&account, &expected_owner)?;
                    if note.note_id != note_id || note.bump != bump || note.vault != self.vault {
                        return Err(LedgerError::InvalidData("noncanonical note account".into()));
                    }
                    let registration = Felt252::try_from_bytes_be(note.commitment)
                        .map_err(LedgerError::InvalidData)?;
                    match note.status {
                        // Exits are leaf-bound: the leaf stays through a
                        // pending escape and after close/claim until a
                        // permissionless retirement removes it.
                        vault_program::NOTE_STATUS_ACTIVE
                        | vault_program::NOTE_STATUS_PENDING
                        | vault_program::NOTE_STATUS_CLOSED => core::note_leaf(
                            note_id, &registration, u128::from(note.deposit_amount), note.expiry,
                        ),
                        vault_program::NOTE_STATUS_RETIRED => Felt252::ZERO,
                        _ => return Err(LedgerError::InvalidData("invalid note status".into())),
                    }
                } else {
                    Felt252::ZERO
                };
                leaves.push(leaf);
                if leaf != Felt252::ZERO {
                    tree.set_leaf(note_id, leaf);
                }
            }
            start = end;
        }
        let state = runtime_view(vault, slot, commitment)?.state;
        if tree.root() != state.root {
            return Err(LedgerError::Rejected(
                "live note snapshot does not reconstruct the vault root; refresh the path".into(),
            ));
        }
        Ok(LedgerSnapshot { state, leaves })
    }

    async fn prove_transition(
        &self,
        public: SolanaMerkleTransitionInputs,
        siblings: [Felt252; zkapi_types::MERKLE_DEPTH],
    ) -> Result<Vec<u8>, LedgerError> {
        let prover = Arc::clone(&self.transition_prover);
        let proof = tokio::task::spawn_blocking(move || prover.prove(&public, siblings))
            .await
            .map_err(|error| {
                LedgerError::Unavailable(format!("transition proving task failed: {error}"))
            })?
            .map_err(|error| {
                LedgerError::Rejected(format!("invalid Merkle transition witness: {error}"))
            })?;
        proof_bytes(&proof)
    }

    fn message(
        instruction: Instruction,
        payer: Pubkey,
        blockhash: Hash,
        last_valid_height: u64,
    ) -> Result<PreparedLedgerTransaction, LedgerError> {
        Self::message_with_instructions(&[instruction], payer, blockhash, last_valid_height)
    }

    fn compute_intensive_message(
        instruction: Instruction,
        payer: Pubkey,
        blockhash: Hash,
        last_valid_height: u64,
    ) -> Result<PreparedLedgerTransaction, LedgerError> {
        Self::message_with_instructions(
            &[
                ComputeBudgetInstruction::request_heap_frame(HASH_HEAP_BYTES),
                ComputeBudgetInstruction::set_compute_unit_limit(HASH_COMPUTE_UNITS),
                instruction,
            ],
            payer,
            blockhash,
            last_valid_height,
        )
    }

    fn message_with_instructions(
        instructions: &[Instruction],
        payer: Pubkey,
        blockhash: Hash,
        last_valid_height: u64,
    ) -> Result<PreparedLedgerTransaction, LedgerError> {
        let message = Message::new_with_blockhash(instructions, Some(&payer), &blockhash);
        let bytes = bincode::serialize(&message)
            .map_err(|error| LedgerError::InvalidData(error.to_string()))?;
        // One payer signature adds 65 bytes (shortvec length + signature).
        if bytes.len().saturating_add(65) > 1_232 {
            return Err(LedgerError::InvalidData(format!(
                "prepared Solana transaction exceeds packet limit: {} bytes before signature",
                bytes.len()
            )));
        }
        Ok(PreparedLedgerTransaction {
            format: MESSAGE_FORMAT.into(),
            bytes,
            required_signers: vec![LedgerAccount::new(payer.to_bytes())],
            last_valid_height: Some(last_valid_height),
        })
    }

    async fn staged_operation<F>(
        &self,
        kind: u8,
        payer: Pubkey,
        payload: Vec<u8>,
        execute: F,
    ) -> Result<PreparedLedgerOperation, LedgerError>
    where
        F: FnOnce(Pubkey) -> Instruction,
    {
        let total_len = u16::try_from(payload.len())
            .map_err(|_| LedgerError::InvalidData("operation payload exceeds uint16".into()))?;
        if payload.is_empty() || payload.len() > 4_096 {
            return Err(LedgerError::InvalidData(
                "operation payload is outside the vault limit".into(),
            ));
        }
        let (blockhash, last_valid_height) = self.latest_blockhash().await?;
        let expires_at_slot = self
            .current_slot()
            .await?
            .checked_add(OPERATION_LIFETIME_SLOTS)
            .ok_or_else(|| LedgerError::InvalidData("operation expiry overflow".into()))?;
        let mut operation_id = [0; 32];
        rand::rngs::OsRng.fill_bytes(&mut operation_id);
        let (operation, _) = operation_address(self.vault, payer, operation_id, self.program_id);
        let digest: [u8; 32] = Keccak256::digest(&payload).into();
        let initialize = Instruction {
            program_id: self.program_id,
            accounts: vault_program::accounts::InitializeOperation {
                vault: self.vault,
                operation,
                owner: payer,
                system_program: anchor_lang::system_program::ID,
            }
            .to_account_metas(None),
            data: vault_program::instruction::InitializeOperation {
                args: vault_program::InitializeOperationArgs {
                    operation_id,
                    kind,
                    total_len,
                    digest,
                    expires_at_slot,
                },
            }
            .data(),
        };
        let mut transactions = vec![Self::message(
            initialize,
            payer,
            blockhash,
            last_valid_height,
        )?];
        for (index, chunk) in payload.chunks(OPERATION_CHUNK_BYTES).enumerate() {
            let offset = u16::try_from(index * OPERATION_CHUNK_BYTES)
                .map_err(|_| LedgerError::InvalidData("operation offset overflow".into()))?;
            let write = Instruction {
                program_id: self.program_id,
                accounts: vault_program::accounts::WriteOperation {
                    vault: self.vault,
                    operation,
                    owner: payer,
                }
                .to_account_metas(None),
                data: vault_program::instruction::WriteOperation {
                    offset,
                    chunk: chunk.to_vec(),
                }
                .data(),
            };
            transactions.push(Self::message(write, payer, blockhash, last_valid_height)?);
        }
        transactions.push(Self::compute_intensive_message(
            execute(operation),
            payer,
            blockhash,
            last_valid_height,
        )?);
        Ok(PreparedLedgerOperation { transactions })
    }

    async fn direct_operation(
        &self,
        payer: Pubkey,
        instruction: Instruction,
    ) -> Result<PreparedLedgerOperation, LedgerError> {
        let (blockhash, last_valid_height) = self.latest_blockhash().await?;
        Ok(PreparedLedgerOperation {
            transactions: vec![Self::message(
                instruction,
                payer,
                blockhash,
                last_valid_height,
            )?],
        })
    }

    /// One proof-verifying transaction whose evidence fits a packet.
    async fn direct_compute_operation(
        &self,
        payer: Pubkey,
        instruction: Instruction,
    ) -> Result<PreparedLedgerOperation, LedgerError> {
        let (blockhash, last_valid_height) = self.latest_blockhash().await?;
        Ok(PreparedLedgerOperation {
            transactions: vec![Self::compute_intensive_message(
                instruction,
                payer,
                blockhash,
                last_valid_height,
            )?],
        })
    }
}

fn shared_transition_prover() -> Result<Arc<SolanaTransitionProver>, LedgerError> {
    static PROVER: OnceLock<Result<Arc<SolanaTransitionProver>, String>> = OnceLock::new();
    PROVER
        .get_or_init(|| {
            SolanaTransitionProver::from_bytes(TRANSITION_PROVING_KEY)
                .map(Arc::new)
                .map_err(|error| error.to_string())
        })
        .as_ref()
        .map(Arc::clone)
        .map_err(|error| {
            LedgerError::InvalidData(format!(
                "embedded transition proving key is invalid: {error}"
            ))
        })
}

fn bucket_expiry(now: u64, ttl: u64) -> Result<u64, LedgerError> {
    let raw = now
        .checked_add(ttl)
        .ok_or_else(|| LedgerError::InvalidData("deposit expiry overflow".into()))?;
    raw.checked_add(EXPIRY_BUCKET_SECONDS - 1)
        .and_then(|value| value.checked_div(EXPIRY_BUCKET_SECONDS))
        .and_then(|value| value.checked_mul(EXPIRY_BUCKET_SECONDS))
        .ok_or_else(|| LedgerError::InvalidData("deposit expiry overflow".into()))
}

/// Anyone can transfer lamports to a PDA address before the program creates it
/// or after the program closes it. That System-owned, data-less account is not
/// program state (Anchor `init` adopts it), so the PDA scans must treat it as
/// absent instead of failing the whole tree or pending-escape scan.
fn is_unclaimed_pda(account: &Value) -> bool {
    account["owner"].as_str() == Some("11111111111111111111111111111111")
        && account["executable"].as_bool() == Some(false)
        && account["data"][0].as_str() == Some("")
        && account["data"][1].as_str() == Some("base64")
}

fn decode_scanned_account<T: AccountDeserialize + Space>(
    account: &Value,
    expected_owner: &str,
) -> Result<T, LedgerError> {
    if account["owner"].as_str() != Some(expected_owner)
        || account["executable"].as_bool() != Some(false)
        || account["data"][1].as_str() != Some("base64")
    {
        return Err(LedgerError::InvalidData("invalid account scan metadata".into()));
    }
    let data = base64::engine::general_purpose::STANDARD
        .decode(account["data"][0].as_str().ok_or_else(|| {
            LedgerError::InvalidData("account scan data missing".into())
        })?)
        .map_err(|error| LedgerError::InvalidData(error.to_string()))?;
    if data.len() != 8 + T::INIT_SPACE {
        return Err(LedgerError::InvalidData("noncanonical account scan size".into()));
    }
    T::try_deserialize(&mut data.as_slice())
        .map_err(|error| LedgerError::InvalidData(error.to_string()))
}

fn runtime_view(
    vault: vault_program::VaultState,
    slot: u64,
    commitment: LedgerCommitment,
) -> Result<SolanaVaultRuntimeView, LedgerError> {
    let felt = |bytes| Felt252::try_from_bytes_be(bytes).map_err(LedgerError::InvalidData);
    Ok(SolanaVaultRuntimeView {
        state: LedgerState {
            root: felt(vault.current_root)?,
            next_note_id: vault.next_note_id,
            observed_height: Some(slot),
            commitment,
        },
        paused: vault.paused,
        request_charge_cap: vault.request_charge_cap,
        challenge_period: vault.challenge_period,
        state_signing_key_x: felt(vault.state_signing_key_x)?,
        state_signing_key_y: felt(vault.state_signing_key_y)?,
        clearance_signing_key_x: felt(vault.clearance_signing_key_x)?,
        clearance_signing_key_y: felt(vault.clearance_signing_key_y)?,
    })
}

impl CreditLedger for SolanaCreditLedger {
    fn deployment(&self) -> &LedgerDeployment {
        &self.deployment
    }

    fn state(&self, commitment: LedgerCommitment) -> LedgerFuture<'_, LedgerState> {
        Box::pin(async move {
            let (vault, slot) = self.vault_account(commitment).await?;
            Ok(LedgerState {
                root: Felt252::try_from_bytes_be(vault.current_root)
                    .map_err(LedgerError::InvalidData)?,
                next_note_id: vault.next_note_id,
                observed_height: Some(slot),
                commitment,
            })
        })
    }

    fn snapshot(&self, commitment: LedgerCommitment) -> LedgerFuture<'_, LedgerSnapshot> {
        Box::pin(async move {
            if commitment != LedgerCommitment::Finalized {
                return self.live_snapshot(commitment).await;
            }
            let state = self.state(commitment).await?;
            let indexer = self
                .config
                .indexer_url
                .as_deref()
                .ok_or(LedgerError::Unsupported {
                    operation: "tree_snapshot_without_indexer",
                })?;
            #[derive(serde::Deserialize)]
            struct Response {
                root: Felt252,
                next_note_id: u32,
                leaves: Vec<Felt252>,
            }
            let response = self
                .http
                .get(format!(
                    "{}/v1/tree/snapshot",
                    indexer.trim_end_matches('/')
                ))
                .send()
                .await
                .map_err(|error| LedgerError::Unavailable(error.to_string()))?
                .error_for_status()
                .map_err(|error| LedgerError::Unavailable(error.to_string()))?
                .json::<Response>()
                .await
                .map_err(|error| LedgerError::InvalidData(error.to_string()))?;
            if response.root != state.root
                || response.next_note_id != state.next_note_id
                || response.leaves.len() != state.next_note_id as usize
            {
                return Err(LedgerError::InvalidData(
                    "indexer snapshot does not match the Solana vault".into(),
                ));
            }
            Ok(LedgerSnapshot {
                state,
                leaves: response.leaves,
            })
        })
    }

    fn path(
        &self,
        note_id: u32,
        zero_leaf: bool,
        commitment: LedgerCommitment,
    ) -> LedgerFuture<'_, LedgerPath> {
        Box::pin(async move {
            // Fetch the same whole-tree payload for every caller and derive the
            // requested path locally. This prevents an untrusted indexer from
            // learning which note is being challenged or withdrawn.
            let snapshot = self.snapshot(commitment).await?;
            if note_id > snapshot.state.next_note_id
                || (!zero_leaf && note_id == snapshot.state.next_note_id)
            {
                return Err(LedgerError::InvalidData(
                    "requested note is outside the Solana tree".into(),
                ));
            }
            let mut tree = zkapi_core::merkle::MerkleTree::new();
            for (index, value) in snapshot.leaves.iter().copied().enumerate() {
                tree.set_leaf(index as u32, value);
            }
            if tree.root() != snapshot.state.root {
                return Err(LedgerError::InvalidData(
                    "indexer snapshot does not reconstruct the Solana vault root".into(),
                ));
            }
            let leaf = if zero_leaf {
                Felt252::ZERO
            } else {
                snapshot.leaves[note_id as usize]
            };
            let siblings = tree.get_siblings(note_id);
            if zkapi_core::v2::merkle_root(note_id, &leaf, &siblings) != snapshot.state.root {
                return Err(LedgerError::InvalidData(
                    "requested path does not reconstruct the Solana vault root".into(),
                ));
            }
            Ok(LedgerPath {
                state: snapshot.state,
                note_id,
                leaf,
                siblings,
            })
        })
    }

    fn nullifier_status(
        &self,
        nullifier: Felt252,
        commitment: LedgerCommitment,
    ) -> LedgerFuture<'_, LedgerNullifierStatus> {
        Box::pin(async move {
            self.assert_cluster().await?;
            let (address, _) = Pubkey::find_program_address(
                &[b"nullifier", self.vault.as_ref(), nullifier.as_bytes()],
                &self.program_id,
            );
            match self.account_snapshot(address, commitment).await? {
                None => Ok(LedgerNullifierStatus::Unused),
                // A funded but unclaimed PDA is not a used nullifier: the
                // program's `init` adopts it when the nullifier is consumed.
                Some(snapshot)
                    if snapshot.owner == anchor_lang::system_program::ID
                        && !snapshot.executable
                        && snapshot.data.is_empty() =>
                {
                    Ok(LedgerNullifierStatus::Unused)
                }
                Some(snapshot) if snapshot.owner == self.program_id && !snapshot.executable => {
                    let mut input = snapshot.data.as_slice();
                    let used = vault_program::UsedNullifier::try_deserialize(&mut input)
                        .map_err(|error| LedgerError::InvalidData(error.to_string()))?;
                    let (_, expected_bump) = Pubkey::find_program_address(
                        &[b"nullifier", self.vault.as_ref(), nullifier.as_bytes()],
                        &self.program_id,
                    );
                    if used.vault != self.vault
                        || used.nullifier != *nullifier.as_bytes()
                        || used.bump != expected_bump
                    {
                        return Err(LedgerError::DeploymentMismatch(
                            "nullifier PDA contents do not match its address".into(),
                        ));
                    }
                    // A defeat releases the successor nullifier (status 0) so
                    // the operator may serve it again; consumed and challenged
                    // nullifiers can never be spent.
                    match used.status {
                        vault_program::NULLIFIER_RELEASED => Ok(LedgerNullifierStatus::Unused),
                        vault_program::NULLIFIER_CONSUMED | vault_program::NULLIFIER_CHALLENGED => {
                            Ok(LedgerNullifierStatus::Used)
                        }
                        other => Err(LedgerError::InvalidData(format!(
                            "nullifier PDA has unknown status {other}"
                        ))),
                    }
                }
                Some(_) => Err(LedgerError::DeploymentMismatch(
                    "nullifier PDA has a foreign owner".into(),
                )),
            }
        })
    }

    fn pending_escapes(
        &self,
        commitment: LedgerCommitment,
    ) -> LedgerFuture<'_, Vec<LedgerPendingEscape>> {
        Box::pin(async move {
            let (vault, mut slot) = self.vault_account(commitment).await?;
            let expected_owner = self.program_id.to_string();
            let mut escapes = Vec::new();
            let mut start = 0;
            while start < vault.next_note_id {
                let end = start.saturating_add(ACCOUNT_PAGE_SIZE).min(vault.next_note_id);
                let addresses: Vec<_> = (start..end)
                    .map(|id| pending_address(self.vault, id, self.program_id)).collect();
                let (page_slot, accounts) = self.account_page(&addresses, commitment, slot).await?;
                slot = page_slot;
                for ((note_id, (_, bump)), account) in (start..end).zip(addresses).zip(accounts) {
                    let Some(account) = account.filter(|value| !is_unclaimed_pda(value)) else {
                        continue;
                    };
                    let pending: vault_program::PendingWithdrawal =
                        decode_scanned_account(&account, &expected_owner)?;
                    if pending.note_id != note_id || pending.bump != bump
                        || pending.vault != self.vault
                    {
                        return Err(LedgerError::DeploymentMismatch(
                            "pending withdrawal does not match its canonical PDA".into(),
                        ));
                    }
                    let felt = |bytes| Felt252::try_from_bytes_be(bytes)
                        .map_err(LedgerError::InvalidData);
                    if pending.final_balance.checked_add(pending.conceded)
                        != Some(pending.state_balance)
                    {
                        return Err(LedgerError::InvalidData(
                            "pending withdrawal balance does not equal payout plus concession".into(),
                        ));
                    }
                    escapes.push(LedgerPendingEscape {
                        note_id,
                        nullifier: felt(pending.nullifier)?,
                        next_nullifier: felt(pending.next_nullifier)?,
                        state_balance: u128::from(pending.state_balance),
                        conceded: u128::from(pending.conceded),
                        deadline: pending.deadline,
                        observed_time: None,
                    });
                }
                start = end;
            }
            let observed_time: Option<i64> = self.rpc("getBlockTime", json!([slot])).await?;
            let observed_time = observed_time.map(|time| u64::try_from(time).map_err(|_| {
                LedgerError::InvalidData("pending-account block time is negative".into())
            })).transpose()?;
            for escape in &mut escapes {
                escape.observed_time = observed_time;
            }
            Ok(escapes)
        })
    }

    fn prepare_deposit(
        &self,
        request: DepositRequest,
    ) -> LedgerFuture<'_, PreparedLedgerOperation> {
        Box::pin(async move {
            let payer = account_pubkey(request.payer);
            let amount = u64::try_from(request.amount)
                .map_err(|_| LedgerError::Rejected("deposit exceeds u64".into()))?;
            if amount == 0 || request.commitment == Felt252::ZERO {
                return Err(LedgerError::Rejected(
                    "deposit amount and commitment must be nonzero".into(),
                ));
            }
            let (vault, observed_slot) = self.vault_account(LedgerCommitment::Tip).await?;
            if vault.next_note_id != request.expected_note_id {
                return Err(LedgerError::Rejected("deposit note ID is stale".into()));
            }
            let old_root =
                Felt252::try_from_bytes_be(vault.current_root).map_err(LedgerError::InvalidData)?;
            let siblings = request.zero_path;
            if core::merkle_root(request.expected_note_id, &Felt252::ZERO, &siblings) != old_root {
                return Err(LedgerError::Rejected(
                    "deposit path does not prove an empty leaf at the current root".into(),
                ));
            }
            let expiry = bucket_expiry(self.block_time(observed_slot).await?, vault.note_ttl)?;
            let leaf = core::note_leaf(
                request.expected_note_id,
                &request.commitment,
                u128::from(amount),
                expiry,
            );
            let new_root = core::merkle_root(request.expected_note_id, &leaf, &siblings);
            let transition = SolanaMerkleTransitionInputs {
                protocol_version: PROTOCOL_VERSION,
                chain_id: vault.chain_id,
                protocol_binding: Felt252::try_from_bytes_be(vault.protocol_binding)
                    .map_err(LedgerError::InvalidData)?,
                old_root,
                new_root,
                note_id: request.expected_note_id,
                commitment: request.commitment,
                amount,
                expiry,
                inserting: true,
            };
            let transition_proof = self.prove_transition(transition, siblings).await?;
            let payload = vault_program::DepositPayload {
                expected_note_id: request.expected_note_id,
                commitment: *request.commitment.as_bytes(),
                amount,
                expiry,
                new_root: *new_root.as_bytes(),
                transition_proof,
            }
            .try_to_vec()
            .map_err(|error| LedgerError::InvalidData(error.to_string()))?;
            let (note, _) = Pubkey::find_program_address(
                &[
                    b"note",
                    self.vault.as_ref(),
                    &request.expected_note_id.to_le_bytes(),
                ],
                &self.program_id,
            );
            self.staged_operation(KIND_DEPOSIT, payer, payload, |operation| Instruction {
                program_id: self.program_id,
                accounts: vault_program::accounts::ExecuteDeposit {
                    vault: self.vault,
                    operation,
                    note,
                    owner: payer,
                    system_program: anchor_lang::system_program::ID,
                }
                .to_account_metas(None),
                data: vault_program::instruction::ExecuteDeposit {
                    expected_note_id: request.expected_note_id,
                }
                .data(),
            })
            .await
        })
    }

    fn prepare_close(
        &self,
        request: WithdrawalRequest,
    ) -> LedgerFuture<'_, PreparedLedgerOperation> {
        Box::pin(async move { self.prepare_withdrawal(request, true).await })
    }

    fn prepare_escape(
        &self,
        request: WithdrawalRequest,
    ) -> LedgerFuture<'_, PreparedLedgerOperation> {
        Box::pin(async move { self.prepare_withdrawal(request, false).await })
    }

    fn prepare_challenge(
        &self,
        request: ChallengeRequest,
    ) -> LedgerFuture<'_, PreparedLedgerOperation> {
        Box::pin(async move {
            let payer = account_pubkey(request.payer);
            let proof = proof_bytes(&request.proof)?;
            let (vault, _) = self.vault_account(LedgerCommitment::Tip).await?;
            assert_request_binding(&vault, &request.public_inputs)?;
            let (pending_address, pending) = self
                .pending_account(request.note_id, LedgerCommitment::Tip)
                .await?;
            // Only a request that spent the successor state defeats an exit;
            // evidence at the escaped nullifier can only raise the concession.
            if *request.public_inputs.request_nullifier.as_bytes() != pending.next_nullifier {
                return Err(LedgerError::Rejected(
                    "defeat evidence must spend the escape's successor nullifier".into(),
                ));
            }
            // Root-free and one packet: no operation account (and no rent) is
            // ever created, and no root change can front-run it.
            let (note, _) = note_address(self.vault, request.note_id, self.program_id);
            let instruction = Instruction {
                program_id: self.program_id,
                accounts: vault_program::accounts::ExecuteChallenge {
                    vault: self.vault,
                    note,
                    pending: pending_address,
                    used_nullifier: nullifier_address(self.vault, pending.nullifier, self.program_id),
                    next_nullifier: nullifier_address(
                        self.vault,
                        pending.next_nullifier,
                        self.program_id,
                    ),
                    payer,
                }
                .to_account_metas(None),
                data: vault_program::instruction::ExecuteChallenge {
                    note_id: request.note_id,
                    payload: vault_program::ChallengePayload {
                        note_id: request.note_id,
                        public_inputs: request_inputs(&request.public_inputs),
                        proof,
                    },
                }
                .data(),
            };
            self.direct_compute_operation(payer, instruction).await
        })
    }

    fn prepare_raise_concession(
        &self,
        request: RaiseConcessionRequest,
    ) -> LedgerFuture<'_, PreparedLedgerOperation> {
        Box::pin(async move {
            let payer = account_pubkey(request.payer);
            let proof = proof_bytes(&request.proof)?;
            let (vault, _) = self.vault_account(LedgerCommitment::Tip).await?;
            assert_request_binding(&vault, &request.public_inputs)?;
            let (pending_address, pending) = self
                .pending_account(request.note_id, LedgerCommitment::Tip)
                .await?;
            if *request.public_inputs.request_nullifier.as_bytes() != pending.nullifier {
                return Err(LedgerError::Rejected(
                    "raise evidence must spend the escaped nullifier".into(),
                ));
            }
            let raised = request
                .amount
                .min(request.public_inputs.solvency_bound)
                .min(u128::from(pending.state_balance));
            if raised <= u128::from(pending.conceded) {
                return Err(LedgerError::Rejected(
                    "raise would not increase the escape's concession".into(),
                ));
            }
            let (note, _) = note_address(self.vault, request.note_id, self.program_id);
            let instruction = Instruction {
                program_id: self.program_id,
                accounts: vault_program::accounts::RaiseEscapeConcession {
                    vault: self.vault,
                    note,
                    pending: pending_address,
                    payer,
                }
                .to_account_metas(None),
                data: vault_program::instruction::RaiseEscapeConcession {
                    note_id: request.note_id,
                    payload: vault_program::ChallengePayload {
                        note_id: request.note_id,
                        public_inputs: request_inputs(&request.public_inputs),
                        proof,
                    },
                    amount: request.amount,
                }
                .data(),
            };
            self.direct_compute_operation(payer, instruction).await
        })
    }

    fn prepare_retire_closed_leaf(
        &self,
        request: RetireClosedLeafRequest,
    ) -> LedgerFuture<'_, PreparedLedgerOperation> {
        Box::pin(async move {
            let payer = account_pubkey(request.payer);
            let (vault, _) = self.vault_account(LedgerCommitment::Tip).await?;
            let note_state = self
                .note_account(request.note_id, LedgerCommitment::Tip)
                .await?;
            if note_state.status != vault_program::NOTE_STATUS_CLOSED {
                return Err(LedgerError::Rejected("note is not closed".into()));
            }
            let old_root =
                Felt252::try_from_bytes_be(vault.current_root).map_err(LedgerError::InvalidData)?;
            let commitment = Felt252::try_from_bytes_be(note_state.commitment)
                .map_err(LedgerError::InvalidData)?;
            let siblings = request.siblings;
            let leaf = core::note_leaf(
                request.note_id,
                &commitment,
                u128::from(note_state.deposit_amount),
                note_state.expiry,
            );
            if core::merkle_root(request.note_id, &leaf, &siblings) != old_root {
                return Err(LedgerError::Rejected(
                    "retirement path does not match the current root".into(),
                ));
            }
            let new_root = core::merkle_root(request.note_id, &Felt252::ZERO, &siblings);
            let transition = SolanaMerkleTransitionInputs {
                protocol_version: PROTOCOL_VERSION,
                chain_id: vault.chain_id,
                protocol_binding: Felt252::try_from_bytes_be(vault.protocol_binding)
                    .map_err(LedgerError::InvalidData)?,
                old_root,
                new_root,
                note_id: request.note_id,
                commitment,
                amount: note_state.deposit_amount,
                expiry: note_state.expiry,
                inserting: false,
            };
            let transition_proof = self.prove_transition(transition, siblings).await?;
            let (note, _) = note_address(self.vault, request.note_id, self.program_id);
            let instruction = Instruction {
                program_id: self.program_id,
                accounts: vault_program::accounts::RetireClosedLeaf {
                    vault: self.vault,
                    note,
                    payer,
                }
                .to_account_metas(None),
                data: vault_program::instruction::RetireClosedLeaf {
                    note_id: request.note_id,
                    new_root: *new_root.as_bytes(),
                    transition_proof,
                }
                .data(),
            };
            self.direct_compute_operation(payer, instruction).await
        })
    }

    fn prepare_finalize_escape(
        &self,
        request: FinalizeEscapeRequest,
    ) -> LedgerFuture<'_, PreparedLedgerOperation> {
        Box::pin(async move {
            let payer = account_pubkey(request.payer);
            // Deployment check only: the operator share accrues in the vault,
            // so finalization never touches the treasury account.
            self.vault_account(LedgerCommitment::Tip).await?;
            let (note, _) = note_address(self.vault, request.note_id, self.program_id);
            let (pending_address, pending) = self
                .pending_account(request.note_id, LedgerCommitment::Tip)
                .await?;
            let instruction = Instruction {
                program_id: self.program_id,
                accounts: vault_program::accounts::FinalizeEscape {
                    vault: self.vault,
                    note,
                    pending: pending_address,
                    payer,
                    destination: pending.destination,
                }
                .to_account_metas(None),
                data: vault_program::instruction::FinalizeEscape {
                    note_id: request.note_id,
                }
                .data(),
            };
            self.direct_operation(payer, instruction).await
        })
    }

    fn prepare_claim_expired(
        &self,
        request: ClaimExpiredRequest,
    ) -> LedgerFuture<'_, PreparedLedgerOperation> {
        Box::pin(async move {
            let payer = account_pubkey(request.payer);
            self.vault_account(LedgerCommitment::Tip).await?;
            let note_state = self
                .note_account(request.note_id, LedgerCommitment::Tip)
                .await?;
            if note_state.status != vault_program::NOTE_STATUS_ACTIVE {
                return Err(LedgerError::Rejected("note is not active".into()));
            }
            // Leaf-bound exits make the claim root-free: the leaf stays in the
            // tree (as for any closed note) until a permissionless retirement.
            let (note, _) = note_address(self.vault, request.note_id, self.program_id);
            let instruction = Instruction {
                program_id: self.program_id,
                accounts: vault_program::accounts::ExecuteClaimExpired {
                    vault: self.vault,
                    note,
                    owner: payer,
                }
                .to_account_metas(None),
                data: vault_program::instruction::ExecuteClaimExpired {
                    note_id: request.note_id,
                }
                .data(),
            };
            self.direct_operation(payer, instruction).await
        })
    }

    fn submit(&self, transaction: SignedLedgerTransaction) -> LedgerFuture<'_, LedgerSubmission> {
        Box::pin(async move {
            if transaction.format != SIGNED_TRANSACTION_FORMAT {
                return Err(LedgerError::InvalidData(format!(
                    "expected {SIGNED_TRANSACTION_FORMAT}"
                )));
            }
            if transaction.bytes.is_empty() || transaction.bytes.len() > 1_232 {
                return Err(LedgerError::InvalidData(
                    "signed Solana transaction is outside the packet limit".into(),
                ));
            }
            self.assert_cluster().await?;
            let encoded = base64::engine::general_purpose::STANDARD.encode(transaction.bytes);
            let signature: String = self
                .rpc(
                    "sendTransaction",
                    json!([
                        encoded,
                        {"encoding":"base64","skipPreflight":false,"preflightCommitment":"confirmed"}
                    ]),
                )
                .await?;
            Ok(LedgerSubmission {
                transaction_id: signature.into_bytes(),
            })
        })
    }

    fn transaction_status(
        &self,
        transaction_id: Vec<u8>,
    ) -> LedgerFuture<'_, LedgerTransactionStatus> {
        Box::pin(async move {
            self.assert_cluster().await?;
            let signature = String::from_utf8(transaction_id)
                .map_err(|error| LedgerError::InvalidData(error.to_string()))?;
            let result: Value = self
                .rpc(
                    "getSignatureStatuses",
                    json!([[signature], {"searchTransactionHistory":true}]),
                )
                .await?;
            let status = &result["value"][0];
            if status.is_null() {
                return Ok(LedgerTransactionStatus::Unknown);
            }
            if !status["err"].is_null() {
                return Ok(LedgerTransactionStatus::Failed {
                    reason: status["err"].to_string(),
                });
            }
            let height = status["slot"].as_u64();
            Ok(match status["confirmationStatus"].as_str() {
                Some("finalized") => LedgerTransactionStatus::Finalized { height },
                Some("confirmed") => LedgerTransactionStatus::Confirmed { height },
                _ => LedgerTransactionStatus::Pending,
            })
        })
    }

    fn transaction_height(&self, commitment: LedgerCommitment) -> LedgerFuture<'_, u64> {
        Box::pin(async move {
            self.assert_cluster().await?;
            self.rpc(
                "getBlockHeight",
                json!([{"commitment": commitment_name(commitment)}]),
            )
            .await
        })
    }
}

impl SolanaCreditLedger {
    async fn pending_account(
        &self,
        note_id: u32,
        commitment: LedgerCommitment,
    ) -> Result<(Pubkey, vault_program::PendingWithdrawal), LedgerError> {
        let (address, expected_bump) = pending_address(self.vault, note_id, self.program_id);
        // Absent, or only lamports sent to the PDA by anyone: no escape.
        let snapshot = match self.account_snapshot(address, commitment).await? {
            Some(snapshot)
                if !(snapshot.owner == anchor_lang::system_program::ID
                    && snapshot.data.is_empty()) =>
            {
                snapshot
            }
            _ => return Err(LedgerError::Rejected("note has no pending escape".into())),
        };
        let pending: vault_program::PendingWithdrawal = self.decode_owned(address, &snapshot)?;
        if pending.vault != self.vault || pending.note_id != note_id || pending.bump != expected_bump
        {
            return Err(LedgerError::DeploymentMismatch(
                "pending withdrawal does not match its canonical PDA".into(),
            ));
        }
        Ok((address, pending))
    }

    async fn prepare_withdrawal(
        &self,
        request: WithdrawalRequest,
        close: bool,
    ) -> Result<PreparedLedgerOperation, LedgerError> {
        let payer = account_pubkey(request.payer);
        let destination = account_pubkey(request.destination);
        let public = &request.public_inputs;
        if !solana_destination_matches(&public.destination, destination.as_array()) {
            return Err(LedgerError::Rejected(
                "withdrawal destination does not match its proof binding".into(),
            ));
        }
        if public.has_clearance != close {
            return Err(LedgerError::Rejected(
                "withdrawal clearance mode does not match operation".into(),
            ));
        }
        if close && (public.next_nullifier != Felt252::ZERO || public.conceded != 0) {
            return Err(LedgerError::Rejected(
                "a mutual close cannot carry a successor nullifier or concession".into(),
            ));
        }
        if !close
            && (public.next_nullifier == Felt252::ZERO
                || public.next_nullifier == public.withdrawal_nullifier)
        {
            return Err(LedgerError::Rejected(
                "an escape must publish a distinct successor nullifier".into(),
            ));
        }
        let proof = proof_bytes(&request.proof)?;
        let note_id = public.note_id;
        let (vault, _) = self.vault_account(LedgerCommitment::Tip).await?;
        if public.protocol_version != PROTOCOL_VERSION
            || public.chain_id != vault.chain_id
            || *public.contract_address.as_bytes() != vault.protocol_binding
            || *public.state_signing_key_x.as_bytes() != vault.state_signing_key_x
            || *public.state_signing_key_y.as_bytes() != vault.state_signing_key_y
            || *public.clearance_signing_key_x.as_bytes() != vault.clearance_signing_key_x
            || *public.clearance_signing_key_y.as_bytes() != vault.clearance_signing_key_y
        {
            return Err(LedgerError::Rejected(
                "withdrawal proof targets a foreign deployment".into(),
            ));
        }
        // Leaf-bound exit: the statement names the note's stored registration
        // and (n, D, e); no root or Merkle path is involved, so unrelated
        // deposits cannot stale it.
        let note_state = self.note_account(note_id, LedgerCommitment::Tip).await?;
        if note_state.status != vault_program::NOTE_STATUS_ACTIVE {
            return Err(LedgerError::Rejected("note is not active".into()));
        }
        let deposit = u128::from(note_state.deposit_amount);
        if *public.registration.as_bytes() != note_state.commitment
            || public.deposit_amount != deposit
            || public.expiry_ts != note_state.expiry
        {
            return Err(LedgerError::Rejected(
                "withdrawal proof is not bound to this note".into(),
            ));
        }
        if public
            .final_balance
            .checked_add(public.conceded)
            .map_or(true, |balance| balance > deposit)
        {
            return Err(LedgerError::Rejected(
                "withdrawal balance exceeds the note deposit".into(),
            ));
        }
        let payload = vault_program::WithdrawalPayload {
            destination,
            public_inputs: withdrawal_inputs(public),
            proof,
        };
        let (note, _) = note_address(self.vault, note_id, self.program_id);
        let used_nullifier = nullifier_address(
            self.vault,
            *public.withdrawal_nullifier.as_bytes(),
            self.program_id,
        );
        let instruction = if close {
            Instruction {
                program_id: self.program_id,
                accounts: vault_program::accounts::ExecuteClose {
                    vault: self.vault,
                    note,
                    used_nullifier,
                    owner: payer,
                    destination,
                    system_program: anchor_lang::system_program::ID,
                }
                .to_account_metas(None),
                data: vault_program::instruction::ExecuteClose { note_id, payload }.data(),
            }
        } else {
            let (pending, _) = pending_address(self.vault, note_id, self.program_id);
            Instruction {
                program_id: self.program_id,
                accounts: vault_program::accounts::ExecuteEscape {
                    vault: self.vault,
                    note,
                    pending,
                    used_nullifier,
                    next_nullifier: nullifier_address(
                        self.vault,
                        *public.next_nullifier.as_bytes(),
                        self.program_id,
                    ),
                    owner: payer,
                    destination,
                    system_program: anchor_lang::system_program::ID,
                }
                .to_account_metas(None),
                data: vault_program::instruction::ExecuteEscape { note_id, payload }.data(),
            }
        };
        self.direct_compute_operation(payer, instruction).await
    }
}

fn immutable_program_data_address(
    program_id: Pubkey,
    account: &SolanaAccountSnapshot,
) -> Result<Pubkey, LedgerError> {
    if account.owner != bpf_loader_upgradeable::ID {
        return Err(LedgerError::DeploymentMismatch(format!(
            "program {program_id} is not owned by the supported loader-v3 program"
        )));
    }
    if !account.executable {
        return Err(LedgerError::DeploymentMismatch(format!(
            "program {program_id} is not executable"
        )));
    }
    if account.data.len() != UpgradeableLoaderState::size_of_program() {
        return Err(LedgerError::DeploymentMismatch(format!(
            "program {program_id} has invalid loader-v3 metadata length"
        )));
    }
    let program_data_address = match bincode::deserialize(&account.data) {
        Ok(UpgradeableLoaderState::Program {
            programdata_address,
        }) => programdata_address,
        _ => {
            return Err(LedgerError::DeploymentMismatch(format!(
                "program {program_id} is not a loader-v3 program account"
            )))
        }
    };
    if program_data_address != bpf_loader_upgradeable::get_program_data_address(&program_id) {
        return Err(LedgerError::DeploymentMismatch(format!(
            "program {program_id} points to an unexpected program-data account"
        )));
    }
    Ok(program_data_address)
}

fn assert_immutable_program_data(
    address: Pubkey,
    account: &SolanaAccountSnapshot,
) -> Result<(), LedgerError> {
    if account.owner != bpf_loader_upgradeable::ID || account.executable {
        return Err(LedgerError::DeploymentMismatch(format!(
            "program-data account {address} has invalid owner or executable state"
        )));
    }
    if account.data.len() < UpgradeableLoaderState::size_of_programdata_metadata() {
        return Err(LedgerError::DeploymentMismatch(format!(
            "program-data account {address} is truncated"
        )));
    }
    match bincode::deserialize(&account.data) {
        Ok(UpgradeableLoaderState::ProgramData {
            upgrade_authority_address: None,
            ..
        }) => Ok(()),
        Ok(UpgradeableLoaderState::ProgramData {
            upgrade_authority_address: Some(_),
            ..
        }) => Err(LedgerError::DeploymentMismatch(format!(
            "program-data account {address} still has an upgrade authority"
        ))),
        _ => Err(LedgerError::DeploymentMismatch(format!(
            "account {address} is not loader-v3 program data"
        ))),
    }
}

fn account_pubkey(account: LedgerAccount) -> Pubkey {
    Pubkey::new_from_array(account.0)
}

fn validate_service_url(label: &str, value: &str) -> Result<(), LedgerError> {
    let url = reqwest::Url::parse(value)
        .map_err(|error| LedgerError::InvalidData(format!("invalid {label} URL: {error}")))?;
    if url.scheme() != "https"
        && !(url.scheme() == "http"
            && matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "::1")))
    {
        return Err(LedgerError::InvalidData(format!(
            "{label} requires HTTPS or loopback HTTP"
        )));
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.query().is_some()
    {
        return Err(LedgerError::InvalidData(format!(
            "{label} URL cannot contain credentials, a query, or a fragment"
        )));
    }
    Ok(())
}

fn commitment_name(commitment: LedgerCommitment) -> &'static str {
    match commitment {
        LedgerCommitment::Tip => "processed",
        LedgerCommitment::Confirmed => "confirmed",
        LedgerCommitment::Finalized => "finalized",
    }
}

fn operation_address(
    vault: Pubkey,
    owner: Pubkey,
    operation_id: [u8; 32],
    program: Pubkey,
) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[b"operation", vault.as_ref(), owner.as_ref(), &operation_id],
        &program,
    )
}

fn note_address(vault: Pubkey, note_id: u32, program: Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"note", vault.as_ref(), &note_id.to_le_bytes()], &program)
}

fn pending_address(vault: Pubkey, note_id: u32, program: Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[b"pending", vault.as_ref(), &note_id.to_le_bytes()],
        &program,
    )
}

fn nullifier_address(vault: Pubkey, nullifier: [u8; 32], program: Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[b"nullifier", vault.as_ref(), &nullifier], &program).0
}

fn proof_bytes(proof: &Groth16ProofWire) -> Result<Vec<u8>, LedgerError> {
    if proof.backend != ProofBackendWire::Groth16Bn254 {
        return Err(LedgerError::Rejected(
            "expected groth16_bn254 proof backend".into(),
        ));
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(&proof.proof)
        .map_err(|error| LedgerError::InvalidData(error.to_string()))?;
    if bytes.len() != 256 {
        return Err(LedgerError::InvalidData(
            "Groth16 proof must contain 256 bytes".into(),
        ));
    }
    Ok(bytes)
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

fn withdrawal_inputs(value: &WithdrawalPublicInputsV2) -> vault_program::WithdrawalInputs {
    vault_program::WithdrawalInputs {
        protocol_version: value.protocol_version,
        chain_id: value.chain_id,
        contract_address: *value.contract_address.as_bytes(),
        registration: *value.registration.as_bytes(),
        state_signing_key_x: *value.state_signing_key_x.as_bytes(),
        state_signing_key_y: *value.state_signing_key_y.as_bytes(),
        clearance_signing_key_x: *value.clearance_signing_key_x.as_bytes(),
        clearance_signing_key_y: *value.clearance_signing_key_y.as_bytes(),
        note_id: value.note_id,
        deposit_amount: value.deposit_amount,
        expiry_ts: value.expiry_ts,
        final_balance: value.final_balance,
        destination: value.destination,
        withdrawal_nullifier: *value.withdrawal_nullifier.as_bytes(),
        has_clearance: value.has_clearance,
        next_nullifier: *value.next_nullifier.as_bytes(),
        conceded: value.conceded,
        valid_until: value.valid_until,
    }
}

/// Reject request evidence bound to another deployment or state key before a
/// challenger pays for a transaction the vault would refuse.
fn assert_request_binding(
    vault: &vault_program::VaultState,
    value: &RequestPublicInputsV2,
) -> Result<(), LedgerError> {
    if value.protocol_version != PROTOCOL_VERSION
        || value.chain_id != vault.chain_id
        || *value.contract_address.as_bytes() != vault.protocol_binding
        || *value.state_signing_key_x.as_bytes() != vault.state_signing_key_x
        || *value.state_signing_key_y.as_bytes() != vault.state_signing_key_y
    {
        return Err(LedgerError::Rejected(
            "request evidence targets a foreign deployment".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anchor_lang::AccountSerialize;

    fn loader_snapshot(state: UpgradeableLoaderState, executable: bool) -> SolanaAccountSnapshot {
        let mut data = bincode::serialize(&state).unwrap();
        if matches!(state, UpgradeableLoaderState::ProgramData { .. }) {
            data.resize(UpgradeableLoaderState::size_of_programdata_metadata(), 0);
            data.extend_from_slice(b"program bytes");
        }
        SolanaAccountSnapshot {
            data,
            owner: bpf_loader_upgradeable::ID,
            executable,
            observed_slot: 42,
        }
    }

    async fn single_response_rpc(result: Value) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 16_384];
            let _ = tokio::io::AsyncReadExt::read(&mut socket, &mut request)
                .await
                .unwrap();
            let body = serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": result,
            }))
            .unwrap();
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            tokio::io::AsyncWriteExt::write_all(&mut socket, head.as_bytes())
                .await
                .unwrap();
            tokio::io::AsyncWriteExt::write_all(&mut socket, &body)
                .await
                .unwrap();
        });
        (format!("http://{address}"), handle)
    }

    async fn response_sequence_rpc(results: Vec<Value>) -> (String, tokio::task::JoinHandle<()>) {
        raw_response_sequence_rpc(results.into_iter().map(|result| {
            json!({"jsonrpc": "2.0", "id": 1, "result": result})
        }).collect()).await
    }

    async fn raw_response_sequence_rpc(replies: Vec<Value>) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            for reply in replies {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = vec![0; 16_384];
                let _ = tokio::io::AsyncReadExt::read(&mut socket, &mut request)
                    .await
                    .unwrap();
                let body = serde_json::to_vec(&reply).unwrap();
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                tokio::io::AsyncWriteExt::write_all(&mut socket, head.as_bytes())
                    .await
                    .unwrap();
                tokio::io::AsyncWriteExt::write_all(&mut socket, &body)
                    .await
                    .unwrap();
            }
        });
        (format!("http://{address}"), handle)
    }

    fn rpc_account(snapshot: &SolanaAccountSnapshot) -> Value {
        json!({
            "context": {"slot": snapshot.observed_slot},
            "value": {
                "owner": snapshot.owner.to_string(),
                "executable": snapshot.executable,
                "data": [
                    base64::engine::general_purpose::STANDARD.encode(&snapshot.data),
                    "base64"
                ]
            }
        })
    }

    #[tokio::test]
    async fn account_pages_check_cardinality_and_context() {
        let addresses: Vec<_> = (0..ACCOUNT_PAGE_SIZE)
            .map(|_| (Pubkey::new_unique(), 0)).collect();
        for (count, slot, valid) in [(100, 44, true), (99, 44, false), (100, 43, false)] {
            let (rpc_url, server) = single_response_rpc(json!({
                "context": {"slot": slot}, "value": vec![Value::Null; count],
            })).await;
            let ledger = SolanaCreditLedger::new(SolanaLedgerConfig {
                rpc_url, indexer_url: None, network: "localnet".into(),
                program_id: vault_program::ID.to_bytes(),
                vault_state: [2; 32], genesis_hash: [3; 32],
            }).unwrap();
            assert_eq!(
                ledger.account_page(&addresses, LedgerCommitment::Tip, 44).await.is_ok(),
                valid,
            );
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn only_transaction_preflight_errors_are_definitive_rejections() {
        let program_failure = json!({"InstructionError": [2, {"Custom": 6000}]});
        for (method, code, err, rejected) in [
            ("sendTransaction", -32002, program_failure.clone(), true),
            ("sendTransaction", -32002, json!("InsufficientFundsForFee"), true),
            // An earlier send landed, or the node lags the plan's blockhash.
            ("sendTransaction", -32002, json!("AlreadyProcessed"), false),
            ("sendTransaction", -32002, json!("BlockhashNotFound"), false),
            ("sendTransaction", -32002, Value::Null, false),
            ("sendTransaction", -32005, program_failure.clone(), false),
            ("getAccountInfo", -32002, program_failure.clone(), false),
        ] {
            let (rpc_url, server) = raw_response_sequence_rpc(vec![json!({
                "jsonrpc": "2.0", "id": 1,
                "error": {
                    "code": code, "message": "simulation failed",
                    "data": {"err": err}
                }
            })]).await;
            let ledger = SolanaCreditLedger::new(SolanaLedgerConfig {
                rpc_url, indexer_url: None, network: "localnet".into(),
                program_id: vault_program::ID.to_bytes(),
                vault_state: [2; 32], genesis_hash: [3; 32],
            }).unwrap();
            let error = ledger.rpc::<Value>(method, json!([])).await.unwrap_err();
            assert_eq!(matches!(error, LedgerError::Rejected(_)), rejected, "{error}");
            if !rejected {
                assert!(matches!(error, LedgerError::Unavailable(_)));
            }
            server.await.unwrap();
        }
    }

    /// Canonical vault state at its PDA for a fresh authority.
    fn test_vault(
        program_id: Pubkey,
        genesis_hash: [u8; 32],
        root: Felt252,
        next_note_id: u32,
    ) -> (Pubkey, vault_program::VaultState) {
        let authority = Pubkey::new_unique();
        let (address, bump) =
            Pubkey::find_program_address(&[b"vault", authority.as_ref()], &program_id);
        let state = vault_program::VaultState {
            version: vault_program::VAULT_VERSION,
            bump,
            paused: false,
            authority,
            treasury: Pubkey::new_unique(),
            genesis_hash,
            chain_id: solana_chain_id(&genesis_hash),
            protocol_binding: *solana_deployment_binding(
                &program_id.to_bytes(), &address.to_bytes(), &genesis_hash,
            ).as_bytes(),
            current_root: *root.as_bytes(),
            next_note_id,
            note_ttl: 86_400,
            challenge_period: 60,
            request_charge_cap: 1_000_000,
            total_credits: 100,
            state_signing_key_x: *Felt252::from_u64(11).as_bytes(),
            state_signing_key_y: *Felt252::from_u64(12).as_bytes(),
            clearance_signing_key_x: *Felt252::from_u64(13).as_bytes(),
            clearance_signing_key_y: *Felt252::from_u64(14).as_bytes(),
            paused_at: 0,
            last_pause_end: 0,
            total_paused_duration: 0,
            treasury_accrued: 0,
        };
        (address, state)
    }

    fn program_account<T: AccountSerialize>(value: &T, program_id: Pubkey) -> Value {
        let mut data = Vec::new();
        value.try_serialize(&mut data).unwrap();
        rpc_account(&SolanaAccountSnapshot {
            data, owner: program_id, executable: false, observed_slot: 44,
        })
    }

    /// Exits are leaf-bound: a pending escape and a closed (or claimed) note
    /// keep their leaf until permissionless retirement, so the live tree must
    /// count them; hiding any of them (e.g. by funding a PDA) breaks the root.
    #[tokio::test]
    async fn live_zero_path_uses_rpc_notes_without_finalized_indexer() {
        let program_id = vault_program::ID;
        let genesis_hash = [3; 32];
        let registration = Felt252::from_u64(17);
        let leaf = |note_id| core::note_leaf(note_id, &registration, 50, 4_000_000_000);
        let mut tree = zkapi_core::MerkleTree::new();
        for note_id in 0..3 {
            tree.set_leaf(note_id, leaf(note_id));
        }
        let (vault_address, vault) = test_vault(program_id, genesis_hash, tree.root(), 4);
        let vault_response = program_account(&vault, program_id);
        let note_value = |note_id: u32, status: u8| {
            let (_, bump) = note_address(vault_address, note_id, program_id);
            program_account(&vault_program::NoteState {
                vault: vault_address, note_id, commitment: *registration.as_bytes(),
                deposit_amount: 50, expiry: 4_000_000_000, status, bump,
                claimable_after: 4_000_000_000, paused_offset: 0,
            }, program_id)["value"].clone()
        };
        let notes = vec![
            note_value(0, vault_program::NOTE_STATUS_PENDING),
            note_value(1, vault_program::NOTE_STATUS_ACTIVE),
            note_value(2, vault_program::NOTE_STATUS_CLOSED),
            note_value(3, vault_program::NOTE_STATUS_RETIRED),
        ];
        // Anyone can fund an unused PDA; it is not program state.
        let unclaimed = json!({
            "owner": anchor_lang::system_program::ID.to_string(), "executable": false,
            "lamports": 890_880, "data": ["", "base64"],
        });
        assert!(is_unclaimed_pda(&unclaimed));
        for variant in 0..12 {
            let mut vault_response = vault_response.clone();
            let mut response = json!({"context": {"slot": 44}, "value": notes});
            match variant {
                0 => {}
                1 => response["value"][1] = Value::Null,
                2 => response["value"][1] = notes[0].clone(),
                3 => response["value"][0]["owner"] = json!(Pubkey::new_unique().to_string()),
                4 => response["context"]["slot"] = json!(43),
                5 => {
                    // A malicious count must not allocate a 2^32-element Vec.
                    // The first bounded page is rejected before growing it.
                    let mut huge = vault.clone();
                    huge.next_note_id = u32::MAX;
                    vault_response = program_account(&huge, program_id);
                }
                // A retired (zero-leaf) slot is unaffected by funding.
                6 => response["value"][3] = unclaimed.clone(),
                // Funding cannot hide a pending or closed leaf.
                7 => response["value"][0] = unclaimed.clone(),
                8 => response["value"][2] = unclaimed.clone(),
                // A claimed-but-unretired closed leaf is not out of the tree.
                9 => response["value"][2] = note_value(2, vault_program::NOTE_STATUS_RETIRED),
                // Status 3 is the reserved, removed two-phase "challenged".
                10 => response["value"][3] = note_value(3, 3),
                11 => response["value"][3] = note_value(3, vault_program::NOTE_STATUS_CLOSED),
                _ => unreachable!(),
            }
            let (rpc_url, server) = response_sequence_rpc(vec![
                json!(Hash::new_from_array(genesis_hash).to_string()),
                vault_response.clone(),
                response,
            ]).await;
            let ledger = SolanaCreditLedger::new(SolanaLedgerConfig {
                rpc_url, indexer_url: None, network: "localnet".into(),
                program_id: program_id.to_bytes(), vault_state: vault_address.to_bytes(),
                genesis_hash,
            }).unwrap();
            let result = ledger.path(3, true, LedgerCommitment::Tip).await;
            if matches!(variant, 0 | 6) {
                let path = result.unwrap();
                assert_eq!(path.state.root, tree.root());
                assert_eq!(path.state.commitment, LedgerCommitment::Tip);
                assert_eq!(path.leaf, Felt252::ZERO);
                assert_eq!(path.siblings, tree.get_siblings(3));
            } else {
                assert!(result.is_err(), "accepted malformed live snapshot {variant}");
            }
            server.await.unwrap();
        }
    }

    #[test]
    fn deployment_binding_matches_shared_helper() {
        let config = SolanaLedgerConfig {
            rpc_url: "http://127.0.0.1:8899".into(),
            indexer_url: None,
            network: "localnet".into(),
            program_id: vault_program::ID.to_bytes(),
            vault_state: [2; 32],
            genesis_hash: [3; 32],
        };
        let ledger = SolanaCreditLedger::new(config.clone()).unwrap();
        assert_eq!(
            ledger.deployment.chain_id,
            solana_chain_id(&config.genesis_hash)
        );
        assert_eq!(
            ledger.deployment.protocol_binding,
            solana_deployment_binding(
                &config.program_id,
                &config.vault_state,
                &config.genesis_hash
            )
        );
        let _: &dyn CreditLedger = &ledger;
    }

    #[test]
    fn immutable_program_policy_accepts_only_final_loader_v3_deployments() {
        let program_id = Pubkey::new_unique();
        let program_data_address = bpf_loader_upgradeable::get_program_data_address(&program_id);
        let program = loader_snapshot(
            UpgradeableLoaderState::Program {
                programdata_address: program_data_address,
            },
            true,
        );
        assert_eq!(
            immutable_program_data_address(program_id, &program).unwrap(),
            program_data_address
        );

        let immutable = loader_snapshot(
            UpgradeableLoaderState::ProgramData {
                slot: 7,
                upgrade_authority_address: None,
            },
            false,
        );
        assert_immutable_program_data(program_data_address, &immutable).unwrap();

        let mutable = loader_snapshot(
            UpgradeableLoaderState::ProgramData {
                slot: 7,
                upgrade_authority_address: Some(Pubkey::new_unique()),
            },
            false,
        );
        assert!(assert_immutable_program_data(program_data_address, &mutable).is_err());

        let mut wrong_loader = program.clone();
        wrong_loader.owner = Pubkey::new_unique();
        assert!(immutable_program_data_address(program_id, &wrong_loader).is_err());

        let mut not_executable = program.clone();
        not_executable.executable = false;
        assert!(immutable_program_data_address(program_id, &not_executable).is_err());

        let wrong_pointer = loader_snapshot(
            UpgradeableLoaderState::Program {
                programdata_address: Pubkey::new_unique(),
            },
            true,
        );
        assert!(immutable_program_data_address(program_id, &wrong_pointer).is_err());

        let mut executable_program_data = immutable.clone();
        executable_program_data.executable = true;
        assert!(
            assert_immutable_program_data(program_data_address, &executable_program_data).is_err()
        );

        let truncated = SolanaAccountSnapshot {
            data: vec![0; UpgradeableLoaderState::size_of_programdata_metadata() - 1],
            ..immutable
        };
        assert!(assert_immutable_program_data(program_data_address, &truncated).is_err());
    }

    #[tokio::test]
    async fn finalized_program_read_requires_revoked_upgrade_authority() {
        let genesis_hash = [3; 32];
        let program_id = Pubkey::new_unique();
        let program_data_address = bpf_loader_upgradeable::get_program_data_address(&program_id);
        let program = loader_snapshot(
            UpgradeableLoaderState::Program {
                programdata_address: program_data_address,
            },
            true,
        );
        let program_data = loader_snapshot(
            UpgradeableLoaderState::ProgramData {
                slot: 7,
                upgrade_authority_address: None,
            },
            false,
        );
        let (rpc_url, server) = response_sequence_rpc(vec![
            Value::String(Hash::new_from_array(genesis_hash).to_string()),
            rpc_account(&program),
            rpc_account(&program_data),
        ])
        .await;
        let ledger = SolanaCreditLedger::new(SolanaLedgerConfig {
            rpc_url,
            indexer_url: None,
            network: "localnet".into(),
            program_id: program_id.to_bytes(),
            vault_state: [2; 32],
            genesis_hash,
        })
        .unwrap();

        ledger.assert_immutable_program().await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn finalized_pending_escape_scan_pages_beyond_one_megabyte() {
        let genesis_hash = [3; 32];
        let program_id = vault_program::ID;
        let count = 4_096;
        let (vault, state) =
            test_vault(program_id, genesis_hash, core::EMPTY_MERKLE_ROOT, count);
        let authority = state.authority;
        let vault_response = program_account(&state, program_id);
        let accounts: Vec<Value> = (0..count).map(|note_id| {
            let (_, bump) = pending_address(vault, note_id, program_id);
            let pending = vault_program::PendingWithdrawal {
                vault, note_id,
                nullifier: *Felt252::from_u64(u64::from(note_id) + 1).as_bytes(),
                next_nullifier: *Felt252::from_u64(u64::from(note_id) + 100_000).as_bytes(),
                state_balance: 10, conceded: 9, final_balance: 1, destination: authority,
                deadline: 1_900_000_000, bump,
            };
            let mut data = Vec::new();
            pending.try_serialize(&mut data).unwrap();
            rpc_account(&SolanaAccountSnapshot {
                data, owner: program_id, executable: false, observed_slot: 44,
            })["value"].clone()
        }).collect();
        assert!(serde_json::to_vec(&accounts).unwrap().len() > MAX_RPC_RESPONSE_BYTES);
        let mut responses = vec![
            json!(Hash::new_from_array(genesis_hash).to_string()), vault_response.clone(),
        ];
        for page in accounts.chunks(ACCOUNT_PAGE_SIZE as usize) {
            let response = json!({"context": {"slot": 44}, "value": page});
            assert!(serde_json::to_vec(&response).unwrap().len() < MAX_RPC_RESPONSE_BYTES);
            responses.push(response);
        }
        responses.push(json!(1_800_000_000i64));
        let (rpc_url, server) = response_sequence_rpc(responses).await;
        let ledger = SolanaCreditLedger::new(SolanaLedgerConfig {
            rpc_url, indexer_url: None, network: "localnet".into(),
            program_id: program_id.to_bytes(), vault_state: vault.to_bytes(), genesis_hash,
        }).unwrap();
        let escapes = ledger.pending_escapes(LedgerCommitment::Finalized).await.unwrap();
        assert_eq!(escapes.len(), count as usize);
        for (note_id, escape) in escapes.iter().enumerate() {
            assert_eq!(escape.note_id, note_id as u32);
            assert_eq!(escape.nullifier, Felt252::from_u64(note_id as u64 + 1));
            assert_eq!(escape.next_nullifier, Felt252::from_u64(note_id as u64 + 100_000));
            assert_eq!((escape.state_balance, escape.conceded), (10, 9));
            assert_eq!(escape.observed_time, Some(1_800_000_000));
        }
        server.await.unwrap();

        // Funding the pending PDA of a non-escaped note (a System transfer
        // anyone can make) must not hide the real escapes from the challenger.
        let unclaimed = json!({
            "owner": anchor_lang::system_program::ID.to_string(), "executable": false,
            "lamports": 890_880, "data": ["", "base64"],
        });
        let mut funded = accounts.clone();
        funded[7] = unclaimed.clone();
        funded[count as usize - 1] = unclaimed;
        let mut responses = vec![
            json!(Hash::new_from_array(genesis_hash).to_string()), vault_response.clone(),
        ];
        for page in funded.chunks(ACCOUNT_PAGE_SIZE as usize) {
            responses.push(json!({"context": {"slot": 44}, "value": page}));
        }
        responses.push(json!(1_800_000_000i64));
        let (rpc_url, server) = response_sequence_rpc(responses).await;
        let ledger = SolanaCreditLedger::new(SolanaLedgerConfig {
            rpc_url, ..ledger.config.clone()
        }).unwrap();
        let escapes = ledger.pending_escapes(LedgerCommitment::Finalized).await.unwrap();
        assert_eq!(escapes.len(), count as usize - 2);
        assert!(escapes.iter().all(|escape| escape.note_id != 7 && escape.note_id != count - 1));
        assert!(escapes.iter().any(|escape| escape.note_id == 8));
        server.await.unwrap();

        let mut wrong_accounts = accounts[..ACCOUNT_PAGE_SIZE as usize].to_vec();
        wrong_accounts.swap(0, 1);
        let (rpc_url, server) = response_sequence_rpc(vec![
            json!(Hash::new_from_array(genesis_hash).to_string()),
            vault_response,
            json!({"context": {"slot": 44}, "value": wrong_accounts}),
        ]).await;
        let ledger = SolanaCreditLedger::new(SolanaLedgerConfig {
            rpc_url, ..ledger.config.clone()
        }).unwrap();
        assert!(matches!(
            ledger.pending_escapes(LedgerCommitment::Finalized).await,
            Err(LedgerError::DeploymentMismatch(_)),
        ));
        server.await.unwrap();

        // A record whose payout plus concession is not its state balance is
        // malformed, not silently passed to the challenger's raise policy.
        let (_, bump) = pending_address(vault, 0, program_id);
        let mut inconsistent = accounts[..ACCOUNT_PAGE_SIZE as usize].to_vec();
        inconsistent[0] = program_account(&vault_program::PendingWithdrawal {
            vault, note_id: 0, nullifier: *Felt252::ONE.as_bytes(),
            next_nullifier: *Felt252::from_u64(2).as_bytes(), state_balance: 10, conceded: 3,
            final_balance: 1, destination: authority, deadline: 1_900_000_000, bump,
        }, program_id)["value"].clone();
        let (rpc_url, server) = response_sequence_rpc(vec![
            json!(Hash::new_from_array(genesis_hash).to_string()),
            program_account(&state, program_id),
            json!({"context": {"slot": 44}, "value": inconsistent}),
        ]).await;
        let ledger = SolanaCreditLedger::new(SolanaLedgerConfig {
            rpc_url, ..ledger.config.clone()
        }).unwrap();
        assert!(matches!(
            ledger.pending_escapes(LedgerCommitment::Finalized).await,
            Err(LedgerError::InvalidData(_)),
        ));
        server.await.unwrap();
    }

    #[test]
    fn runtime_view_exposes_only_normalized_startup_metadata() {
        let root = Felt252::from_u64(7);
        let state_x = Felt252::from_u64(11);
        let state_y = Felt252::from_u64(12);
        let clear_x = Felt252::from_u64(13);
        let clear_y = Felt252::from_u64(14);
        let view = runtime_view(
            vault_program::VaultState {
                version: vault_program::VAULT_VERSION,
                bump: 1,
                paused: true,
                authority: Pubkey::new_unique(),
                treasury: Pubkey::new_unique(),
                genesis_hash: [3; 32],
                chain_id: 9,
                protocol_binding: [4; 32],
                current_root: *root.as_bytes(),
                next_note_id: 17,
                note_ttl: 86_400,
                challenge_period: 60,
                request_charge_cap: 1_000_000,
                total_credits: 2_000_000,
                state_signing_key_x: *state_x.as_bytes(),
                state_signing_key_y: *state_y.as_bytes(),
                clearance_signing_key_x: *clear_x.as_bytes(),
                clearance_signing_key_y: *clear_y.as_bytes(),
                paused_at: 1_900_000_000,
                last_pause_end: 0,
                total_paused_duration: 0,
                treasury_accrued: 0,
            },
            42,
            LedgerCommitment::Finalized,
        )
        .unwrap();

        assert_eq!(view.state.root, root);
        assert_eq!(view.state.next_note_id, 17);
        assert_eq!(view.state.observed_height, Some(42));
        assert_eq!(view.state.commitment, LedgerCommitment::Finalized);
        assert!(view.paused);
        assert_eq!(view.request_charge_cap, 1_000_000);
        assert_eq!(view.challenge_period, 60);
        assert_eq!(view.state_signing_key_x, state_x);
        assert_eq!(view.state_signing_key_y, state_y);
        assert_eq!(view.clearance_signing_key_x, clear_x);
        assert_eq!(view.clearance_signing_key_y, clear_y);
    }

    #[test]
    fn every_staged_chunk_fits_a_solana_packet() {
        let payer = Pubkey::new_unique();
        let operation = Pubkey::new_unique();
        let instruction = Instruction {
            program_id: vault_program::ID,
            accounts: vault_program::accounts::WriteOperation {
                vault: Pubkey::new_unique(),
                operation,
                owner: payer,
            }
            .to_account_metas(None),
            data: vault_program::instruction::WriteOperation {
                offset: 0,
                chunk: vec![9; OPERATION_CHUNK_BYTES],
            }
            .data(),
        };
        let prepared =
            SolanaCreditLedger::message(instruction, payer, Hash::new_unique(), 10).unwrap();
        assert!(prepared.bytes.len() + 65 <= 1_232);
    }

    /// Exits and disputes are single, root-free transactions: no operation
    /// account can be orphaned (no rent leak) and no multi-transaction window
    /// lets a root change front-run them. Sizes use maximal field values.
    #[test]
    fn every_exit_and_dispute_fits_one_packet() {
        use vault_program::{accounts, instruction};
        let payer = Pubkey::new_unique();
        let vault = Pubkey::new_unique();
        let destination = Pubkey::new_unique();
        let system_program = anchor_lang::system_program::ID;
        let felt = [7; 32];
        let unique = Pubkey::new_unique;
        let withdrawal = vault_program::WithdrawalPayload {
            destination,
            public_inputs: vault_program::WithdrawalInputs {
                protocol_version: u16::MAX,
                chain_id: u64::MAX,
                contract_address: felt,
                registration: felt,
                state_signing_key_x: felt,
                state_signing_key_y: felt,
                clearance_signing_key_x: felt,
                clearance_signing_key_y: felt,
                note_id: u32::MAX,
                deposit_amount: u128::MAX,
                expiry_ts: u64::MAX,
                final_balance: u128::MAX,
                destination: [9; 20],
                withdrawal_nullifier: felt,
                has_clearance: true,
                next_nullifier: felt,
                conceded: u128::MAX,
                valid_until: u64::MAX,
            },
            proof: vec![9; 256],
        };
        let evidence = vault_program::ChallengePayload {
            note_id: u32::MAX,
            public_inputs: vault_program::RequestInputs {
                protocol_version: u16::MAX,
                chain_id: u64::MAX,
                contract_address: felt,
                active_root: felt,
                state_signing_key_x: felt,
                state_signing_key_y: felt,
                request_time: u64::MAX,
                solvency_bound: u128::MAX,
                request_nullifier: felt,
                authorization_tag: felt,
                anonymous_commitment_x: felt,
                anonymous_commitment_y: felt,
            },
            proof: vec![9; 256],
        };
        let build = |accounts, data| Instruction { program_id: vault_program::ID, accounts, data };
        let cases = [
            ("escape", true, build(
                accounts::ExecuteEscape {
                    vault, note: unique(), pending: unique(), used_nullifier: unique(),
                    next_nullifier: unique(), owner: payer, destination, system_program,
                }.to_account_metas(None),
                instruction::ExecuteEscape { note_id: u32::MAX, payload: withdrawal.clone() }.data(),
            )),
            ("close", true, build(
                accounts::ExecuteClose {
                    vault, note: unique(), used_nullifier: unique(), owner: payer, destination,
                    system_program,
                }.to_account_metas(None),
                instruction::ExecuteClose { note_id: u32::MAX, payload: withdrawal }.data(),
            )),
            ("defeat", false, build(
                accounts::ExecuteChallenge {
                    vault, note: unique(), pending: unique(), used_nullifier: unique(),
                    next_nullifier: unique(), payer,
                }.to_account_metas(None),
                instruction::ExecuteChallenge { note_id: u32::MAX, payload: evidence.clone() }.data(),
            )),
            ("raise", false, build(
                accounts::RaiseEscapeConcession { vault, note: unique(), pending: unique(), payer }
                    .to_account_metas(None),
                instruction::RaiseEscapeConcession {
                    note_id: u32::MAX, payload: evidence, amount: u128::MAX,
                }.data(),
            )),
            ("retire", true, build(
                accounts::RetireClosedLeaf { vault, note: unique(), payer }.to_account_metas(None),
                instruction::RetireClosedLeaf {
                    note_id: u32::MAX, new_root: felt, transition_proof: vec![9; 256],
                }.data(),
            )),
            ("withdraw_treasury", true, build(
                accounts::WithdrawTreasury { vault, treasury: unique() }.to_account_metas(None),
                instruction::WithdrawTreasury {}.data(),
            )),
            ("claim_expired", true, build(
                accounts::ExecuteClaimExpired { vault, note: unique(), owner: payer }
                    .to_account_metas(None),
                instruction::ExecuteClaimExpired { note_id: u32::MAX }.data(),
            )),
        ];
        for (name, vault_writable, instruction) in cases {
            // The SDK transport pins the vault as the first vault-ix account;
            // root-free disputes must not take the vault write lock.
            assert_eq!(instruction.accounts[0].pubkey, vault, "{name}");
            assert_eq!(instruction.accounts[0].is_writable, vault_writable, "{name}");
            let prepared = SolanaCreditLedger::compute_intensive_message(
                instruction, payer, Hash::new_unique(), 10,
            )
            .unwrap();
            eprintln!("{name}: {} of 1232 signed bytes", prepared.bytes.len() + 65);
            assert!(prepared.bytes.len() + 65 <= 1_232, "{name}");
        }
    }

    /// A defeat releases N⁺ (status 0) so the operator may serve the
    /// successor again; consumed and challenged nullifiers stay spent. A
    /// System-owned PDA funded by anyone (F7) is not a spent nullifier.
    #[tokio::test]
    async fn nullifier_status_maps_released_consumed_and_challenged() {
        let genesis_hash = [3; 32];
        let vault = Pubkey::new_from_array([2; 32]);
        let nullifier = Felt252::from_u64(9);
        let (_, bump) = Pubkey::find_program_address(
            &[b"nullifier", vault.as_ref(), nullifier.as_bytes()],
            &vault_program::ID,
        );
        let used = |status, bump| program_account(&vault_program::UsedNullifier {
            vault, nullifier: *nullifier.as_bytes(), bump, status,
        }, vault_program::ID);
        let bare = |owner| rpc_account(&SolanaAccountSnapshot {
            data: Vec::new(), owner, executable: false, observed_slot: 44,
        });
        use LedgerNullifierStatus::{Unused, Used};
        for (account, expected) in [
            (json!({"context": {"slot": 44}, "value": null}), Some(Unused)),
            (bare(anchor_lang::system_program::ID), Some(Unused)),
            (bare(Pubkey::new_unique()), None),
            (used(vault_program::NULLIFIER_RELEASED, bump), Some(Unused)),
            (used(vault_program::NULLIFIER_CONSUMED, bump), Some(Used)),
            (used(vault_program::NULLIFIER_CHALLENGED, bump), Some(Used)),
            (used(7, bump), None),
            (used(vault_program::NULLIFIER_CONSUMED, bump.wrapping_sub(1)), None),
        ] {
            let (rpc_url, server) = response_sequence_rpc(vec![
                json!(Hash::new_from_array(genesis_hash).to_string()),
                account,
            ])
            .await;
            let ledger = SolanaCreditLedger::new(SolanaLedgerConfig {
                rpc_url, indexer_url: None, network: "localnet".into(),
                program_id: vault_program::ID.to_bytes(), vault_state: vault.to_bytes(), genesis_hash,
            })
            .unwrap();
            let status = ledger.nullifier_status(nullifier, LedgerCommitment::Tip).await;
            assert_eq!(status.as_ref().ok().copied(), expected, "{status:?}");
            server.await.unwrap();
        }
    }

    /// The challenger's prepared transactions enforce the concession rule
    /// before paying fees: only evidence at N⁺ defeats (stale escape), evidence
    /// at N only raises (under-concession), and only when the raise is real.
    #[tokio::test]
    async fn disputes_route_evidence_by_nullifier_and_concession() {
        let program_id = vault_program::ID;
        let genesis_hash = [3; 32];
        let (vault_address, vault) =
            test_vault(program_id, genesis_hash, core::EMPTY_MERKLE_ROOT, 1);
        let (escaped, successor) = (Felt252::from_u64(901), Felt252::from_u64(902));
        let (_, bump) = pending_address(vault_address, 0, program_id);
        let pending = vault_program::PendingWithdrawal {
            vault: vault_address, note_id: 0, nullifier: *escaped.as_bytes(),
            next_nullifier: *successor.as_bytes(), state_balance: 10, conceded: 3,
            final_balance: 7, destination: Pubkey::new_unique(), deadline: 1_900_000_000, bump,
        };
        let request = |nullifier, solvency_bound| RequestPublicInputsV2 {
            protocol_version: PROTOCOL_VERSION,
            chain_id: vault.chain_id,
            contract_address: Felt252::try_from_bytes_be(vault.protocol_binding).unwrap(),
            active_root: Felt252::from_u64(5),
            state_signing_key_x: Felt252::from_u64(11),
            state_signing_key_y: Felt252::from_u64(12),
            request_time: 1,
            solvency_bound,
            request_nullifier: nullifier,
            authorization_tag: Felt252::from_u64(6),
            anonymous_commitment_x: Felt252::from_u64(7),
            anonymous_commitment_y: Felt252::from_u64(8),
        };
        let proof = Groth16ProofWire {
            backend: ProofBackendWire::Groth16Bn254,
            proof: base64::engine::general_purpose::STANDARD.encode([9; 256]),
        };
        let payer = LedgerAccount::new([6; 32]);
        let genesis = json!(Hash::new_from_array(genesis_hash).to_string());
        let mut foreign = request(successor, 10);
        foreign.chain_id = foreign.chain_id.wrapping_add(1);
        // (defeat?, request, raise amount, RPC replies consumed, accepted)
        let cases = [
            (true, request(successor, 10), 0, 3, true),
            (true, request(escaped, 10), 0, 3, false),
            (true, foreign.clone(), 0, 2, false),
            (false, request(successor, 10), 10, 3, false),
            (false, request(escaped, 5), 100, 3, true),
            (false, request(escaped, 3), 100, 3, false),
            (false, request(escaped, 100), 2, 3, false),
            (false, foreign, 100, 2, false),
        ];
        for (index, (defeat, public_inputs, amount, reads, accepted)) in
            cases.into_iter().enumerate()
        {
            let mut responses = vec![
                genesis.clone(),
                program_account(&vault, program_id),
                program_account(&pending, program_id),
            ];
            responses.truncate(reads);
            if accepted {
                responses.push(genesis.clone());
                responses.push(json!({"context": {"slot": 44}, "value": {
                    "blockhash": Hash::new_unique().to_string(), "lastValidBlockHeight": 10,
                }}));
            }
            let (rpc_url, server) = response_sequence_rpc(responses).await;
            let ledger = SolanaCreditLedger::new(SolanaLedgerConfig {
                rpc_url, indexer_url: None, network: "localnet".into(),
                program_id: program_id.to_bytes(), vault_state: vault_address.to_bytes(),
                genesis_hash,
            }).unwrap();
            let result = if defeat {
                ledger.prepare_challenge(ChallengeRequest {
                    payer, note_id: 0, public_inputs, proof: proof.clone(),
                }).await
            } else {
                ledger.prepare_raise_concession(RaiseConcessionRequest {
                    payer, note_id: 0, public_inputs, proof: proof.clone(), amount,
                }).await
            };
            if accepted {
                assert_eq!(result.unwrap().transactions.len(), 1, "case {index}");
            } else {
                assert!(matches!(result, Err(LedgerError::Rejected(_))), "case {index}");
            }
            server.await.unwrap();
        }
    }

    /// Exits accrue the operator share in the vault; anyone may sweep it to
    /// the pinned treasury, and nothing is prepared when nothing accrued.
    #[tokio::test]
    async fn treasury_sweep_targets_the_pinned_treasury_only_when_accrued() {
        let program_id = vault_program::ID;
        let genesis_hash = [3; 32];
        let genesis = json!(Hash::new_from_array(genesis_hash).to_string());
        for accrued in [0, 250_000] {
            let (vault_address, mut vault) =
                test_vault(program_id, genesis_hash, core::EMPTY_MERKLE_ROOT, 0);
            vault.treasury_accrued = accrued;
            let mut responses = vec![genesis.clone(), program_account(&vault, program_id)];
            if accrued > 0 {
                responses.push(genesis.clone());
                responses.push(json!({"context": {"slot": 44}, "value": {
                    "blockhash": Hash::new_unique().to_string(), "lastValidBlockHeight": 10,
                }}));
            }
            let (rpc_url, server) = response_sequence_rpc(responses).await;
            let ledger = SolanaCreditLedger::new(SolanaLedgerConfig {
                rpc_url, indexer_url: None, network: "localnet".into(),
                program_id: program_id.to_bytes(), vault_state: vault_address.to_bytes(),
                genesis_hash,
            }).unwrap();
            let result = ledger.prepare_withdraw_treasury(LedgerAccount::new([6; 32])).await;
            if accrued == 0 {
                assert!(matches!(result, Err(LedgerError::Rejected(_))));
            } else {
                let operation = result.unwrap();
                assert_eq!(operation.transactions.len(), 1);
                let message: Message =
                    bincode::deserialize(&operation.transactions[0].bytes).unwrap();
                assert!(message.account_keys.contains(&vault.treasury));
                assert_eq!(message.account_keys[0], Pubkey::new_from_array([6; 32]));
            }
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn rpc_cluster_identity_is_verified_before_ledger_use() {
        let (rpc_url, server) =
            single_response_rpc(Value::String(Hash::new_from_array([4; 32]).to_string())).await;
        let ledger = SolanaCreditLedger::new(SolanaLedgerConfig {
            rpc_url,
            indexer_url: None,
            network: "localnet".into(),
            program_id: vault_program::ID.to_bytes(),
            vault_state: [2; 32],
            genesis_hash: [3; 32],
        })
        .unwrap();
        assert!(matches!(
            ledger.assert_cluster().await,
            Err(LedgerError::DeploymentMismatch(_))
        ));
        server.await.unwrap();
    }

    #[test]
    fn service_urls_and_deployment_identity_fail_closed() {
        let fixture = |rpc_url: &str, indexer_url: Option<&str>| SolanaLedgerConfig {
            rpc_url: rpc_url.into(),
            indexer_url: indexer_url.map(str::to_string),
            network: "localnet".into(),
            program_id: vault_program::ID.to_bytes(),
            vault_state: [2; 32],
            genesis_hash: [3; 32],
        };
        assert!(SolanaCreditLedger::new(fixture("http://rpc.example", None)).is_err());
        assert!(
            SolanaCreditLedger::new(fixture("https://rpc.example/?token=secret", None)).is_err()
        );
        assert!(SolanaCreditLedger::new(fixture(
            "https://rpc.example",
            Some("http://indexer.example")
        ))
        .is_err());
        let mut zero = fixture("https://rpc.example", None);
        zero.genesis_hash = [0; 32];
        assert!(SolanaCreditLedger::new(zero).is_err());
    }
}
