//! Explicit local-validator integration tests of the USDC vault lifecycle.
//!
//! Start the profile-bound validator with `scripts/localnet/stack.mjs` (real
//! classic Token program, cloned mainnet USDC mint, a USDC faucet account, a
//! frozen USDC account and the test-only PDA signer program), export
//! `DAGON_SOLANA_RPC_URL`, `DAGON_USDC_FAUCET_KEYPAIR`,
//! `DAGON_USDC_FROZEN_ACCOUNT`, `DAGON_USDC_FROZEN_OWNER_KEYPAIR` and
//! `DAGON_TEST_PDA_SIGNER_PROGRAM`, then run:
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
//! - asset substitution: a foreign classic mint (as source and as `mint`), a
//!   Token-2022 account (as source and as destination) or token program, a
//!   forged program-owned account, the vault token account itself, and a
//!   frozen USDC account are all refused;
//! - payout substitution: only the proof-bound token account (any owner,
//!   including an off-curve PDA) and only the pinned treasury account can be
//!   paid; a destination closed before finalize parks the payout, which a
//!   permissionless release pays exactly once after the account is recreated;
//! - donations into the vault token account stay surplus: after every step
//!   `vault balance >= total_credits + treasury_accrued + deferred_payouts`
//!   and the excess equals the cumulative donations;
//! - double payout: replayed close, second finalize/release, claim after close
//!   and a second treasury withdrawal pay nothing;
//! - CPI deposit: a program PDA is the USDC token authority while the outer
//!   signer owns and pays for the operation.

use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anchor_lang::{AccountDeserialize, InstructionData, ToAccountMetas};
use base64::Engine;
use dagon_zkapi_ledger::{
    ChallengeRequest, ClaimExpiredRequest, CreditLedger, DepositRequest, FinalizeEscapeRequest,
    LedgerAccount, LedgerCommitment, LedgerError, LedgerNullifierStatus, PreparedLedgerOperation,
    PreparedLedgerTransaction, RaiseConcessionRequest, ReleaseEscapePayoutRequest,
    RetireClosedLeafRequest, WithdrawalRequest,
};
use dagon_zkapi_profile::{
    usdc_associated_token_address, vault_token_address, NetworkIdentity, ResolvedIdentity,
    SharedProfile, IDENTITY_SCHEMA,
};
use dagon_zkapi_solana_ledger::{
    check_vault_profile, create_usdc_ata_idempotent_instruction, SolanaCreditLedger,
    SolanaLedgerConfig,
};
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
use vault_program::token::{TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID, USDC_DECIMALS, USDC_MINT};
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

/// USDC base units (micro-USD) per note: covers the profile's request charge
/// cap, the smallest request bound the server signs, with room for the
/// charges below.
const DEPOSIT: u128 = 25_000_000;
/// The classic Token program's `AccountFrozen` error.
const TOKEN_ERROR_ACCOUNT_FROZEN: u32 = 17;

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

fn env_var(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is required (see the module docs)"))
}

fn read_keypair(path: &str) -> Keypair {
    let bytes: Vec<u8> = serde_json::from_str(
        &std::fs::read_to_string(path).unwrap_or_else(|error| panic!("{path}: {error}")),
    )
    .unwrap();
    Keypair::try_from(bytes.as_slice()).unwrap()
}

fn usdc_ata(owner: Pubkey) -> Pubkey {
    Pubkey::new_from_array(usdc_associated_token_address(&owner.to_bytes()))
}

/// The local accounts the stack provides.
struct Stack {
    rpc_url: String,
    faucet: Keypair,
    frozen_account: Pubkey,
    frozen_owner: Keypair,
    pda_signer_program: Pubkey,
}

impl Stack {
    fn from_env() -> Self {
        Self {
            rpc_url: env_var("DAGON_SOLANA_RPC_URL"),
            faucet: read_keypair(&env_var("DAGON_USDC_FAUCET_KEYPAIR")),
            frozen_account: Pubkey::from_str(&env_var("DAGON_USDC_FROZEN_ACCOUNT")).unwrap(),
            frozen_owner: read_keypair(&env_var("DAGON_USDC_FROZEN_OWNER_KEYPAIR")),
            pda_signer_program: Pubkey::from_str(&env_var("DAGON_TEST_PDA_SIGNER_PROGRAM"))
                .unwrap(),
        }
    }
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

    /// A vault instruction with the proof-verification compute budget.
    fn budgeted(instruction: Instruction) -> Vec<Instruction> {
        vec![
            ComputeBudgetInstruction::request_heap_frame(128 * 1_024),
            ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
            instruction,
        ]
    }

    async fn instruction_message(&self, instruction: Instruction, signer: &Keypair) -> Vec<u8> {
        Message::new_with_blockhash(
            &Self::budgeted(instruction),
            Some(&signer.pubkey()),
            &self.latest_blockhash().await,
        )
        .serialize()
    }

    async fn send_instruction(&self, instruction: Instruction, signer: &Keypair) -> String {
        let message = self.instruction_message(instruction, signer).await;
        self.send_message(message, signer).await
    }

    /// Submit a signed transaction with preflight; return the RPC error
    /// instead of panicking.
    async fn try_submit(&self, transaction: Vec<u8>) -> Result<String, Value> {
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

    async fn try_send_message(&self, message: Vec<u8>, signer: &Keypair) -> Result<String, Value> {
        let signature = signer.sign_message(&message);
        let mut transaction = Vec::with_capacity(1 + 64 + message.len());
        transaction.push(1);
        transaction.extend_from_slice(signature.as_ref());
        transaction.extend_from_slice(&message);
        self.try_submit(transaction).await
    }

    async fn send_message(&self, message: Vec<u8>, signer: &Keypair) -> String {
        self.try_send_message(message, signer)
            .await
            .unwrap_or_else(|error| panic!("transaction rejected: {error}"))
    }

    /// Sign `instructions` with every required signer (the first pays).
    async fn try_send_signed(
        &self,
        instructions: &[Instruction],
        signers: &[&Keypair],
    ) -> Result<String, Value> {
        let message = Message::new_with_blockhash(
            instructions,
            Some(&signers[0].pubkey()),
            &self.latest_blockhash().await,
        );
        let bytes = message.serialize();
        let required = usize::from(message.header.num_required_signatures);
        assert!(required < 128);
        let mut transaction = vec![required as u8];
        for key in &message.account_keys[..required] {
            let signer = signers
                .iter()
                .find(|signer| signer.pubkey() == *key)
                .unwrap_or_else(|| panic!("missing signer {key}"));
            transaction.extend_from_slice(signer.sign_message(&bytes).as_ref());
        }
        transaction.extend_from_slice(&bytes);
        self.try_submit(transaction).await
    }

    async fn send_signed(&self, instructions: &[Instruction], signers: &[&Keypair]) -> String {
        self.try_send_signed(instructions, signers)
            .await
            .unwrap_or_else(|error| panic!("transaction rejected: {error}"))
    }

    /// A raw vault instruction with the proof compute budget.
    async fn try_vault(
        &self,
        instruction: Instruction,
        signers: &[&Keypair],
    ) -> Result<String, Value> {
        self.try_send_signed(&Self::budgeted(instruction), signers)
            .await
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

    /// Send every staged transaction of a deposit but its execute, and
    /// return the decoded execute instruction for the caller to submit (or
    /// tamper with). A failed execute leaves the staged buffer reusable.
    async fn stage(&self, mut operation: PreparedLedgerOperation, signer: &Keypair) -> Instruction {
        let execute = operation.transactions.pop().unwrap();
        assert!(!operation.transactions.is_empty(), "deposits stay staged");
        self.send_operation(operation, signer).await;
        vault_instruction(&execute)
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

    /// The amount held by a classic-Token account.
    async fn token_amount(&self, address: Pubkey) -> u64 {
        let value = self
            .account_value(address)
            .await
            .unwrap_or_else(|| panic!("token account {address} does not exist"));
        assert_eq!(
            value["owner"].as_str(),
            Some(TOKEN_PROGRAM_ID.to_string().as_str())
        );
        let data = base64::engine::general_purpose::STANDARD
            .decode(value["data"][0].as_str().unwrap())
            .unwrap();
        assert_eq!(data.len(), 165);
        u64::from_le_bytes(data[64..72].try_into().unwrap())
    }

    async fn rent(&self, space: usize) -> u64 {
        self.call("getMinimumBalanceForRentExemption", json!([space]))
            .await
    }

    /// The validator's `Clock::unix_timestamp`, exactly what the program
    /// compares deadlines and expiries with. Never the host clock: a stack
    /// may run its validator at an offset time.
    async fn chain_time(&self) -> u64 {
        let value = self
            .account_value(Pubkey::from_str("SysvarC1ock11111111111111111111111111111111").unwrap())
            .await
            .expect("Clock sysvar");
        let data = base64::engine::general_purpose::STANDARD
            .decode(value["data"][0].as_str().unwrap())
            .unwrap();
        u64::try_from(i64::from_le_bytes(data[32..40].try_into().unwrap())).unwrap()
    }

    async fn wait_until_after_for(&self, deadline: u64, polls: u32) {
        for _ in 0..polls {
            if self.chain_time().await > deadline {
                return;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        panic!("validator clock did not pass {deadline}");
    }

    async fn wait_until_after(&self, deadline: u64) {
        self.wait_until_after_for(deadline, 480).await;
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
        self.send_signed(&[transfer], &[signer]).await;
    }

    async fn airdrop(&self, address: Pubkey, lamports: u64) {
        let signature: String = self
            .call("requestAirdrop", json!([address.to_string(), lamports]))
            .await;
        self.wait_confirmed(&signature).await;
    }

    /// Create `owner`'s canonical USDC ATA (idempotent).
    async fn create_usdc_ata(&self, payer: &Keypair, owner: Pubkey) -> Pubkey {
        self.send_signed(
            &[create_usdc_ata_idempotent_instruction(
                &payer.pubkey(),
                &owner,
            )],
            &[payer],
        )
        .await;
        usdc_ata(owner)
    }

    /// Move faucet USDC; `payer` pays the fee.
    async fn fund_usdc(&self, stack: &Stack, payer: &Keypair, destination: Pubkey, amount: u64) {
        let transfer = transfer_checked_ix(
            TOKEN_PROGRAM_ID,
            usdc_ata(stack.faucet.pubkey()),
            USDC_MINT,
            destination,
            stack.faucet.pubkey(),
            amount,
            USDC_DECIMALS,
        );
        self.send_signed(&[transfer], &[payer, &stack.faucet]).await;
    }

    /// A fresh mint under `program` (classic Token or Token-2022, no
    /// extensions) with `authority` as mint authority.
    async fn create_mint(&self, payer: &Keypair, program: Pubkey, authority: Pubkey) -> Pubkey {
        let mint = Keypair::new();
        let rent = self.rent(82).await;
        let mut initialize = vec![20, USDC_DECIMALS];
        initialize.extend_from_slice(authority.as_ref());
        initialize.push(0);
        self.send_signed(
            &[
                create_account_ix(payer.pubkey(), mint.pubkey(), rent, 82, program),
                Instruction {
                    program_id: program,
                    accounts: vec![AccountMeta::new(mint.pubkey(), false)],
                    data: initialize,
                },
            ],
            &[payer, &mint],
        )
        .await;
        mint.pubkey()
    }

    /// Initialize a token account at `account`'s address.
    async fn create_token_account(
        &self,
        payer: &Keypair,
        account: &Keypair,
        program: Pubkey,
        mint: Pubkey,
        owner: Pubkey,
    ) {
        let rent = self.rent(165).await;
        let mut initialize = vec![18];
        initialize.extend_from_slice(owner.as_ref());
        self.send_signed(
            &[
                create_account_ix(payer.pubkey(), account.pubkey(), rent, 165, program),
                Instruction {
                    program_id: program,
                    accounts: vec![
                        AccountMeta::new(account.pubkey(), false),
                        AccountMeta::new_readonly(mint, false),
                    ],
                    data: initialize,
                },
            ],
            &[payer, account],
        )
        .await;
    }

    async fn mint_to(
        &self,
        payer: &Keypair,
        program: Pubkey,
        mint: Pubkey,
        account: Pubkey,
        amount: u64,
    ) {
        let mut data = vec![7];
        data.extend_from_slice(&amount.to_le_bytes());
        self.send_signed(
            &[Instruction {
                program_id: program,
                accounts: vec![
                    AccountMeta::new(mint, false),
                    AccountMeta::new(account, false),
                    AccountMeta::new_readonly(payer.pubkey(), true),
                ],
                data,
            }],
            &[payer],
        )
        .await;
    }
}

fn create_account_ix(
    payer: Pubkey,
    account: Pubkey,
    lamports: u64,
    space: u64,
    owner: Pubkey,
) -> Instruction {
    let mut data = vec![0, 0, 0, 0];
    data.extend_from_slice(&lamports.to_le_bytes());
    data.extend_from_slice(&space.to_le_bytes());
    data.extend_from_slice(owner.as_ref());
    Instruction {
        program_id: anchor_lang::system_program::ID,
        accounts: vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(account, true),
        ],
        data,
    }
}

fn transfer_checked_ix(
    program: Pubkey,
    source: Pubkey,
    mint: Pubkey,
    destination: Pubkey,
    authority: Pubkey,
    amount: u64,
    decimals: u8,
) -> Instruction {
    let mut data = vec![12];
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(decimals);
    Instruction {
        program_id: program,
        accounts: vec![
            AccountMeta::new(source, false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new(destination, false),
            AccountMeta::new_readonly(authority, true),
        ],
        data,
    }
}

fn close_token_account_ix(account: Pubkey, destination: Pubkey, owner: Pubkey) -> Instruction {
    Instruction {
        program_id: TOKEN_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(account, false),
            AccountMeta::new(destination, false),
            AccountMeta::new_readonly(owner, true),
        ],
        data: vec![9],
    }
}

/// The vault instruction of a prepared ledger transaction.
fn vault_instruction(transaction: &PreparedLedgerTransaction) -> Instruction {
    let message: Message = bincode::deserialize(&transaction.bytes).unwrap();
    let compiled = message
        .instructions
        .iter()
        .find(|instruction| {
            message.account_keys[usize::from(instruction.program_id_index)] == vault_program::ID
        })
        .unwrap();
    Instruction {
        program_id: vault_program::ID,
        accounts: compiled
            .accounts
            .iter()
            .map(|&index| {
                let index = usize::from(index);
                AccountMeta {
                    pubkey: message.account_keys[index],
                    is_signer: message.is_signer(index),
                    is_writable: message.is_maybe_writable(index, None),
                }
            })
            .collect(),
        data: compiled.data.clone(),
    }
}

/// `ExecuteDeposit` account positions.
const DEPOSIT_DEPOSITOR: usize = 4;
const DEPOSIT_SOURCE: usize = 5;
const DEPOSIT_MINT: usize = 7;
const DEPOSIT_TOKEN_PROGRAM: usize = 8;

fn with_account(mut instruction: Instruction, index: usize, meta: AccountMeta) -> Instruction {
    instruction.accounts[index] = meta;
    instruction
}

/// Relay `inner` through the test PDA-signer program, which signs for its
/// `["forwarder"]` PDA with `invoke_signed`.
fn forwarded(program: Pubkey, forwarder: Pubkey, inner: Instruction) -> Instruction {
    let mut data = inner.program_id.to_bytes().to_vec();
    data.push(u8::try_from(inner.accounts.len()).unwrap());
    let mut accounts = Vec::with_capacity(inner.accounts.len() + 1);
    for meta in &inner.accounts {
        data.extend_from_slice(meta.pubkey.as_ref());
        data.push(u8::from(meta.is_signer));
        data.push(u8::from(meta.is_writable));
        accounts.push(AccountMeta {
            pubkey: meta.pubkey,
            is_signer: meta.is_signer && meta.pubkey != forwarder,
            is_writable: meta.is_writable,
        });
    }
    accounts.push(AccountMeta::new_readonly(inner.program_id, false));
    data.extend_from_slice(&inner.data);
    Instruction {
        program_id: program,
        accounts,
        data,
    }
}

/// The vault custom error a failed preflight reported.
fn custom_error(error: &Value) -> Option<u32> {
    error["data"]["err"]["InstructionError"][1]["Custom"]
        .as_u64()
        .and_then(|code| u32::try_from(code).ok())
}

fn assert_custom_error(result: Result<String, Value>, expected: u32, context: &str) {
    let error = result.expect_err(context);
    assert_eq!(
        custom_error(&error),
        Some(expected),
        "{context}: expected {expected}, got {error}"
    );
}

fn assert_vault_error(result: Result<String, Value>, expected: VaultError, context: &str) {
    assert_custom_error(result, expected.into(), context);
}

fn assert_rejected<T: std::fmt::Debug>(result: Result<T, LedgerError>, context: &str) {
    assert!(
        matches!(result, Err(LedgerError::Rejected(_))),
        "{context}: {result:?}"
    );
}

/// After every step: the vault token balance covers every liability, and
/// the excess is exactly what was donated (never swept or paid out).
async fn assert_solvent(
    rpc: &Rpc,
    vault: Pubkey,
    vault_token: Pubkey,
    donated: u64,
    context: &str,
) -> vault_program::VaultState {
    let state: vault_program::VaultState = rpc.anchor_account(vault).await;
    let balance = rpc.token_amount(vault_token).await;
    let liabilities = state.total_credits + state.treasury_accrued + state.deferred_payouts;
    assert!(
        balance >= liabilities,
        "{context}: vault holds {balance} < liabilities {liabilities}"
    );
    assert_eq!(
        balance - liabilities,
        donated,
        "{context}: surplus is not the donations"
    );
    state
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

    /// A withdrawal proof whose destination binding is the payout token
    /// account `destination`.
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

fn withdrawal_payload(
    value: &WithdrawalPublicInputsV2,
    proof: &Groth16ProofWire,
) -> vault_program::WithdrawalPayload {
    vault_program::WithdrawalPayload {
        public_inputs: vault_program::WithdrawalInputs {
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
        },
        proof: proof_bytes(proof),
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

/// Raw builders for exit instructions with arbitrary (possibly hostile)
/// accounts, to show the program itself refuses what the ledger would not
/// prepare.
struct RawVault {
    vault: Pubkey,
    vault_token: Pubkey,
    payer: Pubkey,
}

impl RawVault {
    fn close(
        &self,
        public: &WithdrawalPublicInputsV2,
        proof: &Groth16ProofWire,
        destination_token: Pubkey,
        mint: Pubkey,
        token_program: Pubkey,
    ) -> Instruction {
        Instruction {
            program_id: vault_program::ID,
            accounts: vault_program::accounts::ExecuteClose {
                vault: self.vault,
                note: note_address(self.vault, public.note_id),
                used_nullifier: nullifier_address(self.vault, public.withdrawal_nullifier),
                owner: self.payer,
                destination_token,
                vault_token: self.vault_token,
                mint,
                token_program,
                system_program: anchor_lang::system_program::ID,
            }
            .to_account_metas(None),
            data: vault_program::instruction::ExecuteClose {
                note_id: public.note_id,
                payload: withdrawal_payload(public, proof),
            }
            .data(),
        }
    }

    fn escape(
        &self,
        public: &WithdrawalPublicInputsV2,
        proof: &Groth16ProofWire,
        destination: Pubkey,
    ) -> Instruction {
        Instruction {
            program_id: vault_program::ID,
            accounts: vault_program::accounts::ExecuteEscape {
                vault: self.vault,
                note: note_address(self.vault, public.note_id),
                pending: pending_address(self.vault, public.note_id),
                used_nullifier: nullifier_address(self.vault, public.withdrawal_nullifier),
                next_nullifier: nullifier_address(self.vault, public.next_nullifier),
                owner: self.payer,
                destination,
                system_program: anchor_lang::system_program::ID,
            }
            .to_account_metas(None),
            data: vault_program::instruction::ExecuteEscape {
                note_id: public.note_id,
                payload: withdrawal_payload(public, proof),
            }
            .data(),
        }
    }

    /// Finalize (or release) paying `destination_token`, refunding rent to
    /// `rent_payer` (passed writable, as the program requires).
    fn settle(
        &self,
        note_id: u32,
        release: bool,
        rent_payer: Pubkey,
        destination_token: Pubkey,
    ) -> Instruction {
        let (pending, note) = (
            pending_address(self.vault, note_id),
            note_address(self.vault, note_id),
        );
        let mut accounts = if release {
            vault_program::accounts::ReleaseEscapePayout {
                vault: self.vault,
                note,
                pending,
                payer: self.payer,
                rent_payer,
                destination_token,
                vault_token: self.vault_token,
                mint: USDC_MINT,
                token_program: TOKEN_PROGRAM_ID,
            }
            .to_account_metas(None)
        } else {
            vault_program::accounts::FinalizeEscape {
                vault: self.vault,
                note,
                pending,
                payer: self.payer,
                rent_payer,
                destination_token,
                vault_token: self.vault_token,
                mint: USDC_MINT,
                token_program: TOKEN_PROGRAM_ID,
            }
            .to_account_metas(None)
        };
        for meta in &mut accounts {
            if meta.pubkey == rent_payer {
                meta.is_writable = true;
            }
        }
        let data = if release {
            vault_program::instruction::ReleaseEscapePayout { note_id }.data()
        } else {
            vault_program::instruction::FinalizeEscape { note_id }.data()
        };
        Instruction {
            program_id: vault_program::ID,
            accounts,
            data,
        }
    }

    fn claim_expired(&self, note_id: u32) -> Instruction {
        Instruction {
            program_id: vault_program::ID,
            accounts: vault_program::accounts::ExecuteClaimExpired {
                vault: self.vault,
                note: note_address(self.vault, note_id),
                owner: self.payer,
                vault_token: self.vault_token,
            }
            .to_account_metas(None),
            data: vault_program::instruction::ExecuteClaimExpired { note_id }.data(),
        }
    }

    fn withdraw_treasury(&self, treasury_token: Pubkey) -> Instruction {
        Instruction {
            program_id: vault_program::ID,
            accounts: vault_program::accounts::WithdrawTreasury {
                vault: self.vault,
                treasury_token,
                vault_token: self.vault_token,
                mint: USDC_MINT,
                token_program: TOKEN_PROGRAM_ID,
            }
            .to_account_metas(None),
            data: vault_program::instruction::WithdrawTreasury {}.data(),
        }
    }
}

/// A caller (`raw.payer`, signing alone) settling `note_id` cannot pass the
/// escaper read-only (which would park or divert its rent) nor name itself
/// as the refund target: both fail, nothing moves, and the note's status,
/// the pending rent and the caller's balance are unchanged.
#[allow(clippy::too_many_arguments)]
async fn assert_rent_not_redirected(
    rpc: &Rpc,
    raw: &RawVault,
    caller: &Keypair,
    note_id: u32,
    release: bool,
    escaper: Pubkey,
    destination: Pubkey,
    status: u8,
) {
    let pending = pending_address(raw.vault, note_id);
    let (caller_before, rent_before) = (
        rpc.balance(caller.pubkey()).await,
        rpc.balance(pending).await,
    );
    let mut read_only = raw.settle(note_id, release, escaper, destination);
    for meta in &mut read_only.accounts {
        if meta.pubkey == escaper {
            meta.is_writable = false;
        }
    }
    let kind = if release { "release" } else { "finalize" };
    assert_vault_error(
        rpc.try_vault(read_only, &[caller]).await,
        VaultError::RentPayerNotWritable,
        &format!("{kind} with the escaper read-only"),
    );
    assert_vault_error(
        rpc.try_vault(
            raw.settle(note_id, release, caller.pubkey(), destination),
            &[caller],
        )
        .await,
        VaultError::RentPayerMismatch,
        &format!("{kind} refunding the caller"),
    );
    assert!(
        rpc.balance(caller.pubkey()).await <= caller_before,
        "{kind}: caller gained"
    );
    assert_eq!(
        rpc.balance(pending).await,
        rent_before,
        "{kind}: pending rent moved"
    );
    let note: vault_program::NoteState = rpc.anchor_account(note_address(raw.vault, note_id)).await;
    assert_eq!(note.status, status, "{kind}: note status changed");
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

/// A fresh vault (fresh authority) on the stack's validator, with its own
/// pinned treasury USDC account, under `profile` (the test-only overrides).
struct Deployment {
    authority: Keypair,
    vault: Pubkey,
    vault_token: Pubkey,
    treasury_token: Pubkey,
    resolved: ResolvedIdentity,
    genesis: String,
    ledger: SolanaCreditLedger,
}

async fn deploy(
    rpc: &Rpc,
    stack: &Stack,
    profile: &SharedProfile,
    state_signer: &CompactSigner,
    clearance_signer: &CompactSigner,
) -> Deployment {
    let authority = Keypair::new();
    rpc.airdrop(authority.pubkey(), 20_000_000_000).await;
    let treasury_owner = Keypair::new().pubkey();
    let treasury_token = rpc.create_usdc_ata(&authority, treasury_owner).await;
    let genesis: String = rpc.call("getGenesisHash", json!([])).await;
    let genesis_hash = Hash::from_str(&genesis).unwrap().to_bytes();
    let (vault, _) =
        Pubkey::find_program_address(&[b"vault", authority.pubkey().as_ref()], &vault_program::ID);
    let vault_token = Pubkey::new_from_array(vault_token_address(
        &vault_program::ID.to_bytes(),
        &vault.to_bytes(),
    ));
    let identity = NetworkIdentity {
        schema: IDENTITY_SCHEMA.into(),
        network: "localnet".into(),
        genesis_hash: genesis.clone(),
        vault_authority: Some(authority.pubkey().to_string()),
        vault_state: Some(vault.to_string()),
        treasury_token_account: Some(treasury_token.to_string()),
    };
    let resolved = identity.resolve(profile).unwrap();
    let initialize = dagon_zkapi_deploy::initialize_instruction(
        profile,
        &identity,
        state_signer,
        clearance_signer,
    )
    .unwrap();
    // Initialize searches the vault-token PDA bump; give it the full budget.
    rpc.send_signed(&Rpc::budgeted(initialize), &[&authority])
        .await;
    let ledger = SolanaCreditLedger::new(SolanaLedgerConfig {
        rpc_url: stack.rpc_url.clone(),
        indexer_url: None,
        network: "localnet".into(),
        program_id: vault_program::ID.to_bytes(),
        vault_state: vault.to_bytes(),
        genesis_hash,
    })
    .unwrap();
    Deployment {
        authority,
        vault,
        vault_token,
        treasury_token,
        resolved,
        genesis,
        ledger,
    }
}

/// The checked-in test-only overrides on top of the shared profile. No
/// binary reads that file: server startup requires the shared profile's
/// parameters, and its settlement/challenger timing inequality
/// independently rejects the shortened challenge period.
fn test_profile() -> (SharedProfile, Value) {
    let mut profile = SharedProfile::embedded().clone();
    let overrides: Value = serde_json::from_str(include_str!(
        "../../../solana/profile/localnet-test-overrides.json"
    ))
    .unwrap();
    profile.vault.challenge_period_seconds =
        overrides["challenge_period_seconds"].as_u64().unwrap();
    (profile, overrides)
}

#[tokio::test]
#[ignore = "requires the local stack (validator, USDC clone, faucet, frozen account, PDA signer)"]
async fn concession_exit_lifecycle_on_localnet() {
    let stack = Stack::from_env();
    let rpc = Rpc::new(stack.rpc_url.clone());
    let (profile, _) = test_profile();
    let state_signer = CompactSigner::from_seed(&Felt252::from_u64(101));
    let clearance_signer = CompactSigner::from_seed(&Felt252::from_u64(102));
    let setup = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../protocol/setup/v2");
    let request_prover = RequestProver::load(&setup).unwrap();
    let withdrawal_prover = WithdrawalProver::load(&setup).unwrap();
    let mut compute_units = Vec::new();
    let Deployment {
        authority,
        vault,
        vault_token,
        treasury_token,
        resolved,
        genesis,
        ledger,
    } = deploy(&rpc, &stack, &profile, &state_signer, &clearance_signer).await;
    let deposit_units = u64::try_from(DEPOSIT).unwrap();
    let payer = LedgerAccount::new(authority.pubkey().to_bytes());
    let raw = RawVault {
        vault,
        vault_token,
        payer: authority.pubkey(),
    };
    let mut donated = 0u64;
    assert_solvent(&rpc, vault, vault_token, donated, "initialized").await;

    // Wallets: the payer's canonical ATA funds the deposits; the user's
    // canonical ATA is the default payout account; the frozen account and
    // locally created foreign accounts are adversarial.
    let payer_ata = rpc.create_usdc_ata(&authority, authority.pubkey()).await;
    rpc.fund_usdc(&stack, &authority, payer_ata, 6 * deposit_units)
        .await;
    let user = Keypair::new().pubkey();
    let destination = rpc.create_usdc_ata(&authority, user).await;
    let destination_account = LedgerAccount::new(destination.to_bytes());
    let attacker_ata = rpc
        .create_usdc_ata(&authority, Keypair::new().pubkey())
        .await;
    let fake_mint = rpc
        .create_mint(&authority, TOKEN_PROGRAM_ID, authority.pubkey())
        .await;
    let fake_account = Keypair::new();
    rpc.create_token_account(
        &authority,
        &fake_account,
        TOKEN_PROGRAM_ID,
        fake_mint,
        authority.pubkey(),
    )
    .await;
    rpc.mint_to(
        &authority,
        TOKEN_PROGRAM_ID,
        fake_mint,
        fake_account.pubkey(),
        deposit_units,
    )
    .await;
    let token22_mint = rpc
        .create_mint(&authority, TOKEN_2022_PROGRAM_ID, authority.pubkey())
        .await;
    let token22_account = Keypair::new();
    rpc.create_token_account(
        &authority,
        &token22_account,
        TOKEN_2022_PROGRAM_ID,
        token22_mint,
        authority.pubkey(),
    )
    .await;
    rpc.mint_to(
        &authority,
        TOKEN_2022_PROGRAM_ID,
        token22_mint,
        token22_account.pubkey(),
        deposit_units,
    )
    .await;
    // A forged, program-owned (loader-v3 buffer) 165-byte account whose
    // amount and state bytes look like a funded, initialized token account.
    let forged = Keypair::new();
    let forged_rent = rpc.rent(165).await;
    let mut forged_body = vec![0u8; 45];
    forged_body[..8].copy_from_slice(&deposit_units.to_le_bytes());
    forged_body[44] = 1;
    let mut forged_instructions =
        anchor_lang::solana_program::bpf_loader_upgradeable::create_buffer(
            &authority.pubkey(),
            &forged.pubkey(),
            &authority.pubkey(),
            forged_rent,
            128,
        )
        .unwrap();
    forged_instructions.push(anchor_lang::solana_program::bpf_loader_upgradeable::write(
        &forged.pubkey(),
        &authority.pubkey(),
        27,
        forged_body,
    ));
    rpc.send_signed(&forged_instructions, &[&authority, &forged])
        .await;
    let forged = forged.pubkey();
    // The test PDA signer's forwarder PDA and its (off-curve) USDC account.
    let (forwarder, _) = Pubkey::find_program_address(&[b"forwarder"], &stack.pda_signer_program);
    assert!(!forwarder.is_on_curve());
    let forwarder_ata = rpc.create_usdc_ata(&authority, forwarder).await;
    rpc.fund_usdc(&stack, &authority, forwarder_ata, deposit_units)
        .await;
    let sweeper = Keypair::new();
    rpc.airdrop(sweeper.pubkey(), 1_000_000_000).await;

    let set_paused = |paused: bool| Instruction {
        program_id: vault_program::ID,
        accounts: vault_program::accounts::SetPaused {
            vault,
            authority: authority.pubkey(),
        }
        .to_account_metas(None),
        data: vault_program::instruction::SetPaused { paused }.data(),
    };
    let rpc_url = stack.rpc_url.clone();
    let browser_funding = json!({
        "ledger_backend": "dagon.solana.groth16.v1",
        "billing_asset": "usdc", "billing_unit": "micro_usdc", "base_units_per_asset": "1000000",
        "chain_id": ledger.deployment().chain_id.to_string(),
        "contract_address": format!("0x{:0>64}", ledger.deployment().protocol_binding.to_hex().trim_start_matches("0x")),
        "program_id": vault_program::ID.to_string(), "vault_state": vault.to_string(),
        "genesis_hash": genesis, "network": "localnet", "wallet_standard_chain": "solana:localnet",
        "rpc_url": rpc_url, "protocol_server_url": "http://127.0.0.1:1",
        "usdc_mint": profile.asset.mint,
        "token_program": profile.asset.token_program,
        "associated_token_program": profile.asset.associated_token_program,
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
        rpc_url.clone(),
        &profile,
        &resolved,
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
    let accrued = |vault_state: vault_program::VaultState| vault_state.treasury_accrued;

    // The ledger refuses a deposit from a wallet whose canonical USDC
    // account is frozen (or missing) before any proving or fee.
    assert_rejected(
        ledger
            .prepare_deposit(DepositRequest {
                payer: LedgerAccount::new(stack.frozen_owner.pubkey().to_bytes()),
                expected_note_id: 0,
                commitment: core::registration_commitment(&Felt252::from_u64(41)),
                amount: DEPOSIT,
                zero_path: tree.get_siblings(0),
            })
            .await,
        "deposit from a frozen USDC account",
    );

    // ---- Note A: asset substitution at deposit, then the honest deposit
    // through the same staged buffer.
    let secret_a = Felt252::from_u64(42);
    let execute_a = rpc
        .stage(deposit(0, secret_a, tree.get_siblings(0)).await, &authority)
        .await;
    let source = |key: Pubkey| AccountMeta::new(key, false);
    for (tampered, expected, label) in [
        (
            with_account(
                execute_a.clone(),
                DEPOSIT_SOURCE,
                source(fake_account.pubkey()),
            ),
            VaultError::InvalidTokenAccount,
            "deposit from a foreign classic mint",
        ),
        (
            with_account(
                with_account(
                    execute_a.clone(),
                    DEPOSIT_SOURCE,
                    source(fake_account.pubkey()),
                ),
                DEPOSIT_MINT,
                AccountMeta::new_readonly(fake_mint, false),
            ),
            VaultError::InvalidMint,
            "deposit naming a foreign mint",
        ),
        (
            with_account(
                execute_a.clone(),
                DEPOSIT_SOURCE,
                source(token22_account.pubkey()),
            ),
            VaultError::InvalidTokenAccount,
            "deposit from a Token-2022 account",
        ),
        (
            with_account(
                execute_a.clone(),
                DEPOSIT_TOKEN_PROGRAM,
                AccountMeta::new_readonly(TOKEN_2022_PROGRAM_ID, false),
            ),
            VaultError::InvalidTokenProgram,
            "deposit through Token-2022",
        ),
        (
            with_account(execute_a.clone(), DEPOSIT_SOURCE, source(forged)),
            VaultError::InvalidTokenAccount,
            "deposit from a forged program-owned account",
        ),
        (
            with_account(execute_a.clone(), DEPOSIT_SOURCE, source(vault_token)),
            VaultError::InvalidTokenAccount,
            "deposit from the vault token account",
        ),
    ] {
        assert_vault_error(
            rpc.try_vault(tampered, &[&authority]).await,
            expected,
            label,
        );
    }
    let frozen_deposit = with_account(
        with_account(
            execute_a.clone(),
            DEPOSIT_DEPOSITOR,
            AccountMeta::new_readonly(stack.frozen_owner.pubkey(), true),
        ),
        DEPOSIT_SOURCE,
        source(stack.frozen_account),
    );
    assert_custom_error(
        rpc.try_vault(frozen_deposit, &[&authority, &stack.frozen_owner])
            .await,
        TOKEN_ERROR_ACCOUNT_FROZEN,
        "deposit from the frozen USDC account",
    );
    assert_solvent(&rpc, vault, vault_token, donated, "refused deposits").await;
    let payer_before = rpc.token_amount(payer_ata).await;
    let signature = rpc.try_vault(execute_a, &[&authority]).await.unwrap();
    compute_units.push(("deposit execute", rpc.compute_units(&signature).await));
    assert_eq!(
        payer_before - rpc.token_amount(payer_ata).await,
        deposit_units
    );
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
    assert_solvent(&rpc, vault, vault_token, donated, "deposit A").await;
    let valid_until = rpc.chain_time().await + 3_600;

    // ---- Note A close: only the proof-bound, creditable USDC account.
    let a1 = wallet.advance(&a0, 40_000);
    let (close_public, close_proof) = wallet.withdrawal(&a1, destination, 0, true, valid_until);
    let close_nullifier = close_public.withdrawal_nullifier;
    for (account, label) in [
        (attacker_ata, "close to a substituted USDC account"),
        (stack.frozen_account, "close to the frozen account"),
        (token22_account.pubkey(), "close to a Token-2022 account"),
    ] {
        assert_rejected(
            ledger
                .prepare_close(WithdrawalRequest {
                    payer,
                    destination: LedgerAccount::new(account.to_bytes()),
                    public_inputs: close_public.clone(),
                    proof: close_proof.clone(),
                })
                .await,
            label,
        );
    }
    let (frozen_public, frozen_proof) =
        wallet.withdrawal(&a1, stack.frozen_account, 0, true, valid_until);
    let (token22_public, token22_proof) =
        wallet.withdrawal(&a1, token22_account.pubkey(), 0, true, valid_until);
    for (instruction, expected, label) in [
        (
            raw.close(
                &close_public,
                &close_proof,
                attacker_ata,
                USDC_MINT,
                TOKEN_PROGRAM_ID,
            ),
            VaultError::DestinationMismatch,
            "raw close to a substituted USDC account",
        ),
        (
            raw.close(
                &close_public,
                &close_proof,
                destination,
                fake_mint,
                TOKEN_PROGRAM_ID,
            ),
            VaultError::InvalidMint,
            "raw close naming a foreign mint",
        ),
        (
            raw.close(
                &close_public,
                &close_proof,
                destination,
                USDC_MINT,
                TOKEN_2022_PROGRAM_ID,
            ),
            VaultError::InvalidTokenProgram,
            "raw close through Token-2022",
        ),
        (
            raw.close(
                &frozen_public,
                &frozen_proof,
                stack.frozen_account,
                USDC_MINT,
                TOKEN_PROGRAM_ID,
            ),
            VaultError::DestinationNotCreditable,
            "raw close to the frozen account",
        ),
        (
            raw.close(
                &token22_public,
                &token22_proof,
                token22_account.pubkey(),
                USDC_MINT,
                TOKEN_PROGRAM_ID,
            ),
            VaultError::InvalidTokenAccount,
            "raw close to a Token-2022 account",
        ),
    ] {
        assert_vault_error(
            rpc.try_vault(instruction, &[&authority]).await,
            expected,
            label,
        );
    }
    let close_request = WithdrawalRequest {
        payer,
        destination: destination_account,
        public_inputs: close_public.clone(),
        proof: close_proof.clone(),
    };
    let (destination_before, treasury_before) = (
        rpc.token_amount(destination).await,
        rpc.token_amount(treasury_token).await,
    );
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
        u128::from(rpc.token_amount(destination).await - destination_before),
        DEPOSIT - 40_000
    );
    // The operator share accrues in the vault; exits never touch the treasury.
    assert_eq!(rpc.token_amount(treasury_token).await, treasury_before);
    assert_eq!(
        accrued(assert_solvent(&rpc, vault, vault_token, donated, "close A").await),
        40_000
    );
    let closed: vault_program::NoteState = rpc.anchor_account(note_address(vault, 0)).await;
    assert_eq!(closed.status, vault_program::NOTE_STATUS_CLOSED);
    assert_eq!(
        ledger
            .nullifier_status(close_nullifier, LedgerCommitment::Confirmed)
            .await
            .unwrap(),
        LedgerNullifierStatus::Used
    );
    // Double payout: neither a replayed close nor an expiry claim of the
    // closed note pays again.
    assert!(ledger.prepare_close(close_request).await.is_err());
    assert_vault_error(
        rpc.try_vault(
            raw.close(
                &close_public,
                &close_proof,
                destination,
                USDC_MINT,
                TOKEN_PROGRAM_ID,
            ),
            &[&authority],
        )
        .await,
        VaultError::NoteNotActive,
        "replayed close",
    );
    assert_rejected(
        ledger
            .prepare_claim_expired(ClaimExpiredRequest { payer, note_id: 0 })
            .await,
        "claim after close",
    );
    assert!(
        rpc.try_vault(raw.claim_expired(0), &[&authority])
            .await
            .is_err(),
        "raw claim after close"
    );
    assert_eq!(
        u128::from(rpc.token_amount(destination).await - destination_before),
        DEPOSIT - 40_000
    );

    // Treasury: a substituted account is refused; the pinned account is
    // paid once.
    assert_vault_error(
        rpc.try_vault(raw.withdraw_treasury(attacker_ata), &[&sweeper])
            .await,
        VaultError::InvalidTreasuryAccount,
        "treasury substitution",
    );
    let sweep = || async {
        ledger
            .prepare_withdraw_treasury(LedgerAccount::new(sweeper.pubkey().to_bytes()))
            .await
    };
    let signature = rpc.send_operation(sweep().await.unwrap(), &sweeper).await;
    compute_units.push(("withdraw_treasury", rpc.compute_units(&signature).await));
    assert_eq!(
        rpc.token_amount(treasury_token).await - treasury_before,
        40_000
    );
    assert_rejected(sweep().await, "second treasury withdrawal");
    rpc.try_vault(raw.withdraw_treasury(treasury_token), &[&sweeper])
        .await
        .unwrap();
    assert_eq!(
        rpc.token_amount(treasury_token).await - treasury_before,
        40_000,
        "a second treasury withdrawal pays nothing"
    );
    let mut treasury_paid = 40_000u128;
    assert_solvent(&rpc, vault, vault_token, donated, "treasury withdrawn").await;

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
    eprintln!("note A: close paid B in USDC, treasury paid once, leaf retired");

    // ---- Donation straight into the vault token account: surplus only.
    let donation = 1_234_567;
    rpc.send_signed(
        &[transfer_checked_ix(
            TOKEN_PROGRAM_ID,
            usdc_ata(stack.faucet.pubkey()),
            USDC_MINT,
            vault_token,
            stack.faucet.pubkey(),
            donation,
            USDC_DECIMALS,
        )],
        &[&authority, &stack.faucet],
    )
    .await;
    donated += donation;
    assert_solvent(&rpc, vault, vault_token, donated, "donation").await;

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
    assert_solvent(&rpc, vault, vault_token, donated, "deposit B").await;
    let b1 = wallet.advance(&b0, 40_000);
    // The server signs no request bound below the profile's request charge cap.
    let bound_b = u128::from(profile.vault.request_charge_cap);
    let (b_request, b_request_proof) = wallet.request(&b1, bound_b);
    let (b_escape, b_escape_proof) =
        wallet.withdrawal(&b1, destination, bound_b, false, valid_until);
    let (b_n, b_next) = (b_escape.withdrawal_nullifier, b_escape.next_nullifier);
    assert_eq!(b_request.request_nullifier, b_n);
    assert_eq!(b_next, b1.successor_nullifier());
    // A payout account finalize could not credit is refused at escape time,
    // by the ledger before any fee and by the program itself.
    for (uncreditable, expected, label) in [
        (
            vault_token,
            VaultError::DestinationNotCreditable,
            "escape to the vault token account",
        ),
        (
            stack.frozen_account,
            VaultError::DestinationNotCreditable,
            "escape to the frozen account",
        ),
        (
            token22_account.pubkey(),
            VaultError::InvalidTokenAccount,
            "escape to a Token-2022 account",
        ),
        (
            forged,
            VaultError::InvalidTokenAccount,
            "escape to a forged program-owned account",
        ),
        (
            fake_account.pubkey(),
            VaultError::DestinationNotCreditable,
            "escape to a foreign-mint account",
        ),
        (
            anchor_lang::system_program::ID,
            VaultError::InvalidTokenAccount,
            "escape to the System program",
        ),
    ] {
        let (public_inputs, proof) =
            wallet.withdrawal(&b1, uncreditable, bound_b, false, valid_until);
        assert_rejected(
            ledger
                .prepare_escape(WithdrawalRequest {
                    payer,
                    destination: LedgerAccount::new(uncreditable.to_bytes()),
                    public_inputs: public_inputs.clone(),
                    proof: proof.clone(),
                })
                .await,
            label,
        );
        assert_vault_error(
            rpc.try_vault(
                raw.escape(&public_inputs, &proof, uncreditable),
                &[&authority],
            )
            .await,
            expected,
            label,
        );
    }
    assert_vault_error(
        rpc.try_vault(
            raw.escape(&b_escape, &b_escape_proof, attacker_ata),
            &[&authority],
        )
        .await,
        VaultError::DestinationMismatch,
        "escape to a substituted USDC account",
    );

    // F7: anyone can pre-fund both nullifier PDAs; the escape still lands.
    let rent_floor = rpc.rent(0).await;
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
    assert_solvent(&rpc, vault, vault_token, donated, "escape B").await;
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
            public_inputs: b_escape.clone(),
            proof: b_escape_proof.clone(),
        })
        .await;
    assert!(
        replay.is_err(),
        "pending note must reject a replayed escape"
    );
    // Release is only for a parked payout, never before finalization.
    assert_rejected(
        ledger
            .prepare_release_escape_payout(ReleaseEscapePayoutRequest { payer, note_id: 1 })
            .await,
        "release before finalize",
    );
    assert_vault_error(
        rpc.try_vault(
            raw.settle(1, true, authority.pubkey(), destination),
            &[&authority],
        )
        .await,
        VaultError::PayoutNotDeferred,
        "raw release before finalize",
    );

    // The operator holds R1 (at N), but that proves nothing about S2: it can
    // neither defeat the escape nor raise c beyond the bound already conceded.
    assert_rejected(
        ledger
            .prepare_challenge(ChallengeRequest {
                payer,
                note_id: 1,
                public_inputs: b_request.clone(),
                proof: b_request_proof.clone(),
            })
            .await,
        "withheld: defeat at N",
    );
    assert_rejected(
        ledger
            .prepare_raise_concession(RaiseConcessionRequest {
                payer,
                note_id: 1,
                public_inputs: b_request.clone(),
                proof: b_request_proof.clone(),
                amount: DEPOSIT,
            })
            .await,
        "withheld: raise at N",
    );
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
    assert_solvent(&rpc, vault, vault_token, donated, "defeat C").await;

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

    // Finalization of the withheld escape is open while paused: B − b to the
    // bound account, the pending rent to the escaper (not the caller).
    rpc.wait_until_after(b_deadline).await;
    let (destination_before, escaper_before, b_pending_rent) = (
        rpc.token_amount(destination).await,
        rpc.balance(authority.pubkey()).await,
        rpc.balance(pending_address(vault, 1)).await,
    );
    assert!(b_pending_rent > 0);
    // The payout cannot be redirected: neither to another account nor the
    // rent to the caller.
    assert_vault_error(
        rpc.try_vault(
            raw.settle(1, false, authority.pubkey(), attacker_ata),
            &[&sweeper, &authority],
        )
        .await,
        VaultError::DestinationMismatch,
        "finalize to a substituted account",
    );
    assert_vault_error(
        rpc.try_vault(
            raw.settle(1, false, sweeper.pubkey(), destination),
            &[&sweeper, &authority],
        )
        .await,
        VaultError::RentPayerMismatch,
        "finalize refunding the caller",
    );
    let signature = rpc
        .send_operation(
            browser_exit(
                &browser_funding,
                "finalize",
                json!({
                    "payer": sweeper.pubkey().to_string(), "note_id": 1
                }),
            ),
            &sweeper,
        )
        .await;
    compute_units.push((
        "finalize (while paused)",
        rpc.compute_units(&signature).await,
    ));
    assert_eq!(
        u128::from(rpc.token_amount(destination).await - destination_before),
        b1.balance - bound_b,
        "withheld successor: the honest user is paid B - b"
    );
    assert_eq!(
        rpc.balance(authority.pubkey()).await - escaper_before,
        b_pending_rent,
        "the escaper alone gets the pending rent back"
    );
    assert_eq!(rpc.balance(pending_address(vault, 1)).await, 0);
    let mut owed = DEPOSIT - (b1.balance - bound_b);
    assert_eq!(
        u128::from(accrued(
            assert_solvent(&rpc, vault, vault_token, donated, "finalize B").await
        )),
        owed
    );
    let finalized: vault_program::NoteState = rpc.anchor_account(note_address(vault, 1)).await;
    assert_eq!(finalized.status, vault_program::NOTE_STATUS_CLOSED);
    // Double payout: a second finalize finds no open escape.
    assert!(ledger
        .prepare_finalize_escape(FinalizeEscapeRequest { payer, note_id: 1 })
        .await
        .is_err());
    assert!(rpc
        .try_vault(
            raw.settle(1, false, authority.pubkey(), destination),
            &[&sweeper, &authority]
        )
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

    // ---- Note D: a CPI deposit whose USDC authority is the forwarder PDA;
    // the outer signer owns the operation and pays its rent.
    let secret_d = Felt252::from_u64(46);
    let execute_d = rpc
        .stage(deposit(3, secret_d, tree.get_siblings(3)).await, &authority)
        .await;
    let execute_d = with_account(
        with_account(
            execute_d,
            DEPOSIT_DEPOSITOR,
            AccountMeta::new_readonly(forwarder, true),
        ),
        DEPOSIT_SOURCE,
        source(forwarder_ata),
    );
    // The forwarder PDA is the same in every run: compare deltas only.
    let (payer_before, forwarder_before) = (
        rpc.token_amount(payer_ata).await,
        rpc.token_amount(forwarder_ata).await,
    );
    let signature = rpc
        .try_vault(
            forwarded(stack.pda_signer_program, forwarder, execute_d),
            &[&authority],
        )
        .await
        .unwrap();
    compute_units.push((
        "deposit execute (PDA via CPI)",
        rpc.compute_units(&signature).await,
    ));
    assert_eq!(
        forwarder_before - rpc.token_amount(forwarder_ata).await,
        deposit_units
    );
    assert_eq!(rpc.token_amount(payer_ata).await, payer_before);
    rpc.wait_finalized(&signature).await;
    let note_d: vault_program::NoteState = rpc.anchor_account(note_address(vault, 3)).await;
    let d0 = PrivateNoteState::genesis(3, secret_d, note_d.expiry);
    tree.set_leaf(3, d0.leaf());
    assert_solvent(&rpc, vault, vault_token, donated, "CPI deposit D").await;
    // Close D to the PDA's (off-curve) USDC account.
    let d1 = wallet.advance(&d0, 30_000);
    let (d_close, d_close_proof) = wallet.withdrawal(&d1, forwarder_ata, 0, true, valid_until);
    let forwarder_before = rpc.token_amount(forwarder_ata).await;
    let signature = rpc
        .send_operation(
            ledger
                .prepare_close(WithdrawalRequest {
                    payer,
                    destination: LedgerAccount::new(forwarder_ata.to_bytes()),
                    public_inputs: d_close,
                    proof: d_close_proof,
                })
                .await
                .unwrap(),
            &authority,
        )
        .await;
    compute_units.push((
        "close (off-curve PDA owner)",
        rpc.compute_units(&signature).await,
    ));
    assert_eq!(
        u128::from(rpc.token_amount(forwarder_ata).await - forwarder_before),
        DEPOSIT - 30_000
    );
    owed += 30_000;
    assert_solvent(&rpc, vault, vault_token, donated, "close D").await;

    // ---- Notes E and F: E escapes to a keypair token account that is
    // closed before finalize; F escapes to the PDA's account.
    let secret_e = Felt252::from_u64(47);
    let signature = rpc
        .send_operation(deposit(4, secret_e, tree.get_siblings(4)).await, &authority)
        .await;
    rpc.wait_finalized(&signature).await;
    let note_e: vault_program::NoteState = rpc.anchor_account(note_address(vault, 4)).await;
    let e0 = PrivateNoteState::genesis(4, secret_e, note_e.expiry);
    tree.set_leaf(4, e0.leaf());
    let secret_f = Felt252::from_u64(48);
    let signature = rpc
        .send_operation(deposit(5, secret_f, tree.get_siblings(5)).await, &authority)
        .await;
    rpc.wait_finalized(&signature).await;
    let note_f: vault_program::NoteState = rpc.anchor_account(note_address(vault, 5)).await;
    let f0 = PrivateNoteState::genesis(5, secret_f, note_f.expiry);
    tree.set_leaf(5, f0.leaf());
    assert_solvent(&rpc, vault, vault_token, donated, "deposits E and F").await;
    let e_owner = Keypair::new();
    let e_account = Keypair::new();
    rpc.create_token_account(
        &authority,
        &e_account,
        TOKEN_PROGRAM_ID,
        USDC_MINT,
        e_owner.pubkey(),
    )
    .await;
    let e1 = wallet.advance(&e0, 10_000);
    let (e_escape, e_escape_proof) =
        wallet.withdrawal(&e1, e_account.pubkey(), 0, false, valid_until);
    let (f_escape, f_escape_proof) = wallet.withdrawal(&f0, forwarder_ata, 0, false, valid_until);
    for (public, proof, account) in [
        (&e_escape, &e_escape_proof, e_account.pubkey()),
        (&f_escape, &f_escape_proof, forwarder_ata),
    ] {
        rpc.send_operation(
            ledger
                .prepare_escape(WithdrawalRequest {
                    payer,
                    destination: LedgerAccount::new(account.to_bytes()),
                    public_inputs: public.clone(),
                    proof: proof.clone(),
                })
                .await
                .unwrap(),
            &authority,
        )
        .await;
    }
    rpc.send_signed(
        &[close_token_account_ix(
            e_account.pubkey(),
            authority.pubkey(),
            e_owner.pubkey(),
        )],
        &[&authority, &e_owner],
    )
    .await;
    assert!(rpc.account_value(e_account.pubkey()).await.is_none());
    let pending = ledger
        .pending_escapes(LedgerCommitment::Confirmed)
        .await
        .unwrap();
    assert_eq!(
        pending
            .iter()
            .map(|escape| escape.note_id)
            .collect::<Vec<_>>(),
        vec![2, 4, 5]
    );
    let deadline = pending.iter().map(|escape| escape.deadline).max().unwrap();
    rpc.wait_until_after(deadline).await;

    // A third party can neither block the escaper's rent refund by passing
    // it read-only nor redirect it to itself.
    let raw_sweeper = RawVault {
        vault,
        vault_token,
        payer: sweeper.pubkey(),
    };
    assert_rent_not_redirected(
        &rpc,
        &raw_sweeper,
        &sweeper,
        2,
        false,
        authority.pubkey(),
        destination,
        vault_program::NOTE_STATUS_PENDING,
    )
    .await;

    // Finalize C (newest state): c2 to the user.
    let destination_before = rpc.token_amount(destination).await;
    let signature = rpc
        .send_operation(
            ledger
                .prepare_finalize_escape(FinalizeEscapeRequest { payer, note_id: 2 })
                .await
                .unwrap(),
            &authority,
        )
        .await;
    compute_units.push(("finalize", rpc.compute_units(&signature).await));
    assert_eq!(
        u128::from(rpc.token_amount(destination).await - destination_before),
        c2.balance
    );
    owed += DEPOSIT - c2.balance;
    assert_solvent(&rpc, vault, vault_token, donated, "finalize C").await;

    // Finalize E with its account closed: the note closes, the operator
    // share accrues, and the user payout is parked (pending kept, stage 1).
    let e_final = e1.balance;
    let signature = rpc
        .send_operation(
            ledger
                .prepare_finalize_escape(FinalizeEscapeRequest {
                    payer: LedgerAccount::new(sweeper.pubkey().to_bytes()),
                    note_id: 4,
                })
                .await
                .unwrap(),
            &sweeper,
        )
        .await;
    compute_units.push((
        "finalize (payout parked)",
        rpc.compute_units(&signature).await,
    ));
    owed += DEPOSIT - e_final;
    let state = assert_solvent(&rpc, vault, vault_token, donated, "finalize E parked").await;
    assert_eq!(u128::from(state.deferred_payouts), e_final);
    assert_eq!(u128::from(state.treasury_accrued), owed);
    let parked: vault_program::PendingWithdrawal =
        rpc.anchor_account(pending_address(vault, 4)).await;
    assert_eq!(parked.stage, vault_program::PENDING_STAGE_PAYOUT_PARKED);
    let e_note: vault_program::NoteState = rpc.anchor_account(note_address(vault, 4)).await;
    assert_eq!(e_note.status, vault_program::NOTE_STATUS_CLOSED);
    assert_eq!(
        ledger
            .pending_escapes(LedgerCommitment::Confirmed)
            .await
            .unwrap()
            .iter()
            .map(|escape| escape.note_id)
            .collect::<Vec<_>>(),
        vec![5],
        "a parked payout is not a challengeable escape"
    );
    assert_rejected(
        ledger
            .prepare_finalize_escape(FinalizeEscapeRequest { payer, note_id: 4 })
            .await,
        "second finalize of a parked escape",
    );
    assert_vault_error(
        rpc.try_vault(
            raw.settle(4, false, authority.pubkey(), e_account.pubkey()),
            &[&sweeper, &authority],
        )
        .await,
        VaultError::NoteNotPending,
        "raw second finalize",
    );
    // Release fails while the account is closed.
    assert_rejected(
        ledger
            .prepare_release_escape_payout(ReleaseEscapePayoutRequest { payer, note_id: 4 })
            .await,
        "release to a closed account",
    );
    assert_vault_error(
        rpc.try_vault(
            raw.settle(4, true, authority.pubkey(), e_account.pubkey()),
            &[&sweeper, &authority],
        )
        .await,
        VaultError::InvalidTokenAccount,
        "raw release to a closed account",
    );
    assert_vault_error(
        rpc.try_vault(
            raw.settle(4, true, authority.pubkey(), attacker_ata),
            &[&sweeper, &authority],
        )
        .await,
        VaultError::DestinationMismatch,
        "release to a substituted account",
    );
    // Recreated at the same address, the account is paid exactly once. Its
    // pending rent still cannot be blocked or redirected by the caller.
    rpc.create_token_account(
        &authority,
        &e_account,
        TOKEN_PROGRAM_ID,
        USDC_MINT,
        e_owner.pubkey(),
    )
    .await;
    assert_rent_not_redirected(
        &rpc,
        &raw_sweeper,
        &sweeper,
        4,
        true,
        authority.pubkey(),
        e_account.pubkey(),
        vault_program::NOTE_STATUS_CLOSED,
    )
    .await;
    let (escaper_before, e_pending_rent) = (
        rpc.balance(authority.pubkey()).await,
        rpc.balance(pending_address(vault, 4)).await,
    );
    let signature = rpc
        .send_operation(
            browser_exit(
                &browser_funding,
                "release",
                json!({ "payer": sweeper.pubkey().to_string(), "note_id": 4 }),
            ),
            &sweeper,
        )
        .await;
    compute_units.push(("release_escape_payout", rpc.compute_units(&signature).await));
    assert_eq!(
        u128::from(rpc.token_amount(e_account.pubkey()).await),
        e_final
    );
    assert_eq!(
        rpc.balance(authority.pubkey()).await - escaper_before,
        e_pending_rent
    );
    assert!(rpc.account_value(pending_address(vault, 4)).await.is_none());
    let state = assert_solvent(&rpc, vault, vault_token, donated, "release E").await;
    assert_eq!(state.deferred_payouts, 0);
    assert!(ledger
        .prepare_release_escape_payout(ReleaseEscapePayoutRequest { payer, note_id: 4 })
        .await
        .is_err());
    assert!(rpc
        .try_vault(
            raw.settle(4, true, authority.pubkey(), e_account.pubkey()),
            &[&sweeper, &authority]
        )
        .await
        .is_err());
    assert_eq!(
        u128::from(rpc.token_amount(e_account.pubkey()).await),
        e_final,
        "a second release pays nothing"
    );

    // Finalize F to the PDA's (off-curve) account.
    let forwarder_before = rpc.token_amount(forwarder_ata).await;
    let signature = rpc
        .send_operation(
            ledger
                .prepare_finalize_escape(FinalizeEscapeRequest { payer, note_id: 5 })
                .await
                .unwrap(),
            &authority,
        )
        .await;
    rpc.wait_finalized(&signature).await;
    assert_eq!(
        u128::from(rpc.token_amount(forwarder_ata).await - forwarder_before),
        DEPOSIT
    );
    let state = assert_solvent(&rpc, vault, vault_token, donated, "finalize F").await;
    assert_eq!(state.total_credits, 0);
    assert_eq!(u128::from(state.treasury_accrued), owed);

    // The whole accrual is withdrawn to the pinned treasury, once.
    let treasury_before = rpc.token_amount(treasury_token).await;
    let signature = rpc.send_operation(sweep().await.unwrap(), &sweeper).await;
    rpc.wait_finalized(&signature).await;
    assert_eq!(
        u128::from(rpc.token_amount(treasury_token).await - treasury_before),
        owed
    );
    treasury_paid += owed;
    assert_rejected(sweep().await, "nothing left to withdraw");
    let state = assert_solvent(&rpc, vault, vault_token, donated, "final").await;
    assert_eq!(
        (
            state.total_credits,
            state.treasury_accrued,
            state.deferred_payouts
        ),
        (0, 0, 0)
    );
    assert_eq!(
        rpc.token_amount(vault_token).await,
        donated,
        "only the donation remains; it was never paid out"
    );
    assert!(ledger
        .pending_escapes(LedgerCommitment::Confirmed)
        .await
        .unwrap()
        .is_empty());
    // The finalized startup view agrees and passes the profile gate.
    let view = ledger.finalized_vault().await.unwrap();
    check_vault_profile(&view, &profile, &resolved).unwrap();
    assert_eq!(
        (
            view.vault_token_balance,
            view.total_credits,
            view.treasury_accrued,
            view.deferred_payouts
        ),
        (donated, 0, 0, 0)
    );
    // Closed notes keep their leaves until someone retires them.
    let final_state = ledger.state(LedgerCommitment::Finalized).await.unwrap();
    assert_eq!(final_state.next_note_id, 6);
    assert_eq!(final_state.root, tree.root());
    wait_indexed(
        &poller,
        &service,
        6,
        tree.root(),
        &[
            Felt252::ZERO,
            b0.leaf(),
            c0.leaf(),
            d0.leaf(),
            e0.leaf(),
            f0.leaf(),
        ],
    )
    .await;
    eprintln!("treasury paid {treasury_paid} base units in total");

    for (name, units) in &compute_units {
        eprintln!("CU {name}: {units}");
    }
}

/// A successful expired-note claim and the treasury withdrawal of its
/// accrual. Expiry is bucketed to UTC day boundaries, so this needs a stack
/// whose validator clock starts shortly before a UTC midnight and a vault
/// whose `note_ttl_seconds` is the test override.
#[tokio::test]
#[ignore = "requires the local stack started with a clock shortly before UTC midnight"]
async fn expired_note_claim_on_localnet() {
    let stack = Stack::from_env();
    let rpc = Rpc::new(stack.rpc_url.clone());
    let (mut profile, overrides) = test_profile();
    profile.vault.note_ttl_seconds = overrides["note_ttl_seconds"]
        .as_u64()
        .expect("localnet-test-overrides.json lacks note_ttl_seconds");
    let state_signer = CompactSigner::from_seed(&Felt252::from_u64(201));
    let clearance_signer = CompactSigner::from_seed(&Felt252::from_u64(202));
    let Deployment {
        authority,
        vault,
        vault_token,
        treasury_token,
        ledger,
        ..
    } = deploy(&rpc, &stack, &profile, &state_signer, &clearance_signer).await;
    let payer = LedgerAccount::new(authority.pubkey().to_bytes());
    let payer_ata = rpc.create_usdc_ata(&authority, authority.pubkey()).await;
    let deposit_units = u64::try_from(DEPOSIT).unwrap();
    rpc.fund_usdc(&stack, &authority, payer_ata, deposit_units)
        .await;
    let raw = RawVault {
        vault,
        vault_token,
        payer: authority.pubkey(),
    };
    let tree = MerkleTree::new();
    let signature = rpc
        .send_operation(
            ledger
                .prepare_deposit(DepositRequest {
                    payer,
                    expected_note_id: 0,
                    commitment: core::registration_commitment(&Felt252::from_u64(77)),
                    amount: DEPOSIT,
                    zero_path: tree.get_siblings(0),
                })
                .await
                .unwrap(),
            &authority,
        )
        .await;
    rpc.wait_confirmed(&signature).await;
    assert_solvent(&rpc, vault, vault_token, 0, "deposit").await;
    let note: vault_program::NoteState = rpc.anchor_account(note_address(vault, 0)).await;
    assert_vault_error(
        rpc.try_vault(raw.claim_expired(0), &[&authority]).await,
        VaultError::NoteNotExpired,
        "claim before expiry",
    );
    eprintln!(
        "waiting for the validator clock to pass {}",
        note.claimable_after
    );
    rpc.wait_until_after_for(note.claimable_after, 4 * 60 * 30)
        .await;
    let signature = rpc
        .send_operation(
            ledger
                .prepare_claim_expired(ClaimExpiredRequest { payer, note_id: 0 })
                .await
                .unwrap(),
            &authority,
        )
        .await;
    let claim_units = rpc.compute_units(&signature).await;
    let state = assert_solvent(&rpc, vault, vault_token, 0, "claim").await;
    assert_eq!(
        (state.total_credits, state.treasury_accrued),
        (0, deposit_units)
    );
    let closed: vault_program::NoteState = rpc.anchor_account(note_address(vault, 0)).await;
    assert_eq!(closed.status, vault_program::NOTE_STATUS_CLOSED);
    assert!(rpc
        .try_vault(raw.claim_expired(0), &[&authority])
        .await
        .is_err());
    let treasury_before = rpc.token_amount(treasury_token).await;
    let sweeper = Keypair::new();
    rpc.airdrop(sweeper.pubkey(), 100_000_000).await;
    let signature = rpc
        .send_operation(
            ledger
                .prepare_withdraw_treasury(LedgerAccount::new(sweeper.pubkey().to_bytes()))
                .await
                .unwrap(),
            &sweeper,
        )
        .await;
    let withdraw_units = rpc.compute_units(&signature).await;
    assert_eq!(
        rpc.token_amount(treasury_token).await - treasury_before,
        deposit_units
    );
    let state = assert_solvent(&rpc, vault, vault_token, 0, "withdraw").await;
    assert_eq!(state.treasury_accrued, 0);
    assert_eq!(rpc.token_amount(vault_token).await, 0);
    eprintln!("CU execute_claim_expired: {claim_units}");
    eprintln!("CU withdraw_treasury (claimed deposit): {withdraw_units}");
}
