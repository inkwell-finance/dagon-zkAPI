//! The wallet driver: every command a release build answers. Secrets (note secrets, blindings, keypair bytes) stay in this
//! process or in the keypair file; replies carry public keys, addresses and public protocol values, plus the wallet state and
//! pending-request journal that the caller keeps in its own owner-only storage.

use anyhow::{ensure, Context, Result};
use anchor_lang::AccountDeserialize;
use base64::Engine;
use dagon_zkapi_ledger::{CreditLedger, DepositRequest, LedgerAccount, LedgerCommitment, PreparedLedgerOperation, WithdrawalRequest};
use dagon_zkapi_solana_ledger::{SolanaCreditLedger, SolanaLedgerConfig};
use dagon_zkapi_vault as vault_program;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use solana_keypair::Keypair;
use solana_message::Message;
use solana_program::pubkey::Pubkey;
use solana_signer::Signer;
use std::{path::PathBuf, str::FromStr};
use zkapi_browser::{
    BrowserNoteState, BrowserWalletConfig, CompleteResponseArgs, ConfirmDepositArgs, PendingRequestJournal,
    PrepareRequestArgs, PrepareWithdrawalArgs, TreeSnapshot, WithdrawalPlan,
};
use zkapi_proof::compact::{RequestProver, CIRCUIT_ID};
use zkapi_types::{solana_chain_id, solana_deployment_binding, Felt252, MERKLE_DEPTH};

use crate::chain::{coded, Chain, Progress};

pub const SOLANA_BACKEND: &str = "dagon.solana.groth16.v1";
/// Version of the stdin/stdout command protocol. zkapi-clientd refuses a helper that reports another number.
pub const PROTOCOL: u32 = 1;
const COMPUTE_BUDGET_PROGRAM: &str = "ComputeBudget111111111111111111111111111111";

pub struct Deployment {
    pub ledger: SolanaCreditLedger,
    #[cfg_attr(not(feature = "dev"), allow(dead_code))]
    pub ledger_config: SolanaLedgerConfig,
    pub chain: Chain,
    pub program: Pubkey,
    pub vault: Pubkey,
}

pub struct WalletDriver {
    pub setup: PathBuf,
    pub rt: tokio::runtime::Runtime,
    pub deployment: Option<Deployment>,
    pub config: Option<BrowserWalletConfig>,
    pub state: Option<BrowserNoteState>,
    pub journal: Option<PendingRequestJournal>,
    pub request_prover: Option<RequestProver>,
    #[cfg(feature = "dev")]
    pub dev: crate::dev::DevState,
}

#[derive(Deserialize)]
struct PathArgs {
    snapshot: TreeSnapshot,
    note_id: u32,
    require_existing: bool,
}

/// One unsigned transaction of a staged vault operation.
#[derive(Serialize, Deserialize, Clone)]
struct OperationTx {
    message_b64: String,
    last_valid_height: u64,
}

#[derive(Serialize, Deserialize, Clone)]
struct Operation {
    transactions: Vec<OperationTx>,
    /// The staged operation buffer's ID (first instruction of the first transaction), needed to cancel an abandoned one.
    operation_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct SignedTx {
    transaction_b64: String,
    signature: String,
    last_valid_height: u64,
}

#[derive(Serialize, Deserialize, Clone)]
struct SignedOperation {
    transactions: Vec<SignedTx>,
}

pub fn read_keypair(path: &str) -> Result<Keypair> {
    let bytes: Vec<u8> = serde_json::from_slice(&std::fs::read(path).context("cannot read the keypair file")?)
        .context("the keypair file must be a Solana JSON byte array")?;
    Keypair::try_from(bytes.as_slice()).map_err(|error| anyhow::anyhow!("invalid keypair file: {error}"))
}

pub fn pubkey_of(value: &Value, field: &str) -> Result<Pubkey> {
    Pubkey::from_str(value[field].as_str().with_context(|| field.to_string())?).with_context(|| format!("invalid {field}"))
}

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

/// The ledger's refusals that a client can act on, as stable codes.
fn ledger_error(error: impl std::fmt::Display) -> anyhow::Error {
    let text = error.to_string();
    if text.contains("stale or foreign deployment") || text.contains("does not match the current root") || text.contains("does not prove an empty leaf") {
        coded("stale_root", text)
    } else if text.contains("note ID is stale") {
        coded("stale_note_id", text)
    } else {
        anyhow::anyhow!(text)
    }
}

fn to_operation(operation: PreparedLedgerOperation) -> Result<Operation> {
    ensure!(!operation.transactions.is_empty(), "empty ledger operation");
    let first: Message = bincode::deserialize(&operation.transactions[0].bytes).context("prepared message")?;
    // The initialize instruction is the first one of the first transaction: 8-byte discriminator, then the 32-byte ID.
    let data = &first.instructions.first().context("prepared message has no instruction")?.data;
    ensure!(data.len() >= 40, "unexpected operation initialization");
    let operation_id = data[8..40].iter().map(|b| format!("{b:02x}")).collect::<String>();
    operation_with_id(operation, operation_id)
}

// A direct cancellation has only its 8-byte discriminator, not an initialization ID.
fn operation_with_id(operation: PreparedLedgerOperation, operation_id: String) -> Result<Operation> {
    ensure!(!operation.transactions.is_empty(), "empty ledger operation");
    let transactions = operation
        .transactions
        .into_iter()
        .map(|tx| {
            Ok(OperationTx { message_b64: b64().encode(&tx.bytes), last_valid_height: tx.last_valid_height.context("transaction has no block-height deadline")? })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(Operation { transactions, operation_id })
}

/// Refuse to sign anything but this vault's own instructions (and compute budget requests), paid for and signed only by the
/// local keypair. The messages come from this helper's own ledger, but they travel through the caller's journal in between.
fn inspect(message: &Message, signer: &Pubkey, program: &Pubkey, vault: &Pubkey) -> Result<()> {
    let compute = Pubkey::from_str(COMPUTE_BUDGET_PROGRAM)?;
    ensure!(
        message.header.num_required_signatures == 1 && message.account_keys.first() == Some(signer),
        "the transaction must be paid and signed only by the funding keypair"
    );
    for instruction in &message.instructions {
        let target = message.account_keys.get(instruction.program_id_index as usize).context("instruction program")?;
        if target == &compute {
            continue;
        }
        ensure!(target == program, "the transaction calls a program other than the pinned vault program");
        let first = instruction.accounts.first().and_then(|index| message.account_keys.get(*index as usize));
        ensure!(first == Some(vault), "the transaction does not act on the pinned vault");
    }
    Ok(())
}

fn felt(value: &Value, field: &str) -> Result<Felt252> {
    Felt252::from_hex(value[field].as_str().with_context(|| field.to_string())?).map_err(|error| anyhow::anyhow!("invalid {field}: {error}"))
}

impl WalletDriver {
    pub fn new(setup: PathBuf) -> Result<Self> {
        Ok(Self {
            setup,
            rt: tokio::runtime::Builder::new_multi_thread().enable_all().build()?,
            deployment: None,
            config: None,
            state: None,
            journal: None,
            request_prover: None,
            #[cfg(feature = "dev")]
            dev: Default::default(),
        })
    }

    pub fn status(&self) -> Value {
        json!({
            "state": zkapi_browser::wallet_status(self.state.as_ref(), self.journal.as_ref()),
            "withdrawal_nullifier": self.state.as_ref().map(zkapi_browser::withdrawal_nullifier),
            "pending_request": self.journal.is_some(),
        })
    }

    pub fn deployment(&self) -> Result<&Deployment> {
        self.deployment.as_ref().context("run connect first")
    }

    pub fn handle(&mut self, command: &Value) -> Result<Value> {
        match command["command"].as_str().context("command must be a string")? {
            "handshake" => Ok(json!({
                "name": "zkapi-solana-wallet",
                "version": env!("CARGO_PKG_VERSION"),
                "protocol": PROTOCOL,
                "circuit_id": CIRCUIT_ID,
                "ledger_backend": SOLANA_BACKEND,
                "dev": cfg!(feature = "dev"),
            })),
            "derive_deployment" => {
                // Pure derivation of the proof chain ID and protocol binding from public identities (no RPC), so zkapi-clientd
                // can pin a deployment without re-implementing the derivation.
                let (program_id, vault_state, genesis) =
                    (pubkey_of(command, "program_id")?.to_bytes(), pubkey_of(command, "vault_state")?.to_bytes(), pubkey_of(command, "genesis_hash")?.to_bytes());
                Ok(json!({
                    "chain_id": solana_chain_id(&genesis).to_string(),
                    "protocol_binding": solana_deployment_binding(&program_id, &vault_state, &genesis),
                }))
            }
            "wallet_config" => {
                // The wallet configuration for a pinned deployment, derived exactly as the vault derives its identity.
                let (program_id, vault_state, genesis) =
                    (pubkey_of(command, "program_id")?.to_bytes(), pubkey_of(command, "vault_state")?.to_bytes(), pubkey_of(command, "genesis_hash")?.to_bytes());
                let config = BrowserWalletConfig {
                    protocol_version: 2,
                    ledger_backend: SOLANA_BACKEND.into(),
                    chain_id: solana_chain_id(&genesis),
                    contract_address: solana_deployment_binding(&program_id, &vault_state, &genesis),
                    request_charge_cap: u128::from(command["request_charge_cap"].as_u64().context("request_charge_cap")?),
                    policy_charge_cap: 0,
                    policy_enabled: false,
                    state_signing_key: serde_json::from_value(command["state_signing_key"].clone()).context("state_signing_key")?,
                    clearance_signing_key: serde_json::from_value(command["clearance_signing_key"].clone()).context("clearance_signing_key")?,
                };
                Ok(serde_json::to_value(config)?)
            }
            "load_wallet" => {
                // Replace the whole in-memory wallet from durable client storage (zkapi-clientd keeps state and the pending
                // journal itself and starts this helper per operation).
                let config: BrowserWalletConfig = serde_json::from_value(command["config"].clone())?;
                ensure!(config.protocol_version == 2, "only protocol v2 is supported");
                ensure!(config.ledger_backend == SOLANA_BACKEND, "not a Solana wallet");
                ensure!(!config.contract_address.is_zero(), "vault binding is required");
                self.state = serde_json::from_value(command["state"].clone())?;
                self.journal = serde_json::from_value(command["journal"].clone())?;
                self.config = Some(config);
                Ok(self.status())
            }
            "export_wallet" => {
                // Secret-bearing: the caller must store this in an owner-only file and never log it.
                Ok(json!({
                    "config": self.config.as_ref().context("no wallet configuration")?,
                    "state": self.state,
                    "journal": self.journal,
                }))
            }
            "status" => Ok(self.status()),
            "prepare_request" => {
                ensure!(self.journal.is_none(), "a request is already pending");
                let args: PrepareRequestArgs = serde_json::from_value(command["args"].clone())?;
                if self.request_prover.is_none() {
                    self.request_prover = Some(RequestProver::load(&self.setup)?);
                }
                let prepared = zkapi_browser::prepare_request_with_prover(
                    self.config.as_ref().context("initialize the wallet first")?,
                    self.state.as_ref().context("confirm a deposit first")?,
                    args,
                    self.request_prover.as_ref().context("missing request prover")?,
                )?;
                self.journal = Some(prepared.journal.clone());
                Ok(json!({"request": prepared.request, "journal": prepared.journal}))
            }
            "complete_response" => {
                let next = zkapi_browser::complete_response(
                    self.config.as_ref().context("initialize the wallet first")?,
                    CompleteResponseArgs {
                        state: self.state.clone().context("confirm a deposit first")?,
                        journal: self.journal.clone().context("no pending request")?,
                        response: serde_json::from_value(command["response"].clone())?,
                    },
                )?;
                self.state = Some(next);
                self.journal = None;
                Ok(self.status())
            }
            "tree_path" => {
                let args: PathArgs = serde_json::from_value(command["args"].clone())?;
                Ok(serde_json::to_value(zkapi_browser::tree_path(args.snapshot, args.note_id, args.require_existing)?)?)
            }
            "withdrawal_nullifier" => {
                let state = self.state.as_ref().context("the wallet has no note")?;
                Ok(json!({"nullifier": zkapi_browser::withdrawal_nullifier(state)}))
            }
            "keypair_pubkey" => {
                let keypair = read_keypair(command["keypair"].as_str().context("keypair")?)?;
                Ok(json!({"pubkey": keypair.pubkey().to_string()}))
            }
            "connect" => {
                // The pinned chain access for funding commands: one RPC, one optional finalized-account indexer.
                let rpc = command["rpc_url"].as_str().context("rpc_url")?;
                let chain = Chain::new(rpc)?;
                let ledger_config = SolanaLedgerConfig {
                    rpc_url: rpc.to_string(),
                    indexer_url: command["indexer_url"].as_str().map(str::to_string),
                    network: command["network"].as_str().context("network")?.to_string(),
                    program_id: pubkey_of(command, "program_id")?.to_bytes(),
                    vault_state: pubkey_of(command, "vault_state")?.to_bytes(),
                    genesis_hash: pubkey_of(command, "genesis_hash")?.to_bytes(),
                };
                let genesis = self.rt.block_on(chain.call("getGenesisHash", json!([])))?;
                if Pubkey::from_str(genesis.as_str().unwrap_or_default())?.to_bytes() != ledger_config.genesis_hash {
                    return Err(coded("wrong_cluster", "the RPC is on a different cluster than the pinned genesis hash"));
                }
                let ledger = SolanaCreditLedger::new(ledger_config.clone())?;
                self.deployment = Some(Deployment {
                    ledger,
                    chain,
                    program: Pubkey::new_from_array(ledger_config.program_id),
                    vault: Pubkey::new_from_array(ledger_config.vault_state),
                    ledger_config,
                });
                Ok(json!({"connected": true}))
            }
            "deposit_params" => Ok(serde_json::to_value(zkapi_browser::generate_deposit_params())?),
            "deposit_prepare" => {
                // One staged deposit operation for the next note ID, from a finalized whole-tree snapshot.
                let deployment = self.deployment()?;
                let payer = LedgerAccount::new(pubkey_of(command, "payer")?.to_bytes());
                let amount = command["amount"].as_u64().context("amount")?;
                let commitment = felt(command, "commitment")?;
                let (note_id, operation) = self.rt.block_on(async {
                    let snapshot = deployment.ledger.snapshot(LedgerCommitment::Finalized).await.map_err(ledger_error)?;
                    let note_id = snapshot.state.next_note_id;
                    let path = zkapi_browser::tree_path(
                        TreeSnapshot { root: snapshot.state.root, next_note_id: note_id, leaves: snapshot.leaves },
                        note_id,
                        false,
                    )?;
                    let operation = deployment
                        .ledger
                        .prepare_deposit(DepositRequest {
                            payer,
                            expected_note_id: note_id,
                            commitment,
                            amount: u128::from(amount),
                            zero_path: path.siblings.try_into().map_err(|_| anyhow::anyhow!("path length"))?,
                        })
                        .await
                        .map_err(ledger_error)?;
                    Ok::<_, anyhow::Error>((note_id, to_operation(operation)?))
                })?;
                Ok(json!({"note_id": note_id, "operation": operation}))
            }
            "deposit_confirm" => {
                // Promote a finalized deposit into note state; the caller verified the chain's note account.
                let state = zkapi_browser::confirm_deposit(
                    self.config.as_ref().context("initialize the wallet first")?,
                    ConfirmDepositArgs {
                        secret: felt(command, "secret")?,
                        note_id: command["note_id"].as_u64().context("note_id")? as u32,
                        amount: u128::from(command["amount"].as_u64().context("amount")?),
                        expiry_ts: command["expiry_ts"].as_u64().context("expiry_ts")?,
                    },
                )?;
                Ok(json!({"state": state}))
            }
            "withdraw_prove" => {
                // Mutual close: the clearance signature came from the pinned server for exactly this note's nullifier.
                let mut args = command["args"].clone();
                args["mode"] = json!("mutual");
                let args: PrepareWithdrawalArgs = serde_json::from_value(args)?;
                let key = std::fs::read(self.setup.join("withdrawal.pk")).context("read withdrawal.pk")?;
                let plan = zkapi_browser::prepare_withdrawal(
                    self.config.as_ref().context("initialize the wallet first")?,
                    self.state.as_ref().context("the wallet has no note")?,
                    args,
                    &key,
                )?;
                Ok(serde_json::to_value(plan)?)
            }
            "withdraw_prepare" => {
                let deployment = self.deployment()?;
                let plan: WithdrawalPlan = serde_json::from_value(command["plan"].clone())?;
                ensure!(plan.mode == "mutual", "only mutual closes are supported");
                let siblings: [Felt252; MERKLE_DEPTH] = plan.siblings.try_into().map_err(|_| anyhow::anyhow!("path length"))?;
                let request = WithdrawalRequest {
                    payer: LedgerAccount::new(pubkey_of(command, "payer")?.to_bytes()),
                    destination: LedgerAccount::new(pubkey_of(command, "destination")?.to_bytes()),
                    public_inputs: plan.public_inputs,
                    proof: plan.proof,
                    siblings,
                };
                let operation = self.rt.block_on(deployment.ledger.prepare_close(request)).map_err(ledger_error)?;
                Ok(json!({"operation": to_operation(operation)?}))
            }
            "cancel_prepare" => {
                // Close an abandoned staged operation buffer and return its rent to the owner.
                let deployment = self.deployment()?;
                let id: [u8; 32] = command["operation_id"]
                    .as_str()
                    .and_then(|text| (0..text.len()).step_by(2).map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok()).collect::<Option<Vec<u8>>>())
                    .and_then(|bytes| bytes.try_into().ok())
                    .context("operation_id must be 32 bytes of hex")?;
                let owner = pubkey_of(command, "payer")?;
                let (buffer, _) = Pubkey::find_program_address(&[b"operation", deployment.vault.as_ref(), owner.as_ref(), &id], &deployment.program);
                let account = self.rt.block_on(deployment.chain.account(&buffer, "finalized"))?;
                let Some((buffer_owner, _)) = account else { return Err(coded("buffer_absent", "staged buffer is absent")); };
                ensure!(buffer_owner == deployment.program, "staged buffer owner mismatch");
                let payer = LedgerAccount::new(owner.to_bytes());
                let operation = self.rt.block_on(deployment.ledger.prepare_cancel_operation(payer, id)).map_err(ledger_error)?;
                Ok(json!({"operation": operation_with_id(operation, command["operation_id"].as_str().unwrap().to_string())?}))
            }
            "sign_operation" => {
                let deployment = self.deployment()?;
                let signer = read_keypair(command["keypair"].as_str().context("keypair")?)?;
                let operation: Operation = serde_json::from_value(command["operation"].clone())?;
                let mut signed = Vec::new();
                for tx in operation.transactions {
                    let bytes = b64().decode(&tx.message_b64).context("message encoding")?;
                    let message: Message = bincode::deserialize(&bytes).context("message")?;
                    inspect(&message, &signer.pubkey(), &deployment.program, &deployment.vault)?;
                    let signature = signer.sign_message(&bytes);
                    let mut transaction = vec![1u8];
                    transaction.extend_from_slice(signature.as_ref());
                    transaction.extend_from_slice(&bytes);
                    signed.push(SignedTx { transaction_b64: b64().encode(transaction), signature: signature.to_string(), last_valid_height: tx.last_valid_height });
                }
                Ok(json!({"signed": SignedOperation { transactions: signed }}))
            }
            "submit_signed" => {
                // Idempotent: a transaction that already landed (an earlier run, a crash) is skipped, one whose blockhash is
                // gone and which never landed is reported as expired and never retried.
                let deployment = self.deployment()?;
                let signed: SignedOperation = serde_json::from_value(command["signed"].clone())?;
                let finalize = command["finalize"].as_bool().unwrap_or(true);
                let chain = &deployment.chain;
                let mut signatures = Vec::new();
                self.rt.block_on(async {
                    for (index, tx) in signed.transactions.iter().enumerate() {
                        let last = index + 1 == signed.transactions.len();
                        let status = chain.status(&tx.signature).await?;
                        if status.failed && status.progress == Progress::Finalized {
                            return Err(coded("transaction_failed", format!("transaction {} failed on chain", tx.signature)));
                        }
                        if status.progress == Progress::Unknown {
                            if chain.finalized_height().await? > tx.last_valid_height {
                                return Err(coded("blockhash_expired", "the signed transaction expired before it landed"));
                            }
                            chain.send_signed(&tx.transaction_b64, &tx.signature).await?;
                        }
                        chain.wait(&tx.signature, last && finalize).await?;
                        signatures.push(tx.signature.clone());
                    }
                    Ok::<(), anyhow::Error>(())
                })?;
                Ok(json!({"signatures": signatures}))
            }
            "signed_status" => {
                let deployment = self.deployment()?;
                let signed: SignedOperation = serde_json::from_value(command["signed"].clone())?;
                let chain = &deployment.chain;
                let (rows, expired) = self.rt.block_on(async {
                    let height = chain.finalized_height().await?;
                    let mut rows = Vec::new();
                    let mut expired = false;
                    for tx in &signed.transactions {
                        let status = chain.status(&tx.signature).await?;
                        expired |= status.progress == Progress::Unknown && height > tx.last_valid_height;
                        let progress = match status.progress {
                            Progress::Unknown => "unknown",
                            Progress::Processed => "processed",
                            Progress::Confirmed => "confirmed",
                            Progress::Finalized => "finalized",
                        };
                        rows.push(json!({"signature": tx.signature, "progress": progress, "failed": status.failed}));
                    }
                    Ok::<_, anyhow::Error>((rows, expired))
                })?;
                Ok(json!({"transactions": rows, "expired": expired}))
            }
            "note_status" => {
                let deployment = self.deployment()?;
                let note_id = command["note_id"].as_u64().context("note_id")? as u32;
                let (address, _) =
                    Pubkey::find_program_address(&[b"note", deployment.vault.as_ref(), &note_id.to_le_bytes()], &deployment.program);
                let account = self.rt.block_on(deployment.chain.account(&address, "finalized"))?;
                let Some((owner, data)) = account else {
                    return Ok(json!({"exists": false, "address": address.to_string()}));
                };
                ensure!(owner == deployment.program, "the note account is not owned by the vault program");
                let note = vault_program::NoteState::try_deserialize(&mut data.as_slice())?;
                ensure!(note.vault == deployment.vault && note.note_id == note_id, "the note account belongs to another vault");
                Ok(json!({
                    "exists": true, "address": address.to_string(), "commitment": Felt252(note.commitment),
                    "amount": note.deposit_amount, "expiry": note.expiry, "active": note.status == vault_program::NOTE_STATUS_ACTIVE,
                }))
            }
            "nullifier_status" => {
                let deployment = self.deployment()?;
                let nullifier = felt(command, "nullifier")?;
                let (address, _) =
                    Pubkey::find_program_address(&[b"nullifier", deployment.vault.as_ref(), nullifier.as_bytes()], &deployment.program);
                let account = self.rt.block_on(deployment.chain.account(&address, "finalized"))?;
                let used = matches!(&account, Some((owner, _)) if *owner == deployment.program);
                Ok(json!({"used": used, "address": address.to_string()}))
            }
            _ => self.handle_dev(command),
        }
    }

    #[cfg(not(feature = "dev"))]
    fn handle_dev(&mut self, _command: &Value) -> Result<Value> {
        anyhow::bail!("unsupported command")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dagon_zkapi_ledger::PreparedLedgerTransaction;
    use solana_program::{hash::Hash, instruction::Instruction};

    fn driver() -> WalletDriver {
        WalletDriver::new(PathBuf::from(".")).unwrap()
    }

    fn connected(driver: &mut WalletDriver) -> Pubkey {
        let config = SolanaLedgerConfig {
            rpc_url: "http://127.0.0.1:1".into(),
            indexer_url: None,
            network: "localnet".into(),
            program_id: vault_program::ID.to_bytes(),
            vault_state: Pubkey::new_unique().to_bytes(),
            genesis_hash: Pubkey::new_unique().to_bytes(),
        };
        let vault = Pubkey::new_from_array(config.vault_state);
        driver.deployment = Some(Deployment {
            ledger: SolanaCreditLedger::new(config.clone()).unwrap(),
            chain: Chain::new("http://127.0.0.1:1").unwrap(),
            program: vault_program::ID,
            vault,
            ledger_config: config,
        });
        vault
    }

    fn message(payer: &Pubkey, program: Pubkey, first_account: Pubkey, data: Vec<u8>) -> Message {
        let instruction = Instruction {
            program_id: program,
            accounts: vec![solana_program::instruction::AccountMeta::new(first_account, false)],
            data,
        };
        Message::new_with_blockhash(&[instruction], Some(payer), &Hash::default())
    }

    fn key() -> Value {
        json!({"x": format!("0x{}", "11".repeat(32)), "y": format!("0x{}", "12".repeat(32))})
    }

    #[test]
    fn handshake_reports_the_protocol_and_the_build_kind() {
        let reply = driver().handle(&json!({"command": "handshake"})).unwrap();
        assert_eq!(reply["protocol"], PROTOCOL);
        assert_eq!(reply["name"], "zkapi-solana-wallet");
        assert_eq!(reply["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(reply["dev"], cfg!(feature = "dev"));
    }

    #[cfg(not(feature = "dev"))]
    #[test]
    fn a_release_build_has_no_test_only_commands() {
        let mut driver = driver();
        for command in ["keygen", "airdrop", "vault_init", "pyth_update", "public_keys", "deposit"] {
            assert!(driver.handle(&json!({"command": command, "path": "x"})).is_err(), "{command} must not exist in a release build");
        }
    }

    #[test]
    fn derivation_and_wallet_config_agree_on_the_vault_identity() {
        let mut driver = driver();
        let (program, vault, genesis) = (Pubkey::new_unique().to_string(), Pubkey::new_unique().to_string(), Pubkey::new_unique().to_string());
        let derived = driver
            .handle(&json!({"command": "derive_deployment", "program_id": program, "vault_state": vault, "genesis_hash": genesis}))
            .unwrap();
        let config = driver
            .handle(&json!({"command": "wallet_config", "program_id": program, "vault_state": vault, "genesis_hash": genesis,
                "state_signing_key": key(), "clearance_signing_key": key(), "request_charge_cap": 12_000_000u64}))
            .unwrap();
        assert_eq!(config["chain_id"].to_string().trim_matches('"'), derived["chain_id"].as_str().unwrap());
        assert_eq!(config["contract_address"], derived["protocol_binding"]);
        assert_eq!(config["ledger_backend"], SOLANA_BACKEND);
        assert_eq!(config["request_charge_cap"], 12_000_000u64);
    }

    #[test]
    fn inspection_signs_only_the_pinned_vaults_own_instructions() {
        let payer = Pubkey::new_unique();
        let vault = Pubkey::new_unique();
        let good = message(&payer, vault_program::ID, vault, vec![0; 8]);
        inspect(&good, &payer, &vault_program::ID, &vault).unwrap();
        // The keypair must be the fee payer.
        assert!(inspect(&good, &Pubkey::new_unique(), &vault_program::ID, &vault).is_err());
        // A foreign program, or another vault, is never signed.
        assert!(inspect(&message(&payer, Pubkey::new_unique(), vault, vec![]), &payer, &vault_program::ID, &vault).is_err());
        assert!(inspect(&message(&payer, vault_program::ID, Pubkey::new_unique(), vec![]), &payer, &vault_program::ID, &vault).is_err());
        // A system-program transfer drains the payer: refused.
        assert!(inspect(&message(&payer, Pubkey::default(), vault, vec![2, 0, 0, 0]), &payer, &vault_program::ID, &vault).is_err());
    }

    #[test]
    fn signing_is_deterministic_and_verifiable_and_refuses_foreign_messages() {
        let mut driver = driver();
        let vault = connected(&mut driver);
        let dir = std::env::temp_dir().join(format!("zkapi-solana-wallet-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("key.json");
        let signer = Keypair::new();
        std::fs::write(&path, serde_json::to_vec(&signer.to_bytes().to_vec()).unwrap()).unwrap();
        let bytes = bincode::serialize(&message(&signer.pubkey(), vault_program::ID, vault, vec![1; 8])).unwrap();
        let operation = json!({"transactions": [{"message_b64": b64().encode(&bytes), "last_valid_height": 77}], "operation_id": "00"});
        let command = json!({"command": "sign_operation", "keypair": path.to_str().unwrap(), "operation": operation});
        let first = driver.handle(&command).unwrap();
        assert_eq!(first, driver.handle(&command).unwrap());
        let tx = &first["signed"]["transactions"][0];
        assert_eq!(tx["last_valid_height"], 77);
        let raw = b64().decode(tx["transaction_b64"].as_str().unwrap()).unwrap();
        assert_eq!(raw[0], 1);
        assert_eq!(&raw[65..], bytes.as_slice());
        let signature = signer.sign_message(&bytes);
        assert_eq!(tx["signature"].as_str().unwrap(), signature.to_string());
        assert!(signature.verify(signer.pubkey().as_ref(), &bytes));
        // Someone else's fee payer is refused even though the vault is the right one.
        let foreign = bincode::serialize(&message(&Pubkey::new_unique(), vault_program::ID, vault, vec![1; 8])).unwrap();
        let operation = json!({"transactions": [{"message_b64": b64().encode(&foreign), "last_valid_height": 77}], "operation_id": "00"});
        assert!(driver.handle(&json!({"command": "sign_operation", "keypair": path.to_str().unwrap(), "operation": operation})).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn an_operation_exposes_its_buffer_id_for_cancellation() {
        let payer = Pubkey::new_unique();
        let mut data = vec![9; 8];
        data.extend_from_slice(&[0xab; 32]);
        data.extend_from_slice(&[1, 2, 3]);
        let bytes = bincode::serialize(&message(&payer, vault_program::ID, Pubkey::new_unique(), data)).unwrap();
        let transaction = |last_valid_height| PreparedLedgerTransaction {
            format: "solana-legacy-message-v1".into(),
            bytes: bytes.clone(),
            required_signers: vec![],
            last_valid_height,
        };
        let operation = to_operation(PreparedLedgerOperation { transactions: vec![transaction(Some(5))] }).unwrap();
        assert_eq!(operation.operation_id, "ab".repeat(32));
        assert_eq!(operation.transactions[0].last_valid_height, 5);
        assert!(to_operation(PreparedLedgerOperation { transactions: vec![transaction(None)] }).is_err());
        assert!(to_operation(PreparedLedgerOperation { transactions: vec![] }).is_err());
    }

    #[test]
    fn ledger_refusals_that_a_client_can_act_on_carry_stable_codes() {
        let code = |text: &str| ledger_error(text).downcast_ref::<crate::chain::Coded>().map(|coded| coded.code);
        assert_eq!(code("withdrawal proof targets a stale or foreign deployment"), Some("stale_root"));
        assert_eq!(code("deposit path does not prove an empty leaf at the current root"), Some("stale_root"));
        assert_eq!(code("deposit note ID is stale"), Some("stale_note_id"));
        assert_eq!(code("something else"), None);
    }

    #[test]
    fn wallet_state_round_trips_through_load_and_export() {
        let mut driver = driver();
        let config = driver
            .handle(&json!({"command": "wallet_config", "program_id": Pubkey::new_unique().to_string(), "vault_state": Pubkey::new_unique().to_string(),
                "genesis_hash": Pubkey::new_unique().to_string(), "state_signing_key": key(), "clearance_signing_key": key(), "request_charge_cap": 5u64}))
            .unwrap();
        driver.handle(&json!({"command": "load_wallet", "config": config, "state": null, "journal": null})).unwrap();
        let exported = driver.handle(&json!({"command": "export_wallet"})).unwrap();
        assert_eq!(exported["config"], config);
        assert!(exported["state"].is_null());
        assert_eq!(driver.handle(&json!({"command": "status"})).unwrap()["pending_request"], false);
        assert!(driver.handle(&json!({"command": "withdrawal_nullifier"})).is_err(), "no note, no nullifier");
    }
}

#[cfg(test)]
mod cancellation_tests {
    use super::*;
    use dagon_zkapi_ledger::PreparedLedgerTransaction;
    use solana_program::{hash::Hash, instruction::Instruction};
    #[test]
    fn direct_cancellation_does_not_require_an_initialization_payload() {
        let payer = Pubkey::new_unique();
        let instruction = Instruction { program_id: vault_program::ID, accounts: vec![], data: vec![7;8] };
        let message = Message::new_with_blockhash(&[instruction], Some(&payer), &Hash::default());
        let operation = PreparedLedgerOperation { transactions: vec![PreparedLedgerTransaction {
            format: "solana-legacy-message-v1".into(), bytes:bincode::serialize(&message).unwrap(), required_signers:vec![], last_valid_height:Some(5)
        }] };
        let result = operation_with_id(operation, "ab".repeat(32)).unwrap();
        assert_eq!(result.operation_id, "ab".repeat(32));
        assert_eq!(result.transactions.len(), 1);
    }
}
