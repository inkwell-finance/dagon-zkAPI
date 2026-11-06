//! In-memory wallet driver for scripts/v2-acceptance.mjs.
//!
//! Each stdin line is a JSON command; stdout contains only JSON replies. Wallet
//! secrets, blindings and pending journals remain in this process. This helper
//! does no networking and never reads an existing wallet or signing credential.
//! It calls the same pure wallet operations used by the browser SDK. Named
//! snapshots deliberately retain a genuine server-signed state for the stale
//! escape scenarios; the helper never constructs a synthetic signed state.
//! Exits are leaf-bound: `prepare_withdrawal` takes `conceded` and
//! `valid_until`, needs no Merkle path, and returns `inputs_abi`, the
//! 18-word ABI tuple `Types.WithdrawalPublicInputs`.

use anyhow::{bail, ensure, Context, Result};
use base64::Engine;
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    io::{self, BufRead, Write},
    path::PathBuf,
};
use zkapi_browser::{
    BrowserNoteState, BrowserWalletConfig, CompleteResponseArgs, ConfirmDepositArgs,
    PendingRequestJournal, PrepareRequestArgs, PrepareWithdrawalArgs, TreeSnapshot,
};
use zkapi_proof::compact::{CompactSigner, RequestProver, CIRCUIT_ID};
use zkapi_types::{Felt252, WithdrawalPublicInputsV2};

/// ABI-encode `Types.WithdrawalPublicInputs` (18 static words; the packed
/// note fields of the proof are unpacked into noteId, depositAmount, expiryTs).
fn withdrawal_tuple_abi(inputs: &WithdrawalPublicInputsV2) -> String {
    let words = [
        Felt252::from_u64(inputs.protocol_version as u64),
        Felt252::from_u64(inputs.chain_id),
        inputs.contract_address,
        inputs.registration,
        inputs.state_signing_key_x,
        inputs.state_signing_key_y,
        inputs.clearance_signing_key_x,
        inputs.clearance_signing_key_y,
        Felt252::from_u64(inputs.note_id as u64),
        Felt252::from_u128(inputs.deposit_amount),
        Felt252::from_u64(inputs.expiry_ts),
        Felt252::from_u128(inputs.final_balance),
        inputs.destination_field(),
        inputs.withdrawal_nullifier,
        Felt252::from_u64(inputs.has_clearance as u64),
        inputs.next_nullifier,
        Felt252::from_u128(inputs.conceded),
        Felt252::from_u64(inputs.valid_until),
    ];
    format!(
        "0x{}",
        words
            .iter()
            .map(|value| hex::encode(value.as_bytes()))
            .collect::<String>()
    )
}

struct WalletDriver {
    setup: PathBuf,
    config: Option<BrowserWalletConfig>,
    state: Option<BrowserNoteState>,
    deposit_secret: Option<Felt252>,
    journal: Option<PendingRequestJournal>,
    snapshots: BTreeMap<String, BrowserNoteState>,
    request_prover: Option<RequestProver>,
    withdrawal_key: Option<Vec<u8>>,
}

#[derive(Deserialize)]
struct ConfirmArgs {
    note_id: u32,
    amount: u128,
    expiry_ts: u64,
}

#[derive(Deserialize)]
struct PathArgs {
    snapshot: TreeSnapshot,
    note_id: u32,
    require_existing: bool,
}

impl WalletDriver {
    fn new(setup: PathBuf) -> Self {
        Self {
            setup,
            config: None,
            state: None,
            deposit_secret: None,
            journal: None,
            snapshots: BTreeMap::new(),
            request_prover: None,
            withdrawal_key: None,
        }
    }

    fn status(&self) -> Value {
        json!({
            "state": zkapi_browser::wallet_status(self.state.as_ref(), self.journal.as_ref()),
            "withdrawal_nullifier": self.state.as_ref().map(zkapi_browser::withdrawal_nullifier),
            "successor_nullifier": self.state.as_ref().map(zkapi_browser::successor_nullifier),
            "pending_request": self.journal.is_some(),
        })
    }

    fn handle(&mut self, command: &Value) -> Result<Value> {
        match command["command"]
            .as_str()
            .context("command must be a string")?
        {
            "public_keys" => Ok(json!({
                "state_signing_key": CompactSigner::from_seed(&Felt252::from_u64(1)).public_key(),
                "clearance_signing_key": CompactSigner::from_seed(&Felt252::from_u64(2)).public_key(),
                "circuit_id": CIRCUIT_ID,
            })),
            "init" => {
                ensure!(self.config.is_none(), "wallet is already initialized");
                let config: BrowserWalletConfig =
                    serde_json::from_value(command["config"].clone())?;
                ensure!(
                    config.protocol_version == 2,
                    "only protocol v2 is supported"
                );
                ensure!(
                    config.chain_id == 11_155_111,
                    "acceptance wallet requires the signer-compatible local chain ID 11155111"
                );
                ensure!(
                    !config.contract_address.is_zero(),
                    "vault address is required"
                );
                self.config = Some(config);
                Ok(self.status())
            }
            "deposit_params" => {
                ensure!(self.config.is_some(), "initialize the wallet first");
                ensure!(self.state.is_none(), "wallet already has a note");
                ensure!(self.deposit_secret.is_none(), "deposit is already prepared");
                let params = zkapi_browser::generate_deposit_params();
                self.deposit_secret = Some(params.secret);
                Ok(json!({"registration_commitment": params.registration_commitment}))
            }
            "confirm_deposit" => {
                ensure!(self.state.is_none(), "wallet already has a note");
                let args: ConfirmArgs = serde_json::from_value(command["args"].clone())?;
                let state = zkapi_browser::confirm_deposit(
                    self.config
                        .as_ref()
                        .context("initialize the wallet first")?,
                    ConfirmDepositArgs {
                        secret: self.deposit_secret.context("prepare a deposit first")?,
                        note_id: args.note_id,
                        amount: args.amount,
                        expiry_ts: args.expiry_ts,
                    },
                )?;
                self.state = Some(state);
                self.deposit_secret = None;
                Ok(self.status())
            }
            "prepare_request" => {
                ensure!(self.journal.is_none(), "a request is already pending");
                let args: PrepareRequestArgs = serde_json::from_value(command["args"].clone())?;
                if self.request_prover.is_none() {
                    self.request_prover = Some(RequestProver::load(&self.setup)?);
                }
                let prepared = zkapi_browser::prepare_request_with_prover(
                    self.config
                        .as_ref()
                        .context("initialize the wallet first")?,
                    self.state.as_ref().context("confirm a deposit first")?,
                    args,
                    self.request_prover
                        .as_ref()
                        .context("missing request prover")?,
                )?;
                // The request's bound is recorded at its state (C2) together
                // with the journal.
                self.state = Some(prepared.state);
                self.journal = Some(prepared.journal);
                Ok(json!({"request": prepared.request}))
            }
            "complete_response" => {
                let next = zkapi_browser::complete_response(
                    self.config
                        .as_ref()
                        .context("initialize the wallet first")?,
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
            "snapshot" => {
                ensure!(
                    self.journal.is_none(),
                    "settle the pending request before snapshotting"
                );
                let name = command["name"]
                    .as_str()
                    .context("snapshot name is required")?;
                ensure!(!name.is_empty(), "snapshot name must not be empty");
                ensure!(
                    !self.snapshots.contains_key(name),
                    "snapshot already exists"
                );
                let state = self.state.as_ref().context("confirm a deposit first")?;
                // Genesis or a verified server-signed state: both are genuine.
                ensure!(
                    state.is_genesis || state.state_signature.is_some(),
                    "a stale-state snapshot requires a genuine state"
                );
                self.snapshots.insert(name.to_string(), state.clone());
                Ok(
                    json!({"name": name, "withdrawal_nullifier": zkapi_browser::withdrawal_nullifier(state)}),
                )
            }
            "prepare_withdrawal" => {
                let args: PrepareWithdrawalArgs = serde_json::from_value(command["args"].clone())?;
                let state = match command.get("snapshot") {
                    Some(value) => {
                        ensure!(
                            args.mode == "escape",
                            "snapshots are only for the stale escape scenario"
                        );
                        let name = value.as_str().context("snapshot must be a name")?;
                        let snapshot = self.snapshots.get(name).context("unknown snapshot")?;
                        let current = self.state.as_ref().context("confirm a deposit first")?;
                        ensure!(
                            current.current_anchor != snapshot.current_anchor,
                            "snapshot must have been consumed by a later verified settlement"
                        );
                        snapshot
                    }
                    None => {
                        // An escape may leave with the request it made at this
                        // state still unanswered (a withheld successor).
                        ensure!(
                            self.journal.is_none() || args.mode == "escape",
                            "settle the pending request before a mutual close"
                        );
                        self.state.as_ref().context("confirm a deposit first")?
                    }
                };
                if self.withdrawal_key.is_none() {
                    self.withdrawal_key = Some(std::fs::read(self.setup.join("withdrawal.pk"))?);
                }
                let plan = zkapi_browser::prepare_withdrawal(
                    self.config
                        .as_ref()
                        .context("initialize the wallet first")?,
                    state,
                    args,
                    self.withdrawal_key
                        .as_deref()
                        .context("missing withdrawal key")?,
                )?;
                let inputs_abi = withdrawal_tuple_abi(&plan.public_inputs);
                let proof_hex = format!(
                    "0x{}",
                    hex::encode(
                        base64::engine::general_purpose::STANDARD.decode(&plan.proof.proof)?
                    )
                );
                let mut result = serde_json::to_value(plan)?;
                result["inputs_abi"] = json!(inputs_abi);
                result["proof_hex"] = json!(proof_hex);
                Ok(result)
            }
            "tree_path" => {
                let args: PathArgs = serde_json::from_value(command["args"].clone())?;
                Ok(serde_json::to_value(zkapi_browser::tree_path(
                    args.snapshot,
                    args.note_id,
                    args.require_existing,
                )?)?)
            }
            "status" => Ok(self.status()),
            _ => bail!("unsupported command"),
        }
    }
}

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let setup = PathBuf::from(
        args.next()
            .context("usage: v2_acceptance_wallet SETUP_DIRECTORY")?,
    );
    ensure!(
        args.next().is_none(),
        "usage: v2_acceptance_wallet SETUP_DIRECTORY"
    );
    let mut driver = WalletDriver::new(setup);
    let stdin = io::stdin();
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {
        let line = line?;
        let parsed = serde_json::from_str::<Value>(&line);
        let (id, result) = match parsed {
            Ok(command) => (
                command.get("id").cloned().unwrap_or(Value::Null),
                driver.handle(&command),
            ),
            Err(error) => (Value::Null, Err(error.into())),
        };
        let reply = match result {
            Ok(result) => json!({"id": id, "ok": true, "result": result}),
            Err(error) => json!({"id": id, "ok": false, "error": format!("{error:#}")}),
        };
        serde_json::to_writer(&mut stdout, &reply)?;
        writeln!(stdout)?;
        stdout.flush()?;
    }
    Ok(())
}
