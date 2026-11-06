//! Durable event-to-submission loop for EVM concession-exit challenges.
//!
//! The service scans `EscapeWithdrawalInitiated` events, reads each pending
//! escape `(N, N⁺, stateBalance, conceded, deadline)` from the vault, and
//! applies the [`ChallengeWatcher`] policy: `challengeEscapeWithdrawal`
//! (defeat) with request evidence at `N⁺`, or `raiseEscapeConcession` with
//! evidence at `N`. Every call is root-independent.
//!
//! One signer, one nonce lane. A same-nonce replacement happens only when a
//! defeat replaces an unmined raise; a raise never replaces a defeat.
//!
//! The configured RPC must expose an operator-controlled transaction signer.
//! Keys are never loaded by this service; the sender must be dedicated to it.

use crate::nullifier_store::NullifierStore;
use crate::watcher::{
    ActionKind, ChallengeAction, ChallengeWatcher, Decision, EvidenceVerifier, PendingEscape,
};
use anyhow::{bail, ensure, Context};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use std::{collections::BTreeMap, path::PathBuf, sync::Arc, time::Duration};
use zkapi_proof::compact::RequestVerifier;
use zkapi_types::Felt252;

const ESCAPE_EVENT: &str =
    "EscapeWithdrawalInitiated(uint32,uint256,uint256,uint128,uint128,address,uint64)";
/// `pendingWithdrawals(uint32)` returns `(exists, withdrawalNullifier,
/// nextNullifier, stateBalance, conceded, finalBalance, destination,
/// challengeDeadline)`.
const PENDING_WORDS: usize = 8;

#[derive(Clone, Debug)]
pub struct ChallengeServiceConfig {
    pub rpc_url: String,
    pub sender: String,
    pub contract_address: Felt252,
    pub chain_id: u64,
    pub from_block: u64,
    pub confirmations: u64,
    pub checkpoint: PathBuf,
    pub proof_setup_dir: PathBuf,
    /// Raise with the request's bound this long before the deadline when its
    /// charge is still unsettled.
    pub raise_lead_seconds: u64,
    /// The signer's `ZKAPI_CHALLENGE_MAX_GAS_PRICE_WEI`: fee bumps never exceed
    /// it, so a refused bump cannot escalate without bound.
    pub max_gas_price_wei: u128,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PendingChallenge {
    nullifier: Felt252,
    next_nullifier: Felt252,
    transaction_hash: Option<String>,
    /// Persist before sending so an ambiguous RPC failure retries the same nonce.
    nonce: Option<u64>,
    /// The call the reserved nonce carries.
    action: Option<ActionKind>,
    #[serde(default)]
    deadline_reported: bool,
    /// Highest gas price attempted at `nonce`, persisted before each send: a
    /// hashless reservation may still hold an accepted mempool transaction.
    #[serde(default)]
    gas_price: Option<u128>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Checkpoint {
    sender: String,
    chain_id: u64,
    contract_address: Felt252,
    from_block: u64,
    next_block: u64,
    last_block_hash: Option<String>,
    pending: BTreeMap<u32, PendingChallenge>,
    /// Nonces no note owns any more. One with a known transaction is in
    /// flight and waited for; one without (never broadcast, or dropped) is a
    /// spare that the next send reuses before allocating a fresh nonce.
    #[serde(default)]
    detached_nonces: BTreeMap<u64, DetachedNonce>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DetachedNonce {
    note_id: u32,
    nullifier: Felt252,
    transaction_hash: Option<String>,
    /// The call the nonce carries, restored with it on event replay.
    #[serde(default)]
    action: Option<ActionKind>,
    /// Highest gas price attempted at this nonce (see `PendingChallenge`).
    #[serde(default)]
    gas_price: Option<u128>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NonceState {
    Free,
    Reserved,
    Pending,
    Mined,
}

pub struct ChallengeService {
    config: ChallengeServiceConfig,
    client: reqwest::Client,
    watcher: ChallengeWatcher,
    checkpoint: Checkpoint,
}

impl ChallengeService {
    pub fn new(config: ChallengeServiceConfig, store: Arc<NullifierStore>) -> anyhow::Result<Self> {
        let verifier = RequestVerifier::load(&config.proof_setup_dir)?;
        Self::with_verifier(config, store, Box::new(verifier))
    }

    pub(crate) fn with_verifier(
        config: ChallengeServiceConfig,
        store: Arc<NullifierStore>,
        verifier: Box<dyn EvidenceVerifier>,
    ) -> anyhow::Result<Self> {
        ensure!(
            config.contract_address.as_bytes()[..12]
                .iter()
                .all(|byte| *byte == 0),
            "vault address exceeds 20 bytes"
        );
        ensure!(config.raise_lead_seconds > 0, "raise lead must be positive");
        ensure!(config.max_gas_price_wei > 0, "gas price cap must be positive");
        let sender = config
            .sender
            .strip_prefix("0x")
            .context("sender must be a 0x-prefixed address")?;
        ensure!(
            hex::decode(sender)?.len() == 20,
            "sender must be a 20-byte address"
        );
        let checkpoint: Checkpoint = if config.checkpoint.exists() {
            serde_json::from_slice(&std::fs::read(&config.checkpoint)?)?
        } else {
            Checkpoint {
                sender: config.sender.to_ascii_lowercase(),
                chain_id: config.chain_id,
                contract_address: config.contract_address,
                from_block: config.from_block,
                next_block: config.from_block,
                last_block_hash: None,
                pending: BTreeMap::new(),
                detached_nonces: BTreeMap::new(),
            }
        };
        ensure!(
            checkpoint.sender == config.sender.to_ascii_lowercase()
                && checkpoint.chain_id == config.chain_id
                && checkpoint.contract_address == config.contract_address
                && checkpoint.from_block == config.from_block,
            "challenge checkpoint belongs to another deployment"
        );
        Ok(Self {
            watcher: ChallengeWatcher::new(
                store,
                verifier,
                config.raise_lead_seconds,
                config.chain_id,
                config.contract_address,
            ),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()?,
            config,
            checkpoint,
        })
    }

    /// Scan a bounded event range, persist it, then reconcile and submit work.
    /// Errors leave the durable queue intact for the next poll or restart.
    pub async fn poll_once(&mut self) -> anyhow::Result<()> {
        let chain = self.rpc("eth_chainId", json!([])).await?;
        ensure!(
            quantity(&chain)? == self.config.chain_id,
            "RPC chain ID does not match challenge deployment"
        );
        let latest = quantity(&self.rpc("eth_blockNumber", json!([])).await?)?;
        if let Some(expected) = &self.checkpoint.last_block_hash {
            let block = self
                .rpc(
                    "eth_getBlockByNumber",
                    json!([format!("0x{:x}", self.checkpoint.next_block - 1), false]),
                )
                .await?;
            if block.get("hash").and_then(Value::as_str) != Some(expected.as_str()) {
                tracing::warn!("challenge cursor was reorganized; replaying deployment events");
                self.checkpoint.next_block = self.config.from_block;
                self.checkpoint.last_block_hash = None;
                self.persist()?;
            }
        }
        if let Some(safe_head) = latest.checked_sub(self.config.confirmations) {
            if self.checkpoint.next_block <= safe_head {
                let to = safe_head.min(self.checkpoint.next_block.saturating_add(999));
                let before = self
                    .rpc("eth_getBlockByNumber", json!([format!("0x{to:x}"), false]))
                    .await?;
                let before_hash = before["hash"].as_str().context("scan block lacks hash")?;
                let logs = self.rpc("eth_getLogs", json!([{
                    "address": self.vault_address(), "fromBlock": format!("0x{:x}", self.checkpoint.next_block),
                    "toBlock": format!("0x{to:x}"), "topics": [format!("0x{}", hex::encode(Keccak256::digest(ESCAPE_EVENT.as_bytes())))]
                }])).await?;
                let after = self
                    .rpc("eth_getBlockByNumber", json!([format!("0x{to:x}"), false]))
                    .await?;
                let after_hash = after["hash"].as_str().context("scan block lacks hash")?;
                ensure!(
                    before_hash == after_hash,
                    "chain reorganized while reading escape events; retrying range"
                );
                for log in logs.as_array().context("RPC logs must be an array")? {
                    if log.get("removed").and_then(Value::as_bool) == Some(true) {
                        continue;
                    }
                    let topics = log["topics"]
                        .as_array()
                        .context("escape event lacks topics")?;
                    ensure!(topics.len() == 2, "malformed escape event topics");
                    let note = quantity(&topics[1])?;
                    ensure!(note <= u32::MAX as u64, "escape note ID exceeds uint32");
                    let words = words(&log["data"])?;
                    ensure!(words.len() == 6, "malformed escape event data");
                    let (nullifier, next_nullifier) = (words[0], words[1]);
                    let old = self.checkpoint.pending.get(&(note as u32));
                    if old.is_none_or(|old| old.nullifier != nullifier) {
                        self.detach_nonce(note as u32);
                        let mut pending = PendingChallenge {
                            nullifier,
                            next_nullifier,
                            transaction_hash: None,
                            nonce: None,
                            action: None,
                            deadline_reported: false,
                            gas_price: None,
                        };
                        // Replaying historical events may temporarily replace
                        // this note and then restore its current nullifier.
                        // Recover its exact reservation instead of stranding it.
                        let restored_nonce = self
                            .checkpoint
                            .detached_nonces
                            .iter()
                            .find(|(_, entry)| {
                                entry.note_id == note as u32 && entry.nullifier == nullifier
                            })
                            .map(|(nonce, _)| *nonce);
                        if let Some(nonce) = restored_nonce {
                            let entry = self.checkpoint.detached_nonces.remove(&nonce).unwrap();
                            pending.nonce = Some(nonce);
                            pending.transaction_hash = entry.transaction_hash;
                            pending.action = entry.action;
                            pending.gas_price = entry.gas_price;
                        }
                        self.checkpoint.pending.insert(note as u32, pending);
                    }
                }
                self.checkpoint.last_block_hash = Some(after_hash.to_owned());
                self.checkpoint.next_block = to.saturating_add(1);
                self.persist()?;
            }
        }
        self.reconcile_detached_nonces().await?;
        let mut notes: Vec<_> = self.checkpoint.pending.keys().copied().collect();
        // Durable ambiguous sends from *previous* polls must run before newly
        // eligible notes, irrespective of note ID or event arrival order.
        notes.sort_by_key(|note| {
            let pending = &self.checkpoint.pending[note];
            (
                pending.nonce.is_none() || pending.transaction_hash.is_some(),
                pending.nonce,
                *note,
            )
        });
        let mut first_error = None;
        for note in notes {
            // Nonce ownership is independent of the withdrawal's deadline,
            // evidence and current state. In particular, an ambiguous send
            // which has mined must not prevent other notes from progressing.
            let nonce_state = match self.reconcile_nonce(note).await {
                Ok(state) => state,
                Err(error) => {
                    first_error.get_or_insert(error);
                    break; // No safe new allocation when nonce status is unknown.
                }
            };
            if let Err(error) = self.reconcile(note, nonce_state).await {
                tracing::error!(note_id = note, error = %error, "escape challenge requires retry");
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
            // Never allocate above this note's unsent reservation while it may
            // still be broadcast. A reservation it no longer needs is released
            // as a spare, and any held nonce above a spare moves down to it, so
            // the lane never waits on a gap.
            if nonce_state != NonceState::Mined
                && self.checkpoint.pending.get(&note).is_some_and(|pending| {
                    pending.nonce.is_some() && pending.transaction_hash.is_none()
                })
            {
                break;
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    async fn reconcile(&mut self, note: u32, nonce_state: NonceState) -> anyhow::Result<()> {
        let pending = self.checkpoint.pending[&note].clone();
        let mut query = selector("pendingWithdrawals(uint32)");
        query.extend_from_slice(Felt252::from_u64(note as u64).as_bytes());
        let state = self.call(query.clone()).await?;
        ensure!(
            state.len() == PENDING_WORDS,
            "malformed pending withdrawal response"
        );
        if state[0] == Felt252::ZERO || state[1] != pending.nullifier {
            // Do not discard an obligation due to an unconfirmed defeat or
            // finalization that a tip reorg could remove without changing the
            // event-scan checkpoint block.
            let latest = quantity(&self.rpc("eth_blockNumber", json!([])).await?)?;
            let Some(confirmed) = latest.checked_sub(self.config.confirmations) else {
                return Ok(());
            };
            let confirmed_state = self.call_at(query, &format!("0x{confirmed:x}")).await?;
            ensure!(
                confirmed_state.len() == PENDING_WORDS,
                "malformed confirmed withdrawal response"
            );
            if confirmed_state[0] != Felt252::ZERO && confirmed_state[1] == pending.nullifier {
                return Ok(());
            }
            self.detach_nonce(note);
            self.checkpoint.pending.remove(&note);
            self.persist()?;
            return Ok(());
        }
        let escape = PendingEscape {
            note_id: note,
            nullifier: state[1],
            next_nullifier: state[2],
            state_balance: felt_u128(&state[3])?,
            conceded: felt_u128(&state[4])?,
            deadline: felt_u64(&state[7])?,
        };
        let head = self
            .rpc("eth_getBlockByNumber", json!(["latest", false]))
            .await?;
        let now = quantity(&head["timestamp"])?;
        let action = match self.watcher.decide(&escape, now)? {
            Decision::Act(action) => action,
            Decision::Wait | Decision::Nothing => return self.release_unsent_nonce(note, nonce_state),
        };
        if now >= escape.deadline {
            if !pending.deadline_reported {
                tracing::error!(note_id = note, nullifier = %pending.nullifier, kind = ?action.kind, "MISSED escape challenge deadline");
                self.checkpoint
                    .pending
                    .get_mut(&note)
                    .unwrap()
                    .deadline_reported = true;
                self.persist()?;
            }
            // Keep the obligation until confirmed vault completion, including
            // the possibility of a reorg back before the deadline, but hand an
            // unsent reservation to the next challenge.
            return self.release_unsent_nonce(note, nonce_state);
        }
        match (nonce_state, pending.action) {
            // Wait for confirmation, then decide again from the vault state.
            (NonceState::Mined, _) => Ok(()),
            // The one replacement: a defeat replaces an unmined raise.
            (NonceState::Pending, Some(ActionKind::Raise { .. })) if action.kind.is_defeat() => {
                tracing::warn!(
                    note_id = note,
                    "successor evidence appeared while a raise is pending; the defeat replaces it on the same nonce"
                );
                self.send(note, &action, true).await
            }
            (NonceState::Pending, _) => Ok(()),
            (_, Some(ActionKind::Defeat)) if !action.kind.is_defeat() => {
                bail!("a raise never replaces a defeat on its reserved nonce")
            }
            (NonceState::Free | NonceState::Reserved, _) => self.send(note, &action, false).await,
        }
    }

    /// A reservation without a known transaction (never broadcast, dropped, or
    /// ambiguously sent) that this note no longer needs becomes a spare: the
    /// next send reuses it, bumping the fee above any attempt recorded for it,
    /// so the lane never has a gap and no other challenge is held behind it.
    fn release_unsent_nonce(&mut self, note: u32, nonce_state: NonceState) -> anyhow::Result<()> {
        if nonce_state != NonceState::Reserved {
            return Ok(());
        }
        self.detach_nonce(note);
        let entry = self.checkpoint.pending.get_mut(&note).unwrap();
        entry.nonce = None;
        entry.transaction_hash = None;
        entry.action = None;
        entry.gas_price = None;
        self.persist()
    }

    /// Simulate, reserve (or reuse) a nonce, persist the call and its gas
    /// price, then send it. `replace` replaces this note's pending transaction.
    async fn send(
        &mut self,
        note: u32,
        action: &ChallengeAction,
        replace: bool,
    ) -> anyhow::Result<()> {
        let (mut transaction, nonce, spare, gas_price) =
            match self.prepare_send(note, action, replace).await {
                Ok(prepared) => prepared,
                Err(error) => {
                    // No new broadcast happened: an unsent reservation must not
                    // hold every other challenge behind it.
                    let held = &self.checkpoint.pending[&note];
                    if !replace && held.nonce.is_some() && held.transaction_hash.is_none() {
                        self.release_unsent_nonce(note, NonceState::Reserved)?;
                    }
                    return Err(error);
                }
            };
        {
            if let Some(nonce) = spare {
                self.checkpoint.detached_nonces.remove(&nonce);
            }
            let entry = self.checkpoint.pending.get_mut(&note).unwrap();
            entry.nonce = Some(nonce);
            entry.gas_price = Some(gas_price);
            // Until the signer accepts a replacement, the known in-flight call
            // is still the raise, so a rejected replacement is retried.
            if !replace {
                entry.action = Some(action.kind);
            }
        }
        self.persist()?;
        transaction["nonce"] = json!(format!("0x{nonce:x}"));
        let hash = self
            .rpc("eth_sendTransaction", json!([transaction]))
            .await?;
        let hash = hash
            .as_str()
            .context("transaction response lacks hash")?
            .to_owned();
        {
            let entry = self.checkpoint.pending.get_mut(&note).unwrap();
            entry.transaction_hash = Some(hash.clone());
            entry.action = Some(action.kind);
        }
        self.persist()?;
        tracing::info!(note_id = note, kind = ?action.kind, transaction_hash = %hash, "submitted escape challenge");
        Ok(())
    }

    /// Everything before the broadcast: simulation, gas, the nonce (held,
    /// lowest spare, or fresh) and its gas price. A nonce that the node's
    /// pending count shows occupied, or that already had an attempt, may hold
    /// an accepted transaction, so its price is bumped to at least 1.25x the
    /// highest recorded attempt (or known transaction) plus 1, capped at the
    /// signer's limit. Returns the transaction, nonce, consumed spare and the
    /// highest price that may now be in flight at the nonce.
    async fn prepare_send(
        &self,
        note: u32,
        action: &ChallengeAction,
        replace: bool,
    ) -> anyhow::Result<(Value, u64, Option<u64>, u128)> {
        let data = format!(
            "0x{}",
            hex::encode(action.calldata().map_err(anyhow::Error::msg)?)
        );
        let mut transaction =
            json!({ "from": self.config.sender, "to": self.vault_address(), "data": data });
        // Simulate against the live contract to check keys, proof and deadline
        // together before reserving a nonce.
        self.rpc("eth_call", json!([transaction, "latest"])).await?;
        let estimated_gas = quantity(&self.rpc("eth_estimateGas", json!([transaction])).await?)?;
        let gas = estimated_gas
            .checked_add(estimated_gas / 5)
            .context("challenge gas estimate overflow")?;
        transaction["gas"] = json!(format!("0x{gas:x}"));
        let pending_count = quantity(
            &self
                .rpc(
                    "eth_getTransactionCount",
                    json!([self.config.sender, "pending"]),
                )
                .await?,
        )?;
        let held = &self.checkpoint.pending[&note];
        let (nonce, mut previous, spare) = if let Some(nonce) = held.nonce {
            (nonce, held.gas_price, None)
        } else if let Some((nonce, previous)) = self.spare_nonce().await? {
            (nonce, previous, Some(nonce))
        } else {
            ensure!(
                !self
                    .checkpoint
                    .pending
                    .values()
                    .any(|entry| entry.nonce == Some(pending_count))
                    && !self.checkpoint.detached_nonces.contains_key(&pending_count),
                "RPC pending nonce conflicts with a durable challenge reservation"
            );
            (pending_count, None, None)
        };
        if replace {
            let hash = held
                .transaction_hash
                .clone()
                .context("a replacement needs the pending transaction")?;
            let pending_transaction = self.rpc("eth_getTransactionByHash", json!([hash])).await?;
            let fee = ["maxFeePerGas", "gasPrice"]
                .iter()
                .find_map(|field| {
                    pending_transaction
                        .get(*field)
                        .filter(|value| !value.is_null())
                })
                .map(quantity_u128)
                .transpose()?;
            previous = previous.max(fee);
        }
        let current = quantity_u128(&self.rpc("eth_gasPrice", json!([])).await?)?;
        let occupied = replace || pending_count > nonce || previous.is_some();
        let gas_price = if occupied {
            let previous = previous.unwrap_or(current);
            previous
                .saturating_add(previous / 4)
                .saturating_add(1)
                .max(current)
        } else {
            current
        }
        .min(self.config.max_gas_price_wei);
        transaction["gasPrice"] = json!(format!("0x{gas_price:x}"));
        Ok((
            transaction,
            nonce,
            spare,
            gas_price.max(previous.unwrap_or(0)),
        ))
    }

    /// Retain ownership even if the note's withdrawal is completed or replaced.
    /// The caller persists the queue change and this reservation atomically.
    fn detach_nonce(&mut self, note: u32) {
        if let Some(pending) = self.checkpoint.pending.get(&note) {
            if let Some(nonce) = pending.nonce {
                self.checkpoint.detached_nonces.insert(
                    nonce,
                    DetachedNonce {
                        note_id: note,
                        nullifier: pending.nullifier,
                        transaction_hash: pending.transaction_hash.clone(),
                        action: pending.action,
                        gas_price: pending.gas_price,
                    },
                );
            }
        }
    }

    async fn nonce_counts(&self) -> anyhow::Result<(u64, u64)> {
        let head = quantity(&self.rpc("eth_blockNumber", json!([])).await?)?;
        let latest = quantity(
            &self
                .rpc(
                    "eth_getTransactionCount",
                    json!([self.config.sender, "latest"]),
                )
                .await?,
        )?;
        let confirmed = if let Some(block) = head.checked_sub(self.config.confirmations) {
            quantity(
                &self
                    .rpc(
                        "eth_getTransactionCount",
                        json!([self.config.sender, format!("0x{block:x}")]),
                    )
                    .await?,
            )?
        } else {
            0
        };
        // A reorg or newly mined block may race the two reads. Never retire a
        // reservation whose consumption the latest nonce read did not observe.
        Ok((latest, confirmed.min(latest)))
    }

    async fn reconcile_nonce(&mut self, note: u32) -> anyhow::Result<NonceState> {
        let pending = self.checkpoint.pending[&note].clone();
        let Some(nonce) = pending.nonce else {
            return Ok(NonceState::Free);
        };
        let (latest, confirmed) = self.nonce_counts().await?;
        if confirmed > nonce {
            // The call is final (applied or reverted); the next decision reads
            // its effect from the vault.
            let entry = self.checkpoint.pending.get_mut(&note).unwrap();
            entry.nonce = None;
            entry.transaction_hash = None;
            entry.action = None;
            entry.gas_price = None;
            self.persist()?;
            return Ok(NonceState::Free);
        }
        if latest > nonce {
            // Let other notes advance, but retain this ownership until enough
            // confirmations have passed to protect against a tip reorg.
            return Ok(NonceState::Mined);
        }
        // A spare below this nonce would leave it unmineable: move this note's
        // call down to the lowest one. Its transaction at `nonce` stays
        // tracked as detached (it reverts harmlessly if it ever mines) or
        // becomes a spare itself once dropped.
        let spare = self
            .checkpoint
            .detached_nonces
            .iter()
            .find(|(spare, entry)| {
                **spare >= latest && **spare < nonce && entry.transaction_hash.is_none()
            })
            .map(|(spare, _)| *spare);
        if let Some(spare) = spare {
            tracing::warn!(note_id = note, nonce, spare, "moving challenge down to fill a nonce gap");
            self.detach_nonce(note);
            let entry = self.checkpoint.pending.get_mut(&note).unwrap();
            entry.nonce = None;
            entry.transaction_hash = None;
            entry.action = None;
            entry.gas_price = None;
            self.persist()?;
            return Ok(NonceState::Free);
        }
        if let Some(hash) = &pending.transaction_hash {
            if !self
                .rpc("eth_getTransactionByHash", json!([hash]))
                .await?
                .is_null()
            {
                return Ok(NonceState::Pending);
            }
            self.checkpoint
                .pending
                .get_mut(&note)
                .unwrap()
                .transaction_hash = None;
            self.persist()?;
        }
        Ok(NonceState::Reserved)
    }

    /// Lowest released nonce with no known transaction that the chain has not
    /// consumed, with the highest gas price attempted at it. It must be filled
    /// before any fresh nonce is allocated.
    async fn spare_nonce(&self) -> anyhow::Result<Option<(u64, Option<u128>)>> {
        let spares: Vec<(u64, Option<u128>)> = self
            .checkpoint
            .detached_nonces
            .iter()
            .filter(|(_, entry)| entry.transaction_hash.is_none())
            .map(|(nonce, entry)| (*nonce, entry.gas_price))
            .collect();
        if spares.is_empty() {
            return Ok(None);
        }
        let latest = quantity(
            &self
                .rpc(
                    "eth_getTransactionCount",
                    json!([self.config.sender, "latest"]),
                )
                .await?,
        )?;
        Ok(spares.into_iter().find(|(nonce, _)| *nonce >= latest))
    }

    async fn reconcile_detached_nonces(&mut self) -> anyhow::Result<()> {
        if self.checkpoint.detached_nonces.is_empty() {
            return Ok(());
        }
        let (latest, confirmed) = self.nonce_counts().await?;
        self.checkpoint
            .detached_nonces
            .retain(|nonce, _| *nonce >= confirmed);
        // A detached transaction the node no longer knows was dropped: its
        // nonce becomes a spare for the next challenge. One still in flight is
        // only tracked: fresh nonces may queue above it, and if it is dropped
        // later every held nonce above it moves down to fill it.
        let in_flight: Vec<(u64, String)> = self
            .checkpoint
            .detached_nonces
            .iter()
            .filter(|(nonce, _)| **nonce >= latest)
            .filter_map(|(nonce, entry)| Some((*nonce, entry.transaction_hash.clone()?)))
            .collect();
        for (nonce, hash) in in_flight {
            if self
                .rpc("eth_getTransactionByHash", json!([hash]))
                .await?
                .is_null()
            {
                self.checkpoint
                    .detached_nonces
                    .get_mut(&nonce)
                    .unwrap()
                    .transaction_hash = None;
            }
        }
        self.persist()?;
        Ok(())
    }

    fn vault_address(&self) -> String {
        format!(
            "0x{}",
            hex::encode(&self.config.contract_address.as_bytes()[12..])
        )
    }

    async fn call(&self, data: Vec<u8>) -> anyhow::Result<Vec<Felt252>> {
        self.call_at(data, "latest").await
    }

    async fn call_at(&self, data: Vec<u8>, block: &str) -> anyhow::Result<Vec<Felt252>> {
        words(&self.rpc("eth_call", json!([{ "to": self.vault_address(), "data": format!("0x{}", hex::encode(data)) }, block])).await?)
    }

    async fn rpc(&self, method: &str, params: Value) -> anyhow::Result<Value> {
        let response: Value = self
            .client
            .post(&self.config.rpc_url)
            .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        if let Some(error) = response.get("error") {
            bail!("{method}: {error}");
        }
        response
            .get("result")
            .cloned()
            .with_context(|| format!("{method}: missing RPC result"))
    }

    fn persist(&self) -> anyhow::Result<()> {
        crate::checkpoint::persist_json(&self.config.checkpoint, &self.checkpoint)
    }
}

fn selector(signature: &str) -> Vec<u8> {
    Keccak256::digest(signature.as_bytes())[..4].to_vec()
}
fn quantity(value: &Value) -> anyhow::Result<u64> {
    u64::try_from(quantity_u128(value)?).context("quantity exceeds uint64")
}
fn quantity_u128(value: &Value) -> anyhow::Result<u128> {
    let value = value
        .as_str()
        .context("expected hex quantity")?
        .strip_prefix("0x")
        .context("hex quantity lacks prefix")?;
    let digits = value.trim_start_matches('0');
    if digits.is_empty() {
        ensure!(!value.is_empty(), "empty hex quantity");
        return Ok(0);
    }
    u128::from_str_radix(digits, 16).context("quantity exceeds uint128")
}
fn felt_u64(value: &Felt252) -> anyhow::Result<u64> {
    ensure!(
        value.as_bytes()[..24].iter().all(|byte| *byte == 0),
        "value exceeds uint64"
    );
    Ok(u64::from_be_bytes(
        value.as_bytes()[24..].try_into().unwrap(),
    ))
}
fn felt_u128(value: &Felt252) -> anyhow::Result<u128> {
    ensure!(
        value.as_bytes()[..16].iter().all(|byte| *byte == 0),
        "value exceeds uint128"
    );
    Ok(u128::from_be_bytes(
        value.as_bytes()[16..].try_into().unwrap(),
    ))
}
fn words(value: &Value) -> anyhow::Result<Vec<Felt252>> {
    let raw = value
        .as_str()
        .context("expected ABI bytes")?
        .strip_prefix("0x")
        .context("ABI bytes lack prefix")?;
    let bytes = hex::decode(raw)?;
    ensure!(bytes.len().is_multiple_of(32), "malformed ABI words");
    Ok(bytes
        .as_chunks::<32>()
        .0
        .iter()
        .map(|chunk| Felt252(*chunk))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::watcher::tests::{served, StubVerifier, BINDING};
    use axum::{extract::State, routing::post, Json, Router};
    use std::sync::Mutex;

    const N: u64 = 10;
    const N_NEXT: u64 = 11;

    #[derive(Clone, Copy)]
    struct Withdrawal {
        active: bool,
        nullifier: Felt252,
        next_nullifier: Felt252,
        conceded: u128,
        deadline: u64,
    }

    struct MockChain {
        nullifier: Felt252,
        next_nullifier: Felt252,
        conceded: u128,
        active: bool,
        confirmed_active: bool,
        mined_nonce: u64,
        pending_nonce: Option<u64>,
        confirmed_nonce: Option<u64>,
        transaction_known: bool,
        withdrawals: BTreeMap<u32, Withdrawal>,
        event_note: u32,
        fail_note_one: bool,
        reorg_during_scan: bool,
        block_hash: String,
        sends: Vec<Value>,
        fail_first_send: bool,
        /// Hashes the node no longer knows, beyond `transaction_known`.
        dropped: Vec<String>,
        revert_note: Option<u32>,
        /// Gas estimation for this note's challenge call fails.
        estimate_fail_note: Option<u32>,
    }
    impl MockChain {
        fn new() -> Self {
            Self {
                nullifier: Felt252::from_u64(N),
                next_nullifier: Felt252::from_u64(N_NEXT),
                conceded: 0,
                active: true,
                confirmed_active: true,
                mined_nonce: 3,
                pending_nonce: None,
                confirmed_nonce: None,
                transaction_known: true,
                withdrawals: BTreeMap::new(),
                event_note: 0,
                fail_note_one: false,
                reorg_during_scan: false,
                block_hash: "0xforkA".into(),
                sends: vec![],
                fail_first_send: false,
                dropped: vec![],
                revert_note: None,
                estimate_fail_note: None,
            }
        }
    }
    fn encoded(values: &[Felt252]) -> Value {
        json!(format!(
            "0x{}",
            hex::encode(
                values
                    .iter()
                    .flat_map(|v| v.as_bytes().iter().copied())
                    .collect::<Vec<_>>()
            )
        ))
    }
    fn pending_words(withdrawal: Withdrawal) -> Value {
        encoded(&[
            Felt252::from_u64(withdrawal.active as u64),
            withdrawal.nullifier,
            withdrawal.next_nullifier,
            Felt252::from_u128(1_000),
            Felt252::from_u128(withdrawal.conceded),
            Felt252::from_u128(1_000 - withdrawal.conceded),
            Felt252::from_u64(5),
            Felt252::from_u64(withdrawal.deadline),
        ])
    }
    async fn rpc(
        State(state): State<Arc<Mutex<MockChain>>>,
        Json(request): Json<Value>,
    ) -> Json<Value> {
        let mut state = state.lock().unwrap();
        let method = request["method"].as_str().unwrap();
        let result = match method {
            "eth_chainId" => json!("0x1"),
            "eth_blockNumber" => json!("0x5"),
            "eth_gasPrice" => json!("0x10"),
            "eth_getBlockByNumber" => json!({ "hash": state.block_hash, "timestamp": "0x64" }),
            "eth_getLogs" => {
                if state.reorg_during_scan {
                    state.block_hash = "0xforkB".into();
                    state.reorg_during_scan = false;
                }
                json!([{
                    "topics": [format!("0x{}", hex::encode(Keccak256::digest(ESCAPE_EVENT.as_bytes()))), format!("0x{:064x}", state.event_note)],
                    "data": encoded(&[state.nullifier, state.next_nullifier, Felt252::from_u64(1_000), Felt252::ZERO, Felt252::from_u64(5), Felt252::from_u64(200)])
                }])
            }
            "eth_call" => {
                let data = request["params"][0]["data"].as_str().unwrap();
                let pending_selector =
                    format!("0x{}", hex::encode(selector("pendingWithdrawals(uint32)")));
                if state.fail_note_one
                    && data == format!("{pending_selector}{}", hex::encode(Felt252::ONE.as_bytes()))
                {
                    return Json(
                        json!({ "jsonrpc": "2.0", "id": 1, "error": { "code": -32000, "message": "temporary note-state failure" } }),
                    );
                }
                // Simulated challenge calls (`from` is set) for this note revert.
                if !request["params"][0]["from"].is_null()
                    && state.revert_note.is_some_and(|note| {
                        data.get(10..74)
                            == Some(hex::encode(Felt252::from_u64(note as u64).as_bytes()).as_str())
                    })
                {
                    return Json(
                        json!({ "jsonrpc": "2.0", "id": 1, "error": { "code": 3, "message": "execution reverted" } }),
                    );
                }
                if data.starts_with(&pending_selector) {
                    let note = u32::from_str_radix(&data[data.len() - 8..], 16).unwrap();
                    if let Some(withdrawal) = state.withdrawals.get(&note) {
                        return Json(
                            json!({"jsonrpc": "2.0", "id": 1, "result": pending_words(*withdrawal)}),
                        );
                    }
                    pending_words(Withdrawal {
                        active: if request["params"][1] == "latest" {
                            state.active
                        } else {
                            state.confirmed_active
                        },
                        nullifier: state.nullifier,
                        next_nullifier: state.next_nullifier,
                        conceded: state.conceded,
                        deadline: 200,
                    })
                } else if data == format!("0x{}", hex::encode(selector("currentRoot()"))) {
                    panic!("challenges must not depend on the current root");
                } else {
                    json!("0x")
                }
            }
            "eth_estimateGas" => {
                let data = request["params"][0]["data"].as_str().unwrap();
                if state.estimate_fail_note.is_some_and(|note| {
                    data.get(10..74)
                        == Some(hex::encode(Felt252::from_u64(note as u64).as_bytes()).as_str())
                }) {
                    return Json(
                        json!({ "jsonrpc": "2.0", "id": 1, "error": { "code": -32000, "message": "estimator unavailable" } }),
                    );
                }
                json!("0x989680")
            }
            "eth_getTransactionCount" => json!(format!(
                "0x{:x}",
                if request["params"][1] == "pending" {
                    state.pending_nonce.unwrap_or(state.mined_nonce)
                } else if request["params"][1] == "latest" {
                    state.mined_nonce
                } else {
                    state.confirmed_nonce.unwrap_or(state.mined_nonce)
                }
            )),
            "eth_sendTransaction" => {
                state.sends.push(request["params"][0].clone());
                if state.fail_first_send {
                    state.fail_first_send = false;
                    return Json(
                        json!({ "jsonrpc": "2.0", "id": 1, "error": { "code": -32000, "message": "temporary signer failure" } }),
                    );
                }
                json!("0xsubmitted")
            }
            "eth_getTransactionByHash" => {
                if state.transaction_known
                    && !state
                        .dropped
                        .iter()
                        .any(|hash| request["params"][0] == hash.as_str())
                {
                    json!({ "hash": "0xsubmitted", "blockNumber": Value::Null, "gasPrice": "0x20" })
                } else {
                    Value::Null
                }
            }
            _ => panic!("unexpected RPC method {method}"),
        };
        Json(json!({ "jsonrpc": "2.0", "id": 1, "result": result }))
    }

    struct Fixture {
        store: Arc<NullifierStore>,
        config: ChallengeServiceConfig,
        chain: Arc<Mutex<MockChain>>,
        server: tokio::task::JoinHandle<()>,
        _directory: tempfile::TempDir,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            self.server.abort();
        }
    }

    impl Fixture {
        /// `evidence_at` lists nullifiers the server holds request evidence
        /// for (all served with issued keys, bound 300).
        async fn new(mock: MockChain, evidence_at: &[u64]) -> Self {
            let store = Arc::new(NullifierStore::in_memory().unwrap());
            for nullifier in evidence_at {
                served(
                    &store,
                    &format!("r{nullifier}"),
                    Felt252::from_u64(*nullifier),
                    300,
                );
            }
            let chain = Arc::new(Mutex::new(mock));
            let app = Router::new()
                .route("/", post(rpc))
                .with_state(chain.clone());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let directory = tempfile::tempdir().unwrap();
            let config = ChallengeServiceConfig {
                rpc_url: url.clone(),
                sender: "0x0000000000000000000000000000000000000001".into(),
                contract_address: Felt252::from_u64(BINDING),
                chain_id: 1,
                from_block: 0,
                confirmations: 2,
                checkpoint: directory.path().join("checkpoint.json"),
                proof_setup_dir: PathBuf::new(),
                raise_lead_seconds: 60,
                max_gas_price_wei: 10_000_000_000,
            };
            Self {
                store,
                config,
                chain,
                server,
                _directory: directory,
            }
        }

        /// A stale escape: evidence at `N⁺` (and at `N`).
        async fn stale() -> Self {
            Self::new(MockChain::new(), &[N, N_NEXT]).await
        }

        fn service(&self) -> ChallengeService {
            ChallengeService::with_verifier(
                self.config.clone(),
                self.store.clone(),
                Box::new(StubVerifier),
            )
            .unwrap()
        }

        fn expected(&self, kind: ActionKind) -> String {
            let watcher = crate::watcher::tests::watcher(self.store.clone());
            let Decision::Act(mut action) = watcher
                .decide(
                    &PendingEscape {
                        note_id: 0,
                        nullifier: Felt252::from_u64(N),
                        next_nullifier: Felt252::from_u64(N_NEXT),
                        state_balance: 1_000,
                        conceded: 0,
                        deadline: 200,
                    },
                    100,
                )
                .unwrap()
            else {
                panic!("expected an action")
            };
            if !kind.is_defeat() {
                let evidence = self.store.request_evidence(&Felt252::from_u64(N)).unwrap();
                action.request_inputs = evidence.request_inputs;
                action.proof = evidence.proof;
            }
            action.kind = kind;
            format!("0x{}", hex::encode(action.calldata().unwrap()))
        }

        fn reserve(&self, service: &mut ChallengeService, note: u32, expired: bool) {
            let mut chain = self.chain.lock().unwrap();
            let withdrawal = Withdrawal {
                active: true,
                nullifier: chain.nullifier,
                next_nullifier: chain.next_nullifier,
                conceded: 0,
                deadline: if expired { 100 } else { 200 },
            };
            chain.withdrawals.insert(note, withdrawal);
            service.checkpoint.pending.insert(
                note,
                PendingChallenge {
                    nullifier: withdrawal.nullifier,
                    next_nullifier: withdrawal.next_nullifier,
                    transaction_hash: None,
                    nonce: Some(3),
                    action: Some(ActionKind::Defeat),
                    deadline_reported: false,
                    gas_price: None,
                },
            );
            service.persist().unwrap();
        }
    }

    /// Threat: stale-state escape. The successor was spent (evidence at
    /// `N⁺`), so the service submits a defeat with the exact evidence, retries
    /// the same nonce after a failed send across restart, and never sends
    /// twice for a pending transaction.
    #[tokio::test]
    async fn stale_escape_is_defeated_and_survives_restart_and_reorg() {
        let mut mock = MockChain::new();
        mock.reorg_during_scan = true;
        mock.fail_first_send = true;
        let fixture = Fixture::new(mock, &[N, N_NEXT]).await;
        let expected = fixture.expected(ActionKind::Defeat);
        let mut service = fixture.service();
        assert!(service
            .poll_once()
            .await
            .unwrap_err()
            .to_string()
            .contains("chain reorganized while reading escape events"));
        assert!(service.checkpoint.pending.is_empty());
        assert!(service
            .poll_once()
            .await
            .unwrap_err()
            .to_string()
            .contains("temporary signer failure"));
        assert_eq!(service.checkpoint.pending[&0].nonce, Some(3));
        assert_eq!(
            service.checkpoint.pending[&0].action,
            Some(ActionKind::Defeat)
        );
        drop(service);
        let mut restarted = fixture.service();
        restarted.poll_once().await.unwrap();
        {
            let chain = fixture.chain.lock().unwrap();
            assert_eq!(chain.sends.len(), 2);
            assert_eq!(chain.sends[0]["nonce"], chain.sends[1]["nonce"], "same nonce");
            assert_eq!(chain.sends[0]["data"], chain.sends[1]["data"], "same payload");
            // The failed first send may have been accepted: the retry bumps.
            assert_eq!(chain.sends[0]["gasPrice"], "0x10");
            assert_eq!(chain.sends[1]["gasPrice"], "0x15", "0x10 + 25% + 1");
            assert_eq!(chain.sends[1]["data"], expected);
        }
        restarted.poll_once().await.unwrap();
        assert_eq!(fixture.chain.lock().unwrap().sends.len(), 2);
        // A reverted defeat consumed its nonce while leaving the escape
        // pending: it is resubmitted on the next nonce.
        fixture.chain.lock().unwrap().mined_nonce += 1;
        fixture.chain.lock().unwrap().confirmed_nonce = Some(4);
        restarted.poll_once().await.unwrap();
        assert_eq!(fixture.chain.lock().unwrap().sends.len(), 3);
        assert_eq!(fixture.chain.lock().unwrap().sends[2]["nonce"], "0x4");
        // A latest-block defeat alone must not drop the obligation.
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.active = false;
            chain.mined_nonce = 5;
            chain.confirmed_nonce = Some(4);
        }
        restarted.poll_once().await.unwrap();
        assert!(!restarted.checkpoint.pending.is_empty());
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.confirmed_active = false;
            chain.confirmed_nonce = None;
        }
        restarted.poll_once().await.unwrap();
        assert!(restarted.checkpoint.pending.is_empty());
    }

    /// Threat: under-concession. Only evidence at `N`, settled at 120: the
    /// service raises to 120; once the vault shows the raise it stops.
    #[tokio::test]
    async fn under_concession_is_raised_once_to_the_settled_charge() {
        let fixture = Fixture::new(MockChain::new(), &[N]).await;
        fixture
            .store
            .record_settlement(&Felt252::from_u64(N), 120, 200, "{}")
            .unwrap();
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        {
            let chain = fixture.chain.lock().unwrap();
            assert_eq!(chain.sends.len(), 1);
            assert_eq!(
                chain.sends[0]["data"],
                fixture.expected(ActionKind::Raise { amount: 120 })
            );
        }
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.conceded = 120;
            chain.mined_nonce = 4;
            chain.confirmed_nonce = Some(4);
        }
        service.poll_once().await.unwrap();
        service.poll_once().await.unwrap();
        assert_eq!(fixture.chain.lock().unwrap().sends.len(), 1);
        assert_eq!(service.checkpoint.pending[&0].action, None);
    }

    /// A defeat supersedes an unmined raise: same nonce, higher fee, defeat
    /// calldata. A raise never replaces a pending defeat.
    #[tokio::test]
    async fn defeat_replaces_an_unmined_raise_on_the_same_nonce() {
        let fixture = Fixture::new(MockChain::new(), &[N]).await;
        fixture
            .store
            .record_settlement(&Felt252::from_u64(N), 120, 200, "{}")
            .unwrap();
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert_eq!(
            service.checkpoint.pending[&0].action,
            Some(ActionKind::Raise { amount: 120 })
        );
        // The cheater's request at N⁺ arrives while the raise is unmined.
        served(&fixture.store, "late", Felt252::from_u64(N_NEXT), 300);
        service.poll_once().await.unwrap();
        {
            let chain = fixture.chain.lock().unwrap();
            assert_eq!(chain.sends.len(), 2);
            assert_eq!(chain.sends[1]["nonce"], chain.sends[0]["nonce"]);
            assert_eq!(chain.sends[1]["gasPrice"], "0x29", "0x20 + 25% + 1");
            assert_eq!(chain.sends[1]["data"], fixture.expected(ActionKind::Defeat));
        }
        assert_eq!(
            service.checkpoint.pending[&0].action,
            Some(ActionKind::Defeat)
        );
        service.poll_once().await.unwrap();
        assert_eq!(fixture.chain.lock().unwrap().sends.len(), 2);
    }

    /// A rejected defeat replacement (signer outage, fee cap) leaves the raise
    /// as the known in-flight call, so the replacement is retried; it is not
    /// recorded as a defeat that will never be resent while the raise sits
    /// unmined.
    #[tokio::test]
    async fn rejected_defeat_replacement_is_retried() {
        let fixture = Fixture::new(MockChain::new(), &[N]).await;
        fixture
            .store
            .record_settlement(&Felt252::from_u64(N), 120, 200, "{}")
            .unwrap();
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        served(&fixture.store, "late", Felt252::from_u64(N_NEXT), 300);
        fixture.chain.lock().unwrap().fail_first_send = true;
        assert!(service.poll_once().await.is_err());
        assert_eq!(
            service.checkpoint.pending[&0].action,
            Some(ActionKind::Raise { amount: 120 })
        );
        service.poll_once().await.unwrap();
        {
            let chain = fixture.chain.lock().unwrap();
            assert_eq!(chain.sends.len(), 3);
            assert_eq!(chain.sends[2]["nonce"], chain.sends[0]["nonce"]);
            assert_eq!(chain.sends[2]["data"], fixture.expected(ActionKind::Defeat));
        }
        assert_eq!(
            service.checkpoint.pending[&0].action,
            Some(ActionKind::Defeat)
        );
    }

    /// An honest fresh escape: no evidence at `N` or `N⁺`; nothing is sent.
    #[tokio::test]
    async fn honest_fresh_escape_is_never_challenged() {
        let fixture = Fixture::new(MockChain::new(), &[]).await;
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        service.poll_once().await.unwrap();
        assert!(fixture.chain.lock().unwrap().sends.is_empty());
        assert_eq!(service.checkpoint.pending[&0].nonce, None);
    }

    /// Threat: challenger halt. A raise's send failed after its nonce was
    /// reserved (fee above the signer cap, signer outage, or a front-run),
    /// then the escape's owner raised her own concession so no raise is due.
    /// The unbroadcast nonce must carry the next challenge: it must neither
    /// silently stop the defeat of another stale escape nor halt the service
    /// once that escape finalizes.
    #[tokio::test]
    async fn unneeded_reserved_nonce_is_reused_instead_of_halting_challenges() {
        let fixture = Fixture::stale().await;
        fixture
            .store
            .record_settlement(&Felt252::from_u64(N), 120, 200, "{}")
            .unwrap();
        let mut service = fixture.service();
        // Note 1: no successor evidence, already raised to its bound by its owner.
        fixture.chain.lock().unwrap().withdrawals.insert(
            1,
            Withdrawal {
                active: true,
                nullifier: Felt252::from_u64(N),
                next_nullifier: Felt252::from_u64(99),
                conceded: 300,
                deadline: 200,
            },
        );
        service.checkpoint.pending.insert(
            1,
            PendingChallenge {
                nullifier: Felt252::from_u64(N),
                next_nullifier: Felt252::from_u64(99),
                transaction_hash: None,
                nonce: Some(3),
                action: Some(ActionKind::Raise { amount: 120 }),
                deadline_reported: false,
                gas_price: None,
            },
        );
        service.persist().unwrap();
        service.poll_once().await.unwrap();
        {
            let chain = fixture.chain.lock().unwrap();
            assert_eq!(chain.sends.len(), 1, "note 0's stale escape must be defeated");
            assert_eq!(chain.sends[0]["nonce"], "0x3", "reuse, never allocate above it");
            assert_eq!(chain.sends[0]["data"], fixture.expected(ActionKind::Defeat));
        }
        assert_eq!(service.checkpoint.pending[&1].nonce, None);
        assert_eq!(service.checkpoint.pending[&0].nonce, Some(3));
        // Note 1's escape finalizes: no orphaned reservation halts the service.
        fixture
            .chain
            .lock()
            .unwrap()
            .withdrawals
            .get_mut(&1)
            .unwrap()
            .active = false;
        service.poll_once().await.unwrap();
        assert!(!service.checkpoint.pending.contains_key(&1));
        assert!(service.checkpoint.detached_nonces.is_empty());
    }

    /// Threat: a gap below a held nonce. A completed note's detached
    /// transaction at 3 is dropped while note 1's defeat waits at 4; nothing
    /// else fills 3, so the defeat could never mine. Note 1's defeat moves
    /// down to 3 (its old transaction at 4 stays tracked), and the in-flight
    /// detached transaction never halts the service.
    #[tokio::test]
    async fn held_nonce_above_a_dropped_spare_moves_down_to_fill_it() {
        let fixture = Fixture::new(MockChain::new(), &[]).await;
        let mut service = fixture.service();
        fixture.chain.lock().unwrap().withdrawals.insert(
            7,
            Withdrawal {
                active: false,
                nullifier: Felt252::from_u64(70),
                next_nullifier: Felt252::from_u64(71),
                conceded: 0,
                deadline: 200,
            },
        );
        service.checkpoint.pending.insert(
            7,
            PendingChallenge {
                nullifier: Felt252::from_u64(70),
                next_nullifier: Felt252::from_u64(71),
                transaction_hash: Some("0xold".into()),
                nonce: Some(3),
                action: Some(ActionKind::Defeat),
                deadline_reported: false,
                gas_price: None,
            },
        );
        service.persist().unwrap();
        service.poll_once().await.unwrap();
        assert!(!service.checkpoint.pending.contains_key(&7));
        // Note 1's stale escape already has a defeat pending at nonce 4.
        served(&fixture.store, "late", Felt252::from_u64(51), 300);
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.dropped.push("0xold".into());
            chain.withdrawals.insert(
                1,
                Withdrawal {
                    active: true,
                    nullifier: Felt252::from_u64(50),
                    next_nullifier: Felt252::from_u64(51),
                    conceded: 0,
                    deadline: 200,
                },
            );
        }
        service.checkpoint.pending.insert(
            1,
            PendingChallenge {
                nullifier: Felt252::from_u64(50),
                next_nullifier: Felt252::from_u64(51),
                transaction_hash: Some("0xmine".into()),
                nonce: Some(4),
                action: Some(ActionKind::Defeat),
                deadline_reported: false,
                gas_price: None,
            },
        );
        service.persist().unwrap();
        service.poll_once().await.unwrap();
        {
            let chain = fixture.chain.lock().unwrap();
            assert_eq!(chain.sends.len(), 1, "the gap at 3 must be filled");
            assert_eq!(chain.sends[0]["nonce"], "0x3");
        }
        assert_eq!(service.checkpoint.pending[&1].nonce, Some(3));
        assert_eq!(
            service.checkpoint.pending[&1].action,
            Some(ActionKind::Defeat)
        );
        assert_eq!(
            service.checkpoint.detached_nonces[&4]
                .transaction_hash
                .as_deref(),
            Some("0xmine")
        );
        // The superseded transaction at 4 is tracked, never waited on.
        service.poll_once().await.unwrap();
        assert_eq!(fixture.chain.lock().unwrap().sends.len(), 1);
    }

    /// Threat: a restored in-flight raise loses its kind. Event replay
    /// restores the reservation with its action, so a defeat that becomes due
    /// still replaces the unmined raise on the same nonce.
    #[tokio::test]
    async fn event_replay_restores_the_reserved_action_so_a_defeat_replaces_the_raise() {
        let fixture = Fixture::new(MockChain::new(), &[N]).await;
        fixture
            .store
            .record_settlement(&Felt252::from_u64(N), 120, 200, "{}")
            .unwrap();
        let mut service = fixture.service();
        service.checkpoint.pending.insert(
            0,
            PendingChallenge {
                nullifier: Felt252::from_u64(N),
                next_nullifier: Felt252::from_u64(N_NEXT),
                transaction_hash: Some("0xsubmitted".into()),
                nonce: Some(3),
                action: Some(ActionKind::Raise { amount: 120 }),
                deadline_reported: false,
                gas_price: None,
            },
        );
        service.persist().unwrap();
        // An intervening fork presents a different, unchallengeable withdrawal.
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.nullifier = Felt252::from_u64(999);
            chain.next_nullifier = Felt252::from_u64(998);
        }
        service.poll_once().await.ok();
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.nullifier = Felt252::from_u64(N);
            chain.next_nullifier = Felt252::from_u64(N_NEXT);
            chain.block_hash = "0xforkB".into();
        }
        served(&fixture.store, "late", Felt252::from_u64(N_NEXT), 300);
        drop(service);
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        {
            let chain = fixture.chain.lock().unwrap();
            assert_eq!(chain.sends.len(), 1, "the defeat must replace the raise");
            assert_eq!(chain.sends[0]["nonce"], "0x3");
            assert_eq!(chain.sends[0]["gasPrice"], "0x29");
            assert_eq!(chain.sends[0]["data"], fixture.expected(ActionKind::Defeat));
        }
        assert_eq!(
            service.checkpoint.pending[&0].action,
            Some(ActionKind::Defeat)
        );
    }

    /// Threat: a reserved call that now fails simulation (the vault would
    /// revert it) must not hold its unsent nonce and stop other defeats.
    #[tokio::test]
    async fn reserved_call_failing_simulation_releases_its_nonce() {
        let fixture = Fixture::stale().await;
        let mut service = fixture.service();
        fixture.reserve(&mut service, 1, false);
        fixture.chain.lock().unwrap().revert_note = Some(1);
        assert!(service.poll_once().await.is_err());
        {
            let chain = fixture.chain.lock().unwrap();
            assert_eq!(chain.sends.len(), 1, "note 0's defeat must not be held");
            assert_eq!(chain.sends[0]["nonce"], "0x3");
            assert_eq!(chain.sends[0]["data"], fixture.expected(ActionKind::Defeat));
        }
        assert_eq!(service.checkpoint.pending[&1].nonce, None);
        assert_eq!(service.checkpoint.pending[&0].nonce, Some(3));
    }

    /// Threat: a hashless reservation is not an unused nonce. A raise's send
    /// failed ambiguously, yet the node accepted it (pending count 4); after
    /// the raise became unnecessary its nonce carries another note's defeat,
    /// which must outbid the occupant or be "replacement underpriced" forever.
    #[tokio::test]
    async fn reused_hashless_nonce_occupied_in_the_mempool_bumps_the_fee() {
        let mut mock = MockChain::new();
        mock.fail_first_send = true;
        let fixture = Fixture::new(mock, &[N]).await;
        fixture
            .store
            .record_settlement(&Felt252::from_u64(N), 120, 200, "{}")
            .unwrap();
        let mut service = fixture.service();
        assert!(service.poll_once().await.is_err());
        assert_eq!(service.checkpoint.pending[&0].nonce, Some(3));
        assert_eq!(service.checkpoint.pending[&0].gas_price, Some(0x10));
        served(&fixture.store, "stale", Felt252::from_u64(61), 300);
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.conceded = 300;
            chain.pending_nonce = Some(4);
            chain.withdrawals.insert(
                1,
                Withdrawal {
                    active: true,
                    nullifier: Felt252::from_u64(60),
                    next_nullifier: Felt252::from_u64(61),
                    conceded: 0,
                    deadline: 200,
                },
            );
        }
        service.checkpoint.pending.insert(
            1,
            PendingChallenge {
                nullifier: Felt252::from_u64(60),
                next_nullifier: Felt252::from_u64(61),
                transaction_hash: None,
                nonce: None,
                action: None,
                deadline_reported: false,
                gas_price: None,
            },
        );
        service.persist().unwrap();
        service.poll_once().await.unwrap();
        {
            let chain = fixture.chain.lock().unwrap();
            assert_eq!(chain.sends.len(), 2);
            assert_eq!(chain.sends[1]["nonce"], "0x3");
            assert_eq!(chain.sends[1]["gasPrice"], "0x15", "0x10 + 25% + 1");
        }
        assert_eq!(service.checkpoint.pending[&0].nonce, None);
        assert_eq!(service.checkpoint.pending[&1].gas_price, Some(0x15));
    }

    /// A required bump never exceeds the signer's gas price cap, so a refused
    /// bump cannot escalate; the occupant mines or drops and the retry lands.
    #[tokio::test]
    async fn fee_bump_is_capped_at_the_signer_limit() {
        let fixture = Fixture::stale().await;
        let mut config = fixture.config.clone();
        config.max_gas_price_wei = 0x12;
        let mut service =
            ChallengeService::with_verifier(config, fixture.store.clone(), Box::new(StubVerifier))
                .unwrap();
        fixture.reserve(&mut service, 1, false);
        fixture.chain.lock().unwrap().pending_nonce = Some(4);
        service.poll_once().await.unwrap();
        let chain = fixture.chain.lock().unwrap();
        assert_eq!(chain.sends[0]["nonce"], "0x3");
        assert_eq!(chain.sends[0]["gasPrice"], "0x12");
    }

    /// Threat: a transient gas-estimator failure for a reserved call must not
    /// hold its unsent nonce and stop other defeats.
    #[tokio::test]
    async fn reserved_call_failing_gas_estimation_releases_its_nonce() {
        let fixture = Fixture::stale().await;
        let mut service = fixture.service();
        fixture.reserve(&mut service, 1, false);
        fixture.chain.lock().unwrap().estimate_fail_note = Some(1);
        assert!(service.poll_once().await.is_err());
        {
            let chain = fixture.chain.lock().unwrap();
            assert_eq!(chain.sends.len(), 1, "note 0's defeat must not be held");
            assert_eq!(chain.sends[0]["nonce"], "0x3");
            assert_eq!(chain.sends[0]["data"], fixture.expected(ActionKind::Defeat));
        }
        assert_eq!(service.checkpoint.pending[&1].nonce, None);
        assert_eq!(service.checkpoint.pending[&0].nonce, Some(3));
    }

    #[tokio::test]
    async fn expired_ambiguous_mined_nonce_allows_queue_progress_across_restart() {
        let fixture = Fixture::stale().await;
        let mut service = fixture.service();
        fixture.reserve(&mut service, 1, true);
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.mined_nonce = 4;
            chain.confirmed_nonce = Some(3);
        }
        drop(service);
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert_eq!(fixture.chain.lock().unwrap().sends.len(), 1);
        assert_eq!(fixture.chain.lock().unwrap().sends[0]["nonce"], "0x4");
        assert_eq!(
            service.checkpoint.pending[&1].nonce,
            Some(3),
            "retain tip-reorg protection"
        );
        assert!(service.checkpoint.pending[&1].deadline_reported);
        drop(service);
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert_eq!(
            fixture.chain.lock().unwrap().sends.len(),
            1,
            "restart cannot duplicate submission"
        );
        fixture.chain.lock().unwrap().confirmed_nonce = Some(4);
        service.poll_once().await.unwrap();
        assert_eq!(service.checkpoint.pending[&1].nonce, None);
        assert_eq!(fixture.chain.lock().unwrap().sends.len(), 1);
    }

    /// An expired note's unsent reservation carries the next challenge: even
    /// when the RPC pending count has advanced past it, nothing is allocated
    /// above it.
    #[tokio::test]
    async fn expired_unsent_nonce_carries_the_next_challenge_even_when_pending_count_advances() {
        let fixture = Fixture::stale().await;
        let mut service = fixture.service();
        fixture.reserve(&mut service, 1, true);
        fixture.chain.lock().unwrap().pending_nonce = Some(4);
        drop(service);
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        {
            let chain = fixture.chain.lock().unwrap();
            assert_eq!(chain.sends.len(), 1);
            assert_eq!(chain.sends[0]["nonce"], "0x3");
        }
        assert_eq!(service.checkpoint.pending[&1].nonce, None);
        assert!(service.checkpoint.pending[&1].deadline_reported);
        assert_eq!(service.checkpoint.pending[&0].nonce, Some(3));
        assert!(service.checkpoint.detached_nonces.is_empty());
    }

    /// A completed withdrawal's reservation: while its transaction is in
    /// flight it is tracked without halting the service; once the node drops
    /// it, it carries the next challenge.
    #[tokio::test]
    async fn completed_withdrawal_nonce_is_tracked_in_flight_then_carries_the_next_challenge() {
        let fixture = Fixture::new(MockChain::new(), &[]).await;
        let mut service = fixture.service();
        fixture.reserve(&mut service, 1, false);
        service
            .checkpoint
            .pending
            .get_mut(&1)
            .unwrap()
            .transaction_hash = Some("0xsubmitted".into());
        service.persist().unwrap();
        fixture
            .chain
            .lock()
            .unwrap()
            .withdrawals
            .get_mut(&1)
            .unwrap()
            .active = false;
        service.poll_once().await.unwrap();
        assert!(!service.checkpoint.pending.contains_key(&1));
        assert_eq!(
            service.checkpoint.detached_nonces[&3]
                .transaction_hash
                .as_deref(),
            Some("0xsubmitted")
        );
        service.poll_once().await.unwrap();
        assert!(fixture.chain.lock().unwrap().sends.is_empty());
        assert_eq!(
            service.checkpoint.detached_nonces[&3].action,
            Some(ActionKind::Defeat)
        );
        // The node dropped it; note 0's escape turns out stale.
        fixture.chain.lock().unwrap().transaction_known = false;
        served(&fixture.store, "stale", Felt252::from_u64(N_NEXT), 300);
        drop(service);
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        {
            let chain = fixture.chain.lock().unwrap();
            assert_eq!(chain.sends.len(), 1);
            assert_eq!(chain.sends[0]["nonce"], "0x3");
            assert_eq!(chain.sends[0]["data"], fixture.expected(ActionKind::Defeat));
        }
        assert!(service.checkpoint.detached_nonces.is_empty());
        assert_eq!(service.checkpoint.pending[&0].nonce, Some(3));
    }

    #[tokio::test]
    async fn event_replay_restores_reservation_when_its_original_nullifier_returns() {
        let fixture = Fixture::stale().await;
        let mut service = fixture.service();
        fixture.reserve(&mut service, 0, false);
        // An intervening fork presents a different, unchallengeable withdrawal.
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.nullifier = Felt252::from_u64(999);
            chain.next_nullifier = Felt252::from_u64(998);
            chain.withdrawals.clear();
        }
        service.poll_once().await.unwrap();
        assert!(service.checkpoint.detached_nonces[&3]
            .transaction_hash
            .is_none());
        assert!(fixture.chain.lock().unwrap().sends.is_empty());
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.nullifier = Felt252::from_u64(N);
            chain.next_nullifier = Felt252::from_u64(N_NEXT);
            chain.block_hash = "0xforkB".into();
        }
        drop(service);
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert!(service.checkpoint.detached_nonces.is_empty());
        assert_eq!(service.checkpoint.pending[&0].nonce, Some(3));
        assert_eq!(fixture.chain.lock().unwrap().sends.len(), 1);
        assert_eq!(fixture.chain.lock().unwrap().sends[0]["nonce"], "0x3");
    }

    #[tokio::test]
    async fn lagging_rpc_pending_count_cannot_reuse_another_notes_known_nonce() {
        let fixture = Fixture::stale().await;
        let mut service = fixture.service();
        fixture.reserve(&mut service, 1, true);
        service
            .checkpoint
            .pending
            .get_mut(&1)
            .unwrap()
            .transaction_hash = Some("0xsubmitted".into());
        service.persist().unwrap();
        assert!(service
            .poll_once()
            .await
            .unwrap_err()
            .to_string()
            .contains("conflicts with a durable challenge reservation"));
        assert!(fixture.chain.lock().unwrap().sends.is_empty());
        assert_eq!(service.checkpoint.pending[&1].nonce, Some(3));
        assert_eq!(service.checkpoint.pending[&0].nonce, None);
    }
}
