//! Durable concession-exit challenger for chain-neutral [`CreditLedger`]
//! backends.
//!
//! Discovery, transaction construction, submission and recovery all cross the
//! ledger boundary. Each pending escape is judged by the [`ChallengeWatcher`]
//! policy: defeat with evidence at `N⁺`, or raise the concession with evidence
//! at `N`. Both are root-independent. A defeat supersedes an unmined raise;
//! a raise never replaces a defeat. The only Solana-specific component is the
//! local transaction signer.

use crate::{
    checkpoint::persist_json,
    nullifier_store::NullifierStore,
    watcher::{ActionKind, ChallengeWatcher, Decision, EvidenceVerifier, PendingEscape},
};
use anyhow::{bail, ensure, Context};
use dagon_zkapi_ledger::{
    ChallengeRequest, CreditLedger, LedgerAccount, LedgerCommitment, LedgerDeployment,
    LedgerPendingEscape, LedgerTransactionStatus, PreparedLedgerTransaction,
    RaiseConcessionRequest, SignedLedgerTransaction,
};
use serde::{Deserialize, Serialize};
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use std::{collections::BTreeMap, path::PathBuf, sync::Arc};
use zkapi_proof::compact::RequestVerifier;
use zkapi_types::Felt252;

const CHECKPOINT_VERSION: u16 = 2;
const MAX_OPERATION_TRANSACTIONS: usize = 32;

#[derive(Clone, Debug)]
pub struct LedgerChallengeServiceConfig {
    pub checkpoint: PathBuf,
    pub proof_setup_dir: PathBuf,
    /// Raise with the request's bound this long before the deadline when its
    /// charge is still unsettled.
    pub raise_lead_seconds: u64,
}

/// Signed bytes plus the deterministic transaction identifier derived before
/// submission. Persisting both closes the "RPC accepted it but the response was
/// lost" crash window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedLedgerEnvelope {
    pub transaction: SignedLedgerTransaction,
    pub transaction_id: Vec<u8>,
}

pub trait LedgerTransactionSigner: Send + Sync {
    fn account(&self) -> LedgerAccount;
    fn sign(&self, transaction: &PreparedLedgerTransaction)
        -> anyhow::Result<SignedLedgerEnvelope>;
}

/// Restricted one-keypair signer for messages produced by the Solana ledger.
/// It refuses arbitrary formats, multiple signers and a payer different from
/// the configured operator key.
pub struct SolanaKeypairTransactionSigner {
    keypair: Keypair,
}

impl SolanaKeypairTransactionSigner {
    pub fn new(keypair: Keypair) -> Self {
        Self { keypair }
    }
}

impl LedgerTransactionSigner for SolanaKeypairTransactionSigner {
    fn account(&self) -> LedgerAccount {
        LedgerAccount::new(self.keypair.pubkey().to_bytes())
    }

    fn sign(
        &self,
        transaction: &PreparedLedgerTransaction,
    ) -> anyhow::Result<SignedLedgerEnvelope> {
        ensure!(
            transaction.format == dagon_zkapi_solana_ledger::MESSAGE_FORMAT,
            "operator signer rejects transaction format {}",
            transaction.format
        );
        ensure!(
            transaction.required_signers.as_slice() == [self.account()],
            "prepared operation requires an unexpected signer set"
        );
        let message: Message = bincode::deserialize(&transaction.bytes)
            .context("prepared Solana message is not canonical bincode")?;
        ensure!(
            bincode::serialize(&message)? == transaction.bytes,
            "prepared Solana message has a noncanonical encoding"
        );
        ensure!(
            message.header.num_required_signatures == 1
                && message.account_keys.first() == Some(&self.keypair.pubkey()),
            "prepared Solana message does not use the operator as its sole signer"
        );
        let message_bytes = message.serialize();
        ensure!(
            message_bytes == transaction.bytes,
            "prepared Solana message serialization changed before signing"
        );
        let signature = self.keypair.try_sign_message(&message_bytes)?;
        let mut bytes = Vec::with_capacity(1 + signature.as_ref().len() + message_bytes.len());
        bytes.push(1); // canonical shortvec encoding for one signature
        bytes.extend_from_slice(signature.as_ref());
        bytes.extend_from_slice(&message_bytes);
        Ok(SignedLedgerEnvelope {
            transaction: SignedLedgerTransaction {
                format: dagon_zkapi_solana_ledger::SIGNED_TRANSACTION_FORMAT.into(),
                bytes,
            },
            transaction_id: signature.to_string().into_bytes(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Checkpoint {
    version: u16,
    deployment: LedgerDeployment,
    payer: LedgerAccount,
    jobs: BTreeMap<String, ChallengeJob>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ChallengeJob {
    note_id: u32,
    nullifier: Felt252,
    next_nullifier: Felt252,
    state_balance: u128,
    conceded: u128,
    deadline: u64,
    #[serde(default)]
    observed_time: Option<u64>,
    #[serde(default)]
    deadline_reported: bool,
    plan: Option<DurablePlan>,
}

impl ChallengeJob {
    fn escape(&self) -> PendingEscape {
        PendingEscape {
            note_id: self.note_id,
            nullifier: self.nullifier,
            next_nullifier: self.next_nullifier,
            state_balance: self.state_balance,
            conceded: self.conceded,
            deadline: self.deadline,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DurablePlan {
    /// The call this plan submits.
    action: ActionKind,
    transactions: Vec<DurableTransaction>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DurableTransaction {
    signed: SignedLedgerTransaction,
    transaction_id: Vec<u8>,
    last_valid_height: Option<u64>,
    submitted: bool,
}

pub struct LedgerChallengeService {
    config: LedgerChallengeServiceConfig,
    ledger: Arc<dyn CreditLedger>,
    signer: Arc<dyn LedgerTransactionSigner>,
    watcher: ChallengeWatcher,
    checkpoint: Checkpoint,
}

impl LedgerChallengeService {
    pub fn new(
        config: LedgerChallengeServiceConfig,
        store: Arc<NullifierStore>,
        ledger: Arc<dyn CreditLedger>,
        signer: Arc<dyn LedgerTransactionSigner>,
    ) -> anyhow::Result<Self> {
        let verifier = RequestVerifier::load(&config.proof_setup_dir)?;
        Self::with_verifier(config, store, ledger, signer, Box::new(verifier))
    }

    pub(crate) fn with_verifier(
        config: LedgerChallengeServiceConfig,
        store: Arc<NullifierStore>,
        ledger: Arc<dyn CreditLedger>,
        signer: Arc<dyn LedgerTransactionSigner>,
        verifier: Box<dyn EvidenceVerifier>,
    ) -> anyhow::Result<Self> {
        let deployment = ledger.deployment().clone();
        let payer = signer.account();
        ensure!(
            payer != LedgerAccount::ZERO,
            "challenge payer cannot be zero"
        );
        ensure!(config.raise_lead_seconds > 0, "raise lead must be positive");
        let checkpoint: Checkpoint = if config.checkpoint.exists() {
            serde_json::from_slice(&std::fs::read(&config.checkpoint)?)?
        } else {
            Checkpoint {
                version: CHECKPOINT_VERSION,
                deployment: deployment.clone(),
                payer,
                jobs: BTreeMap::new(),
            }
        };
        validate_checkpoint(&checkpoint, &deployment, payer)?;
        Ok(Self {
            watcher: ChallengeWatcher::new(
                store,
                verifier,
                config.raise_lead_seconds,
                deployment.chain_id,
                deployment.protocol_binding,
            ),
            config,
            ledger,
            signer,
            checkpoint,
        })
    }

    pub fn outstanding_jobs(&self) -> usize {
        self.checkpoint.jobs.len()
    }

    /// Discover finalized obligations, persist them, then make one durable step
    /// for every challengeable note. Each note's transactions are independent,
    /// so a failure for one note does not starve the others.
    pub async fn poll_once(&mut self) -> anyhow::Result<()> {
        let pending = self
            .ledger
            .pending_escapes(LedgerCommitment::Finalized)
            .await?;
        let current = validated_pending_map(pending)?;
        let mut changed = false;
        for (key, escape) in &current {
            match self.checkpoint.jobs.get_mut(key) {
                Some(job) => {
                    let refreshed = (
                        escape.next_nullifier,
                        escape.state_balance,
                        escape.conceded,
                        escape.deadline,
                        escape.observed_time,
                    );
                    if (
                        job.next_nullifier,
                        job.state_balance,
                        job.conceded,
                        job.deadline,
                        job.observed_time,
                    ) != refreshed
                    {
                        (
                            job.next_nullifier,
                            job.state_balance,
                            job.conceded,
                            job.deadline,
                            job.observed_time,
                        ) = refreshed;
                        changed = true;
                    }
                }
                None => {
                    self.checkpoint.jobs.insert(
                        key.clone(),
                        ChallengeJob {
                            note_id: escape.note_id,
                            nullifier: escape.nullifier,
                            next_nullifier: escape.next_nullifier,
                            state_balance: escape.state_balance,
                            conceded: escape.conceded,
                            deadline: escape.deadline,
                            observed_time: escape.observed_time,
                            deadline_reported: false,
                            plan: None,
                        },
                    );
                    changed = true;
                }
            }
        }
        let before = self.checkpoint.jobs.len();
        self.checkpoint
            .jobs
            .retain(|key, _| current.contains_key(key));
        changed |= before != self.checkpoint.jobs.len();
        if changed {
            self.persist()?;
        }

        let keys: Vec<_> = self.checkpoint.jobs.keys().cloned().collect();
        let mut first_error = None;
        for key in keys {
            if let Err(error) = self.reconcile(&key).await {
                let job = &self.checkpoint.jobs[&key];
                tracing::error!(
                    note_id = job.note_id,
                    nullifier = %job.nullifier,
                    error = %error,
                    "ledger escape challenge requires retry"
                );
                first_error.get_or_insert(error);
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    async fn reconcile(&mut self, key: &str) -> anyhow::Result<()> {
        let job = self.checkpoint.jobs[key].clone();
        // The backend's snapshot time is authoritative when present.
        let now = job.observed_time.unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        });
        let action = match self.watcher.decide(&job.escape(), now)? {
            Decision::Act(action) => *action,
            Decision::Wait => return Ok(()),
            Decision::Nothing => {
                // A landed raise leaves nothing due; retire its finished plan.
                if job.plan.is_some() {
                    self.checkpoint.jobs.get_mut(key).unwrap().plan = None;
                    self.persist()?;
                }
                return Ok(());
            }
        };
        if job
            .observed_time
            .is_some_and(|observed_time| observed_time >= job.deadline)
        {
            if !job.deadline_reported {
                tracing::error!(
                    note_id = job.note_id,
                    nullifier = %job.nullifier,
                    kind = ?action.kind,
                    "MISSED ledger escape challenge deadline"
                );
                self.checkpoint.jobs.get_mut(key).unwrap().deadline_reported = true;
                self.persist()?;
            }
            return Ok(());
        }
        match job.plan.as_ref().map(|plan| plan.action) {
            None => self.prepare_plan(key, action).await?,
            // The one replacement: a defeat supersedes an unmined raise. The
            // raise may still land; the defeat stays valid after it.
            Some(ActionKind::Raise { .. }) if action.kind.is_defeat() => {
                tracing::warn!(
                    note_id = job.note_id,
                    "successor evidence appeared while a raise is in flight; preparing the defeat"
                );
                self.prepare_plan(key, action).await?
            }
            Some(ActionKind::Defeat) if !action.kind.is_defeat() => {
                bail!("a raise never replaces a defeat")
            }
            Some(_) => {}
        }
        self.drive_plan(key).await
    }

    async fn prepare_plan(
        &mut self,
        key: &str,
        action: crate::watcher::ChallengeAction,
    ) -> anyhow::Result<()> {
        let job = self.checkpoint.jobs[key].clone();
        // Defeat and raise need no Merkle path: they cannot be staled by
        // root changes. The watcher verified the evidence for this deployment.
        let operation = match action.kind {
            ActionKind::Defeat => {
                self.ledger
                    .prepare_challenge(ChallengeRequest {
                        payer: self.signer.account(),
                        note_id: job.note_id,
                        public_inputs: action.request_inputs,
                        proof: action.proof,
                    })
                    .await?
            }
            ActionKind::Raise { amount } => {
                self.ledger
                    .prepare_raise_concession(RaiseConcessionRequest {
                        payer: self.signer.account(),
                        note_id: job.note_id,
                        public_inputs: action.request_inputs,
                        proof: action.proof,
                        amount,
                    })
                    .await?
            }
        };
        ensure!(
            !operation.transactions.is_empty()
                && operation.transactions.len() <= MAX_OPERATION_TRANSACTIONS,
            "ledger returned an invalid challenge transaction count"
        );
        let mut transactions = Vec::with_capacity(operation.transactions.len());
        let mut identifiers = std::collections::HashSet::new();
        for prepared in operation.transactions {
            ensure!(
                prepared.required_signers.as_slice() == [self.signer.account()],
                "challenge transaction requires an unexpected signer"
            );
            let envelope = self.signer.sign(&prepared)?;
            ensure!(
                !envelope.transaction.bytes.is_empty()
                    && !envelope.transaction_id.is_empty()
                    && identifiers.insert(envelope.transaction_id.clone()),
                "signer returned an empty or duplicate challenge transaction"
            );
            transactions.push(DurableTransaction {
                signed: envelope.transaction,
                transaction_id: envelope.transaction_id,
                last_valid_height: prepared.last_valid_height,
                submitted: false,
            });
        }
        self.checkpoint.jobs.get_mut(key).unwrap().plan = Some(DurablePlan {
            action: action.kind,
            transactions,
        });
        self.persist()?;
        Ok(())
    }

    async fn drive_plan(&mut self, key: &str) -> anyhow::Result<()> {
        let count = self.checkpoint.jobs[key]
            .plan
            .as_ref()
            .expect("plan prepared")
            .transactions
            .len();
        for index in 0..count {
            let transaction = self.checkpoint.jobs[key]
                .plan
                .as_ref()
                .unwrap()
                .transactions[index]
                .clone();
            match self
                .ledger
                .transaction_status(transaction.transaction_id.clone())
                .await?
            {
                LedgerTransactionStatus::Finalized { .. }
                | LedgerTransactionStatus::Confirmed { .. } => {
                    if !transaction.submitted {
                        self.mark_submitted(key, index)?;
                    }
                }
                LedgerTransactionStatus::Pending => {
                    if !transaction.submitted {
                        self.mark_submitted(key, index)?;
                    }
                    return Ok(());
                }
                LedgerTransactionStatus::Unknown => {
                    if let Some(last_valid_height) = transaction.last_valid_height {
                        let current_height = self
                            .ledger
                            .transaction_height(LedgerCommitment::Confirmed)
                            .await?;
                        if current_height > last_valid_height {
                            self.checkpoint.jobs.get_mut(key).unwrap().plan = None;
                            self.persist()?;
                            bail!(
                                "challenge transaction expired before confirmation; a fresh operation will be prepared"
                            );
                        }
                    }
                    let submission = match self.ledger.submit(transaction.signed).await {
                        Ok(submission) => submission,
                        Err(dagon_zkapi_ledger::LedgerError::Rejected(reason)) => {
                            // Preflight rejection never produces a Failed signature
                            // status. Rebuild a fresh transaction on the next poll.
                            self.checkpoint.jobs.get_mut(key).unwrap().plan = None;
                            self.persist()?;
                            bail!("challenge transaction rejected before submission: {reason}");
                        }
                        Err(error) => return Err(error.into()),
                    };
                    ensure!(
                        submission.transaction_id == transaction.transaction_id,
                        "ledger returned a different transaction identifier"
                    );
                    self.mark_submitted(key, index)?;
                    return Ok(());
                }
                LedgerTransactionStatus::Failed { reason } => {
                    self.checkpoint.jobs.get_mut(key).unwrap().plan = None;
                    self.persist()?;
                    bail!("challenge transaction failed: {reason}");
                }
            }
        }
        // The finalized pending-escape snapshot is the authoritative completion
        // signal. Keep the fully submitted plan until it shows the effect.
        Ok(())
    }

    fn mark_submitted(&mut self, key: &str, index: usize) -> anyhow::Result<()> {
        let transaction = &mut self
            .checkpoint
            .jobs
            .get_mut(key)
            .unwrap()
            .plan
            .as_mut()
            .unwrap()
            .transactions[index];
        if !transaction.submitted {
            transaction.submitted = true;
            self.persist()?;
        }
        Ok(())
    }

    fn persist(&self) -> anyhow::Result<()> {
        persist_json(&self.config.checkpoint, &self.checkpoint)
    }
}

fn job_key(note_id: u32, nullifier: Felt252) -> String {
    format!("{note_id}:{}", nullifier.to_hex())
}

fn validated_pending_map(
    pending: Vec<LedgerPendingEscape>,
) -> anyhow::Result<BTreeMap<String, LedgerPendingEscape>> {
    let mut result = BTreeMap::new();
    let mut notes = std::collections::HashSet::new();
    for escape in pending {
        ensure!(
            escape.nullifier != Felt252::ZERO
                && escape.next_nullifier != Felt252::ZERO
                && escape.next_nullifier != escape.nullifier
                && escape.conceded <= escape.state_balance
                && escape.deadline > 0,
            "ledger returned an invalid pending escape"
        );
        ensure!(
            notes.insert(escape.note_id),
            "ledger returned duplicate pending escapes for one note"
        );
        result.insert(job_key(escape.note_id, escape.nullifier), escape);
    }
    Ok(result)
}

fn validate_checkpoint(
    checkpoint: &Checkpoint,
    deployment: &LedgerDeployment,
    payer: LedgerAccount,
) -> anyhow::Result<()> {
    ensure!(
        checkpoint.version == CHECKPOINT_VERSION
            && &checkpoint.deployment == deployment
            && checkpoint.payer == payer,
        "challenge checkpoint belongs to another ledger deployment or payer"
    );
    let mut identifiers = std::collections::HashSet::new();
    for (key, job) in &checkpoint.jobs {
        ensure!(
            key == &job_key(job.note_id, job.nullifier)
                && job.nullifier != Felt252::ZERO
                && job.deadline > 0,
            "challenge checkpoint contains an invalid job"
        );
        if let Some(plan) = &job.plan {
            ensure!(
                !plan.transactions.is_empty()
                    && plan.transactions.len() <= MAX_OPERATION_TRANSACTIONS,
                "challenge checkpoint contains an invalid operation plan"
            );
            for transaction in &plan.transactions {
                ensure!(
                    !transaction.signed.format.is_empty()
                        && !transaction.signed.bytes.is_empty()
                        && !transaction.transaction_id.is_empty()
                        && identifiers.insert(transaction.transaction_id.clone()),
                    "challenge checkpoint contains an invalid transaction"
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::watcher::tests::{served, StubVerifier, BINDING};
    use dagon_zkapi_ledger::{
        LedgerAsset, LedgerError, LedgerFuture, LedgerNullifierStatus, LedgerPath, LedgerSnapshot,
        LedgerState, LedgerSubmission, PreparedLedgerOperation,
    };
    use std::collections::HashMap;
    use std::sync::Mutex;

    const N: u64 = 10;
    const N_NEXT: u64 = 11;

    #[derive(Default)]
    struct MockState {
        pending: Vec<LedgerPendingEscape>,
        statuses: HashMap<Vec<u8>, LedgerTransactionStatus>,
        submissions: Vec<Vec<u8>>,
        fail_after_accept_once: bool,
        reject_before_accept_once: bool,
        prepared: usize,
        /// `(kind, amount)` of every prepared operation.
        operations: Vec<(&'static str, u128)>,
        transaction_height: u64,
    }

    struct MockLedger {
        deployment: LedgerDeployment,
        state: Arc<Mutex<MockState>>,
        payer: LedgerAccount,
    }

    impl MockLedger {
        fn prepare(
            &self,
            kind: &'static str,
            amount: u128,
            payer: LedgerAccount,
            public_inputs: &zkapi_types::RequestPublicInputsV2,
        ) -> LedgerFuture<'_, PreparedLedgerOperation> {
            let state = self.state.clone();
            let expected_payer = self.payer;
            let identity_ok = payer == expected_payer
                && public_inputs.chain_id == self.deployment.chain_id
                && public_inputs.contract_address == self.deployment.protocol_binding;
            Box::pin(async move {
                if !identity_ok {
                    return Err(LedgerError::Rejected(
                        "wrong mock challenge identity".into(),
                    ));
                }
                let generation = {
                    let mut state = state.lock().unwrap();
                    state.prepared += 1;
                    state.operations.push((kind, amount));
                    state.prepared as u8
                };
                let first = generation.saturating_mul(2).saturating_sub(1);
                Ok(PreparedLedgerOperation {
                    transactions: vec![
                        PreparedLedgerTransaction {
                            format: "mock-message".into(),
                            bytes: vec![first],
                            required_signers: vec![expected_payer],
                            last_valid_height: Some(100),
                        },
                        PreparedLedgerTransaction {
                            format: "mock-message".into(),
                            bytes: vec![first + 1],
                            required_signers: vec![expected_payer],
                            last_valid_height: Some(100),
                        },
                    ],
                })
            })
        }
    }

    impl CreditLedger for MockLedger {
        fn deployment(&self) -> &LedgerDeployment {
            &self.deployment
        }

        fn state(&self, commitment: LedgerCommitment) -> LedgerFuture<'_, LedgerState> {
            Box::pin(async move {
                Ok(LedgerState {
                    root: zkapi_core::v2::EMPTY_MERKLE_ROOT,
                    next_note_id: 1,
                    observed_height: Some(10),
                    commitment,
                })
            })
        }

        fn snapshot(&self, _commitment: LedgerCommitment) -> LedgerFuture<'_, LedgerSnapshot> {
            panic!("challenges must not read the tree")
        }

        fn path(
            &self,
            _note_id: u32,
            _zero_leaf: bool,
            _commitment: LedgerCommitment,
        ) -> LedgerFuture<'_, LedgerPath> {
            // Defeat and raise are root-independent: a challenger that needs a
            // Merkle path could be front-run by any unrelated root change.
            panic!("escape challenges must not read a Merkle path")
        }

        fn nullifier_status(
            &self,
            _nullifier: Felt252,
            _commitment: LedgerCommitment,
        ) -> LedgerFuture<'_, LedgerNullifierStatus> {
            Box::pin(async { Ok(LedgerNullifierStatus::Used) })
        }

        fn pending_escapes(
            &self,
            commitment: LedgerCommitment,
        ) -> LedgerFuture<'_, Vec<LedgerPendingEscape>> {
            assert_eq!(commitment, LedgerCommitment::Finalized);
            let state = self.state.clone();
            Box::pin(async move { Ok(state.lock().unwrap().pending.clone()) })
        }

        fn prepare_challenge(
            &self,
            request: ChallengeRequest,
        ) -> LedgerFuture<'_, PreparedLedgerOperation> {
            self.prepare("defeat", 0, request.payer, &request.public_inputs)
        }

        fn prepare_raise_concession(
            &self,
            request: RaiseConcessionRequest,
        ) -> LedgerFuture<'_, PreparedLedgerOperation> {
            self.prepare(
                "raise",
                request.amount,
                request.payer,
                &request.public_inputs,
            )
        }

        fn submit(
            &self,
            transaction: SignedLedgerTransaction,
        ) -> LedgerFuture<'_, LedgerSubmission> {
            let state = self.state.clone();
            Box::pin(async move {
                let id = vec![transaction.bytes[0] + 100];
                let mut state = state.lock().unwrap();
                if std::mem::take(&mut state.reject_before_accept_once) {
                    return Err(LedgerError::Rejected("preflight failure".into()));
                }
                state.submissions.push(id.clone());
                state
                    .statuses
                    .insert(id.clone(), LedgerTransactionStatus::Pending);
                if std::mem::take(&mut state.fail_after_accept_once) {
                    return Err(LedgerError::Unavailable(
                        "mock lost the accepted submission response".into(),
                    ));
                }
                Ok(LedgerSubmission { transaction_id: id })
            })
        }

        fn transaction_status(
            &self,
            transaction_id: Vec<u8>,
        ) -> LedgerFuture<'_, LedgerTransactionStatus> {
            let state = self.state.clone();
            Box::pin(async move {
                Ok(state
                    .lock()
                    .unwrap()
                    .statuses
                    .get(&transaction_id)
                    .cloned()
                    .unwrap_or(LedgerTransactionStatus::Unknown))
            })
        }

        fn transaction_height(&self, _commitment: LedgerCommitment) -> LedgerFuture<'_, u64> {
            let state = self.state.clone();
            Box::pin(async move { Ok(state.lock().unwrap().transaction_height) })
        }
    }

    struct MockSigner(LedgerAccount);

    impl LedgerTransactionSigner for MockSigner {
        fn account(&self) -> LedgerAccount {
            self.0
        }

        fn sign(
            &self,
            transaction: &PreparedLedgerTransaction,
        ) -> anyhow::Result<SignedLedgerEnvelope> {
            ensure!(transaction.format == "mock-message");
            Ok(SignedLedgerEnvelope {
                transaction: SignedLedgerTransaction {
                    format: "mock-signed".into(),
                    bytes: transaction.bytes.clone(),
                },
                transaction_id: vec![transaction.bytes[0] + 100],
            })
        }
    }

    fn deadline() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 6_000
    }

    fn escape(conceded: u128, observed_time: u64, deadline: u64) -> LedgerPendingEscape {
        LedgerPendingEscape {
            note_id: 0,
            nullifier: Felt252::from_u64(N),
            next_nullifier: Felt252::from_u64(N_NEXT),
            state_balance: 1_000,
            conceded,
            deadline,
            observed_time: Some(observed_time),
        }
    }

    struct Fixture {
        store: Arc<NullifierStore>,
        state: Arc<Mutex<MockState>>,
        ledger: Arc<MockLedger>,
        signer: Arc<MockSigner>,
        config: LedgerChallengeServiceConfig,
        _directory: tempfile::TempDir,
    }

    impl Fixture {
        fn new(evidence_at: &[u64], pending: Vec<LedgerPendingEscape>) -> Self {
            let store = Arc::new(NullifierStore::in_memory().unwrap());
            for nullifier in evidence_at {
                served(
                    &store,
                    &format!("r{nullifier}"),
                    Felt252::from_u64(*nullifier),
                    300,
                );
            }
            let payer = LedgerAccount::new([9; 32]);
            let state = Arc::new(Mutex::new(MockState {
                pending,
                transaction_height: 10,
                ..Default::default()
            }));
            let ledger = Arc::new(MockLedger {
                deployment: LedgerDeployment {
                    backend: "mock.groth16.v1".into(),
                    network: "test".into(),
                    chain_id: 1,
                    protocol_binding: Felt252::from_u64(BINDING),
                    vault: LedgerAccount::new([7; 32]),
                    asset: LedgerAsset {
                        symbol: "TEST".into(),
                        decimals: 9,
                        mint: None,
                    },
                },
                state: state.clone(),
                payer,
            });
            let directory = tempfile::tempdir().unwrap();
            Self {
                store,
                state,
                ledger,
                signer: Arc::new(MockSigner(payer)),
                config: LedgerChallengeServiceConfig {
                    checkpoint: directory.path().join("ledger-challenge.json"),
                    proof_setup_dir: PathBuf::new(),
                    raise_lead_seconds: 600,
                },
                _directory: directory,
            }
        }

        fn service(&self) -> LedgerChallengeService {
            LedgerChallengeService::with_verifier(
                self.config.clone(),
                self.store.clone(),
                self.ledger.clone(),
                self.signer.clone(),
                Box::new(StubVerifier),
            )
            .unwrap()
        }

        fn operations(&self) -> Vec<(&'static str, u128)> {
            self.state.lock().unwrap().operations.clone()
        }
    }

    #[test]
    fn solana_signer_accepts_only_its_canonical_single_signer_message() {
        let keypair = Keypair::new();
        let account = LedgerAccount::new(keypair.pubkey().to_bytes());
        let message = Message {
            header: solana_message::MessageHeader {
                num_required_signatures: 1,
                num_readonly_signed_accounts: 0,
                num_readonly_unsigned_accounts: 0,
            },
            account_keys: vec![keypair.pubkey()],
            recent_blockhash: Default::default(),
            instructions: Vec::new(),
        };
        let bytes = message.serialize();
        let expected_signature = keypair.sign_message(&bytes).to_string().into_bytes();
        let signer = SolanaKeypairTransactionSigner::new(keypair);
        let prepared = PreparedLedgerTransaction {
            format: dagon_zkapi_solana_ledger::MESSAGE_FORMAT.into(),
            bytes,
            required_signers: vec![account],
            last_valid_height: Some(10),
        };
        let signed = signer.sign(&prepared).unwrap();
        assert_eq!(signed.transaction_id, expected_signature);
        assert_eq!(signed.transaction.bytes[0], 1);
        assert_eq!(signed.transaction.bytes.len(), 65 + prepared.bytes.len());

        let mut wrong_signer = prepared.clone();
        wrong_signer.required_signers = vec![LedgerAccount::new([8; 32])];
        assert!(signer.sign(&wrong_signer).is_err());
        let mut wrong_format = prepared;
        wrong_format.format = "arbitrary".into();
        assert!(signer.sign(&wrong_format).is_err());
    }

    /// Threat: stale-state escape (ledger path). Evidence at `N⁺` yields a
    /// defeat; an accepted-but-lost submission recovers from the checkpoint
    /// without resending, expired blockhashes and preflight rejections are
    /// re-prepared, and an expired authoritative snapshot never funds one.
    #[tokio::test]
    async fn stale_escape_is_defeated_and_submission_recovers_from_checkpoint() {
        let deadline = deadline();
        let fixture = Fixture::new(&[N, N_NEXT], vec![escape(0, deadline - 6_000, deadline)]);
        fixture.state.lock().unwrap().fail_after_accept_once = true;
        let mut first = fixture.service();
        assert!(first.poll_once().await.is_err());
        assert_eq!(first.outstanding_jobs(), 1);
        assert_eq!(fixture.operations(), vec![("defeat", 0)]);
        assert_eq!(fixture.state.lock().unwrap().submissions, vec![vec![101]]);
        drop(first);

        let mut recovered = fixture.service();
        recovered.poll_once().await.unwrap();
        assert_eq!(
            fixture.state.lock().unwrap().submissions,
            vec![vec![101]],
            "restart must observe the accepted signature instead of resending"
        );
        fixture.state.lock().unwrap().statuses.insert(
            vec![101],
            LedgerTransactionStatus::Confirmed { height: Some(11) },
        );
        recovered.poll_once().await.unwrap();
        assert_eq!(
            fixture.state.lock().unwrap().submissions,
            vec![vec![101], vec![102]]
        );
        fixture.state.lock().unwrap().statuses.insert(
            vec![102],
            LedgerTransactionStatus::Finalized { height: Some(12) },
        );
        recovered.poll_once().await.unwrap();
        assert_eq!(recovered.outstanding_jobs(), 1);

        fixture.state.lock().unwrap().pending.clear();
        recovered.poll_once().await.unwrap();
        assert_eq!(recovered.outstanding_jobs(), 0);
        assert_eq!(fixture.state.lock().unwrap().prepared, 1);

        fixture.state.lock().unwrap().pending = vec![escape(0, deadline, deadline)];
        recovered.poll_once().await.unwrap();
        assert_eq!(recovered.outstanding_jobs(), 1);
        assert_eq!(
            fixture.state.lock().unwrap().prepared,
            1,
            "an authoritative expired snapshot must not prepare or fund an operation"
        );

        {
            let mut state = fixture.state.lock().unwrap();
            state.pending[0].observed_time = Some(deadline - 1);
            state.transaction_height = 101;
        }
        assert!(recovered.poll_once().await.is_err());
        assert_eq!(fixture.state.lock().unwrap().prepared, 2);
        assert_eq!(
            fixture.state.lock().unwrap().submissions,
            vec![vec![101], vec![102]],
            "an expired blockhash must be replaced before submission"
        );
        {
            let mut state = fixture.state.lock().unwrap();
            state.transaction_height = 10;
            state.reject_before_accept_once = true;
        }
        let error = recovered.poll_once().await.unwrap_err();
        assert!(
            error.to_string().contains("rejected before submission"),
            "{error:#}"
        );
        assert_eq!(fixture.state.lock().unwrap().prepared, 3);
        let saved: Checkpoint =
            serde_json::from_slice(&std::fs::read(&recovered.config.checkpoint).unwrap()).unwrap();
        assert!(saved.jobs.values().all(|job| job.plan.is_none()));
        recovered.poll_once().await.unwrap();
        assert_eq!(fixture.state.lock().unwrap().prepared, 4);
        assert_eq!(
            fixture.state.lock().unwrap().submissions,
            vec![vec![101], vec![102], vec![107]]
        );
    }

    /// Threat: under-concession (ledger path). Only evidence at `N`, settled
    /// at 120: raise to 120 once; when the snapshot shows the raise, the
    /// finished plan is retired and nothing more is sent.
    #[tokio::test]
    async fn under_concession_is_raised_to_the_settled_charge() {
        let deadline = deadline();
        let fixture = Fixture::new(&[N], vec![escape(0, deadline - 6_000, deadline)]);
        fixture
            .store
            .record_settlement(&Felt252::from_u64(N), 120, 200, "{}")
            .unwrap();
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert_eq!(fixture.operations(), vec![("raise", 120)]);
        fixture.state.lock().unwrap().pending = vec![escape(120, deadline - 5_000, deadline)];
        service.poll_once().await.unwrap();
        service.poll_once().await.unwrap();
        assert_eq!(fixture.operations(), vec![("raise", 120)]);
        assert!(service
            .checkpoint
            .jobs
            .values()
            .all(|job| job.plan.is_none()));
    }

    /// An unsettled, possibly delivered request is raised to its bound only
    /// at `deadline − raise_lead`, never before.
    #[tokio::test]
    async fn unsettled_delivered_request_is_raised_to_its_bound_at_the_lead() {
        let deadline = deadline();
        let fixture = Fixture::new(&[N], vec![escape(0, deadline - 6_000, deadline)]);
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert!(fixture.operations().is_empty());
        fixture.state.lock().unwrap().pending = vec![escape(0, deadline - 600, deadline)];
        service.poll_once().await.unwrap();
        assert_eq!(fixture.operations(), vec![("raise", 300)]);
    }

    /// A defeat supersedes an in-flight raise; a raise never replaces it.
    #[tokio::test]
    async fn defeat_supersedes_an_in_flight_raise() {
        let deadline = deadline();
        let fixture = Fixture::new(&[N], vec![escape(0, deadline - 6_000, deadline)]);
        fixture
            .store
            .record_settlement(&Felt252::from_u64(N), 120, 200, "{}")
            .unwrap();
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert_eq!(fixture.operations(), vec![("raise", 120)]);
        served(&fixture.store, "late", Felt252::from_u64(N_NEXT), 300);
        service.poll_once().await.unwrap();
        assert_eq!(fixture.operations(), vec![("raise", 120), ("defeat", 0)]);
        service.poll_once().await.unwrap();
        assert_eq!(fixture.operations().len(), 2);
    }

    /// An honest fresh escape is never touched.
    #[tokio::test]
    async fn honest_fresh_escape_is_never_challenged() {
        let deadline = deadline();
        let fixture = Fixture::new(&[], vec![escape(0, deadline - 600, deadline)]);
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert!(fixture.operations().is_empty());
        assert!(fixture.state.lock().unwrap().submissions.is_empty());
    }

    #[tokio::test]
    async fn malformed_pending_escapes_are_rejected() {
        let deadline = deadline();
        let mut same = escape(0, 0, deadline);
        same.next_nullifier = same.nullifier;
        let mut overconceded = escape(0, 0, deadline);
        overconceded.conceded = 1_001;
        for bad in [same, overconceded] {
            let fixture = Fixture::new(&[], vec![bad]);
            assert!(fixture.service().poll_once().await.is_err());
        }
    }
}
