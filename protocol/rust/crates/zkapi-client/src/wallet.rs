//! zkAPI v2 wallet: compact Groth16 proofs, proof-friendly state signatures
//! and the concession exit.
//!
//! Rules enforced here:
//! * S1–S6 before a successor is installed; a correctly signed successor
//!   that fails S3, S4 or S5 is refused with
//!   [`ClientError::InvalidSuccessor`] and handled like a withheld one.
//! * C2: one solvency bound per state (`bound_at_state`), written to disk
//!   before the request proof is journaled.
//! * C3: while `exit_lock.json` exists the wallet makes no request proofs,
//!   and only the lock's own mode's exit proofs at the lock's state.
//! * C4: no new request when it could not settle before the exit deadline.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use zkapi_core::v2 as core;
use zkapi_proof::compact::{
    add_blindings, balance_commitment, random_field, random_scalar, rerandomize, server_update,
    verify_signature, RequestProver, RequestWitnessData, WithdrawalProver, WithdrawalWitnessData,
};
use zkapi_types::wire::{
    ApiRequestV2, ClearanceRequest, ClearanceResponseV2, CurvePointWire, ErrorResponse,
    Groth16ProofWire, RecoveryResponseV2, RequestResponseV2,
};
use zkapi_types::{
    canonical_payload_hash, canonical_request_context, canonical_response_hash, Felt252,
    RequestPublicInputsV2, SchnorrSignature, WithdrawalPublicInputsV2, MERKLE_DEPTH,
};

use crate::config::{ClientConfig, ClientProofMode};
use crate::error::ClientError;
use crate::exit_lock::{ExitLock, ExitMode, ReleasedProof, EXIT_LOCK_FILE};
use crate::exit_policy::{
    self, disposition, EarlyExit, ExitDecision, ExitFacts, MutualOutcome, NoteChainStatus,
    Reading, ReleasedRecord, ServerReading,
};
use crate::journal::PendingRequestJournal;
use crate::note_state::NoteState;

pub struct Wallet {
    config: ClientConfig,
    state: Option<NoteState>,
    state_path: PathBuf,
    journal_path: PathBuf,
    exit_lock_path: PathBuf,
    http: reqwest::Client,
}

/// Inputs of [`Wallet::decide_exit`] that come from outside the wallet.
#[derive(Debug, Clone, Default)]
pub struct ExitContext {
    pub now: u64,
    /// The server's settlement deadline for this state's nullifier, if any.
    pub settlement_deadline_reported: Option<u64>,
    /// The charge of a finalized response that passes
    /// [`Wallet::check_unrecoverable_response`] but cannot be installed.
    pub lost_epsilon_charge: Option<u128>,
    pub mutual_outcome: Option<MutualOutcome>,
    pub early_exit: Option<EarlyExit>,
}

impl Wallet {
    pub fn new(config: ClientConfig) -> Result<Self, ClientError> {
        let state_dir = PathBuf::from(&config.state_dir);
        std::fs::create_dir_all(&state_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o700))?;
        }
        let state_path = state_dir.join("note_state.json");
        let journal_path = state_dir.join("pending_journal.json");
        let exit_lock_path = state_dir.join(EXIT_LOCK_FILE);
        let state = state_path
            .exists()
            .then(|| NoteState::load(&state_path))
            .transpose()?;
        let wallet = Self {
            config,
            state,
            state_path,
            journal_path,
            exit_lock_path,
            http: reqwest::Client::new(),
        };
        wallet.drop_installed_journal()?;
        Ok(wallet)
    }

    /// Finish an install a crash interrupted: the successor of the journal's
    /// request is saved (it sits at `next_anchor(N)` with `prev_anchor` the
    /// journal's state), but the journal was not cleared. Such a journal can
    /// never complete and would block every later request.
    fn drop_installed_journal(&self) -> Result<(), ClientError> {
        let (Some(state), Some(journal)) = (
            self.state.as_ref(),
            PendingRequestJournal::read(&self.journal_path)?,
        ) else {
            return Ok(());
        };
        let Some(prev_anchor) = state.prev_anchor else {
            return Ok(());
        };
        if core::nullifier(&state.secret_s, state.note_id, &prev_anchor) == journal.nullifier
            && core::next_anchor(&journal.nullifier) == state.current_anchor
        {
            PendingRequestJournal::clear(&self.journal_path)?;
        }
        Ok(())
    }

    pub fn state(&self) -> Option<&NoteState> {
        self.state.as_ref()
    }

    pub fn has_pending_request(&self) -> bool {
        PendingRequestJournal::read(&self.journal_path)
            .ok()
            .flatten()
            .is_some()
    }

    pub fn get_pending_journal(&self) -> Result<Option<PendingRequestJournal>, ClientError> {
        PendingRequestJournal::read(&self.journal_path)
    }

    /// Return the durable, already-proved request for an idempotent transport
    /// retry. Older journals may not contain the full request.
    pub fn pending_api_request(&self) -> Result<Option<ApiRequestV2>, ClientError> {
        Ok(PendingRequestJournal::read(&self.journal_path)?
            .and_then(|journal| journal.prepared_request))
    }

    /// The exit lock, if an exit was begun at the current state.
    pub fn exit_lock(&self) -> Result<Option<ExitLock>, ClientError> {
        ExitLock::load(&self.exit_lock_path)
    }

    pub fn generate_deposit_params(&self) -> (Felt252, Felt252) {
        loop {
            let secret = random_field();
            if !secret.is_zero() {
                return (secret, core::registration_commitment(&secret));
            }
        }
    }

    pub fn confirm_deposit(
        &mut self,
        secret: Felt252,
        note_id: u32,
        deposit_amount: u128,
        expiry: u64,
    ) -> Result<(), ClientError> {
        if self.state.is_some() {
            return Err(ClientError::NoteAlreadyExists);
        }
        let blinding = random_scalar();
        let commitment = balance_commitment(
            deposit_amount,
            &blinding,
            &core::note_leaf(
                note_id,
                &core::registration_commitment(&secret),
                deposit_amount,
                expiry,
            ),
        );
        let state = NoteState::new_from_deposit(
            self.config.protocol_version,
            self.config.chain_id,
            self.config.contract_address,
            note_id,
            secret,
            deposit_amount,
            expiry,
            blinding.to_hex(),
            commitment.x,
            commitment.y,
        );
        state.save(&self.state_path)?;
        self.state = Some(state);
        Ok(())
    }

    pub async fn request_flow(
        &mut self,
        payload: &str,
        payload_hash: Felt252,
        active_root: Felt252,
        merkle_siblings: Vec<Felt252>,
    ) -> Result<RequestResponseV2, ClientError> {
        let request = self.prepare_request(payload, payload_hash, active_root, merkle_siblings)?;
        let response = self
            .http
            .post(format!(
                "{}/v2/requests",
                self.config.server_url.trim_end_matches('/')
            ))
            .json(&request)
            .send()
            .await
            .map_err(|error| ClientError::ServerError(error.to_string()))?;
        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|error| ClientError::ServerError(error.to_string()))?;
        if !status.is_success() {
            if let Ok(error) = serde_json::from_str::<ErrorResponse>(&body) {
                if error.error_code == "stale_root" {
                    self.clear_pending_request()?;
                    return Err(ClientError::StaleRoot);
                }
                return Err(ClientError::ServerError(format!(
                    "{}: {}",
                    error.error_code, error.error_message
                )));
            }
            return Err(ClientError::ServerError(format!("HTTP {status}: {body}")));
        }
        let response: RequestResponseV2 = serde_json::from_str(&body)
            .map_err(|error| ClientError::InvalidResponse(error.to_string()))?;
        self.complete_pending_response(&response)?;
        Ok(response)
    }

    /// Generate and durably journal one zkAPI request without submitting it.
    /// This is used by multi-network-request flows such as an OpenRouter lease,
    /// whose zkAPI state transition completes only after later settlement.
    ///
    /// Write order: the state with `bound_at_state` and the released record
    /// is saved first, then the journal; only then may the request leave.
    pub fn prepare_request(
        &mut self,
        payload: &str,
        payload_hash: Felt252,
        active_root: Felt252,
        merkle_siblings: Vec<Felt252>,
    ) -> Result<ApiRequestV2, ClientError> {
        if self.has_pending_request() {
            return Err(ClientError::PendingRequest);
        }
        if self.exit_lock()?.is_some() {
            return Err(ClientError::ExitLocked(
                "no request proofs while an exit is in progress".into(),
            ));
        }
        if canonical_payload_hash(payload.as_bytes()) != payload_hash {
            return Err(ClientError::InvalidResponse(
                "payload_hash does not match payload bytes".to_string(),
            ));
        }
        let state = self.state.as_ref().ok_or(ClientError::NoActiveNote)?;
        state.check_consistency()?;
        if state
            .released
            .iter()
            .any(|record| record.disposition == disposition::INVALID_SUCCESSOR)
        {
            return Err(ClientError::InvalidSuccessor(
                "this state's successor was invalid; exit from this state".into(),
            ));
        }
        let solvency_bound = self.config.solvency_bound();
        if solvency_bound == 0 {
            return Err(ClientError::ProofGeneration(
                "the solvency bound must be positive".into(),
            ));
        }
        if state.bound_at_state != 0 && state.bound_at_state != solvency_bound {
            return Err(ClientError::BoundFixedAtState {
                bound: state.bound_at_state,
                requested: solvency_bound,
            });
        }
        if state.current_balance < solvency_bound {
            return Err(ClientError::InsufficientBalance {
                needed: solvency_bound,
                available: state.current_balance,
            });
        }
        let now = now_seconds();
        if exit_policy::note_near_expiry(
            now,
            self.config.settlement_window_seconds,
            exit_policy::must_initiate_by(state.expiry_ts),
        ) {
            return Err(ClientError::NoteNearExpiry);
        }
        let prev_anchor = state.predecessor_anchor()?;

        let siblings = siblings_array(merkle_siblings)?;
        let current_blinding = parse_scalar(&state.balance_blinding)?;
        let expected_current = stored_commitment(state, &current_blinding)?;
        let rerandomization = random_scalar();
        let anonymous = rerandomize(&expected_current, &rerandomization)
            .map_err(|error| ClientError::ProofGeneration(error.to_string()))?;
        let nullifier = state.nullifier();
        let client_request_id = uuid::Uuid::new_v4().to_string();
        let request_context = canonical_request_context(&client_request_id, &payload_hash);
        let public_inputs = RequestPublicInputsV2 {
            protocol_version: state.protocol_version,
            chain_id: state.chain_id,
            contract_address: state.contract_address,
            active_root,
            state_signing_key_x: self.config.state_signing_key.x,
            state_signing_key_y: self.config.state_signing_key.y,
            request_time: now,
            solvency_bound,
            request_nullifier: nullifier,
            authorization_tag: core::authorization_tag(&nullifier, &request_context),
            anonymous_commitment_x: anonymous.x,
            anonymous_commitment_y: anonymous.y,
        };
        let prover = RequestProver::load(self.setup_dir())
            .map_err(|error| ClientError::ProofGeneration(error.to_string()))?;
        let proof = prover
            .prove(
                &public_inputs,
                RequestWitnessData {
                    secret: state.secret_s,
                    request_context,
                    note_id: state.note_id,
                    deposit_amount: state.deposit_amount,
                    expiry: state.expiry_ts,
                    merkle_siblings: siblings,
                    current_balance: state.current_balance,
                    current_blinding,
                    rerandomization,
                    current_anchor: state.current_anchor,
                    prev_anchor,
                    state_signature: state.state_signature,
                },
            )
            .map_err(|error| ClientError::ProofGeneration(error.to_string()))?;

        let request = ApiRequestV2 {
            client_request_id: client_request_id.clone(),
            payload: payload.to_string(),
            payload_hash,
            public_inputs,
            proof,
        };
        let mut bound = state.clone();
        bound.bound_at_state = solvency_bound;
        bound.released.push(ReleasedRecord {
            client_request_id: client_request_id.clone(),
            disposition: disposition::PENDING.into(),
            request_time: now,
            created_at: now,
            reading: None,
        });
        bound.save(&self.state_path)?;
        self.state = Some(bound);
        PendingRequestJournal::write(
            &self.journal_path,
            &PendingRequestJournal {
                exists: true,
                client_request_id,
                nullifier,
                payload_hash,
                user_rerandomization: rerandomization,
                created_at_ms: now.saturating_mul(1_000),
                prepared_request: Some(request.clone()),
            },
        )?;
        Ok(request)
    }

    /// Verify a finalized response for the currently journaled request
    /// (S1–S6), persist the next note state, and clear the journal after the
    /// state is safe on disk.
    ///
    /// A signed successor failing S3, S4 or S5 is recorded at this state as
    /// `invalid_successor` (handled like a withheld successor) and refused;
    /// the journal stays. While an exit proof released at this state may
    /// still land, no successor is installed.
    pub fn complete_pending_response(
        &mut self,
        response: &RequestResponseV2,
    ) -> Result<(), ClientError> {
        let journal =
            PendingRequestJournal::read(&self.journal_path)?.ok_or(ClientError::PendingRequest)?;
        let lock = self.exit_lock()?;
        if lock.as_ref().is_some_and(ExitLock::exit_released) {
            return Err(ClientError::ExitLocked(
                "an exit proof was released at this state; the successor is kept until the exit lock is released".into(),
            ));
        }
        let state = self.state.as_ref().ok_or(ClientError::NoActiveNote)?;
        let next = match verify_successor(&self.config, state, &journal, response) {
            Ok(next) => next,
            Err(ClientError::InvalidSuccessor(detail)) => {
                let mut marked = state.clone();
                for record in marked
                    .released
                    .iter_mut()
                    .filter(|record| record.client_request_id == journal.client_request_id)
                {
                    record.disposition = disposition::INVALID_SUCCESSOR.into();
                }
                marked.save(&self.state_path)?;
                self.state = Some(marked);
                return Err(ClientError::InvalidSuccessor(detail));
            }
            Err(error) => return Err(error),
        };
        next.save(&self.state_path)?;
        self.state = Some(next);
        // E3: a successor installed before any exit proof left moves the lock
        // to the new state.
        if let (Some(mut lock), Some(state)) = (lock, self.state.as_ref()) {
            lock.anchor = state.current_anchor;
            lock.save(&self.exit_lock_path)?;
        }
        PendingRequestJournal::clear(&self.journal_path)?;
        Ok(())
    }

    /// Clear a request that the server explicitly rejected before reserving
    /// its nullifier (for example because the indexer root was stale). The
    /// state keeps its bound (C2): the proof left the wallet.
    pub fn clear_pending_request(&mut self) -> Result<(), ClientError> {
        if let (Some(journal), Some(state)) = (
            PendingRequestJournal::read(&self.journal_path)?,
            self.state.as_ref(),
        ) {
            let mut next = state.clone();
            for record in next
                .released
                .iter_mut()
                .filter(|record| record.client_request_id == journal.client_request_id)
            {
                record.disposition = disposition::DISCARDED_STALE_ROOT.into();
            }
            next.save(&self.state_path)?;
            self.state = Some(next);
        }
        PendingRequestJournal::clear(&self.journal_path)
    }

    /// Ask the server about the journaled request, record its reading for the
    /// exit decision, and install its successor when it has one.
    pub async fn recover(&mut self) -> Result<Option<RequestResponseV2>, ClientError> {
        let Some(journal) = PendingRequestJournal::read(&self.journal_path)? else {
            return Ok(None);
        };
        let response = self
            .http
            .get(format!(
                "{}/v2/requests/{}",
                self.config.server_url.trim_end_matches('/'),
                journal.client_request_id
            ))
            .send()
            .await;
        let response = match response {
            Ok(response) => response,
            Err(error) => {
                self.record_reading(&journal, ServerReading::Unavailable)?;
                return Err(ClientError::ServerError(error.to_string()));
            }
        };
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            self.record_reading(&journal, ServerReading::Unknown)?;
            return Ok(None);
        }
        let recovery: Result<RecoveryResponseV2, ClientError> = match response.error_for_status() {
            Ok(response) => response
                .json()
                .await
                .map_err(|error| ClientError::InvalidResponse(error.to_string())),
            Err(error) => Err(ClientError::ServerError(error.to_string())),
        };
        let recovery = match recovery {
            Ok(recovery) => recovery,
            Err(error) => {
                self.record_reading(&journal, ServerReading::Unavailable)?;
                return Err(error);
            }
        };
        self.record_reading(
            &journal,
            ServerReading::from_nullifier_status(&recovery.nullifier_status),
        )?;
        let Some(response) = recovery.request_response else {
            return Ok(None);
        };
        self.complete_pending_response(&response)?;
        Ok(Some(response))
    }

    fn record_reading(
        &mut self,
        journal: &PendingRequestJournal,
        status: ServerReading,
    ) -> Result<(), ClientError> {
        let Some(state) = self.state.as_ref() else {
            return Ok(());
        };
        let mut next = state.clone();
        let reading = Reading {
            status,
            observed_at: now_seconds(),
        };
        for record in next
            .released
            .iter_mut()
            .filter(|record| record.client_request_id == journal.client_request_id)
        {
            record.reading = Some(reading);
        }
        next.save(&self.state_path)?;
        self.state = Some(next);
        Ok(())
    }

    /// Check a finalized response at the current state that cannot be
    /// installed because its journal (ε) is lost: S1 (it names this state's
    /// nullifier), S2, S6 and S4. Its charge may lower an escape's
    /// concession to `min(charge, bound_at_state)` ([`ExitContext`]).
    pub fn check_unrecoverable_response(
        &self,
        response: &RequestResponseV2,
    ) -> Result<u128, ClientError> {
        let state = self.state.as_ref().ok_or(ClientError::NoActiveNote)?;
        let nullifier = state.nullifier();
        if response.request_nullifier != nullifier {
            return Err(ClientError::VerificationFailed(
                "the response names another nullifier than this state's".into(),
            ));
        }
        check_response_hash(response)?;
        check_successor_signature(&self.config, state, response)?;
        check_derived_anchor(&nullifier, &response.next_anchor)?;
        Ok(response.charge_applied)
    }

    /// E2/E3: what the wallet should do to exit from its newest state, and
    /// with what concession.
    pub fn decide_exit(&self, context: ExitContext) -> Result<ExitDecision, ClientError> {
        let state = self.state.as_ref().ok_or(ClientError::NoActiveNote)?;
        Ok(exit_policy::decide(&ExitFacts {
            now: context.now,
            must_initiate_by: exit_policy::must_initiate_by(state.expiry_ts),
            settlement_window: self.config.settlement_window_seconds,
            unsettled_escape_after: exit_policy::unsettled_escape_after(
                self.config.unsettled_request_escape_after_seconds,
            ),
            bound_at_state: state.bound_at_state,
            records: state.released.clone(),
            settlement_deadline_reported: context.settlement_deadline_reported,
            lost_epsilon_charge: context.lost_epsilon_charge,
            mutual_outcome: context.mutual_outcome,
            early_exit: context.early_exit,
        }))
    }

    /// C3: freeze the wallet for an exit in `mode` at the current state.
    /// The lock is durable before any exit proof exists. A lock may change
    /// mode only while no exit proof was released under it.
    pub fn begin_exit(&self, mode: ExitMode) -> Result<ExitLock, ClientError> {
        let state = self.state.as_ref().ok_or(ClientError::NoActiveNote)?;
        let lock = match self.exit_lock()? {
            Some(lock) if lock.note_id != state.note_id || lock.anchor != state.current_anchor => {
                return Err(ClientError::ExitLocked(
                    "the exit lock belongs to another note state".into(),
                ))
            }
            Some(lock) if lock.mode == mode => return Ok(lock),
            Some(lock) if lock.exit_released() => {
                return Err(ClientError::ExitLocked(format!(
                    "a {:?} exit proof was released at this state",
                    lock.mode
                )))
            }
            Some(mut lock) => {
                lock.mode = mode;
                lock
            }
            None => ExitLock::new(state.note_id, state.current_anchor, mode, now_seconds()),
        };
        lock.save(&self.exit_lock_path)?;
        Ok(lock)
    }

    /// E6: release the exit lock when every released proof is dead (or the
    /// note is closed, or nothing was released and the user cancels).
    /// Returns whether the lock was released.
    pub fn release_exit_lock(
        &self,
        user_cancels: bool,
        note: NoteChainStatus,
        finalized_block_timestamp: Option<u64>,
        now: u64,
    ) -> Result<bool, ClientError> {
        let Some(lock) = self.exit_lock()? else {
            return Ok(true);
        };
        if !exit_policy::lock_releasable(
            &lock.released_exits(),
            user_cancels,
            note,
            finalized_block_timestamp,
            now,
        ) {
            return Ok(false);
        }
        ExitLock::remove(&self.exit_lock_path)?;
        Ok(true)
    }

    /// Mutual close: clearance, then a close proof conceding nothing, valid
    /// for [`exit_policy::EXIT_PROOF_VALIDITY_SECONDS`].
    pub async fn withdrawal_mutual_close(
        &self,
        destination: [u8; 20],
    ) -> Result<(WithdrawalPublicInputsV2, Groth16ProofWire), ClientError> {
        let lock = self.begin_exit(ExitMode::Mutual)?;
        let state = self.state.as_ref().ok_or(ClientError::NoActiveNote)?;
        let nullifier = state.nullifier();
        let clearance = self.request_clearance(&nullifier).await?;
        if clearance.withdrawal_nullifier != nullifier {
            return Err(ClientError::VerificationFailed(
                "clearance nullifier mismatch".into(),
            ));
        }
        let message = core::clearance_message(
            state.protocol_version,
            state.chain_id,
            &state.contract_address,
            &nullifier,
        );
        if !verify_signature(
            &self.config.clearance_signing_key,
            &message,
            &clearance.signature,
        )
        .map_err(|error| ClientError::VerificationFailed(error.to_string()))?
        {
            return Err(ClientError::VerificationFailed(
                "invalid clearance signature".to_string(),
            ));
        }
        self.release_withdrawal(lock, destination, 0, Some(clearance.signature))
    }

    /// Escape conceding `conceded` (at most `bound_at_state`), valid for
    /// [`exit_policy::EXIT_PROOF_VALIDITY_SECONDS`]. Choose `conceded` with
    /// [`Wallet::decide_exit`].
    pub fn withdrawal_escape_hatch(
        &self,
        destination: [u8; 20],
        conceded: u128,
    ) -> Result<(WithdrawalPublicInputsV2, Groth16ProofWire), ClientError> {
        let state = self.state.as_ref().ok_or(ClientError::NoActiveNote)?;
        if conceded > state.bound_at_state {
            return Err(ClientError::ConcededExceedsBound {
                conceded,
                bound: state.bound_at_state,
            });
        }
        let lock = self.begin_exit(ExitMode::Escape)?;
        self.release_withdrawal(lock, destination, conceded, None)
    }

    pub fn archive_note(&mut self) -> Result<(), ClientError> {
        if let Some(state) = &self.state {
            state.archive(&self.state_path)?;
        }
        self.state = None;
        PendingRequestJournal::clear(&self.journal_path)?;
        ExitLock::remove(&self.exit_lock_path)?;
        Ok(())
    }

    /// Prove an exit of the lock's mode and record it in the lock before the
    /// proof leaves the wallet.
    fn release_withdrawal(
        &self,
        mut lock: ExitLock,
        destination: [u8; 20],
        conceded: u128,
        clearance_signature: Option<SchnorrSignature>,
    ) -> Result<(WithdrawalPublicInputsV2, Groth16ProofWire), ClientError> {
        let state = self.state.as_ref().ok_or(ClientError::NoActiveNote)?;
        let valid_until = now_seconds().saturating_add(exit_policy::EXIT_PROOF_VALIDITY_SECONDS);
        let public = withdrawal_statement(
            &self.config,
            state,
            lock.mode,
            destination,
            conceded,
            valid_until,
        )?;
        let prover = WithdrawalProver::load(self.setup_dir())
            .map_err(|error| ClientError::ProofGeneration(error.to_string()))?;
        let proof = prover
            .prove(
                &public,
                WithdrawalWitnessData {
                    secret: state.secret_s,
                    current_balance: state.current_balance,
                    final_blinding: parse_scalar(&state.balance_blinding)?,
                    current_anchor: state.current_anchor,
                    prev_anchor: state.predecessor_anchor()?,
                    state_signature: state.state_signature,
                    clearance_signature,
                },
            )
            .map_err(|error| ClientError::ProofGeneration(error.to_string()))?;
        lock.released.push(ReleasedProof {
            kind: lock.mode.kind(),
            valid_until,
            conceded,
        });
        lock.save(&self.exit_lock_path)?;
        Ok((public, proof))
    }

    async fn request_clearance(
        &self,
        nullifier: &Felt252,
    ) -> Result<ClearanceResponseV2, ClientError> {
        let response = self
            .http
            .post(format!(
                "{}/v2/withdraw/clearance",
                self.config.server_url.trim_end_matches('/')
            ))
            .json(&ClearanceRequest {
                withdrawal_nullifier: *nullifier,
            })
            .send()
            .await
            .map_err(|error| ClientError::ServerError(error.to_string()))?;
        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|error| ClientError::ServerError(error.to_string()))?;
        if !status.is_success() {
            return Err(ClientError::ServerError(format!("HTTP {status}: {body}")));
        }
        serde_json::from_str(&body).map_err(|error| ClientError::InvalidResponse(error.to_string()))
    }

    fn setup_dir(&self) -> &str {
        match &self.config.proof_mode {
            ClientProofMode::Groth16 { setup_dir } => setup_dir,
        }
    }
}

/// The withdrawal statement of an exit in `mode` from `state`: an escape
/// publishes the successor nullifier and its concession, a mutual close
/// neither. No Merkle path or root: the vault compares `registration` and
/// the note fields with the note it stores.
pub fn withdrawal_statement(
    config: &ClientConfig,
    state: &NoteState,
    mode: ExitMode,
    destination: [u8; 20],
    conceded: u128,
    valid_until: u64,
) -> Result<WithdrawalPublicInputsV2, ClientError> {
    state.check_consistency()?;
    state.predecessor_anchor()?;
    if destination == [0u8; 20] {
        return Err(ClientError::ProofGeneration(
            "a withdrawal needs a nonzero destination".into(),
        ));
    }
    let (has_clearance, next_nullifier) = match mode {
        ExitMode::Mutual if conceded != 0 => {
            return Err(ClientError::ProofGeneration(
                "only an escape may concede; a mutual close concedes 0".into(),
            ))
        }
        ExitMode::Mutual => (true, Felt252::ZERO),
        ExitMode::Escape if conceded > state.bound_at_state => {
            return Err(ClientError::ConcededExceedsBound {
                conceded,
                bound: state.bound_at_state,
            })
        }
        ExitMode::Escape => (false, state.successor_nullifier()),
    };
    Ok(WithdrawalPublicInputsV2 {
        protocol_version: state.protocol_version,
        chain_id: state.chain_id,
        contract_address: state.contract_address,
        registration: core::registration_commitment(&state.secret_s),
        state_signing_key_x: config.state_signing_key.x,
        state_signing_key_y: config.state_signing_key.y,
        clearance_signing_key_x: config.clearance_signing_key.x,
        clearance_signing_key_y: config.clearance_signing_key.y,
        note_id: state.note_id,
        deposit_amount: state.deposit_amount,
        expiry_ts: state.expiry_ts,
        // bound_at_state <= current_balance (check_consistency).
        final_balance: state.current_balance - conceded,
        destination,
        withdrawal_nullifier: state.nullifier(),
        has_clearance,
        next_nullifier,
        conceded,
        valid_until,
    })
}

/// S1–S6 for a response to `journal` at `state`; returns the successor to
/// install (`prev_anchor = τ`, `bound_at_state = 0`, no released records).
pub fn verify_successor(
    config: &ClientConfig,
    state: &NoteState,
    journal: &PendingRequestJournal,
    response: &RequestResponseV2,
) -> Result<NoteState, ClientError> {
    state.check_consistency()?;
    let current_blinding = parse_scalar(&state.balance_blinding)?;
    let current = stored_commitment(state, &current_blinding)?;
    // S1
    let nullifier = state.nullifier();
    if response.client_request_id != journal.client_request_id
        || response.request_nullifier != journal.nullifier
    {
        return Err(ClientError::VerificationFailed(
            "response request identity mismatch".to_string(),
        ));
    }
    if journal.nullifier != nullifier
        || journal.prepared_request.as_ref().is_some_and(|request| {
            request.public_inputs.request_nullifier != nullifier
                || request.client_request_id != journal.client_request_id
        })
    {
        return Err(ClientError::VerificationFailed(
            "the journal was not made at this note state".into(),
        ));
    }
    // S2
    check_response_hash(response)?;
    // S6
    check_successor_signature(config, state, response)?;
    // S3
    let journal_bound = journal
        .prepared_request
        .as_ref()
        .map(|request| request.public_inputs.solvency_bound);
    if state.bound_at_state == 0 || journal_bound.is_some_and(|bound| bound != state.bound_at_state)
    {
        return Err(ClientError::InvalidSuccessor(format!(
            "S3: the journal's solvency bound is not this state's bound {}",
            state.bound_at_state
        )));
    }
    if response.charge_applied > state.bound_at_state {
        return Err(ClientError::InvalidSuccessor(format!(
            "S3: charge {} exceeds the state's bound {}",
            response.charge_applied, state.bound_at_state
        )));
    }
    // S4
    check_derived_anchor(&nullifier, &response.next_anchor)?;
    // S5
    let anonymous = rerandomize(&current, &journal.user_rerandomization)
        .map_err(|error| ClientError::VerificationFailed(error.to_string()))?;
    let expected = server_update(
        &anonymous,
        response.charge_applied,
        &response.blind_delta_srv,
    )
    .map_err(|error| ClientError::VerificationFailed(error.to_string()))?;
    if expected != response.next_commitment {
        return Err(ClientError::InvalidSuccessor(
            "S5: the successor commitment is not C + ε·H − charge·G + δ·H".into(),
        ));
    }
    let next_blinding = add_blindings(
        &add_blindings(&current_blinding, &journal.user_rerandomization),
        &response.blind_delta_srv,
    );
    let mut next = state.clone();
    next.prev_anchor = Some(state.current_anchor);
    next.current_balance = next
        .current_balance
        .checked_sub(response.charge_applied)
        .ok_or_else(|| ClientError::InvalidSuccessor("S3: charge exceeds balance".into()))?;
    next.balance_blinding = next_blinding.to_hex();
    next.current_commitment_x = response.next_commitment.x;
    next.current_commitment_y = response.next_commitment.y;
    next.current_anchor = response.next_anchor;
    next.is_genesis = false;
    next.state_signature = Some(response.next_state_signature);
    next.bound_at_state = 0;
    next.released.clear();
    Ok(next)
}

fn check_response_hash(response: &RequestResponseV2) -> Result<(), ClientError> {
    if canonical_response_hash(response.response_payload.as_bytes()) != response.response_hash {
        return Err(ClientError::VerificationFailed(
            "response payload hash mismatch".to_string(),
        ));
    }
    Ok(())
}

fn check_successor_signature(
    config: &ClientConfig,
    state: &NoteState,
    response: &RequestResponseV2,
) -> Result<(), ClientError> {
    let message = core::state_message(
        state.protocol_version,
        state.chain_id,
        &state.contract_address,
        &response.next_commitment.x,
        &response.next_commitment.y,
        &response.next_anchor,
    );
    if !verify_signature(
        &config.state_signing_key,
        &message,
        &response.next_state_signature,
    )
    .map_err(|error| ClientError::VerificationFailed(error.to_string()))?
    {
        return Err(ClientError::VerificationFailed(
            "invalid next-state signature".to_string(),
        ));
    }
    Ok(())
}

/// S4: a successor must sit at `next_anchor(N)`; a random anchor or the
/// genesis anchor (a born-spent successor) is refused.
fn check_derived_anchor(nullifier: &Felt252, next_anchor: &Felt252) -> Result<(), ClientError> {
    if *next_anchor != core::next_anchor(nullifier)
        || next_anchor.is_zero()
        || *next_anchor == core::GENESIS_ANCHOR
    {
        return Err(ClientError::InvalidSuccessor(
            "S4: the successor is not at the derived anchor next_anchor(N)".into(),
        ));
    }
    Ok(())
}

fn stored_commitment(
    state: &NoteState,
    blinding: &Felt252,
) -> Result<CurvePointWire, ClientError> {
    let commitment = balance_commitment(state.current_balance, blinding, &state_note_leaf(state));
    if commitment.x != state.current_commitment_x || commitment.y != state.current_commitment_y {
        return Err(ClientError::VerificationFailed(
            "persisted balance commitment is inconsistent".to_string(),
        ));
    }
    Ok(commitment)
}

fn parse_scalar(value: &str) -> Result<Felt252, ClientError> {
    Felt252::from_hex(value).map_err(ClientError::Serialization)
}

fn siblings_array(values: Vec<Felt252>) -> Result<[Felt252; MERKLE_DEPTH], ClientError> {
    values.try_into().map_err(|values: Vec<Felt252>| {
        ClientError::ProofGeneration(format!(
            "expected {MERKLE_DEPTH} Merkle siblings, got {}",
            values.len()
        ))
    })
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn state_note_leaf(state: &NoteState) -> Felt252 {
    core::note_leaf(
        state.note_id,
        &core::registration_commitment(&state.secret_s),
        state.deposit_amount,
        state.expiry_ts,
    )
}
