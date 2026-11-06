//! SQLite-backed nullifier and transcript store.
//!
//! Stores nullifier reservations and finalized transcripts. Each nullifier
//! progresses through: Reserved -> (settled) -> Finalized (or
//! ClearanceReserved for withdrawals). A settled request whose nullifier an
//! exit consumed on chain is `exit_deferred`; when the deferral window passes
//! without a defeat releasing the nullifier it becomes `exited_unsigned` and
//! its successor is never signed (O7).
//!
//! `request_evidence` is append-only: SQLite triggers refuse every UPDATE and
//! DELETE. It is written in the same transaction as the reservation, so the
//! challenger's defeat/raise evidence never depends on mutable lease rows or
//! on finalization.

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use sha3::{Digest, Keccak256};
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use zkapi_types::wire::{ApiRequestV2, Groth16ProofWire, ProofBackendWire};
use zkapi_types::{Felt252, NullifierStatus, RequestPublicInputsV2, SchnorrSignature};

use crate::error::ServerError;

/// A transcript record stored in the database.
#[derive(Debug, Clone)]
pub struct TranscriptRecord {
    pub nullifier: Felt252,
    pub status: NullifierStatus,
    pub reservation_kind: String,
    pub client_request_id: Option<String>,
    pub payload_hash: Option<Felt252>,
    pub charge_applied: Option<u128>,
    pub response_code: Option<u16>,
    pub response_payload: Option<String>,
    pub response_hash: Option<Felt252>,
    pub next_commitment_x: Option<Felt252>,
    pub next_commitment_y: Option<Felt252>,
    pub next_anchor: Option<Felt252>,
    pub blind_delta_srv: Option<Felt252>,
    pub next_state_sig: Option<SchnorrSignature>,
    pub policy_reason_code: Option<u32>,
    pub policy_evidence_hash: Option<Felt252>,
    pub proof_blob: Option<Vec<u8>>,
    pub request_inputs_json: Option<String>,
    /// Domain-separated digest of the complete canonical v2 API request.
    /// Reserved retries must match this before proof verification is skipped.
    pub api_request_binding: Option<String>,
    pub created_at: u64,
    pub finalized_at: Option<u64>,
    /// Charge persisted when the request settled; the successor is signed at
    /// exactly this charge (settle-then-sign, O7).
    pub settled_charge: Option<u128>,
    pub settled_at: Option<u64>,
    /// First time the settled request's nullifier was seen consumed on chain.
    pub exit_deferred_since: Option<u64>,
    /// Terminal: the consuming exit was never defeated; never signed.
    pub exited_unsigned_at: Option<u64>,
}

impl TranscriptRecord {
    /// Settled, not yet signed and not terminally unsigned.
    pub fn settled_unsigned(&self) -> bool {
        self.status == NullifierStatus::Reserved
            && self.settled_charge.is_some()
            && self.exited_unsigned_at.is_none()
    }
}

/// Immutable request evidence: the exact accepted public inputs and Groth16
/// proof, recorded with the nullifier reservation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestEvidence {
    pub nullifier: Felt252,
    pub client_request_id: String,
    pub request_inputs: RequestPublicInputsV2,
    pub proof: Groth16ProofWire,
    pub created_at: u64,
}

/// Result of recording that a settled request's nullifier is consumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureDeferral {
    Deferred { since: u64 },
    ExitedUnsigned,
}

/// Whether an OA provisioning attempt can safely be cancelled without usage.
/// An absent key hash does not establish non-issuance: the upstream response
/// may have been lost after a key was created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OaProvisioningOutcome {
    NotStarted,
    MayHaveIssued,
    ConfirmedUnissued,
}

impl OaProvisioningOutcome {
    fn from_db(value: &str) -> Self {
        match value {
            "not_started" => Self::NotStarted,
            "confirmed_unissued" => Self::ConfirmedUnissued,
            // Historical rows and unknown values must never enable a refund.
            _ => Self::MayHaveIssued,
        }
    }
}

/// Durable metadata for one prompt-private OpenRouter lease. The plaintext
/// runtime key is deliberately never stored.
#[derive(Debug, Clone)]
pub struct OpenRouterLeaseRecord {
    pub client_request_id: String,
    pub request_nullifier: Felt252,
    pub api_request: ApiRequestV2,
    /// Native OA requests use a deployment/proof-bound upstream namespace.
    /// Optional for decoding historical rows; new OA leases require a bound ID.
    pub oa_client_request_id: Option<String>,
    pub key_hash: Option<String>,
    pub key_source: String,
    pub(crate) oa_provisioning_outcome: OaProvisioningOutcome,
    pub status: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub settle_after: u64,
    pub spending_limit_usd: f64,
    pub usage_usd: Option<f64>,
    pub charge_applied: Option<u128>,
    pub last_error: Option<String>,
}

/// SQLite-backed nullifier store.
pub struct NullifierStore {
    conn: Mutex<Connection>,
}

/// Bind the complete semantically decoded v2 wire request. Serde emits struct
/// fields in declaration order, so equivalent JSON input has one canonical
/// representation while every downstream request field affects the digest.
pub(crate) fn api_request_binding(request: &ApiRequestV2) -> Result<String, ServerError> {
    let request = serde_json::to_vec(request).map_err(|error| {
        ServerError::Internal(format!("failed to serialize v2 request binding: {error}"))
    })?;
    let mut digest = Keccak256::new();
    digest.update(b"zkapi:v2:api-request-binding\0");
    digest.update(request);
    Ok(hex::encode(digest.finalize()))
}

impl NullifierStore {
    /// Open or create a nullifier store at the given path.
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, ServerError> {
        let conn = Connection::open(path)
            .map_err(|e| ServerError::Database(format!("failed to open db: {}", e)))?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS nullifiers (
                nullifier TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                reservation_kind TEXT NOT NULL DEFAULT 'proxy',
                client_request_id TEXT,
                payload_hash TEXT,
                charge_applied INTEGER,
                response_code INTEGER,
                response_payload TEXT,
                response_hash TEXT,
                next_commitment_x TEXT,
                next_commitment_y TEXT,
                next_anchor TEXT,
                blind_delta_srv TEXT,
                next_state_sig_epoch INTEGER,
                next_state_sig_root TEXT,
                next_state_sig_json TEXT,
                policy_reason_code INTEGER,
                policy_evidence_hash TEXT,
                proof_blob BLOB,
                request_inputs_json TEXT,
                api_request_binding TEXT,
                created_at INTEGER NOT NULL,
                finalized_at INTEGER,
                settled_charge INTEGER,
                settled_at INTEGER,
                exit_deferred_since INTEGER,
                exited_unsigned_at INTEGER
            );
            CREATE TABLE IF NOT EXISTS request_evidence (
                nullifier TEXT PRIMARY KEY,
                client_request_id TEXT NOT NULL,
                request_inputs_json TEXT NOT NULL,
                proof_backend TEXT NOT NULL,
                proof TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TRIGGER IF NOT EXISTS request_evidence_no_update
                BEFORE UPDATE ON request_evidence
                BEGIN SELECT RAISE(ABORT, 'request_evidence is append-only'); END;
            CREATE TRIGGER IF NOT EXISTS request_evidence_no_delete
                BEFORE DELETE ON request_evidence
                BEGIN SELECT RAISE(ABORT, 'request_evidence is append-only'); END;
            CREATE TABLE IF NOT EXISTS openrouter_leases (
                client_request_id TEXT PRIMARY KEY,
                request_nullifier TEXT NOT NULL UNIQUE,
                api_request_json TEXT NOT NULL,
                oa_client_request_id TEXT,
                key_hash TEXT UNIQUE,
                key_source TEXT NOT NULL DEFAULT 'openrouter',
                oa_provisioning_outcome TEXT NOT NULL DEFAULT 'may_have_issued',
                status TEXT NOT NULL,
                issued_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                settle_after INTEGER NOT NULL,
                spending_limit_usd REAL NOT NULL,
                usage_usd REAL,
                charge_applied INTEGER,
                last_error TEXT,
                updated_at INTEGER NOT NULL
            );",
        )
        .map_err(|e| ServerError::Database(format!("failed to create table: {}", e)))?;

        let _ = conn.execute(
            "ALTER TABLE nullifiers ADD COLUMN next_state_sig_root TEXT",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE nullifiers ADD COLUMN response_payload TEXT",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE nullifiers ADD COLUMN reservation_kind TEXT NOT NULL DEFAULT 'proxy'",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE nullifiers ADD COLUMN api_request_binding TEXT",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE openrouter_leases ADD COLUMN key_source TEXT NOT NULL DEFAULT 'openrouter'",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE openrouter_leases ADD COLUMN oa_client_request_id TEXT",
            [],
        );
        for column in [
            "settled_charge INTEGER",
            "settled_at INTEGER",
            "exit_deferred_since INTEGER",
            "exited_unsigned_at INTEGER",
        ] {
            let _ = conn.execute(&format!("ALTER TABLE nullifiers ADD COLUMN {column}"), []);
        }
        migrate_oa_provisioning_outcome(&conn)?;
        backfill_openrouter_request_bindings(&conn)?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Create an in-memory store (for testing).
    pub fn in_memory() -> Result<Self, ServerError> {
        Self::new(":memory:")
    }

    /// Acquire the long-lived server writer lock for the actual SQLite file,
    /// not a possibly different config path. In-memory test stores are exempt.
    /// Ordinary store users such as the challenger do not acquire this lock.
    pub(crate) fn acquire_writer_lock(
        &self,
    ) -> Result<Option<crate::writer_lock::ServerWriterLock>, ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        match conn.path().filter(|path| !path.is_empty()) {
            Some(path) => crate::writer_lock::ServerWriterLock::acquire(Path::new(path)).map(Some),
            None => Ok(None),
        }
    }

    /// Reserve a nullifier. Returns Ok(()) if the nullifier was successfully reserved.
    /// Returns Err(Replay) if the nullifier already exists.
    #[cfg(test)]
    pub fn reserve(
        &self,
        nullifier: &Felt252,
        client_request_id: &str,
        payload_hash: &Felt252,
    ) -> Result<(), ServerError> {
        self.reserve_with_kind(
            nullifier,
            client_request_id,
            payload_hash,
            "proxy",
            None,
            None,
        )
    }

    /// Reserve a lease request's nullifier and append its evidence (exact
    /// public inputs and proof) in one transaction.
    pub fn reserve_openrouter_lease(&self, request: &ApiRequestV2) -> Result<(), ServerError> {
        let binding = api_request_binding(request)?;
        let inputs = serde_json::to_string(&request.public_inputs).map_err(|error| {
            ServerError::Internal(format!("failed to serialize request evidence: {error}"))
        })?;
        self.reserve_with_kind(
            &request.public_inputs.request_nullifier,
            &request.client_request_id,
            &request.payload_hash,
            "openrouter_lease",
            Some(&binding),
            Some((&inputs, &request.proof)),
        )
    }

    fn reserve_with_kind(
        &self,
        nullifier: &Felt252,
        client_request_id: &str,
        payload_hash: &Felt252,
        reservation_kind: &str,
        api_request_binding: Option<&str>,
        evidence: Option<(&str, &Groth16ProofWire)>,
    ) -> Result<(), ServerError> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|e| ServerError::Database(format!("lock poisoned: {}", e)))?;
        let now = current_timestamp();
        let null_hex = nullifier.to_hex();
        let conflict = |e: rusqlite::Error| {
            if let rusqlite::Error::SqliteFailure(err, _) = &e {
                if err.code == rusqlite::ErrorCode::ConstraintViolation {
                    return ServerError::Replay;
                }
            }
            ServerError::Database(format!("insert failed: {}", e))
        };
        let transaction = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| ServerError::Database(format!("reservation transaction failed: {e}")))?;
        transaction
            .execute(
                "INSERT INTO nullifiers (
                    nullifier, status, reservation_kind, client_request_id, payload_hash,
                    api_request_binding, created_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    null_hex,
                    status_to_str(NullifierStatus::Reserved),
                    reservation_kind,
                    client_request_id,
                    payload_hash.to_hex(),
                    api_request_binding,
                    now as i64,
                ],
            )
            .map_err(conflict)?;
        if let Some((inputs, proof)) = evidence {
            let backend = serde_json::to_value(proof.backend)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
                .ok_or_else(|| ServerError::Internal("unencodable proof backend".into()))?;
            transaction
                .execute(
                    "INSERT INTO request_evidence (
                        nullifier, client_request_id, request_inputs_json, proof_backend,
                        proof, created_at
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        null_hex,
                        client_request_id,
                        inputs,
                        backend,
                        proof.proof,
                        now as i64
                    ],
                )
                .map_err(conflict)?;
        }
        transaction
            .commit()
            .map_err(|e| ServerError::Database(format!("reservation commit failed: {e}")))?;
        Ok(())
    }

    /// The immutable evidence recorded with a request's reservation.
    pub fn request_evidence(&self, nullifier: &Felt252) -> Option<RequestEvidence> {
        let conn = self.conn.lock().ok()?;
        conn.query_row(
            "SELECT nullifier, client_request_id, request_inputs_json, proof_backend, proof,
                    created_at
             FROM request_evidence WHERE nullifier = ?1",
            params![nullifier.to_hex()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .optional()
        .ok()
        .flatten()
        .and_then(
            |(null_hex, client_request_id, inputs, backend, proof, created_at)| {
                let request_inputs: RequestPublicInputsV2 = serde_json::from_str(&inputs).ok()?;
                let backend: ProofBackendWire =
                    serde_json::from_value(serde_json::Value::String(backend)).ok()?;
                let nullifier = Felt252::from_hex(&null_hex).ok()?;
                (request_inputs.request_nullifier == nullifier).then_some(RequestEvidence {
                    nullifier,
                    client_request_id,
                    request_inputs,
                    proof: Groth16ProofWire { backend, proof },
                    created_at: created_at as u64,
                })
            },
        )
    }

    /// Persist a request's settled charge and provider response once. A
    /// settled charge is final: a later settlement attempt returns the stored
    /// record unchanged.
    pub fn record_settlement(
        &self,
        nullifier: &Felt252,
        charge: u128,
        response_code: u16,
        response_payload: &str,
    ) -> Result<TranscriptRecord, ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ServerError::Database(format!("lock poisoned: {}", e)))?;
        conn.execute(
            "UPDATE nullifiers SET settled_charge = ?1, settled_at = ?2, response_code = ?3,
                response_payload = ?4
             WHERE nullifier = ?5 AND status = ?6 AND settled_charge IS NULL",
            params![
                i64::try_from(charge)
                    .map_err(|_| ServerError::Internal("settled charge exceeds i64".into()))?,
                current_timestamp() as i64,
                response_code as i32,
                response_payload,
                nullifier.to_hex(),
                status_to_str(NullifierStatus::Reserved),
            ],
        )
        .map_err(|e| ServerError::Database(format!("settlement failed: {e}")))?;
        conn.query_row(
            "SELECT * FROM nullifiers WHERE nullifier = ?1",
            params![nullifier.to_hex()],
            row_to_record,
        )
        .optional()
        .map_err(|e| ServerError::Database(format!("settlement read failed: {e}")))?
        .filter(|record| record.settled_charge.is_some())
        .ok_or_else(|| ServerError::Internal("request nullifier is not reserved".into()))
    }

    /// Record that a settled, unsigned request's nullifier is consumed on
    /// chain. The first observation starts the deferral; once `window`
    /// seconds have passed the request is terminally `exited_unsigned`.
    pub fn defer_signature(
        &self,
        nullifier: &Felt252,
        now: u64,
        window: u64,
    ) -> Result<SignatureDeferral, ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ServerError::Database(format!("lock poisoned: {}", e)))?;
        conn.execute(
            "UPDATE nullifiers SET exit_deferred_since = ?1
             WHERE nullifier = ?2 AND status = ?3 AND settled_charge IS NOT NULL
               AND exit_deferred_since IS NULL",
            params![
                now as i64,
                nullifier.to_hex(),
                status_to_str(NullifierStatus::Reserved)
            ],
        )
        .map_err(|e| ServerError::Database(format!("deferral failed: {e}")))?;
        let (since, ended): (Option<i64>, Option<i64>) = conn
            .query_row(
                "SELECT exit_deferred_since, exited_unsigned_at FROM nullifiers
                 WHERE nullifier = ?1 AND status = ?2 AND settled_charge IS NOT NULL",
                params![nullifier.to_hex(), status_to_str(NullifierStatus::Reserved)],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|e| ServerError::Database(format!("deferral read failed: {e}")))?
            .ok_or_else(|| ServerError::Internal("request is not settled and unsigned".into()))?;
        if ended.is_some() {
            return Ok(SignatureDeferral::ExitedUnsigned);
        }
        let since = since.unwrap_or(now as i64) as u64;
        if now >= since.saturating_add(window) {
            conn.execute(
                "UPDATE nullifiers SET exited_unsigned_at = ?1
                 WHERE nullifier = ?2 AND exited_unsigned_at IS NULL",
                params![now as i64, nullifier.to_hex()],
            )
            .map_err(|e| ServerError::Database(format!("exit marking failed: {e}")))?;
            return Ok(SignatureDeferral::ExitedUnsigned);
        }
        Ok(SignatureDeferral::Deferred { since })
    }

    /// Settled requests whose successor is neither signed nor terminally
    /// unsigned, oldest first: the signing sweep's work list.
    pub fn settled_unsigned_entries(&self) -> Vec<TranscriptRecord> {
        let Ok(conn) = self.conn.lock() else {
            return Vec::new();
        };
        let Ok(mut statement) = conn.prepare(
            "SELECT * FROM nullifiers WHERE status = ?1 AND settled_charge IS NOT NULL
               AND exited_unsigned_at IS NULL ORDER BY settled_at ASC",
        ) else {
            return Vec::new();
        };
        let Ok(rows) = statement.query_map(
            params![status_to_str(NullifierStatus::Reserved)],
            row_to_record,
        ) else {
            return Vec::new();
        };
        rows.filter_map(Result::ok).collect()
    }

    /// Record the signed successor of a settled request. The transcript's
    /// charge must equal the persisted settled charge, and a terminally
    /// unsigned request can never be finalized.
    pub fn finalize(
        &self,
        nullifier: &Felt252,
        transcript: &TranscriptRecord,
    ) -> Result<(), ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ServerError::Database(format!("lock poisoned: {}", e)))?;
        let now = current_timestamp();
        let null_hex = nullifier.to_hex();

        let sig_json = transcript
            .next_state_sig
            .as_ref()
            .map(|sig| serde_json::to_string(sig).unwrap_or_default());

        let rows = conn
            .execute(
                "UPDATE nullifiers SET
                    status = ?1,
                    charge_applied = ?2,
                    response_code = ?3,
                    response_payload = ?4,
                    response_hash = ?5,
                    next_commitment_x = ?6,
                    next_commitment_y = ?7,
                    next_anchor = ?8,
                    blind_delta_srv = ?9,
                    next_state_sig_epoch = ?10,
                    next_state_sig_root = ?11,
                    next_state_sig_json = ?12,
                    policy_reason_code = ?13,
                    policy_evidence_hash = ?14,
                    proof_blob = ?15,
                    request_inputs_json = ?16,
                    finalized_at = ?17
                 WHERE nullifier = ?18 AND status = ?19 AND settled_charge = ?2
                   AND exited_unsigned_at IS NULL",
                params![
                    status_to_str(NullifierStatus::Finalized),
                    transcript.charge_applied.map(|c| c as i64),
                    transcript.response_code.map(|c| c as i32),
                    transcript.response_payload.as_deref(),
                    transcript.response_hash.map(|h| h.to_hex()),
                    transcript.next_commitment_x.map(|c| c.to_hex()),
                    transcript.next_commitment_y.map(|c| c.to_hex()),
                    transcript.next_anchor.map(|a| a.to_hex()),
                    transcript.blind_delta_srv.map(|b| b.to_hex()),
                    Option::<i32>::None,
                    Option::<String>::None,
                    sig_json,
                    transcript.policy_reason_code.map(|c| c as i32),
                    transcript.policy_evidence_hash.map(|h| h.to_hex()),
                    transcript.proof_blob.as_deref(),
                    transcript.request_inputs_json.as_deref(),
                    now as i64,
                    null_hex,
                    status_to_str(NullifierStatus::Reserved),
                ],
            )
            .map_err(|e| ServerError::Database(format!("finalize failed: {}", e)))?;

        if rows == 0 {
            return Err(ServerError::Internal(
                "nullifier is not settled at this charge, not reserved, or exited unsigned"
                    .to_string(),
            ));
        }

        Ok(())
    }

    /// Look up a transcript record by nullifier.
    pub fn lookup_by_nullifier(&self, nullifier: &Felt252) -> Option<TranscriptRecord> {
        let conn = self.conn.lock().ok()?;
        let null_hex = nullifier.to_hex();

        conn.query_row(
            "SELECT * FROM nullifiers WHERE nullifier = ?1",
            params![null_hex],
            row_to_record,
        )
        .optional()
        .ok()
        .flatten()
    }

    /// Look up a transcript record by client request ID.
    pub fn lookup_by_client_id(&self, client_request_id: &str) -> Option<TranscriptRecord> {
        let conn = self.conn.lock().ok()?;

        conn.query_row(
            "SELECT * FROM nullifiers WHERE client_request_id = ?1",
            params![client_request_id],
            row_to_record,
        )
        .optional()
        .ok()
        .flatten()
    }

    /// Reserve a nullifier for clearance (withdrawal signing).
    pub fn reserve_clearance(&self, nullifier: &Felt252) -> Result<(), ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ServerError::Database(format!("lock poisoned: {}", e)))?;
        let now = current_timestamp();
        let null_hex = nullifier.to_hex();

        conn.execute(
            "INSERT INTO nullifiers (nullifier, status, created_at)
             VALUES (?1, ?2, ?3)",
            params![
                null_hex,
                status_to_str(NullifierStatus::ClearanceReserved),
                now as i64,
            ],
        )
        .map_err(|e| {
            if let rusqlite::Error::SqliteFailure(ref err, _) = e {
                if err.code == rusqlite::ErrorCode::ConstraintViolation {
                    return ServerError::NullifierUsed;
                }
            }
            ServerError::Database(format!("clearance reserve failed: {}", e))
        })?;

        Ok(())
    }

    /// Get all reserved (not yet finalized) entries, for crash recovery.
    pub fn get_reserved_entries(&self) -> Vec<TranscriptRecord> {
        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };

        let mut stmt = match conn.prepare("SELECT * FROM nullifiers WHERE status = ?1") {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        let rows = match stmt.query_map(
            params![status_to_str(NullifierStatus::Reserved)],
            row_to_record,
        ) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };

        rows.filter_map(|r| r.ok()).collect()
    }

    /// Get all nullifiers (for challenge watcher).
    pub fn get_all_nullifiers(&self) -> Vec<TranscriptRecord> {
        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };

        let mut stmt = match conn.prepare("SELECT * FROM nullifiers") {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        let rows = match stmt.query_map([], row_to_record) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };

        rows.filter_map(|r| r.ok()).collect()
    }

    /// Persist a lease before contacting OpenRouter, closing the normal crash
    /// window between nullifier reservation and external key provisioning.
    pub fn create_openrouter_lease(
        &self,
        request: &ApiRequestV2,
        key_source: &str,
        issued_at: u64,
        expires_at: u64,
        settle_after: u64,
        spending_limit_usd: f64,
    ) -> Result<(), ServerError> {
        self.create_openrouter_lease_with_oa_id(
            request,
            key_source,
            issued_at,
            expires_at,
            settle_after,
            spending_limit_usd,
            None,
        )
    }

    // Extends the legacy constructor without changing existing callers.
    #[allow(clippy::too_many_arguments)]
    pub fn create_openrouter_lease_with_oa_id(
        &self,
        request: &ApiRequestV2,
        key_source: &str,
        issued_at: u64,
        expires_at: u64,
        settle_after: u64,
        spending_limit_usd: f64,
        oa_client_request_id: Option<&str>,
    ) -> Result<(), ServerError> {
        let request_json = serde_json::to_string(request).map_err(|error| {
            ServerError::Database(format!("lease serialization failed: {error}"))
        })?;
        let conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        conn.execute(
            "INSERT INTO openrouter_leases (
                client_request_id, request_nullifier, api_request_json, key_source, status,
                issued_at, expires_at, settle_after, spending_limit_usd, updated_at, oa_client_request_id,
                oa_provisioning_outcome
             ) VALUES (?1, ?2, ?3, ?4, 'provisioning', ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                request.client_request_id,
                request.public_inputs.request_nullifier.to_hex(),
                request_json,
                key_source,
                issued_at as i64,
                expires_at as i64,
                settle_after as i64,
                spending_limit_usd,
                current_timestamp() as i64,
                oa_client_request_id,
                if key_source == "oa_org" { "not_started" } else { "may_have_issued" },
            ],
        )
        .map_err(|error| ServerError::Database(format!("lease insert failed: {error}")))?;
        Ok(())
    }

    /// Durably fence upstream I/O before sending an OA issuance request. Only
    /// the first attempt may establish confirmed non-issuance from a definitive
    /// rejection; a retry cannot erase an earlier ambiguous result. The caller
    /// must hold its issuance lock through the upstream call and classification.
    pub(crate) fn begin_oa_issuance(&self, client_request_id: &str) -> Result<bool, ServerError> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        let transaction = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| {
                ServerError::Database(format!("OA issuance transaction failed: {error}"))
            })?;
        let prior = transaction
            .query_row(
                "SELECT oa_provisioning_outcome FROM openrouter_leases
                 WHERE client_request_id = ?1 AND key_source = 'oa_org'
                   AND status = 'provisioning' AND key_hash IS NULL",
                params![client_request_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| {
                ServerError::Database(format!("OA issuance state read failed: {error}"))
            })?
            .ok_or_else(|| ServerError::Internal("lease cannot begin OA issuance".to_string()))?;
        let outcome = OaProvisioningOutcome::from_db(&prior);
        if outcome == OaProvisioningOutcome::ConfirmedUnissued {
            return Err(ServerError::Internal(
                "confirmed unissued lease cannot resume issuance".to_string(),
            ));
        }
        let rows = transaction
            .execute(
                "UPDATE openrouter_leases SET oa_provisioning_outcome = 'may_have_issued', updated_at = ?1
                 WHERE client_request_id = ?2 AND key_source = 'oa_org'
                   AND status = 'provisioning' AND key_hash IS NULL AND oa_provisioning_outcome = ?3",
                params![current_timestamp() as i64, client_request_id, prior],
            )
            .map_err(|error| ServerError::Database(format!("OA issuance fence failed: {error}")))?;
        if rows != 1 {
            return Err(ServerError::Internal(
                "OA issuance state changed".to_string(),
            ));
        }
        transaction.commit().map_err(|error| {
            ServerError::Database(format!("OA issuance commit failed: {error}"))
        })?;
        Ok(outcome == OaProvisioningOutcome::NotStarted)
    }

    /// Mark a first attempt's definitive pre-issuance rejection for zero-charge
    /// recovery. This must never be called for an ambiguous or retried attempt.
    pub(crate) fn confirm_oa_unissued(&self, client_request_id: &str) -> Result<(), ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        let now = current_timestamp() as i64;
        let rows = conn
            .execute(
                "UPDATE openrouter_leases SET oa_provisioning_outcome = 'confirmed_unissued',
                    settle_after = ?1, updated_at = ?1
                 WHERE client_request_id = ?2 AND key_source = 'oa_org'
                   AND status = 'provisioning' AND key_hash IS NULL
                   AND oa_provisioning_outcome = 'may_have_issued'",
                params![now, client_request_id],
            )
            .map_err(|error| {
                ServerError::Database(format!("OA non-issuance update failed: {error}"))
            })?;
        if rows != 1 {
            return Err(ServerError::Internal(
                "OA issuance state changed".to_string(),
            ));
        }
        Ok(())
    }

    pub fn update_openrouter_lease_timing(
        &self,
        client_request_id: &str,
        expires_at: u64,
        settle_after: u64,
    ) -> Result<(), ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        let rows = conn
            .execute(
                "UPDATE openrouter_leases
                 SET expires_at = ?1, settle_after = ?2, updated_at = ?3
                 WHERE client_request_id = ?4 AND status = 'provisioning'",
                params![
                    expires_at as i64,
                    settle_after as i64,
                    current_timestamp() as i64,
                    client_request_id,
                ],
            )
            .map_err(|error| {
                ServerError::Database(format!("lease timing update failed: {error}"))
            })?;
        if rows != 1 {
            return Err(ServerError::Internal(
                "lease was not in provisioning state".to_string(),
            ));
        }
        Ok(())
    }

    pub fn activate_openrouter_lease(
        &self,
        client_request_id: &str,
        key_hash: &str,
    ) -> Result<(), ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        let rows = conn
            .execute(
                "UPDATE openrouter_leases
                 SET status = 'active', key_hash = ?1, updated_at = ?2
                 WHERE client_request_id = ?3 AND status = 'provisioning'",
                params![key_hash, current_timestamp() as i64, client_request_id],
            )
            .map_err(|error| ServerError::Database(format!("lease activation failed: {error}")))?;
        if rows != 1 {
            return Err(ServerError::Internal(
                "lease was not in provisioning state".to_string(),
            ));
        }
        Ok(())
    }

    /// Recover an existing issuer binding atomically. No plaintext key is
    /// stored, and a definitive non-issuance outcome can never become issued.
    pub(crate) fn reconcile_oa_lease(
        &self,
        client_request_id: &str,
        key_hash: &str,
        expires_at: u64,
        settle_after: u64,
    ) -> Result<(), ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        let rows = conn
            .execute(
                "UPDATE openrouter_leases SET
                    status = 'active', key_hash = ?1, expires_at = ?2,
                    settle_after = ?3, last_error = NULL, updated_at = ?4
                 WHERE client_request_id = ?5 AND key_source = 'oa_org'
                    AND status = 'provisioning' AND key_hash IS NULL
                    AND oa_provisioning_outcome = 'may_have_issued'",
                params![
                    key_hash,
                    expires_at as i64,
                    settle_after as i64,
                    current_timestamp() as i64,
                    client_request_id
                ],
            )
            .map_err(|error| {
                ServerError::Database(format!("OA reconciliation update failed: {error}"))
            })?;
        if rows != 1 {
            return Err(ServerError::Internal(
                "OA reconciliation state changed".into(),
            ));
        }
        Ok(())
    }

    pub fn remove_failed_openrouter_lease(
        &self,
        client_request_id: &str,
    ) -> Result<(), ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        conn.execute(
            "DELETE FROM openrouter_leases
             WHERE client_request_id = ?1 AND status = 'provisioning' AND key_hash IS NULL",
            params![client_request_id],
        )
        .map_err(|error| ServerError::Database(format!("lease cleanup failed: {error}")))?;
        Ok(())
    }

    pub fn lookup_openrouter_lease(
        &self,
        client_request_id: &str,
    ) -> Option<OpenRouterLeaseRecord> {
        let conn = self.conn.lock().ok()?;
        conn.query_row(
            "SELECT * FROM openrouter_leases WHERE client_request_id = ?1",
            params![client_request_id],
            row_to_openrouter_lease,
        )
        .optional()
        .ok()
        .flatten()
    }

    pub fn due_openrouter_leases(&self, now: u64) -> Vec<OpenRouterLeaseRecord> {
        let conn = match self.conn.lock() {
            Ok(conn) => conn,
            Err(_) => return Vec::new(),
        };
        let mut statement = match conn.prepare(
            "SELECT * FROM openrouter_leases
             WHERE (status IN ('active', 'retiring', 'disabled', 'revoking') AND settle_after <= ?1)
                OR (key_source = 'oa_org' AND status = 'provisioning' AND key_hash IS NULL
                    AND (oa_provisioning_outcome = 'confirmed_unissued'
                         OR (oa_provisioning_outcome IN ('not_started', 'may_have_issued') AND settle_after <= ?1)))
             ORDER BY settle_after ASC",
        ) {
            Ok(statement) => statement,
            Err(_) => return Vec::new(),
        };
        let rows = match statement.query_map(params![now as i64], row_to_openrouter_lease) {
            Ok(rows) => rows,
            Err(_) => return Vec::new(),
        };
        rows.filter_map(Result::ok).collect()
    }

    pub fn record_openrouter_lease_error(
        &self,
        client_request_id: &str,
        error: &str,
    ) -> Result<(), ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|cause| ServerError::Database(format!("lock poisoned: {cause}")))?;
        conn.execute(
            "UPDATE openrouter_leases SET last_error = ?1, updated_at = ?2
             WHERE client_request_id = ?3 AND status IN ('provisioning', 'active', 'retiring', 'disabled', 'revoking')",
            params![error, current_timestamp() as i64, client_request_id],
        )
        .map_err(|cause| ServerError::Database(format!("lease error update failed: {cause}")))?;
        Ok(())
    }

    /// Persist the direct-key retirement state before each external side
    /// effect, so revocation and settlement resume after failures or restarts.
    pub fn advance_openrouter_retirement(
        &self,
        client_request_id: &str,
        from: &str,
        to: &str,
        settle_after: u64,
        usage_usd: Option<f64>,
    ) -> Result<(), ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        let rows = conn
            .execute(
                "UPDATE openrouter_leases SET status = ?1, settle_after = ?2,
                usage_usd = COALESCE(?3, usage_usd), last_error = NULL, updated_at = ?4
             WHERE client_request_id = ?5 AND key_source = 'openrouter' AND status = ?6",
                params![
                    to,
                    settle_after as i64,
                    usage_usd,
                    current_timestamp() as i64,
                    client_request_id,
                    from
                ],
            )
            .map_err(|error| {
                ServerError::Database(format!("lease retirement update failed: {error}"))
            })?;
        if rows != 1 {
            return Err(ServerError::Internal(
                "lease retirement state changed".to_string(),
            ));
        }
        Ok(())
    }

    pub fn finalize_openrouter_lease(
        &self,
        client_request_id: &str,
        usage_usd: f64,
        charge_applied: u128,
    ) -> Result<(), ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        conn.execute(
            "UPDATE openrouter_leases SET
                status = 'finalized', usage_usd = ?1, charge_applied = ?2,
                last_error = NULL, updated_at = ?3
             WHERE client_request_id = ?4",
            params![
                usage_usd,
                charge_applied as i64,
                current_timestamp() as i64,
                client_request_id,
            ],
        )
        .map_err(|error| ServerError::Database(format!("lease finalize failed: {error}")))?;
        Ok(())
    }
}

fn migrate_oa_provisioning_outcome(conn: &Connection) -> Result<(), ServerError> {
    let columns = conn
        .prepare("PRAGMA table_info(openrouter_leases)")
        .and_then(|mut statement| {
            statement
                .query_map([], |row| row.get::<_, String>(1))?
                .collect::<Result<Vec<_>, _>>()
        })
        .map_err(|error| {
            ServerError::Database(format!("OA outcome migration read failed: {error}"))
        })?;
    if !columns.iter().any(|name| name == "oa_provisioning_outcome") {
        conn.execute(
            "ALTER TABLE openrouter_leases ADD COLUMN oa_provisioning_outcome TEXT NOT NULL DEFAULT 'may_have_issued'",
            [],
        )
        .map_err(|error| ServerError::Database(format!("OA outcome migration failed: {error}")))?;
    }
    Ok(())
}

/// Older lease rows already contain the complete original request. Use that
/// durable copy to migrate their nullifier reservation safely; proxy
/// reservations have no equivalent source and intentionally remain unbound so
/// retries fail closed.
fn backfill_openrouter_request_bindings(conn: &Connection) -> Result<(), ServerError> {
    let rows = {
        let mut statement = conn
            .prepare(
                "SELECT client_request_id, request_nullifier, api_request_json
                 FROM openrouter_leases",
            )
            .map_err(|error| {
                ServerError::Database(format!("lease binding migration query failed: {error}"))
            })?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(|error| {
                ServerError::Database(format!("lease binding migration read failed: {error}"))
            })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(|error| {
            ServerError::Database(format!("lease binding migration row failed: {error}"))
        })?
    };

    for (client_request_id, request_nullifier, request_json) in rows {
        let Ok(request) = serde_json::from_str::<ApiRequestV2>(&request_json) else {
            // A malformed durable lease cannot be resumed safely. Leave the
            // reservation unbound so validate_and_reserve rejects it.
            continue;
        };
        if request.client_request_id != client_request_id
            || request.public_inputs.request_nullifier.to_hex() != request_nullifier
        {
            continue;
        }
        let binding = api_request_binding(&request)?;
        conn.execute(
            "UPDATE nullifiers SET api_request_binding = ?1
             WHERE nullifier = ?2
               AND client_request_id = ?3
               AND payload_hash = ?4
               AND reservation_kind = 'openrouter_lease'
               AND api_request_binding IS NULL",
            params![
                binding,
                request_nullifier,
                client_request_id,
                request.payload_hash.to_hex(),
            ],
        )
        .map_err(|error| {
            ServerError::Database(format!("lease binding migration update failed: {error}"))
        })?;
    }
    Ok(())
}

/// Convert a NullifierStatus to its string representation for storage.
fn status_to_str(status: NullifierStatus) -> &'static str {
    match status {
        NullifierStatus::Reserved => "Reserved",
        NullifierStatus::Finalized => "Finalized",
        NullifierStatus::ClearanceReserved => "ClearanceReserved",
    }
}

/// Parse a status string from the database.
fn str_to_status(s: &str) -> NullifierStatus {
    match s {
        "Reserved" => NullifierStatus::Reserved,
        "Finalized" => NullifierStatus::Finalized,
        "ClearanceReserved" => NullifierStatus::ClearanceReserved,
        _ => NullifierStatus::Reserved, // fallback
    }
}

/// Parse an optional hex string into a Felt252.
fn parse_opt_felt(s: Option<String>) -> Option<Felt252> {
    s.and_then(|h| Felt252::from_hex(&h).ok())
}

/// Convert a database row into a TranscriptRecord.
fn row_to_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<TranscriptRecord> {
    let nullifier_hex: String = row.get("nullifier")?;
    let status_str: String = row.get("status")?;
    let reservation_kind: String = row.get("reservation_kind")?;
    let client_request_id: Option<String> = row.get("client_request_id")?;
    let payload_hash: Option<String> = row.get("payload_hash")?;
    let charge_applied: Option<i64> = row.get("charge_applied")?;
    let response_code: Option<i32> = row.get("response_code")?;
    let response_payload: Option<String> = row.get("response_payload")?;
    let response_hash: Option<String> = row.get("response_hash")?;
    let next_commitment_x: Option<String> = row.get("next_commitment_x")?;
    let next_commitment_y: Option<String> = row.get("next_commitment_y")?;
    let next_anchor: Option<String> = row.get("next_anchor")?;
    let blind_delta_srv: Option<String> = row.get("blind_delta_srv")?;
    let next_state_sig_json: Option<String> = row.get("next_state_sig_json")?;
    let policy_reason_code: Option<i32> = row.get("policy_reason_code")?;
    let policy_evidence_hash: Option<String> = row.get("policy_evidence_hash")?;
    let proof_blob: Option<Vec<u8>> = row.get("proof_blob")?;
    let request_inputs_json: Option<String> = row.get("request_inputs_json")?;
    let api_request_binding: Option<String> = row.get("api_request_binding")?;
    let created_at: i64 = row.get("created_at")?;
    let finalized_at: Option<i64> = row.get("finalized_at")?;

    let next_state_sig =
        next_state_sig_json.and_then(|json| serde_json::from_str::<SchnorrSignature>(&json).ok());

    Ok(TranscriptRecord {
        nullifier: Felt252::from_hex(&nullifier_hex).unwrap_or(Felt252::ZERO),
        status: str_to_status(&status_str),
        reservation_kind,
        client_request_id,
        payload_hash: parse_opt_felt(payload_hash),
        charge_applied: charge_applied.map(|c| c as u128),
        response_code: response_code.map(|c| c as u16),
        response_payload,
        response_hash: parse_opt_felt(response_hash),
        next_commitment_x: parse_opt_felt(next_commitment_x),
        next_commitment_y: parse_opt_felt(next_commitment_y),
        next_anchor: parse_opt_felt(next_anchor),
        blind_delta_srv: parse_opt_felt(blind_delta_srv),
        next_state_sig,
        policy_reason_code: policy_reason_code.map(|c| c as u32),
        policy_evidence_hash: parse_opt_felt(policy_evidence_hash),
        proof_blob,
        request_inputs_json,
        api_request_binding,
        created_at: created_at as u64,
        finalized_at: finalized_at.map(|t| t as u64),
        settled_charge: row
            .get::<_, Option<i64>>("settled_charge")?
            .map(|c| c as u128),
        settled_at: row.get::<_, Option<i64>>("settled_at")?.map(|t| t as u64),
        exit_deferred_since: row
            .get::<_, Option<i64>>("exit_deferred_since")?
            .map(|t| t as u64),
        exited_unsigned_at: row
            .get::<_, Option<i64>>("exited_unsigned_at")?
            .map(|t| t as u64),
    })
}

fn row_to_openrouter_lease(row: &rusqlite::Row<'_>) -> rusqlite::Result<OpenRouterLeaseRecord> {
    let request_json: String = row.get("api_request_json")?;
    let api_request = serde_json::from_str(&request_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            request_json.len(),
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })?;
    let nullifier: String = row.get("request_nullifier")?;
    Ok(OpenRouterLeaseRecord {
        client_request_id: row.get("client_request_id")?,
        request_nullifier: Felt252::from_hex(&nullifier).unwrap_or(Felt252::ZERO),
        api_request,
        oa_client_request_id: row.get("oa_client_request_id")?,
        key_hash: row.get("key_hash")?,
        key_source: row.get("key_source")?,
        oa_provisioning_outcome: OaProvisioningOutcome::from_db(
            &row.get::<_, String>("oa_provisioning_outcome")?,
        ),
        status: row.get("status")?,
        issued_at: row.get::<_, i64>("issued_at")? as u64,
        expires_at: row.get::<_, i64>("expires_at")? as u64,
        settle_after: row.get::<_, i64>("settle_after")? as u64,
        spending_limit_usd: row.get("spending_limit_usd")?,
        usage_usd: row.get("usage_usd")?,
        charge_applied: row
            .get::<_, Option<i64>>("charge_applied")?
            .map(|value| value as u128),
        last_error: row.get("last_error")?,
    })
}

/// Get the current UNIX timestamp in seconds.
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lease_request(client_request_id: &str, nullifier: u64) -> ApiRequestV2 {
        use zkapi_types::wire::{Groth16ProofWire, ProofBackendWire};
        use zkapi_types::RequestPublicInputsV2;

        ApiRequestV2 {
            client_request_id: client_request_id.to_string(),
            payload: "{\"mode\":\"openrouter_ephemeral_lease\",\"version\":1}".to_string(),
            payload_hash: Felt252::from_u64(88),
            public_inputs: RequestPublicInputsV2 {
                protocol_version: 2,
                chain_id: 1,
                contract_address: Felt252::from_u64(2),
                active_root: Felt252::from_u64(3),
                state_signing_key_x: Felt252::from_u64(4),
                state_signing_key_y: Felt252::from_u64(5),
                request_time: 6,
                solvency_bound: 1_000,
                request_nullifier: Felt252::from_u64(nullifier),
                authorization_tag: Felt252::from_u64(7),
                anonymous_commitment_x: Felt252::from_u64(8),
                anonymous_commitment_y: Felt252::from_u64(9),
            },
            proof: Groth16ProofWire {
                backend: ProofBackendWire::Groth16Bn254,
                proof: "public-proof".to_string(),
            },
        }
    }

    fn create_oa_lease(store: &NullifierStore, id: &str, nullifier: u64) {
        store
            .create_openrouter_lease_with_oa_id(
                &lease_request(id, nullifier),
                "oa_org",
                10,
                20,
                21,
                6.0,
                Some(&format!("bound-{id}")),
            )
            .unwrap();
    }

    #[test]
    fn oa_issuance_fence_preserves_ambiguity_across_retries() {
        let store = NullifierStore::in_memory().unwrap();
        create_oa_lease(&store, "ambiguous", 1);
        assert_eq!(
            store
                .lookup_openrouter_lease("ambiguous")
                .unwrap()
                .oa_provisioning_outcome,
            OaProvisioningOutcome::NotStarted
        );
        assert!(store.due_openrouter_leases(20).is_empty());
        assert_eq!(store.due_openrouter_leases(21).len(), 1);
        assert!(store.confirm_oa_unissued("ambiguous").is_err());
        assert!(store.begin_oa_issuance("ambiguous").unwrap());
        assert_eq!(
            store
                .lookup_openrouter_lease("ambiguous")
                .unwrap()
                .oa_provisioning_outcome,
            OaProvisioningOutcome::MayHaveIssued
        );
        assert_eq!(store.due_openrouter_leases(10_000).len(), 1);
        store
            .record_openrouter_lease_error("ambiguous", "response lost")
            .unwrap();
        assert!(!store.begin_oa_issuance("ambiguous").unwrap());
        let lease = store.lookup_openrouter_lease("ambiguous").unwrap();
        assert_eq!(
            lease.oa_provisioning_outcome,
            OaProvisioningOutcome::MayHaveIssued
        );
        assert_eq!(lease.last_error.as_deref(), Some("response lost"));
        assert_eq!(store.due_openrouter_leases(10_000).len(), 1);
    }

    #[test]
    fn confirmed_unissued_oa_lease_is_due_immediately_and_cannot_resume() {
        let store = NullifierStore::in_memory().unwrap();
        create_oa_lease(&store, "rejected", 1);
        assert!(store.begin_oa_issuance("rejected").unwrap());
        let before = current_timestamp();
        store.confirm_oa_unissued("rejected").unwrap();
        let lease = store.lookup_openrouter_lease("rejected").unwrap();
        assert_eq!(
            lease.oa_provisioning_outcome,
            OaProvisioningOutcome::ConfirmedUnissued
        );
        assert!(lease.settle_after >= before);
        assert_eq!(store.due_openrouter_leases(0).len(), 1);
        assert!(store.begin_oa_issuance("rejected").is_err());
        assert!(store.confirm_oa_unissued("rejected").is_err());
        store
            .record_openrouter_lease_error("rejected", "recovery retry")
            .unwrap();
        assert_eq!(
            store
                .lookup_openrouter_lease("rejected")
                .unwrap()
                .oa_provisioning_outcome,
            OaProvisioningOutcome::ConfirmedUnissued
        );
    }

    #[test]
    fn oa_outcome_changes_require_an_unissued_provisioning_oa_row() {
        let store = NullifierStore::in_memory().unwrap();
        store
            .create_openrouter_lease(&lease_request("direct", 1), "openrouter", 10, 20, 21, 6.0)
            .unwrap();
        assert_eq!(
            store
                .lookup_openrouter_lease("direct")
                .unwrap()
                .oa_provisioning_outcome,
            OaProvisioningOutcome::MayHaveIssued
        );
        for id in ["missing", "direct"] {
            assert!(store.begin_oa_issuance(id).is_err());
            assert!(store.confirm_oa_unissued(id).is_err());
        }
        for (index, status, key_hash) in [
            (2, "active", None),
            (3, "finalized", None),
            (4, "provisioning", Some("provider-key-hash")),
        ] {
            let id = format!("guard-{index}");
            create_oa_lease(&store, &id, index);
            assert!(store.begin_oa_issuance(&id).unwrap());
            store.conn.lock().unwrap().execute(
                "UPDATE openrouter_leases SET status = ?1, key_hash = ?2 WHERE client_request_id = ?3",
                params![status, key_hash, id],
            ).unwrap();
            assert!(store.begin_oa_issuance(&id).is_err());
            assert!(store.confirm_oa_unissued(&id).is_err());
        }
        assert!(store.due_openrouter_leases(0).is_empty());
    }

    #[test]
    fn unknown_oa_outcome_is_ambiguous_until_normalized_for_reconciliation() {
        let store = NullifierStore::in_memory().unwrap();
        create_oa_lease(&store, "unknown", 1);
        store.conn.lock().unwrap().execute(
            "UPDATE openrouter_leases SET oa_provisioning_outcome = 'future_or_invalid' WHERE client_request_id = 'unknown'",
            [],
        ).unwrap();
        assert_eq!(
            store
                .lookup_openrouter_lease("unknown")
                .unwrap()
                .oa_provisioning_outcome,
            OaProvisioningOutcome::MayHaveIssued
        );
        assert!(store.due_openrouter_leases(10_000).is_empty());
        assert!(store.confirm_oa_unissued("unknown").is_err());
        assert!(!store.begin_oa_issuance("unknown").unwrap());
        assert_eq!(store.due_openrouter_leases(10_000).len(), 1);
    }

    #[test]
    fn legacy_oa_leases_migrate_to_ambiguous_and_outcomes_survive_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("leases.sqlite");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE openrouter_leases (
                    client_request_id TEXT PRIMARY KEY, request_nullifier TEXT NOT NULL UNIQUE,
                    api_request_json TEXT NOT NULL, oa_client_request_id TEXT, key_hash TEXT UNIQUE,
                    key_source TEXT NOT NULL DEFAULT 'openrouter', status TEXT NOT NULL,
                    issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, settle_after INTEGER NOT NULL,
                    spending_limit_usd REAL NOT NULL, usage_usd REAL, charge_applied INTEGER,
                    last_error TEXT, updated_at INTEGER NOT NULL
                );",
            ).unwrap();
            let request = lease_request("legacy", 1);
            conn.execute(
                "INSERT INTO openrouter_leases (client_request_id, request_nullifier, api_request_json,
                    oa_client_request_id, key_source, status, issued_at, expires_at, settle_after,
                    spending_limit_usd, updated_at)
                 VALUES ('legacy', ?1, ?2, 'legacy-bound-id', 'oa_org', 'provisioning', 10, 20, 21, 6.0, 10)",
                params![request.public_inputs.request_nullifier.to_hex(), serde_json::to_string(&request).unwrap()],
            ).unwrap();
        }
        {
            let store = NullifierStore::new(&path).unwrap();
            assert_eq!(
                store
                    .lookup_openrouter_lease("legacy")
                    .unwrap()
                    .oa_provisioning_outcome,
                OaProvisioningOutcome::MayHaveIssued
            );
            assert_eq!(store.due_openrouter_leases(10_000).len(), 1);
            assert!(!store.begin_oa_issuance("legacy").unwrap());
            create_oa_lease(&store, "never-started", 2);
            create_oa_lease(&store, "attempted", 3);
            assert!(store.begin_oa_issuance("attempted").unwrap());
            create_oa_lease(&store, "rejected", 4);
            assert!(store.begin_oa_issuance("rejected").unwrap());
            store.confirm_oa_unissued("rejected").unwrap();
        }
        let reopened = NullifierStore::new(&path).unwrap();
        assert_eq!(
            reopened
                .lookup_openrouter_lease("never-started")
                .unwrap()
                .oa_provisioning_outcome,
            OaProvisioningOutcome::NotStarted
        );
        assert!(!reopened.begin_oa_issuance("attempted").unwrap());
        assert_eq!(
            reopened
                .lookup_openrouter_lease("rejected")
                .unwrap()
                .oa_provisioning_outcome,
            OaProvisioningOutcome::ConfirmedUnissued
        );
        assert!(reopened.begin_oa_issuance("rejected").is_err());
        let mut due_ids: Vec<_> = reopened
            .due_openrouter_leases(21)
            .into_iter()
            .map(|lease| lease.client_request_id)
            .collect();
        due_ids.sort();
        assert_eq!(
            due_ids,
            vec!["attempted", "legacy", "never-started", "rejected"]
        );
    }

    #[test]
    fn test_reserve_and_lookup() {
        let store = NullifierStore::in_memory().unwrap();
        let nullifier = Felt252::from_u64(42);
        let client_id = "test-req-1";
        let payload_hash = Felt252::from_u64(100);

        store.reserve(&nullifier, client_id, &payload_hash).unwrap();

        let record = store.lookup_by_nullifier(&nullifier).unwrap();
        assert_eq!(record.status, NullifierStatus::Reserved);
        assert_eq!(record.client_request_id.as_deref(), Some(client_id));
    }

    #[test]
    fn test_reserve_duplicate_fails() {
        let store = NullifierStore::in_memory().unwrap();
        let nullifier = Felt252::from_u64(42);

        store
            .reserve(&nullifier, "req-1", &Felt252::from_u64(1))
            .unwrap();
        let result = store.reserve(&nullifier, "req-2", &Felt252::from_u64(2));
        assert!(result.is_err());
    }

    #[test]
    fn test_lookup_by_client_id() {
        let store = NullifierStore::in_memory().unwrap();
        let nullifier = Felt252::from_u64(42);
        let client_id = "unique-client-id";

        store
            .reserve(&nullifier, client_id, &Felt252::from_u64(1))
            .unwrap();

        let record = store.lookup_by_client_id(client_id).unwrap();
        assert_eq!(record.nullifier, nullifier);
    }

    #[test]
    fn test_finalize() {
        let store = NullifierStore::in_memory().unwrap();
        let nullifier = Felt252::from_u64(42);

        store
            .reserve(&nullifier, "req-1", &Felt252::from_u64(1))
            .unwrap();

        let transcript = TranscriptRecord {
            nullifier,
            status: NullifierStatus::Finalized,
            reservation_kind: "proxy".to_string(),
            client_request_id: Some("req-1".to_string()),
            payload_hash: Some(Felt252::from_u64(1)),
            charge_applied: Some(100),
            response_code: Some(200),
            response_payload: Some("{\"ok\":true}".to_string()),
            response_hash: Some(Felt252::from_u64(999)),
            next_commitment_x: Some(Felt252::from_u64(10)),
            next_commitment_y: Some(Felt252::from_u64(20)),
            next_anchor: Some(Felt252::from_u64(30)),
            blind_delta_srv: Some(Felt252::from_u64(40)),
            next_state_sig: None,
            policy_reason_code: None,
            policy_evidence_hash: None,
            proof_blob: None,
            request_inputs_json: None,
            api_request_binding: None,
            created_at: 0,
            finalized_at: None,
            settled_charge: None,
            settled_at: None,
            exit_deferred_since: None,
            exited_unsigned_at: None,
        };

        assert!(
            store.finalize(&nullifier, &transcript).is_err(),
            "an unsettled request is never signed"
        );
        store
            .record_settlement(&nullifier, 99, 200, "{\"ok\":true}")
            .unwrap();
        assert!(
            store.finalize(&nullifier, &transcript).is_err(),
            "the successor is signed only at the settled charge"
        );
        store.record_settlement(&nullifier, 100, 200, "{}").unwrap();
        assert_eq!(
            store
                .lookup_by_nullifier(&nullifier)
                .unwrap()
                .settled_charge,
            Some(99),
            "a settled charge is final"
        );
        let transcript = TranscriptRecord {
            charge_applied: Some(99),
            ..transcript
        };
        store.finalize(&nullifier, &transcript).unwrap();

        let record = store.lookup_by_nullifier(&nullifier).unwrap();
        assert_eq!(record.status, NullifierStatus::Finalized);
        assert_eq!(record.charge_applied, Some(99));
        assert_eq!(record.response_payload.as_deref(), Some("{\"ok\":true}"));
    }

    /// Threat: an operator (or bug) rewriting or deleting the proof that
    /// defeats a stale escape. Evidence is written with the reservation and
    /// SQLite refuses every UPDATE and DELETE on it.
    #[test]
    fn request_evidence_is_written_with_the_reservation_and_is_immutable() {
        let store = NullifierStore::in_memory().unwrap();
        let request = lease_request("evidence", 5);
        let nullifier = request.public_inputs.request_nullifier;
        assert!(store.request_evidence(&nullifier).is_none());
        store.reserve_openrouter_lease(&request).unwrap();
        let evidence = store.request_evidence(&nullifier).unwrap();
        assert_eq!(evidence.request_inputs, request.public_inputs);
        assert_eq!(evidence.proof, request.proof);
        assert_eq!(evidence.client_request_id, "evidence");
        let conn = store.conn.lock().unwrap();
        for statement in [
            "UPDATE request_evidence SET proof = 'forged'",
            "UPDATE request_evidence SET request_inputs_json = '{}'",
            "DELETE FROM request_evidence",
        ] {
            let error = conn.execute(statement, []).unwrap_err().to_string();
            assert!(error.contains("append-only"), "{statement}: {error}");
        }
        drop(conn);
        assert_eq!(store.request_evidence(&nullifier).unwrap(), evidence);
        // A replayed reservation appends nothing and changes nothing.
        assert!(matches!(
            store.reserve_openrouter_lease(&request),
            Err(ServerError::Replay)
        ));
        assert_eq!(store.request_evidence(&nullifier).unwrap(), evidence);
    }

    #[test]
    fn evidence_insert_failure_rolls_back_the_reservation() {
        let store = NullifierStore::in_memory().unwrap();
        let request = lease_request("orphan", 6);
        let nullifier = request.public_inputs.request_nullifier;
        store
            .conn
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO request_evidence VALUES (?1, 'other', '{}', 'groth16_bn254', 'x', 0)",
                params![nullifier.to_hex()],
            )
            .unwrap();
        assert!(store.reserve_openrouter_lease(&request).is_err());
        assert!(
            store.lookup_by_nullifier(&nullifier).is_none(),
            "no reservation may exist without its own evidence"
        );
    }

    #[test]
    fn signature_deferral_ends_in_exited_unsigned_after_the_window() {
        let store = NullifierStore::in_memory().unwrap();
        let request = lease_request("deferred", 9);
        let nullifier = request.public_inputs.request_nullifier;
        store.reserve_openrouter_lease(&request).unwrap();
        assert!(
            store.defer_signature(&nullifier, 100, 50).is_err(),
            "only a settled request defers"
        );
        store.record_settlement(&nullifier, 7, 200, "{}").unwrap();
        assert_eq!(store.settled_unsigned_entries().len(), 1);
        assert_eq!(
            store.defer_signature(&nullifier, 100, 50).unwrap(),
            SignatureDeferral::Deferred { since: 100 }
        );
        assert_eq!(
            store.defer_signature(&nullifier, 149, 50).unwrap(),
            SignatureDeferral::Deferred { since: 100 }
        );
        assert_eq!(
            store.defer_signature(&nullifier, 150, 50).unwrap(),
            SignatureDeferral::ExitedUnsigned
        );
        assert!(store.settled_unsigned_entries().is_empty());
        let record = store.lookup_by_nullifier(&nullifier).unwrap();
        assert_eq!(record.exit_deferred_since, Some(100));
        assert_eq!(record.exited_unsigned_at, Some(150));
        let transcript = TranscriptRecord {
            status: NullifierStatus::Finalized,
            charge_applied: Some(7),
            ..record
        };
        assert!(
            store.finalize(&nullifier, &transcript).is_err(),
            "an exited-unsigned request is never signed"
        );
    }

    #[test]
    fn test_reserve_clearance() {
        let store = NullifierStore::in_memory().unwrap();
        let nullifier = Felt252::from_u64(42);

        store.reserve_clearance(&nullifier).unwrap();

        let record = store.lookup_by_nullifier(&nullifier).unwrap();
        assert_eq!(record.status, NullifierStatus::ClearanceReserved);
    }

    #[test]
    fn test_get_reserved_entries() {
        let store = NullifierStore::in_memory().unwrap();

        store
            .reserve(&Felt252::from_u64(1), "r1", &Felt252::from_u64(10))
            .unwrap();
        store
            .reserve(&Felt252::from_u64(2), "r2", &Felt252::from_u64(20))
            .unwrap();

        let reserved = store.get_reserved_entries();
        assert_eq!(reserved.len(), 2);
    }

    #[test]
    fn openrouter_lease_never_persists_plaintext_key() {
        use zkapi_types::wire::{ApiRequestV2, Groth16ProofWire, ProofBackendWire};
        use zkapi_types::RequestPublicInputsV2;

        let store = NullifierStore::in_memory().unwrap();
        let nullifier = Felt252::from_u64(77);
        let request = ApiRequestV2 {
            client_request_id: "lease-1".to_string(),
            payload: "{\"mode\":\"openrouter_ephemeral_lease\",\"version\":1}".to_string(),
            payload_hash: Felt252::from_u64(88),
            public_inputs: RequestPublicInputsV2 {
                protocol_version: 2,
                chain_id: 1,
                contract_address: Felt252::from_u64(2),
                active_root: Felt252::from_u64(3),
                state_signing_key_x: Felt252::from_u64(4),
                state_signing_key_y: Felt252::from_u64(5),
                request_time: 6,
                solvency_bound: 1_000,
                request_nullifier: nullifier,
                authorization_tag: Felt252::from_u64(7),
                anonymous_commitment_x: Felt252::from_u64(8),
                anonymous_commitment_y: Felt252::from_u64(9),
            },
            proof: Groth16ProofWire {
                backend: ProofBackendWire::Groth16Bn254,
                proof: "public-proof".to_string(),
            },
        };
        store.reserve_openrouter_lease(&request).unwrap();
        let reservation = store.lookup_by_nullifier(&nullifier).unwrap();
        assert_eq!(
            reservation.api_request_binding.as_deref(),
            Some(api_request_binding(&request).unwrap().as_str())
        );
        store
            .create_openrouter_lease(&request, "openrouter", 10, 20, 21, 0.001)
            .unwrap();
        {
            let conn = store.conn.lock().unwrap();
            conn.execute(
                "UPDATE nullifiers SET api_request_binding = NULL WHERE nullifier = ?1",
                params![nullifier.to_hex()],
            )
            .unwrap();
            backfill_openrouter_request_bindings(&conn).unwrap();
        }
        assert_eq!(
            store
                .lookup_by_nullifier(&nullifier)
                .unwrap()
                .api_request_binding,
            Some(api_request_binding(&request).unwrap())
        );
        store
            .activate_openrouter_lease("lease-1", "safe-key-hash")
            .unwrap();

        let lease = store.lookup_openrouter_lease("lease-1").unwrap();
        assert_eq!(lease.key_hash.as_deref(), Some("safe-key-hash"));
        assert!(!serde_json::to_string(&lease.api_request)
            .unwrap()
            .contains("sk-or-"));
        assert_eq!(store.due_openrouter_leases(20).len(), 0);
        assert_eq!(store.due_openrouter_leases(21).len(), 1);
    }
}
