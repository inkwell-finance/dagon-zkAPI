//! Client error types.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("no active note")]
    NoActiveNote,
    #[error("note already exists")]
    NoteAlreadyExists,
    #[error("insufficient balance: need {needed}, have {available}")]
    InsufficientBalance { needed: u128, available: u128 },
    #[error("stale root")]
    StaleRoot,
    #[error("server error: {0}")]
    ServerError(String),
    #[error("invalid server response: {0}")]
    InvalidResponse(String),
    #[error("pending request exists, must recover first")]
    PendingRequest,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("proof generation failed: {0}")]
    ProofGeneration(String),
    #[error("verification failed: {0}")]
    VerificationFailed(String),
    /// S3, S4 or S5 failed on a correctly signed successor: it is treated
    /// exactly like a withheld successor.
    #[error("invalid_successor: {0}")]
    InvalidSuccessor(String),
    /// C2: a request proof at this state already used another bound.
    #[error("bound_fixed_at_state: request proofs at this state use the bound {bound}; refusing {requested}")]
    BoundFixedAtState { bound: u128, requested: u128 },
    /// A signed state without its predecessor's anchor cannot prove.
    #[error("prev_anchor_missing: this signed state was saved without its predecessor's anchor")]
    PrevAnchorMissing,
    /// C4: the note is too close to expiry for a new request to settle.
    #[error("note_near_expiry: a new request could not settle before the exit deadline")]
    NoteNearExpiry,
    /// C3: an exit lock freezes the wallet.
    #[error("exit_locked: {0}")]
    ExitLocked(String),
    /// An escape may concede at most the state's bound.
    #[error("conceded_exceeds_bound: conceded {conceded} exceeds the state's bound {bound}")]
    ConcededExceedsBound { conceded: u128, bound: u128 },
}
