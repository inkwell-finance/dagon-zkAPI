//! Chain-neutral settlement boundary for Dagon zkAPI.
//!
//! The inference request protocol intentionally depends only on the Groth16
//! public statements in `zkapi-types`. A ledger backend owns chain reads and
//! transaction construction behind this interface. The production backend is
//! Solana + Groth16; experimental accounting implementations can be added
//! without changing the request API or the vault lifecycle.

use std::future::Future;
use std::pin::Pin;

use serde::{Deserialize, Serialize};
use zkapi_types::wire::Groth16ProofWire;
use zkapi_types::{Felt252, RequestPublicInputsV2, WithdrawalPublicInputsV2, MERKLE_DEPTH};

/// Boxed future keeps [`CreditLedger`] object-safe without fixing a runtime.
pub type LedgerFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, LedgerError>> + Send + 'a>>;

/// A chain account normalized to the 32-byte account width used by Solana.
///
/// Compatibility backends left-pad shorter account identifiers. The bytes are
/// an identifier only; protocol proofs bind [`LedgerDeployment::protocol_binding`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LedgerAccount(pub [u8; 32]);

impl LedgerAccount {
    pub const ZERO: Self = Self([0; 32]);

    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_evm_address(address: [u8; 20]) -> Self {
        let mut bytes = [0; 32];
        bytes[12..].copy_from_slice(&address);
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Finality requested for a read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LedgerCommitment {
    /// Lowest-latency state. It may be rolled back.
    Tip,
    /// State confirmed by the backend's normal safety threshold.
    Confirmed,
    /// State past the backend's finality boundary.
    Finalized,
}

/// Stable identity and unit information for one deployed ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerDeployment {
    /// Extensible backend identifier, for example `dagon.solana.groth16.v1`.
    pub backend: String,
    /// Human-readable cluster/network label.
    pub network: String,
    /// Protocol chain identifier carried by the unchanged v2 statements.
    pub chain_id: u64,
    /// Field element carried in the v2 `contract_address` input.
    pub protocol_binding: Felt252,
    /// Concrete vault state account (or a left-padded compatibility address).
    pub vault: LedgerAccount,
    pub asset: LedgerAsset,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerAsset {
    pub symbol: String,
    /// Number of base-10 fractional digits in one ledger credit unit.
    pub decimals: u8,
    /// `None` denotes the chain's native asset.
    pub mint: Option<LedgerAccount>,
}

/// Small authoritative ledger view used by request authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerState {
    pub root: Felt252,
    pub next_note_id: u32,
    /// Slot/block height when the backend can report it.
    pub observed_height: Option<u64>,
    pub commitment: LedgerCommitment,
}

/// Privacy-safe whole-tree view. Clients derive paths locally from this data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerSnapshot {
    pub state: LedgerState,
    pub leaves: Vec<Felt252>,
}

/// One Merkle path, used by operator workflows and compatibility clients.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerPath {
    pub state: LedgerState,
    pub note_id: u32,
    pub leaf: Felt252,
    pub siblings: [Felt252; MERKLE_DEPTH],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LedgerNullifierStatus {
    Unused,
    Used,
}

/// An escape withdrawal that is still inside the ledger's challenge lifecycle.
///
/// The challenger applies the concession policy to each record: defeat it with
/// request evidence at `next_nullifier`, or raise `conceded` with evidence at
/// `nullifier` (capped by the request's solvency bound and `state_balance`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerPendingEscape {
    pub note_id: u32,
    /// Nullifier of the escaped state.
    pub nullifier: Felt252,
    /// Successor nullifier; only a request proof here defeats the escape.
    pub next_nullifier: Felt252,
    /// Balance of the escaped state (`final_balance + conceded`).
    pub state_balance: u128,
    /// Concession currently in force.
    pub conceded: u128,
    /// Backend-authoritative Unix timestamp after which a challenge is invalid.
    pub deadline: u64,
    /// Backend-authoritative time of the snapshot, when available. Challengers
    /// must not substitute an untrusted host clock when this value is present.
    pub observed_time: Option<u64>,
}

/// Deposit semantics shared by every ledger backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositRequest {
    pub payer: LedgerAccount,
    pub expected_note_id: u32,
    pub commitment: Felt252,
    pub amount: u128,
    pub zero_path: [Felt252; MERKLE_DEPTH],
}

/// Both mutual close and escape initiation use the same proof statement. The
/// concrete destination is supplied separately so a Solana program can
/// recompute the statement's 160-bit destination binding. Exits are
/// leaf-bound and root-free, so no Merkle path is carried.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalRequest {
    pub payer: LedgerAccount,
    pub destination: LedgerAccount,
    pub public_inputs: WithdrawalPublicInputsV2,
    pub proof: Groth16ProofWire,
}

/// Defeat: request evidence at the pending escape's successor nullifier. It
/// does not depend on the current root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeRequest {
    pub payer: LedgerAccount,
    pub note_id: u32,
    pub public_inputs: RequestPublicInputsV2,
    pub proof: Groth16ProofWire,
}

/// Raise: request evidence at the escaped nullifier lifts the concession to
/// `min(amount, solvency_bound, state_balance)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RaiseConcessionRequest {
    pub payer: LedgerAccount,
    pub note_id: u32,
    pub public_inputs: RequestPublicInputsV2,
    pub proof: Groth16ProofWire,
    pub amount: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalizeEscapeRequest {
    pub payer: LedgerAccount,
    pub note_id: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimExpiredRequest {
    pub payer: LedgerAccount,
    pub note_id: u32,
}

/// Permissionless removal of a closed note's leaf (current-leaf path).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetireClosedLeafRequest {
    pub payer: LedgerAccount,
    pub note_id: u32,
    pub siblings: [Felt252; MERKLE_DEPTH],
}

/// Chain-specific unsigned transaction returned to a wallet or restricted
/// operator signer. The semantic request above remains chain-neutral.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparedLedgerTransaction {
    pub format: String,
    pub bytes: Vec<u8>,
    pub required_signers: Vec<LedgerAccount>,
    pub last_valid_height: Option<u64>,
}

/// Ordered transaction plan for one semantic ledger operation. Solana uses
/// this to stage proof/path bytes that cannot fit in a single transaction and
/// then execute them from an authenticated operation buffer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparedLedgerOperation {
    pub transactions: Vec<PreparedLedgerTransaction>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedLedgerTransaction {
    pub format: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerSubmission {
    /// Opaque signature/hash bytes in the backend's canonical representation.
    pub transaction_id: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum LedgerTransactionStatus {
    Unknown,
    Pending,
    Confirmed { height: Option<u64> },
    Finalized { height: Option<u64> },
    Failed { reason: String },
}

#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error("ledger operation `{operation}` is not supported by this backend")]
    Unsupported { operation: &'static str },
    #[error("ledger is temporarily unavailable: {0}")]
    Unavailable(String),
    #[error("ledger returned invalid data: {0}")]
    InvalidData(String),
    #[error("ledger deployment mismatch: {0}")]
    DeploymentMismatch(String),
    #[error("ledger rejected the operation: {0}")]
    Rejected(String),
}

fn unsupported<T>(operation: &'static str) -> LedgerFuture<'static, T> {
    Box::pin(async move { Err(LedgerError::Unsupported { operation }) })
}

/// Object-safe, asynchronous boundary between zkAPI and its credit ledger.
///
/// Implementations must preserve the v2 root/nullifier/escape lifecycle. A
/// backend may change storage or transaction encoding, but it must not reinterpret
/// these operations or the Groth16 public statements.
pub trait CreditLedger: Send + Sync {
    fn deployment(&self) -> &LedgerDeployment;

    fn state(&self, commitment: LedgerCommitment) -> LedgerFuture<'_, LedgerState>;

    fn snapshot(&self, commitment: LedgerCommitment) -> LedgerFuture<'_, LedgerSnapshot>;

    fn path(
        &self,
        note_id: u32,
        zero_leaf: bool,
        commitment: LedgerCommitment,
    ) -> LedgerFuture<'_, LedgerPath>;

    fn nullifier_status(
        &self,
        nullifier: Felt252,
        commitment: LedgerCommitment,
    ) -> LedgerFuture<'_, LedgerNullifierStatus>;

    /// Enumerate pending escapes for the operator challenger.
    ///
    /// Every record must be authoritative at no less than the requested
    /// finality; implementations reject malformed or foreign records rather
    /// than silently omitting them. A paginated backend may observe pages at
    /// increasing heights, so escapes created mid-scan can appear next poll.
    fn pending_escapes(
        &self,
        _commitment: LedgerCommitment,
    ) -> LedgerFuture<'_, Vec<LedgerPendingEscape>> {
        unsupported("pending_escapes")
    }

    fn prepare_deposit(
        &self,
        _request: DepositRequest,
    ) -> LedgerFuture<'_, PreparedLedgerOperation> {
        unsupported("deposit")
    }

    fn prepare_close(
        &self,
        _request: WithdrawalRequest,
    ) -> LedgerFuture<'_, PreparedLedgerOperation> {
        unsupported("close")
    }

    fn prepare_escape(
        &self,
        _request: WithdrawalRequest,
    ) -> LedgerFuture<'_, PreparedLedgerOperation> {
        unsupported("escape")
    }

    fn prepare_challenge(
        &self,
        _request: ChallengeRequest,
    ) -> LedgerFuture<'_, PreparedLedgerOperation> {
        unsupported("challenge")
    }

    fn prepare_finalize_escape(
        &self,
        _request: FinalizeEscapeRequest,
    ) -> LedgerFuture<'_, PreparedLedgerOperation> {
        unsupported("finalize_escape")
    }

    fn prepare_raise_concession(
        &self,
        _request: RaiseConcessionRequest,
    ) -> LedgerFuture<'_, PreparedLedgerOperation> {
        unsupported("raise_concession")
    }

    fn prepare_retire_closed_leaf(
        &self,
        _request: RetireClosedLeafRequest,
    ) -> LedgerFuture<'_, PreparedLedgerOperation> {
        unsupported("retire_closed_leaf")
    }

    fn prepare_claim_expired(
        &self,
        _request: ClaimExpiredRequest,
    ) -> LedgerFuture<'_, PreparedLedgerOperation> {
        unsupported("claim_expired")
    }

    fn submit(&self, _transaction: SignedLedgerTransaction) -> LedgerFuture<'_, LedgerSubmission> {
        unsupported("submit")
    }

    fn transaction_status(
        &self,
        _transaction_id: Vec<u8>,
    ) -> LedgerFuture<'_, LedgerTransactionStatus> {
        unsupported("transaction_status")
    }

    /// Current backend height in the same domain as
    /// [`PreparedLedgerTransaction::last_valid_height`]. This is deliberately
    /// separate from [`LedgerState::observed_height`], which may be a slot or a
    /// block number depending on the state read.
    fn transaction_height(&self, _commitment: LedgerCommitment) -> LedgerFuture<'_, u64> {
        unsupported("transaction_height")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ReadOnlyLedger {
        deployment: LedgerDeployment,
    }

    impl CreditLedger for ReadOnlyLedger {
        fn deployment(&self) -> &LedgerDeployment {
            &self.deployment
        }

        fn state(&self, commitment: LedgerCommitment) -> LedgerFuture<'_, LedgerState> {
            Box::pin(async move {
                Ok(LedgerState {
                    root: Felt252::from_u64(7),
                    next_note_id: 2,
                    observed_height: Some(11),
                    commitment,
                })
            })
        }

        fn snapshot(&self, commitment: LedgerCommitment) -> LedgerFuture<'_, LedgerSnapshot> {
            Box::pin(async move {
                Ok(LedgerSnapshot {
                    state: LedgerState {
                        root: Felt252::from_u64(7),
                        next_note_id: 2,
                        observed_height: Some(11),
                        commitment,
                    },
                    leaves: vec![Felt252::from_u64(3), Felt252::from_u64(4)],
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
                Ok(LedgerPath {
                    state: LedgerState {
                        root: Felt252::from_u64(7),
                        next_note_id: 2,
                        observed_height: Some(11),
                        commitment,
                    },
                    note_id,
                    leaf: if zero_leaf {
                        Felt252::ZERO
                    } else {
                        Felt252::from_u64(3)
                    },
                    siblings: [Felt252::ZERO; MERKLE_DEPTH],
                })
            })
        }

        fn nullifier_status(
            &self,
            _nullifier: Felt252,
            _commitment: LedgerCommitment,
        ) -> LedgerFuture<'_, LedgerNullifierStatus> {
            Box::pin(async { Ok(LedgerNullifierStatus::Unused) })
        }
    }

    fn fixture() -> ReadOnlyLedger {
        ReadOnlyLedger {
            deployment: LedgerDeployment {
                backend: "test.groth16.v1".into(),
                network: "local".into(),
                chain_id: 9,
                protocol_binding: Felt252::from_u64(10),
                vault: LedgerAccount::new([1; 32]),
                asset: LedgerAsset {
                    symbol: "TEST".into(),
                    decimals: 9,
                    mint: None,
                },
            },
        }
    }

    #[tokio::test]
    async fn trait_is_object_safe_and_preserves_read_semantics() {
        let ledger: Box<dyn CreditLedger> = Box::new(fixture());
        assert_eq!(ledger.deployment().backend, "test.groth16.v1");
        assert_eq!(
            ledger.state(LedgerCommitment::Finalized).await.unwrap(),
            LedgerState {
                root: Felt252::from_u64(7),
                next_note_id: 2,
                observed_height: Some(11),
                commitment: LedgerCommitment::Finalized,
            }
        );
        assert_eq!(
            ledger
                .nullifier_status(Felt252::from_u64(8), LedgerCommitment::Tip)
                .await
                .unwrap(),
            LedgerNullifierStatus::Unused
        );
    }

    #[tokio::test]
    async fn unsupported_writes_fail_closed() {
        let ledger = fixture();
        let error = ledger
            .prepare_finalize_escape(FinalizeEscapeRequest {
                payer: LedgerAccount::ZERO,
                note_id: 1,
            })
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            LedgerError::Unsupported {
                operation: "finalize_escape"
            }
        ));
    }
}
