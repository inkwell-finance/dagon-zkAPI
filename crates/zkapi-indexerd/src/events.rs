//! Contract event types for the indexer.

use serde::{Deserialize, Serialize};
use zkapi_types::Felt252;

/// Events emitted by the ZkApiVault contract (concession exit). Exits are
/// leaf-bound and root-free: only deposits and `ClosedLeafRetired` change the
/// Merkle tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VaultEvent {
    NoteDeposited {
        note_id: u32,
        commitment: Felt252,
        amount: u128,
        expiry_ts: u64,
        new_root: Felt252,
    },
    MutualClose {
        note_id: u32,
        nullifier: Felt252,
        final_balance: u128,
    },
    EscapeWithdrawalInitiated {
        note_id: u32,
        nullifier: Felt252,
        next_nullifier: Felt252,
        final_balance: u128,
        conceded: u128,
        challenge_deadline: u64,
    },
    /// A request at the escape's successor nullifier defeated it: the note is
    /// active again and its leaf never left the tree.
    EscapeWithdrawalDefeated {
        note_id: u32,
        nullifier: Felt252,
        next_nullifier: Felt252,
    },
    EscapeConcessionRaised {
        note_id: u32,
        nullifier: Felt252,
        conceded: u128,
        final_balance: u128,
    },
    EscapeWithdrawalFinalized {
        note_id: u32,
        nullifier: Felt252,
        final_balance: u128,
    },
    ExpiredClaimed {
        note_id: u32,
        deposit_amount: u128,
    },
    /// The only exit-side tree change: a closed note's leaf is zeroed.
    ClosedLeafRetired {
        note_id: u32,
        new_root: Felt252,
    },
    VaultPaused {
        paused_at: u64,
    },
    VaultUnpaused {
        unpaused_at: u64,
    },
}
