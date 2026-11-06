//! Local Merkle tree mirror maintained from contract events.

use zkapi_core::leaf::compute_note_leaf;
use zkapi_core::merkle::MerkleTree;
use zkapi_types::{Felt252, MERKLE_DEPTH};

use crate::events::VaultEvent;

/// Serializable state paired atomically with the indexer's block cursor.
///
/// Persisting only the cursor is unsafe because TreeMirror otherwise starts
/// empty after a process restart and skips the events needed to rebuild it.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct TreeMirrorSnapshot {
    pub next_note_id: u32,
    pub current_leaves: Vec<Felt252>,
}

/// A mirror of the on-chain Merkle tree, maintained by consuming events.
///
/// Exits are leaf-bound and root-free: escape, defeat, raise, finalize,
/// mutual close and expiry claims leave the leaf in place. Only a deposit
/// inserts a leaf and only `ClosedLeafRetired` removes one.
pub struct TreeMirror {
    tree: MerkleTree,
    next_note_id: u32,
}

impl TreeMirror {
    pub fn new() -> Self {
        Self {
            tree: MerkleTree::new(),
            next_note_id: 0,
        }
    }

    /// Get the current root.
    pub fn root(&self) -> Felt252 {
        self.tree.root()
    }

    /// Get the next available note ID.
    pub fn next_note_id(&self) -> u32 {
        self.next_note_id
    }

    /// All current leaves, indexed 0..next_note_id.
    ///
    /// This backs the privacy-safe snapshot endpoint: a client fetches the same
    /// full leaf vector regardless of which note it cares about, rebuilds the
    /// tree locally, and derives any sibling path without revealing its note_id
    /// to the (untrusted) indexer.
    pub fn current_leaves(&self) -> Vec<Felt252> {
        (0..self.next_note_id)
            .map(|i| self.tree.get_leaf(i))
            .collect()
    }

    /// Capture all state needed to restore paths.
    pub fn snapshot(&self) -> TreeMirrorSnapshot {
        TreeMirrorSnapshot {
            next_note_id: self.next_note_id,
            current_leaves: self.current_leaves(),
        }
    }

    /// Restore a mirror from an atomic cursor checkpoint.
    pub fn from_snapshot(snapshot: TreeMirrorSnapshot) -> Result<Self, String> {
        if snapshot.current_leaves.len() != snapshot.next_note_id as usize {
            return Err(format!(
                "snapshot has {} leaves but next_note_id is {}",
                snapshot.current_leaves.len(),
                snapshot.next_note_id
            ));
        }

        let mut tree = MerkleTree::new();
        for (note_id, leaf) in snapshot.current_leaves.iter().copied().enumerate() {
            if !leaf.is_zero() {
                tree.set_leaf(note_id as u32, leaf);
            }
        }

        Ok(Self {
            tree,
            next_note_id: snapshot.next_note_id,
        })
    }

    /// Get the sibling path for a note's current leaf.
    pub fn get_path(&self, note_id: u32) -> [Felt252; MERKLE_DEPTH] {
        self.tree.get_siblings(note_id)
    }

    /// Get the sibling path for a zero leaf at the given index.
    /// This is the same as get_path since the tree stores the current state.
    pub fn get_zero_path(&self, note_id: u32) -> [Felt252; MERKLE_DEPTH] {
        self.tree.get_siblings(note_id)
    }

    /// Get the leaf value at a given index.
    pub fn get_leaf(&self, note_id: u32) -> Felt252 {
        self.tree.get_leaf(note_id)
    }

    /// Process a contract event and update the tree.
    pub fn process_event(&mut self, event: &VaultEvent) {
        match event {
            VaultEvent::NoteDeposited {
                note_id,
                commitment,
                amount,
                expiry_ts,
                ..
            } => {
                let leaf = compute_note_leaf(*note_id, commitment, *amount, *expiry_ts);
                self.tree.set_leaf(*note_id, leaf);
                self.next_note_id = self.next_note_id.max(note_id.saturating_add(1));
            }
            VaultEvent::ClosedLeafRetired { note_id, .. } => {
                self.tree.set_leaf(*note_id, Felt252::ZERO);
            }
            VaultEvent::MutualClose { .. }
            | VaultEvent::EscapeWithdrawalInitiated { .. }
            | VaultEvent::EscapeWithdrawalDefeated { .. }
            | VaultEvent::EscapeConcessionRaised { .. }
            | VaultEvent::EscapeWithdrawalFinalized { .. }
            | VaultEvent::ExpiredClaimed { .. }
            | VaultEvent::VaultPaused { .. }
            | VaultEvent::VaultUnpaused { .. } => {}
        }
    }
}

impl Default for TreeMirror {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deposit(note_id: u32) -> VaultEvent {
        VaultEvent::NoteDeposited {
            note_id,
            commitment: Felt252::from_u64(100 + note_id as u64),
            amount: 1_000,
            expiry_ts: 1_700_000_000,
            new_root: Felt252::ZERO,
        }
    }

    /// Exits never remove a leaf: a defeated escape returns the note to
    /// Active with its leaf intact, and a front-running deposit cannot change
    /// anything an exit depends on.
    #[test]
    fn exits_and_disputes_keep_the_leaf_and_only_retirement_removes_it() {
        let mut mirror = TreeMirror::new();
        mirror.process_event(&deposit(0));
        let root_after_deposit = mirror.root();
        assert_ne!(root_after_deposit, MerkleTree::new().root());
        let nullifier = Felt252::from_u64(999);
        for event in [
            VaultEvent::EscapeWithdrawalInitiated {
                note_id: 0,
                nullifier,
                next_nullifier: Felt252::from_u64(1_000),
                final_balance: 900,
                conceded: 0,
                challenge_deadline: 1_700_086_400,
            },
            VaultEvent::EscapeConcessionRaised {
                note_id: 0,
                nullifier,
                conceded: 50,
                final_balance: 850,
            },
            VaultEvent::EscapeWithdrawalDefeated {
                note_id: 0,
                nullifier,
                next_nullifier: Felt252::from_u64(1_000),
            },
            VaultEvent::MutualClose {
                note_id: 0,
                nullifier: Felt252::from_u64(1_001),
                final_balance: 900,
            },
            VaultEvent::EscapeWithdrawalFinalized {
                note_id: 0,
                nullifier,
                final_balance: 850,
            },
            VaultEvent::ExpiredClaimed {
                note_id: 0,
                deposit_amount: 1_000,
            },
            VaultEvent::VaultPaused { paused_at: 1 },
            VaultEvent::VaultUnpaused { unpaused_at: 2 },
        ] {
            mirror.process_event(&event);
            assert_eq!(mirror.root(), root_after_deposit, "{event:?}");
        }
        mirror.process_event(&VaultEvent::ClosedLeafRetired {
            note_id: 0,
            new_root: MerkleTree::new().root(),
        });
        assert!(mirror.get_leaf(0).is_zero());
        assert_eq!(mirror.root(), MerkleTree::new().root());
    }

    #[test]
    fn retirement_after_unrelated_deposit_keeps_the_other_leaf() {
        let mut mirror = TreeMirror::new();
        mirror.process_event(&deposit(0));
        mirror.process_event(&deposit(1));
        let leaf1 = mirror.get_leaf(1);
        mirror.process_event(&VaultEvent::ClosedLeafRetired {
            note_id: 0,
            new_root: Felt252::ZERO,
        });
        let mut expected = MerkleTree::new();
        expected.set_leaf(1, leaf1);
        assert_eq!(mirror.root(), expected.root());
    }

    #[test]
    fn test_multiple_deposits() {
        let mut mirror = TreeMirror::new();
        for i in 0..5 {
            mirror.process_event(&deposit(i));
        }
        for i in 0..5 {
            assert!(!mirror.get_leaf(i).is_zero());
        }
    }

    #[test]
    fn snapshot_round_trip_preserves_current_leaves() {
        let mut mirror = TreeMirror::new();
        for note_id in 0..3 {
            mirror.process_event(&deposit(note_id));
        }
        mirror.process_event(&VaultEvent::ClosedLeafRetired {
            note_id: 1,
            new_root: Felt252::ZERO,
        });
        let expected_root = mirror.root();
        let expected_path = mirror.get_path(2);
        let restored = TreeMirror::from_snapshot(mirror.snapshot()).unwrap();
        assert_eq!(restored.root(), expected_root);
        assert_eq!(restored.next_note_id(), 3);
        assert_eq!(restored.get_path(2), expected_path);
        assert!(restored.get_leaf(1).is_zero());
    }
}
