//! Local Merkle tree mirror rebuilt from finalized Solana vault accounts.

use zkapi_core::merkle::MerkleTree;
use zkapi_types::{Felt252, MERKLE_DEPTH};

/// The complete current leaf vector of a vault tree.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct TreeMirrorSnapshot {
    pub next_note_id: u32,
    pub current_leaves: Vec<Felt252>,
}

/// A mirror of the on-chain Merkle tree.
///
/// Exits are leaf-bound and root-free: escape, defeat, raise, finalize,
/// mutual close and expiry claims leave the leaf in place. Only a deposit
/// inserts a leaf and only closed-leaf retirement removes one.
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

    /// Build a mirror from a complete leaf vector.
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
}

impl Default for TreeMirror {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(note_id: u32) -> Felt252 {
        zkapi_core::leaf::compute_note_leaf(
            note_id,
            &Felt252::from_u64(100 + note_id as u64),
            1_000,
            1_700_000_000,
        )
    }

    #[test]
    fn snapshot_rebuilds_current_leaves_and_retired_slots() {
        let mirror = TreeMirror::from_snapshot(TreeMirrorSnapshot {
            next_note_id: 3,
            current_leaves: vec![leaf(0), Felt252::ZERO, leaf(2)],
        })
        .unwrap();
        let mut expected = MerkleTree::new();
        expected.set_leaf(0, leaf(0));
        expected.set_leaf(2, leaf(2));
        assert_eq!(mirror.root(), expected.root());
        assert_eq!(mirror.next_note_id(), 3);
        assert_eq!(mirror.get_path(2), expected.get_siblings(2));
        assert!(mirror.get_leaf(1).is_zero());
        assert_eq!(
            mirror.current_leaves(),
            vec![leaf(0), Felt252::ZERO, leaf(2)]
        );
    }

    #[test]
    fn snapshot_rejects_a_leaf_count_mismatch() {
        assert!(TreeMirror::from_snapshot(TreeMirrorSnapshot {
            next_note_id: 2,
            current_leaves: vec![leaf(0)],
        })
        .is_err());
    }
}
