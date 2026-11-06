//! `exit_lock.json` (C3 freeze, E6 release).
//!
//! The lock is written durably before any exit proof is generated, and each
//! proof is appended to `released` before it leaves the wallet. While the
//! lock is held the wallet creates no request proof, and only the lock's own
//! mode's proofs at the lock's state:
//! - `mutual`: mutual-close proofs (no concession);
//! - `escape`: escape proofs conceding at most `bound_at_state`.

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use zkapi_types::Felt252;

use crate::error::ClientError;
use crate::exit_policy::ReleasedExit;

pub const EXIT_LOCK_FILE: &str = "exit_lock.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitMode {
    Mutual,
    Escape,
}

impl ExitMode {
    /// The exit kind its proofs carry: 0 escape, 1 mutual close.
    pub fn kind(self) -> u8 {
        match self {
            Self::Escape => 0,
            Self::Mutual => 1,
        }
    }
}

/// One exit proof that left, or may have left, the wallet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleasedProof {
    /// 0 escape, 1 mutual close.
    pub kind: u8,
    pub valid_until: u64,
    pub conceded: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitLock {
    pub note_id: u32,
    /// The anchor of the state the lock freezes.
    pub anchor: Felt252,
    pub mode: ExitMode,
    /// When the lock was first set (seconds).
    pub since: u64,
    pub released: Vec<ReleasedProof>,
}

impl ExitLock {
    pub fn new(note_id: u32, anchor: Felt252, mode: ExitMode, since: u64) -> Self {
        Self {
            note_id,
            anchor,
            mode,
            since,
            released: Vec::new(),
        }
    }

    /// Whether any exit proof was released under it.
    pub fn exit_released(&self) -> bool {
        !self.released.is_empty()
    }

    /// Whether an escape proof was released under it.
    pub fn escape_released(&self) -> bool {
        self.released.iter().any(|proof| proof.kind == 0)
    }

    /// The released proofs as E6 sees them.
    pub fn released_exits(&self) -> Vec<ReleasedExit> {
        self.released
            .iter()
            .map(|proof| ReleasedExit {
                kind: proof.kind,
                valid_until: proof.valid_until,
            })
            .collect()
    }

    pub fn load(path: &Path) -> Result<Option<Self>, ClientError> {
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|error| ClientError::Serialization(format!("{EXIT_LOCK_FILE}: {error}")))
    }

    /// Write the lock atomically: a crash leaves the old or the new lock.
    pub fn save(&self, path: &Path) -> Result<(), ClientError> {
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|error| ClientError::Serialization(error.to_string()))?;
        crate::note_state::replace_private_file(path, &bytes)
    }

    pub fn remove(path: &Path) -> Result<(), ClientError> {
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_round_trips_and_tracks_released_proofs() {
        let dir = std::env::temp_dir().join("zkapi_exit_lock_roundtrip");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join(EXIT_LOCK_FILE);
        assert_eq!(ExitLock::load(&path).unwrap(), None);
        let mut lock = ExitLock::new(3, Felt252::ONE, ExitMode::Escape, 10);
        assert!(!lock.exit_released());
        lock.released.push(ReleasedProof {
            kind: ExitMode::Escape.kind(),
            valid_until: 20,
            conceded: 5,
        });
        lock.save(&path).unwrap();
        let loaded = ExitLock::load(&path).unwrap().unwrap();
        assert_eq!(loaded, lock);
        assert!(loaded.escape_released());
        assert_eq!(loaded.released_exits()[0].valid_until, 20);
        ExitLock::remove(&path).unwrap();
        ExitLock::remove(&path).unwrap();
        assert_eq!(ExitLock::load(&path).unwrap(), None);
    }
}
