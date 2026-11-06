//! Client private state per spec section 5.2.
//!
//! Each active note is represented by a `NoteState` struct that tracks the
//! current balance, blinding factor, commitment, anchor, predecessor anchor,
//! the solvency bound released at this state, and the server-issued state
//! signature. The state is persisted atomically to disk so that the wallet
//! can always recover to a consistent point after a crash.

use std::fs;
use std::io::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};

use zkapi_core::v2 as core;
use zkapi_types::{Felt252, SchnorrSignature};

use crate::error::ClientError;
use crate::exit_policy::ReleasedRecord;

/// Client-side private state for a single note.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoteState {
    pub protocol_version: u16,
    pub chain_id: u64,
    pub contract_address: Felt252,
    pub note_id: u32,
    pub secret_s: Felt252,
    pub deposit_amount: u128,
    pub expiry_ts: u64,
    pub current_balance: u128,
    /// Blinding factor serialized as 0x-prefixed lowercase hex.
    pub balance_blinding: String,
    pub current_commitment_x: Felt252,
    pub current_commitment_y: Felt252,
    pub current_anchor: Felt252,
    pub is_genesis: bool,
    pub state_signature: Option<SchnorrSignature>,
    /// The anchor of the state this one succeeded (`None` at genesis). A
    /// signed state without it cannot prove requests or exits.
    #[serde(default)]
    pub prev_anchor: Option<Felt252>,
    /// The solvency bound of every request proof made at this state (C2);
    /// 0 while no request proof left the wallet. Reset to 0 by an install.
    #[serde(default)]
    pub bound_at_state: u128,
    /// Requests released at this state, for the exit decision. Reset by an
    /// install.
    #[serde(default)]
    pub released: Vec<ReleasedRecord>,
}

impl NoteState {
    /// Create genesis state after a successful on-chain deposit.
    ///
    /// The initial balance equals the deposit amount, the anchor is 1 (genesis),
    /// and no state signature exists yet.
    #[allow(clippy::too_many_arguments)]
    pub fn new_from_deposit(
        protocol_version: u16,
        chain_id: u64,
        contract_address: Felt252,
        note_id: u32,
        secret_s: Felt252,
        deposit_amount: u128,
        expiry_ts: u64,
        balance_blinding: String,
        commitment_x: Felt252,
        commitment_y: Felt252,
    ) -> Self {
        Self {
            protocol_version,
            chain_id,
            contract_address,
            note_id,
            secret_s,
            deposit_amount,
            expiry_ts,
            current_balance: deposit_amount,
            balance_blinding,
            current_commitment_x: commitment_x,
            current_commitment_y: commitment_y,
            current_anchor: core::GENESIS_ANCHOR,
            is_genesis: true,
            state_signature: None,
            prev_anchor: None,
            bound_at_state: 0,
            released: Vec::new(),
        }
    }

    /// The `prev_anchor` proof witness: zero at genesis, the recorded
    /// predecessor anchor otherwise.
    pub fn predecessor_anchor(&self) -> Result<Felt252, ClientError> {
        if self.is_genesis {
            return Ok(Felt252::ZERO);
        }
        self.prev_anchor.ok_or(ClientError::PrevAnchorMissing)
    }

    /// The nullifier `N(s, note_id, τ)` this state's requests spend and its
    /// exits publish.
    pub fn nullifier(&self) -> Felt252 {
        core::nullifier(&self.secret_s, self.note_id, &self.current_anchor)
    }

    /// The successor nullifier `N⁺` an escape from this state publishes.
    pub fn successor_nullifier(&self) -> Felt252 {
        core::successor_nullifier(&self.secret_s, self.note_id, &self.nullifier())
    }

    /// Reject a state whose genesis flag, signature, balance or bound
    /// disagree.
    pub fn check_consistency(&self) -> Result<(), ClientError> {
        let genesis = self.current_anchor == core::GENESIS_ANCHOR;
        if self.is_genesis != genesis
            || (genesis
                && (self.state_signature.is_some()
                    || self.prev_anchor.is_some()
                    || self.current_balance != self.deposit_amount))
            || (!genesis && self.state_signature.is_none())
            || self.current_balance > self.deposit_amount
            || self.bound_at_state > self.current_balance
        {
            return Err(ClientError::VerificationFailed(
                "note state is inconsistent (genesis flag, signature, balance or bound)".into(),
            ));
        }
        Ok(())
    }

    /// Persist the state atomically by writing to a temporary file and then
    /// renaming it into the target path. This guarantees that a crash at any
    /// point leaves either the old state or the new state on disk, never a
    /// partial write.
    pub fn save(&self, path: &Path) -> Result<(), ClientError> {
        let json = serde_json::to_vec_pretty(self)
            .map_err(|e| ClientError::Serialization(e.to_string()))?;
        replace_private_file(path, &json)
    }

    /// Load state from a JSON file on disk.
    pub fn load(path: &Path) -> Result<Self, ClientError> {
        let data = fs::read_to_string(path)?;
        serde_json::from_str(&data).map_err(|e| ClientError::Serialization(e.to_string()))
    }

    /// Archive the state file by moving it into an `archive/` subdirectory
    /// alongside the original path, with a filename that includes the note id.
    /// This is called after a successful close or withdrawal.
    pub fn archive(&self, path: &Path) -> Result<(), ClientError> {
        let parent = path.parent().unwrap_or(Path::new("."));
        let archive_dir = parent.join("archive");
        fs::create_dir_all(&archive_dir)?;

        let filename = format!("note_{}_closed.json", self.note_id);
        let archive_path = archive_dir.join(filename);

        // Save a copy to the archive, then remove the active state file.
        self.save(&archive_path)?;
        if path.exists() {
            fs::remove_file(path)?;
        }
        Ok(())
    }
}

/// Replace `path` with `bytes` through a synced private sibling temp file and
/// a rename, so a crash leaves either the old or the new content.
pub(crate) fn replace_private_file(path: &Path, bytes: &[u8]) -> Result<(), ClientError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp_path = path.with_extension("tmp");
    let mut options = fs::OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&tmp_path, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("zkapi_notestate_{}", name));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_new_from_deposit_genesis() {
        let state = NoteState::new_from_deposit(
            1,
            1,
            Felt252::from_u64(0xdead),
            0,
            Felt252::from_u64(42),
            1000,
            1700000000,
            "0x2a".to_string(),
            Felt252::from_u64(1),
            Felt252::from_u64(2),
        );
        assert!(state.is_genesis);
        assert_eq!(state.current_balance, 1000);
        assert_eq!(state.current_anchor, Felt252::ONE);
        assert!(state.state_signature.is_none());
    }

    #[test]
    fn states_saved_before_the_concession_fields_still_load() {
        let dir = test_dir("legacy_fields");
        let path = dir.join("note_state.json");
        let state = NoteState::new_from_deposit(
            2,
            1,
            Felt252::from_u64(0xdead),
            4,
            Felt252::from_u64(42),
            1000,
            1700000000,
            "0x2a".to_string(),
            Felt252::from_u64(1),
            Felt252::from_u64(2),
        );
        let mut value = serde_json::to_value(&state).unwrap();
        let object = value.as_object_mut().unwrap();
        for field in ["prev_anchor", "bound_at_state", "released"] {
            object.remove(field);
        }
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        let loaded = NoteState::load(&path).unwrap();
        assert_eq!(loaded.prev_anchor, None);
        assert_eq!(loaded.bound_at_state, 0);
        assert!(loaded.released.is_empty());
        assert_eq!(loaded.predecessor_anchor().unwrap(), Felt252::ZERO);
        loaded.check_consistency().unwrap();
    }

    #[test]
    fn nullifiers_are_note_bound_and_chain_to_the_successor() {
        let state = NoteState::new_from_deposit(
            2,
            1,
            Felt252::ZERO,
            9,
            Felt252::from_u64(7),
            1000,
            0,
            "0x0".into(),
            Felt252::ZERO,
            Felt252::ZERO,
        );
        assert_eq!(
            state.nullifier(),
            core::nullifier(&state.secret_s, 9, &core::GENESIS_ANCHOR)
        );
        let mut next = state.clone();
        next.current_anchor = core::next_anchor(&state.nullifier());
        assert_eq!(next.nullifier(), state.successor_nullifier());
        next.is_genesis = false;
        assert!(matches!(
            next.predecessor_anchor(),
            Err(ClientError::PrevAnchorMissing)
        ));
        assert!(next.check_consistency().is_err());
    }

    #[test]
    fn test_save_and_load_roundtrip() {
        let dir = test_dir("save_load");
        let path = dir.join("note_state.json");
        let state = NoteState::new_from_deposit(
            1,
            1,
            Felt252::from_u64(0xdead),
            7,
            Felt252::from_u64(42),
            5000,
            1700000000,
            "0xff".to_string(),
            Felt252::from_u64(10),
            Felt252::from_u64(20),
        );
        state.save(&path).unwrap();
        let loaded = NoteState::load(&path).unwrap();
        assert_eq!(loaded.note_id, 7);
        assert_eq!(loaded.current_balance, 5000);
        assert_eq!(loaded.balance_blinding, "0xff");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn test_archive() {
        let dir = test_dir("archive");
        let path = dir.join("note_state.json");
        let state = NoteState::new_from_deposit(
            1,
            1,
            Felt252::ZERO,
            3,
            Felt252::from_u64(1),
            100,
            0,
            "0x0".into(),
            Felt252::ZERO,
            Felt252::ZERO,
        );
        state.save(&path).unwrap();
        assert!(path.exists());

        state.archive(&path).unwrap();
        assert!(!path.exists());
        let archived = dir.join("archive").join("note_3_closed.json");
        assert!(archived.exists());
    }
}
