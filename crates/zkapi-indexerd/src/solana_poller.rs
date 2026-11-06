//! Finalized Solana account-snapshot poller for the Dagon zkAPI indexer.
//!
//! Closed notes are closed as Solana accounts, while active and pending notes
//! remain as PDAs. Rebuilding the tree from those accounts plus `next_note_id`
//! therefore yields the complete current leaf vector without trusting event
//! history. A snapshot is published only when its Merkle root exactly matches
//! the finalized vault account.
//!
//! The poller is bound to the profile's program and a network identity: it
//! refuses an RPC on another cluster and a vault whose genesis hash, version,
//! request charge cap, note TTL or challenge period differ from the profile.

use std::sync::Arc;
use std::time::Duration;

use anchor_lang::{AccountDeserialize, Space};
use anyhow::{anyhow, ensure, Context};
use base64::Engine;
use dagon_zkapi_profile::{ResolvedIdentity, SharedProfile, VaultProfile};
use dagon_zkapi_vault::{
    NoteState, VaultState, NOTE_STATUS_ACTIVE, NOTE_STATUS_CLOSED, NOTE_STATUS_PENDING,
    NOTE_STATUS_RETIRED,
};
use reqwest::Client;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use zkapi_types::{solana_chain_id, solana_deployment_binding, Felt252};

use crate::service::IndexerService;
use crate::tree_mirror::{TreeMirror, TreeMirrorSnapshot};

const COMMITMENT: &str = "finalized";

#[derive(Debug, Clone)]
pub struct SolanaPollerConfig {
    pub rpc_url: String,
    pub program_id: [u8; 32],
    pub vault_state: [u8; 32],
    pub genesis_hash: [u8; 32],
    /// Vault parameters every finalized vault read must carry.
    pub vault: VaultProfile,
}

impl SolanaPollerConfig {
    /// The profile's program and vault parameters under a network identity.
    pub fn from_identity(
        rpc_url: String,
        profile: &SharedProfile,
        identity: &ResolvedIdentity,
    ) -> Self {
        Self {
            rpc_url,
            program_id: profile.program_id(),
            vault_state: identity.vault_state,
            genesis_hash: identity.genesis_hash,
            vault: profile.vault.clone(),
        }
    }
}

pub struct SolanaAccountPoller {
    client: Client,
    rpc_url: String,
    program_id: anchor_lang::prelude::Pubkey,
    vault_state: anchor_lang::prelude::Pubkey,
    genesis_hash: [u8; 32],
    vault: VaultProfile,
}

impl SolanaAccountPoller {
    pub fn new(config: SolanaPollerConfig) -> anyhow::Result<Self> {
        let url = reqwest::Url::parse(&config.rpc_url).context("invalid Solana RPC URL")?;
        ensure!(
            url.scheme() == "https"
                || (url.scheme() == "http"
                    && matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "::1"))),
            "Solana indexer RPC requires HTTPS or loopback HTTP"
        );
        ensure!(
            url.username().is_empty() && url.password().is_none() && url.fragment().is_none(),
            "Solana indexer RPC URL cannot contain credentials or a fragment"
        );
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            client,
            rpc_url: config.rpc_url,
            program_id: anchor_lang::prelude::Pubkey::new_from_array(config.program_id),
            vault_state: anchor_lang::prelude::Pubkey::new_from_array(config.vault_state),
            genesis_hash: config.genesis_hash,
            vault: config.vault,
        })
    }

    /// The RPC must serve the identity's cluster.
    pub async fn assert_cluster(&self) -> anyhow::Result<()> {
        let genesis: String = self.rpc("getGenesisHash", json!([])).await?;
        ensure!(
            dagon_zkapi_profile::parse_base58_32("RPC genesis hash", &genesis)?
                == self.genesis_hash,
            "Solana RPC genesis hash does not match the network identity"
        );
        Ok(())
    }

    pub async fn poll_once(&self, service: &IndexerService) -> anyhow::Result<usize> {
        let (notes_slot, notes) = self.fetch_notes().await?;
        let (_vault_slot, vault) = self.fetch_vault(notes_slot).await?;
        validate_deployment(
            self.program_id,
            self.vault_state,
            &self.genesis_hash,
            &self.vault,
            &vault,
        )?;
        let count = notes.len();
        let mirror = mirror_from_accounts(self.vault_state, &vault, notes)?;
        service.replace(mirror);
        Ok(count)
    }

    async fn fetch_notes(&self) -> anyhow::Result<(u64, Vec<NoteState>)> {
        let result: RpcContext<Value> = self
            .rpc(
                "getProgramAccounts",
                json!([
                    self.program_id.to_string(),
                    {
                        "commitment": COMMITMENT,
                        "encoding": "base64",
                        "withContext": true,
                        "filters": [
                            {"dataSize": 8 + NoteState::INIT_SPACE},
                            {"memcmp": {"offset": 8, "bytes": self.vault_state.to_string()}}
                        ]
                    }
                ]),
            )
            .await?;
        let accounts = result
            .value
            .as_array()
            .ok_or_else(|| anyhow!("Solana getProgramAccounts value is not an array"))?;
        let mut notes = Vec::with_capacity(accounts.len());
        for entry in accounts {
            let address = entry["pubkey"]
                .as_str()
                .ok_or_else(|| anyhow!("Solana program account lacks pubkey"))?;
            let account = entry
                .get("account")
                .ok_or_else(|| anyhow!("Solana program account lacks account data"))?;
            let note: NoteState = decode_program_account(account, self.program_id)
                .with_context(|| format!("invalid note account {address}"))?;
            notes.push(note);
        }
        Ok((result.context.slot, notes))
    }

    async fn fetch_vault(&self, min_context_slot: u64) -> anyhow::Result<(u64, VaultState)> {
        let result: RpcContext<Option<Value>> = self
            .rpc(
                "getAccountInfo",
                json!([
                    self.vault_state.to_string(),
                    {
                        "commitment": COMMITMENT,
                        "encoding": "base64",
                        "minContextSlot": min_context_slot
                    }
                ]),
            )
            .await?;
        let account = result
            .value
            .ok_or_else(|| anyhow!("Solana vault-state account does not exist"))?;
        let vault = decode_program_account(&account, self.program_id)
            .context("invalid Solana vault-state account")?;
        Ok((result.context.slot, vault))
    }

    async fn rpc<T: DeserializeOwned>(&self, method: &str, params: Value) -> anyhow::Result<T> {
        let response = self
            .client
            .post(&self.rpc_url)
            .json(&RpcRequest {
                jsonrpc: "2.0",
                id: 1,
                method,
                params,
            })
            .send()
            .await
            .with_context(|| format!("Solana RPC {method} failed"))?
            .error_for_status()
            .context("Solana RPC returned a non-success status")?;
        let body: RpcResponse<T> = response
            .json()
            .await
            .context("invalid Solana RPC response")?;
        if let Some(error) = body.error {
            return Err(anyhow!(
                "Solana RPC {method} failed with {}: {}",
                error.code,
                error.message
            ));
        }
        body.result
            .ok_or_else(|| anyhow!("Solana RPC {method} response lacks result"))
    }
}

/// Poll forever, publishing each validated snapshot.
pub fn spawn_solana_account_poller(
    service: Arc<IndexerService>,
    poller: SolanaAccountPoller,
    interval: Duration,
) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            if let Err(error) = poller.poll_once(&service).await {
                tracing::warn!(%error, "Solana indexer snapshot rejected");
            }
        }
    });
}

fn validate_deployment(
    program_id: anchor_lang::prelude::Pubkey,
    vault_address: anchor_lang::prelude::Pubkey,
    genesis_hash: &[u8; 32],
    profile: &VaultProfile,
    vault: &VaultState,
) -> anyhow::Result<()> {
    ensure!(
        &vault.genesis_hash == genesis_hash,
        "Solana vault genesis hash does not match the network identity"
    );
    ensure!(
        vault.version == profile.version
            && vault.request_charge_cap == profile.request_charge_cap
            && vault.note_ttl == profile.note_ttl_seconds
            && vault.challenge_period == profile.challenge_period_seconds,
        "Solana vault parameters do not match the deployment profile"
    );
    ensure!(
        vault.chain_id == solana_chain_id(&vault.genesis_hash),
        "Solana vault chain binding is invalid"
    );
    let binding = solana_deployment_binding(
        &program_id.to_bytes(),
        &vault_address.to_bytes(),
        &vault.genesis_hash,
    );
    ensure!(
        vault.protocol_binding == *binding.as_bytes(),
        "Solana vault deployment binding is invalid"
    );
    Ok(())
}

fn mirror_from_accounts(
    vault_address: anchor_lang::prelude::Pubkey,
    vault: &VaultState,
    notes: Vec<NoteState>,
) -> anyhow::Result<TreeMirror> {
    let next_note_id = vault.next_note_id;
    let mut current_leaves = vec![Felt252::ZERO; next_note_id as usize];
    let mut seen = std::collections::HashSet::with_capacity(notes.len());

    for note in notes {
        ensure!(note.vault == vault_address, "note belongs to another vault");
        ensure!(
            note.note_id < next_note_id,
            "note ID exceeds vault next_note_id"
        );
        ensure!(seen.insert(note.note_id), "duplicate Solana note account");
        let commitment = Felt252::try_from_bytes_be(note.commitment)
            .map_err(|error| anyhow!("invalid note commitment: {error}"))?;
        let leaf = zkapi_core::v2::note_leaf(
            note.note_id,
            &commitment,
            u128::from(note.deposit_amount),
            note.expiry,
        );
        match note.status {
            // Exits are leaf-bound: the leaf stays through a pending escape
            // and after close/claim until permissionless retirement.
            NOTE_STATUS_ACTIVE | NOTE_STATUS_PENDING | NOTE_STATUS_CLOSED => {
                current_leaves[note.note_id as usize] = leaf
            }
            NOTE_STATUS_RETIRED => {}
            other => return Err(anyhow!("unsupported Solana note status {other}")),
        }
    }

    let mirror = TreeMirror::from_snapshot(TreeMirrorSnapshot {
        next_note_id,
        current_leaves,
    })
    .map_err(|error| anyhow!(error))?;
    let expected = Felt252::try_from_bytes_be(vault.current_root)
        .map_err(|error| anyhow!("invalid vault root: {error}"))?;
    ensure!(
        mirror.root() == expected,
        "reconstructed Solana tree root does not match the finalized vault"
    );
    Ok(mirror)
}

fn decode_program_account<T: AccountDeserialize>(
    value: &Value,
    program_id: anchor_lang::prelude::Pubkey,
) -> anyhow::Result<T> {
    let owner = value["owner"]
        .as_str()
        .ok_or_else(|| anyhow!("account owner is missing"))?;
    ensure!(
        owner == program_id.to_string(),
        "account has a foreign owner"
    );
    let encoded = value["data"]
        .as_array()
        .and_then(|parts| parts.first())
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("account data is not base64"))?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .context("invalid base64 account data")?;
    let mut input = bytes.as_slice();
    T::try_deserialize(&mut input).context("Anchor account decode failed")
}

#[derive(Serialize)]
struct RpcRequest<'a> {
    jsonrpc: &'static str,
    id: u64,
    method: &'a str,
    params: Value,
}

#[derive(Deserialize)]
struct RpcResponse<T> {
    result: Option<T>,
    error: Option<RpcError>,
}

#[derive(Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

#[derive(Deserialize)]
struct RpcContext<T> {
    context: RpcSlot,
    value: T,
}

#[derive(Deserialize)]
struct RpcSlot {
    slot: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use anchor_lang::prelude::Pubkey;
    use zkapi_core::merkle::MerkleTree;

    fn vault(next_note_id: u32, current_root: Felt252) -> VaultState {
        VaultState {
            version: dagon_zkapi_vault::VAULT_VERSION,
            bump: 1,
            paused: false,
            authority: Pubkey::new_unique(),
            treasury: Pubkey::new_unique(),
            genesis_hash: [3; 32],
            chain_id: 0,
            protocol_binding: [0; 32],
            current_root: *current_root.as_bytes(),
            next_note_id,
            note_ttl: 86_400,
            challenge_period: 60,
            request_charge_cap: 1_000,
            total_credits: 2_000,
            state_signing_key_x: [1; 32],
            state_signing_key_y: [2; 32],
            clearance_signing_key_x: [3; 32],
            clearance_signing_key_y: [4; 32],
            paused_at: 0,
            last_pause_end: 0,
            total_paused_duration: 0,
            treasury_accrued: 0,
        }
    }

    fn note(vault: Pubkey, note_id: u32, status: u8) -> NoteState {
        NoteState {
            vault,
            note_id,
            commitment: *Felt252::from_u64(100 + u64::from(note_id)).as_bytes(),
            deposit_amount: 1_000,
            expiry: 1_800_000_000,
            status,
            bump: 1,
            claimable_after: 1_800_000_000,
            paused_offset: 0,
        }
    }

    #[test]
    fn account_snapshot_keeps_pending_and_closed_leaves_until_retired() {
        let address = Pubkey::new_unique();
        let notes = vec![
            note(address, 0, NOTE_STATUS_ACTIVE),
            note(address, 1, NOTE_STATUS_PENDING),
            note(address, 2, NOTE_STATUS_CLOSED),
            note(address, 3, NOTE_STATUS_RETIRED),
        ];
        let mut tree = MerkleTree::new();
        for note in &notes[..3] {
            tree.set_leaf(
                note.note_id,
                zkapi_core::v2::note_leaf(
                    note.note_id,
                    &Felt252::try_from_bytes_be(note.commitment).unwrap(),
                    1_000,
                    note.expiry,
                ),
            );
        }
        let vault = vault(4, tree.root());
        let mirror = mirror_from_accounts(address, &vault, notes).unwrap();
        assert_eq!(
            mirror.root(),
            Felt252::try_from_bytes_be(vault.current_root).unwrap()
        );
        assert_eq!(mirror.next_note_id(), 4);
        for note_id in 0..3 {
            assert!(!mirror.get_leaf(note_id).is_zero());
        }
        assert!(mirror.get_leaf(3).is_zero());
    }

    #[test]
    fn account_snapshot_rejects_duplicates_and_root_mismatches() {
        let address = Pubkey::new_unique();
        let first = note(address, 0, NOTE_STATUS_ACTIVE);
        let mut candidate = note(address, 1, 9);
        let empty = MerkleTree::new().root();
        let vault = vault(2, empty);
        assert!(mirror_from_accounts(address, &vault, vec![first.clone(), first]).is_err());
        assert!(mirror_from_accounts(address, &vault, vec![candidate.clone()]).is_err());
        // Status 3 is the reserved, removed two-phase "challenged" state.
        candidate.status = 3;
        assert!(mirror_from_accounts(address, &vault, vec![candidate.clone()]).is_err());
        // Pending and closed notes keep their leaf, so an empty root mismatches.
        for status in [NOTE_STATUS_PENDING, NOTE_STATUS_CLOSED] {
            candidate.status = status;
            assert!(mirror_from_accounts(address, &vault, vec![candidate.clone()]).is_err());
        }
        candidate.status = NOTE_STATUS_RETIRED;
        assert!(mirror_from_accounts(address, &vault, vec![candidate]).is_ok());
    }

    /// The poller accepts only the identity's vault with the profile's
    /// parameters, bound to the profile program.
    #[test]
    fn deployment_gate_requires_identity_genesis_and_profile_parameters() {
        let profile = SharedProfile::embedded();
        let program = Pubkey::new_from_array(profile.program_id());
        let address = Pubkey::new_unique();
        let genesis = [3; 32];
        let mut good = vault(0, MerkleTree::new().root());
        good.version = profile.vault.version;
        good.request_charge_cap = profile.vault.request_charge_cap;
        good.note_ttl = profile.vault.note_ttl_seconds;
        good.challenge_period = profile.vault.challenge_period_seconds;
        good.chain_id = solana_chain_id(&genesis);
        good.protocol_binding =
            *solana_deployment_binding(&program.to_bytes(), &address.to_bytes(), &genesis)
                .as_bytes();
        validate_deployment(program, address, &genesis, &profile.vault, &good).unwrap();
        assert!(validate_deployment(program, address, &[4; 32], &profile.vault, &good).is_err());
        let mutations: [fn(&mut VaultState); 6] = [
            |vault| vault.version += 1,
            |vault| vault.request_charge_cap += 1,
            |vault| vault.note_ttl -= 1,
            |vault| vault.challenge_period = 3_600,
            |vault| vault.chain_id += 1,
            |vault| vault.protocol_binding = [0; 32],
        ];
        for mutate in mutations {
            let mut changed = good.clone();
            mutate(&mut changed);
            assert!(
                validate_deployment(program, address, &genesis, &profile.vault, &changed).is_err()
            );
        }
    }
}
