//! Finalized Solana account-snapshot poller for the Dagon zkAPI indexer.
//!
//! Closed notes are closed as Solana accounts, while active and pending notes
//! remain as PDAs. Rebuilding the tree from those accounts plus `next_note_id`
//! therefore yields the complete current leaf vector without trusting event
//! history. A snapshot is published only when its Merkle root exactly matches
//! the finalized vault account.

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anchor_lang::{AccountDeserialize, Space};
use anyhow::{anyhow, ensure, Context};
use base64::Engine;
use dagon_zkapi_vault::{
    NoteState, VaultState, NOTE_STATUS_ACTIVE, NOTE_STATUS_CLOSED, NOTE_STATUS_PENDING,
    NOTE_STATUS_RETIRED, VAULT_VERSION,
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
    pub program_id: String,
    pub vault_state: String,
}

pub struct SolanaAccountPoller {
    client: Client,
    rpc_url: String,
    program_id: anchor_lang::prelude::Pubkey,
    vault_state: anchor_lang::prelude::Pubkey,
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
        let program_id = anchor_lang::prelude::Pubkey::from_str(&config.program_id)
            .context("invalid Solana program ID")?;
        let vault_state = anchor_lang::prelude::Pubkey::from_str(&config.vault_state)
            .context("invalid Solana vault-state address")?;
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            client,
            rpc_url: config.rpc_url,
            program_id,
            vault_state,
        })
    }

    pub async fn poll_once(&self, service: &IndexerService) -> anyhow::Result<usize> {
        let (notes_slot, notes) = self.fetch_notes().await?;
        let (_vault_slot, vault) = self.fetch_vault(notes_slot).await?;
        validate_deployment(self.program_id, self.vault_state, &vault)?;
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

pub fn spawn_solana_account_poller(
    service: Arc<IndexerService>,
    config: SolanaPollerConfig,
    interval: Duration,
) {
    tokio::spawn(async move {
        let poller = match SolanaAccountPoller::new(config) {
            Ok(poller) => poller,
            Err(error) => {
                tracing::error!(%error, "failed to initialize Solana indexer poller");
                return;
            }
        };
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
    vault: &VaultState,
) -> anyhow::Result<()> {
    ensure!(
        vault.version == VAULT_VERSION,
        "unsupported Solana vault version"
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
            version: VAULT_VERSION,
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
}
