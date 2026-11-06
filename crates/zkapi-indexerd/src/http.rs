//! Axum HTTP server for the tree indexer.

use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use axum::extract::{Path as UrlPath, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use dagon_zkapi_profile::{NetworkIdentity, SharedProfile};
use zkapi_types::Felt252;

use crate::service::{
    IndexerService, NextNoteIdResponse, TreePathResponse, TreeRootResponse, TreeSnapshotResponse,
};
use crate::solana_poller::{spawn_solana_account_poller, SolanaAccountPoller, SolanaPollerConfig};
use crate::tree_mirror::TreeMirror;

/// Runtime configuration for the indexer HTTP server.
#[derive(Debug, Clone)]
pub struct IndexerConfig {
    pub listen_addr: String,
    pub poll_interval_ms: u64,
    pub ledger: SolanaPollerConfig,
}

impl IndexerConfig {
    /// The embedded profile's vault under the network identity at `path`.
    pub fn from_identity_file(
        path: &Path,
        rpc_url: String,
        listen_addr: String,
        poll_interval_ms: u64,
    ) -> anyhow::Result<Self> {
        let profile = SharedProfile::embedded();
        let identity = NetworkIdentity::load(path)?.resolve(profile)?;
        Ok(Self {
            listen_addr,
            poll_interval_ms,
            ledger: SolanaPollerConfig::from_identity(rpc_url, profile, &identity),
        })
    }
}

type AppState = Arc<IndexerService>;

/// Check the RPC's cluster, then serve the tree while polling the vault.
pub async fn run_indexer(config: IndexerConfig) -> anyhow::Result<()> {
    anyhow::ensure!(
        config.poll_interval_ms > 0,
        "poll interval must be positive"
    );
    let poller = SolanaAccountPoller::new(config.ledger)?;
    poller.assert_cluster().await?;
    let service = Arc::new(IndexerService::new_syncing(Arc::new(RwLock::new(
        TreeMirror::new(),
    ))));
    spawn_solana_account_poller(
        service.clone(),
        poller,
        Duration::from_millis(config.poll_interval_ms),
    );

    let router = create_router(service);
    let listener = tokio::net::TcpListener::bind(&config.listen_addr).await?;
    tracing::info!("Indexer listening on {}", config.listen_addr);
    axum::serve(listener, router).await?;
    Ok(())
}

pub fn create_router(service: Arc<IndexerService>) -> Router {
    Router::new()
        .route("/health", get(handle_health))
        .route("/v1/tree/root", get(handle_root))
        .route("/v1/tree/next-note-id", get(handle_next_note_id))
        .route("/v1/tree/snapshot", get(handle_snapshot))
        .route("/v1/tree/notes/{note_id}/path", get(handle_note_path))
        .route("/v1/tree/notes/{note_id}/zero-path", get(handle_zero_path))
        .with_state(service)
}

async fn handle_health(State(service): State<AppState>) -> Response {
    if service.is_ready() {
        Json(serde_json::json!({ "status": "ok" })).into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "status": "syncing" })),
        )
            .into_response()
    }
}

async fn handle_root(
    State(service): State<AppState>,
) -> Result<Json<TreeRootResponse>, StatusCode> {
    ensure_ready(&service)?;
    Ok(Json(TreeRootResponse {
        root: service.get_root(),
    }))
}

/// Privacy-safe whole-tree snapshot. The same payload is returned regardless of
/// which note the caller cares about, so the untrusted indexer never learns it.
async fn handle_snapshot(
    State(service): State<AppState>,
) -> Result<Json<TreeSnapshotResponse>, StatusCode> {
    ensure_ready(&service)?;
    Ok(Json(service.get_snapshot()))
}

async fn handle_next_note_id(
    State(service): State<AppState>,
) -> Result<Json<NextNoteIdResponse>, StatusCode> {
    ensure_ready(&service)?;
    Ok(Json(NextNoteIdResponse {
        next_note_id: service.get_next_note_id(),
    }))
}

async fn handle_note_path(
    State(service): State<AppState>,
    UrlPath(note_id): UrlPath<u32>,
) -> Result<Json<TreePathResponse>, StatusCode> {
    ensure_ready(&service)?;
    Ok(Json(TreePathResponse {
        note_id,
        leaf: service.get_leaf(note_id),
        siblings: service.get_note_path(note_id).to_vec(),
    }))
}

async fn handle_zero_path(
    State(service): State<AppState>,
    UrlPath(note_id): UrlPath<u32>,
) -> Result<Json<TreePathResponse>, StatusCode> {
    ensure_ready(&service)?;
    Ok(Json(TreePathResponse {
        note_id,
        leaf: Felt252::ZERO,
        siblings: service.get_zero_path(note_id).to_vec(),
    }))
}

fn ensure_ready(service: &IndexerService) -> Result<(), StatusCode> {
    service
        .is_ready()
        .then_some(())
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::tree_mirror::TreeMirrorSnapshot;

    /// A ready service holding `count` deposited leaves.
    fn service_with_leaves(count: u32) -> Arc<IndexerService> {
        let service = Arc::new(IndexerService::new_syncing(Arc::new(RwLock::new(
            TreeMirror::new(),
        ))));
        let current_leaves = (0..count)
            .map(|note_id| {
                zkapi_core::leaf::compute_note_leaf(
                    note_id,
                    &Felt252::from_u64(100 + note_id as u64),
                    100,
                    1_700_000_000,
                )
            })
            .collect();
        service.replace(
            TreeMirror::from_snapshot(TreeMirrorSnapshot {
                next_note_id: count,
                current_leaves,
            })
            .unwrap(),
        );
        service
    }

    #[tokio::test]
    async fn test_zero_path_endpoint_returns_zero_leaf() {
        let service = service_with_leaves(1);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = create_router(service);
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let response = reqwest::get(format!("http://{addr}/v1/tree/notes/0/zero-path"))
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json::<TreePathResponse>()
            .await
            .unwrap();

        assert_eq!(response.note_id, 0);
        assert_eq!(response.leaf, Felt252::ZERO);
    }

    #[tokio::test]
    async fn snapshot_lets_a_client_rebuild_paths_locally() {
        use zkapi_core::merkle::MerkleTree;

        let service = service_with_leaves(3);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = create_router(service.clone());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let snapshot = reqwest::get(format!("http://{addr}/v1/tree/snapshot"))
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json::<TreeSnapshotResponse>()
            .await
            .unwrap();

        assert_eq!(snapshot.leaves.len() as u32, snapshot.next_note_id);

        // A client rebuilds the whole tree from the snapshot alone — no per-slot
        // request — and recovers the root plus any sibling path locally.
        let mut local = MerkleTree::new();
        for leaf in &snapshot.leaves {
            local.insert(*leaf);
        }
        assert_eq!(local.root(), snapshot.root);
        assert_eq!(
            local.get_siblings(1).to_vec(),
            service.get_note_path(1).to_vec(),
            "locally derived path must match the indexer's per-slot path"
        );

        server.abort();
    }

    #[tokio::test]
    async fn syncing_indexer_does_not_serve_partial_tree_data() {
        let service = Arc::new(IndexerService::new_syncing(Arc::new(RwLock::new(
            TreeMirror::new(),
        ))));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = create_router(service.clone());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let health = reqwest::get(format!("http://{addr}/health")).await.unwrap();
        assert_eq!(health.status(), StatusCode::SERVICE_UNAVAILABLE);
        let root = reqwest::get(format!("http://{addr}/v1/tree/root"))
            .await
            .unwrap();
        assert_eq!(root.status(), StatusCode::SERVICE_UNAVAILABLE);

        service.mark_ready();
        let root = reqwest::get(format!("http://{addr}/v1/tree/root"))
            .await
            .unwrap();
        assert_eq!(root.status(), StatusCode::OK);
    }
}
