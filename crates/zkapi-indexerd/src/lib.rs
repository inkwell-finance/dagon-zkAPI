//! Indexer: mirrors the Solana vault tree into a local Merkle view.
//!
//! The indexer rebuilds the complete current leaf vector from finalized vault
//! and note accounts and publishes it only when its root matches the vault. It
//! serves the whole-tree snapshot, the latest root and sibling paths.
//!
//! The indexer is NOT trusted. Incorrect paths only cause proof or tx failure.

pub mod http;
pub mod service;
pub mod solana_poller;
pub mod tree_mirror;

pub use http::{create_router, run_indexer, IndexerConfig};
pub use service::{
    IndexerService, NextNoteIdResponse, TreePathResponse, TreeRootResponse, TreeSnapshotResponse,
};
pub use solana_poller::{SolanaAccountPoller, SolanaPollerConfig};
pub use tree_mirror::TreeMirror;
