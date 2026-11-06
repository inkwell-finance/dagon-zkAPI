//! Server-side logic for the Dagon zkAPI protocol on Solana.
//!
//! This crate implements proof verification, nullifier storage, prompt-private
//! lease issuance and settlement against Pyth SOL/USD quotes, Baby-JubJub
//! Schnorr signing, the concession-exit challenger, and the HTTP routes.

#[cfg(any(test, feature = "adversary"))]
pub mod adversary;
pub mod billing;
mod checkpoint;
pub mod config;
pub mod dashboard;
pub mod error;
pub mod ledger_challenge_service;
pub mod nullifier_store;
pub mod oa_org;
pub mod openrouter;
pub mod pricing;
#[path = "processor_v2.rs"]
pub mod processor;
pub mod routes;
pub mod settlement;
#[path = "signer_v2.rs"]
pub mod signer;
pub mod sol_billing;
pub mod successor;
pub mod testnet_auth;
pub mod watcher;
mod writer_lock;

#[cfg(test)]
pub(crate) mod test_support;

#[cfg(test)]
mod note_binding;
