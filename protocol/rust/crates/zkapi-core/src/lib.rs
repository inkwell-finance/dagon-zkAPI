#![allow(unexpected_cfgs)]

//! BN254 Poseidon hashing, Merkle trees, and note/state helpers for zkAPI v2.

pub mod leaf;
pub mod merkle;
pub mod nullifier;
#[cfg(any(target_os = "solana", test))]
mod poseidon_constants;
pub mod v2;

pub use merkle::MerkleTree;
