//! Solana bindings for the unchanged zkAPI v2 public statements.
//!
//! The v2 circuits deliberately remain chain-neutral. Solana deployment and
//! destination identities are compressed into the existing `chain_id`,
//! `contract_address`, and 20-byte `destination` fields with domain-separated
//! Keccak hashes. The on-chain program must reproduce these exact functions.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

use crate::Felt252;

/// Public statement for the Solana-only auxiliary Merkle transition proof.
///
/// The main request and withdrawal statements remain unchanged. This proof
/// lets the vault verify an insertion/removal with the same zkAPI-v2 Poseidon
/// tree without attempting that expensive hash computation inside SBF.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SolanaMerkleTransitionInputs {
    pub protocol_version: u16,
    #[serde(deserialize_with = "crate::serialization::deserialize_u64_or_decimal_string")]
    pub chain_id: u64,
    pub protocol_binding: Felt252,
    pub old_root: Felt252,
    pub new_root: Felt252,
    pub note_id: u32,
    pub commitment: Felt252,
    pub amount: u64,
    pub expiry: u64,
    pub inserting: bool,
}

impl SolanaMerkleTransitionInputs {
    pub fn to_field_elements(&self) -> [Felt252; 10] {
        [
            Felt252::from_u64(self.protocol_version as u64),
            Felt252::from_u64(self.chain_id),
            self.protocol_binding,
            self.old_root,
            self.new_root,
            Felt252::from_u64(self.note_id as u64),
            self.commitment,
            Felt252::from_u64(self.amount),
            Felt252::from_u64(self.expiry),
            Felt252::from_u64(self.inserting as u64),
        ]
    }
}

pub const SOLANA_CHAIN_ID_DOMAIN: &[u8] = b"dagon.zkapi.solana.chain-id.v1";
pub const SOLANA_DEPLOYMENT_DOMAIN: &[u8] = b"dagon.zkapi.solana.deployment.v1";
pub const SOLANA_DESTINATION_DOMAIN: &[u8] = b"dagon.zkapi.solana.destination.v1";

/// Derive the v2 `chain_id` from the cluster's complete 32-byte genesis hash.
///
/// Cluster labels such as `mainnet-beta` are not authoritative identities and
/// are intentionally excluded.
pub fn solana_chain_id(genesis_hash: &[u8; 32]) -> u64 {
    let mut hash = Keccak256::new();
    hash.update(SOLANA_CHAIN_ID_DOMAIN);
    hash.update(genesis_hash);
    let digest: [u8; 32] = hash.finalize().into();
    u64::from_be_bytes(digest[..8].try_into().expect("eight-byte prefix"))
}

/// Bind one program deployment into the v2 `contract_address` field.
///
/// The program ID alone is insufficient because one program can own multiple
/// independently configured vault-state PDAs. Including the genesis hash also
/// prevents the same addresses from being replayed on another cluster.
pub fn solana_deployment_binding(
    program_id: &[u8; 32],
    vault_state: &[u8; 32],
    genesis_hash: &[u8; 32],
) -> Felt252 {
    let mut payload = [0u8; 96];
    payload[..32].copy_from_slice(program_id);
    payload[32..64].copy_from_slice(vault_state);
    payload[64..].copy_from_slice(genesis_hash);
    hash_to_felt(SOLANA_DEPLOYMENT_DOMAIN, &payload)
}

/// Bind a full Solana account to the existing 20-byte withdrawal destination.
///
/// The program compares these bytes with the suffix of a domain-separated
/// Keccak digest of the actual writable destination account. This keeps the
/// selected Groth16 circuit and setup unchanged while retaining 160-bit
/// collision resistance.
pub fn solana_destination_binding(destination: &[u8; 32]) -> [u8; 20] {
    let mut hash = Keccak256::new();
    hash.update(SOLANA_DESTINATION_DOMAIN);
    hash.update(destination);
    let digest: [u8; 32] = hash.finalize().into();
    digest[12..].try_into().expect("twenty-byte suffix")
}

pub fn solana_destination_matches(binding: &[u8; 20], destination: &[u8; 32]) -> bool {
    binding == &solana_destination_binding(destination)
}

/// Rejection-sample Keccak output into the BN254 scalar field. This mirrors the
/// v2 request hashing rule and avoids a biased modular reduction.
fn hash_to_felt(domain: &[u8], payload: &[u8]) -> Felt252 {
    let mut counter = 0u32;
    loop {
        let mut hash = Keccak256::new();
        hash.update(domain);
        hash.update((payload.len() as u64).to_be_bytes());
        hash.update(payload);
        hash.update(counter.to_be_bytes());
        let digest: [u8; 32] = hash.finalize().into();
        if let Ok(felt) = Felt252::try_from_bytes_be(digest) {
            return felt;
        }
        counter = counter
            .checked_add(1)
            .expect("Solana deployment binding rejection counter exhausted");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct BindingVector {
        program_id: String,
        vault_state: String,
        genesis_hash: String,
        destination: String,
        chain_id: u64,
        deployment_binding: String,
        destination_binding: String,
    }

    fn bytes<const N: usize>(value: &str) -> [u8; N] {
        let value = value.strip_prefix("0x").unwrap_or(value);
        assert_eq!(value.len(), N * 2);
        let mut result = [0; N];
        for (index, byte) in result.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap();
        }
        result
    }

    #[test]
    fn bindings_are_domain_separated_and_stable() {
        let vector: BindingVector = serde_json::from_str(include_str!(
            "../../../../test-vectors/solana-bindings.json"
        ))
        .unwrap();
        let program = bytes(&vector.program_id);
        let vault = bytes(&vector.vault_state);
        let genesis = bytes(&vector.genesis_hash);
        let destination = bytes(&vector.destination);

        let chain_id = solana_chain_id(&genesis);
        let deployment = solana_deployment_binding(&program, &vault, &genesis);
        let destination_binding = solana_destination_binding(&destination);

        assert_eq!(chain_id, vector.chain_id);
        assert_eq!(
            deployment,
            Felt252::from_hex(&vector.deployment_binding).unwrap()
        );
        assert_eq!(
            destination_binding,
            bytes::<20>(&vector.destination_binding)
        );
        assert!(solana_destination_matches(
            &destination_binding,
            &destination
        ));
        assert!(!solana_destination_matches(&destination_binding, &[5; 32]));
    }

    #[test]
    fn every_deployment_component_is_bound() {
        let program = [1u8; 32];
        let vault = [2u8; 32];
        let genesis = [3u8; 32];
        let expected = solana_deployment_binding(&program, &vault, &genesis);

        assert_ne!(
            expected,
            solana_deployment_binding(&[9; 32], &vault, &genesis)
        );
        assert_ne!(
            expected,
            solana_deployment_binding(&program, &[9; 32], &genesis)
        );
        assert_ne!(
            expected,
            solana_deployment_binding(&program, &vault, &[9; 32])
        );
    }
}
