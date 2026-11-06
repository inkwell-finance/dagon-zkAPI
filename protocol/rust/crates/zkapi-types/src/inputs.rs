//! Public input structs for request and withdrawal proofs.
//!
//! Field ordering matches the Groth16 circuits and Solidity Types.sol.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

use crate::Felt252;

/// Public statement verified for every v2 API request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequestPublicInputsV2 {
    pub protocol_version: u16,
    #[serde(deserialize_with = "crate::serialization::deserialize_u64_or_decimal_string")]
    pub chain_id: u64,
    pub contract_address: Felt252,
    pub active_root: Felt252,
    pub state_signing_key_x: Felt252,
    pub state_signing_key_y: Felt252,
    pub request_time: u64,
    pub solvency_bound: u128,
    pub request_nullifier: Felt252,
    pub authorization_tag: Felt252,
    pub anonymous_commitment_x: Felt252,
    pub anonymous_commitment_y: Felt252,
}

impl RequestPublicInputsV2 {
    pub fn to_field_elements(&self) -> [Felt252; 12] {
        [
            Felt252::from_u64(self.protocol_version as u64),
            Felt252::from_u64(self.chain_id),
            self.contract_address,
            self.active_root,
            self.state_signing_key_x,
            self.state_signing_key_y,
            Felt252::from_u64(self.request_time),
            Felt252::from_u128(self.solvency_bound),
            self.request_nullifier,
            self.authorization_tag,
            self.anonymous_commitment_x,
            self.anonymous_commitment_y,
        ]
    }
}

/// Public statement verified for a v2 mutual close or concession escape.
///
/// Exits are leaf-bound and root-free: the vault compares `registration` and
/// `note_fields` with the note it stores, so no Merkle root is published.
/// Escapes (`has_clearance == false`) also publish the successor nullifier
/// `next_nullifier` and the declared concession `conceded`; mutual closes
/// publish zero for both.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WithdrawalPublicInputsV2 {
    pub protocol_version: u16,
    #[serde(deserialize_with = "crate::serialization::deserialize_u64_or_decimal_string")]
    pub chain_id: u64,
    pub contract_address: Felt252,
    pub registration: Felt252,
    pub state_signing_key_x: Felt252,
    pub state_signing_key_y: Felt252,
    pub clearance_signing_key_x: Felt252,
    pub clearance_signing_key_y: Felt252,
    pub note_id: u32,
    pub deposit_amount: u128,
    #[serde(deserialize_with = "crate::serialization::deserialize_u64_or_decimal_string")]
    pub expiry_ts: u64,
    pub final_balance: u128,
    pub destination: [u8; 20],
    pub withdrawal_nullifier: Felt252,
    pub has_clearance: bool,
    pub next_nullifier: Felt252,
    pub conceded: u128,
    #[serde(deserialize_with = "crate::serialization::deserialize_u64_or_decimal_string")]
    pub valid_until: u64,
}

impl WithdrawalPublicInputsV2 {
    pub const NUM_PUBLIC_INPUTS: usize = 16;

    pub fn destination_field(&self) -> Felt252 {
        let mut bytes = [0u8; 32];
        bytes[12..].copy_from_slice(&self.destination);
        Felt252(bytes)
    }

    /// `note_id * 2^192 + deposit_amount * 2^64 + expiry_ts`.
    pub fn note_fields(&self) -> Felt252 {
        pack_note_fields(self.note_id, self.deposit_amount, self.expiry_ts)
    }

    pub fn to_field_elements(&self) -> [Felt252; 16] {
        [
            Felt252::from_u64(self.protocol_version as u64),
            Felt252::from_u64(self.chain_id),
            self.contract_address,
            self.registration,
            self.state_signing_key_x,
            self.state_signing_key_y,
            self.clearance_signing_key_x,
            self.clearance_signing_key_y,
            self.note_fields(),
            Felt252::from_u128(self.final_balance),
            self.destination_field(),
            self.withdrawal_nullifier,
            Felt252::from_u64(self.has_clearance as u64),
            self.next_nullifier,
            Felt252::from_u128(self.conceded),
            Felt252::from_u64(self.valid_until),
        ]
    }
}

/// Pack `(n, D, e)` into `n * 2^192 + D * 2^64 + e` (big-endian bytes 4..32).
pub fn pack_note_fields(note_id: u32, deposit_amount: u128, expiry_ts: u64) -> Felt252 {
    let mut bytes = [0u8; 32];
    bytes[4..8].copy_from_slice(&note_id.to_be_bytes());
    bytes[8..24].copy_from_slice(&deposit_amount.to_be_bytes());
    bytes[24..32].copy_from_slice(&expiry_ts.to_be_bytes());
    Felt252(bytes)
}

/// Hash the exact client request id and payload digest into the private context
/// that the request proof binds through `authorization_tag`.
pub fn canonical_request_context(client_request_id: &str, payload_hash: &Felt252) -> Felt252 {
    let id = client_request_id.as_bytes();
    let mut bytes = Vec::with_capacity(8 + id.len() + 32);
    bytes.extend_from_slice(&(id.len() as u64).to_be_bytes());
    bytes.extend_from_slice(id);
    bytes.extend_from_slice(payload_hash.as_bytes());
    hash_bytes_to_felt(b"zkapi.v2.request-context", &bytes)
}

pub fn canonical_payload_hash(payload: &[u8]) -> Felt252 {
    hash_bytes_to_felt(b"zkapi.payload.v1", payload)
}

pub fn canonical_response_hash(payload: &[u8]) -> Felt252 {
    hash_bytes_to_felt(b"zkapi.response.v1", payload)
}

fn hash_bytes_to_felt(domain: &[u8], payload: &[u8]) -> Felt252 {
    let mut counter = 0u32;
    loop {
        let mut h = Keccak256::new();
        h.update(domain);
        h.update((payload.len() as u64).to_be_bytes());
        h.update(payload);
        h.update(counter.to_be_bytes());
        let digest: [u8; 32] = h.finalize().into();
        if let Ok(felt) = Felt252::try_from_bytes_be(digest) {
            return felt;
        }
        counter = counter
            .checked_add(1)
            .expect("hash-to-felt counter exhausted");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_and_response_hashes_are_domain_separated() {
        let payload = b"{\"ok\":true}";
        assert_eq!(
            canonical_payload_hash(payload),
            canonical_payload_hash(payload)
        );
        assert_eq!(
            canonical_response_hash(payload),
            canonical_response_hash(payload)
        );
        assert_ne!(
            canonical_payload_hash(payload),
            canonical_response_hash(payload)
        );
        assert_ne!(
            canonical_payload_hash(payload),
            canonical_payload_hash(b"other")
        );
    }
}
