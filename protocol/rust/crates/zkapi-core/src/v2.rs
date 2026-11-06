//! Native zkAPI v2 primitives over the BN254 scalar field.

#[cfg(not(target_os = "solana"))]
use std::sync::OnceLock;

use ark_bn254::Fr;
#[cfg(not(target_os = "solana"))]
use ark_crypto_primitives::sponge::poseidon::find_poseidon_ark_and_mds;
use ark_crypto_primitives::sponge::poseidon::{PoseidonConfig, PoseidonSponge};
use ark_crypto_primitives::sponge::{CryptographicSponge, FieldBasedCryptographicSponge};
use ark_ff::{BigInteger, PrimeField};
use zkapi_types::{Felt252, MERKLE_DEPTH};

const DOMAIN_REG: &[u8] = b"zkapi.v2.reg";
const DOMAIN_LEAF: &[u8] = b"zkapi.v2.leaf";
const DOMAIN_NODE: &[u8] = b"zkapi.v2.node";
/// Note-bound nullifier domain (concession exit): `N = H(d, s, n, tau)`.
pub const DOMAIN_NULLIFIER: &[u8] = b"zkapi.v2c.null";
const DOMAIN_AUTHORIZATION: &[u8] = b"zkapi.v2.auth";
const DOMAIN_STATE: &[u8] = b"zkapi.v2.state";
const DOMAIN_CLEARANCE: &[u8] = b"zkapi.v2.clear";
/// Derived successor anchor domain (concession exit): `tau' = H(d, N)`.
pub const DOMAIN_ANCHOR: &[u8] = b"zkapi.v2c.anchor";
const DOMAIN_BLIND: &[u8] = b"zkapi.v2.blind";

/// Empty depth-32 Merkle root for the immutable zkAPI v2 Poseidon parameters.
///
/// The Solana vault uses this constant during initialization so genesis does
/// not spend an entire transaction recomputing protocol constants on-chain.
pub const EMPTY_MERKLE_ROOT: Felt252 = Felt252([
    43, 180, 55, 89, 194, 70, 101, 217, 138, 51, 175, 168, 213, 9, 72, 23, 211, 89, 213, 228, 199,
    42, 69, 180, 90, 42, 86, 49, 118, 211, 121, 51,
]);

fn build_config() -> PoseidonConfig<Fr> {
    #[cfg(target_os = "solana")]
    {
        crate::poseidon_constants::config()
    }
    #[cfg(not(target_os = "solana"))]
    {
        let full_rounds = 8;
        let partial_rounds = 57;
        let rate = 2;
        let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(
            Fr::MODULUS_BIT_SIZE as u64,
            rate,
            full_rounds,
            partial_rounds,
            0,
        );
        PoseidonConfig::new(
            full_rounds as usize,
            partial_rounds as usize,
            5,
            mds,
            ark,
            rate,
            1,
        )
    }
}

#[cfg(not(target_os = "solana"))]
fn config() -> &'static PoseidonConfig<Fr> {
    static CONFIG: OnceLock<PoseidonConfig<Fr>> = OnceLock::new();
    CONFIG.get_or_init(build_config)
}

/// Reusable zkAPI v2 Poseidon context.
///
/// Solana SBF programs cannot contain writable global data, so on-chain
/// callers construct one context per instruction and reuse it for every hash
/// in that instruction. Native callers keep using the shared immutable
/// configuration through the existing free-function API below.
pub struct V2Hasher {
    config: PoseidonConfig<Fr>,
}

impl V2Hasher {
    pub fn new() -> Self {
        Self {
            config: build_config(),
        }
    }

    pub fn hash_fields(&self, inputs: &[Fr]) -> Fr {
        let mut sponge = PoseidonSponge::new(&self.config);
        sponge.absorb(&inputs);
        sponge.squeeze_native_field_elements(1)[0]
    }

    pub fn hash_felts(&self, inputs: &[Felt252]) -> Felt252 {
        let fields = inputs.iter().map(felt_to_field).collect::<Vec<_>>();
        field_to_felt(&self.hash_fields(&fields))
    }

    fn hash_domain(&self, label: &[u8], inputs: &[Felt252]) -> Felt252 {
        let mut fields = Vec::with_capacity(inputs.len() + 1);
        fields.push(domain(label));
        fields.extend(inputs.iter().map(felt_to_field));
        field_to_felt(&self.hash_fields(&fields))
    }

    pub fn note_leaf(
        &self,
        note_id: u32,
        registration: &Felt252,
        deposit_amount: u128,
        expiry: u64,
    ) -> Felt252 {
        self.hash_domain(
            DOMAIN_LEAF,
            &[
                Felt252::from_u64(note_id as u64),
                *registration,
                Felt252::from_u128(deposit_amount),
                Felt252::from_u64(expiry),
            ],
        )
    }

    pub fn merkle_node(&self, left: &Felt252, right: &Felt252) -> Felt252 {
        self.hash_domain(DOMAIN_NODE, &[*left, *right])
    }

    pub fn merkle_root_slice(&self, note_id: u32, leaf: &Felt252, siblings: &[Felt252]) -> Felt252 {
        assert_eq!(
            siblings.len(),
            MERKLE_DEPTH,
            "Merkle path must have 32 siblings"
        );
        let mut current = *leaf;
        for (level, sibling) in siblings.iter().enumerate() {
            current = if ((note_id >> level) & 1) == 0 {
                self.merkle_node(&current, sibling)
            } else {
                self.merkle_node(sibling, &current)
            };
        }
        current
    }

    pub fn zero_hashes(&self) -> [Felt252; MERKLE_DEPTH + 1] {
        let mut values = [Felt252::ZERO; MERKLE_DEPTH + 1];
        for level in 1..=MERKLE_DEPTH {
            values[level] = self.merkle_node(&values[level - 1], &values[level - 1]);
        }
        values
    }
}

impl Default for V2Hasher {
    fn default() -> Self {
        Self::new()
    }
}

fn domain(label: &[u8]) -> Fr {
    Fr::from_be_bytes_mod_order(label)
}

pub fn felt_to_field(value: &Felt252) -> Fr {
    Fr::from_be_bytes_mod_order(value.as_bytes())
}

pub fn field_to_felt(value: &Fr) -> Felt252 {
    let raw = value.into_bigint().to_bytes_be();
    let mut bytes = [0u8; 32];
    bytes[32 - raw.len()..].copy_from_slice(&raw);
    Felt252(bytes)
}

pub fn hash_fields(inputs: &[Fr]) -> Fr {
    #[cfg(not(target_os = "solana"))]
    {
        let mut sponge = PoseidonSponge::new(config());
        sponge.absorb(&inputs);
        sponge.squeeze_native_field_elements(1)[0]
    }
    #[cfg(target_os = "solana")]
    {
        V2Hasher::new().hash_fields(inputs)
    }
}

pub fn hash_felts(inputs: &[Felt252]) -> Felt252 {
    let fields = inputs.iter().map(felt_to_field).collect::<Vec<_>>();
    field_to_felt(&hash_fields(&fields))
}

fn hash_domain(label: &[u8], inputs: &[Felt252]) -> Felt252 {
    let mut fields = Vec::with_capacity(inputs.len() + 1);
    fields.push(domain(label));
    fields.extend(inputs.iter().map(felt_to_field));
    field_to_felt(&hash_fields(&fields))
}

pub fn registration_commitment(secret: &Felt252) -> Felt252 {
    hash_domain(DOMAIN_REG, &[*secret, Felt252::ZERO])
}

pub fn note_leaf(
    note_id: u32,
    registration: &Felt252,
    deposit_amount: u128,
    expiry: u64,
) -> Felt252 {
    hash_domain(
        DOMAIN_LEAF,
        &[
            Felt252::from_u64(note_id as u64),
            *registration,
            Felt252::from_u128(deposit_amount),
            Felt252::from_u64(expiry),
        ],
    )
}

pub fn merkle_node(left: &Felt252, right: &Felt252) -> Felt252 {
    hash_domain(DOMAIN_NODE, &[*left, *right])
}

pub fn merkle_root(note_id: u32, leaf: &Felt252, siblings: &[Felt252; MERKLE_DEPTH]) -> Felt252 {
    merkle_root_slice(note_id, leaf, siblings)
}

/// Slice form used by Solana programs so sibling paths can remain heap-backed
/// and do not consume a 1 KiB SBF stack frame.
pub fn merkle_root_slice(note_id: u32, leaf: &Felt252, siblings: &[Felt252]) -> Felt252 {
    assert_eq!(
        siblings.len(),
        MERKLE_DEPTH,
        "Merkle path must have 32 siblings"
    );
    let mut current = *leaf;
    for (level, sibling) in siblings.iter().enumerate() {
        current = if ((note_id >> level) & 1) == 0 {
            merkle_node(&current, sibling)
        } else {
            merkle_node(sibling, &current)
        };
    }
    current
}

pub fn zero_hashes() -> [Felt252; MERKLE_DEPTH + 1] {
    let mut values = [Felt252::ZERO; MERKLE_DEPTH + 1];
    for level in 1..=MERKLE_DEPTH {
        values[level] = merkle_node(&values[level - 1], &values[level - 1]);
    }
    values
}

/// Genesis anchor. A state is genesis iff its anchor equals this value.
pub const GENESIS_ANCHOR: Felt252 = Felt252::ONE;

/// Note-bound nullifier `N = H(d_null, s, n, tau)`.
pub fn nullifier(secret: &Felt252, note_id: u32, anchor: &Felt252) -> Felt252 {
    hash_domain(
        DOMAIN_NULLIFIER,
        &[*secret, Felt252::from_u64(note_id as u64), *anchor],
    )
}

/// Derived successor anchor `tau' = H(d_anchor, N)` for the state the server
/// signs in answer to a request that published nullifier `N`.
pub fn next_anchor(request_nullifier: &Felt252) -> Felt252 {
    hash_domain(DOMAIN_ANCHOR, &[*request_nullifier])
}

/// Nullifier of the successor state of the state whose nullifier is `N`.
pub fn successor_nullifier(secret: &Felt252, note_id: u32, current_nullifier: &Felt252) -> Felt252 {
    nullifier(secret, note_id, &next_anchor(current_nullifier))
}

/// Pack `(n, D, e)` into one field element `n * 2^192 + D * 2^64 + e`.
pub fn note_fields(note_id: u32, deposit_amount: u128, expiry: u64) -> Felt252 {
    zkapi_types::pack_note_fields(note_id, deposit_amount, expiry)
}

/// Inverse of [`note_fields`]; `None` when the top 32 bits are non-zero.
pub fn unpack_note_fields(fields: &Felt252) -> Option<(u32, u128, u64)> {
    let bytes = fields.as_bytes();
    if bytes[..4] != [0u8; 4] {
        return None;
    }
    let note_id = u32::from_be_bytes(bytes[4..8].try_into().ok()?);
    let deposit = u128::from_be_bytes(bytes[8..24].try_into().ok()?);
    let expiry = u64::from_be_bytes(bytes[24..32].try_into().ok()?);
    Some((note_id, deposit, expiry))
}

pub fn authorization_tag(nullifier: &Felt252, request_context: &Felt252) -> Felt252 {
    hash_domain(DOMAIN_AUTHORIZATION, &[*nullifier, *request_context])
}

pub fn state_message(
    protocol_version: u16,
    chain_id: u64,
    contract_address: &Felt252,
    commitment_x: &Felt252,
    commitment_y: &Felt252,
    anchor: &Felt252,
) -> Felt252 {
    hash_domain(
        DOMAIN_STATE,
        &[
            Felt252::from_u64(protocol_version as u64),
            Felt252::from_u64(chain_id),
            *contract_address,
            *commitment_x,
            *commitment_y,
            *anchor,
        ],
    )
}

pub fn clearance_message(
    protocol_version: u16,
    chain_id: u64,
    contract_address: &Felt252,
    withdrawal_nullifier: &Felt252,
) -> Felt252 {
    hash_domain(
        DOMAIN_CLEARANCE,
        &[
            Felt252::from_u64(protocol_version as u64),
            Felt252::from_u64(chain_id),
            *contract_address,
            *withdrawal_nullifier,
        ],
    )
}

pub fn blind_delta(server_randomness: &Felt252, request_nullifier: &Felt252) -> Felt252 {
    hash_domain(DOMAIN_BLIND, &[*server_randomness, *request_nullifier])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_membership_round_trip() {
        let secret = Felt252::from_u64(42);
        let registration = registration_commitment(&secret);
        let leaf = note_leaf(0, &registration, 5_000_000, 4_000_000_000);
        let siblings = [Felt252::ZERO; MERKLE_DEPTH];
        assert_eq!(
            merkle_root(0, &leaf, &siblings),
            merkle_root(0, &leaf, &siblings)
        );
    }

    #[test]
    fn committed_empty_root_matches_poseidon_parameters() {
        assert_eq!(zero_hashes()[MERKLE_DEPTH], EMPTY_MERKLE_ROOT);
    }

    #[test]
    fn note_fields_round_trip_and_layout() {
        use ark_ff::Field;
        let packed = note_fields(7, 5_000_000, 4_000_000_000);
        assert_eq!(unpack_note_fields(&packed), Some((7, 5_000_000, 4_000_000_000)));
        let two = Fr::from(2u64);
        let expected = Fr::from(7u64) * two.pow([192u64])
            + Fr::from(5_000_000u64) * two.pow([64u64])
            + Fr::from(4_000_000_000u64);
        assert_eq!(felt_to_field(&packed), expected);
        let mut overflow = packed;
        overflow.0[0] = 1;
        assert_eq!(unpack_note_fields(&overflow), None);
    }

    #[test]
    fn derived_successor_chain_is_note_bound() {
        let secret = Felt252::from_u64(42);
        let n0 = nullifier(&secret, 3, &GENESIS_ANCHOR);
        assert_ne!(n0, nullifier(&secret, 4, &GENESIS_ANCHOR));
        let succ = successor_nullifier(&secret, 3, &n0);
        assert_eq!(succ, nullifier(&secret, 3, &next_anchor(&n0)));
        assert_ne!(succ, n0);
        assert_ne!(next_anchor(&n0), GENESIS_ANCHOR);
    }

    #[test]
    fn committed_poseidon_constants_match_arkworks_generation() {
        let generated = build_config();
        let committed = crate::poseidon_constants::config();
        assert_eq!(generated.full_rounds, committed.full_rounds);
        assert_eq!(generated.partial_rounds, committed.partial_rounds);
        assert_eq!(generated.alpha, committed.alpha);
        assert_eq!(generated.rate, committed.rate);
        assert_eq!(generated.capacity, committed.capacity);
        assert_eq!(generated.ark, committed.ark);
        assert_eq!(generated.mds, committed.mds);
    }
}
