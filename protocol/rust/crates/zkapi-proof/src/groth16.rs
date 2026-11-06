//! Compact zkAPI v2 request proof over BN254.
//!
//! The circuit uses Poseidon over the BN254 scalar field, a note-bound
//! Baby-JubJub Pedersen balance commitment, and a Poseidon-
//! challenged Schnorr state signature. Exact balance, note identity, expiry,
//! state anchor, and server signature stay private. The request context is
//! bound through a public authorization tag while the state nullifier remains
//! independent of the payload, so one state cannot authorize two requests.

use std::ops::Not;
use std::sync::OnceLock;

use ark_bn254::{Bn254, Fr as CircuitField};
use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
use ark_crypto_primitives::sponge::poseidon::{
    find_poseidon_ark_and_mds, PoseidonConfig, PoseidonSponge,
};
use ark_crypto_primitives::sponge::{CryptographicSponge, FieldBasedCryptographicSponge};
use ark_ec::twisted_edwards::TECurveConfig;
use ark_ec::{AdditiveGroup, AffineRepr, CurveConfig, CurveGroup, PrimeGroup};
use ark_ed_on_bn254::{
    constraints::EdwardsVar, EdwardsAffine, EdwardsConfig, EdwardsProjective,
    Fq as EdwardsBaseField, Fr as EdwardsScalarField,
};
use ark_ff::{BigInteger, Field, PrimeField, UniformRand};
use ark_groth16::{prepare_verifying_key, Groth16, Proof, ProvingKey, VerifyingKey};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::cmp::CmpGadget;
use ark_r1cs_std::convert::ToBitsGadget;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::groups::CurveVar;
use ark_r1cs_std::prelude::{UInt128, UInt32, UInt64};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_std::rand::{CryptoRng, RngCore};
use sha3::{Digest, Keccak256};

use crate::circom_reduction::CircomReduction;

pub const REQUEST_PUBLIC_INPUTS: usize = 12;
pub const WITHDRAWAL_PUBLIC_INPUTS: usize = 16;
pub const SOLANA_TRANSITION_PUBLIC_INPUTS: usize = 10;
pub const REQUEST_MERKLE_DEPTH: usize = 32;

const DOMAIN_REG: &[u8] = b"zkapi.v2.reg";
const DOMAIN_LEAF: &[u8] = b"zkapi.v2.leaf";
const DOMAIN_NODE: &[u8] = b"zkapi.v2.node";
const DOMAIN_NULLIFIER: &[u8] = zkapi_core::v2::DOMAIN_NULLIFIER;
const DOMAIN_ANCHOR: &[u8] = zkapi_core::v2::DOMAIN_ANCHOR;
const DOMAIN_AUTHORIZATION: &[u8] = b"zkapi.v2.auth";
const DOMAIN_STATE: &[u8] = b"zkapi.v2.state";
const DOMAIN_CLEARANCE: &[u8] = b"zkapi.v2.clear";
const DOMAIN_SIGNATURE: &[u8] = b"zkapi.v2.sig";

pub(crate) fn poseidon_config() -> &'static PoseidonConfig<CircuitField> {
    static CONFIG: OnceLock<PoseidonConfig<CircuitField>> = OnceLock::new();
    CONFIG.get_or_init(|| {
        let full_rounds = 8;
        let partial_rounds = 57;
        let rate = 2;
        let (ark, mds) = find_poseidon_ark_and_mds::<CircuitField>(
            CircuitField::MODULUS_BIT_SIZE as u64,
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
    })
}

pub fn poseidon_hash(inputs: &[CircuitField]) -> CircuitField {
    let mut sponge = PoseidonSponge::new(poseidon_config());
    sponge.absorb(&inputs);
    sponge.squeeze_native_field_elements(1)[0]
}

fn poseidon_hash_var(
    cs: ConstraintSystemRef<CircuitField>,
    inputs: &[FpVar<CircuitField>],
) -> Result<FpVar<CircuitField>, SynthesisError> {
    let mut sponge = PoseidonSpongeVar::new(cs, poseidon_config());
    sponge.absorb(&inputs)?;
    Ok(sponge.squeeze_field_elements(1)?[0].clone())
}

fn domain(label: &[u8]) -> CircuitField {
    CircuitField::from_be_bytes_mod_order(label)
}

fn domain_var(label: &[u8]) -> FpVar<CircuitField> {
    FpVar::Constant(domain(label))
}

/// Independently derived blinding generator. Its discrete logarithm relative
/// to the standard Baby-JubJub generator is not known.
pub fn balance_blinding_generator() -> EdwardsProjective {
    static GENERATOR: OnceLock<EdwardsProjective> = OnceLock::new();
    *GENERATOR.get_or_init(|| derive_generator(b"zkapi.v2.balance.blinding.generator"))
}

/// Independent third Pedersen generator for the private active-note leaf.
/// Do not derive this as a known scalar multiple of G or H: that would let
/// a client absorb a different note binding into the balance or blinding.
pub fn note_binding_generator() -> EdwardsProjective {
    static GENERATOR: OnceLock<EdwardsProjective> = OnceLock::new();
    *GENERATOR.get_or_init(|| derive_generator(b"zkapi.v2.note-binding.generator.v1"))
}

fn derive_generator(label: &[u8]) -> EdwardsProjective {
    for counter in 0u32..u32::MAX {
        let mut digest = Keccak256::new();
        digest.update(label);
        digest.update(counter.to_be_bytes());
        let x = EdwardsBaseField::from_be_bytes_mod_order(&digest.finalize());
        let x_squared = x.square();
        let numerator = EdwardsBaseField::ONE - x_squared;
        let denominator = EdwardsBaseField::ONE - (EdwardsConfig::COEFF_D * x_squared);
        let Some(denominator_inverse) = denominator.inverse() else {
            continue;
        };
        let Some(mut y) = (numerator * denominator_inverse).sqrt() else {
            continue;
        };
        if y.into_bigint().is_odd() {
            y = -y;
        }
        let point = EdwardsAffine::new_unchecked(x, y)
            .mul_bigint(EdwardsConfig::COFACTOR)
            .into_affine();
        if !point.is_zero() && point.is_in_correct_subgroup_assuming_on_curve() {
            return point.into_group();
        }
    }
    unreachable!("hash-to-curve counter exhausted")
}

/// C = balance*G + blinding*H + note_leaf*J. The full canonical field
/// representation of the leaf is multiplied by J (implicitly modulo its
/// prime subgroup order), identically to the circuit's bit decomposition.
pub fn balance_commitment(
    balance: u128,
    blinding: EdwardsScalarField,
    note_leaf: CircuitField,
) -> EdwardsProjective {
    EdwardsProjective::generator().mul_bigint(EdwardsScalarField::from(balance).into_bigint())
        + balance_blinding_generator().mul_bigint(blinding.into_bigint())
        + note_binding_generator().mul_bigint(note_leaf.into_bigint())
}

pub fn rerandomize_commitment(
    commitment: EdwardsProjective,
    rerandomization: EdwardsScalarField,
) -> EdwardsProjective {
    commitment + balance_blinding_generator().mul_bigint(rerandomization.into_bigint())
}

#[derive(Clone, Debug)]
pub struct StateSigningKey {
    secret: EdwardsScalarField,
    pub public: EdwardsAffine,
}

impl StateSigningKey {
    pub fn from_secret(mut secret: EdwardsScalarField) -> Self {
        if secret == EdwardsScalarField::ZERO {
            secret = EdwardsScalarField::ONE;
        }
        let public = EdwardsProjective::generator()
            .mul_bigint(secret.into_bigint())
            .into_affine();
        Self { secret, public }
    }

    pub fn generate(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        Self::from_secret(EdwardsScalarField::rand(rng))
    }

    pub fn sign(
        &self,
        message: CircuitField,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> StateSignature {
        let nonce = EdwardsScalarField::rand(rng);
        let r = EdwardsProjective::generator()
            .mul_bigint(nonce.into_bigint())
            .into_affine();
        let challenge = signature_challenge(r, message);
        let s = nonce + (challenge * self.secret);
        StateSignature { r, s }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct StateSignature {
    pub r: EdwardsAffine,
    pub s: EdwardsScalarField,
}

pub fn state_message(
    protocol_version: u16,
    chain_id: u64,
    contract_address: CircuitField,
    commitment: EdwardsAffine,
    anchor: CircuitField,
) -> CircuitField {
    poseidon_hash(&[
        domain(DOMAIN_STATE),
        CircuitField::from(protocol_version as u64),
        CircuitField::from(chain_id),
        contract_address,
        commitment.x,
        commitment.y,
        anchor,
    ])
}

pub fn clearance_message(
    protocol_version: u16,
    chain_id: u64,
    contract_address: CircuitField,
    withdrawal_nullifier: CircuitField,
) -> CircuitField {
    poseidon_hash(&[
        domain(DOMAIN_CLEARANCE),
        CircuitField::from(protocol_version as u64),
        CircuitField::from(chain_id),
        contract_address,
        withdrawal_nullifier,
    ])
}

fn signature_challenge(r: EdwardsAffine, message: CircuitField) -> EdwardsScalarField {
    let hash = poseidon_hash(&[domain(DOMAIN_SIGNATURE), r.x, r.y, message]);
    EdwardsScalarField::from_le_bytes_mod_order(&hash.into_bigint().to_bytes_le())
}

pub fn verify_state_signature(
    public: EdwardsAffine,
    message: CircuitField,
    signature: StateSignature,
) -> bool {
    let challenge = signature_challenge(signature.r, message);
    let lhs = EdwardsProjective::generator().mul_bigint(signature.s.into_bigint());
    let rhs = signature.r.into_group() + public.mul_bigint(challenge.into_bigint());
    lhs == rhs
}

fn scalar_bits_witness(
    cs: ConstraintSystemRef<CircuitField>,
    value: EdwardsScalarField,
) -> Result<Vec<Boolean<CircuitField>>, SynthesisError> {
    let native_bits = value.into_bigint().to_bits_le();
    (0..EdwardsScalarField::MODULUS_BIT_SIZE as usize)
        .map(|index| {
            Boolean::new_witness(cs.clone(), || {
                Ok(native_bits.get(index).copied().unwrap_or(false))
            })
        })
        .collect()
}

fn commitment_var(
    cs: ConstraintSystemRef<CircuitField>,
    balance: &UInt128<CircuitField>,
    blinding: EdwardsScalarField,
    note_leaf: &FpVar<CircuitField>,
) -> Result<EdwardsVar, SynthesisError> {
    let g = EdwardsVar::new_constant(cs.clone(), EdwardsProjective::generator())?;
    let h = EdwardsVar::new_constant(cs.clone(), balance_blinding_generator())?;
    let j = EdwardsVar::new_constant(cs.clone(), note_binding_generator())?;
    let blinding_bits = scalar_bits_witness(cs, blinding)?;
    let note_bits = note_leaf.to_bits_le()?;
    Ok(g.scalar_mul_le(balance.bits.iter())?
        + h.scalar_mul_le(blinding_bits.iter())?
        + j.scalar_mul_le(note_bits.iter())?)
}

fn enforce_signature(
    cs: ConstraintSystemRef<CircuitField>,
    public_key: &EdwardsVar,
    message: &FpVar<CircuitField>,
    signature: StateSignature,
    condition: &Boolean<CircuitField>,
) -> Result<(), SynthesisError> {
    let r = EdwardsVar::new_witness(cs.clone(), || Ok(signature.r))?;
    let s_bits = scalar_bits_witness(cs.clone(), signature.s)?;
    let challenge_hash = poseidon_hash_var(
        cs.clone(),
        &[
            domain_var(DOMAIN_SIGNATURE),
            r.x.clone(),
            r.y.clone(),
            message.clone(),
        ],
    )?;
    let challenge_bits = challenge_hash.to_bits_le()?;
    let g = EdwardsVar::new_constant(cs, EdwardsProjective::generator())?;
    let lhs = g.scalar_mul_le(s_bits.iter())?;
    let rhs = r + public_key.scalar_mul_le(challenge_bits.iter())?;
    lhs.conditional_enforce_equal(&rhs, condition)
}

#[derive(Clone, Debug)]
pub struct RequestPublic {
    pub protocol_version: u16,
    pub chain_id: u64,
    pub contract_address: CircuitField,
    pub active_root: CircuitField,
    pub state_signing_key: EdwardsAffine,
    pub request_time: u64,
    pub solvency_bound: u128,
    pub request_nullifier: CircuitField,
    pub authorization_tag: CircuitField,
    pub anonymous_commitment: EdwardsAffine,
}

impl RequestPublic {
    pub fn to_field_elements(&self) -> Vec<CircuitField> {
        vec![
            CircuitField::from(self.protocol_version as u64),
            CircuitField::from(self.chain_id),
            self.contract_address,
            self.active_root,
            self.state_signing_key.x,
            self.state_signing_key.y,
            CircuitField::from(self.request_time),
            CircuitField::from(self.solvency_bound),
            self.request_nullifier,
            self.authorization_tag,
            self.anonymous_commitment.x,
            self.anonymous_commitment.y,
        ]
    }
}

#[derive(Clone, Debug)]
pub struct RequestWitness {
    pub secret: CircuitField,
    pub request_context: CircuitField,
    pub note_id: u32,
    pub deposit_amount: u128,
    pub expiry: u64,
    pub merkle_siblings: [CircuitField; REQUEST_MERKLE_DEPTH],
    pub current_balance: u128,
    pub current_blinding: EdwardsScalarField,
    pub rerandomization: EdwardsScalarField,
    pub current_anchor: CircuitField,
    pub prev_anchor: CircuitField,
    pub state_signature: StateSignature,
}

#[derive(Clone, Debug)]
pub struct RequestCircuit {
    pub public: RequestPublic,
    pub witness: RequestWitness,
}

impl ConstraintSynthesizer<CircuitField> for RequestCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<CircuitField>,
    ) -> Result<(), SynthesisError> {
        let protocol_version = FpVar::new_input(cs.clone(), || {
            Ok(CircuitField::from(self.public.protocol_version as u64))
        })?;
        let chain_id =
            FpVar::new_input(cs.clone(), || Ok(CircuitField::from(self.public.chain_id)))?;
        let contract_address = FpVar::new_input(cs.clone(), || Ok(self.public.contract_address))?;
        let active_root = FpVar::new_input(cs.clone(), || Ok(self.public.active_root))?;
        let state_signing_key =
            EdwardsVar::new_input(cs.clone(), || Ok(self.public.state_signing_key))?;
        let request_time_field = FpVar::new_input(cs.clone(), || {
            Ok(CircuitField::from(self.public.request_time))
        })?;
        let solvency_bound_field = FpVar::new_input(cs.clone(), || {
            Ok(CircuitField::from(self.public.solvency_bound))
        })?;
        let request_nullifier = FpVar::new_input(cs.clone(), || Ok(self.public.request_nullifier))?;
        let authorization_tag = FpVar::new_input(cs.clone(), || Ok(self.public.authorization_tag))?;
        let anonymous_commitment =
            EdwardsVar::new_input(cs.clone(), || Ok(self.public.anonymous_commitment))?;

        let secret = FpVar::new_witness(cs.clone(), || Ok(self.witness.secret))?;
        secret.enforce_not_equal(&FpVar::zero())?;
        let request_context = FpVar::new_witness(cs.clone(), || Ok(self.witness.request_context))?;
        let note_id = UInt32::new_witness(cs.clone(), || Ok(self.witness.note_id))?;
        let deposit_amount = UInt128::new_witness(cs.clone(), || Ok(self.witness.deposit_amount))?;
        let expiry = UInt64::new_witness(cs.clone(), || Ok(self.witness.expiry))?;
        let balance = UInt128::new_witness(cs.clone(), || Ok(self.witness.current_balance))?;
        let request_time = UInt64::new_witness(cs.clone(), || Ok(self.public.request_time))?;
        request_time.to_fp()?.enforce_equal(&request_time_field)?;
        expiry.is_ge(&request_time)?.enforce_equal(&Boolean::TRUE)?;
        let solvency_bound = UInt128::new_witness(cs.clone(), || Ok(self.public.solvency_bound))?;
        solvency_bound
            .to_fp()?
            .enforce_equal(&solvency_bound_field)?;
        balance
            .is_ge(&solvency_bound)?
            .enforce_equal(&Boolean::TRUE)?;
        deposit_amount.is_ge(&balance)?.enforce_equal(&Boolean::TRUE)?;

        let registration = poseidon_hash_var(
            cs.clone(),
            &[domain_var(DOMAIN_REG), secret.clone(), FpVar::zero()],
        )?;
        let leaf = poseidon_hash_var(
            cs.clone(),
            &[
                domain_var(DOMAIN_LEAF),
                note_id.to_fp()?,
                registration,
                deposit_amount.to_fp()?,
                expiry.to_fp()?,
            ],
        )?;
        let mut current = leaf.clone();
        for (level, sibling_value) in self.witness.merkle_siblings.iter().enumerate() {
            let sibling = FpVar::new_witness(cs.clone(), || Ok(*sibling_value))?;
            let bit = &note_id.bits[level];
            let left = bit.select(&sibling, &current)?;
            let right = bit.select(&current, &sibling)?;
            current = poseidon_hash_var(cs.clone(), &[domain_var(DOMAIN_NODE), left, right])?;
        }
        current.enforce_equal(&active_root)?;

        let anchor = FpVar::new_witness(cs.clone(), || Ok(self.witness.current_anchor))?;
        let is_genesis = enforce_anchor_chain(
            cs.clone(), &secret, &note_id.to_fp()?, &anchor, self.witness.prev_anchor,
        )?;
        balance
            .to_fp()?
            .conditional_enforce_equal(&deposit_amount.to_fp()?, &is_genesis)?;

        let current_commitment =
            commitment_var(cs.clone(), &balance, self.witness.current_blinding, &leaf)?;
        let state_message = poseidon_hash_var(
            cs.clone(),
            &[
                domain_var(DOMAIN_STATE),
                protocol_version,
                chain_id,
                contract_address,
                current_commitment.x.clone(),
                current_commitment.y.clone(),
                anchor.clone(),
            ],
        )?;
        enforce_signature(
            cs.clone(),
            &state_signing_key,
            &state_message,
            self.witness.state_signature,
            &is_genesis.not(),
        )?;

        let h = EdwardsVar::new_constant(cs.clone(), balance_blinding_generator())?;
        let rerandomization_bits = scalar_bits_witness(cs.clone(), self.witness.rerandomization)?;
        let computed_anonymous =
            current_commitment + h.scalar_mul_le(rerandomization_bits.iter())?;
        computed_anonymous.enforce_equal(&anonymous_commitment)?;

        let computed_nullifier =
            poseidon_hash_var(cs.clone(), &[domain_var(DOMAIN_NULLIFIER), secret, note_id.to_fp()?, anchor])?;
        computed_nullifier.enforce_equal(&request_nullifier)?;
        let computed_authorization = poseidon_hash_var(
            cs,
            &[
                domain_var(DOMAIN_AUTHORIZATION),
                request_nullifier,
                request_context,
            ],
        )?;
        computed_authorization.enforce_equal(&authorization_tag)?;

        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct WithdrawalPublic {
    pub protocol_version: u16,
    pub chain_id: u64,
    pub contract_address: CircuitField,
    pub registration: CircuitField,
    pub state_signing_key: EdwardsAffine,
    pub clearance_signing_key: EdwardsAffine,
    pub note_id: u32,
    pub deposit_amount: u128,
    pub expiry: u64,
    pub final_balance: u128,
    pub destination: CircuitField,
    pub withdrawal_nullifier: CircuitField,
    pub has_clearance: bool,
    pub next_nullifier: CircuitField,
    pub conceded: u128,
    pub valid_until: u64,
}

impl WithdrawalPublic {
    pub fn to_field_elements(&self) -> Vec<CircuitField> {
        vec![
            CircuitField::from(self.protocol_version as u64),
            CircuitField::from(self.chain_id),
            self.contract_address,
            self.registration,
            self.state_signing_key.x,
            self.state_signing_key.y,
            self.clearance_signing_key.x,
            self.clearance_signing_key.y,
            packed_note_fields(self.note_id, self.deposit_amount, self.expiry),
            CircuitField::from(self.final_balance),
            self.destination,
            self.withdrawal_nullifier,
            CircuitField::from(self.has_clearance as u64),
            self.next_nullifier,
            CircuitField::from(self.conceded),
            CircuitField::from(self.valid_until),
        ]
    }
}

#[derive(Clone, Debug)]
pub struct WithdrawalWitness {
    pub secret: CircuitField,
    pub current_balance: u128,
    pub final_blinding: EdwardsScalarField,
    pub current_anchor: CircuitField,
    pub prev_anchor: CircuitField,
    pub state_signature: StateSignature,
    pub clearance_signature: StateSignature,
}

#[derive(Clone, Debug)]
pub struct WithdrawalCircuit {
    pub public: WithdrawalPublic,
    pub witness: WithdrawalWitness,
}

/// Public statement for the auxiliary Solana Merkle-transition proof.
///
/// It is intentionally separate from the stable request/withdrawal statements.
/// The program uses it only to authenticate the old/new Poseidon roots for one
/// note insertion or removal.
#[derive(Clone, Debug)]
pub struct SolanaTransitionPublic {
    pub protocol_version: u16,
    pub chain_id: u64,
    pub protocol_binding: CircuitField,
    pub old_root: CircuitField,
    pub new_root: CircuitField,
    pub note_id: u32,
    pub commitment: CircuitField,
    pub amount: u64,
    pub expiry: u64,
    pub inserting: bool,
}

impl SolanaTransitionPublic {
    pub fn to_field_elements(&self) -> [CircuitField; SOLANA_TRANSITION_PUBLIC_INPUTS] {
        [
            CircuitField::from(self.protocol_version as u64),
            CircuitField::from(self.chain_id),
            self.protocol_binding,
            self.old_root,
            self.new_root,
            CircuitField::from(self.note_id),
            self.commitment,
            CircuitField::from(self.amount),
            CircuitField::from(self.expiry),
            CircuitField::from(self.inserting as u64),
        ]
    }
}

#[derive(Clone, Debug)]
pub struct SolanaTransitionWitness {
    pub siblings: [CircuitField; REQUEST_MERKLE_DEPTH],
}

#[derive(Clone, Debug)]
pub struct SolanaTransitionCircuit {
    pub public: SolanaTransitionPublic,
    pub witness: SolanaTransitionWitness,
}

impl ConstraintSynthesizer<CircuitField> for SolanaTransitionCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<CircuitField>,
    ) -> Result<(), SynthesisError> {
        let protocol_version = FpVar::new_input(cs.clone(), || {
            Ok(CircuitField::from(self.public.protocol_version as u64))
        })?;
        protocol_version.enforce_equal(&FpVar::Constant(CircuitField::from(2u64)))?;

        let chain_id =
            FpVar::new_input(cs.clone(), || Ok(CircuitField::from(self.public.chain_id)))?;
        let chain_id_u64 = UInt64::new_witness(cs.clone(), || Ok(self.public.chain_id))?;
        chain_id_u64.to_fp()?.enforce_equal(&chain_id)?;
        chain_id.enforce_not_equal(&FpVar::zero())?;

        let protocol_binding = FpVar::new_input(cs.clone(), || Ok(self.public.protocol_binding))?;
        protocol_binding.enforce_not_equal(&FpVar::zero())?;
        let old_root = FpVar::new_input(cs.clone(), || Ok(self.public.old_root))?;
        let new_root = FpVar::new_input(cs.clone(), || Ok(self.public.new_root))?;

        let note_id_field =
            FpVar::new_input(cs.clone(), || Ok(CircuitField::from(self.public.note_id)))?;
        let note_id = UInt32::new_witness(cs.clone(), || Ok(self.public.note_id))?;
        note_id.to_fp()?.enforce_equal(&note_id_field)?;

        let commitment = FpVar::new_input(cs.clone(), || Ok(self.public.commitment))?;
        commitment.enforce_not_equal(&FpVar::zero())?;
        let amount_field =
            FpVar::new_input(cs.clone(), || Ok(CircuitField::from(self.public.amount)))?;
        let amount = UInt64::new_witness(cs.clone(), || Ok(self.public.amount))?;
        amount.to_fp()?.enforce_equal(&amount_field)?;
        amount_field.enforce_not_equal(&FpVar::zero())?;
        let expiry_field =
            FpVar::new_input(cs.clone(), || Ok(CircuitField::from(self.public.expiry)))?;
        let expiry = UInt64::new_witness(cs.clone(), || Ok(self.public.expiry))?;
        expiry.to_fp()?.enforce_equal(&expiry_field)?;
        expiry_field.enforce_not_equal(&FpVar::zero())?;
        let inserting = Boolean::new_input(cs.clone(), || Ok(self.public.inserting))?;

        let leaf = poseidon_hash_var(
            cs.clone(),
            &[
                domain_var(DOMAIN_LEAF),
                note_id.to_fp()?,
                commitment,
                amount.to_fp()?,
                expiry.to_fp()?,
            ],
        )?;
        let mut computed_old = inserting.select(&FpVar::zero(), &leaf)?;
        let mut computed_new = inserting.select(&leaf, &FpVar::zero())?;
        for (level, sibling_value) in self.witness.siblings.iter().enumerate() {
            let sibling = FpVar::new_witness(cs.clone(), || Ok(*sibling_value))?;
            let bit = &note_id.bits[level];
            let old_left = bit.select(&sibling, &computed_old)?;
            let old_right = bit.select(&computed_old, &sibling)?;
            computed_old =
                poseidon_hash_var(cs.clone(), &[domain_var(DOMAIN_NODE), old_left, old_right])?;
            let new_left = bit.select(&sibling, &computed_new)?;
            let new_right = bit.select(&computed_new, &sibling)?;
            computed_new =
                poseidon_hash_var(cs.clone(), &[domain_var(DOMAIN_NODE), new_left, new_right])?;
        }
        computed_old.enforce_equal(&old_root)?;
        computed_new.enforce_equal(&new_root)?;
        Ok(())
    }
}

impl ConstraintSynthesizer<CircuitField> for WithdrawalCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<CircuitField>,
    ) -> Result<(), SynthesisError> {
        let protocol_version = FpVar::new_input(cs.clone(), || {
            Ok(CircuitField::from(self.public.protocol_version as u64))
        })?;
        let chain_id =
            FpVar::new_input(cs.clone(), || Ok(CircuitField::from(self.public.chain_id)))?;
        let contract_address = FpVar::new_input(cs.clone(), || Ok(self.public.contract_address))?;
        let registration_field = FpVar::new_input(cs.clone(), || Ok(self.public.registration))?;
        let state_signing_key =
            EdwardsVar::new_input(cs.clone(), || Ok(self.public.state_signing_key))?;
        let clearance_signing_key =
            EdwardsVar::new_input(cs.clone(), || Ok(self.public.clearance_signing_key))?;
        let note_fields = FpVar::new_input(cs.clone(), || {
            Ok(packed_note_fields(self.public.note_id, self.public.deposit_amount, self.public.expiry))
        })?;
        let final_balance_field = FpVar::new_input(cs.clone(), || {
            Ok(CircuitField::from(self.public.final_balance))
        })?;
        let destination = FpVar::new_input(cs.clone(), || Ok(self.public.destination))?;
        // With the old tag removed, still bind the destination into the R1CS.
        let _destination_bits = destination.to_bits_le()?;
        let withdrawal_nullifier =
            FpVar::new_input(cs.clone(), || Ok(self.public.withdrawal_nullifier))?;
        let has_clearance = Boolean::new_input(cs.clone(), || Ok(self.public.has_clearance))?;
        let next_nullifier = FpVar::new_input(cs.clone(), || Ok(self.public.next_nullifier))?;
        let conceded_field = FpVar::new_input(cs.clone(), || Ok(CircuitField::from(self.public.conceded)))?;
        let valid_until_field = FpVar::new_input(cs.clone(), || Ok(CircuitField::from(self.public.valid_until)))?;
        let valid_until = UInt64::new_witness(cs.clone(), || Ok(self.public.valid_until))?;
        valid_until.to_fp()?.enforce_equal(&valid_until_field)?;

        let secret = FpVar::new_witness(cs.clone(), || Ok(self.witness.secret))?;
        secret.enforce_not_equal(&FpVar::zero())?;
        let note_id = UInt32::new_witness(cs.clone(), || Ok(self.public.note_id))?;
        let deposit_amount = UInt128::new_witness(cs.clone(), || Ok(self.public.deposit_amount))?;
        let final_balance = UInt128::new_witness(cs.clone(), || Ok(self.public.final_balance))?;
        final_balance.to_fp()?.enforce_equal(&final_balance_field)?;
        let balance = UInt128::new_witness(cs.clone(), || Ok(self.witness.current_balance))?;
        let conceded = UInt128::new_witness(cs.clone(), || Ok(self.public.conceded))?;
        conceded.to_fp()?.enforce_equal(&conceded_field)?;
        // Three u128 values cannot wrap the scalar field; equality enforces a
        // non-overflowing integer sum, not UInt128's modular addition.
        balance.to_fp()?.enforce_equal(&(final_balance.to_fp()? + conceded.to_fp()?))?;
        deposit_amount.is_ge(&balance)?.enforce_equal(&Boolean::TRUE)?;
        conceded_field.conditional_enforce_equal(&FpVar::zero(), &has_clearance)?;
        let expiry = UInt64::new_witness(cs.clone(), || Ok(self.public.expiry))?;
        (note_id.to_fp()? * CircuitField::from(2u64).pow([192])
            + deposit_amount.to_fp()? * CircuitField::from(2u64).pow([64])
            + expiry.to_fp()?).enforce_equal(&note_fields)?;

        let registration = poseidon_hash_var(
            cs.clone(),
            &[domain_var(DOMAIN_REG), secret.clone(), FpVar::zero()],
        )?;
        registration.enforce_equal(&registration_field)?;
        let leaf = poseidon_hash_var(
            cs.clone(),
            &[
                domain_var(DOMAIN_LEAF),
                note_id.to_fp()?,
                registration,
                deposit_amount.to_fp()?,
                expiry.to_fp()?,
            ],
        )?;

        let anchor = FpVar::new_witness(cs.clone(), || Ok(self.witness.current_anchor))?;
        let is_genesis = enforce_anchor_chain(
            cs.clone(), &secret, &note_id.to_fp()?, &anchor, self.witness.prev_anchor,
        )?;
        balance
            .to_fp()?
            .conditional_enforce_equal(&deposit_amount.to_fp()?, &is_genesis)?;

        let current_commitment = commitment_var(
            cs.clone(),
            &balance,
            self.witness.final_blinding,
            &leaf,
        )?;
        let state_message = poseidon_hash_var(
            cs.clone(),
            &[
                domain_var(DOMAIN_STATE),
                protocol_version.clone(),
                chain_id.clone(),
                contract_address.clone(),
                current_commitment.x.clone(),
                current_commitment.y.clone(),
                anchor.clone(),
            ],
        )?;
        enforce_signature(
            cs.clone(),
            &state_signing_key,
            &state_message,
            self.witness.state_signature,
            &is_genesis.not(),
        )?;

        let computed_nullifier =
            poseidon_hash_var(cs.clone(), &[domain_var(DOMAIN_NULLIFIER), secret.clone(), note_id.to_fp()?, anchor])?;
        computed_nullifier.enforce_equal(&withdrawal_nullifier)?;

        let next_anchor = poseidon_hash_var(cs.clone(), &[
            domain_var(DOMAIN_ANCHOR), withdrawal_nullifier.clone(),
        ])?;
        let computed_next = poseidon_hash_var(cs.clone(), &[
            domain_var(DOMAIN_NULLIFIER), secret, note_id.to_fp()?, next_anchor,
        ])?;
        has_clearance.select(&FpVar::zero(), &computed_next)?.enforce_equal(&next_nullifier)?;

        let clear_message = poseidon_hash_var(
            cs.clone(),
            &[
                domain_var(DOMAIN_CLEARANCE),
                protocol_version,
                chain_id,
                contract_address,
                withdrawal_nullifier,
            ],
        )?;
        enforce_signature(
            cs,
            &clearance_signing_key,
            &clear_message,
            self.witness.clearance_signature,
            &has_clearance,
        )?;
        Ok(())
    }
}

pub fn request_nullifier(secret: CircuitField, note_id: u32, anchor: CircuitField) -> CircuitField {
    poseidon_hash(&[domain(DOMAIN_NULLIFIER), secret, CircuitField::from(note_id), anchor])
}

pub fn next_anchor(nullifier: CircuitField) -> CircuitField {
    poseidon_hash(&[domain(DOMAIN_ANCHOR), nullifier])
}

pub fn successor_nullifier(secret: CircuitField, note_id: u32, nullifier: CircuitField) -> CircuitField {
    request_nullifier(secret, note_id, next_anchor(nullifier))
}

pub fn packed_note_fields(note_id: u32, deposit_amount: u128, expiry: u64) -> CircuitField {
    CircuitField::from(note_id) * CircuitField::from(2u64).pow([192])
        + CircuitField::from(deposit_amount) * CircuitField::from(2u64).pow([64])
        + CircuitField::from(expiry)
}

fn enforce_anchor_chain(
    cs: ConstraintSystemRef<CircuitField>,
    secret: &FpVar<CircuitField>,
    note_id: &FpVar<CircuitField>,
    anchor: &FpVar<CircuitField>,
    prev_anchor: CircuitField,
) -> Result<Boolean<CircuitField>, SynthesisError> {
    let is_genesis = anchor.is_eq(&FpVar::one())?;
    let previous = FpVar::new_witness(cs.clone(), || Ok(prev_anchor))?;
    let previous_nullifier = poseidon_hash_var(cs.clone(), &[
        domain_var(DOMAIN_NULLIFIER), secret.clone(), note_id.clone(), previous,
    ])?;
    let derived_anchor = poseidon_hash_var(cs, &[domain_var(DOMAIN_ANCHOR), previous_nullifier])?;
    anchor.conditional_enforce_equal(&derived_anchor, &is_genesis.clone().not())?;
    Ok(is_genesis)
}

pub fn authorization_tag(nullifier: CircuitField, request_context: CircuitField) -> CircuitField {
    poseidon_hash(&[domain(DOMAIN_AUTHORIZATION), nullifier, request_context])
}

pub fn registration_commitment(secret: CircuitField) -> CircuitField {
    poseidon_hash(&[domain(DOMAIN_REG), secret, CircuitField::ZERO])
}

pub fn note_leaf(
    note_id: u32,
    registration: CircuitField,
    deposit_amount: u128,
    expiry: u64,
) -> CircuitField {
    poseidon_hash(&[
        domain(DOMAIN_LEAF),
        CircuitField::from(note_id),
        registration,
        CircuitField::from(deposit_amount),
        CircuitField::from(expiry),
    ])
}

pub fn merkle_root(
    note_id: u32,
    leaf: CircuitField,
    siblings: &[CircuitField; REQUEST_MERKLE_DEPTH],
) -> CircuitField {
    let mut current = leaf;
    for (level, sibling) in siblings.iter().enumerate() {
        current = if ((note_id >> level) & 1) == 0 {
            poseidon_hash(&[domain(DOMAIN_NODE), current, *sibling])
        } else {
            poseidon_hash(&[domain(DOMAIN_NODE), *sibling, current])
        };
    }
    current
}

pub fn request_setup(
    circuit: RequestCircuit,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>), SynthesisError> {
    Groth16::<Bn254>::setup(circuit, rng)
}

pub fn withdrawal_setup(
    circuit: WithdrawalCircuit,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>), SynthesisError> {
    Groth16::<Bn254>::setup(circuit, rng)
}

pub fn solana_transition_setup(
    circuit: SolanaTransitionCircuit,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>), SynthesisError> {
    Groth16::<Bn254>::setup(circuit, rng)
}

pub fn prove_solana_transition(
    proving_key: &ProvingKey<Bn254>,
    circuit: SolanaTransitionCircuit,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Proof<Bn254>, SynthesisError> {
    Groth16::<Bn254>::prove(proving_key, circuit, rng)
}

pub fn verify_solana_transition(
    verifying_key: &VerifyingKey<Bn254>,
    public: &SolanaTransitionPublic,
    proof: &Proof<Bn254>,
) -> Result<bool, SynthesisError> {
    let prepared = prepare_verifying_key(verifying_key);
    Groth16::<Bn254>::verify_with_processed_vk(&prepared, &public.to_field_elements(), proof)
}

pub fn prove_withdrawal(
    proving_key: &ProvingKey<Bn254>,
    circuit: WithdrawalCircuit,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Proof<Bn254>, SynthesisError> {
    Groth16::<Bn254>::prove(proving_key, circuit, rng)
}

pub fn verify_withdrawal(
    verifying_key: &VerifyingKey<Bn254>,
    public: &WithdrawalPublic,
    proof: &Proof<Bn254>,
) -> Result<bool, SynthesisError> {
    let prepared = prepare_verifying_key(verifying_key);
    Groth16::<Bn254>::verify_with_processed_vk(&prepared, &public.to_field_elements(), proof)
}

pub fn prove_request(
    proving_key: &ProvingKey<Bn254>,
    circuit: RequestCircuit,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Proof<Bn254>, SynthesisError> {
    Groth16::<Bn254>::prove(proving_key, circuit, rng)
}

/// How a proving key's `H` query is laid out, which selects the R1CS-to-QAP
/// witness map the prover must use. Verification is identical for both kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyKind {
    /// Single-party arkworks setup (`ark-groth16`'s default `LibsnarkReduction`).
    Legacy,
    /// Keys converted from a snarkjs `.zkey` ceremony (`CircomReduction`).
    Snarkjs,
}

/// Prove any of the zkAPI circuits with the reduction matching the key kind.
pub fn prove_with_kind<C: ConstraintSynthesizer<CircuitField>>(
    kind: KeyKind,
    proving_key: &ProvingKey<Bn254>,
    circuit: C,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Proof<Bn254>, SynthesisError> {
    match kind {
        KeyKind::Legacy => Groth16::<Bn254>::prove(proving_key, circuit, rng),
        KeyKind::Snarkjs => Groth16::<Bn254, CircomReduction>::prove(proving_key, circuit, rng),
    }
}

pub fn verify_request(
    verifying_key: &VerifyingKey<Bn254>,
    public: &RequestPublic,
    proof: &Proof<Bn254>,
) -> Result<bool, SynthesisError> {
    let prepared = prepare_verifying_key(verifying_key);
    Groth16::<Bn254>::verify_with_processed_vk(&prepared, &public.to_field_elements(), proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_serialize::CanonicalSerialize;
    use ark_std::rand::{rngs::StdRng, SeedableRng};

    fn test_rng() -> StdRng {
        StdRng::seed_from_u64(0x7a6b_6170_6932)
    }

    fn fixture() -> RequestCircuit {
        let mut rng = test_rng();
        let protocol_version = 2;
        let chain_id = 11_155_111;
        let contract_address = CircuitField::from(0xdead_u64);
        let secret = CircuitField::from(42u64);
        let note_id = 0;
        let deposit_amount = 5_000_000;
        let expiry = 4_000_000_000;
        let siblings = [CircuitField::ZERO; REQUEST_MERKLE_DEPTH];
        let registration = registration_commitment(secret);
        let leaf = note_leaf(note_id, registration, deposit_amount, expiry);
        let active_root = merkle_root(note_id, leaf, &siblings);
        let current_balance = 4_900_000;
        let current_blinding = EdwardsScalarField::rand(&mut rng);
        let rerandomization = EdwardsScalarField::rand(&mut rng);
        let current_commitment =
            balance_commitment(current_balance, current_blinding, leaf).into_affine();
        let anonymous_commitment =
            rerandomize_commitment(current_commitment.into_group(), rerandomization).into_affine();
        let prev_anchor = CircuitField::ONE;
        let current_anchor = next_anchor(request_nullifier(secret, note_id, prev_anchor));
        let signer = StateSigningKey::generate(&mut rng);
        let message = state_message(
            protocol_version,
            chain_id,
            contract_address,
            current_commitment,
            current_anchor,
        );
        let signature = signer.sign(message, &mut rng);
        assert!(verify_state_signature(signer.public, message, signature));
        let request_context = CircuitField::from(777u64);
        let nullifier = request_nullifier(secret, note_id, current_anchor);

        RequestCircuit {
            public: RequestPublic {
                protocol_version,
                chain_id,
                contract_address,
                active_root,
                state_signing_key: signer.public,
                request_time: 3_000_000_000,
                solvency_bound: 1_000_000,
                request_nullifier: nullifier,
                authorization_tag: authorization_tag(nullifier, request_context),
                anonymous_commitment,
            },
            witness: RequestWitness {
                secret,
                request_context,
                note_id,
                deposit_amount,
                expiry,
                merkle_siblings: siblings,
                current_balance,
                current_blinding,
                rerandomization,
                current_anchor,
                prev_anchor,
                state_signature: signature,
            },
        }
    }

    fn withdrawal_fixture() -> WithdrawalCircuit {
        let mut rng = test_rng();
        let protocol_version = 2;
        let chain_id = 11_155_111;
        let contract_address = CircuitField::from(0xdead_u64);
        let secret = CircuitField::from(42u64);
        let note_id = 0;
        let deposit_amount = 5_000_000;
        let expiry = 4_000_000_000;
        let registration = registration_commitment(secret);
        let leaf = note_leaf(note_id, registration, deposit_amount, expiry);
        let final_balance = 4_900_000;
        let final_blinding = EdwardsScalarField::rand(&mut rng);
        let current_commitment =
            balance_commitment(final_balance, final_blinding, leaf).into_affine();
        let prev_anchor = CircuitField::ONE;
        let current_anchor = next_anchor(request_nullifier(secret, note_id, prev_anchor));
        let state_signer = StateSigningKey::generate(&mut rng);
        let state_signature = state_signer.sign(
            state_message(
                protocol_version,
                chain_id,
                contract_address,
                current_commitment,
                current_anchor,
            ),
            &mut rng,
        );
        let clearance_signer = StateSigningKey::generate(&mut rng);
        let nullifier = request_nullifier(secret, note_id, current_anchor);
        let clearance_signature = clearance_signer.sign(
            clearance_message(protocol_version, chain_id, contract_address, nullifier),
            &mut rng,
        );
        let destination = CircuitField::from(0xbeef_u64);
        let has_clearance = true;

        WithdrawalCircuit {
            public: WithdrawalPublic {
                protocol_version,
                chain_id,
                contract_address,
                registration,
                state_signing_key: state_signer.public,
                clearance_signing_key: clearance_signer.public,
                note_id,
                deposit_amount,
                expiry,
                final_balance,
                destination,
                withdrawal_nullifier: nullifier,
                has_clearance,
                next_nullifier: CircuitField::ZERO,
                conceded: 0,
                valid_until: expiry,
            },
            witness: WithdrawalWitness {
                secret,
                current_balance: final_balance,
                final_blinding,
                current_anchor,
                prev_anchor,
                state_signature,
                clearance_signature,
            },
        }
    }

    fn solana_transition_fixture(inserting: bool) -> SolanaTransitionCircuit {
        let note_id = 7;
        let commitment = CircuitField::from(0xcafe_u64);
        let amount = 5_000_000u64;
        let expiry = 4_000_000_000;
        let siblings = [CircuitField::ZERO; REQUEST_MERKLE_DEPTH];
        let leaf = note_leaf(note_id, commitment, u128::from(amount), expiry);
        let empty_root = merkle_root(note_id, CircuitField::ZERO, &siblings);
        let populated_root = merkle_root(note_id, leaf, &siblings);

        SolanaTransitionCircuit {
            public: SolanaTransitionPublic {
                protocol_version: 2,
                chain_id: 11_155_111,
                protocol_binding: CircuitField::from(0xdead_u64),
                old_root: if inserting {
                    empty_root
                } else {
                    populated_root
                },
                new_root: if inserting {
                    populated_root
                } else {
                    empty_root
                },
                note_id,
                commitment,
                amount,
                expiry,
                inserting,
            },
            witness: SolanaTransitionWitness { siblings },
        }
    }

    #[test]
    fn generators_are_distinct_nonzero_subgroup_points() {
        let g = EdwardsProjective::generator();
        let h = balance_blinding_generator();
        let j = note_binding_generator();
        assert_ne!(g, h);
        assert_ne!(g, j);
        assert_ne!(h, j);
        for point in [h, j] {
            assert_ne!(point, EdwardsProjective::default());
            assert!(point.into_affine().is_on_curve());
            assert!(point
                .into_affine()
                .is_in_correct_subgroup_assuming_on_curve());
        }
    }

    #[test]
    fn signed_state_cannot_move_to_another_note() {
        for (secret, amount) in [(42, 5_000_000), (43, 5_000_000), (43, 6_000_000)] {
            let mut circuit = fixture();
            circuit.witness.secret = CircuitField::from(secret as u64);
            circuit.witness.note_id = 1;
            circuit.witness.deposit_amount = amount;
            let leaf = note_leaf(
                1,
                registration_commitment(circuit.witness.secret),
                amount,
                circuit.witness.expiry,
            );
            circuit.public.active_root = merkle_root(1, leaf, &circuit.witness.merkle_siblings);
            circuit.public.request_nullifier =
                request_nullifier(circuit.witness.secret, circuit.witness.note_id, circuit.witness.current_anchor);
            circuit.public.authorization_tag = authorization_tag(
                circuit.public.request_nullifier,
                circuit.witness.request_context,
            );
            // Recompute everything the attacker controls for B; only A's genuine
            // signature is retained. Both amounts exceed the current balance.
            circuit.public.anonymous_commitment = rerandomize_commitment(
                balance_commitment(
                    circuit.witness.current_balance,
                    circuit.witness.current_blinding,
                    leaf,
                ),
                circuit.witness.rerandomization,
            )
            .into_affine();
            let cs = ConstraintSystem::new_ref();
            circuit.generate_constraints(cs.clone()).unwrap();
            assert!(!cs.is_satisfied().unwrap());
        }
    }

    #[test]
    fn signed_withdrawal_cannot_move_to_another_note() {
        for (secret, amount) in [(42, 5_000_000), (43, 5_000_000), (43, 6_000_000)] {
            let mut circuit = withdrawal_fixture();
            circuit.witness.secret = CircuitField::from(secret as u64);
            circuit.public.note_id = 1;
            circuit.public.deposit_amount = amount;
            circuit.public.registration = registration_commitment(circuit.witness.secret);
            circuit.public.withdrawal_nullifier =
                request_nullifier(circuit.witness.secret, circuit.public.note_id, circuit.witness.current_anchor);
            circuit.public.has_clearance = false;
            circuit.public.next_nullifier = successor_nullifier(
                circuit.witness.secret, circuit.public.note_id, circuit.public.withdrawal_nullifier,
            );
            let cs = ConstraintSystem::new_ref();
            circuit.generate_constraints(cs.clone()).unwrap();
            assert!(!cs.is_satisfied().unwrap());
        }
    }

    #[test]
    fn request_circuit_is_satisfied() {
        let circuit = fixture();
        let cs = ConstraintSystem::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
        assert_eq!(cs.num_instance_variables() - 1, REQUEST_PUBLIC_INPUTS);
        eprintln!("request constraints: {}", cs.num_constraints());
    }

    #[test]
    fn solana_transition_circuit_accepts_insert_and_remove_only() {
        for inserting in [true, false] {
            let circuit = solana_transition_fixture(inserting);
            let cs = ConstraintSystem::new_ref();
            circuit.clone().generate_constraints(cs.clone()).unwrap();
            assert!(cs.is_satisfied().unwrap());
            assert_eq!(
                cs.num_instance_variables() - 1,
                SOLANA_TRANSITION_PUBLIC_INPUTS
            );

            let mut wrong_root = circuit.clone();
            wrong_root.public.new_root += CircuitField::ONE;
            let cs = ConstraintSystem::new_ref();
            wrong_root.generate_constraints(cs.clone()).unwrap();
            assert!(!cs.is_satisfied().unwrap());

            let mut wrong_direction = circuit;
            wrong_direction.public.inserting = !inserting;
            let cs = ConstraintSystem::new_ref();
            wrong_direction.generate_constraints(cs.clone()).unwrap();
            assert!(!cs.is_satisfied().unwrap());
        }
    }

    #[test]
    fn request_proof_round_trip() {
        use std::time::Instant;

        let mut rng = test_rng();
        let circuit = fixture();
        let public = circuit.public.clone();
        let setup_started = Instant::now();
        let (pk, vk) = request_setup(circuit.clone(), &mut rng).unwrap();
        let setup_elapsed = setup_started.elapsed();
        let prove_started = Instant::now();
        let proof = prove_request(&pk, circuit, &mut rng).unwrap();
        let prove_elapsed = prove_started.elapsed();
        let verify_started = Instant::now();
        assert!(verify_request(&vk, &public, &proof).unwrap());
        let verify_elapsed = verify_started.elapsed();

        let mut proof_bytes = Vec::new();
        proof.serialize_compressed(&mut proof_bytes).unwrap();
        eprintln!("request proof bytes: {}", proof_bytes.len());
        eprintln!("setup: {setup_elapsed:?}");
        eprintln!("prove: {prove_elapsed:?}");
        eprintln!("verify: {verify_elapsed:?}");
    }

    #[test]
    fn request_context_is_cryptographically_bound() {
        let mut rng = test_rng();
        let circuit = fixture();
        let (pk, vk) = request_setup(circuit.clone(), &mut rng).unwrap();
        let proof = prove_request(&pk, circuit.clone(), &mut rng).unwrap();
        let mut wrong = circuit.public;
        wrong.authorization_tag += CircuitField::ONE;
        assert!(!verify_request(&vk, &wrong, &proof).unwrap());
    }

    #[test]
    fn withdrawal_proof_round_trip() {
        use std::time::Instant;

        let mut rng = test_rng();
        let circuit = withdrawal_fixture();
        let public = circuit.public.clone();
        let cs = ConstraintSystem::new_ref();
        circuit.clone().generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
        assert_eq!(cs.num_instance_variables() - 1, WITHDRAWAL_PUBLIC_INPUTS);

        let setup_started = Instant::now();
        let (pk, vk) = withdrawal_setup(circuit.clone(), &mut rng).unwrap();
        let setup_elapsed = setup_started.elapsed();
        let prove_started = Instant::now();
        let proof = prove_withdrawal(&pk, circuit, &mut rng).unwrap();
        let prove_elapsed = prove_started.elapsed();
        let verify_started = Instant::now();
        assert!(verify_withdrawal(&vk, &public, &proof).unwrap());
        let verify_elapsed = verify_started.elapsed();

        let mut proof_bytes = Vec::new();
        proof.serialize_compressed(&mut proof_bytes).unwrap();
        eprintln!("withdrawal constraints: {}", cs.num_constraints());
        eprintln!("withdrawal proof bytes: {}", proof_bytes.len());
        eprintln!("setup: {setup_elapsed:?}");
        eprintln!("prove: {prove_elapsed:?}");
        eprintln!("verify: {verify_elapsed:?}");
    }

    fn satisfied(circuit: impl ConstraintSynthesizer<CircuitField>) -> bool {
        let cs = ConstraintSystem::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        cs.is_satisfied().unwrap()
    }

    /// Every allocated public input and witness must occur in some constraint;
    /// a variable in none of them is free for a malicious prover.
    fn assert_every_variable_is_constrained(circuit: impl ConstraintSynthesizer<CircuitField>) {
        let cs = ConstraintSystem::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        cs.finalize();
        assert!(cs.is_satisfied().unwrap());
        let matrices = cs.to_matrices().unwrap();
        let total = matrices.num_instance_variables + matrices.num_witness_variables;
        let mut used = vec![false; total];
        for matrix in [&matrices.a, &matrices.b, &matrices.c] {
            for row in matrix {
                for (_, column) in row {
                    used[*column] = true;
                }
            }
        }
        let unused = (1..total).filter(|index| !used[*index]).collect::<Vec<_>>();
        assert!(unused.is_empty(), "unconstrained variables: {unused:?}");
    }

    /// Re-derive every public value from the request witness so a test only
    /// changes the one relation it targets.
    fn reseal_request(circuit: &mut RequestCircuit) {
        let leaf = note_leaf(
            circuit.witness.note_id,
            registration_commitment(circuit.witness.secret),
            circuit.witness.deposit_amount,
            circuit.witness.expiry,
        );
        circuit.public.active_root = merkle_root(
            circuit.witness.note_id,
            leaf,
            &circuit.witness.merkle_siblings,
        );
        circuit.public.anonymous_commitment = rerandomize_commitment(
            balance_commitment(
                circuit.witness.current_balance,
                circuit.witness.current_blinding,
                leaf,
            ),
            circuit.witness.rerandomization,
        )
        .into_affine();
        circuit.public.request_nullifier =
            request_nullifier(circuit.witness.secret, circuit.witness.note_id, circuit.witness.current_anchor);
        circuit.public.authorization_tag = authorization_tag(
            circuit.public.request_nullifier,
            circuit.witness.request_context,
        );
    }

    fn genesis_request() -> RequestCircuit {
        let mut circuit = fixture();
        circuit.witness.current_anchor = CircuitField::ONE;
        circuit.witness.current_balance = circuit.witness.deposit_amount;
        circuit.witness.state_signature = StateSignature {
            r: EdwardsAffine::zero(),
            s: EdwardsScalarField::ZERO,
        };
        reseal_request(&mut circuit);
        circuit
    }

    #[test]
    fn every_variable_of_every_circuit_is_constrained() {
        assert_every_variable_is_constrained(fixture());
        assert_every_variable_is_constrained(genesis_request());
        assert_every_variable_is_constrained(withdrawal_fixture());
        for inserting in [true, false] {
            assert_every_variable_is_constrained(solana_transition_fixture(inserting));
        }
    }

    #[test]
    fn request_rejects_forged_balance_expiry_and_genesis_witnesses() {
        assert!(satisfied(fixture()));
        assert!(satisfied(genesis_request()));

        let mut insolvent = fixture();
        insolvent.public.solvency_bound = u128::from(insolvent.witness.current_balance) + 1;
        assert!(!satisfied(insolvent));

        let mut expired = fixture();
        expired.public.request_time = expired.witness.expiry + 1;
        assert!(!satisfied(expired));

        // Genesis must open to exactly the deposit at anchor 1.
        let mut inflated = genesis_request();
        inflated.witness.current_balance += 1;
        reseal_request(&mut inflated);
        assert!(!satisfied(inflated));
        let mut fresh_anchor = genesis_request();
        fresh_anchor.witness.current_anchor = CircuitField::from(2u64);
        reseal_request(&mut fresh_anchor);
        assert!(!satisfied(fresh_anchor));

        // A self-signed or unsigned non-genesis state is rejected.
        let mut forged = fixture();
        let attacker = StateSigningKey::generate(&mut test_rng());
        let commitment = balance_commitment(
            forged.witness.current_balance + 1_000_000,
            forged.witness.current_blinding,
            note_leaf(
                forged.witness.note_id,
                registration_commitment(forged.witness.secret),
                forged.witness.deposit_amount,
                forged.witness.expiry,
            ),
        )
        .into_affine();
        forged.witness.current_balance += 1_000_000;
        forged.witness.state_signature = attacker.sign(
            state_message(
                forged.public.protocol_version,
                forged.public.chain_id,
                forged.public.contract_address,
                commitment,
                forged.witness.current_anchor,
            ),
            &mut test_rng(),
        );
        reseal_request(&mut forged);
        assert!(!satisfied(forged));

        // The signed state is bound to its deployment fields.
        let mut other_chain = fixture();
        other_chain.public.chain_id += 1;
        assert!(!satisfied(other_chain));
    }

    #[test]
    fn request_rejects_off_curve_or_mismatched_public_points() {
        let mut off_curve = fixture();
        let point = off_curve.public.anonymous_commitment;
        off_curve.public.anonymous_commitment =
            EdwardsAffine::new_unchecked(point.x, point.y + EdwardsBaseField::ONE);
        assert!(!off_curve.public.anonymous_commitment.is_on_curve());
        assert!(!satisfied(off_curve));

        let mut negated = fixture();
        negated.public.anonymous_commitment = -negated.public.anonymous_commitment;
        assert!(!satisfied(negated));
    }

    #[test]
    fn withdrawal_rejects_overdrawn_or_uncleared_statements() {
        assert!(satisfied(withdrawal_fixture()));

        // Even a validly signed state cannot reveal more than the deposit.
        let mut rng = test_rng();
        let mut overdrawn = withdrawal_fixture();
        let signer = StateSigningKey::generate(&mut rng);
        let balance = overdrawn.public.deposit_amount + 1;
        let leaf = note_leaf(
            overdrawn.public.note_id,
            registration_commitment(overdrawn.witness.secret),
            overdrawn.public.deposit_amount,
            overdrawn.public.expiry,
        );
        let commitment =
            balance_commitment(balance, overdrawn.witness.final_blinding, leaf).into_affine();
        overdrawn.public.state_signing_key = signer.public;
        overdrawn.witness.state_signature = signer.sign(
            state_message(
                overdrawn.public.protocol_version,
                overdrawn.public.chain_id,
                overdrawn.public.contract_address,
                commitment,
                overdrawn.witness.current_anchor,
            ),
            &mut rng,
        );
        overdrawn.public.final_balance = balance;
        overdrawn.witness.current_balance = balance;
        assert!(!satisfied(overdrawn));

        // Clearance must sign this exact nullifier.
        let mut wrong_clearance = withdrawal_fixture();
        wrong_clearance.witness.clearance_signature = wrong_clearance.witness.state_signature;
        assert!(!satisfied(wrong_clearance));

        // Changing clearance mode without its required successor is invalid.
        let mut downgraded = withdrawal_fixture();
        downgraded.public.has_clearance = false;
        assert!(!satisfied(downgraded));
    }

    #[test]
    fn withdrawal_genesis_binds_balance_anchor_and_secret() {
        fn reseal(circuit: &mut WithdrawalCircuit) {
            circuit.public.registration = registration_commitment(circuit.witness.secret);
            circuit.public.withdrawal_nullifier =
                request_nullifier(circuit.witness.secret, circuit.public.note_id, circuit.witness.current_anchor);
            circuit.public.next_nullifier = successor_nullifier(
                circuit.witness.secret, circuit.public.note_id, circuit.public.withdrawal_nullifier,
            );
        }
        let mut genesis = withdrawal_fixture();
        genesis.witness.current_anchor = CircuitField::ONE;
        genesis.public.final_balance = genesis.public.deposit_amount;
        genesis.witness.current_balance = genesis.public.deposit_amount;
        genesis.public.has_clearance = false;
        genesis.witness.state_signature = StateSignature {
            r: EdwardsAffine::zero(),
            s: EdwardsScalarField::ZERO,
        };
        reseal(&mut genesis);
        assert!(satisfied(genesis.clone()));
        for field in 0..2 {
            let mut forged = genesis.clone();
            match field {
                // Under-deposit balance passes the general balance upper bound,
                // but cannot manufacture a fresh unsigned state/nullifier.
                0 => {
                    forged.public.final_balance -= 1;
                    forged.witness.current_balance -= 1;
                }
                1 => forged.witness.current_anchor += CircuitField::ONE,
                _ => unreachable!(),
            }
            reseal(&mut forged);
            assert!(!satisfied(forged));
        }
        let mut zero_secret = genesis;
        zero_secret.witness.secret = CircuitField::ZERO;
        reseal(&mut zero_secret);
        // The nonzero gadget needs secret^-1; zero cannot even populate that
        // witness, rather than producing a fully assigned unsatisfied system.
        assert_eq!(
            zero_secret.generate_constraints(ConstraintSystem::new_ref()),
            Err(SynthesisError::AssignmentMissing),
        );
    }

    fn resign_request(circuit: &mut RequestCircuit) {
        reseal_request(circuit);
        let signer = StateSigningKey::generate(&mut test_rng());
        circuit.public.state_signing_key = signer.public;
        let leaf = note_leaf(circuit.witness.note_id, registration_commitment(circuit.witness.secret),
            circuit.witness.deposit_amount, circuit.witness.expiry);
        let commitment = balance_commitment(circuit.witness.current_balance,
            circuit.witness.current_blinding, leaf).into_affine();
        circuit.witness.state_signature = signer.sign(state_message(circuit.public.protocol_version,
            circuit.public.chain_id, circuit.public.contract_address, commitment,
            circuit.witness.current_anchor), &mut test_rng());
    }

    fn escape_fixture() -> WithdrawalCircuit {
        let mut circuit = withdrawal_fixture();
        circuit.public.has_clearance = false;
        circuit.public.next_nullifier = successor_nullifier(circuit.witness.secret,
            circuit.public.note_id, circuit.public.withdrawal_nullifier);
        circuit
    }

    fn resign_withdrawal(circuit: &mut WithdrawalCircuit) {
        circuit.public.withdrawal_nullifier = request_nullifier(circuit.witness.secret,
            circuit.public.note_id, circuit.witness.current_anchor);
        circuit.public.next_nullifier = if circuit.public.has_clearance { CircuitField::ZERO } else {
            successor_nullifier(circuit.witness.secret, circuit.public.note_id,
                circuit.public.withdrawal_nullifier)
        };
        let signer = StateSigningKey::generate(&mut test_rng());
        circuit.public.state_signing_key = signer.public;
        let leaf = note_leaf(circuit.public.note_id, circuit.public.registration,
            circuit.public.deposit_amount, circuit.public.expiry);
        let commitment = balance_commitment(circuit.witness.current_balance,
            circuit.witness.final_blinding, leaf).into_affine();
        circuit.witness.state_signature = signer.sign(state_message(circuit.public.protocol_version,
            circuit.public.chain_id, circuit.public.contract_address, commitment,
            circuit.witness.current_anchor), &mut test_rng());
    }

    #[test]
    fn concession_constraints_reject_forged_signed_states() {
        // Even the legitimate operator cannot sign spendable random or born-spent anchors.
        for anchor in [CircuitField::from(12345u64), CircuitField::ONE] {
            let mut request = fixture();
            request.witness.current_anchor = anchor;
            resign_request(&mut request);
            assert!(!satisfied(request));
            let mut exit = escape_fixture();
            exit.witness.current_anchor = anchor;
            resign_withdrawal(&mut exit);
            assert!(!satisfied(exit));
        }
        let mut request = fixture();
        request.witness.prev_anchor += CircuitField::ONE;
        assert!(!satisfied(request));
        let mut exit = escape_fixture();
        exit.witness.prev_anchor += CircuitField::ONE;
        assert!(!satisfied(exit));
        let mut request = fixture();
        request.witness.current_balance = request.witness.deposit_amount + 1;
        resign_request(&mut request);
        assert!(!satisfied(request));
        let mut request = fixture();
        request.public.request_nullifier = request_nullifier(request.witness.secret,
            request.witness.note_id + 1, request.witness.current_anchor);
        request.public.authorization_tag = authorization_tag(request.public.request_nullifier,
            request.witness.request_context);
        assert!(!satisfied(request));
        let mut exit = escape_fixture();
        exit.public.withdrawal_nullifier = request_nullifier(exit.witness.secret,
            exit.public.note_id + 1, exit.witness.current_anchor);
        exit.public.next_nullifier = successor_nullifier(exit.witness.secret,
            exit.public.note_id, exit.public.withdrawal_nullifier);
        assert!(!satisfied(exit));
    }

    #[test]
    fn concession_exit_rejects_forged_fields_and_wrapping_sum() {
        assert!(satisfied(escape_fixture()));
        for mutation in 0..8 {
            let mut exit = escape_fixture();
            match mutation {
                0 => exit.public.next_nullifier += CircuitField::ONE,
                1 => exit.public.registration += CircuitField::ONE,
                2 => exit.public.note_id += 1,
                3 => exit.public.deposit_amount += 1,
                4 => exit.public.expiry += 1,
                5 => exit.public.conceded = 1,
                6 => {
                    exit.public.final_balance = u128::MAX;
                    exit.public.conceded = exit.witness.current_balance + 1;
                }
                7 => {
                    exit.witness.current_balance = exit.public.deposit_amount + 1;
                    exit.public.final_balance = exit.witness.current_balance;
                    resign_withdrawal(&mut exit);
                }
                _ => unreachable!(),
            }
            assert!(!satisfied(exit), "mutation {mutation}");
        }
        let mut close = withdrawal_fixture();
        close.public.conceded = 1;
        close.public.final_balance -= 1; // sum and signed B remain correct
        assert!(!satisfied(close));
        let mut close = withdrawal_fixture();
        close.public.next_nullifier = successor_nullifier(close.witness.secret,
            close.public.note_id, close.public.withdrawal_nullifier);
        assert!(!satisfied(close));

        // Rust u64/u32/u128 types cannot represent these malicious public
        // scalars. Inject them directly into the public assignment instead.
        for (index, value) in [
            (15, CircuitField::from(2u64).pow([64])),
            (8, CircuitField::from(2u64).pow([224])),
            (14, CircuitField::from(2u64).pow([128])),
        ] {
            let cs = ConstraintSystem::new_ref();
            escape_fixture().generate_constraints(cs.clone()).unwrap();
            cs.borrow_mut().unwrap().instance_assignment[index + 1] = value;
            assert!(!cs.is_satisfied().unwrap());
        }
    }

    #[test]
    fn concession_escape_proofs_bind_all_public_fields() {
        let mut rng = test_rng();
        let circuit = escape_fixture();
        let (pk, vk) = withdrawal_setup(circuit.clone(), &mut rng).unwrap();
        for conceded in [0, 100_000, circuit.witness.current_balance] {
            let mut exit = circuit.clone();
            exit.public.conceded = conceded;
            exit.public.final_balance = exit.witness.current_balance - conceded;
            let proof = prove_withdrawal(&pk, exit.clone(), &mut rng).unwrap();
            assert!(verify_withdrawal(&vk, &exit.public, &proof).unwrap());
            for index in 0..WITHDRAWAL_PUBLIC_INPUTS {
                let mut fields = exit.public.to_field_elements();
                fields[index] += CircuitField::ONE;
                assert!(!Groth16::<Bn254>::verify(&vk, &fields, &proof).unwrap(),
                    "unbound public input {index}");
            }
        }
    }

    #[test]
    fn transition_binds_leaf_index_and_shared_sibling_path() {
        let circuit = solana_transition_fixture(true);
        assert!(satisfied(circuit.clone()));
        let leaf = note_leaf(
            circuit.public.note_id,
            circuit.public.commitment,
            u128::from(circuit.public.amount),
            circuit.public.expiry,
        );
        // Both roots are consistent Merkle trees, but the leaf was moved to a
        // different index without changing the note ID embedded in its hash.
        let mut relocated = circuit.clone();
        relocated.public.note_id ^= 1;
        relocated.public.old_root = merkle_root(
            relocated.public.note_id,
            CircuitField::ZERO,
            &relocated.witness.siblings,
        );
        relocated.public.new_root = merkle_root(
            relocated.public.note_id,
            leaf,
            &relocated.witness.siblings,
        );
        assert!(!satisfied(relocated));

        // Inserting one note cannot also mutate an unrelated sibling subtree.
        let mut changed_path = circuit.witness.siblings;
        changed_path[0] += CircuitField::ONE;
        let mut collateral_update = circuit;
        collateral_update.public.new_root =
            merkle_root(collateral_update.public.note_id, leaf, &changed_path);
        assert!(!satisfied(collateral_update));
    }

    #[test]
    fn transition_rejects_overwrites_and_mismatched_removals() {
        let note_id = 7;
        let mut siblings = [CircuitField::ZERO; REQUEST_MERKLE_DEPTH];
        siblings[0] = CircuitField::from(99u64);
        let mut overwrite = solana_transition_fixture(true);
        overwrite.witness.siblings = siblings;
        let resident = CircuitField::from(5u64);
        overwrite.public.old_root = merkle_root(note_id, resident, &siblings);
        let leaf = note_leaf(
            note_id,
            overwrite.public.commitment,
            u128::from(overwrite.public.amount),
            overwrite.public.expiry,
        );
        overwrite.public.new_root = merkle_root(note_id, leaf, &siblings);
        assert!(!satisfied(overwrite));

        let mut wrong_amount = solana_transition_fixture(false);
        wrong_amount.public.amount += 1;
        assert!(!satisfied(wrong_amount));
        let mut wrong_slot = solana_transition_fixture(false);
        wrong_slot.public.note_id += 1;
        assert!(!satisfied(wrong_slot));
    }
}
