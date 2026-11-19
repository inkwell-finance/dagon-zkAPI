//! Instrumented copies of the hardened zkAPI synthesizers and helper gadgets.
//! Source: protocol/rust/crates/zkapi-proof/src/groth16.rs, zkapi-v2-hardening-v1.
//! Function bodies are verbatim except counter-only sec()/free() markers.
//! main.rs rejects any exported R1CS bytes that differ from the ceremony pins.

use std::cell::RefCell;
use std::ops::Not;
use std::sync::OnceLock;

use ark_bn254::Fr as CircuitField;
use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
use ark_crypto_primitives::sponge::poseidon::{find_poseidon_ark_and_mds, PoseidonConfig};
use ark_ec::PrimeGroup;
use ark_ed_on_bn254::{constraints::EdwardsVar, EdwardsAffine, EdwardsProjective, Fr as EdwardsScalarField};
use ark_ff::{BigInteger, Field, PrimeField};
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
use zkapi_proof::groth16::{
    balance_blinding_generator, note_binding_generator, packed_note_fields,
    RequestCircuit, RequestPublic, RequestWitness, SolanaTransitionCircuit,
    SolanaTransitionPublic, SolanaTransitionWitness, WithdrawalPublic, WithdrawalWitness,
    StateSignature, WithdrawalCircuit,
};
use ark_r1cs_std::R1CSVar;

#[derive(Clone, Debug)]
pub enum Mark {
    Section(String, usize, usize),
    Free(String, usize, usize),
}

thread_local! {
    pub static MARKS: RefCell<Vec<Mark>> = const { RefCell::new(Vec::new()) };
}

fn label(label: &str, marks: &[Mark]) -> String {
    if label.contains('/') {
        label.to_string()
    } else {
        let circuit = marks.iter().find_map(|m| match m {
            Mark::Section(s, _, _) => s.split('/').next(),
            _ => None,
        }).unwrap_or("gadget");
        format!("{circuit}/{label}")
    }
}

fn sec(cs: &ConstraintSystemRef<CircuitField>, name: &str) {
    MARKS.with(|v| {
        let mut marks = v.borrow_mut();
        let name = label(name, &marks);
        marks.push(Mark::Section(name, cs.num_witness_variables(), cs.num_constraints()));
    });
}

// Mark only the next n input wires, never the allocator's derived helper wires.
fn free(cs: &ConstraintSystemRef<CircuitField>, name: &str, n: usize) {
    MARKS.with(|v| {
        let mut marks = v.borrow_mut();
        let name = label(name, &marks);
        let start = cs.num_witness_variables();
        marks.push(Mark::Free(name, start, start + n));
    });
}


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

/// Allocates a 251-bit Baby-JubJub scalar and bounds it by `r-1`, so every
/// scalar has one witness. Takes the integer so tests can supply `r` itself.
pub(crate) fn scalar_bits_witness(
    cs: ConstraintSystemRef<CircuitField>,
    value: <EdwardsScalarField as PrimeField>::BigInt,
) -> Result<Vec<Boolean<CircuitField>>, SynthesisError> {
    sec(&cs, "L275 scalar bits");
    let native_bits = value.to_bits_le();
    free(&cs, "scalar bits", 251);
    let bits = (0..EdwardsScalarField::MODULUS_BIT_SIZE as usize)
        .map(|index| {
            Boolean::new_witness(cs.clone(), || {
                Ok(native_bits.get(index).copied().unwrap_or(false))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    sec(&cs, "L283 scalar bound");
    Boolean::enforce_smaller_or_equal_than_le(&bits, (-EdwardsScalarField::ONE).into_bigint())?;
    Ok(bits)
}

/// Input allocation checks the curve equation, but not subgroup membership.
/// A subgroup witness equal to the input proves membership cheaply: arkworks
/// allocates its cofactor preimage and multiplies by eight. Reject the identity,
/// whose Schnorr signatures can be forged without a signing secret.
fn signing_key_input(
    cs: ConstraintSystemRef<CircuitField>,
    point: EdwardsAffine,
) -> Result<EdwardsVar, SynthesisError> {
    sec(&cs, "L295 public signing key on-curve");
    let input = EdwardsVar::new_input(cs.clone(), || Ok(point))?;
    sec(&cs, "L296 signing key Q witness");
    free(&cs, "signing key Q pre-cofactor point", 2);
    let subgroup = EdwardsVar::new_witness(cs, || Ok(point))?;
    sec(&input.cs(), "L297 signing key subgroup equality");
    input.enforce_equal(&subgroup)?;
    sec(&input.cs(), "L298 signing key nonidentity");
    input.is_zero()?.enforce_equal(&Boolean::FALSE)?;
    Ok(input)
}

fn enforce_deployment(
    cs: ConstraintSystemRef<CircuitField>,
    version: &FpVar<CircuitField>,
    chain: &FpVar<CircuitField>,
    chain_value: u64,
    binding: &FpVar<CircuitField>,
) -> Result<(), SynthesisError> {
    sec(&cs, "L309 deployment");
    version.enforce_equal(&FpVar::Constant(CircuitField::from(2u64)))?;
    sec(&cs, "L310 chain UInt64");
    UInt64::new_witness(cs, || Ok(chain_value))?.to_fp()?.enforce_equal(chain)?;
    sec(&chain.cs(), "L311 chain nonzero");
    chain.enforce_not_equal(&FpVar::zero())?;
    // Deployment bindings are canonical BN254 field elements, not EVM addresses.
    sec(&binding.cs(), "L313 binding nonzero");
    binding.enforce_not_equal(&FpVar::zero())
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
    sec(&cs, "L325 blinding bits");
    let blinding_bits = scalar_bits_witness(cs, blinding.into_bigint())?;
    sec(&note_leaf.cs(), "L326 note_leaf.to_bits_le");
    let note_bits = note_leaf.to_bits_le()?;
    sec(&note_leaf.cs(), "L327 G*balance + H*blinding + J*leaf");
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
    sec(&cs, "L339 R witness");
    free(&cs, "signature R pre-cofactor point", 2);
    let r = EdwardsVar::new_witness(cs.clone(), || Ok(signature.r))?;
    sec(&cs, "L340 signature s bits");
    let s_bits = scalar_bits_witness(cs.clone(), signature.s.into_bigint())?;
    sec(&cs, "L341 signature challenge Poseidon");
    let challenge_hash = poseidon_hash_var(
        cs.clone(),
        &[
            domain_var(DOMAIN_SIGNATURE),
            r.x.clone(),
            r.y.clone(),
            message.clone(),
        ],
    )?;
    sec(&cs, "L350 challenge.to_bits_le");
    let challenge_bits = challenge_hash.to_bits_le()?;
    let g = EdwardsVar::new_constant(cs, EdwardsProjective::generator())?;
    sec(&public_key.cs(), "L352 G*s");
    let lhs = g.scalar_mul_le(s_bits.iter())?;
    sec(&public_key.cs(), "L353 R + PK*challenge");
    let rhs = r + public_key.scalar_mul_le(challenge_bits.iter())?;
    sec(&public_key.cs(), "L354 signature equality");
    lhs.conditional_enforce_equal(&rhs, condition)
}

fn enforce_anchor_chain(
    cs: ConstraintSystemRef<CircuitField>,
    secret: &FpVar<CircuitField>,
    note_id: &FpVar<CircuitField>,
    anchor: &FpVar<CircuitField>,
    prev_anchor: CircuitField,
) -> Result<Boolean<CircuitField>, SynthesisError> {
    sec(&cs, "L879 anchor.is_eq");
    let is_genesis = anchor.is_eq(&FpVar::one())?;
    sec(&cs, "L880 previous anchor");
    free(&cs, "prev_anchor", 1);
    let previous = FpVar::new_witness(cs.clone(), || Ok(prev_anchor))?;
    sec(&cs, "L881 previous nullifier Poseidon");
    let previous_nullifier = poseidon_hash_var(cs.clone(), &[
        domain_var(DOMAIN_NULLIFIER), secret.clone(), note_id.clone(), previous,
    ])?;
    sec(&cs, "L884 derived anchor Poseidon");
    let derived_anchor = poseidon_hash_var(cs, &[domain_var(DOMAIN_ANCHOR), previous_nullifier])?;
    sec(&anchor.cs(), "L885 anchor equality");
    anchor.conditional_enforce_equal(&derived_anchor, &is_genesis.clone().not())?;
    Ok(is_genesis)
}

pub struct MarkedRequest {
    pub public: RequestPublic,
    pub witness: RequestWitness,
}

impl From<RequestCircuit> for MarkedRequest {
    fn from(c: RequestCircuit) -> Self {
        Self { public: c.public, witness: c.witness }
    }
}

impl ConstraintSynthesizer<CircuitField> for MarkedRequest {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<CircuitField>,
    ) -> Result<(), SynthesisError> {
        sec(&cs, "request/L417 public inputs");
        let protocol_version = FpVar::new_input(cs.clone(), || {
            Ok(CircuitField::from(self.public.protocol_version as u64))
        })?;
        let chain_id =
            FpVar::new_input(cs.clone(), || Ok(CircuitField::from(self.public.chain_id)))?;
        let contract_address = FpVar::new_input(cs.clone(), || Ok(self.public.contract_address))?;
        sec(&cs, "request/L423 deployment");
        enforce_deployment(cs.clone(), &protocol_version, &chain_id,
            self.public.chain_id, &contract_address)?;
        sec(&cs, "request/L425 public inputs");
        let active_root = FpVar::new_input(cs.clone(), || Ok(self.public.active_root))?;
        let state_signing_key =
            signing_key_input(cs.clone(), self.public.state_signing_key)?;
        sec(&cs, "request/L428 public inputs");
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

        sec(&cs, "request/L439 secret witness");
        free(&cs, "secret", 1);
        let secret = FpVar::new_witness(cs.clone(), || Ok(self.witness.secret))?;
        sec(&cs, "request/L440 secret nonzero");
        secret.enforce_not_equal(&FpVar::zero())?;
        sec(&cs, "request/L441 request_context witness");
        free(&cs, "request_context", 1);
        let request_context = FpVar::new_witness(cs.clone(), || Ok(self.witness.request_context))?;
        sec(&cs, "request/L442 note_id");
        free(&cs, "note_id bits", 32);
        let note_id = UInt32::new_witness(cs.clone(), || Ok(self.witness.note_id))?;
        sec(&cs, "request/L443 deposit");
        free(&cs, "deposit bits", 128);
        let deposit_amount = UInt128::new_witness(cs.clone(), || Ok(self.witness.deposit_amount))?;
        sec(&cs, "request/L444 expiry");
        free(&cs, "expiry bits", 64);
        let expiry = UInt64::new_witness(cs.clone(), || Ok(self.witness.expiry))?;
        sec(&cs, "request/L445 balance");
        free(&cs, "balance bits", 128);
        let balance = UInt128::new_witness(cs.clone(), || Ok(self.witness.current_balance))?;
        sec(&cs, "request/L446 request time");
        let request_time = UInt64::new_witness(cs.clone(), || Ok(self.public.request_time))?;
        request_time.to_fp()?.enforce_equal(&request_time_field)?;
        sec(&cs, "request/L448 expiry comparison");
        expiry.is_ge(&request_time)?.enforce_equal(&Boolean::TRUE)?;
        sec(&cs, "request/L449 solvency");
        let solvency_bound = UInt128::new_witness(cs.clone(), || Ok(self.public.solvency_bound))?;
        solvency_bound
            .to_fp()?
            .enforce_equal(&solvency_bound_field)?;
        sec(&cs, "request/L453 balance comparison");
        balance
            .is_ge(&solvency_bound)?
            .enforce_equal(&Boolean::TRUE)?;
        sec(&cs, "request/L456 deposit comparison");
        deposit_amount.is_ge(&balance)?.enforce_equal(&Boolean::TRUE)?;

        sec(&cs, "request/L458 registration Poseidon");
        let registration = poseidon_hash_var(
            cs.clone(),
            &[domain_var(DOMAIN_REG), secret.clone(), FpVar::zero()],
        )?;
        sec(&cs, "request/L462 leaf Poseidon");
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
            sec(&cs, "request/L474 merkle sibling");
            free(&cs, "merkle sibling", 1);
            let sibling = FpVar::new_witness(cs.clone(), || Ok(*sibling_value))?;
            sec(&cs, "request/L475 merkle select+Poseidon");
            let bit = &note_id.bits[level];
            let left = bit.select(&sibling, &current)?;
            let right = bit.select(&current, &sibling)?;
            current = poseidon_hash_var(cs.clone(), &[domain_var(DOMAIN_NODE), left, right])?;
        }
        sec(&cs, "request/L480 root equality");
        current.enforce_equal(&active_root)?;

        sec(&cs, "request/L482 anchor");
        free(&cs, "current_anchor", 1);
        let anchor = FpVar::new_witness(cs.clone(), || Ok(self.witness.current_anchor))?;
        let is_genesis = enforce_anchor_chain(
            cs.clone(), &secret, &note_id.to_fp()?, &anchor, self.witness.prev_anchor,
        )?;
        sec(&cs, "request/L486 genesis balance");
        balance
            .to_fp()?
            .conditional_enforce_equal(&deposit_amount.to_fp()?, &is_genesis)?;

        sec(&cs, "request/L490 commitment");
        let current_commitment =
            commitment_var(cs.clone(), &balance, self.witness.current_blinding, &leaf)?;
        sec(&cs, "request/L492 state message Poseidon");
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
        sec(&cs, "request/L504 state signature");
        enforce_signature(
            cs.clone(),
            &state_signing_key,
            &state_message,
            self.witness.state_signature,
            &is_genesis.not(),
        )?;

        let h = EdwardsVar::new_constant(cs.clone(), balance_blinding_generator())?;
        sec(&cs, "request/L513 rerandomization bits");
        let rerandomization_bits =
            scalar_bits_witness(cs.clone(), self.witness.rerandomization.into_bigint())?;
        sec(&cs, "request/L515 commitment + H*rerandomization");
        let computed_anonymous =
            current_commitment + h.scalar_mul_le(rerandomization_bits.iter())?;
        sec(&cs, "request/L517 commitment equality");
        computed_anonymous.enforce_equal(&anonymous_commitment)?;

        sec(&cs, "request/L519 nullifier Poseidon");
        let computed_nullifier =
            poseidon_hash_var(cs.clone(), &[domain_var(DOMAIN_NULLIFIER), secret, note_id.to_fp()?, anchor])?;
        sec(&cs, "request/L521 nullifier equality");
        computed_nullifier.enforce_equal(&request_nullifier)?;
        sec(&cs, "request/L522 authorization Poseidon");
        let computed_authorization = poseidon_hash_var(
            cs,
            &[
                domain_var(DOMAIN_AUTHORIZATION),
                request_nullifier,
                request_context,
            ],
        )?;
        sec(&authorization_tag.cs(), "request/L530 authorization equality");
        computed_authorization.enforce_equal(&authorization_tag)?;

        sec(&authorization_tag.cs(), "request/END");
        Ok(())
    }
}

pub struct MarkedTransition {
    pub public: SolanaTransitionPublic,
    pub witness: SolanaTransitionWitness,
}

impl From<SolanaTransitionCircuit> for MarkedTransition {
    fn from(c: SolanaTransitionCircuit) -> Self {
        Self { public: c.public, witness: c.witness }
    }
}

impl ConstraintSynthesizer<CircuitField> for MarkedTransition {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<CircuitField>,
    ) -> Result<(), SynthesisError> {
        sec(&cs, "transition/L648 version");
        let protocol_version = FpVar::new_input(cs.clone(), || {
            Ok(CircuitField::from(self.public.protocol_version as u64))
        })?;
        protocol_version.enforce_equal(&FpVar::Constant(CircuitField::from(2u64)))?;

        sec(&cs, "transition/L653 chain UInt64");
        let chain_id =
            FpVar::new_input(cs.clone(), || Ok(CircuitField::from(self.public.chain_id)))?;
        let chain_id_u64 = UInt64::new_witness(cs.clone(), || Ok(self.public.chain_id))?;
        chain_id_u64.to_fp()?.enforce_equal(&chain_id)?;
        sec(&cs, "transition/L657 chain nonzero");
        chain_id.enforce_not_equal(&FpVar::zero())?;

        sec(&cs, "transition/L659 binding");
        let protocol_binding = FpVar::new_input(cs.clone(), || Ok(self.public.protocol_binding))?;
        protocol_binding.enforce_not_equal(&FpVar::zero())?;
        sec(&cs, "transition/L661 roots");
        let old_root = FpVar::new_input(cs.clone(), || Ok(self.public.old_root))?;
        let new_root = FpVar::new_input(cs.clone(), || Ok(self.public.new_root))?;

        sec(&cs, "transition/L664 note id");
        let note_id_field =
            FpVar::new_input(cs.clone(), || Ok(CircuitField::from(self.public.note_id)))?;
        let note_id = UInt32::new_witness(cs.clone(), || Ok(self.public.note_id))?;
        note_id.to_fp()?.enforce_equal(&note_id_field)?;

        sec(&cs, "transition/L669 commitment");
        let commitment = FpVar::new_input(cs.clone(), || Ok(self.public.commitment))?;
        commitment.enforce_not_equal(&FpVar::zero())?;
        sec(&cs, "transition/L671 amount");
        let amount_field =
            FpVar::new_input(cs.clone(), || Ok(CircuitField::from(self.public.amount)))?;
        let amount = UInt64::new_witness(cs.clone(), || Ok(self.public.amount))?;
        amount.to_fp()?.enforce_equal(&amount_field)?;
        sec(&cs, "transition/L675 amount nonzero");
        amount_field.enforce_not_equal(&FpVar::zero())?;
        sec(&cs, "transition/L676 expiry");
        let expiry_field =
            FpVar::new_input(cs.clone(), || Ok(CircuitField::from(self.public.expiry)))?;
        let expiry = UInt64::new_witness(cs.clone(), || Ok(self.public.expiry))?;
        expiry.to_fp()?.enforce_equal(&expiry_field)?;
        sec(&cs, "transition/L680 expiry nonzero");
        expiry_field.enforce_not_equal(&FpVar::zero())?;
        sec(&cs, "transition/L681 inserting");
        let inserting = Boolean::new_input(cs.clone(), || Ok(self.public.inserting))?;

        sec(&cs, "transition/L683 leaf Poseidon");
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
        sec(&cs, "transition/L693 select leaves");
        let mut computed_old = inserting.select(&FpVar::zero(), &leaf)?;
        let mut computed_new = inserting.select(&leaf, &FpVar::zero())?;
        for (level, sibling_value) in self.witness.siblings.iter().enumerate() {
            sec(&cs, "transition/L696 sibling");
            free(&cs, "sibling", 1);
            let sibling = FpVar::new_witness(cs.clone(), || Ok(*sibling_value))?;
            sec(&cs, "transition/L697 select+Poseidon");
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
        sec(&cs, "transition/L707 roots equality");
        computed_old.enforce_equal(&old_root)?;
        computed_new.enforce_equal(&new_root)?;
        sec(&cs, "transition/END");
        Ok(())
    }
}

pub struct MarkedWithdrawal {
    pub public: WithdrawalPublic,
    pub witness: WithdrawalWitness,
}

impl From<WithdrawalCircuit> for MarkedWithdrawal {
    fn from(c: WithdrawalCircuit) -> Self {
        Self { public: c.public, witness: c.witness }
    }
}

impl ConstraintSynthesizer<CircuitField> for MarkedWithdrawal {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<CircuitField>,
    ) -> Result<(), SynthesisError> {
        sec(&cs, "withdrawal/L718 public inputs");
        let protocol_version = FpVar::new_input(cs.clone(), || {
            Ok(CircuitField::from(self.public.protocol_version as u64))
        })?;
        let chain_id =
            FpVar::new_input(cs.clone(), || Ok(CircuitField::from(self.public.chain_id)))?;
        let contract_address = FpVar::new_input(cs.clone(), || Ok(self.public.contract_address))?;
        sec(&cs, "withdrawal/L724 deployment");
        enforce_deployment(cs.clone(), &protocol_version, &chain_id,
            self.public.chain_id, &contract_address)?;
        sec(&cs, "withdrawal/L726 registration input");
        let registration_field = FpVar::new_input(cs.clone(), || Ok(self.public.registration))?;
        let state_signing_key =
            signing_key_input(cs.clone(), self.public.state_signing_key)?;
        let clearance_signing_key =
            signing_key_input(cs.clone(), self.public.clearance_signing_key)?;
        sec(&cs, "withdrawal/L731 public inputs");
        let note_fields = FpVar::new_input(cs.clone(), || {
            Ok(packed_note_fields(self.public.note_id, self.public.deposit_amount, self.public.expiry))
        })?;
        let final_balance_field = FpVar::new_input(cs.clone(), || {
            Ok(CircuitField::from(self.public.final_balance))
        })?;
        let destination = FpVar::new_input(cs.clone(), || Ok(self.public.destination))?;
        // The wire statement carries a 20-byte destination binding. Its bit
        // decomposition both binds the public input and enforces that width.
        sec(&cs, "withdrawal/L740 destination.to_bits_le");
        for bit in &destination.to_bits_le()?[160..] {
            bit.enforce_equal(&Boolean::FALSE)?;
        }
        sec(&cs, "withdrawal/L743 public inputs");
        let withdrawal_nullifier =
            FpVar::new_input(cs.clone(), || Ok(self.public.withdrawal_nullifier))?;
        let has_clearance = Boolean::new_input(cs.clone(), || Ok(self.public.has_clearance))?;
        let next_nullifier = FpVar::new_input(cs.clone(), || Ok(self.public.next_nullifier))?;
        let conceded_field = FpVar::new_input(cs.clone(), || Ok(CircuitField::from(self.public.conceded)))?;
        let valid_until_field = FpVar::new_input(cs.clone(), || Ok(CircuitField::from(self.public.valid_until)))?;
        sec(&cs, "withdrawal/L749 valid_until");
        let valid_until = UInt64::new_witness(cs.clone(), || Ok(self.public.valid_until))?;
        valid_until.to_fp()?.enforce_equal(&valid_until_field)?;

        sec(&cs, "withdrawal/L752 secret");
        free(&cs, "secret", 1);
        let secret = FpVar::new_witness(cs.clone(), || Ok(self.witness.secret))?;
        sec(&cs, "withdrawal/L753 secret nonzero");
        secret.enforce_not_equal(&FpVar::zero())?;
        sec(&cs, "withdrawal/L754 note_id");
        let note_id = UInt32::new_witness(cs.clone(), || Ok(self.public.note_id))?;
        sec(&cs, "withdrawal/L755 deposit");
        let deposit_amount = UInt128::new_witness(cs.clone(), || Ok(self.public.deposit_amount))?;
        sec(&cs, "withdrawal/L756 final balance");
        let final_balance = UInt128::new_witness(cs.clone(), || Ok(self.public.final_balance))?;
        final_balance.to_fp()?.enforce_equal(&final_balance_field)?;
        sec(&cs, "withdrawal/L758 balance");
        let balance = UInt128::new_witness(cs.clone(), || Ok(self.witness.current_balance))?;
        sec(&cs, "withdrawal/L759 conceded");
        let conceded = UInt128::new_witness(cs.clone(), || Ok(self.public.conceded))?;
        conceded.to_fp()?.enforce_equal(&conceded_field)?;
        // Three u128 values cannot wrap the scalar field; equality enforces a
        // non-overflowing integer sum, not UInt128's modular addition.
        sec(&cs, "withdrawal/L763 balance sum");
        balance.to_fp()?.enforce_equal(&(final_balance.to_fp()? + conceded.to_fp()?))?;
        sec(&cs, "withdrawal/L764 deposit comparison");
        deposit_amount.is_ge(&balance)?.enforce_equal(&Boolean::TRUE)?;
        sec(&cs, "withdrawal/L765 clearance concession");
        conceded_field.conditional_enforce_equal(&FpVar::zero(), &has_clearance)?;
        sec(&cs, "withdrawal/L766 expiry");
        let expiry = UInt64::new_witness(cs.clone(), || Ok(self.public.expiry))?;
        sec(&cs, "withdrawal/L767 packed fields");
        (note_id.to_fp()? * CircuitField::from(2u64).pow([192])
            + deposit_amount.to_fp()? * CircuitField::from(2u64).pow([64])
            + expiry.to_fp()?).enforce_equal(&note_fields)?;

        sec(&cs, "withdrawal/L771 registration Poseidon");
        let registration = poseidon_hash_var(
            cs.clone(),
            &[domain_var(DOMAIN_REG), secret.clone(), FpVar::zero()],
        )?;
        sec(&cs, "withdrawal/L775 registration equality");
        registration.enforce_equal(&registration_field)?;
        sec(&cs, "withdrawal/L776 leaf Poseidon");
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

        sec(&cs, "withdrawal/L787 anchor");
        free(&cs, "current_anchor", 1);
        let anchor = FpVar::new_witness(cs.clone(), || Ok(self.witness.current_anchor))?;
        let is_genesis = enforce_anchor_chain(
            cs.clone(), &secret, &note_id.to_fp()?, &anchor, self.witness.prev_anchor,
        )?;
        sec(&cs, "withdrawal/L791 genesis balance");
        balance
            .to_fp()?
            .conditional_enforce_equal(&deposit_amount.to_fp()?, &is_genesis)?;

        sec(&cs, "withdrawal/L795 commitment");
        let current_commitment = commitment_var(
            cs.clone(),
            &balance,
            self.witness.final_blinding,
            &leaf,
        )?;
        sec(&cs, "withdrawal/L801 state message Poseidon");
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
        sec(&cs, "withdrawal/L813 state signature");
        enforce_signature(
            cs.clone(),
            &state_signing_key,
            &state_message,
            self.witness.state_signature,
            &is_genesis.not(),
        )?;

        sec(&cs, "withdrawal/L821 nullifier Poseidon");
        let computed_nullifier =
            poseidon_hash_var(cs.clone(), &[domain_var(DOMAIN_NULLIFIER), secret.clone(), note_id.to_fp()?, anchor])?;
        sec(&cs, "withdrawal/L823 nullifier equality");
        computed_nullifier.enforce_equal(&withdrawal_nullifier)?;

        sec(&cs, "withdrawal/L825 next anchor Poseidon");
        let next_anchor = poseidon_hash_var(cs.clone(), &[
            domain_var(DOMAIN_ANCHOR), withdrawal_nullifier.clone(),
        ])?;
        sec(&cs, "withdrawal/L828 next nullifier Poseidon");
        let computed_next = poseidon_hash_var(cs.clone(), &[
            domain_var(DOMAIN_NULLIFIER), secret, note_id.to_fp()?, next_anchor,
        ])?;
        sec(&cs, "withdrawal/L831 nullifier select");
        has_clearance.select(&FpVar::zero(), &computed_next)?.enforce_equal(&next_nullifier)?;

        sec(&cs, "withdrawal/L833 clearance message Poseidon");
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
        sec(&cs, "withdrawal/L843 clearance signature");
        enforce_signature(
            cs,
            &clearance_signing_key,
            &clear_message,
            self.witness.clearance_signature,
            &has_clearance,
        )?;
        sec(&has_clearance.cs(), "withdrawal/END");
        Ok(())
    }
}
