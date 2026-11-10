//! Instrumented, byte-identical copies of the three zkAPI synthesizers in
//! protocol/rust/crates/zkapi-proof/src/groth16.rs (commit d05a8e3).
//! The only additions are `sec`/`free` calls, which read counters and never
//! touch the constraint system. main.rs asserts the exported r1cs bytes hash to
//! the ceremony pins, which proves the copies are exact.

use std::cell::RefCell;
use std::ops::Not;
use std::sync::OnceLock;

use ark_bn254::Fr as CircuitField;
use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
use ark_crypto_primitives::sponge::poseidon::{find_poseidon_ark_and_mds, PoseidonConfig};
use ark_ec::PrimeGroup;
use ark_ed_on_bn254::{constraints::EdwardsVar, EdwardsProjective, Fr as EdwardsScalarField};
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
    balance_blinding_generator, note_binding_generator, RequestCircuit, SolanaTransitionCircuit,
    StateSignature, WithdrawalCircuit,
};

#[derive(Clone, Debug)]
pub enum Mark {
    /// Start of a source-level section: (label, witness count, constraint count).
    Section(String, usize, usize),
    /// Witness indices [start, end) are prover-chosen free values.
    Free(String, usize, usize),
}

thread_local! {
    pub static MARKS: RefCell<Vec<Mark>> = const { RefCell::new(Vec::new()) };
}

fn nw(cs: &ConstraintSystemRef<CircuitField>) -> usize {
    cs.num_witness_variables()
}

fn sec(cs: &ConstraintSystemRef<CircuitField>, label: &str) {
    let m = Mark::Section(label.to_string(), cs.num_witness_variables(), cs.num_constraints());
    MARKS.with(|v| v.borrow_mut().push(m));
}

fn free(cs: &ConstraintSystemRef<CircuitField>, label: &str, start: usize, len: Option<usize>) {
    let end = match len {
        Some(n) => start + n,
        None => cs.num_witness_variables(),
    };
    MARKS.with(|v| v.borrow_mut().push(Mark::Free(label.to_string(), start, end)));
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

fn scalar_bits_witness(
    cs: ConstraintSystemRef<CircuitField>,
    value: EdwardsScalarField,
    label: &str,
) -> Result<Vec<Boolean<CircuitField>>, SynthesisError> {
    let w0 = nw(&cs);
    let native_bits = value.into_bigint().to_bits_le();
    let out = (0..EdwardsScalarField::MODULUS_BIT_SIZE as usize)
        .map(|index| {
            Boolean::new_witness(cs.clone(), || {
                Ok(native_bits.get(index).copied().unwrap_or(false))
            })
        })
        .collect();
    free(&cs, label, w0, None);
    out
}

fn commitment_var(
    cs: ConstraintSystemRef<CircuitField>,
    balance: &UInt128<CircuitField>,
    blinding: EdwardsScalarField,
    note_leaf: &FpVar<CircuitField>,
    p: &str,
) -> Result<EdwardsVar, SynthesisError> {
    let g = EdwardsVar::new_constant(cs.clone(), EdwardsProjective::generator())?;
    let h = EdwardsVar::new_constant(cs.clone(), balance_blinding_generator())?;
    let j = EdwardsVar::new_constant(cs.clone(), note_binding_generator())?;
    sec(&cs, &format!("{p}/L283 commitment_var: blinding bits (scalar_bits_witness)"));
    let blinding_bits = scalar_bits_witness(cs.clone(), blinding, &format!("{p} blinding bits"))?;
    sec(&cs, &format!("{p}/L285 commitment_var: note_leaf.to_bits_le"));
    let note_bits = note_leaf.to_bits_le()?;
    sec(&cs, &format!("{p}/L286 commitment_var: G*balance"));
    let a = g.scalar_mul_le(balance.bits.iter())?;
    sec(&cs, &format!("{p}/L287 commitment_var: H*blinding"));
    let b = h.scalar_mul_le(blinding_bits.iter())?;
    sec(&cs, &format!("{p}/L286-287 commitment_var: G*balance + H*blinding"));
    let ab = a + b;
    sec(&cs, &format!("{p}/L288 commitment_var: J*leaf"));
    let c = j.scalar_mul_le(note_bits.iter())?;
    sec(&cs, &format!("{p}/L288 commitment_var: (..) + J*leaf"));
    Ok(ab + c)
}

fn enforce_signature(
    cs: ConstraintSystemRef<CircuitField>,
    public_key: &EdwardsVar,
    message: &FpVar<CircuitField>,
    signature: StateSignature,
    condition: &Boolean<CircuitField>,
    p: &str,
) -> Result<(), SynthesisError> {
    sec(&cs, &format!("{p}/L298 enforce_signature: R witness (cofactor-cleared alloc)"));
    let w0 = nw(&cs);
    let r = EdwardsVar::new_witness(cs.clone(), || Ok(signature.r))?;
    free(&cs, &format!("{p} signature R pre-cofactor point (x,y)"), w0, Some(2));
    sec(&cs, &format!("{p}/L299 enforce_signature: s bits"));
    let s_bits = scalar_bits_witness(cs.clone(), signature.s, &format!("{p} signature s bits"))?;
    sec(&cs, &format!("{p}/L300 enforce_signature: challenge Poseidon"));
    let challenge_hash = poseidon_hash_var(
        cs.clone(),
        &[
            domain_var(DOMAIN_SIGNATURE),
            r.x.clone(),
            r.y.clone(),
            message.clone(),
        ],
    )?;
    sec(&cs, &format!("{p}/L309 enforce_signature: challenge.to_bits_le"));
    let challenge_bits = challenge_hash.to_bits_le()?;
    let g = EdwardsVar::new_constant(cs.clone(), EdwardsProjective::generator())?;
    sec(&cs, &format!("{p}/L311 enforce_signature: G*s"));
    let lhs = g.scalar_mul_le(s_bits.iter())?;
    sec(&cs, &format!("{p}/L312 enforce_signature: PK*challenge"));
    let pkc = public_key.scalar_mul_le(challenge_bits.iter())?;
    sec(&cs, &format!("{p}/L312 enforce_signature: R + PK*c"));
    let rhs = r + pkc;
    sec(&cs, &format!("{p}/L313 enforce_signature: conditional_enforce_equal"));
    lhs.conditional_enforce_equal(&rhs, condition)
}

fn enforce_anchor_chain(
    cs: ConstraintSystemRef<CircuitField>,
    secret: &FpVar<CircuitField>,
    note_id: &FpVar<CircuitField>,
    anchor: &FpVar<CircuitField>,
    prev_anchor: CircuitField,
    p: &str,
) -> Result<Boolean<CircuitField>, SynthesisError> {
    sec(&cs, &format!("{p}/L830 anchor_chain: is_genesis = anchor.is_eq(1)"));
    let is_genesis = anchor.is_eq(&FpVar::one())?;
    sec(&cs, &format!("{p}/L831 anchor_chain: previous anchor witness"));
    let w0 = nw(&cs);
    let previous = FpVar::new_witness(cs.clone(), || Ok(prev_anchor))?;
    free(&cs, &format!("{p} prev_anchor"), w0, None);
    sec(&cs, &format!("{p}/L832 anchor_chain: previous_nullifier Poseidon"));
    let previous_nullifier = poseidon_hash_var(cs.clone(), &[
        domain_var(DOMAIN_NULLIFIER), secret.clone(), note_id.clone(), previous,
    ])?;
    sec(&cs, &format!("{p}/L835 anchor_chain: derived_anchor Poseidon"));
    let derived_anchor = poseidon_hash_var(cs.clone(), &[domain_var(DOMAIN_ANCHOR), previous_nullifier])?;
    sec(&cs, &format!("{p}/L836 anchor_chain: conditional_enforce_equal"));
    anchor.conditional_enforce_equal(&derived_anchor, &is_genesis.clone().not())?;
    Ok(is_genesis)
}

pub struct MarkedRequest(pub RequestCircuit);
pub struct MarkedWithdrawal(pub WithdrawalCircuit);
pub struct MarkedTransition(pub SolanaTransitionCircuit);

impl ConstraintSynthesizer<CircuitField> for MarkedRequest {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<CircuitField>,
    ) -> Result<(), SynthesisError> {
        let s = self.0;
        let p = "request";
        sec(&cs, "request/L376-394 public inputs");
        let protocol_version = FpVar::new_input(cs.clone(), || {
            Ok(CircuitField::from(s.public.protocol_version as u64))
        })?;
        let chain_id =
            FpVar::new_input(cs.clone(), || Ok(CircuitField::from(s.public.chain_id)))?;
        let contract_address = FpVar::new_input(cs.clone(), || Ok(s.public.contract_address))?;
        let active_root = FpVar::new_input(cs.clone(), || Ok(s.public.active_root))?;
        let state_signing_key =
            EdwardsVar::new_input(cs.clone(), || Ok(s.public.state_signing_key))?;
        let request_time_field = FpVar::new_input(cs.clone(), || {
            Ok(CircuitField::from(s.public.request_time))
        })?;
        let solvency_bound_field = FpVar::new_input(cs.clone(), || {
            Ok(CircuitField::from(s.public.solvency_bound))
        })?;
        let request_nullifier = FpVar::new_input(cs.clone(), || Ok(s.public.request_nullifier))?;
        let authorization_tag = FpVar::new_input(cs.clone(), || Ok(s.public.authorization_tag))?;
        let anonymous_commitment =
            EdwardsVar::new_input(cs.clone(), || Ok(s.public.anonymous_commitment))?;

        sec(&cs, "request/L396 secret witness");
        let w0 = nw(&cs);
        let secret = FpVar::new_witness(cs.clone(), || Ok(s.witness.secret))?;
        free(&cs, "request secret", w0, None);
        sec(&cs, "request/L397 secret != 0");
        secret.enforce_not_equal(&FpVar::zero())?;
        sec(&cs, "request/L398 request_context witness");
        let w0 = nw(&cs);
        let request_context = FpVar::new_witness(cs.clone(), || Ok(s.witness.request_context))?;
        free(&cs, "request request_context", w0, None);
        sec(&cs, "request/L399 note_id UInt32 witness");
        let w0 = nw(&cs);
        let note_id = UInt32::new_witness(cs.clone(), || Ok(s.witness.note_id))?;
        free(&cs, "request note_id bits", w0, None);
        sec(&cs, "request/L400 deposit_amount UInt128 witness");
        let w0 = nw(&cs);
        let deposit_amount = UInt128::new_witness(cs.clone(), || Ok(s.witness.deposit_amount))?;
        free(&cs, "request deposit_amount bits", w0, None);
        sec(&cs, "request/L401 expiry UInt64 witness");
        let w0 = nw(&cs);
        let expiry = UInt64::new_witness(cs.clone(), || Ok(s.witness.expiry))?;
        free(&cs, "request expiry bits", w0, None);
        sec(&cs, "request/L402 balance UInt128 witness");
        let w0 = nw(&cs);
        let balance = UInt128::new_witness(cs.clone(), || Ok(s.witness.current_balance))?;
        free(&cs, "request balance bits", w0, None);
        sec(&cs, "request/L403-404 request_time UInt64 bits == public request_time");
        let request_time = UInt64::new_witness(cs.clone(), || Ok(s.public.request_time))?;
        request_time.to_fp()?.enforce_equal(&request_time_field)?;
        sec(&cs, "request/L405 expiry >= request_time");
        expiry.is_ge(&request_time)?.enforce_equal(&Boolean::TRUE)?;
        sec(&cs, "request/L406-409 solvency_bound UInt128 bits == public solvency_bound");
        let solvency_bound = UInt128::new_witness(cs.clone(), || Ok(s.public.solvency_bound))?;
        solvency_bound
            .to_fp()?
            .enforce_equal(&solvency_bound_field)?;
        sec(&cs, "request/L410-412 balance >= solvency_bound");
        balance
            .is_ge(&solvency_bound)?
            .enforce_equal(&Boolean::TRUE)?;
        sec(&cs, "request/L413 deposit_amount >= balance");
        deposit_amount.is_ge(&balance)?.enforce_equal(&Boolean::TRUE)?;

        sec(&cs, "request/L415 registration Poseidon");
        let registration = poseidon_hash_var(
            cs.clone(),
            &[domain_var(DOMAIN_REG), secret.clone(), FpVar::zero()],
        )?;
        sec(&cs, "request/L419 leaf Poseidon");
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
        for (level, sibling_value) in s.witness.merkle_siblings.iter().enumerate() {
            sec(&cs, &format!("request/L431 merkle sibling[{level}] witness"));
            let w0 = nw(&cs);
            let sibling = FpVar::new_witness(cs.clone(), || Ok(*sibling_value))?;
            free(&cs, &format!("request merkle sibling[{level}]"), w0, None);
            sec(&cs, &format!("request/L432-435 merkle level {level} select+Poseidon"));
            let bit = &note_id.bits[level];
            let left = bit.select(&sibling, &current)?;
            let right = bit.select(&current, &sibling)?;
            current = poseidon_hash_var(cs.clone(), &[domain_var(DOMAIN_NODE), left, right])?;
        }
        sec(&cs, "request/L437 root == active_root");
        current.enforce_equal(&active_root)?;

        sec(&cs, "request/L439 anchor witness");
        let w0 = nw(&cs);
        let anchor = FpVar::new_witness(cs.clone(), || Ok(s.witness.current_anchor))?;
        free(&cs, "request current_anchor", w0, None);
        let is_genesis = enforce_anchor_chain(
            cs.clone(), &secret, &note_id.to_fp()?, &anchor, s.witness.prev_anchor, p,
        )?;
        sec(&cs, "request/L443-445 genesis => balance == deposit");
        balance
            .to_fp()?
            .conditional_enforce_equal(&deposit_amount.to_fp()?, &is_genesis)?;

        let current_commitment =
            commitment_var(cs.clone(), &balance, s.witness.current_blinding, &leaf, p)?;
        sec(&cs, "request/L449 state_message Poseidon");
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
            s.witness.state_signature,
            &is_genesis.not(),
            &format!("{p}/state-sig"),
        )?;

        let h = EdwardsVar::new_constant(cs.clone(), balance_blinding_generator())?;
        sec(&cs, "request/L470 rerandomization bits");
        let rerandomization_bits =
            scalar_bits_witness(cs.clone(), s.witness.rerandomization, "request rerandomization bits")?;
        sec(&cs, "request/L472 H*rerandomization");
        let hr = h.scalar_mul_le(rerandomization_bits.iter())?;
        sec(&cs, "request/L471 commitment + H*rerand");
        let computed_anonymous = current_commitment + hr;
        sec(&cs, "request/L473 == anonymous_commitment");
        computed_anonymous.enforce_equal(&anonymous_commitment)?;

        sec(&cs, "request/L475 nullifier Poseidon");
        let computed_nullifier =
            poseidon_hash_var(cs.clone(), &[domain_var(DOMAIN_NULLIFIER), secret, note_id.to_fp()?, anchor])?;
        sec(&cs, "request/L477 nullifier == public");
        computed_nullifier.enforce_equal(&request_nullifier)?;
        sec(&cs, "request/L478 authorization Poseidon");
        let computed_authorization = poseidon_hash_var(
            cs.clone(),
            &[
                domain_var(DOMAIN_AUTHORIZATION),
                request_nullifier,
                request_context,
            ],
        )?;
        sec(&cs, "request/L486 authorization == public");
        computed_authorization.enforce_equal(&authorization_tag)?;
        sec(&cs, "request/END");
        Ok(())
    }
}

impl ConstraintSynthesizer<CircuitField> for MarkedTransition {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<CircuitField>,
    ) -> Result<(), SynthesisError> {
        let s = self.0;
        sec(&cs, "transition/L604-607 protocol_version input == 2");
        let protocol_version = FpVar::new_input(cs.clone(), || {
            Ok(CircuitField::from(s.public.protocol_version as u64))
        })?;
        protocol_version.enforce_equal(&FpVar::Constant(CircuitField::from(2u64)))?;

        sec(&cs, "transition/L609-612 chain_id input + UInt64 bits");
        let chain_id =
            FpVar::new_input(cs.clone(), || Ok(CircuitField::from(s.public.chain_id)))?;
        let chain_id_u64 = UInt64::new_witness(cs.clone(), || Ok(s.public.chain_id))?;
        chain_id_u64.to_fp()?.enforce_equal(&chain_id)?;
        sec(&cs, "transition/L613 chain_id != 0");
        chain_id.enforce_not_equal(&FpVar::zero())?;

        sec(&cs, "transition/L615 protocol_binding input");
        let protocol_binding = FpVar::new_input(cs.clone(), || Ok(s.public.protocol_binding))?;
        sec(&cs, "transition/L616 protocol_binding != 0");
        protocol_binding.enforce_not_equal(&FpVar::zero())?;
        sec(&cs, "transition/L617-621 roots, note_id inputs");
        let old_root = FpVar::new_input(cs.clone(), || Ok(s.public.old_root))?;
        let new_root = FpVar::new_input(cs.clone(), || Ok(s.public.new_root))?;

        let note_id_field =
            FpVar::new_input(cs.clone(), || Ok(CircuitField::from(s.public.note_id)))?;
        sec(&cs, "transition/L622-623 note_id UInt32 bits == public");
        let note_id = UInt32::new_witness(cs.clone(), || Ok(s.public.note_id))?;
        note_id.to_fp()?.enforce_equal(&note_id_field)?;

        sec(&cs, "transition/L625 commitment input");
        let commitment = FpVar::new_input(cs.clone(), || Ok(s.public.commitment))?;
        sec(&cs, "transition/L626 commitment != 0");
        commitment.enforce_not_equal(&FpVar::zero())?;
        sec(&cs, "transition/L627-630 amount input + UInt64 bits");
        let amount_field =
            FpVar::new_input(cs.clone(), || Ok(CircuitField::from(s.public.amount)))?;
        let amount = UInt64::new_witness(cs.clone(), || Ok(s.public.amount))?;
        amount.to_fp()?.enforce_equal(&amount_field)?;
        sec(&cs, "transition/L631 amount != 0");
        amount_field.enforce_not_equal(&FpVar::zero())?;
        sec(&cs, "transition/L632-635 expiry input + UInt64 bits");
        let expiry_field =
            FpVar::new_input(cs.clone(), || Ok(CircuitField::from(s.public.expiry)))?;
        let expiry = UInt64::new_witness(cs.clone(), || Ok(s.public.expiry))?;
        expiry.to_fp()?.enforce_equal(&expiry_field)?;
        sec(&cs, "transition/L636 expiry != 0");
        expiry_field.enforce_not_equal(&FpVar::zero())?;
        sec(&cs, "transition/L637 inserting Boolean input");
        let inserting = Boolean::new_input(cs.clone(), || Ok(s.public.inserting))?;

        sec(&cs, "transition/L639 leaf Poseidon");
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
        sec(&cs, "transition/L649-650 select old/new leaf");
        let mut computed_old = inserting.select(&FpVar::zero(), &leaf)?;
        let mut computed_new = inserting.select(&leaf, &FpVar::zero())?;
        for (level, sibling_value) in s.witness.siblings.iter().enumerate() {
            sec(&cs, &format!("transition/L652 sibling[{level}] witness"));
            let w0 = nw(&cs);
            let sibling = FpVar::new_witness(cs.clone(), || Ok(*sibling_value))?;
            free(&cs, &format!("transition sibling[{level}]"), w0, None);
            sec(&cs, &format!("transition/L653-661 level {level} old/new select+Poseidon"));
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
        sec(&cs, "transition/L663-664 roots == public");
        computed_old.enforce_equal(&old_root)?;
        computed_new.enforce_equal(&new_root)?;
        sec(&cs, "transition/END");
        Ok(())
    }
}

impl ConstraintSynthesizer<CircuitField> for MarkedWithdrawal {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<CircuitField>,
    ) -> Result<(), SynthesisError> {
        let s = self.0;
        let p = "withdrawal";
        sec(&cs, "withdrawal/L674-691 public inputs (part 1)");
        let protocol_version = FpVar::new_input(cs.clone(), || {
            Ok(CircuitField::from(s.public.protocol_version as u64))
        })?;
        let chain_id =
            FpVar::new_input(cs.clone(), || Ok(CircuitField::from(s.public.chain_id)))?;
        let contract_address = FpVar::new_input(cs.clone(), || Ok(s.public.contract_address))?;
        let registration_field = FpVar::new_input(cs.clone(), || Ok(s.public.registration))?;
        let state_signing_key =
            EdwardsVar::new_input(cs.clone(), || Ok(s.public.state_signing_key))?;
        let clearance_signing_key =
            EdwardsVar::new_input(cs.clone(), || Ok(s.public.clearance_signing_key))?;
        let note_fields = FpVar::new_input(cs.clone(), || {
            Ok(zkapi_proof::groth16::packed_note_fields(s.public.note_id, s.public.deposit_amount, s.public.expiry))
        })?;
        let final_balance_field = FpVar::new_input(cs.clone(), || {
            Ok(CircuitField::from(s.public.final_balance))
        })?;
        let destination = FpVar::new_input(cs.clone(), || Ok(s.public.destination))?;
        sec(&cs, "withdrawal/L693 destination.to_bits_le");
        let _destination_bits = destination.to_bits_le()?;
        sec(&cs, "withdrawal/L694-699 public inputs (part 2)");
        let withdrawal_nullifier =
            FpVar::new_input(cs.clone(), || Ok(s.public.withdrawal_nullifier))?;
        let has_clearance = Boolean::new_input(cs.clone(), || Ok(s.public.has_clearance))?;
        let next_nullifier = FpVar::new_input(cs.clone(), || Ok(s.public.next_nullifier))?;
        let conceded_field = FpVar::new_input(cs.clone(), || Ok(CircuitField::from(s.public.conceded)))?;
        let valid_until_field = FpVar::new_input(cs.clone(), || Ok(CircuitField::from(s.public.valid_until)))?;
        sec(&cs, "withdrawal/L700-701 valid_until UInt64 bits == public");
        let valid_until = UInt64::new_witness(cs.clone(), || Ok(s.public.valid_until))?;
        valid_until.to_fp()?.enforce_equal(&valid_until_field)?;

        sec(&cs, "withdrawal/L703 secret witness");
        let w0 = nw(&cs);
        let secret = FpVar::new_witness(cs.clone(), || Ok(s.witness.secret))?;
        free(&cs, "withdrawal secret", w0, None);
        sec(&cs, "withdrawal/L704 secret != 0");
        secret.enforce_not_equal(&FpVar::zero())?;
        sec(&cs, "withdrawal/L705 note_id UInt32 bits (tied to packed public L717-720)");
        let note_id = UInt32::new_witness(cs.clone(), || Ok(s.public.note_id))?;
        sec(&cs, "withdrawal/L706 deposit_amount UInt128 bits (tied to packed public L717-720)");
        let deposit_amount = UInt128::new_witness(cs.clone(), || Ok(s.public.deposit_amount))?;
        sec(&cs, "withdrawal/L707-708 final_balance UInt128 bits == public");
        let final_balance = UInt128::new_witness(cs.clone(), || Ok(s.public.final_balance))?;
        final_balance.to_fp()?.enforce_equal(&final_balance_field)?;
        sec(&cs, "withdrawal/L709 balance UInt128 bits (tied by L714)");
        let balance = UInt128::new_witness(cs.clone(), || Ok(s.witness.current_balance))?;
        sec(&cs, "withdrawal/L710-711 conceded UInt128 bits == public");
        let conceded = UInt128::new_witness(cs.clone(), || Ok(s.public.conceded))?;
        conceded.to_fp()?.enforce_equal(&conceded_field)?;
        sec(&cs, "withdrawal/L714 balance == final_balance + conceded");
        balance.to_fp()?.enforce_equal(&(final_balance.to_fp()? + conceded.to_fp()?))?;
        sec(&cs, "withdrawal/L715 deposit_amount >= balance");
        deposit_amount.is_ge(&balance)?.enforce_equal(&Boolean::TRUE)?;
        sec(&cs, "withdrawal/L716 has_clearance => conceded == 0");
        conceded_field.conditional_enforce_equal(&FpVar::zero(), &has_clearance)?;
        sec(&cs, "withdrawal/L717 expiry UInt64 bits (tied to packed public L717-720)");
        let expiry = UInt64::new_witness(cs.clone(), || Ok(s.public.expiry))?;
        sec(&cs, "withdrawal/L718-720 packed note fields == public");
        (note_id.to_fp()? * CircuitField::from(2u64).pow([192])
            + deposit_amount.to_fp()? * CircuitField::from(2u64).pow([64])
            + expiry.to_fp()?).enforce_equal(&note_fields)?;

        sec(&cs, "withdrawal/L722 registration Poseidon");
        let registration = poseidon_hash_var(
            cs.clone(),
            &[domain_var(DOMAIN_REG), secret.clone(), FpVar::zero()],
        )?;
        sec(&cs, "withdrawal/L726 registration == public");
        registration.enforce_equal(&registration_field)?;
        sec(&cs, "withdrawal/L727 leaf Poseidon");
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

        sec(&cs, "withdrawal/L738 anchor witness");
        let w0 = nw(&cs);
        let anchor = FpVar::new_witness(cs.clone(), || Ok(s.witness.current_anchor))?;
        free(&cs, "withdrawal current_anchor", w0, None);
        let is_genesis = enforce_anchor_chain(
            cs.clone(), &secret, &note_id.to_fp()?, &anchor, s.witness.prev_anchor, p,
        )?;
        sec(&cs, "withdrawal/L742-744 genesis => balance == deposit");
        balance
            .to_fp()?
            .conditional_enforce_equal(&deposit_amount.to_fp()?, &is_genesis)?;

        let current_commitment = commitment_var(
            cs.clone(),
            &balance,
            s.witness.final_blinding,
            &leaf,
            p,
        )?;
        sec(&cs, "withdrawal/L752 state_message Poseidon");
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
            s.witness.state_signature,
            &is_genesis.not(),
            &format!("{p}/state-sig"),
        )?;

        sec(&cs, "withdrawal/L772 nullifier Poseidon");
        let computed_nullifier =
            poseidon_hash_var(cs.clone(), &[domain_var(DOMAIN_NULLIFIER), secret.clone(), note_id.to_fp()?, anchor])?;
        sec(&cs, "withdrawal/L774 nullifier == public");
        computed_nullifier.enforce_equal(&withdrawal_nullifier)?;

        sec(&cs, "withdrawal/L776 next_anchor Poseidon");
        let next_anchor = poseidon_hash_var(cs.clone(), &[
            domain_var(DOMAIN_ANCHOR), withdrawal_nullifier.clone(),
        ])?;
        sec(&cs, "withdrawal/L779 computed_next Poseidon");
        let computed_next = poseidon_hash_var(cs.clone(), &[
            domain_var(DOMAIN_NULLIFIER), secret, note_id.to_fp()?, next_anchor,
        ])?;
        sec(&cs, "withdrawal/L782 next_nullifier == select(has_clearance, 0, computed_next)");
        has_clearance.select(&FpVar::zero(), &computed_next)?.enforce_equal(&next_nullifier)?;

        sec(&cs, "withdrawal/L784 clearance message Poseidon");
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
            cs.clone(),
            &clearance_signing_key,
            &clear_message,
            s.witness.clearance_signature,
            &has_clearance,
            &format!("{p}/clearance-sig"),
        )?;
        sec(&cs, "withdrawal/END");
        Ok(())
    }
}
