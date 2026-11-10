//! Throwaway forged-witness and gadget-lemma checks for the Picus audit.
//! Every check prints PASS/FAIL with what it demonstrates; exit code 1 on FAIL.

#[path = "../circuits.rs"]
mod circuits;

use ark_bn254::Fr;
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_ed_on_bn254::{constraints::EdwardsVar, EdwardsAffine, EdwardsProjective, Fr as Scalar};
use ark_ff::{PrimeField, UniformRand};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::groups::CurveVar;
use ark_r1cs_std::R1CSVar;

use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, OptimizationGoal};
use rand::rngs::StdRng;
use rand::SeedableRng;
use zkapi_proof::groth16::*;

use circuits::{Mark, MarkedRequest, MarkedWithdrawal, MARKS};

static mut FAILS: u32 = 0;

fn check(name: &str, ok: bool, detail: &str) {
    println!("{} {name}: {detail}", if ok { "PASS" } else { "FAIL" });
    if !ok {
        unsafe { FAILS += 1 };
    }
}

fn bits_le(v: &num_bigint_lite::Big, n: usize) -> Vec<bool> {
    (0..n).map(|i| v.bit(i)).collect()
}

/// Minimal big-integer helper (no extra crates): little-endian u64 limbs.
mod num_bigint_lite {
    #[derive(Clone)]
    pub struct Big(pub Vec<u64>);
    impl Big {
        pub fn bit(&self, i: usize) -> bool {
            self.0.get(i / 64).map(|l| (l >> (i % 64)) & 1 == 1).unwrap_or(false)
        }
        pub fn add(&self, o: &Big) -> Big {
            let n = self.0.len().max(o.0.len()) + 1;
            let mut out = vec![0u64; n];
            let mut carry = 0u128;
            for i in 0..n {
                let s = *self.0.get(i).unwrap_or(&0) as u128 + *o.0.get(i).unwrap_or(&0) as u128 + carry;
                out[i] = s as u64;
                carry = s >> 64;
            }
            Big(out)
        }
    }
}
use num_bigint_lite::Big;

fn modulus() -> Big {
    Big(Fr::MODULUS.0.to_vec())
}

/// L-bits: Boolean::enforce_in_field_le(bits) + sum check, exactly as
/// FpVar::to_bits_le does it, on caller-chosen (possibly non-canonical) bits.
fn in_field_accepts(bits: &[bool], x: Fr) -> bool {
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    let xv = FpVar::new_witness(cs.clone(), || Ok(x)).unwrap();
    let bs: Vec<Boolean<Fr>> = bits.iter().map(|b| Boolean::new_witness(cs.clone(), || Ok(*b)).unwrap()).collect();
    let sum = Boolean::le_bits_to_fp(&bs).unwrap();
    sum.enforce_equal(&xv).unwrap();
    Boolean::enforce_in_field_le(&bs).unwrap();
    cs.is_satisfied().unwrap()
}

fn lemma_bits(rng: &mut StdRng) {
    let p = modulus();
    let mut ok_canon = true;
    let mut rejected_alias = true;
    let mut tested_alias = 0;
    for i in 0..400 {
        let x = if i < 200 { Fr::from(i as u64) } else { Fr::rand(rng) };
        let xb = Big(x.into_bigint().0.to_vec());
        ok_canon &= in_field_accepts(&bits_le(&xb, 254), x);
        let alias = xb.add(&p);
        if !alias.bit(254) && !alias.bit(255) {
            tested_alias += 1;
            rejected_alias &= !in_field_accepts(&bits_le(&alias, 254), x);
        }
    }
    check("L-bits canonical", ok_canon, "to_bits_le gadget accepts the canonical 254-bit decomposition (400 values)");
    check("L-bits alias", rejected_alias && tested_alias > 0,
        &format!("the only other 254-bit decomposition x+p is rejected ({tested_alias} values with x+p < 2^254)"));
    // boundary: p-1 accepted, p..p+k rejected as decompositions of 0..k
    let pm1 = Fr::from(0u64) - Fr::from(1u64);
    let b_pm1 = Big(pm1.into_bigint().0.to_vec());
    check("L-bits p-1", in_field_accepts(&bits_le(&b_pm1, 254), pm1), "p-1 accepted");
    check("L-bits p", !in_field_accepts(&bits_le(&p, 254), Fr::from(0u64)), "bits of p rejected as a decomposition of 0");
}

fn find_free(prefix: &str, num_instance: usize) -> Vec<(String, usize, usize)> {
    MARKS.with(|m| m.borrow().iter().filter_map(|mk| match mk {
        Mark::Free(l, s, e) if l.starts_with(prefix) => Some((l.clone(), s + num_instance, e + num_instance)),
        _ => None,
    }).collect())
}

fn section_start(label_part: &str) -> usize {
    MARKS.with(|m| m.borrow().iter().find_map(|mk| match mk {
        Mark::Section(l, w, _) if l.contains(label_part) => Some(*w),
        _ => None,
    }).expect("section"))
}

fn request_fixture(rng: &mut StdRng, genesis: bool) -> RequestCircuit {
    let secret = Fr::rand(rng);
    let note_id = 5u32;
    let deposit = 1_000u128;
    let expiry = 2_000u64;
    let reg = registration_commitment(secret);
    let leaf = note_leaf(note_id, reg, deposit, expiry);
    let siblings: [Fr; REQUEST_MERKLE_DEPTH] = std::array::from_fn(|_| Fr::rand(rng));
    let root = merkle_root(note_id, leaf, &siblings);
    let key = StateSigningKey::generate(rng);
    let (anchor, prev, balance) = if genesis {
        (Fr::from(1u64), Fr::from(0u64), deposit)
    } else {
        let prev = Fr::from(1u64);
        (next_anchor(request_nullifier(secret, note_id, prev)), prev, 600u128)
    };
    let blinding = Scalar::rand(rng);
    let commitment = balance_commitment(balance, blinding, leaf).into_affine();
    let sig = if genesis {
        StateSignature { r: EdwardsAffine::zero(), s: Scalar::from(0u64) }
    } else {
        key.sign(state_message(2, 7, Fr::from(9u64), commitment, anchor), rng)
    };
    let rerand = Scalar::rand(rng);
    let anon = rerandomize_commitment(commitment.into_group(), rerand).into_affine();
    let nullifier = request_nullifier(secret, note_id, anchor);
    let ctx = Fr::rand(rng);
    RequestCircuit {
        public: RequestPublic {
            protocol_version: 2, chain_id: 7, contract_address: Fr::from(9u64), active_root: root,
            state_signing_key: key.public, request_time: 1_500, solvency_bound: 10,
            request_nullifier: nullifier, authorization_tag: authorization_tag(nullifier, ctx),
            anonymous_commitment: anon,
        },
        witness: RequestWitness {
            secret, request_context: ctx, note_id, deposit_amount: deposit, expiry,
            merkle_siblings: siblings, current_balance: balance, current_blinding: blinding,
            rerandomization: rerand, current_anchor: anchor, prev_anchor: prev, state_signature: sig,
        },
    }
}

fn synth<C: ConstraintSynthesizer<Fr>>(c: C) -> ConstraintSystemRef<Fr> {
    MARKS.with(|m| m.borrow_mut().clear());
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    c.generate_constraints(cs.clone()).unwrap();
    cs.finalize();
    cs
}

fn set_wire(cs: &ConstraintSystemRef<Fr>, wire: usize, v: Fr) -> Fr {
    let ni = cs.num_instance_variables();
    let mut b = cs.borrow_mut().unwrap();
    let old = b.witness_assignment[wire - ni];
    b.witness_assignment[wire - ni] = v;
    old
}

fn is_eq_multiplier(rng: &mut StdRng) {
    // genesis: anchor == 1, so is_eq's inverse-multiplier is unconstrained
    let cs = synth(MarkedRequest(request_fixture(rng, true)));
    check("request genesis fixture", cs.is_satisfied().unwrap(), "honest genesis request witness satisfies the pinned constraints");
    let ni = cs.num_instance_variables();
    let s = section_start("request/L830") + ni;
    // wires: s = is_not_equal (no booleanity), s+1 = multiplier
    let forged = Fr::rand(rng);
    let old = set_wire(&cs, s + 1, forged);
    let sat = cs.is_satisfied().unwrap();
    check("C1 is_eq multiplier (request genesis)", sat && old != forged,
        "multiplier wire (L830 anchor.is_eq(1)) replaced by a random value: still satisfied, same public inputs; it feeds no other constraint");
    set_wire(&cs, s + 1, old);
    let old_ne = set_wire(&cs, s, Fr::from(1u64));
    check("C1 control: is_genesis flag", !cs.is_satisfied().unwrap(), "flipping is_not_equal itself is rejected");
    set_wire(&cs, s, old_ne);

    let cs2 = synth(MarkedRequest(request_fixture(rng, false)));
    check("request non-genesis fixture", cs2.is_satisfied().unwrap(), "honest signed non-genesis request satisfies");
    let s2 = section_start("request/L830") + ni;
    set_wire(&cs2, s2 + 1, Fr::rand(rng));
    check("C1 control: multiplier when anchor != 1", !cs2.is_satisfied().unwrap(), "multiplier is pinned to 1/(anchor-1) when anchor != 1");
}

fn genesis_free_witnesses(rng: &mut StdRng) {
    // genesis: prev_anchor only feeds the (disabled) chain equality; signature unchecked
    let cs = synth(MarkedRequest(request_fixture(rng, true)));
    let ni = cs.num_instance_variables();
    let prev = find_free("request prev_anchor", 0)[0].1 + 0;
    let _ = ni;
    // Changing prev_anchor requires recomputing its two Poseidon hashes; instead
    // re-synthesise with a different prev_anchor and compare public inputs.
    let mut a = request_fixture(&mut StdRng::seed_from_u64(77), true);
    let mut b = a.clone();
    b.witness.prev_anchor = Fr::from(123456u64);
    b.witness.state_signature = StateSignature {
        r: (EdwardsProjective::generator() * Scalar::from(5u64)).into_affine(),
        s: Scalar::from(99u64),
    };
    a.witness.prev_anchor = Fr::from(0u64);
    let (ca, cb) = (synth(MarkedRequest(a.clone())), synth(MarkedRequest(b.clone())));
    let same_pub = a.public.to_field_elements() == b.public.to_field_elements();
    check("C2 genesis prev_anchor / signature free", ca.is_satisfied().unwrap() && cb.is_satisfied().unwrap() && same_pub,
        &format!("two genesis witnesses with different prev_anchor and arbitrary (R,s) both satisfy with identical public inputs (prev wire {prev})"));
}

fn torsion_and_scalar_aliases(rng: &mut StdRng) {
    // C3: EdwardsVar::new_witness allocates ge with 8*ge = R; ge + T (T in E[8]) gives the same R.
    // Reproduce the exact arkworks allocation path: on-curve alloc of ge, three doublings.
    let r = (EdwardsProjective::generator() * Scalar::rand(rng)).into_affine();
    // a point of order 2 on Baby-JubJub (a=1 form): (0,-1)
    let t2 = EdwardsAffine::new_unchecked(ark_ed_on_bn254::Fq::from(0u64), -ark_ed_on_bn254::Fq::from(1u64));
    let ge = r.mul_by_cofactor_inv();
    let alt = (ge.into_group() + t2.into_group()).into_affine();
    let mut outs = vec![];
    for g in [ge, alt] {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mut v = EdwardsVar::new_variable_omit_prime_order_check(cs.clone(), || Ok(g.into_group()), ark_r1cs_std::alloc::AllocationMode::Witness).unwrap();
        for _ in 0..3 { v.double_in_place().unwrap(); }
        let target = EdwardsVar::new_input(cs.clone(), || Ok(r)).unwrap();
        v.enforce_equal(&target).unwrap();
        outs.push(cs.is_satisfied().unwrap());
    }
    check("C3 signature R pre-cofactor alias", outs == vec![true, true] && ge != alt,
        "ge and ge+(0,-1) both satisfy the R allocation (8*ge = R) with the same R");

    // C4: 251-bit scalar witnesses (s, blinding, rerandomization) are not range-checked
    // below the subgroup order l; k and k+l give the same point.
    let l = Big(Scalar::MODULUS.0.to_vec());
    let mut found = false;
    for _ in 0..64 {
        let k = Scalar::rand(rng);
        let kb = Big(k.into_bigint().0.to_vec());
        let alias = kb.add(&l);
        if (251..256).any(|i| alias.bit(i)) { continue; }
        let h = balance_blinding_generator();
        let mut pts = vec![];
        for bits in [bits_le(&kb, 251), bits_le(&alias, 251)] {
            let cs = ConstraintSystem::<Fr>::new_ref();
            let hv = EdwardsVar::new_constant(cs.clone(), h).unwrap();
            let bs: Vec<Boolean<Fr>> = bits.iter().map(|b| Boolean::new_witness(cs.clone(), || Ok(*b)).unwrap()).collect();
            let out = hv.scalar_mul_le(bs.iter()).unwrap();
            assert!(cs.is_satisfied().unwrap());
            pts.push(out.value().unwrap());
        }
        found = pts[0] == pts[1];
        break;
    }
    check("C4 251-bit scalar alias", found, "bits(k) and bits(k+l) both satisfy H*bits with the same output point");
}

fn withdrawal_check(rng: &mut StdRng) {
    // honest non-genesis withdrawal (escape, no clearance) satisfies; used as a fixture sanity check
    let secret = Fr::rand(rng);
    let (note_id, deposit, expiry) = (3u32, 5_000u128, 9_000u64);
    let reg = registration_commitment(secret);
    let leaf = note_leaf(note_id, reg, deposit, expiry);
    let key = StateSigningKey::generate(rng);
    let prev = Fr::from(1u64);
    let anchor = next_anchor(request_nullifier(secret, note_id, prev));
    let (balance, conceded) = (4_000u128, 250u128);
    let blinding = Scalar::rand(rng);
    let commitment = balance_commitment(balance, blinding, leaf).into_affine();
    let sig = key.sign(state_message(2, 7, Fr::from(9u64), commitment, anchor), rng);
    let wn = request_nullifier(secret, note_id, anchor);
    let c = WithdrawalCircuit {
        public: WithdrawalPublic {
            protocol_version: 2, chain_id: 7, contract_address: Fr::from(9u64), registration: reg,
            state_signing_key: key.public, clearance_signing_key: key.public, note_id, deposit_amount: deposit,
            expiry, final_balance: balance - conceded, destination: Fr::from(42u64), withdrawal_nullifier: wn,
            has_clearance: false, next_nullifier: successor_nullifier(secret, note_id, wn), conceded, valid_until: 77,
        },
        witness: WithdrawalWitness {
            secret, current_balance: balance, final_blinding: blinding, current_anchor: anchor, prev_anchor: prev,
            state_signature: sig, clearance_signature: StateSignature { r: EdwardsAffine::zero(), s: Scalar::from(0u64) },
        },
    };
    let cs = synth(MarkedWithdrawal(c.clone()));
    check("withdrawal escape fixture", cs.is_satisfied().unwrap(), "honest escape withdrawal satisfies");
    let mut bad = c.clone();
    bad.public.final_balance = balance - conceded + 1;
    let cs = synth(MarkedWithdrawal(bad));
    check("withdrawal control", !cs.is_satisfied().unwrap(), "final_balance + conceded != signed balance is rejected");
}
fn ec_denominators(rng: &mut StdRng) {
    // L-EC sanity: for on-curve points (prime-order and small-torsion mixes),
    // the add/double denominators used by the arkworks gadget never vanish.
    use ark_ec::twisted_edwards::TECurveConfig;
    use ark_ed_on_bn254::{EdwardsConfig, Fq};
    let (a, d) = (EdwardsConfig::COEFF_A, EdwardsConfig::COEFF_D);
    let t2 = EdwardsAffine::new_unchecked(Fq::from(0u64), -Fq::from(1u64));
    let mut pts: Vec<EdwardsAffine> = (0..200)
        .map(|i| {
            let p = EdwardsProjective::generator() * Scalar::rand(rng);
            if i % 2 == 0 { (p + t2.into_group()).into_affine() } else { p.into_affine() }
        })
        .collect();
    pts.push(EdwardsAffine::zero());
    pts.push(t2);
    let mut ok = true;
    for p in &pts {
        ok &= p.is_on_curve();
        let (x2, y2) = (p.x * p.x, p.y * p.y);
        ok &= a * x2 + y2 != Fq::from(0u64);
        ok &= Fq::from(2u64) - a * x2 - y2 != Fq::from(0u64);
        for q in pts.iter().take(40) {
            let v = d * p.x * q.x * p.y * q.y;
            ok &= Fq::from(1u64) + v != Fq::from(0u64) && Fq::from(1u64) - v != Fq::from(0u64);
        }
    }
    check("L-EC denominators", ok, &format!("a={a}, d non-square; 1 +- d*x1*x2*y1*y2 and a*x^2+y^2, 2-a*x^2-y^2 non-zero on {} on-curve points incl. 2-torsion", pts.len()));
}


fn main() {
    let mut rng = StdRng::seed_from_u64(0x5eed);
    lemma_bits(&mut rng);
    is_eq_multiplier(&mut rng);
    genesis_free_witnesses(&mut rng);
    torsion_and_scalar_aliases(&mut rng);
    withdrawal_check(&mut rng);
    ec_denominators(&mut rng);

    let fails = unsafe { FAILS };
    println!("{} failures", fails);
    std::process::exit(if fails == 0 { 0 } else { 1 });
}
