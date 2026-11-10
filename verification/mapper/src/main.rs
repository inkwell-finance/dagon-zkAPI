mod circuits;

use std::fs;

use anyhow::{anyhow, ensure, Result};
use ark_bn254::Fr;
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_ed_on_bn254::{EdwardsAffine, EdwardsProjective, Fr as EdwardsScalarField};
use ark_relations::r1cs::{
    ConstraintMatrices, ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, SynthesisMode,
};
use sha2::{Digest, Sha256};
use zkapi_proof::groth16::*;

use circuits::{Mark, MarkedRequest, MarkedTransition, MarkedWithdrawal, MARKS};

const PINS: [(&str, &str); 3] = [
    ("request", "ed73c7919790d3cb75e9fc60373aa7ac3c5fb4820c43f2364451ebfdb7f14566"),
    ("withdrawal", "a2b46576733aafbe90b816a26cfe8f40c613d76581fbf9e982026e191fa0c973"),
    ("transition", "a9cd49c195bd2d6e80664672f0994542baa12aa661e8e93bd9563f3bed8ad1c1"),
];

fn matrices_of(circuit: impl ConstraintSynthesizer<Fr>) -> Result<ConstraintMatrices<Fr>> {
    let cs = ConstraintSystem::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Setup);
    circuit
        .generate_constraints(cs.clone())
        .map_err(|e| anyhow!("synthesis failed: {e}"))?;
    cs.finalize();
    cs.to_matrices().ok_or_else(|| anyhow!("no matrices"))
}

fn sig() -> StateSignature {
    StateSignature { r: EdwardsAffine::zero(), s: EdwardsScalarField::from(0u64) }
}

fn key() -> EdwardsAffine {
    EdwardsProjective::generator().into_affine()
}

fn request() -> RequestCircuit {
    RequestCircuit {
        public: RequestPublic {
            protocol_version: 2,
            chain_id: 1,
            contract_address: Fr::from(1u64),
            active_root: Fr::from(1u64),
            state_signing_key: key(),
            request_time: 1,
            solvency_bound: 0,
            request_nullifier: Fr::from(1u64),
            authorization_tag: Fr::from(1u64),
            anonymous_commitment: key(),
        },
        witness: RequestWitness {
            secret: Fr::from(1u64),
            request_context: Fr::from(1u64),
            note_id: 0,
            deposit_amount: 0,
            expiry: 1,
            merkle_siblings: [Fr::from(0u64); REQUEST_MERKLE_DEPTH],
            current_balance: 0,
            current_blinding: EdwardsScalarField::from(0u64),
            rerandomization: EdwardsScalarField::from(0u64),
            current_anchor: Fr::from(1u64),
            prev_anchor: Fr::from(0u64),
            state_signature: sig(),
        },
    }
}

fn withdrawal() -> WithdrawalCircuit {
    WithdrawalCircuit {
        public: WithdrawalPublic {
            protocol_version: 2,
            chain_id: 1,
            contract_address: Fr::from(1u64),
            registration: Fr::from(1u64),
            state_signing_key: key(),
            clearance_signing_key: key(),
            note_id: 0,
            deposit_amount: 0,
            expiry: 1,
            final_balance: 0,
            destination: Fr::from(1u64),
            withdrawal_nullifier: Fr::from(1u64),
            has_clearance: false,
            next_nullifier: Fr::from(1u64),
            conceded: 0,
            valid_until: 1,
        },
        witness: WithdrawalWitness {
            secret: Fr::from(1u64),
            current_balance: 0,
            final_blinding: EdwardsScalarField::from(0u64),
            current_anchor: Fr::from(1u64),
            prev_anchor: Fr::from(0u64),
            state_signature: sig(),
            clearance_signature: sig(),
        },
    }
}

fn transition() -> SolanaTransitionCircuit {
    SolanaTransitionCircuit {
        public: SolanaTransitionPublic {
            protocol_version: 2,
            chain_id: 1,
            protocol_binding: Fr::from(1u64),
            old_root: Fr::from(1u64),
            new_root: Fr::from(1u64),
            note_id: 0,
            commitment: Fr::from(7u64),
            amount: 1,
            expiry: 1,
            inserting: true,
        },
        witness: SolanaTransitionWitness { siblings: [Fr::from(0u64); REQUEST_MERKLE_DEPTH] },
    }
}

fn dump(id: &str, m: &ConstraintMatrices<Fr>, out: &str) -> Result<()> {
    let bytes = zkapi_proof::ceremony::r1cs_bytes(m)?;
    let digest = hex::encode(Sha256::digest(&bytes));
    let pin = PINS.iter().find(|(k, _)| *k == id).unwrap().1;
    println!("{id}: sha256={digest} pin_match={} constraints={} inst={} wit={}",
        digest == pin, m.num_constraints, m.num_instance_variables, m.num_witness_variables);
    ensure!(digest == pin, "{id}: instrumented copy is not byte-identical to the pinned r1cs");
    let marks: Vec<serde_json::Value> = MARKS.with(|v| v.borrow_mut().drain(..).collect::<Vec<_>>())
        .into_iter()
        .map(|mk| match mk {
            Mark::Section(l, w, c) => serde_json::json!({"kind":"section","label":l,"wit":w,"cons":c}),
            Mark::Free(l, s, e) => serde_json::json!({"kind":"free","label":l,"start":s,"end":e}),
        })
        .collect();
    let doc = serde_json::json!({
        "id": id,
        "num_instance": m.num_instance_variables,
        "num_witness": m.num_witness_variables,
        "num_constraints": m.num_constraints,
        "marks": marks,
    });
    fs::write(format!("{out}/{id}.marks.json"), serde_json::to_string_pretty(&doc)?)?;
    Ok(())
}

fn main() -> Result<()> {
    let out = std::env::args().nth(1).ok_or_else(|| anyhow!("usage: picus-mapper OUT_DIR"))?;
    fs::create_dir_all(&out)?;
    dump("request", &matrices_of(MarkedRequest(request()))?, &out)?;
    dump("withdrawal", &matrices_of(MarkedWithdrawal(withdrawal()))?, &out)?;
    dump("transition", &matrices_of(MarkedTransition(transition()))?, &out)?;
    Ok(())
}
