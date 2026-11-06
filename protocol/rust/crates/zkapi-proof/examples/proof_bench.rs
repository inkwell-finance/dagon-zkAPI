use std::env;
use std::fs;
use std::hint::black_box;
use std::path::Path;
use std::time::Instant;

use anyhow::{bail, Context, Result};
use ark_bn254::Fr;
use ark_ed_on_bn254::{EdwardsAffine, Fr as EdwardsScalarField};
use ark_ff::PrimeField;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use base64::Engine;
use serde::Serialize;
use zkapi_core::v2 as core;
use zkapi_proof::compact::{
    balance_commitment, rerandomize, CompactSigner, RequestProver, RequestVerifier,
    RequestWitnessData, WithdrawalProver, WithdrawalVerifier, WithdrawalWitnessData,
};
use zkapi_proof::groth16::{
    RequestCircuit, RequestPublic, RequestWitness, StateSignature, WithdrawalCircuit,
    WithdrawalPublic, WithdrawalWitness,
};
use zkapi_types::{
    Felt252, RequestPublicInputsV2, SchnorrSignature, WithdrawalPublicInputsV2, MERKLE_DEPTH,
};

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum BenchCase {
    RequestGenesis,
    RequestState,
    WithdrawalGenesisEscape,
    WithdrawalGenesisMutual,
    WithdrawalStateEscape,
    WithdrawalStateMutual,
}

impl BenchCase {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "request_genesis" => Ok(Self::RequestGenesis),
            "request_state" => Ok(Self::RequestState),
            "withdrawal_genesis_escape" => Ok(Self::WithdrawalGenesisEscape),
            "withdrawal_genesis_mutual" => Ok(Self::WithdrawalGenesisMutual),
            "withdrawal_state_escape" => Ok(Self::WithdrawalStateEscape),
            "withdrawal_state_mutual" => Ok(Self::WithdrawalStateMutual),
            _ => bail!(
                "unknown case {value:?}; expected request_genesis, request_state, \
                 withdrawal_genesis_escape, withdrawal_genesis_mutual, \
                 withdrawal_state_escape, or withdrawal_state_mutual"
            ),
        }
    }

    fn is_request(self) -> bool {
        matches!(self, Self::RequestGenesis | Self::RequestState)
    }
}

#[derive(Debug, Serialize)]
struct Distribution {
    samples_ms: Vec<f64>,
    min_ms: f64,
    median_ms: f64,
    mean_ms: f64,
    p95_ms: f64,
    max_ms: f64,
}

impl Distribution {
    fn new(samples_ms: Vec<f64>) -> Self {
        let mut sorted = samples_ms.clone();
        sorted.sort_by(f64::total_cmp);
        let len = sorted.len();
        let median_ms = if len % 2 == 0 {
            (sorted[len / 2 - 1] + sorted[len / 2]) / 2.0
        } else {
            sorted[len / 2]
        };
        let p95_index = ((len as f64 * 0.95).ceil() as usize)
            .saturating_sub(1)
            .min(len - 1);
        Self {
            min_ms: sorted[0],
            median_ms,
            mean_ms: sorted.iter().sum::<f64>() / len as f64,
            p95_ms: sorted[p95_index],
            max_ms: sorted[len - 1],
            samples_ms,
        }
    }
}

#[derive(Debug, Serialize)]
struct BenchResult {
    case: BenchCase,
    iterations: usize,
    load_iterations: usize,
    warmup_iterations: usize,
    rayon_threads: String,
    proving_key_bytes: u64,
    verifying_key_bytes: u64,
    constraints: usize,
    instance_variables: usize,
    witness_variables: usize,
    proof_bytes: usize,
    prover_load: Distribution,
    verifier_load: Distribution,
    prove: Distribution,
    verify: Distribution,
}

#[derive(Clone)]
struct RequestFixture {
    public: RequestPublicInputsV2,
    witness: RequestWitnessData,
    circuit: RequestCircuit,
}

#[derive(Clone)]
struct WithdrawalFixture {
    public: WithdrawalPublicInputsV2,
    witness: WithdrawalWitnessData,
    circuit: WithdrawalCircuit,
}

fn main() -> Result<()> {
    let args = env::args().collect::<Vec<_>>();
    if !(5..=6).contains(&args.len()) {
        bail!(
            "usage: proof_bench SETUP_DIRECTORY CASE ITERATIONS WARMUP_ITERATIONS \
             [LOAD_ITERATIONS]"
        );
    }
    let setup = Path::new(&args[1]);
    let case = BenchCase::parse(&args[2])?;
    let iterations = parse_positive("ITERATIONS", &args[3])?;
    let warmup_iterations = args[4]
        .parse::<usize>()
        .with_context(|| format!("invalid WARMUP_ITERATIONS {:?}", args[4]))?;
    let load_iterations = args
        .get(5)
        .map(|value| parse_positive("LOAD_ITERATIONS", value))
        .transpose()?
        .unwrap_or(iterations);

    let result = if case.is_request() {
        bench_request(setup, case, iterations, warmup_iterations, load_iterations)?
    } else {
        bench_withdrawal(setup, case, iterations, warmup_iterations, load_iterations)?
    };
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

fn parse_positive(name: &str, value: &str) -> Result<usize> {
    let parsed = value
        .parse::<usize>()
        .with_context(|| format!("invalid {name} {value:?}"))?;
    if parsed == 0 {
        bail!("{name} must be positive");
    }
    Ok(parsed)
}

fn bench_request(
    setup: &Path,
    case: BenchCase,
    iterations: usize,
    warmup_iterations: usize,
    load_iterations: usize,
) -> Result<BenchResult> {
    let fixture = request_fixture(matches!(case, BenchCase::RequestGenesis))?;
    let (constraints, instance_variables, witness_variables) = constraint_counts(fixture.circuit)?;

    let (prover, prover_load) = timed_load(load_iterations, || RequestProver::load(setup))?;
    let (verifier, verifier_load) = timed_load(load_iterations, || RequestVerifier::load(setup))?;

    for _ in 0..warmup_iterations {
        let proof = prover.prove(&fixture.public, fixture.witness.clone())?;
        if !verifier.verify(&fixture.public, &proof)? {
            bail!("request warmup proof did not verify");
        }
    }

    let mut proofs = Vec::with_capacity(iterations);
    let mut prove_ms = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let started = Instant::now();
        let proof = prover.prove(
            black_box(&fixture.public),
            black_box(fixture.witness.clone()),
        )?;
        prove_ms.push(elapsed_ms(started));
        proofs.push(proof);
    }
    let proof_bytes = decoded_proof_len(&proofs[0].proof)?;
    let mut verify_ms = Vec::with_capacity(iterations);
    for proof in &proofs {
        let started = Instant::now();
        if !verifier.verify(black_box(&fixture.public), black_box(proof))? {
            bail!("request proof did not verify");
        }
        verify_ms.push(elapsed_ms(started));
    }

    Ok(BenchResult {
        case,
        iterations,
        load_iterations,
        warmup_iterations,
        rayon_threads: env::var("RAYON_NUM_THREADS").unwrap_or_else(|_| "default".into()),
        proving_key_bytes: fs::metadata(setup.join("request.pk"))?.len(),
        verifying_key_bytes: fs::metadata(setup.join("request.vk"))?.len(),
        constraints,
        instance_variables,
        witness_variables,
        proof_bytes,
        prover_load: Distribution::new(prover_load),
        verifier_load: Distribution::new(verifier_load),
        prove: Distribution::new(prove_ms),
        verify: Distribution::new(verify_ms),
    })
}

fn bench_withdrawal(
    setup: &Path,
    case: BenchCase,
    iterations: usize,
    warmup_iterations: usize,
    load_iterations: usize,
) -> Result<BenchResult> {
    let genesis = matches!(
        case,
        BenchCase::WithdrawalGenesisEscape | BenchCase::WithdrawalGenesisMutual
    );
    let mutual = matches!(
        case,
        BenchCase::WithdrawalGenesisMutual | BenchCase::WithdrawalStateMutual
    );
    let fixture = withdrawal_fixture(genesis, mutual)?;
    let (constraints, instance_variables, witness_variables) = constraint_counts(fixture.circuit)?;

    let (prover, prover_load) = timed_load(load_iterations, || WithdrawalProver::load(setup))?;
    let (verifier, verifier_load) =
        timed_load(load_iterations, || WithdrawalVerifier::load(setup))?;

    for _ in 0..warmup_iterations {
        let proof = prover.prove(&fixture.public, fixture.witness.clone())?;
        if !verifier.verify(&fixture.public, &proof)? {
            bail!("withdrawal warmup proof did not verify");
        }
    }

    let mut proofs = Vec::with_capacity(iterations);
    let mut prove_ms = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let started = Instant::now();
        let proof = prover.prove(
            black_box(&fixture.public),
            black_box(fixture.witness.clone()),
        )?;
        prove_ms.push(elapsed_ms(started));
        proofs.push(proof);
    }
    let proof_bytes = decoded_proof_len(&proofs[0].proof)?;
    let mut verify_ms = Vec::with_capacity(iterations);
    for proof in &proofs {
        let started = Instant::now();
        if !verifier.verify(black_box(&fixture.public), black_box(proof))? {
            bail!("withdrawal proof did not verify");
        }
        verify_ms.push(elapsed_ms(started));
    }

    Ok(BenchResult {
        case,
        iterations,
        load_iterations,
        warmup_iterations,
        rayon_threads: env::var("RAYON_NUM_THREADS").unwrap_or_else(|_| "default".into()),
        proving_key_bytes: fs::metadata(setup.join("withdrawal.pk"))?.len(),
        verifying_key_bytes: fs::metadata(setup.join("withdrawal.vk"))?.len(),
        constraints,
        instance_variables,
        witness_variables,
        proof_bytes,
        prover_load: Distribution::new(prover_load),
        verifier_load: Distribution::new(verifier_load),
        prove: Distribution::new(prove_ms),
        verify: Distribution::new(verify_ms),
    })
}

fn timed_load<T>(iterations: usize, mut load: impl FnMut() -> Result<T>) -> Result<(T, Vec<f64>)> {
    let mut samples = Vec::with_capacity(iterations);
    let mut last = None;
    for _ in 0..iterations {
        let started = Instant::now();
        last = Some(load()?);
        samples.push(elapsed_ms(started));
    }
    Ok((last.context("load loop produced no value")?, samples))
}

fn constraint_counts<C: ConstraintSynthesizer<Fr>>(circuit: C) -> Result<(usize, usize, usize)> {
    let cs = ConstraintSystem::new_ref();
    circuit.generate_constraints(cs.clone())?;
    if !cs.is_satisfied()? {
        bail!("benchmark circuit is not satisfied");
    }
    Ok((
        cs.num_constraints(),
        cs.num_instance_variables(),
        cs.num_witness_variables(),
    ))
}

fn request_fixture(genesis: bool) -> Result<RequestFixture> {
    let common = CommonFixture::new(genesis)?;
    let request_context = Felt252::from_u64(99);
    let rerandomization = Felt252::from_u64(9);
    let anonymous = rerandomize(&common.commitment, &rerandomization)?;
    let public = RequestPublicInputsV2 {
        protocol_version: common.protocol_version,
        chain_id: common.chain_id,
        contract_address: common.contract_address,
        active_root: common.root,
        state_signing_key_x: common.state_key.x,
        state_signing_key_y: common.state_key.y,
        request_time: 2_000_000_000,
        solvency_bound: 500_000,
        request_nullifier: common.nullifier,
        authorization_tag: core::authorization_tag(&common.nullifier, &request_context),
        anonymous_commitment_x: anonymous.x,
        anonymous_commitment_y: anonymous.y,
    };
    let witness = RequestWitnessData {
        secret: common.secret,
        request_context,
        note_id: common.note_id,
        deposit_amount: common.deposit_amount,
        expiry: common.expiry,
        merkle_siblings: common.siblings,
        current_balance: common.balance,
        current_blinding: common.blinding,
        rerandomization,
        current_anchor: common.anchor,
        prev_anchor: common.prev_anchor,
        state_signature: common.state_signature,
    };
    let circuit = RequestCircuit {
        public: RequestPublic {
            protocol_version: public.protocol_version,
            chain_id: public.chain_id,
            contract_address: field(public.contract_address),
            active_root: field(public.active_root),
            state_signing_key: point(public.state_signing_key_x, public.state_signing_key_y),
            request_time: public.request_time,
            solvency_bound: public.solvency_bound,
            request_nullifier: field(public.request_nullifier),
            authorization_tag: field(public.authorization_tag),
            anonymous_commitment: point(
                public.anonymous_commitment_x,
                public.anonymous_commitment_y,
            ),
        },
        witness: RequestWitness {
            secret: field(witness.secret),
            request_context: field(witness.request_context),
            note_id: witness.note_id,
            deposit_amount: witness.deposit_amount,
            expiry: witness.expiry,
            merkle_siblings: witness.merkle_siblings.map(field),
            current_balance: witness.current_balance,
            current_blinding: scalar(witness.current_blinding),
            rerandomization: scalar(witness.rerandomization),
            current_anchor: field(witness.current_anchor),
            prev_anchor: field(witness.prev_anchor),
            state_signature: signature(witness.state_signature),
        },
    };
    Ok(RequestFixture {
        public,
        witness,
        circuit,
    })
}

fn withdrawal_fixture(genesis: bool, mutual: bool) -> Result<WithdrawalFixture> {
    let common = CommonFixture::new(genesis)?;
    let destination = [0x11u8; 20];
    let destination_felt = Felt252::try_from_bytes_be({
        let mut bytes = [0u8; 32];
        bytes[12..].copy_from_slice(&destination);
        bytes
    })
    .map_err(anyhow::Error::msg)?;
    let clearance_signature = if mutual {
        let message = core::clearance_message(
            common.protocol_version,
            common.chain_id,
            &common.contract_address,
            &common.nullifier,
        );
        Some(common.clearance_signer.sign(&message))
    } else {
        None
    };
    let public = WithdrawalPublicInputsV2 {
        protocol_version: common.protocol_version,
        chain_id: common.chain_id,
        contract_address: common.contract_address,
        registration: core::registration_commitment(&common.secret),
        state_signing_key_x: common.state_key.x,
        state_signing_key_y: common.state_key.y,
        clearance_signing_key_x: common.clearance_key.x,
        clearance_signing_key_y: common.clearance_key.y,
        note_id: common.note_id,
        deposit_amount: common.deposit_amount,
        expiry_ts: common.expiry,
        final_balance: common.balance,
        destination,
        withdrawal_nullifier: common.nullifier,
        has_clearance: mutual,
        next_nullifier: if mutual { Felt252::ZERO } else {
            core::successor_nullifier(&common.secret, common.note_id, &common.nullifier)
        },
        conceded: 0,
        valid_until: common.expiry,
    };
    let witness = WithdrawalWitnessData {
        secret: common.secret,
        current_balance: common.balance,
        final_blinding: common.blinding,
        current_anchor: common.anchor,
        prev_anchor: common.prev_anchor,
        state_signature: common.state_signature,
        clearance_signature,
    };
    let circuit = WithdrawalCircuit {
        public: WithdrawalPublic {
            protocol_version: public.protocol_version,
            chain_id: public.chain_id,
            contract_address: field(public.contract_address),
            registration: field(public.registration),
            state_signing_key: point(public.state_signing_key_x, public.state_signing_key_y),
            clearance_signing_key: point(
                public.clearance_signing_key_x,
                public.clearance_signing_key_y,
            ),
            note_id: public.note_id,
            deposit_amount: public.deposit_amount,
            expiry: public.expiry_ts,
            final_balance: public.final_balance,
            destination: field(destination_felt),
            withdrawal_nullifier: field(public.withdrawal_nullifier),
            has_clearance: public.has_clearance,
            next_nullifier: field(public.next_nullifier),
            conceded: public.conceded,
            valid_until: public.valid_until,
        },
        witness: WithdrawalWitness {
            secret: field(witness.secret),
            current_balance: witness.current_balance,
            final_blinding: scalar(witness.final_blinding),
            current_anchor: field(witness.current_anchor),
            prev_anchor: field(witness.prev_anchor),
            state_signature: signature(witness.state_signature),
            clearance_signature: signature(witness.clearance_signature),
        },
    };
    Ok(WithdrawalFixture {
        public,
        witness,
        circuit,
    })
}

struct CommonFixture {
    protocol_version: u16,
    chain_id: u64,
    contract_address: Felt252,
    secret: Felt252,
    note_id: u32,
    deposit_amount: u128,
    expiry: u64,
    siblings: [Felt252; MERKLE_DEPTH],
    root: Felt252,
    balance: u128,
    blinding: Felt252,
    commitment: zkapi_types::wire::CurvePointWire,
    anchor: Felt252,
    prev_anchor: Felt252,
    nullifier: Felt252,
    state_key: zkapi_types::wire::CurvePointWire,
    clearance_key: zkapi_types::wire::CurvePointWire,
    state_signature: Option<SchnorrSignature>,
    clearance_signer: CompactSigner,
}

impl CommonFixture {
    fn new(genesis: bool) -> Result<Self> {
        let protocol_version = 2;
        let chain_id = 31_337;
        let contract_address = Felt252::from_u64(0x1234);
        let secret = Felt252::from_u64(42);
        let note_id = 0;
        let deposit_amount = 1_000_000;
        let expiry = 4_000_000_000;
        let siblings: [Felt252; MERKLE_DEPTH] = core::zero_hashes()[..MERKLE_DEPTH]
            .try_into()
            .expect("fixed Merkle depth");
        let registration = core::registration_commitment(&secret);
        let leaf = core::note_leaf(note_id, &registration, deposit_amount, expiry);
        let root = core::merkle_root(note_id, &leaf, &siblings);
        let balance = if genesis { deposit_amount } else { 900_000 };
        let blinding = Felt252::from_u64(7);
        let commitment = balance_commitment(balance, &blinding, &leaf);
        let anchor = if genesis {
            Felt252::ONE
        } else {
            core::next_anchor(&core::nullifier(&secret, note_id, &Felt252::ONE))
        };
        let nullifier = core::nullifier(&secret, note_id, &anchor);
        let state_signer = CompactSigner::from_seed(&Felt252::from_u64(1));
        let clearance_signer = CompactSigner::from_seed(&Felt252::from_u64(2));
        let state_key = state_signer.public_key();
        let clearance_key = clearance_signer.public_key();
        let state_signature = if genesis {
            None
        } else {
            let message = core::state_message(
                protocol_version,
                chain_id,
                &contract_address,
                &commitment.x,
                &commitment.y,
                &anchor,
            );
            Some(state_signer.sign(&message))
        };
        Ok(Self {
            protocol_version,
            chain_id,
            contract_address,
            secret,
            note_id,
            deposit_amount,
            expiry,
            siblings,
            root,
            balance,
            blinding,
            commitment,
            anchor,
            prev_anchor: if genesis { Felt252::ZERO } else { Felt252::ONE },
            nullifier,
            state_key,
            clearance_key,
            state_signature,
            clearance_signer,
        })
    }
}

fn field(value: Felt252) -> Fr {
    core::felt_to_field(&value)
}

fn scalar(value: Felt252) -> EdwardsScalarField {
    EdwardsScalarField::from_be_bytes_mod_order(value.as_bytes())
}

fn point(x: Felt252, y: Felt252) -> EdwardsAffine {
    let point = EdwardsAffine::new_unchecked(field(x), field(y));
    debug_assert!(point.is_on_curve());
    point
}

fn signature(value: Option<SchnorrSignature>) -> StateSignature {
    let value = value.unwrap_or(SchnorrSignature::IDENTITY);
    StateSignature {
        r: point(value.r_x, value.r_y),
        s: scalar(value.s),
    }
}

fn decoded_proof_len(encoded: &str) -> Result<usize> {
    Ok(base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .context("decode proof")?
        .len())
}

fn elapsed_ms(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1_000.0
}
