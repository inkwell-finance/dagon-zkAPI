//! Stable native interface for zkAPI v2 Groth16 proofs and curve operations.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_ed_on_bn254::{EdwardsAffine, EdwardsProjective, Fr as EdwardsScalarField};
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_groth16::{Proof, ProvingKey, VerifyingKey};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use base64::Engine;
use rand::rngs::OsRng;
use serde::Serialize;
use zkapi_core::v2 as core;
use zkapi_types::wire::{CurvePointWire, Groth16ProofWire, ProofBackendWire};
use zkapi_types::{
    Felt252, RequestPublicInputsV2, SchnorrSignature, SolanaMerkleTransitionInputs,
    WithdrawalPublicInputsV2, MERKLE_DEPTH,
};

pub use crate::groth16::KeyKind;
use crate::groth16::{
    balance_blinding_generator, prove_with_kind, request_setup, rerandomize_commitment,
    solana_transition_setup, verify_request, verify_solana_transition, verify_state_signature,
    verify_withdrawal, withdrawal_setup, RequestCircuit, RequestPublic, RequestWitness,
    SolanaTransitionCircuit, SolanaTransitionPublic, SolanaTransitionWitness, StateSignature,
    StateSigningKey, WithdrawalCircuit, WithdrawalPublic, WithdrawalWitness,
};

/// Concession exits and note-bound derived anchor chains; earlier keys are incompatible.
pub const CIRCUIT_ID: &str = "zkapi-v2-concession-v1";
/// Header of single-party arkworks keys (default QAP reduction).
const KEY_HEADER: &[u8] = b"zkapi-v2-concession-v1\0";
/// Header of keys converted from a snarkjs ceremony (`CircomReduction`).
const KEY_HEADER_SNARKJS: &[u8] = b"zkapi-v2-concession-v1/snarkjs\0";
pub const SOLANA_TRANSITION_CIRCUIT_ID: &str = "dagon-zkapi-solana-transition-v1";
const SOLANA_TRANSITION_KEY_HEADER: &[u8] = b"dagon-zkapi-solana-transition-v1\0";
const SOLANA_TRANSITION_KEY_HEADER_SNARKJS: &[u8] = b"dagon-zkapi-solana-transition-v1/snarkjs\0";

pub const REQUEST_PROVING_KEY_FILE: &str = "request.pk";
pub const REQUEST_VERIFYING_KEY_FILE: &str = "request.vk";
pub const WITHDRAWAL_PROVING_KEY_FILE: &str = "withdrawal.pk";
pub const WITHDRAWAL_VERIFYING_KEY_FILE: &str = "withdrawal.vk";
pub const SETUP_MANIFEST_FILE: &str = "manifest.json";
pub const SOLANA_TRANSITION_PROVING_KEY_FILE: &str = "transition.pk";
pub const SOLANA_TRANSITION_VERIFYING_KEY_FILE: &str = "transition.vk";
pub const SOLANA_TRANSITION_MANIFEST_FILE: &str = "manifest.json";

#[derive(Serialize)]
struct SetupManifest {
    circuit_id: &'static str,
    protocol_version: u16,
    proof_backend: &'static str,
    request: VerifyingKeyManifest,
    withdrawal: VerifyingKeyManifest,
    poseidon: PoseidonManifest,
}

#[derive(Serialize)]
struct SolanaTransitionSetupManifest {
    circuit_id: &'static str,
    protocol_version: u16,
    proof_backend: &'static str,
    public_inputs: [&'static str; 10],
    transition: VerifyingKeyManifest,
}

#[derive(Serialize)]
struct VerifyingKeyManifest {
    alpha_g1: [String; 2],
    beta_g2: [[String; 2]; 2],
    gamma_g2: [[String; 2]; 2],
    delta_g2: [[String; 2]; 2],
    ic: Vec<[String; 2]>,
}

#[derive(Serialize)]
struct PoseidonManifest {
    field_modulus: String,
    full_rounds: usize,
    partial_rounds: usize,
    alpha: u64,
    rate: usize,
    capacity: usize,
    round_constants: Vec<String>,
    mds: Vec<String>,
    test_hash3: String,
    test_hash5: String,
}

#[derive(Clone, Debug)]
pub struct RequestWitnessData {
    pub secret: Felt252,
    pub request_context: Felt252,
    pub note_id: u32,
    pub deposit_amount: u128,
    pub expiry: u64,
    pub merkle_siblings: [Felt252; MERKLE_DEPTH],
    pub current_balance: u128,
    pub current_blinding: Felt252,
    pub rerandomization: Felt252,
    pub current_anchor: Felt252,
    pub prev_anchor: Felt252,
    pub state_signature: Option<SchnorrSignature>,
}

#[derive(Clone, Debug)]
pub struct WithdrawalWitnessData {
    pub secret: Felt252,
    pub current_balance: u128,
    pub final_blinding: Felt252,
    pub current_anchor: Felt252,
    pub prev_anchor: Felt252,
    pub state_signature: Option<SchnorrSignature>,
    pub clearance_signature: Option<SchnorrSignature>,
}

pub struct RequestProver {
    key: ProvingKey<Bn254>,
    kind: KeyKind,
}

impl RequestProver {
    /// Decode the canonical proving-key bytes supplied by the caller.
    /// Browser clients use this because WebAssembly has no native filesystem.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (key, kind) = decode_compressed(bytes).context("decode request proving key")?;
        Ok(Self { key, kind })
    }

    /// Which ceremony/format the loaded proving key came from.
    pub fn key_kind(&self) -> KeyKind {
        self.kind
    }

    pub fn load(directory: impl AsRef<Path>) -> Result<Self> {
        let path = directory.as_ref().join(REQUEST_PROVING_KEY_FILE);
        let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        Self::from_bytes(&bytes)
    }

    pub fn prove(
        &self,
        public: &RequestPublicInputsV2,
        witness: RequestWitnessData,
    ) -> Result<Groth16ProofWire> {
        let circuit = RequestCircuit {
            public: request_public_from_wire(public)?,
            witness: RequestWitness {
                secret: field(&witness.secret),
                request_context: field(&witness.request_context),
                note_id: witness.note_id,
                deposit_amount: witness.deposit_amount,
                expiry: witness.expiry,
                merkle_siblings: witness.merkle_siblings.map(|value| field(&value)),
                current_balance: witness.current_balance,
                current_blinding: scalar(&witness.current_blinding),
                rerandomization: scalar(&witness.rerandomization),
                current_anchor: field(&witness.current_anchor),
                prev_anchor: field(&witness.prev_anchor),
                state_signature: signature_from_wire(
                    witness
                        .state_signature
                        .unwrap_or(SchnorrSignature::IDENTITY),
                )?,
            },
        };
        validate_witness(circuit.clone())?;
        let proof = prove_with_kind(self.kind, &self.key, circuit, &mut OsRng)
            .map_err(|error| anyhow!("request proving failed: {error}"))?;
        proof_to_wire(&proof)
    }
}

pub struct RequestVerifier {
    key: VerifyingKey<Bn254>,
}

impl RequestVerifier {
    pub fn load(directory: impl AsRef<Path>) -> Result<Self> {
        let (key, _) = read_compressed(directory.as_ref().join(REQUEST_VERIFYING_KEY_FILE))?;
        Ok(Self { key })
    }

    pub fn verify(&self, public: &RequestPublicInputsV2, proof: &Groth16ProofWire) -> Result<bool> {
        ensure_backend(proof)?;
        let proof = proof_from_wire(proof)?;
        verify_request(&self.key, &request_public_from_wire(public)?, &proof)
            .map_err(|error| anyhow!("request verification failed: {error}"))
    }
}

pub struct WithdrawalProver {
    key: ProvingKey<Bn254>,
    kind: KeyKind,
}

impl WithdrawalProver {
    /// Decode the canonical proving-key bytes supplied by the caller.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (key, kind) = decode_compressed(bytes).context("decode withdrawal proving key")?;
        Ok(Self { key, kind })
    }

    /// Which ceremony/format the loaded proving key came from.
    pub fn key_kind(&self) -> KeyKind {
        self.kind
    }

    pub fn load(directory: impl AsRef<Path>) -> Result<Self> {
        let path = directory.as_ref().join(WITHDRAWAL_PROVING_KEY_FILE);
        let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        Self::from_bytes(&bytes)
    }

    pub fn prove(
        &self,
        public: &WithdrawalPublicInputsV2,
        witness: WithdrawalWitnessData,
    ) -> Result<Groth16ProofWire> {
        let circuit = WithdrawalCircuit {
            public: withdrawal_public_from_wire(public)?,
            witness: WithdrawalWitness {
                secret: field(&witness.secret),
                current_balance: witness.current_balance,
                final_blinding: scalar(&witness.final_blinding),
                current_anchor: field(&witness.current_anchor),
                prev_anchor: field(&witness.prev_anchor),
                state_signature: signature_from_wire(
                    witness
                        .state_signature
                        .unwrap_or(SchnorrSignature::IDENTITY),
                )?,
                clearance_signature: signature_from_wire(
                    witness
                        .clearance_signature
                        .unwrap_or(SchnorrSignature::IDENTITY),
                )?,
            },
        };
        validate_witness(circuit.clone())?;
        let proof = prove_with_kind(self.kind, &self.key, circuit, &mut OsRng)
            .map_err(|error| anyhow!("withdrawal proving failed: {error}"))?;
        proof_to_wire(&proof)
    }
}

pub struct WithdrawalVerifier {
    key: VerifyingKey<Bn254>,
}

impl WithdrawalVerifier {
    pub fn load(directory: impl AsRef<Path>) -> Result<Self> {
        let (key, _) = read_compressed(directory.as_ref().join(WITHDRAWAL_VERIFYING_KEY_FILE))?;
        Ok(Self { key })
    }

    pub fn verify(
        &self,
        public: &WithdrawalPublicInputsV2,
        proof: &Groth16ProofWire,
    ) -> Result<bool> {
        ensure_backend(proof)?;
        let proof = proof_from_wire(proof)?;
        verify_withdrawal(&self.key, &withdrawal_public_from_wire(public)?, &proof)
            .map_err(|error| anyhow!("withdrawal verification failed: {error}"))
    }
}

pub struct SolanaTransitionProver {
    key: ProvingKey<Bn254>,
    kind: KeyKind,
}

impl SolanaTransitionProver {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (key, kind) = decode_compressed_with_headers(bytes, &SOLANA_TRANSITION_KEY_HEADERS)
            .context("decode Solana transition proving key")?;
        Ok(Self { key, kind })
    }

    /// Which ceremony/format the loaded proving key came from.
    pub fn key_kind(&self) -> KeyKind {
        self.kind
    }

    pub fn load(directory: impl AsRef<Path>) -> Result<Self> {
        let path = directory.as_ref().join(SOLANA_TRANSITION_PROVING_KEY_FILE);
        let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        Self::from_bytes(&bytes)
    }

    pub fn prove(
        &self,
        public: &SolanaMerkleTransitionInputs,
        siblings: [Felt252; MERKLE_DEPTH],
    ) -> Result<Groth16ProofWire> {
        let circuit = SolanaTransitionCircuit {
            public: solana_transition_public_from_wire(public),
            witness: SolanaTransitionWitness {
                siblings: siblings.map(|value| field(&value)),
            },
        };
        validate_witness(circuit.clone())?;
        let proof = prove_with_kind(self.kind, &self.key, circuit, &mut OsRng)
            .map_err(|error| anyhow!("Solana transition proving failed: {error}"))?;
        proof_to_wire(&proof)
    }
}

pub struct SolanaTransitionVerifier {
    key: VerifyingKey<Bn254>,
}

impl SolanaTransitionVerifier {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (key, _) = decode_compressed_with_headers(bytes, &SOLANA_TRANSITION_KEY_HEADERS)
            .context("decode Solana transition verifying key")?;
        Ok(Self { key })
    }

    pub fn load(directory: impl AsRef<Path>) -> Result<Self> {
        let path = directory
            .as_ref()
            .join(SOLANA_TRANSITION_VERIFYING_KEY_FILE);
        let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        Self::from_bytes(&bytes)
    }

    pub fn verify(
        &self,
        public: &SolanaMerkleTransitionInputs,
        proof: &Groth16ProofWire,
    ) -> Result<bool> {
        ensure_backend(proof)?;
        let proof = proof_from_wire(proof)?;
        verify_solana_transition(
            &self.key,
            &solana_transition_public_from_wire(public),
            &proof,
        )
        .map_err(|error| anyhow!("Solana transition verification failed: {error}"))
    }
}

#[derive(Clone)]
pub struct CompactSigner {
    key: StateSigningKey,
}

impl CompactSigner {
    pub fn from_seed(seed: &Felt252) -> Self {
        Self {
            key: StateSigningKey::from_secret(scalar(seed)),
        }
    }

    pub fn public_key(&self) -> CurvePointWire {
        point_to_wire(self.key.public)
    }

    pub fn sign(&self, message: &Felt252) -> SchnorrSignature {
        signature_to_wire(self.key.sign(field(message), &mut OsRng))
    }

    pub fn verify(&self, message: &Felt252, signature: &SchnorrSignature) -> Result<bool> {
        Ok(verify_state_signature(
            self.key.public,
            field(message),
            signature_from_wire(*signature)?,
        ))
    }
}

/// Witness-independent request circuit used for every setup and for the
/// snarkjs ceremony's R1CS export; only its shape matters.
pub(crate) fn request_template() -> Result<RequestCircuit> {
    let (state_key, empty_signature) = template_signing_material()?;
    Ok(RequestCircuit {
        public: RequestPublic {
            protocol_version: 2,
            chain_id: 1,
            contract_address: Fr::from(1u64),
            active_root: Fr::from(1u64),
            state_signing_key: state_key,
            request_time: 1,
            solvency_bound: 0,
            request_nullifier: Fr::from(1u64),
            authorization_tag: Fr::from(1u64),
            anonymous_commitment: EdwardsProjective::generator().into_affine(),
        },
        witness: RequestWitness {
            secret: Fr::from(1u64),
            request_context: Fr::from(1u64),
            note_id: 0,
            deposit_amount: 0,
            expiry: 1,
            merkle_siblings: [Fr::from(0u64); MERKLE_DEPTH],
            current_balance: 0,
            current_blinding: EdwardsScalarField::from(0u64),
            rerandomization: EdwardsScalarField::from(0u64),
            current_anchor: Fr::from(1u64),
            prev_anchor: Fr::from(0u64),
            state_signature: empty_signature,
        },
    })
}

/// Witness-independent withdrawal circuit; see [`request_template`].
pub(crate) fn withdrawal_template() -> Result<WithdrawalCircuit> {
    let (state_key, empty_signature) = template_signing_material()?;
    Ok(WithdrawalCircuit {
        public: WithdrawalPublic {
            protocol_version: 2,
            chain_id: 1,
            contract_address: Fr::from(1u64),
            registration: Fr::from(1u64),
            state_signing_key: state_key,
            clearance_signing_key: state_key,
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
            state_signature: empty_signature,
            clearance_signature: empty_signature,
        },
    })
}

/// Satisfied Solana Merkle-transition circuit; see [`request_template`].
pub(crate) fn solana_transition_template() -> Result<SolanaTransitionCircuit> {
    let tree = zkapi_core::MerkleTree::new();
    let siblings = tree.get_siblings(0);
    let commitment = Felt252::from_u64(7);
    let amount = 1_000_000u64;
    let expiry = 4_000_000_000u64;
    let leaf = core::note_leaf(0, &commitment, u128::from(amount), expiry);
    let public = SolanaMerkleTransitionInputs {
        protocol_version: 2,
        chain_id: 1,
        protocol_binding: Felt252::ONE,
        old_root: tree.root(),
        new_root: core::merkle_root(0, &leaf, &siblings),
        note_id: 0,
        commitment,
        amount,
        expiry,
        inserting: true,
    };
    let circuit = SolanaTransitionCircuit {
        public: solana_transition_public_from_wire(&public),
        witness: SolanaTransitionWitness {
            siblings: siblings.map(|value| field(&value)),
        },
    };
    validate_witness(circuit.clone())?;
    Ok(circuit)
}

fn template_signing_material() -> Result<(EdwardsAffine, StateSignature)> {
    let template_signer = CompactSigner::from_seed(&Felt252::ONE);
    let state_key = point_from_wire(&template_signer.public_key())?;
    let empty_signature = StateSignature {
        r: EdwardsAffine::zero(),
        s: EdwardsScalarField::from(0u64),
    };
    Ok((state_key, empty_signature))
}

pub fn setup(directory: impl AsRef<Path>) -> Result<()> {
    let (request_pk, _) = request_setup(request_template()?, &mut OsRng)
        .map_err(|error| anyhow!("request setup failed: {error}"))?;
    let (withdrawal_pk, _) = withdrawal_setup(withdrawal_template()?, &mut OsRng)
        .map_err(|error| anyhow!("withdrawal setup failed: {error}"))?;
    write_setup_artifacts(directory, KeyKind::Legacy, &request_pk, &withdrawal_pk)
}

/// Write the request/withdrawal key files and `manifest.json` for
/// already-built proving keys. [`setup`] uses this for fresh single-party
/// keys; the snarkjs ceremony import uses it with [`KeyKind::Snarkjs`], so
/// both paths emit identical key and manifest formats.
pub fn write_setup_artifacts(
    directory: impl AsRef<Path>,
    kind: KeyKind,
    request_pk: &ProvingKey<Bn254>,
    withdrawal_pk: &ProvingKey<Bn254>,
) -> Result<()> {
    let directory = directory.as_ref();
    fs::create_dir_all(directory)
        .with_context(|| format!("create setup directory {}", directory.display()))?;
    let request_vk = &request_pk.vk;
    let withdrawal_vk = &withdrawal_pk.vk;
    write_compressed(directory.join(REQUEST_PROVING_KEY_FILE), request_pk, kind)?;
    write_compressed(directory.join(REQUEST_VERIFYING_KEY_FILE), request_vk, kind)?;
    write_compressed(
        directory.join(WITHDRAWAL_PROVING_KEY_FILE),
        withdrawal_pk,
        kind,
    )?;
    write_compressed(
        directory.join(WITHDRAWAL_VERIFYING_KEY_FILE),
        withdrawal_vk,
        kind,
    )?;
    let manifest = SetupManifest {
        circuit_id: CIRCUIT_ID,
        protocol_version: 2,
        proof_backend: "groth16_bn254",
        request: verifying_key_manifest(request_vk),
        withdrawal: verifying_key_manifest(withdrawal_vk),
        poseidon: poseidon_manifest(),
    };
    fs::write(
        directory.join(SETUP_MANIFEST_FILE),
        serde_json::to_vec_pretty(&manifest).context("encode setup manifest")?,
    )
    .context("write setup manifest")?;
    Ok(())
}

/// Generate the Solana-only Merkle-transition proving and verifying keys.
///
/// This is a separate circuit/setup so the stable request and withdrawal
/// statements, keys, and browser assets remain byte-for-byte unchanged.
pub fn setup_solana_transition(directory: impl AsRef<Path>) -> Result<()> {
    let (proving_key, _) = solana_transition_setup(solana_transition_template()?, &mut OsRng)
        .map_err(|error| anyhow!("Solana transition setup failed: {error}"))?;
    write_solana_transition_artifacts(directory, KeyKind::Legacy, &proving_key)
}

/// Write the Solana transition key files and `manifest.json` for an
/// already-built proving key; see [`write_setup_artifacts`].
pub fn write_solana_transition_artifacts(
    directory: impl AsRef<Path>,
    kind: KeyKind,
    proving_key: &ProvingKey<Bn254>,
) -> Result<()> {
    let directory = directory.as_ref();
    fs::create_dir_all(directory)
        .with_context(|| format!("create setup directory {}", directory.display()))?;
    write_compressed_with_headers(
        directory.join(SOLANA_TRANSITION_PROVING_KEY_FILE),
        proving_key,
        &SOLANA_TRANSITION_KEY_HEADERS,
        kind,
    )?;
    write_compressed_with_headers(
        directory.join(SOLANA_TRANSITION_VERIFYING_KEY_FILE),
        &proving_key.vk,
        &SOLANA_TRANSITION_KEY_HEADERS,
        kind,
    )?;
    let manifest = SolanaTransitionSetupManifest {
        circuit_id: SOLANA_TRANSITION_CIRCUIT_ID,
        protocol_version: 2,
        proof_backend: "groth16_bn254",
        public_inputs: [
            "protocol_version",
            "chain_id",
            "protocol_binding",
            "old_root",
            "new_root",
            "note_id",
            "commitment",
            "amount",
            "expiry",
            "inserting",
        ],
        transition: verifying_key_manifest(&proving_key.vk),
    };
    fs::write(
        directory.join(SOLANA_TRANSITION_MANIFEST_FILE),
        serde_json::to_vec_pretty(&manifest).context("encode Solana transition manifest")?,
    )
    .context("write Solana transition manifest")?;
    Ok(())
}

pub fn random_field() -> Felt252 {
    felt(&Fr::rand(&mut OsRng))
}

pub fn random_scalar() -> Felt252 {
    scalar_to_felt(&EdwardsScalarField::rand(&mut OsRng))
}

pub fn balance_commitment(
    balance: u128,
    blinding: &Felt252,
    note_leaf: &Felt252,
) -> CurvePointWire {
    point_to_wire(
        crate::groth16::balance_commitment(balance, scalar(blinding), field(note_leaf))
            .into_affine(),
    )
}

pub fn rerandomize(
    commitment: &CurvePointWire,
    rerandomization: &Felt252,
) -> Result<CurvePointWire> {
    Ok(point_to_wire(
        rerandomize_commitment(
            point_from_wire(commitment)?.into_group(),
            scalar(rerandomization),
        )
        .into_affine(),
    ))
}

pub fn add_blindings(left: &Felt252, right: &Felt252) -> Felt252 {
    scalar_to_felt(&(scalar(left) + scalar(right)))
}

pub fn server_update(
    anonymous: &CurvePointWire,
    charge: u128,
    blind_delta: &Felt252,
) -> Result<CurvePointWire> {
    let point = point_from_wire(anonymous)?.into_group()
        - EdwardsProjective::generator().mul_bigint(EdwardsScalarField::from(charge).into_bigint())
        + balance_blinding_generator().mul_bigint(scalar(blind_delta).into_bigint());
    Ok(point_to_wire(point.into_affine()))
}

pub fn verify_signature(
    public_key: &CurvePointWire,
    message: &Felt252,
    signature: &SchnorrSignature,
) -> Result<bool> {
    Ok(verify_state_signature(
        point_from_wire(public_key)?,
        field(message),
        signature_from_wire(*signature)?,
    ))
}

fn request_public_from_wire(public: &RequestPublicInputsV2) -> Result<RequestPublic> {
    Ok(RequestPublic {
        protocol_version: public.protocol_version,
        chain_id: public.chain_id,
        contract_address: field(&public.contract_address),
        active_root: field(&public.active_root),
        state_signing_key: point_from_wire(&CurvePointWire {
            x: public.state_signing_key_x,
            y: public.state_signing_key_y,
        })?,
        request_time: public.request_time,
        solvency_bound: public.solvency_bound,
        request_nullifier: field(&public.request_nullifier),
        authorization_tag: field(&public.authorization_tag),
        anonymous_commitment: point_from_wire(&CurvePointWire {
            x: public.anonymous_commitment_x,
            y: public.anonymous_commitment_y,
        })?,
    })
}

fn withdrawal_public_from_wire(public: &WithdrawalPublicInputsV2) -> Result<WithdrawalPublic> {
    Ok(WithdrawalPublic {
        protocol_version: public.protocol_version,
        chain_id: public.chain_id,
        contract_address: field(&public.contract_address),
        registration: field(&public.registration),
        state_signing_key: point_from_wire(&CurvePointWire {
            x: public.state_signing_key_x,
            y: public.state_signing_key_y,
        })?,
        clearance_signing_key: point_from_wire(&CurvePointWire {
            x: public.clearance_signing_key_x,
            y: public.clearance_signing_key_y,
        })?,
        note_id: public.note_id,
        deposit_amount: public.deposit_amount,
        expiry: public.expiry_ts,
        final_balance: public.final_balance,
        destination: field(&public.destination_field()),
        withdrawal_nullifier: field(&public.withdrawal_nullifier),
        has_clearance: public.has_clearance,
        next_nullifier: field(&public.next_nullifier),
        conceded: public.conceded,
        valid_until: public.valid_until,
    })
}

fn solana_transition_public_from_wire(
    public: &SolanaMerkleTransitionInputs,
) -> SolanaTransitionPublic {
    SolanaTransitionPublic {
        protocol_version: public.protocol_version,
        chain_id: public.chain_id,
        protocol_binding: field(&public.protocol_binding),
        old_root: field(&public.old_root),
        new_root: field(&public.new_root),
        note_id: public.note_id,
        commitment: field(&public.commitment),
        amount: public.amount,
        expiry: public.expiry,
        inserting: public.inserting,
    }
}

// Return a recoverable error for corrupt/transplanted private state instead of
// relying on arkworks' debug assertion or spending time producing an invalid proof.
fn validate_witness(circuit: impl ConstraintSynthesizer<Fr>) -> Result<()> {
    let cs = ConstraintSystem::new_ref();
    circuit
        .generate_constraints(cs.clone())
        .map_err(|error| anyhow!("invalid witness: {error}"))?;
    anyhow::ensure!(
        cs.is_satisfied()
            .map_err(|error| anyhow!("invalid witness: {error}"))?,
        "private state does not satisfy the note-bound circuit"
    );
    Ok(())
}

fn ensure_backend(proof: &Groth16ProofWire) -> Result<()> {
    if proof.backend != ProofBackendWire::Groth16Bn254 {
        return Err(anyhow!("expected groth16_bn254 proof backend"));
    }
    Ok(())
}

fn proof_to_wire(proof: &Proof<Bn254>) -> Result<Groth16ProofWire> {
    let mut bytes = Vec::with_capacity(256);
    for coordinate in [
        proof.a.x,
        proof.a.y,
        proof.b.x.c0,
        proof.b.x.c1,
        proof.b.y.c0,
        proof.b.y.c1,
        proof.c.x,
        proof.c.y,
    ] {
        bytes.extend_from_slice(&prime_field_bytes(&coordinate));
    }
    Ok(Groth16ProofWire {
        backend: ProofBackendWire::Groth16Bn254,
        proof: base64::engine::general_purpose::STANDARD.encode(bytes),
    })
}

fn proof_from_wire(proof: &Groth16ProofWire) -> Result<Proof<Bn254>> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(&proof.proof)
        .context("decode Groth16 proof base64")?;
    if bytes.len() != 256 {
        return Err(anyhow!(
            "Groth16 proof must contain eight 32-byte coordinates"
        ));
    }
    let coordinates = bytes
        .as_chunks::<32>()
        .0
        .iter()
        .map(|coordinate| canonical_fq(coordinate))
        .collect::<Result<Vec<_>>>()?;
    let a = G1Affine::new_unchecked(coordinates[0], coordinates[1]);
    let b = G2Affine::new_unchecked(
        Fq2::new(coordinates[2], coordinates[3]),
        Fq2::new(coordinates[4], coordinates[5]),
    );
    let c = G1Affine::new_unchecked(coordinates[6], coordinates[7]);
    if !a.is_on_curve()
        || !a.is_in_correct_subgroup_assuming_on_curve()
        || !b.is_on_curve()
        || !b.is_in_correct_subgroup_assuming_on_curve()
        || !c.is_on_curve()
        || !c.is_in_correct_subgroup_assuming_on_curve()
    {
        return Err(anyhow!("Groth16 proof contains an invalid curve point"));
    }
    Ok(Proof { a, b, c })
}

fn canonical_fq(bytes: &[u8]) -> Result<Fq> {
    let value = Fq::from_be_bytes_mod_order(bytes);
    if prime_field_bytes(&value).as_slice() != bytes {
        return Err(anyhow!("non-canonical BN254 base-field coordinate"));
    }
    Ok(value)
}

fn prime_field_bytes<F: PrimeField>(value: &F) -> [u8; 32] {
    let raw = value.into_bigint().to_bytes_be();
    let mut bytes = [0u8; 32];
    bytes[32 - raw.len()..].copy_from_slice(&raw);
    bytes
}

fn signature_from_wire(signature: SchnorrSignature) -> Result<StateSignature> {
    Ok(StateSignature {
        r: point_from_wire(&CurvePointWire {
            x: signature.r_x,
            y: signature.r_y,
        })?,
        s: scalar(&signature.s),
    })
}

fn signature_to_wire(signature: StateSignature) -> SchnorrSignature {
    let point = point_to_wire(signature.r);
    SchnorrSignature {
        r_x: point.x,
        r_y: point.y,
        s: scalar_to_felt(&signature.s),
    }
}

fn point_from_wire(point: &CurvePointWire) -> Result<EdwardsAffine> {
    let point = EdwardsAffine::new_unchecked(field(&point.x), field(&point.y));
    if !point.is_on_curve() || !point.is_in_correct_subgroup_assuming_on_curve() {
        return Err(anyhow!("invalid Baby-JubJub point"));
    }
    Ok(point)
}

fn point_to_wire(point: EdwardsAffine) -> CurvePointWire {
    CurvePointWire {
        x: felt(&point.x),
        y: felt(&point.y),
    }
}

fn field(value: &Felt252) -> Fr {
    core::felt_to_field(value)
}

fn felt(value: &Fr) -> Felt252 {
    core::field_to_felt(value)
}

fn scalar(value: &Felt252) -> EdwardsScalarField {
    EdwardsScalarField::from_be_bytes_mod_order(value.as_bytes())
}

fn scalar_to_felt(value: &EdwardsScalarField) -> Felt252 {
    let raw = value.into_bigint().to_bytes_be();
    let mut bytes = [0u8; 32];
    bytes[32 - raw.len()..].copy_from_slice(&raw);
    Felt252(bytes)
}

/// File headers of one circuit's key files, one per [`KeyKind`].
struct KeyHeaders {
    legacy: &'static [u8],
    snarkjs: &'static [u8],
}

impl KeyHeaders {
    fn for_kind(&self, kind: KeyKind) -> &'static [u8] {
        match kind {
            KeyKind::Legacy => self.legacy,
            KeyKind::Snarkjs => self.snarkjs,
        }
    }
}

const REQUEST_KEY_HEADERS: KeyHeaders = KeyHeaders {
    legacy: KEY_HEADER,
    snarkjs: KEY_HEADER_SNARKJS,
};
const SOLANA_TRANSITION_KEY_HEADERS: KeyHeaders = KeyHeaders {
    legacy: SOLANA_TRANSITION_KEY_HEADER,
    snarkjs: SOLANA_TRANSITION_KEY_HEADER_SNARKJS,
};

fn read_compressed<T: CanonicalDeserialize>(path: PathBuf) -> Result<(T, KeyKind)> {
    let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    decode_compressed(&bytes).with_context(|| format!("decode {}", path.display()))
}

fn decode_compressed<T: CanonicalDeserialize>(bytes: &[u8]) -> Result<(T, KeyKind)> {
    decode_compressed_with_headers(bytes, &REQUEST_KEY_HEADERS)
}

fn decode_compressed_with_headers<T: CanonicalDeserialize>(
    bytes: &[u8],
    headers: &KeyHeaders,
) -> Result<(T, KeyKind)> {
    let (kind, mut bytes) = [KeyKind::Legacy, KeyKind::Snarkjs]
        .into_iter()
        .find_map(|kind| {
            bytes
                .strip_prefix(headers.for_kind(kind))
                .map(|rest| (kind, rest))
        })
        .ok_or_else(|| anyhow!("incompatible setup-key header"))?;
    let value = T::deserialize_compressed(&mut bytes)
        .map_err(|error| anyhow!("deserialize compressed value: {error}"))?;
    anyhow::ensure!(bytes.is_empty(), "trailing setup key bytes");
    Ok((value, kind))
}

fn write_compressed<T: CanonicalSerialize>(path: PathBuf, value: &T, kind: KeyKind) -> Result<()> {
    write_compressed_with_headers(path, value, &REQUEST_KEY_HEADERS, kind)
}

fn write_compressed_with_headers<T: CanonicalSerialize>(
    path: PathBuf,
    value: &T,
    headers: &KeyHeaders,
    kind: KeyKind,
) -> Result<()> {
    let mut bytes = headers.for_kind(kind).to_vec();
    value
        .serialize_compressed(&mut bytes)
        .with_context(|| format!("encode {}", path.display()))?;
    fs::write(&path, bytes).with_context(|| format!("write {}", path.display()))
}

fn verifying_key_manifest(key: &VerifyingKey<Bn254>) -> VerifyingKeyManifest {
    VerifyingKeyManifest {
        alpha_g1: g1_manifest(&key.alpha_g1),
        beta_g2: g2_manifest(&key.beta_g2),
        gamma_g2: g2_manifest(&key.gamma_g2),
        delta_g2: g2_manifest(&key.delta_g2),
        ic: key.gamma_abc_g1.iter().map(g1_manifest).collect(),
    }
}

fn poseidon_manifest() -> PoseidonManifest {
    let config = crate::groth16::poseidon_config();
    PoseidonManifest {
        field_modulus: zkapi_types::FIELD_MODULUS_HEX.to_string(),
        full_rounds: config.full_rounds,
        partial_rounds: config.partial_rounds,
        alpha: config.alpha,
        rate: config.rate,
        capacity: config.capacity,
        round_constants: config.ark.iter().flatten().map(field_hex).collect(),
        mds: config.mds.iter().flatten().map(field_hex).collect(),
        test_hash3: field_hex(&crate::groth16::poseidon_hash(&[
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
        ])),
        test_hash5: field_hex(&crate::groth16::poseidon_hash(&[
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
            Fr::from(5u64),
        ])),
    }
}

fn g1_manifest(point: &G1Affine) -> [String; 2] {
    [field_hex(&point.x), field_hex(&point.y)]
}

fn g2_manifest(point: &G2Affine) -> [[String; 2]; 2] {
    [
        [field_hex(&point.x.c0), field_hex(&point.x.c1)],
        [field_hex(&point.y.c0), field_hex(&point.y.c1)],
    ]
}

fn field_hex<F: PrimeField>(value: &F) -> String {
    format!("0x{}", hex::encode(prime_field_bytes(value)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_headers_select_the_reduction_kind() {
        let setup = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../setup/v2");
        let legacy = fs::read(setup.join(REQUEST_VERIFYING_KEY_FILE)).unwrap();
        let (key, kind) = decode_compressed::<VerifyingKey<Bn254>>(&legacy).unwrap();
        assert_eq!(kind, KeyKind::Legacy);

        let body = &legacy[KEY_HEADER.len()..];
        let snarkjs = [KEY_HEADER_SNARKJS, body].concat();
        let (again, kind) = decode_compressed::<VerifyingKey<Bn254>>(&snarkjs).unwrap();
        assert_eq!(kind, KeyKind::Snarkjs);
        assert_eq!(again, key);

        // Headers are per circuit and never interchangeable.
        assert!(decode_compressed_with_headers::<VerifyingKey<Bn254>>(
            &snarkjs,
            &SOLANA_TRANSITION_KEY_HEADERS
        )
        .is_err());
        let transition = [SOLANA_TRANSITION_KEY_HEADER_SNARKJS, body].concat();
        assert!(decode_compressed::<VerifyingKey<Bn254>>(&transition).is_err());
        let (_, kind) = decode_compressed_with_headers::<VerifyingKey<Bn254>>(
            &transition,
            &SOLANA_TRANSITION_KEY_HEADERS,
        )
        .unwrap();
        assert_eq!(kind, KeyKind::Snarkjs);
        // Trailing garbage after a valid key is still rejected for both kinds.
        assert!(
            decode_compressed::<VerifyingKey<Bn254>>(&[snarkjs.as_slice(), &[0]].concat()).is_err()
        );
    }

    /// Dry-run acceptance test for keys imported from a snarkjs ceremony (see
    /// `ceremony/README-rust.md`):
    ///
    /// `ZKAPI_CEREMONY_IMPORT_DIR=<ceremony_import OUT_DIR> cargo test --release \
    ///   -p zkapi-proof --lib -- --ignored imported_ceremony_keys`
    #[test]
    #[ignore = "needs ZKAPI_CEREMONY_IMPORT_DIR with ceremony_import output; slow"]
    fn imported_ceremony_keys_prove_and_verify_all_circuits() {
        let root = PathBuf::from(std::env::var("ZKAPI_CEREMONY_IMPORT_DIR").unwrap());
        let v2 = root.join("v2");
        let transition_dir = root.join("solana-transition-v1");

        // Request (genesis note) and withdrawal.
        let requests = RequestProver::load(&v2).unwrap();
        let withdrawals = WithdrawalProver::load(&v2).unwrap();
        let transition = SolanaTransitionProver::load(&transition_dir).unwrap();
        for kind in [
            requests.key_kind(),
            withdrawals.key_kind(),
            transition.key_kind(),
        ] {
            assert_eq!(kind, KeyKind::Snarkjs);
        }
        let request_verifier = RequestVerifier::load(&v2).unwrap();
        let withdrawal_verifier = WithdrawalVerifier::load(&v2).unwrap();
        let transition_verifier = SolanaTransitionVerifier::load(&transition_dir).unwrap();

        let signer = CompactSigner::from_seed(&Felt252::from_u64(1));
        let key = signer.public_key();
        let vault = Felt252::from_u64(0xfeed);
        let secret = Felt252::from_u64(43);
        let (note_id, deposit, expiry) = (1u32, 1_000_000u128, 2_100_000_000u64);
        let registration = core::registration_commitment(&secret);
        let leaf = core::note_leaf(note_id, &registration, deposit, expiry);
        let siblings: [Felt252; MERKLE_DEPTH] =
            core::zero_hashes()[..MERKLE_DEPTH].try_into().unwrap();
        let (blinding, anchor, rerandomization) =
            (Felt252::from_u64(8), Felt252::ONE, Felt252::from_u64(9));
        let nullifier = core::nullifier(&secret, note_id, &anchor);

        let anonymous = rerandomize(
            &balance_commitment(deposit, &blinding, &leaf),
            &rerandomization,
        )
        .unwrap();
        let request_public = RequestPublicInputsV2 {
            protocol_version: 2,
            chain_id: 31_337,
            contract_address: vault,
            active_root: core::merkle_root(note_id, &leaf, &siblings),
            state_signing_key_x: key.x,
            state_signing_key_y: key.y,
            request_time: 2_000_000_000,
            solvency_bound: 100_000,
            request_nullifier: nullifier,
            authorization_tag: core::authorization_tag(&nullifier, &Felt252::from_u64(99)),
            anonymous_commitment_x: anonymous.x,
            anonymous_commitment_y: anonymous.y,
        };
        let request_proof = requests
            .prove(
                &request_public,
                RequestWitnessData {
                    secret,
                    request_context: Felt252::from_u64(99),
                    note_id,
                    deposit_amount: deposit,
                    expiry,
                    merkle_siblings: siblings,
                    current_balance: deposit,
                    current_blinding: blinding,
                    rerandomization,
                    current_anchor: anchor,
                    prev_anchor: Felt252::ZERO,
                    state_signature: None,
                },
            )
            .unwrap();
        assert!(request_verifier
            .verify(&request_public, &request_proof)
            .unwrap());
        let mut tampered = request_public.clone();
        tampered.solvency_bound += 1;
        assert!(!request_verifier.verify(&tampered, &request_proof).unwrap());

        let clearance_signer = CompactSigner::from_seed(&Felt252::from_u64(2));
        let clearance_key = clearance_signer.public_key();
        let withdrawal_public = WithdrawalPublicInputsV2 {
            protocol_version: 2,
            chain_id: 31_337,
            contract_address: vault,
            registration,
            state_signing_key_x: key.x,
            state_signing_key_y: key.y,
            clearance_signing_key_x: clearance_key.x,
            clearance_signing_key_y: clearance_key.y,
            note_id,
            deposit_amount: deposit,
            expiry_ts: expiry,
            final_balance: deposit,
            destination: [0x11; 20],
            withdrawal_nullifier: nullifier,
            has_clearance: true,
            next_nullifier: Felt252::ZERO,
            conceded: 0,
            valid_until: expiry,
        };
        let withdrawal_proof = withdrawals
            .prove(
                &withdrawal_public,
                WithdrawalWitnessData {
                    secret,
                    current_balance: deposit,
                    final_blinding: blinding,
                    current_anchor: anchor,
                    prev_anchor: Felt252::ZERO,
                    state_signature: None,
                    clearance_signature: Some(
                        clearance_signer
                            .sign(&core::clearance_message(2, 31_337, &vault, &nullifier)),
                    ),
                },
            )
            .unwrap();
        assert!(withdrawal_verifier
            .verify(&withdrawal_public, &withdrawal_proof)
            .unwrap());
        let mut tampered = withdrawal_public.clone();
        tampered.final_balance -= 1;
        assert!(!withdrawal_verifier
            .verify(&tampered, &withdrawal_proof)
            .unwrap());

        let tree = zkapi_core::MerkleTree::new();
        let transition_siblings = tree.get_siblings(7);
        let commitment = Felt252::from_u64(0xcafe);
        let transition_leaf = core::note_leaf(7, &commitment, 5_000_000, 4_000_000_000);
        let transition_public = SolanaMerkleTransitionInputs {
            protocol_version: 2,
            chain_id: 11_155_111,
            protocol_binding: Felt252::from_u64(0xdead),
            old_root: tree.root(),
            new_root: core::merkle_root(7, &transition_leaf, &transition_siblings),
            note_id: 7,
            commitment,
            amount: 5_000_000,
            expiry: 4_000_000_000,
            inserting: true,
        };
        let transition_proof = transition
            .prove(&transition_public, transition_siblings)
            .unwrap();
        assert!(transition_verifier
            .verify(&transition_public, &transition_proof)
            .unwrap());
        let mut tampered = transition_public;
        tampered.amount += 1;
        assert!(!transition_verifier
            .verify(&tampered, &transition_proof)
            .unwrap());
    }

    #[test]
    fn legacy_setup_keys_are_rejected_before_decoding() {
        assert!(RequestProver::from_bytes(&[0; 32])
            .err()
            .unwrap()
            .to_string()
            .contains("decode request"));
        assert!(decode_compressed::<VerifyingKey<Bn254>>(&[0; 32])
            .unwrap_err()
            .to_string()
            .contains("incompatible setup"));
    }

    #[test]
    fn proof_wire_preserves_coordinate_order() {
        let proof = Proof::<Bn254> {
            a: G1Affine::generator(),
            b: G2Affine::generator(),
            c: -G1Affine::generator(),
        };
        let wire = proof_to_wire(&proof).unwrap();
        assert_eq!(proof_from_wire(&wire).unwrap(), proof);
    }

    #[test]
    fn proof_wire_rejects_incomplete_or_extra_coordinates() {
        for length in [0, 255, 257, 288] {
            let wire = Groth16ProofWire {
                backend: ProofBackendWire::Groth16Bn254,
                proof: base64::engine::general_purpose::STANDARD.encode(vec![0; length]),
            };
            assert!(proof_from_wire(&wire)
                .unwrap_err()
                .to_string()
                .contains("eight 32-byte coordinates"));
        }
    }

    #[test]
    fn proof_wire_rejects_noncanonical_coordinates() {
        let mut bytes = [0; 256];
        bytes[..32].fill(0xff);
        let wire = Groth16ProofWire {
            backend: ProofBackendWire::Groth16Bn254,
            proof: base64::engine::general_purpose::STANDARD.encode(bytes),
        };
        assert!(proof_from_wire(&wire)
            .unwrap_err()
            .to_string()
            .contains("non-canonical BN254 base-field coordinate"));
    }

    #[test]
    fn proof_wire_rejects_invalid_curve_points() {
        let mut bytes = [0; 256];
        bytes[63] = 1;
        let wire = Groth16ProofWire {
            backend: ProofBackendWire::Groth16Bn254,
            proof: base64::engine::general_purpose::STANDARD.encode(bytes),
        };
        assert!(proof_from_wire(&wire)
            .unwrap_err()
            .to_string()
            .contains("invalid curve point"));
    }

    #[test]
    fn commitment_update_matches_blinding_arithmetic() {
        let blind = random_scalar();
        let rerandomization = random_scalar();
        let delta = random_scalar();
        let initial = balance_commitment(100, &blind, &Felt252::from_u64(42));
        let anonymous = rerandomize(&initial, &rerandomization).unwrap();
        let updated = server_update(&anonymous, 7, &delta).unwrap();
        let expected_blind = add_blindings(&add_blindings(&blind, &rerandomization), &delta);
        assert_eq!(
            updated,
            balance_commitment(93, &expected_blind, &Felt252::from_u64(42))
        );
    }

    #[test]
    fn compact_signature_round_trip() {
        let signer = CompactSigner::from_seed(&Felt252::from_u64(42));
        let message = core::hash_felts(&[Felt252::from_u64(7)]);
        let signature = signer.sign(&message);
        assert!(signer.verify(&message, &signature).unwrap());
    }

    #[test]
    fn core_and_circuit_primitives_match() {
        let secret = Felt252::from_u64(42);
        let registration = core::registration_commitment(&secret);
        assert_eq!(
            registration,
            felt(&crate::groth16::registration_commitment(field(&secret)))
        );
        let core_leaf = core::note_leaf(7, &registration, 5_000_000, 4_000_000_000);
        let circuit_leaf =
            crate::groth16::note_leaf(7, field(&registration), 5_000_000, 4_000_000_000);
        assert_eq!(core_leaf, felt(&circuit_leaf));
        let siblings = [Felt252::ZERO; MERKLE_DEPTH];
        assert_eq!(
            core::merkle_root(7, &core_leaf, &siblings),
            felt(&crate::groth16::merkle_root(
                7,
                circuit_leaf,
                &siblings.map(|value| field(&value)),
            ))
        );
    }

    #[test]
    fn generated_solana_transition_setup_proves_and_binds_every_public_input() {
        let setup =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../setup/solana-transition-v1");
        let prover = SolanaTransitionProver::load(&setup).unwrap();
        let verifier = SolanaTransitionVerifier::load(&setup).unwrap();

        let note_id = 7;
        let commitment = Felt252::from_u64(0xcafe);
        let amount = 5_000_000;
        let expiry = 4_000_000_000;
        let tree = zkapi_core::MerkleTree::new();
        let siblings = tree.get_siblings(note_id);
        let leaf = core::note_leaf(note_id, &commitment, u128::from(amount), expiry);
        let public = SolanaMerkleTransitionInputs {
            protocol_version: 2,
            chain_id: 11_155_111,
            protocol_binding: Felt252::from_u64(0xdead),
            old_root: tree.root(),
            new_root: core::merkle_root(note_id, &leaf, &siblings),
            note_id,
            commitment,
            amount,
            expiry,
            inserting: true,
        };
        let proof = prover.prove(&public, siblings).unwrap();
        assert!(verifier.verify(&public, &proof).unwrap());

        let mut tampered = Vec::new();
        let mut value = public.clone();
        value.protocol_version = 3;
        tampered.push(value);
        let mut value = public.clone();
        value.chain_id += 1;
        tampered.push(value);
        let mut value = public.clone();
        value.protocol_binding = Felt252::from_u64(0xbeef);
        tampered.push(value);
        let mut value = public.clone();
        value.old_root = Felt252::from_u64(1);
        tampered.push(value);
        let mut value = public.clone();
        value.new_root = Felt252::from_u64(2);
        tampered.push(value);
        let mut value = public.clone();
        value.note_id += 1;
        tampered.push(value);
        let mut value = public.clone();
        value.commitment = Felt252::from_u64(0xbad);
        tampered.push(value);
        let mut value = public.clone();
        value.amount += 1;
        tampered.push(value);
        let mut value = public.clone();
        value.expiry += 1;
        tampered.push(value);
        let mut value = public.clone();
        value.inserting = false;
        tampered.push(value);

        for changed in tampered {
            assert!(!verifier.verify(&changed, &proof).unwrap());
        }

        let mut wrong_siblings = siblings;
        wrong_siblings[0] = Felt252::from_u64(3);
        assert!(prover.prove(&public, wrong_siblings).is_err());
    }
}
