//! Regenerate the real-proof Solana vault regression fixture with the
//! committed setup (run from `protocol/rust`):
//! cargo run --release -p zkapi-proof --example vault_challenge_fixture -- ../setup/v2 \
//!   > ../test-vectors/vault-challenge.json
//!
//! Every statement is bound to a fixed test deployment (genesis hash, program
//! id and vault-state PDA below) through the Solana `chain_id` /
//! `contract_address` derivations, and every withdrawal pays the Solana
//! destination account `DESTINATION`.
use anyhow::{Context, Result};
use base64::Engine;
use serde::Serialize;
use zkapi_core::v2 as core;
use zkapi_proof::compact::{
    balance_commitment, rerandomize, CompactSigner, RequestProver, RequestVerifier,
    RequestWitnessData, WithdrawalProver, WithdrawalVerifier, WithdrawalWitnessData, CIRCUIT_ID,
};
use zkapi_types::{
    wire::Groth16ProofWire, Felt252, RequestPublicInputsV2, SchnorrSignature,
    WithdrawalPublicInputsV2, MERKLE_DEPTH,
};

const TIMESTAMP: u64 = 2_000_000_000;
const NOTE_TTL: u64 = 30 * 86_400;
const DEPOSIT: u128 = 1_000_000;
const GENESIS_HASH: [u8; 32] = [3; 32];
const PROGRAM_ID: [u8; 32] = [0x5a; 32];
const VAULT_STATE: [u8; 32] = [0x7b; 32];
const DESTINATION: [u8; 32] = [0x11; 32];

#[derive(Serialize)]
struct Fixture {
    proof_hex: String,
    public_inputs: serde_json::Value,
    public_fields: Vec<Felt252>,
}

#[derive(Serialize)]
struct Fixtures {
    circuit_id: &'static str,
    note_a_registration: String,
    req0: Fixture,
    req1: Fixture,
    req2: Fixture,
    esc0: Fixture,
    esc1: Fixture,
    esc1_conceded: Fixture,
    esc2: Fixture,
    close2: Fixture,
}

struct Generator {
    requests: RequestProver,
    request_verifier: RequestVerifier,
    withdrawals: WithdrawalProver,
    withdrawal_verifier: WithdrawalVerifier,
    state_signer: CompactSigner,
    clearance_signer: CompactSigner,
    expiry: u64,
    chain_id: u64,
    vault: Felt252,
}

#[derive(Clone)]
struct Note {
    id: u32,
    secret: Felt252,
    balance: u128,
    blinding: Felt252,
    anchor: Felt252,
    prev_anchor: Felt252,
    signature: Option<SchnorrSignature>,
}

impl Generator {
    fn leaf(&self, note: &Note) -> Felt252 {
        core::note_leaf(
            note.id,
            &core::registration_commitment(&note.secret),
            DEPOSIT,
            self.expiry,
        )
    }

    fn request(&self, note: &Note, siblings: [Felt252; MERKLE_DEPTH]) -> Result<Fixture> {
        let key = self.state_signer.public_key();
        let leaf = self.leaf(note);
        let context = Felt252::from_u64(99);
        let rerandomization = Felt252::from_u64(9);
        let anonymous = rerandomize(
            &balance_commitment(note.balance, &note.blinding, &leaf),
            &rerandomization,
        )?;
        let nullifier = core::nullifier(&note.secret, note.id, &note.anchor);
        let public = RequestPublicInputsV2 {
            protocol_version: 2,
            chain_id: self.chain_id,
            contract_address: self.vault,
            active_root: core::merkle_root(note.id, &leaf, &siblings),
            state_signing_key_x: key.x,
            state_signing_key_y: key.y,
            request_time: TIMESTAMP,
            solvency_bound: 100_000,
            request_nullifier: nullifier,
            authorization_tag: core::authorization_tag(&nullifier, &context),
            anonymous_commitment_x: anonymous.x,
            anonymous_commitment_y: anonymous.y,
        };
        let proof = self.requests.prove(
            &public,
            RequestWitnessData {
                secret: note.secret,
                request_context: context,
                note_id: note.id,
                deposit_amount: DEPOSIT,
                expiry: self.expiry,
                merkle_siblings: siblings,
                current_balance: note.balance,
                current_blinding: note.blinding,
                rerandomization,
                current_anchor: note.anchor,
                prev_anchor: note.prev_anchor,
                state_signature: note.signature,
            },
        )?;
        anyhow::ensure!(
            self.request_verifier.verify(&public, &proof)?,
            "request proof failed"
        );
        fixture(&public.to_field_elements(), &proof, &public)
    }

    fn withdrawal(
        &self,
        note: &Note,
        conceded: u128,
        clearance: bool,
    ) -> Result<Fixture> {
        let key = self.state_signer.public_key();
        let clear_key = self.clearance_signer.public_key();
        let nullifier = core::nullifier(&note.secret, note.id, &note.anchor);
        let public = WithdrawalPublicInputsV2 {
            protocol_version: 2,
            chain_id: self.chain_id,
            contract_address: self.vault,
            registration: core::registration_commitment(&note.secret),
            state_signing_key_x: key.x,
            state_signing_key_y: key.y,
            clearance_signing_key_x: clear_key.x,
            clearance_signing_key_y: clear_key.y,
            note_id: note.id,
            deposit_amount: DEPOSIT,
            expiry_ts: self.expiry,
            final_balance: note.balance - conceded,
            destination: zkapi_types::solana_destination_binding(&DESTINATION),
            withdrawal_nullifier: nullifier,
            has_clearance: clearance,
            next_nullifier: if clearance { Felt252::ZERO } else {
                core::successor_nullifier(&note.secret, note.id, &nullifier)
            },
            conceded,
            valid_until: TIMESTAMP + 20 * 86_400,
        };
        let proof = self.withdrawals.prove(
            &public,
            WithdrawalWitnessData {
                secret: note.secret,
                current_balance: note.balance,
                final_blinding: note.blinding,
                current_anchor: note.anchor,
                prev_anchor: note.prev_anchor,
                state_signature: note.signature,
                clearance_signature: clearance.then(|| {
                    self.clearance_signer.sign(&core::clearance_message(
                        2,
                        self.chain_id,
                        &self.vault,
                        &nullifier,
                    ))
                }),
            },
        )?;
        anyhow::ensure!(
            self.withdrawal_verifier.verify(&public, &proof)?,
            "withdrawal proof failed"
        );
        fixture(&public.to_field_elements(), &proof, &public)
    }
}

fn fixture(public_fields: &[Felt252], proof: &Groth16ProofWire, public: &impl Serialize) -> Result<Fixture> {
    let proof = base64::engine::general_purpose::STANDARD.decode(&proof.proof)?;
    Ok(Fixture {
        proof_hex: format!("0x{}", hex::encode(proof)),
        public_inputs: serde_json::to_value(public)?,
        public_fields: public_fields.to_vec(),
    })
}

fn main() -> Result<()> {
    let setup = std::env::args()
        .nth(1)
        .context("usage: vault_challenge_fixture SETUP_DIRECTORY")?;
    let generator = Generator {
        requests: RequestProver::load(&setup)?,
        request_verifier: RequestVerifier::load(&setup)?,
        withdrawals: WithdrawalProver::load(&setup)?,
        withdrawal_verifier: WithdrawalVerifier::load(&setup)?,
        state_signer: CompactSigner::from_seed(&Felt252::from_u64(1)),
        clearance_signer: CompactSigner::from_seed(&Felt252::from_u64(2)),
        expiry: (TIMESTAMP + NOTE_TTL).div_ceil(86_400) * 86_400,
        chain_id: zkapi_types::solana_chain_id(&GENESIS_HASH),
        vault: zkapi_types::solana_deployment_binding(&PROGRAM_ID, &VAULT_STATE, &GENESIS_HASH),
    };
    let genesis = Note {
        id: 0,
        secret: Felt252::from_u64(42),
        balance: DEPOSIT,
        blinding: Felt252::from_u64(7),
        anchor: Felt252::ONE,
        prev_anchor: Felt252::ZERO,
        signature: None,
    };
    let advance = |previous: &Note, charge: u128| {
        let mut next = previous.clone();
        next.prev_anchor = previous.anchor;
        next.anchor = core::next_anchor(&core::nullifier(&previous.secret, previous.id, &previous.anchor));
        next.balance -= charge;
        // Request rerandomization is 9; a zero server delta is sufficient.
        next.blinding = zkapi_proof::compact::add_blindings(&previous.blinding, &Felt252::from_u64(9));
        let commitment = balance_commitment(next.balance, &next.blinding, &generator.leaf(&next));
        next.signature = Some(generator.state_signer.sign(&core::state_message(
            2, generator.chain_id, &generator.vault, &commitment.x, &commitment.y, &next.anchor,
        )));
        next
    };
    let a = advance(&genesis, 100_000);
    let successor = advance(&a, 50_000);
    let empty: [Felt252; MERKLE_DEPTH] = core::zero_hashes()[..MERKLE_DEPTH].try_into().unwrap();
    let fixtures = Fixtures {
        circuit_id: CIRCUIT_ID,
        note_a_registration: format!(
            "0x{}",
            hex::encode(core::registration_commitment(&a.secret).as_bytes())
        ),
        req0: generator.request(&genesis, empty)?,
        req1: generator.request(&a, empty)?,
        req2: generator.request(&successor, empty)?,
        esc0: generator.withdrawal(&genesis, 0, false)?,
        esc1: generator.withdrawal(&a, 0, false)?,
        esc1_conceded: generator.withdrawal(&a, 100_000, false)?,
        esc2: generator.withdrawal(&successor, 0, false)?,
        close2: generator.withdrawal(&successor, 0, true)?,
    };
    println!("{}", serde_json::to_string_pretty(&fixtures)?);
    Ok(())
}
