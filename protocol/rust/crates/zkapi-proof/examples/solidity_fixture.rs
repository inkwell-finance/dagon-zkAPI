use anyhow::{Context, Result};
use base64::Engine;
use serde::Serialize;
use zkapi_core::v2 as core;
use zkapi_proof::compact::{
    balance_commitment, rerandomize, CompactSigner, RequestProver, RequestVerifier,
    RequestWitnessData, WithdrawalProver, WithdrawalVerifier, WithdrawalWitnessData,
};
use zkapi_types::{Felt252, RequestPublicInputsV2, WithdrawalPublicInputsV2, MERKLE_DEPTH};

#[derive(Serialize)]
struct Fixture<T> {
    public_inputs: T,
    proof_hex: String,
}

#[derive(Serialize)]
struct Fixtures {
    request: Fixture<RequestPublicInputsV2>,
    withdrawal: Fixture<WithdrawalPublicInputsV2>,
}

fn main() -> Result<()> {
    let setup = std::env::args()
        .nth(1)
        .context("usage: solidity_fixture SETUP_DIRECTORY")?;
    let secret = Felt252::from_u64(42);
    let deposit_amount = 1_000_000u128;
    let expiry = 4_000_000_000u64;
    let note_id = 0u32;
    let zero_hashes = core::zero_hashes();
    let siblings: [Felt252; MERKLE_DEPTH] = zero_hashes[..MERKLE_DEPTH].try_into().unwrap();
    let registration = core::registration_commitment(&secret);
    let leaf = core::note_leaf(note_id, &registration, deposit_amount, expiry);
    let root = core::merkle_root(note_id, &leaf, &siblings);
    let state_signer = CompactSigner::from_seed(&Felt252::from_u64(1));
    let clearance_signer = CompactSigner::from_seed(&Felt252::from_u64(2));
    let state_key = state_signer.public_key();
    let clearance_key = clearance_signer.public_key();
    let contract_address = Felt252::from_u64(0x1234);
    let current_anchor = Felt252::ONE;
    let blinding = Felt252::from_u64(7);
    let rerandomization = Felt252::from_u64(9);
    let anonymous = rerandomize(
        &balance_commitment(deposit_amount, &blinding, &leaf),
        &rerandomization,
    )?;
    let nullifier = core::nullifier(&secret, note_id, &current_anchor);
    let request_context = Felt252::from_u64(99);
    let request_public = RequestPublicInputsV2 {
        protocol_version: 2,
        chain_id: 31_337,
        contract_address,
        active_root: root,
        state_signing_key_x: state_key.x,
        state_signing_key_y: state_key.y,
        request_time: 2_000_000_000,
        solvency_bound: 500_000,
        request_nullifier: nullifier,
        authorization_tag: core::authorization_tag(&nullifier, &request_context),
        anonymous_commitment_x: anonymous.x,
        anonymous_commitment_y: anonymous.y,
    };
    let request_proof = RequestProver::load(&setup)?.prove(
        &request_public,
        RequestWitnessData {
            secret,
            request_context,
            note_id,
            deposit_amount,
            expiry,
            merkle_siblings: siblings,
            current_balance: deposit_amount,
            current_blinding: blinding,
            rerandomization,
            current_anchor,
            prev_anchor: Felt252::ZERO,
            state_signature: None,
        },
    )?;
    assert!(RequestVerifier::load(&setup)?.verify(&request_public, &request_proof)?);

    let destination = [0x11u8; 20];
    let withdrawal_public = WithdrawalPublicInputsV2 {
        protocol_version: 2,
        chain_id: 31_337,
        contract_address,
        registration,
        state_signing_key_x: state_key.x,
        state_signing_key_y: state_key.y,
        clearance_signing_key_x: clearance_key.x,
        clearance_signing_key_y: clearance_key.y,
        note_id,
        deposit_amount,
        expiry_ts: expiry,
        final_balance: deposit_amount,
        destination,
        withdrawal_nullifier: nullifier,
        has_clearance: false,
        next_nullifier: core::successor_nullifier(&secret, note_id, &nullifier),
        conceded: 0,
        valid_until: expiry,
    };
    let withdrawal_proof = WithdrawalProver::load(&setup)?.prove(
        &withdrawal_public,
        WithdrawalWitnessData {
            secret,
            current_balance: deposit_amount,
            final_blinding: blinding,
            current_anchor,
            prev_anchor: Felt252::ZERO,
            state_signature: None,
            clearance_signature: None,
        },
    )?;
    assert!(WithdrawalVerifier::load(&setup)?.verify(&withdrawal_public, &withdrawal_proof)?);

    let proof_hex = |proof: &zkapi_types::wire::Groth16ProofWire| -> Result<String> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&proof.proof)
            .context("decode proof")?;
        Ok(format!("0x{}", hex::encode(bytes)))
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&Fixtures {
            request: Fixture {
                public_inputs: request_public,
                proof_hex: proof_hex(&request_proof)?,
            },
            withdrawal: Fixture {
                public_inputs: withdrawal_public,
                proof_hex: proof_hex(&withdrawal_proof)?,
            },
        })?
    );
    Ok(())
}
