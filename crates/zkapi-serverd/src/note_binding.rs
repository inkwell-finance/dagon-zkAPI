//! Review regression: server-signed state for A must never authorize note B.
use crate::{
    config::ServerConfig, nullifier_store::NullifierStore, processor::RequestProcessor,
    signer::ServerSigner,
};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use zkapi_core::v2 as core;
use zkapi_proof::compact::{
    add_blindings, balance_commitment, rerandomize, RequestProver, RequestWitnessData,
    WithdrawalProver, WithdrawalVerifier, WithdrawalWitnessData,
};
use zkapi_types::wire::ApiRequestV2;
use zkapi_types::{
    canonical_payload_hash, canonical_request_context, Felt252, RequestPublicInputsV2,
    WithdrawalPublicInputsV2, MERKLE_DEPTH,
};

#[tokio::test]
async fn sequential_signed_state_cannot_branch_across_equal_or_unequal_notes() {
    let setup = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../protocol/setup/v2");
    let prover = RequestProver::load(&setup).unwrap();
    let withdrawal_prover = WithdrawalProver::load(&setup).unwrap();
    let withdrawal_verifier = WithdrawalVerifier::load(&setup).unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expiry = now + 86400;
    for b_deposit in [50, 100] {
        let signer = Arc::new(ServerSigner::new(
            &Felt252::from_u64(7),
            &Felt252::from_u64(8),
        ));
        let key = signer.state_public_key();
        let clear_key = signer.clearance_public_key();
        let a_secret = Felt252::from_u64(42);
        let b_secret = Felt252::from_u64(43);
        let a_leaf = core::note_leaf(0, &core::registration_commitment(&a_secret), 100, expiry);
        let b_leaf = core::note_leaf(
            1,
            &core::registration_commitment(&b_secret),
            b_deposit,
            expiry,
        );
        let mut a_path: [Felt252; MERKLE_DEPTH] =
            core::zero_hashes()[..MERKLE_DEPTH].try_into().unwrap();
        a_path[0] = b_leaf;
        let mut b_path = a_path;
        b_path[0] = a_leaf;
        let root = core::merkle_root(0, &a_leaf, &a_path);
        assert_eq!(root, core::merkle_root(1, &b_leaf, &b_path));
        let mut config: ServerConfig =
            crate::test_support::config(crate::test_support::oa_source());
        config.profile.vault.request_charge_cap = 1;
        config.proof_setup_dir = setup.to_string_lossy().into_owned();
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        let processor = RequestProcessor::try_new(
            config.clone(),
            store,
            signer.clone(),
            root,
            crate::test_support::StubLedger::unavailable(&config),
            crate::test_support::StubBilling::accepting(&config),
        )
        .unwrap();
        let prepare = |id: &str, witness: &RequestWitnessData| {
            let payload = crate::test_support::lease_payload(&config, now);
            let payload_hash = canonical_payload_hash(payload.as_bytes());
            let context = canonical_request_context(id, &payload_hash);
            let leaf = core::note_leaf(
                witness.note_id,
                &core::registration_commitment(&witness.secret),
                witness.deposit_amount,
                witness.expiry,
            );
            let anonymous = rerandomize(
                &balance_commitment(witness.current_balance, &witness.current_blinding, &leaf),
                &witness.rerandomization,
            )
            .unwrap();
            let nullifier =
                core::nullifier(&witness.secret, witness.note_id, &witness.current_anchor);
            (
                RequestPublicInputsV2 {
                    protocol_version: config.protocol_version(),
                    chain_id: config.chain_id(),
                    contract_address: config.contract_address(),
                    active_root: root,
                    state_signing_key_x: key.x,
                    state_signing_key_y: key.y,
                    request_time: now,
                    solvency_bound: 1,
                    request_nullifier: nullifier,
                    authorization_tag: core::authorization_tag(&nullifier, &context),
                    anonymous_commitment_x: anonymous.x,
                    anonymous_commitment_y: anonymous.y,
                },
                context,
                payload,
                payload_hash,
            )
        };
        let mut a = RequestWitnessData {
            secret: a_secret,
            request_context: Felt252::ZERO,
            note_id: 0,
            deposit_amount: 100,
            expiry,
            merkle_siblings: a_path,
            current_balance: 100,
            current_blinding: Felt252::from_u64(17),
            rerandomization: Felt252::from_u64(19),
            current_anchor: core::GENESIS_ANCHOR,
            prev_anchor: Felt252::ZERO,
            state_signature: None,
        };
        let mut last_response = None;
        for step in 0..2 {
            let id = format!("A-{b_deposit}-{step}");
            let (public, context, payload, payload_hash) = prepare(&id, &a);
            a.request_context = context;
            let proof = prover.prove(&public, a.clone()).unwrap();
            let request = ApiRequestV2 {
                client_request_id: id,
                payload,
                payload_hash,
                public_inputs: public,
                proof,
            };
            let response = processor.finalize_test_lease(&request, 1).unwrap();
            assert_eq!(
                response.next_anchor,
                core::next_anchor(&request.public_inputs.request_nullifier),
                "the successor is signed at the derived anchor"
            );
            a.current_balance -= response.charge_applied;
            a.current_blinding = add_blindings(
                &add_blindings(&a.current_blinding, &a.rerandomization),
                &response.blind_delta_srv,
            );
            a.prev_anchor = a.current_anchor;
            a.current_anchor = response.next_anchor;
            a.state_signature = Some(response.next_state_signature);
            assert_eq!(a.current_balance, 99 - step);
            if step == 0 {
                last_response = Some(a.clone());
            }
        }
        // Reuse the genuine 99-unit state after A has already continued to 98.
        let mut b = last_response.unwrap();
        b.secret = b_secret;
        b.note_id = 1;
        b.deposit_amount = b_deposit;
        b.merkle_siblings = b_path;
        let (public, context, _, _) = prepare("B-transplant", &b);
        b.request_context = context;
        assert!(
            prover.prove(&public, b.clone()).is_err(),
            "A's signed state cannot authorize note B"
        );
        // Both honest escape and mutual withdrawals remain provable after two
        // requests; the escape names the derived successor nullifier.
        for has_clearance in [false, true] {
            let nullifier = core::nullifier(&a.secret, 0, &a.current_anchor);
            let public = WithdrawalPublicInputsV2 {
                protocol_version: config.protocol_version(),
                chain_id: config.chain_id(),
                contract_address: config.contract_address(),
                registration: core::registration_commitment(&a.secret),
                state_signing_key_x: key.x,
                state_signing_key_y: key.y,
                clearance_signing_key_x: clear_key.x,
                clearance_signing_key_y: clear_key.y,
                note_id: 0,
                deposit_amount: 100,
                expiry_ts: expiry,
                final_balance: a.current_balance,
                destination: [0x11; 20],
                withdrawal_nullifier: nullifier,
                has_clearance,
                next_nullifier: if has_clearance {
                    Felt252::ZERO
                } else {
                    core::successor_nullifier(&a.secret, 0, &nullifier)
                },
                conceded: 0,
                valid_until: now + 600,
            };
            let witness = WithdrawalWitnessData {
                secret: a.secret,
                current_balance: a.current_balance,
                final_blinding: a.current_blinding,
                current_anchor: a.current_anchor,
                prev_anchor: a.prev_anchor,
                state_signature: a.state_signature,
                clearance_signature: has_clearance.then(|| {
                    signer.sign_clearance(&core::clearance_message(
                        config.protocol_version(),
                        config.chain_id(),
                        &config.contract_address(),
                        &nullifier,
                    ))
                }),
            };
            let proof = withdrawal_prover.prove(&public, witness).unwrap();
            assert!(withdrawal_verifier.verify(&public, &proof).unwrap());
        }
    }
}
