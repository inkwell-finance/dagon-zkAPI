use super::*;
use std::path::PathBuf;
use zkapi_proof::compact::{CompactSigner, RequestVerifier, WithdrawalVerifier};
use zkapi_types::wire::ProofBackendWire;

const BOUND: u128 = 100;
const DEPOSIT: u128 = 2_000_000;
const EXPIRY: u64 = 1_900_000_000;

fn state_signer() -> CompactSigner {
    CompactSigner::from_seed(&Felt252::from_u64(0x5747))
}

fn clearance_signer() -> CompactSigner {
    CompactSigner::from_seed(&Felt252::from_u64(0xc1ea))
}

fn config() -> BrowserWalletConfig {
    BrowserWalletConfig {
        protocol_version: 2,
        ledger_backend: default_ledger_backend(),
        chain_id: 11_155_111,
        contract_address: Felt252::from_u64(99),
        request_charge_cap: BOUND,
        policy_charge_cap: 200,
        policy_enabled: false,
        state_signing_key: state_signer().public_key(),
        clearance_signing_key: clearance_signer().public_key(),
    }
}

fn genesis(note_id: u32) -> BrowserNoteState {
    let params = generate_deposit_params();
    confirm_deposit(
        &config(),
        ConfirmDepositArgs {
            secret: params.secret,
            note_id,
            amount: DEPOSIT,
            expiry_ts: EXPIRY,
        },
    )
    .unwrap()
}

/// A journal for a request at `state` with bound `BOUND`, as
/// `prepare_request` would have written it (the proof bytes are not used by
/// `complete_response`), and the state with the bound recorded.
fn released(state: &BrowserNoteState) -> (BrowserNoteState, PendingRequestJournal) {
    let nullifier = withdrawal_nullifier(state);
    let payload = "{}".to_string();
    let payload_hash = canonical_payload_hash(payload.as_bytes());
    let request = ApiRequestV2 {
        client_request_id: "request-1".into(),
        payload,
        payload_hash,
        public_inputs: RequestPublicInputsV2 {
            protocol_version: state.protocol_version,
            chain_id: state.chain_id,
            contract_address: state.contract_address,
            active_root: Felt252::ONE,
            state_signing_key_x: config().state_signing_key.x,
            state_signing_key_y: config().state_signing_key.y,
            request_time: 1,
            solvency_bound: BOUND,
            request_nullifier: nullifier,
            authorization_tag: Felt252::ONE,
            anonymous_commitment_x: Felt252::ONE,
            anonymous_commitment_y: Felt252::ONE,
        },
        proof: Groth16ProofWire {
            backend: ProofBackendWire::Groth16Bn254,
            proof: "unused".into(),
        },
    };
    let journal = PendingRequestJournal {
        exists: true,
        client_request_id: "request-1".into(),
        nullifier,
        payload_hash,
        user_rerandomization: random_scalar(),
        created_at_ms: 1_000,
        prepared_request: request,
    };
    let mut bound = state.clone();
    bound.bound_at_state = BOUND;
    (bound, journal)
}

/// A response to `journal` at `state` signed by the pinned state key, with
/// the given charge, anchor and the commitment `C + ε·H − charge·G +
/// commitment_delta·H` while reporting `reported_delta`.
fn signed_response(
    state: &BrowserNoteState,
    journal: &PendingRequestJournal,
    charge: u128,
    next_anchor: Felt252,
    commitment_delta: Felt252,
    reported_delta: Felt252,
) -> RequestResponseV2 {
    let current = CurvePointWire {
        x: state.current_commitment_x,
        y: state.current_commitment_y,
    };
    let anonymous = rerandomize(&current, &journal.user_rerandomization).unwrap();
    let next_commitment = server_update(&anonymous, charge, &commitment_delta).unwrap();
    let message = core::state_message(
        state.protocol_version,
        state.chain_id,
        &state.contract_address,
        &next_commitment.x,
        &next_commitment.y,
        &next_anchor,
    );
    let payload = "{\"ok\":true}".to_string();
    RequestResponseV2 {
        status: "finalized".into(),
        client_request_id: journal.client_request_id.clone(),
        request_nullifier: journal.nullifier,
        response_code: 200,
        response_hash: canonical_response_hash(payload.as_bytes()),
        response_payload: payload,
        charge_applied: charge,
        next_commitment,
        next_anchor,
        blind_delta_srv: reported_delta,
        next_state_signature: state_signer().sign(&message),
        policy_reason_code: None,
        policy_evidence_hash: None,
    }
}

fn honest_response(
    state: &BrowserNoteState,
    journal: &PendingRequestJournal,
    charge: u128,
) -> RequestResponseV2 {
    let delta = random_scalar();
    signed_response(
        state,
        journal,
        charge,
        core::next_anchor(&journal.nullifier),
        delta,
        delta,
    )
}

fn install(
    state: BrowserNoteState,
    journal: PendingRequestJournal,
    response: RequestResponseV2,
) -> Result<BrowserNoteState> {
    complete_response(
        &config(),
        CompleteResponseArgs {
            state,
            journal,
            response,
        },
    )
}

fn assert_code(result: Result<impl std::fmt::Debug>, code: &str) {
    let error = result.unwrap_err().to_string();
    assert!(
        error.starts_with(&format!("{code}: ")),
        "expected {code}, got {error}"
    );
}

fn escape_args(conceded: u128) -> PrepareWithdrawalArgs {
    PrepareWithdrawalArgs {
        mode: "escape".into(),
        destination: "0x1111111111111111111111111111111111111111".into(),
        conceded,
        valid_until: 1_800_010_800,
        clearance: None,
    }
}

#[test]
fn deposit_state_roundtrip_has_consistent_commitment() {
    let state = genesis(7);
    let blinding = parse_scalar(&state.balance_blinding).unwrap();
    stored_commitment(&state, &blinding).unwrap();
    assert_eq!(state.current_anchor, core::GENESIS_ANCHOR);
    assert_eq!(state.prev_anchor, None);
    assert_eq!(state.bound_at_state, 0);
    let status = wallet_status(Some(&state), None).note.unwrap();
    assert_eq!((status.note_id, status.bound_at_state), (7, 0));
}

#[test]
fn states_saved_before_the_concession_fields_still_load() {
    let state = genesis(3);
    let mut value = serde_json::to_value(&state).unwrap();
    let object = value.as_object_mut().unwrap();
    object.remove("prev_anchor");
    object.remove("bound_at_state");
    let loaded: BrowserNoteState = serde_json::from_value(value).unwrap();
    assert_eq!(loaded, state);
}

#[test]
fn deployment_mismatch_is_rejected() {
    let mut wrong = config();
    wrong.chain_id = 1;
    assert_code(validate_state(&wrong, &genesis(0)), codes::STATE_INVALID);
}

#[test]
fn address_parser_is_strict() {
    assert_eq!(
        parse_address("0x1111111111111111111111111111111111111111").unwrap(),
        [0x11; 20]
    );
    assert_eq!(
        parse_address("000102030405060708090a0B0c0D0e0F10111213").unwrap(),
        std::array::from_fn(|index| index as u8)
    );
    assert!(parse_address("0x1234").is_err());
    assert!(parse_address("0x111111111111111111111111111111111111111").is_err());
    assert!(parse_address("0x11111111111111111111111111111111111111111").is_err());
    assert!(parse_address("0xgg11111111111111111111111111111111111111").is_err());
}

#[test]
fn solana_destination_is_bound_without_changing_the_withdrawal_statement() {
    let account = [7u8; 32];
    let encoded = bs58::encode(account).into_string();
    assert_eq!(
        withdrawal_destination("dagon.solana.groth16.v1", &encoded).unwrap(),
        zkapi_types::solana_destination_binding(&account)
    );
    assert!(withdrawal_destination("dagon.solana.groth16.v1", "1111").is_err());
    assert!(withdrawal_destination("unknown", &encoded).is_err());
}

/// Threat: a withholding operator signs successors the client cannot spend
/// or exit from. Each is refused as `invalid_successor` (treated as
/// withheld), so the client keeps exiting from its own state.
#[test]
fn signed_but_invalid_successors_are_treated_as_withheld() {
    let (state, journal) = released(&genesis(1));
    let delta = random_scalar();
    let derived = core::next_anchor(&journal.nullifier);

    // S4: random anchor.
    let random_anchor = signed_response(&state, &journal, 10, random_field(), delta, delta);
    assert_code(
        install(state.clone(), journal.clone(), random_anchor),
        codes::INVALID_SUCCESSOR,
    );
    // S4: born-spent anchor (genesis anchor 1).
    let born_spent = signed_response(&state, &journal, 10, core::GENESIS_ANCHOR, delta, delta);
    assert_code(
        install(state.clone(), journal.clone(), born_spent.clone()),
        codes::INVALID_SUCCESSOR,
    );
    assert!(check_unrecoverable_response(&config(), &state, &born_spent).is_err());
    // S5: commitment that does not open to (B − charge, r + ε + δ).
    let phantom = signed_response(&state, &journal, 10, derived, random_scalar(), delta);
    let error = install(state.clone(), journal.clone(), phantom)
        .unwrap_err()
        .to_string();
    assert!(error.starts_with("invalid_successor: S5"), "{error}");
    // S3: overcharge beyond the request's bound.
    let overcharge = signed_response(&state, &journal, BOUND + 1, derived, delta, delta);
    let error = install(state.clone(), journal.clone(), overcharge)
        .unwrap_err()
        .to_string();
    assert!(error.starts_with("invalid_successor: S3"), "{error}");
    // S6: an unsigned successor is a transport fault, not a successor.
    let mut forged = honest_response(&state, &journal, 10);
    forged.next_state_signature = clearance_signer().sign(&Felt252::ONE);
    assert_code(
        install(state.clone(), journal.clone(), forged),
        codes::SUCCESSOR_SIGNATURE_INVALID,
    );
    // S3: a journal whose bound is not the state's recorded bound.
    let mut unbound = state.clone();
    unbound.bound_at_state = 0;
    let response = honest_response(&state, &journal, 10);
    assert_code(
        install(unbound, journal.clone(), response),
        codes::INVALID_SUCCESSOR,
    );
}

#[test]
fn honest_successor_installs_with_prev_anchor_and_a_fresh_bound() {
    let (state, journal) = released(&genesis(2));
    let response = honest_response(&state, &journal, 40);
    let lost = check_unrecoverable_response(&config(), &state, &response).unwrap();
    assert_eq!(lost.charge_applied, 40);
    let next = install(state.clone(), journal.clone(), response).unwrap();
    assert_eq!(next.prev_anchor, Some(core::GENESIS_ANCHOR));
    assert_eq!(next.current_anchor, core::next_anchor(&journal.nullifier));
    assert_eq!(next.current_balance, DEPOSIT - 40);
    assert_eq!(next.bound_at_state, 0);
    assert!(!next.is_genesis);
    let blinding = parse_scalar(&next.balance_blinding).unwrap();
    stored_commitment(&next, &blinding).unwrap();
    // The installed state's nullifier is the successor nullifier an escape
    // from the old state publishes.
    assert_eq!(withdrawal_nullifier(&next), successor_nullifier(&state));
    // A response to an older journal does not apply to the new state.
    let replay = honest_response(&state, &journal, 40);
    assert_code(
        install(next, journal, replay),
        codes::JOURNAL_STATE_MISMATCH,
    );
}

/// C2: one bound per state. A second request at the same state with another
/// bound is refused before any key is loaded; the same bound is allowed.
#[test]
fn a_second_request_at_the_same_state_must_reuse_the_bound() {
    let (state, _) = released(&genesis(4));
    let mut higher = config();
    higher.request_charge_cap = BOUND * 2;
    let args = PrepareRequestArgs {
        payload: "{}".into(),
        active_root: Felt252::ONE,
        merkle_siblings: vec![Felt252::ZERO; MERKLE_DEPTH],
        client_request_id: "request-2".into(),
        request_time: 1,
        created_at_ms: 1,
    };
    assert_code(
        prepare_request(&higher, &state, args.clone(), &[]),
        codes::BOUND_FIXED_AT_STATE,
    );
    assert_eq!(request_bound(&config(), &state).unwrap(), BOUND);
}

#[test]
fn a_signed_state_without_prev_anchor_cannot_prove() {
    let (state, journal) = released(&genesis(6));
    let mut installed = install(state.clone(), journal.clone(), honest_response(&state, &journal, 0)).unwrap();
    installed.prev_anchor = None;
    assert_code(request_bound(&config(), &installed), codes::PREV_ANCHOR_MISSING);
    assert_code(
        withdrawal_statement(&config(), &installed, &escape_args(0)),
        codes::PREV_ANCHOR_MISSING,
    );
}

#[test]
fn withdrawal_statements_bind_the_concession_and_successor() {
    let (state, _) = released(&genesis(8));
    let (escape, clearance) = withdrawal_statement(&config(), &state, &escape_args(BOUND)).unwrap();
    assert!(clearance.is_none());
    assert!(!escape.has_clearance);
    assert_eq!(escape.conceded, BOUND);
    assert_eq!(escape.final_balance, DEPOSIT - BOUND);
    assert_eq!(escape.next_nullifier, successor_nullifier(&state));
    assert_eq!(escape.withdrawal_nullifier, withdrawal_nullifier(&state));
    assert_eq!(
        escape.registration,
        core::registration_commitment(&state.secret_s)
    );
    assert_eq!(
        (escape.note_id, escape.deposit_amount, escape.expiry_ts),
        (8, DEPOSIT, EXPIRY)
    );
    assert_code(
        withdrawal_statement(&config(), &state, &escape_args(BOUND + 1)),
        codes::CONCEDED_EXCEEDS_BOUND,
    );
    let mut stale = escape_args(0);
    stale.valid_until = 0;
    assert_code(
        withdrawal_statement(&config(), &state, &stale),
        codes::WITHDRAWAL_ARGS,
    );

    let nullifier = withdrawal_nullifier(&state);
    let clearance_message = core::clearance_message(
        state.protocol_version,
        state.chain_id,
        &state.contract_address,
        &nullifier,
    );
    let mut mutual = escape_args(0);
    mutual.mode = "mutual".into();
    mutual.clearance = Some(ClearanceResponseV2 {
        status: "cleared".into(),
        withdrawal_nullifier: nullifier,
        signature: clearance_signer().sign(&clearance_message),
    });
    let (close, signature) = withdrawal_statement(&config(), &state, &mutual).unwrap();
    assert!(signature.is_some() && close.has_clearance);
    assert_eq!(
        (close.next_nullifier, close.conceded, close.final_balance),
        (Felt252::ZERO, 0, DEPOSIT)
    );
    mutual.conceded = 1;
    assert_code(
        withdrawal_statement(&config(), &state, &mutual),
        codes::WITHDRAWAL_ARGS,
    );
}

#[test]
fn withdrawal_args_accept_decimal_strings() {
    let args: PrepareWithdrawalArgs = serde_json::from_str(
        r#"{"mode":"escape","destination":"0x1111111111111111111111111111111111111111","conceded":"340282366920938463463374607431768211455","valid_until":"1800000000"}"#,
    )
    .unwrap();
    assert_eq!((args.conceded, args.valid_until), (u128::MAX, 1_800_000_000));
    let args: PrepareWithdrawalArgs = serde_json::from_str(
        r#"{"mode":"mutual","destination":"0x1111111111111111111111111111111111111111","valid_until":5}"#,
    )
    .unwrap();
    assert_eq!(args.conceded, 0);
    assert!(serde_json::from_str::<PrepareWithdrawalArgs>(
        r#"{"mode":"escape","destination":"x","conceded":"-1","valid_until":5}"#
    )
    .is_err());
    assert!(serde_json::from_str::<PrepareWithdrawalArgs>(
        r#"{"mode":"escape","destination":"x","valid_until":5,"merkle_siblings":[]}"#
    )
    .is_err());
}

/// Real proofs with the committed setup: requests from genesis and from an
/// installed successor (exercising Q-chain with `prev_anchor`), a second
/// request at the same state with the same bound, an escape conceding the
/// state's bound and a mutual close, all verified.
#[test]
fn fetched_key_bytes_produce_verifiable_browser_proofs() {
    let config = config();
    let note_id = 0;
    let state = genesis(note_id);
    let leaf = state_note_leaf(&state);
    let mut tree = MerkleTree::new();
    tree.set_leaf(note_id, leaf);
    let setup = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../setup/v2");
    let request_prover =
        RequestProver::from_bytes(&std::fs::read(setup.join("request.pk")).unwrap()).unwrap();
    let request_verifier = RequestVerifier::load(&setup).unwrap();
    let withdrawal_verifier = WithdrawalVerifier::load(&setup).unwrap();
    let withdrawal_key = std::fs::read(setup.join("withdrawal.pk")).unwrap();
    let args = |id: &str| PrepareRequestArgs {
        payload: "{\"mode\":\"openrouter_ephemeral_lease\",\"version\":1}".into(),
        active_root: tree.root(),
        merkle_siblings: tree.get_siblings(note_id).to_vec(),
        client_request_id: id.into(),
        request_time: 1_800_000_000,
        created_at_ms: 1_800_000_000_000,
    };

    let first = prepare_request_with_prover(&config, &state, args("genesis-1"), &request_prover)
        .unwrap();
    assert_eq!(first.state.bound_at_state, BOUND);
    assert!(request_verifier
        .verify(&first.request.public_inputs, &first.request.proof)
        .unwrap());
    // Re-proving an unfinished request at the same state reuses the bound.
    let again =
        prepare_request_with_prover(&config, &first.state, args("genesis-2"), &request_prover)
            .unwrap();
    assert_eq!(again.state.bound_at_state, BOUND);
    assert_eq!(again.request.public_inputs.solvency_bound, BOUND);

    let response = honest_response(&again.state, &again.journal, 30);
    let next = install(again.state.clone(), again.journal.clone(), response).unwrap();
    let successor = prepare_request_with_prover(&config, &next, args("next-1"), &request_prover)
        .unwrap();
    assert_eq!(
        successor.request.public_inputs.request_nullifier,
        successor_nullifier(&again.state)
    );
    assert!(request_verifier
        .verify(&successor.request.public_inputs, &successor.request.proof)
        .unwrap());

    // Escape from the successor with a request in flight concedes b_k.
    let plan = prepare_withdrawal(&config, &successor.state, escape_args(BOUND), &withdrawal_key)
        .unwrap();
    assert_eq!(plan.public_inputs.conceded, BOUND);
    assert_eq!(plan.public_inputs.final_balance, DEPOSIT - 30 - BOUND);
    assert!(withdrawal_verifier
        .verify(&plan.public_inputs, &plan.proof)
        .unwrap());

    // Mutual close from genesis.
    let nullifier = withdrawal_nullifier(&state);
    let message = core::clearance_message(
        state.protocol_version,
        state.chain_id,
        &state.contract_address,
        &nullifier,
    );
    let mut mutual = escape_args(0);
    mutual.mode = "mutual".into();
    mutual.clearance = Some(ClearanceResponseV2 {
        status: "cleared".into(),
        withdrawal_nullifier: nullifier,
        signature: clearance_signer().sign(&message),
    });
    let plan = prepare_withdrawal(&config, &state, mutual, &withdrawal_key).unwrap();
    assert!(withdrawal_verifier
        .verify(&plan.public_inputs, &plan.proof)
        .unwrap());
}
