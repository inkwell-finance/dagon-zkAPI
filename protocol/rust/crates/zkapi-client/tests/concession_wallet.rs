//! Concession-exit behaviour of the native wallet: successor checks S1–S6,
//! one bound per state (C2), the exit lock (C3) and the concession choice
//! (E2/E3), with real proofs from the committed setup.

use std::path::{Path, PathBuf};

use zkapi_client::config::{ClientConfig, ClientProofMode};
use zkapi_client::error::ClientError;
use zkapi_client::exit_lock::ExitMode;
use zkapi_client::exit_policy::{
    self, disposition, EscapeReason, ExitDecision, NoteChainStatus, SETTLEMENT_GRACE_SECONDS,
};
use zkapi_client::journal::PendingRequestJournal;
use zkapi_client::note_state::NoteState;
use zkapi_client::wallet::{verify_successor, withdrawal_statement, ExitContext, Wallet};
use zkapi_core::merkle::MerkleTree;
use zkapi_core::v2 as core;
use zkapi_proof::compact::{
    random_field, random_scalar, rerandomize, server_update, CompactSigner, WithdrawalVerifier,
};
use zkapi_types::wire::{CurvePointWire, RequestResponseV2};
use zkapi_types::{canonical_payload_hash, canonical_response_hash, Felt252};

const CAP: u128 = 400;
const DEPOSIT: u128 = 5_000_000;
const WINDOW: u64 = 21_905;
const DESTINATION: [u8; 20] = [0x11; 20];

fn setup_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../setup/v2")
}

fn state_signer() -> CompactSigner {
    CompactSigner::from_seed(&Felt252::from_u64(0x5747))
}

fn config(state_dir: &Path, cap: u128) -> ClientConfig {
    ClientConfig {
        protocol_version: 2,
        chain_id: 11_155_111,
        contract_address: Felt252::from_u64(99),
        request_charge_cap: cap,
        policy_charge_cap: cap,
        policy_enabled: false,
        server_url: "http://127.0.0.1:9".into(),
        state_dir: state_dir.to_string_lossy().into_owned(),
        proof_mode: ClientProofMode::Groth16 {
            setup_dir: setup_dir().to_string_lossy().into_owned(),
        },
        state_signing_key: state_signer().public_key(),
        clearance_signing_key: CompactSigner::from_seed(&Felt252::from_u64(0xc1ea)).public_key(),
        settlement_window_seconds: WINDOW,
        unsettled_request_escape_after_seconds: None,
    }
}

fn fresh_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "zkapi_concession_{name}_{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A wallet holding a genesis note far from expiry, and the note's path.
fn wallet(name: &str) -> (Wallet, PathBuf, Felt252, Vec<Felt252>) {
    let dir = fresh_dir(name);
    let mut wallet = Wallet::new(config(&dir, CAP)).unwrap();
    let (secret, registration) = wallet.generate_deposit_params();
    let expiry = now() + 30 * 86_400;
    wallet.confirm_deposit(secret, 0, DEPOSIT, expiry).unwrap();
    let mut tree = MerkleTree::new();
    tree.set_leaf(0, core::note_leaf(0, &registration, DEPOSIT, expiry));
    let root = tree.root();
    let siblings = tree.get_siblings(0).to_vec();
    (wallet, dir, root, siblings)
}

fn prepare(wallet: &mut Wallet, root: Felt252, siblings: &[Felt252]) -> Result<(), ClientError> {
    let payload = "{\"mode\":\"openrouter_ephemeral_lease\"}";
    wallet
        .prepare_request(
            payload,
            canonical_payload_hash(payload.as_bytes()),
            root,
            siblings.to_vec(),
        )
        .map(|_| ())
}

/// A response to `journal` at `state` signed by the pinned key, with the
/// given charge and anchor, whose commitment uses `commitment_delta` while
/// it reports `reported_delta`.
fn signed_response(
    state: &NoteState,
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

fn honest(state: &NoteState, journal: &PendingRequestJournal, charge: u128) -> RequestResponseV2 {
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

/// Threat: an operator that withholds the real successor and signs one the
/// client could not spend (random anchor, born-spent anchor 1, a phantom
/// commitment, an overcharge). Each is `invalid_successor`, recorded as
/// such, and the wallet then refuses new requests and escapes conceding its
/// bound once the settlement window passes.
#[test]
fn signed_but_invalid_successors_are_withheld() {
    let (mut wallet, dir, root, siblings) = wallet("withheld");
    prepare(&mut wallet, root, &siblings).unwrap();
    let state = wallet.state().unwrap().clone();
    let journal = wallet.get_pending_journal().unwrap().unwrap();
    let cfg = config(&dir, CAP);
    let delta = random_scalar();
    let derived = core::next_anchor(&journal.nullifier);
    let cases = [
        ("random anchor", signed_response(&state, &journal, 10, random_field(), delta, delta)),
        (
            "born-spent anchor",
            signed_response(&state, &journal, 10, core::GENESIS_ANCHOR, delta, delta),
        ),
        (
            "wrong commitment",
            signed_response(&state, &journal, 10, derived, random_scalar(), delta),
        ),
        ("overcharge", signed_response(&state, &journal, CAP + 1, derived, delta, delta)),
    ];
    for (name, response) in &cases {
        assert!(
            matches!(
                verify_successor(&cfg, &state, &journal, response),
                Err(ClientError::InvalidSuccessor(_))
            ),
            "{name} must be refused as invalid_successor"
        );
    }
    // An unsigned successor is a transport fault, not a withheld successor.
    let mut forged = honest(&state, &journal, 10);
    forged.next_state_signature = CompactSigner::from_seed(&Felt252::ONE).sign(&Felt252::ONE);
    assert!(matches!(
        verify_successor(&cfg, &state, &journal, &forged),
        Err(ClientError::VerificationFailed(_))
    ));

    let error = wallet
        .complete_pending_response(&cases[0].1)
        .unwrap_err();
    assert!(matches!(error, ClientError::InvalidSuccessor(_)));
    let marked = wallet.state().unwrap();
    assert_eq!(marked.current_anchor, core::GENESIS_ANCHOR, "nothing installed");
    assert_eq!(marked.released[0].disposition, disposition::INVALID_SUCCESSOR);
    assert!(wallet.has_pending_request(), "the journal is kept");
    // A reloaded wallet sees the same record.
    let reloaded = Wallet::new(cfg).unwrap();
    assert_eq!(
        reloaded.state().unwrap().released[0].disposition,
        disposition::INVALID_SUCCESSOR
    );
    let created = marked.released[0].created_at;
    let at_deadline = created + WINDOW + SETTLEMENT_GRACE_SECONDS;
    assert_eq!(
        wallet
            .decide_exit(ExitContext {
                now: at_deadline,
                ..ExitContext::default()
            })
            .unwrap(),
        ExitDecision::Escape {
            conceded: CAP,
            reason: EscapeReason::AtDeadline
        }
    );
}

/// C2: re-proving at a state reuses the recorded bound; another bound is
/// refused before any proof is made. An honest install resets it and
/// records `prev_anchor`.
#[test]
fn a_second_request_at_the_same_state_reuses_the_bound() {
    let (mut wallet, dir, root, siblings) = wallet("bound");
    prepare(&mut wallet, root, &siblings).unwrap();
    assert_eq!(wallet.state().unwrap().bound_at_state, CAP);
    // The server refused it before reservation (stale root): the bound stays.
    wallet.clear_pending_request().unwrap();
    let state = wallet.state().unwrap();
    assert_eq!(state.bound_at_state, CAP);
    assert_eq!(state.released[0].disposition, disposition::DISCARDED_STALE_ROOT);

    let mut higher = Wallet::new(config(&dir, CAP * 2)).unwrap();
    assert!(matches!(
        prepare(&mut higher, root, &siblings),
        Err(ClientError::BoundFixedAtState {
            bound: CAP,
            requested
        }) if requested == CAP * 2
    ));
    assert!(!higher.has_pending_request());

    let mut wallet = Wallet::new(config(&dir, CAP)).unwrap();
    prepare(&mut wallet, root, &siblings).unwrap();
    let state = wallet.state().unwrap().clone();
    assert_eq!(state.bound_at_state, CAP);
    assert_eq!(state.released.len(), 2);
    let journal = wallet.get_pending_journal().unwrap().unwrap();
    assert_eq!(
        journal.prepared_request.as_ref().unwrap().public_inputs.solvency_bound,
        CAP
    );

    wallet
        .complete_pending_response(&honest(&state, &journal, 25))
        .unwrap();
    let next = wallet.state().unwrap();
    assert_eq!(next.prev_anchor, Some(core::GENESIS_ANCHOR));
    assert_eq!(next.bound_at_state, 0);
    assert!(next.released.is_empty());
    assert_eq!(next.current_balance, DEPOSIT - 25);
    assert_eq!(next.nullifier(), state.successor_nullifier());
    assert!(!wallet.has_pending_request());
    // The installed state proves requests at the new bound (Q-chain).
    let mut wallet = Wallet::new(config(&dir, CAP * 2)).unwrap();
    prepare(&mut wallet, root, &siblings).unwrap();
    assert_eq!(wallet.state().unwrap().bound_at_state, CAP * 2);
}

/// A crash after the successor was saved but before the journal was cleared
/// leaves the predecessor's journal behind. Reloading finishes that install
/// instead of blocking every later request; a journal at the current state
/// survives a reload.
#[test]
fn a_journal_whose_successor_is_installed_is_cleared_on_reload() {
    let (mut wallet, dir, root, siblings) = wallet("crash");
    prepare(&mut wallet, root, &siblings).unwrap();
    let state = wallet.state().unwrap().clone();
    let journal = wallet.get_pending_journal().unwrap().unwrap();
    // A reload with the journal still at the current state keeps it.
    let wallet = Wallet::new(config(&dir, CAP)).unwrap();
    assert!(wallet.has_pending_request());
    // Crash between `next.save` and `PendingRequestJournal::clear`.
    let next = verify_successor(&config(&dir, CAP), &state, &journal, &honest(&state, &journal, 25))
        .unwrap();
    next.save(&dir.join("note_state.json")).unwrap();
    assert!(PendingRequestJournal::read(&dir.join("pending_journal.json"))
        .unwrap()
        .is_some());

    let mut wallet = Wallet::new(config(&dir, CAP)).unwrap();
    assert!(!wallet.has_pending_request());
    assert_eq!(wallet.state().unwrap().current_anchor, next.current_anchor);
    prepare(&mut wallet, root, &siblings).unwrap();
    assert_eq!(
        wallet.get_pending_journal().unwrap().unwrap().nullifier,
        state.successor_nullifier()
    );
}

/// Threat: withholding operator with a request in flight. The wallet waits
/// for settlement, then escapes conceding exactly `b_k`; the escape proof
/// publishes `N⁺` and `f = B − b_k`, verifies, and freezes the wallet (C3)
/// until the proof is dead.
#[test]
fn the_exit_proof_concedes_the_bound_when_a_request_is_in_flight() {
    let (mut wallet, dir, root, siblings) = wallet("inflight");
    assert_eq!(
        wallet
            .decide_exit(ExitContext {
                now: now(),
                ..ExitContext::default()
            })
            .unwrap(),
        ExitDecision::Mutual,
        "a fresh state closes mutually"
    );
    prepare(&mut wallet, root, &siblings).unwrap();
    let state = wallet.state().unwrap().clone();
    let journal = wallet.get_pending_journal().unwrap().unwrap();
    let created = state.released[0].created_at;
    let deadline = created + WINDOW + SETTLEMENT_GRACE_SECONDS;
    assert_eq!(
        wallet
            .decide_exit(ExitContext {
                now: created + 1,
                ..ExitContext::default()
            })
            .unwrap(),
        ExitDecision::Wait { until: deadline }
    );
    let ExitDecision::Escape { conceded, .. } = wallet
        .decide_exit(ExitContext {
            now: deadline,
            ..ExitContext::default()
        })
        .unwrap()
    else {
        panic!("expected an escape at the deadline");
    };
    assert_eq!(conceded, CAP);
    assert!(matches!(
        wallet.withdrawal_escape_hatch(DESTINATION, CAP + 1),
        Err(ClientError::ConcededExceedsBound { .. })
    ));
    assert!(wallet.exit_lock().unwrap().is_none());

    let before = now();
    let (public, proof) = wallet.withdrawal_escape_hatch(DESTINATION, conceded).unwrap();
    let after = now();
    assert!(!public.has_clearance);
    assert_eq!(public.conceded, CAP);
    assert_eq!(public.final_balance, DEPOSIT - CAP);
    assert_eq!(public.withdrawal_nullifier, state.nullifier());
    assert_eq!(public.next_nullifier, state.successor_nullifier());
    assert_eq!(public.registration, core::registration_commitment(&state.secret_s));
    assert!(
        (before + exit_policy::EXIT_PROOF_VALIDITY_SECONDS..=after + exit_policy::EXIT_PROOF_VALIDITY_SECONDS)
            .contains(&public.valid_until)
    );
    assert!(WithdrawalVerifier::load(setup_dir())
        .unwrap()
        .verify(&public, &proof)
        .unwrap());

    let lock = wallet.exit_lock().unwrap().unwrap();
    assert_eq!(lock.mode, ExitMode::Escape);
    assert_eq!(lock.released.len(), 1);
    assert_eq!(lock.released[0].conceded, CAP);
    // C3: frozen. A late successor is not installed while the proof may land,
    // a mutual close is not started, and no new request is proved.
    assert!(matches!(
        wallet.complete_pending_response(&honest(&state, &journal, 10)),
        Err(ClientError::ExitLocked(_))
    ));
    assert!(matches!(
        wallet.begin_exit(ExitMode::Mutual),
        Err(ClientError::ExitLocked(_))
    ));
    wallet.clear_pending_request().unwrap();
    assert!(matches!(
        prepare(&mut wallet, root, &siblings),
        Err(ClientError::ExitLocked(_))
    ));
    // E6: the lock outlives the proof's validity window.
    let valid_until = lock.released[0].valid_until;
    assert!(!wallet
        .release_exit_lock(true, NoteChainStatus::Active, Some(u64::MAX), valid_until)
        .unwrap());
    assert!(wallet
        .release_exit_lock(
            false,
            NoteChainStatus::Active,
            Some(valid_until + 1_000),
            valid_until + 1_000
        )
        .unwrap());
    assert!(wallet.exit_lock().unwrap().is_none());
    drop(dir);
}

/// E3: a successor that arrives before any exit proof left installs and
/// moves the lock to the new state; the mutual-close statement concedes
/// nothing and publishes no successor nullifier.
#[test]
fn a_successor_before_any_released_exit_moves_the_lock() {
    let (mut wallet, dir, root, siblings) = wallet("moved");
    prepare(&mut wallet, root, &siblings).unwrap();
    let state = wallet.state().unwrap().clone();
    let journal = wallet.get_pending_journal().unwrap().unwrap();
    wallet.begin_exit(ExitMode::Escape).unwrap();
    wallet
        .complete_pending_response(&honest(&state, &journal, 7))
        .unwrap();
    let next = wallet.state().unwrap().clone();
    let lock = wallet.exit_lock().unwrap().unwrap();
    assert_eq!(lock.anchor, next.current_anchor);
    assert!(lock.released.is_empty());
    let switched = wallet.begin_exit(ExitMode::Mutual).unwrap();
    assert_eq!(switched.mode, ExitMode::Mutual);

    let cfg = config(&dir, CAP);
    let close =
        withdrawal_statement(&cfg, &next, ExitMode::Mutual, DESTINATION, 0, now() + 60).unwrap();
    assert!(close.has_clearance);
    assert_eq!(
        (close.next_nullifier, close.conceded, close.final_balance),
        (Felt252::ZERO, 0, DEPOSIT - 7)
    );
    assert!(withdrawal_statement(&cfg, &next, ExitMode::Mutual, DESTINATION, 1, 1).is_err());
    assert!(matches!(
        withdrawal_statement(&cfg, &next, ExitMode::Escape, DESTINATION, 1, 1),
        Err(ClientError::ConcededExceedsBound { bound: 0, .. })
    ));
}
