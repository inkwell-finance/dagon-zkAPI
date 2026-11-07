use super::*;

fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!("../../../../protocol/test-vectors/vault-challenge.json")).unwrap()
}

fn proof(value: &serde_json::Value) -> Vec<u8> {
    hex::decode(value["proof_hex"].as_str().unwrap().trim_start_matches("0x")).unwrap()
}

fn request(value: &serde_json::Value, note_id: u32) -> ChallengePayload {
    let p: RequestPublicInputsV2 = serde_json::from_value(value["public_inputs"].clone()).unwrap();
    ChallengePayload { note_id, proof: proof(value), public_inputs: RequestInputs {
        protocol_version: p.protocol_version, chain_id: p.chain_id,
        contract_address: *p.contract_address.as_bytes(), active_root: *p.active_root.as_bytes(),
        state_signing_key_x: *p.state_signing_key_x.as_bytes(), state_signing_key_y: *p.state_signing_key_y.as_bytes(),
        request_time: p.request_time, solvency_bound: p.solvency_bound,
        request_nullifier: *p.request_nullifier.as_bytes(), authorization_tag: *p.authorization_tag.as_bytes(),
        anonymous_commitment_x: *p.anonymous_commitment_x.as_bytes(), anonymous_commitment_y: *p.anonymous_commitment_y.as_bytes(),
    }}
}

fn withdrawal(value: &serde_json::Value) -> WithdrawalPayload {
    let p: WithdrawalPublicInputsV2 = serde_json::from_value(value["public_inputs"].clone()).unwrap();
    WithdrawalPayload { proof: proof(value), public_inputs: WithdrawalInputs {
        protocol_version: p.protocol_version, chain_id: p.chain_id,
        contract_address: *p.contract_address.as_bytes(), registration: *p.registration.as_bytes(),
        state_signing_key_x: *p.state_signing_key_x.as_bytes(), state_signing_key_y: *p.state_signing_key_y.as_bytes(),
        clearance_signing_key_x: *p.clearance_signing_key_x.as_bytes(), clearance_signing_key_y: *p.clearance_signing_key_y.as_bytes(),
        note_id: p.note_id, deposit_amount: p.deposit_amount, expiry_ts: p.expiry_ts,
        final_balance: p.final_balance, destination: p.destination,
        withdrawal_nullifier: *p.withdrawal_nullifier.as_bytes(), has_clearance: p.has_clearance,
        next_nullifier: *p.next_nullifier.as_bytes(), conceded: p.conceded, valid_until: p.valid_until,
    }}
}

fn state(p: &WithdrawalInputs) -> (VaultState, NoteState, PendingWithdrawal) {
    let key = Pubkey::new_unique();
    let vault = VaultState {
        version: VAULT_VERSION, bump: 255, paused: false, authority: Pubkey::new_unique(),
        treasury_token: Pubkey::new_unique(), mint: crate::token::USDC_MINT,
        vault_token: Pubkey::new_unique(), vault_token_bump: 255,
        genesis_hash: [3; 32], chain_id: p.chain_id,
        protocol_binding: p.contract_address, current_root: [7; 32], next_note_id: p.note_id + 1,
        note_ttl: 86_400, challenge_period: 60, request_charge_cap: 100_000,
        total_credits: p.deposit_amount as u64,
        state_signing_key_x: p.state_signing_key_x, state_signing_key_y: p.state_signing_key_y,
        clearance_signing_key_x: p.clearance_signing_key_x, clearance_signing_key_y: p.clearance_signing_key_y,
        paused_at: 0, last_pause_end: 0, total_paused_duration: 0,
        treasury_accrued: 0, deferred_payouts: 0,
    };
    let note = NoteState { vault: key, note_id: p.note_id, commitment: p.registration,
        deposit_amount: p.deposit_amount as u64, expiry: p.expiry_ts,
        status: NOTE_STATUS_PENDING, bump: 255, claimable_after: p.expiry_ts, paused_offset: 0 };
    let pending = PendingWithdrawal { vault: key, note_id: p.note_id,
        nullifier: p.withdrawal_nullifier, next_nullifier: p.next_nullifier,
        state_balance: (p.final_balance + p.conceded) as u64, conceded: p.conceded as u64,
        final_balance: p.final_balance as u64, destination: Pubkey::new_unique(),
        deadline: p.expiry_ts + 10, bump: 255, rent_payer: Pubkey::new_unique(),
        stage: PENDING_STAGE_OPEN };
    (vault, note, pending)
}

#[test]
fn withheld_successor_cannot_defeat_and_payout_is_balance_minus_bound() {
    let f = fixture();
    let escape = withdrawal(&f["esc1"]);
    verify_withdrawal_bytes(&escape.public_inputs.to_wire().unwrap(), &escape.proof).unwrap();
    let (vault, mut note, mut pending) = state(&escape.public_inputs);
    let evidence = request(&f["req1"], note.note_id);
    let now = pending.deadline;
    let note_id = note.note_id;
    assert!(apply_escape_challenge(&vault, &mut note, &pending, &evidence, note_id, now).is_err());
    assert_eq!(note.status, NOTE_STATUS_PENDING);
    let deadline = pending.deadline;
    apply_raise_concession(&vault, &note, &mut pending, &evidence, note_id, u128::MAX, now).unwrap();
    assert_eq!(pending.conceded, evidence.public_inputs.solvency_bound as u64);
    assert_eq!(pending.final_balance, pending.state_balance - pending.conceded);
    assert_eq!(pending.deadline, deadline, "raising cannot extend the challenge window");
    assert!(apply_raise_concession(&vault, &note, &mut pending, &evidence, note_id, u128::MAX, now).is_err());
    assert!(apply_raise_concession(&vault, &note, &mut pending, &evidence, note_id, 0, now).is_err());
}

#[test]
fn successor_spend_defeats_stale_escape_at_deadline_without_root_or_pause_dependency() {
    let f = fixture();
    let escape = withdrawal(&f["esc1"]);
    let (mut vault, mut note, pending) = state(&escape.public_inputs);
    let evidence = request(&f["req2"], note.note_id);
    vault.current_root = [9; 32];
    vault.paused = true;
    vault.paused_at = pending.deadline - 1;
    let note_id = note.note_id;
    assert!(apply_escape_challenge(&vault, &mut note, &pending, &evidence, note_id, pending.deadline + 1).is_err());
    apply_escape_challenge(&vault, &mut note, &pending, &evidence, note_id, pending.deadline).unwrap();
    assert_eq!(note.status, NOTE_STATUS_ACTIVE);
    assert_eq!(note.claimable_after, pending.deadline + vault.challenge_period);
    assert_eq!(vault.current_root, [9; 32]);
    assert!(validate_expired_claim(&vault, &note, note_id, pending.deadline).is_err());
    assert!(apply_escape_challenge(&vault, &mut note, &pending, &evidence, note_id, pending.deadline).is_err());
}

#[test]
fn raise_caps_at_state_balance_and_rejects_wrong_note_nullifier_or_proof() {
    let f = fixture();
    let escape = withdrawal(&f["esc1"]);
    let (vault, note, mut pending) = state(&escape.public_inputs);
    let evidence = request(&f["req1"], note.note_id);
    let now = pending.deadline;
    pending.state_balance = 50;
    pending.final_balance = 50;
    pending.conceded = 0;
    let mut wrong = evidence.clone();
    wrong.public_inputs.request_nullifier = [4; 32];
    assert!(apply_raise_concession(&vault, &note, &mut pending, &wrong, note.note_id, 100, now).is_err());
    wrong = evidence.clone();
    wrong.note_id += 1;
    assert!(apply_raise_concession(&vault, &note, &mut pending, &wrong, note.note_id, 100, now).is_err());
    wrong = evidence.clone();
    wrong.proof[0] ^= 1;
    assert!(apply_raise_concession(&vault, &note, &mut pending, &wrong, note.note_id, 100, now).is_err());
    assert_eq!(pending.conceded, 0);
    apply_raise_concession(&vault, &note, &mut pending, &evidence, note.note_id, 100, now).unwrap();
    assert_eq!(pending.conceded, 50);
    assert_eq!(pending.final_balance, 0);
}

#[test]
fn leaf_binding_exit_ttl_and_pause_checks_ignore_front_running_deposits() {
    let f = fixture();
    let mut escape = withdrawal(&f["esc1"]);
    let (mut vault, mut note, _) = state(&escape.public_inputs);
    note.status = NOTE_STATUS_ACTIVE;
    // The fixture's real proof is verified above. Bind the destination to this
    // test's fresh token account for the pre-verification account-binding checks.
    let destination = Pubkey::new_unique();
    escape.public_inputs.destination = zkapi_types::solana_destination_binding(&destination.to_bytes());
    let now = escape.public_inputs.valid_until.min(note.expiry - 1);
    assert!(validate_withdrawal(&vault, &note, &escape, &destination, false, now).is_ok());
    assert!(validate_withdrawal(&vault, &note, &escape, &Pubkey::new_unique(), false, now).is_err(),
        "a substituted payout account does not match the proof binding");
    vault.current_root = [11; 32];
    vault.next_note_id += 1;
    assert!(validate_withdrawal(&vault, &note, &escape, &destination, false, now).is_ok());
    let mut wrong = escape.clone();
    wrong.public_inputs.registration = [1; 32];
    assert!(validate_withdrawal(&vault, &note, &wrong, &destination, false, now).is_err());
    wrong = escape.clone();
    wrong.public_inputs.deposit_amount += 1;
    assert!(validate_withdrawal(&vault, &note, &wrong, &destination, false, now).is_err());
    wrong = escape.clone();
    wrong.public_inputs.conceded = u128::MAX;
    assert!(validate_withdrawal(&vault, &note, &wrong, &destination, false, now).is_err());
    assert!(validate_withdrawal(&vault, &note, &escape, &destination, false, escape.public_inputs.valid_until + 1).is_err());
    update_pause(&mut vault, true, now).unwrap();
    assert!(validate_withdrawal(&vault, &note, &escape, &destination, false, now).is_err());
    escape.public_inputs.valid_until = now + MAX_PAUSE_DURATION;
    assert!(validate_withdrawal(&vault, &note, &escape, &destination, false, now + MAX_PAUSE_DURATION).is_ok());
}
