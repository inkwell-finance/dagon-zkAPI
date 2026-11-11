//! Kani model-checking harnesses for the vault's USDC accounting.
//!
//! Compiled only under `cargo kani` (`cfg(kani)`): the SBF build never sees
//! this module, and its `mod` line is the last line of `lib.rs`, so no panic
//! location in the program moves.
//!
//! The handlers take Anchor `Context`s and CPI into the Token program, so
//! `step` replays each handler's accounting statements, in order, through the
//! program's own functions (`close_note_liability`, `ensure_solvency`,
//! `payout_target_ok`, `validate_finalize`, `validate_release`,
//! `validate_rent_refund`, `validate_expired_claim`, `rent_refund`,
//! `apply_escape_challenge`, `apply_raise_concession`, `update_pause`). The
//! few statements that live only inside a handler are copied verbatim and cite
//! their `lib.rs` lines. The Token program is modelled by its balance
//! arithmetic; a deposit's credited amount is left unconstrained, so only the
//! handler's exact-delta check stands between it and the books. Guards that
//! cannot change the accounting (Groth16 proofs, nullifier PDAs, deployment
//! fields, Anchor address/`has_one` constraints, clocks) are dropped. That
//! only adds behaviours, so every safety property proved here also holds for
//! the program. The Groth16 request verifier is stubbed by an arbitrary
//! accept/reject, which likewise covers every proof outcome, and
//! `VaultError`'s name and message are stubbed to empty strings (an error's
//! text never steers control flow).

use super::*;
use crate::token::{ACCOUNT_STATE_FROZEN, ACCOUNT_STATE_INITIALIZED, TOKEN_ACCOUNT_LEN};

const VAULT_STATE: Pubkey = Pubkey::new_from_array([0xA0; 32]);
const VAULT_TOKEN: Pubkey = Pubkey::new_from_array([0xA1; 32]);
const TREASURY: Pubkey = Pubkey::new_from_array([0xA2; 32]);
const RENT_PAYER: Pubkey = Pubkey::new_from_array([0xA3; 32]);
const NOTE_ID: u32 = 7;
const NULLIFIER: [u8; 32] = [7; 32];
const SUCCESSOR: [u8; 32] = [8; 32];

const DEPOSIT: u8 = 0;
const DEPOSIT_OTHER: u8 = 1;
const DONATE: u8 = 2;
const CLOSE: u8 = 3;
const ESCAPE: u8 = 4;
const CHALLENGE: u8 = 5;
const RAISE: u8 = 6;
const FINALIZE: u8 = 7;
const RELEASE: u8 = 8;
const REFUND_RENT: u8 = 9;
const CLAIM_EXPIRED: u8 = 10;
const RETIRE: u8 = 11;
const WITHDRAW_TREASURY: u8 = 12;
const SET_PAUSED: u8 = 13;
const OPS: u8 = 14;

/// Accept or reject any request proof (replaces the Groth16 verifier).
#[allow(dead_code)] // referenced only by `#[kani::stub]`
fn verify_request_stub(
    _public: &RequestPublicInputsV2,
    _proof: &[u8],
) -> core::result::Result<(), dagon_zkapi_solana::SolanaVerifierError> {
    if kani::any() {
        Ok(())
    } else {
        Err(dagon_zkapi_solana::SolanaVerifierError::WrongBackend)
    }
}

/// `VaultError::name` without the text: only `Ok`/`Err` matters here.
#[allow(dead_code)]
fn vault_error_name_stub(_error: &VaultError) -> String {
    String::new()
}

/// `VaultError`'s `Display` without the text.
#[allow(dead_code)]
fn vault_error_fmt_stub(_error: &VaultError, _f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    Ok(())
}

/// Every harness runs with the request verifier stubbed (arbitrary verdict)
/// and `VaultError`'s name and message reduced to empty strings. Error text
/// never steers control flow, and formatting it dominated symbolic execution.
macro_rules! harness {
    ($(#[$attr:meta])* fn $name:ident() $body:block) => {
        #[kani::proof]
        #[kani::stub(dagon_zkapi_solana::verify_request_bytes, verify_request_stub)]
        #[kani::stub(crate::VaultError::name, vault_error_name_stub)]
        #[kani::stub(<crate::VaultError as core::fmt::Display>::fmt, vault_error_fmt_stub)]
        $(#[$attr])*
        fn $name() $body
    };
}

fn any_key() -> Pubkey {
    Pubkey::new_from_array(kani::any())
}

fn any_vault() -> VaultState {
    VaultState {
        version: VAULT_VERSION,
        bump: 255,
        paused: kani::any(),
        authority: Pubkey::new_from_array([0x11; 32]),
        treasury_token: TREASURY,
        mint: USDC_MINT,
        vault_token: VAULT_TOKEN,
        vault_token_bump: 254,
        genesis_hash: [3; 32],
        chain_id: 1,
        protocol_binding: [1; 32],
        current_root: [5; 32],
        next_note_id: kani::any(),
        note_ttl: 86_400,
        challenge_period: kani::any(),
        request_charge_cap: 1_000_000,
        total_credits: kani::any(),
        state_signing_key_x: [1; 32],
        state_signing_key_y: [2; 32],
        clearance_signing_key_x: [3; 32],
        clearance_signing_key_y: [4; 32],
        paused_at: kani::any(),
        last_pause_end: kani::any(),
        total_paused_duration: kani::any(),
        treasury_accrued: kani::any(),
        deferred_payouts: kani::any(),
    }
}

fn any_note() -> NoteState {
    NoteState {
        vault: VAULT_STATE,
        note_id: NOTE_ID,
        commitment: [6; 32],
        deposit_amount: kani::any(),
        expiry: kani::any(),
        status: kani::any(),
        bump: 255,
        claimable_after: kani::any(),
        paused_offset: kani::any(),
    }
}

/// `None` is a pending PDA that does not exist (never created or closed):
/// Anchor refuses to deserialize it, and `init` succeeds only then.
fn any_pending() -> Option<PendingWithdrawal> {
    if kani::any() {
        return None;
    }
    Some(PendingWithdrawal {
        vault: VAULT_STATE,
        note_id: NOTE_ID,
        nullifier: NULLIFIER,
        next_nullifier: SUCCESSOR,
        state_balance: kani::any(),
        conceded: kani::any(),
        final_balance: kani::any(),
        destination: any_key(),
        deadline: kani::any(),
        bump: 255,
        rent_payer: RENT_PAYER,
        stage: kani::any(),
    })
}

/// What `token::read_token_account` can return for the account at `key`:
/// `None` when it fails (closed, wrong owner or layout, uninitialized),
/// otherwise an initialized or frozen classic-Token account of any mint.
fn any_view(key: Pubkey) -> Option<TokenAccountView> {
    if kani::any() {
        return None;
    }
    let state: u8 = kani::any();
    kani::assume(state == ACCOUNT_STATE_INITIALIZED || state == ACCOUNT_STATE_FROZEN);
    let mint = if kani::any() { USDC_MINT } else { any_key() };
    Some(TokenAccountView { key, mint, owner: any_key(), amount: kani::any(), state })
}

fn evidence(vault: &VaultState, nullifier: [u8; 32], solvency_bound: u128) -> ChallengePayload {
    ChallengePayload {
        note_id: NOTE_ID,
        proof: Vec::new(),
        public_inputs: RequestInputs {
            protocol_version: PROTOCOL_VERSION,
            chain_id: vault.chain_id,
            contract_address: vault.protocol_binding,
            active_root: [0; 32],
            state_signing_key_x: vault.state_signing_key_x,
            state_signing_key_y: vault.state_signing_key_y,
            request_time: 0,
            solvency_bound,
            request_nullifier: nullifier,
            authorization_tag: [0; 32],
            anonymous_commitment_x: [0; 32],
            anonymous_commitment_y: [0; 32],
        },
    }
}

/// The vault's books plus one tracked note. `rest_*` stand for every other
/// note's share of the buckets; a step touches only the note it is given.
#[derive(Clone)]
struct World {
    vault: VaultState,
    /// `amount` of the vault token account.
    balance: u64,
    note: NoteState,
    pending: Option<PendingWithdrawal>,
    rest_credits: u64,
    rest_deferred: u64,
    /// Ghost: the tracked note's user payout has happened.
    paid: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Revert {
    /// A program check or account constraint failed.
    Program,
    /// Checked accounting math failed (overflow, underflow, lossy cast).
    Math,
    /// Token refused the vault outflow: `InsufficientFunds`.
    TokenInsufficientFunds,
    /// Token refused an inflow: the destination balance would overflow.
    TokenOverflow,
    /// `ensure_solvency` refused the post-state.
    Solvency,
}

#[derive(Clone, Copy, Default)]
struct Effect {
    /// Vault outflow: (account paid, amount).
    payout: Option<(Pubkey, u64)>,
    /// The account this outflow is bound to (proof, pending record, treasury).
    bound: Pubkey,
    /// Moved into `deferred_payouts`.
    parked: u64,
    /// Added to `treasury_accrued`.
    accrued: u64,
    /// Added to `total_credits` (deposit).
    credited: u64,
    /// Plain transfer into the vault token account.
    donated: u64,
    /// After a raise: (pending.conceded, evidence solvency_bound).
    conceded: Option<(u64, u128)>,
}

type Step = core::result::Result<Effect, Revert>;

/// `ensure_solvency` (lib.rs:1604-1612) against a classic-Token account at
/// the pinned address holding `balance`.
fn program_solvency_check(vault: &VaultState, account: Pubkey, balance: u64) -> bool {
    let mut data = [0u8; TOKEN_ACCOUNT_LEN];
    data[..32].copy_from_slice(vault.mint.as_ref());
    data[64..72].copy_from_slice(&balance.to_le_bytes());
    data[108] = ACCOUNT_STATE_INITIALIZED;
    let owner = TOKEN_PROGRAM_ID;
    let mut lamports = 0u64;
    let info = AccountInfo::new(&account, false, true, &mut lamports, &mut data, &owner, false, 0);
    ensure_solvency(vault, &info).is_ok()
}

fn check_solvency(w: &World) -> core::result::Result<(), Revert> {
    if program_solvency_check(&w.vault, w.vault.vault_token, w.balance) {
        Ok(())
    } else {
        Err(Revert::Solvency)
    }
}

/// Classic Token `TransferChecked` out of the vault token account.
fn pay_out(balance: &mut u64, amount: u64) -> core::result::Result<(), Revert> {
    *balance = balance.checked_sub(amount).ok_or(Revert::TokenInsufficientFunds)?;
    Ok(())
}

/// `rent_refund` (lib.rs:1363-1369) on the stored escaper's account.
fn rent_refund_for(executable: bool, writable: bool) -> Result<RentRefund> {
    let (key, owner) = (RENT_PAYER, system_program::ID);
    let mut lamports = 1u64;
    let mut data: [u8; 0] = [];
    let info = AccountInfo::new(&key, false, writable, &mut lamports, &mut data, &owner, executable, 0);
    rent_refund(&info)
}

/// `settle_pending_rent` (lib.rs:1371-1382): `Refund` closes the record,
/// `Park` moves it to stage 2.
fn settle_rent(pending: &mut Option<PendingWithdrawal>) -> core::result::Result<(), Revert> {
    match rent_refund_for(kani::any(), kani::any()).map_err(|_| Revert::Program)? {
        RentRefund::Refund => *pending = None,
        RentRefund::Park => {
            if let Some(record) = pending.as_mut() {
                record.stage = PENDING_STAGE_RENT_PARKED;
            }
        }
    }
    Ok(())
}

/// Amount checks of `validate_withdrawal` (lib.rs:1319, 1323-1328) on the
/// proof's public `final_balance` and `conceded`.
fn withdrawal_amounts(note: &NoteState) -> core::result::Result<(u128, u128), Revert> {
    if note.status != NOTE_STATUS_ACTIVE {
        return Err(Revert::Program);
    }
    let final_balance: u128 = kani::any();
    let conceded: u128 = kani::any();
    let state_balance = final_balance.checked_add(conceded).ok_or(Revert::Program)?;
    if state_balance > u128::from(note.deposit_amount) {
        return Err(Revert::Program);
    }
    Ok((final_balance, conceded))
}

/// One instruction (or donation) against the tracked note. On `Err` the
/// transaction aborts and the caller discards the mutated copy.
fn step(w: &mut World, op: u8) -> Step {
    let now: u64 = kani::any();
    let mut fx = Effect::default();
    match op {
        // execute_deposit, lib.rs:177-259.
        DEPOSIT | DEPOSIT_OTHER => {
            if op == DEPOSIT && w.note.status != 0 {
                return Err(Revert::Program); // `init` of the note PDA
            }
            if w.vault.paused {
                return Err(Revert::Program); // 184
            }
            let amount: u64 = kani::any();
            if !(amount > 0 && amount <= MAX_CREDIT_UNITS) {
                return Err(Revert::Program); // 189-192
            }
            let before = w.balance; // 215
            let after: u64 = kani::any(); // whatever the Token CPI left (216-225)
            if after.checked_sub(before) != Some(amount) {
                return Err(Revert::Program); // 226-229
            }
            w.balance = after;
            w.vault.total_credits =
                w.vault.total_credits.checked_add(amount).ok_or(Revert::Math)?; // 230-233
            if op == DEPOSIT {
                let expiry: u64 = kani::any();
                w.note.deposit_amount = amount; // 244
                w.note.expiry = expiry;
                w.note.status = NOTE_STATUS_ACTIVE;
                w.note.claimable_after = expiry;
                w.note.paused_offset =
                    paused_duration_now(&w.vault, now).map_err(|_| Revert::Program)?; // 249
            } else {
                w.rest_credits = w.rest_credits.wrapping_add(amount);
            }
            check_solvency(w)?; // 250
            fx.credited = amount;
        }
        // Anyone's plain Token transfer into the vault token account.
        DONATE => {
            let gift: u64 = kani::any();
            w.balance = w.balance.checked_add(gift).ok_or(Revert::TokenOverflow)?;
            fx.donated = gift;
        }
        // execute_close, lib.rs:263-296.
        CLOSE => {
            let (final_balance, conceded) = withdrawal_amounts(&w.note)?;
            if conceded != 0 {
                return Err(Revert::Program); // 1331 clearance mode
            }
            let destination = any_key(); // the proof-bound destination_token
            let deposit = w.note.deposit_amount; // 280
            let final_balance = u64::try_from(final_balance).map_err(|_| Revert::Math)?; // 281
            w.note.status = NOTE_STATUS_CLOSED; // 282
            let treasury = w.vault.treasury_accrued;
            close_note_liability(&mut w.vault, deposit, final_balance)
                .map_err(|_| Revert::Math)?; // 284
            fx.accrued = w.vault.treasury_accrued - treasury;
            fx.bound = destination;
            if final_balance > 0 {
                let target = any_view(destination).ok_or(Revert::Program)?; // 286
                if !payout_target_ok(&w.vault, &destination, &target) {
                    return Err(Revert::Program); // 287-288
                }
                pay_out(&mut w.balance, final_balance)?; // 289-290
                fx.payout = Some((target.key, final_balance));
            }
            check_solvency(w)?; // 292
        }
        // execute_escape, lib.rs:298-344.
        ESCAPE => {
            if w.pending.is_some() {
                return Err(Revert::Program); // `init` of the pending PDA
            }
            let (final_balance, conceded) = withdrawal_amounts(&w.note)?;
            let destination = any_key();
            let target = any_view(destination).ok_or(Revert::Program)?; // 309
            if !payout_target_ok(&w.vault, &destination, &target) {
                return Err(Revert::Program); // 310-311
            }
            w.note.status = NOTE_STATUS_PENDING; // 324
            let final_balance = u64::try_from(final_balance).map_err(|_| Revert::Math)?; // 330
            let conceded = u64::try_from(conceded).map_err(|_| Revert::Math)?; // 331
            let state_balance = final_balance.checked_add(conceded).ok_or(Revert::Math)?; // 332
            let deadline = now.checked_add(w.vault.challenge_period).ok_or(Revert::Program)?; // 337
            w.pending = Some(PendingWithdrawal {
                vault: VAULT_STATE,
                note_id: w.note.note_id,
                nullifier: NULLIFIER,
                next_nullifier: SUCCESSOR,
                state_balance,
                conceded,
                final_balance,
                destination,
                deadline,
                bump: 255,
                rent_payer: RENT_PAYER,
                stage: PENDING_STAGE_OPEN,
            });
        }
        // execute_challenge, lib.rs:346-358; the pending record closes to the
        // challenger (`close = payer`, 820).
        CHALLENGE => {
            let pending = w.pending.as_ref().ok_or(Revert::Program)?;
            let payload = evidence(&w.vault, pending.next_nullifier, kani::any());
            apply_escape_challenge(&w.vault, &mut w.note, pending, &payload, NOTE_ID, now)
                .map_err(|_| Revert::Program)?;
            w.pending = None;
        }
        // raise_escape_concession, lib.rs:360-371.
        RAISE => {
            let bound: u128 = kani::any();
            let amount: u128 = kani::any();
            let pending = w.pending.as_mut().ok_or(Revert::Program)?;
            let payload = evidence(&w.vault, pending.nullifier, bound);
            apply_raise_concession(&w.vault, &w.note, pending, &payload, NOTE_ID, amount, now)
                .map_err(|_| Revert::Program)?;
            fx.conceded = Some((pending.conceded, bound));
        }
        // finalize_escape, lib.rs:394-425.
        FINALIZE => {
            let pending = w.pending.clone().ok_or(Revert::Program)?;
            validate_finalize(&w.note, &pending, NOTE_ID, now).map_err(|_| Revert::Program)?; // 395
            let deposit = w.note.deposit_amount; // 396
            let final_balance = pending.final_balance; // 397
            let destination = pending.destination; // 398
            w.note.status = NOTE_STATUS_CLOSED; // 399
            let treasury = w.vault.treasury_accrued;
            close_note_liability(&mut w.vault, deposit, final_balance)
                .map_err(|_| Revert::Math)?; // 401
            fx.accrued = w.vault.treasury_accrued - treasury;
            fx.bound = destination;
            let account = any_key(); // destination_token as passed
            let view = any_view(account);
            let creditable = final_balance == 0
                || view.is_some_and(|target| payout_target_ok(&w.vault, &destination, &target)); // 402-404
            if creditable {
                if final_balance > 0 {
                    pay_out(&mut w.balance, final_balance)?; // 407-408
                    fx.payout = Some((account, final_balance));
                }
                settle_rent(&mut w.pending)?; // 410
            } else {
                w.vault.deferred_payouts =
                    w.vault.deferred_payouts.checked_add(final_balance).ok_or(Revert::Math)?; // 412
                if let Some(record) = w.pending.as_mut() {
                    record.stage = PENDING_STAGE_PAYOUT_PARKED; // 414
                }
                fx.parked = final_balance;
            }
            check_solvency(w)?; // 416
        }
        // release_escape_payout, lib.rs:430-447.
        RELEASE => {
            let pending = w.pending.clone().ok_or(Revert::Program)?;
            validate_release(&w.note, &pending, NOTE_ID).map_err(|_| Revert::Program)?; // 431
            let amount = pending.final_balance; // 433
            let destination = pending.destination; // 434
            let account = any_key(); // destination_token as passed
            let target = any_view(account).ok_or(Revert::Program)?; // 436
            if !payout_target_ok(&w.vault, &destination, &target) {
                return Err(Revert::Program); // 437-438
            }
            w.vault.deferred_payouts =
                w.vault.deferred_payouts.checked_sub(amount).ok_or(Revert::Math)?; // 439-440
            pay_out(&mut w.balance, amount)?; // 441-442
            fx.payout = Some((account, amount));
            fx.bound = destination;
            settle_rent(&mut w.pending)?; // 443
            check_solvency(w)?; // 444
        }
        // refund_pending_rent, lib.rs:452-457 (the vault account is read-only).
        REFUND_RENT => {
            let pending = w.pending.as_ref().ok_or(Revert::Program)?;
            validate_rent_refund(&w.note, pending, NOTE_ID).map_err(|_| Revert::Program)?;
            let refund = rent_refund_for(kani::any(), kani::any()).map_err(|_| Revert::Program)?;
            if refund != RentRefund::Refund {
                return Err(Revert::Program);
            }
            w.pending = None;
        }
        // execute_claim_expired, lib.rs:459-472.
        CLAIM_EXPIRED => {
            validate_expired_claim(&w.vault, &w.note, NOTE_ID, now).map_err(|_| Revert::Program)?;
            let amount = w.note.deposit_amount; // 461
            w.note.status = NOTE_STATUS_CLOSED; // 463
            let treasury = w.vault.treasury_accrued;
            close_note_liability(&mut w.vault, amount, 0).map_err(|_| Revert::Math)?; // 464
            fx.accrued = w.vault.treasury_accrued - treasury;
            check_solvency(w)?; // 465
        }
        // retire_closed_leaf, lib.rs:373-387 (Merkle proof dropped).
        RETIRE => {
            if w.note.status != NOTE_STATUS_CLOSED {
                return Err(Revert::Program);
            }
            w.note.status = NOTE_STATUS_RETIRED;
        }
        // withdraw_treasury, lib.rs:477-491 (`has_one` dropped).
        WITHDRAW_TREASURY => {
            let amount = w.vault.treasury_accrued; // 479
            let treasury = w.vault.treasury_token; // 480
            let account = any_key();
            let target = any_view(account).ok_or(Revert::Program)?; // 481
            if !payout_target_ok(&w.vault, &treasury, &target) {
                return Err(Revert::Program); // 482
            }
            w.vault.treasury_accrued = 0; // 483
            fx.bound = treasury;
            if amount > 0 {
                pay_out(&mut w.balance, amount)?; // 484-486
                fx.payout = Some((account, amount));
            }
            check_solvency(w)?; // 488
        }
        // set_paused, lib.rs:97-99.
        SET_PAUSED => {
            update_pause(&mut w.vault, kani::any(), now).map_err(|_| Revert::Program)?;
        }
        _ => return Err(Revert::Program),
    }
    Ok(fx)
}

fn liabilities(vault: &VaultState) -> u128 {
    u128::from(vault.total_credits)
        + u128::from(vault.treasury_accrued)
        + u128::from(vault.deferred_payouts)
}

fn solvent(w: &World) -> bool {
    u128::from(w.balance) >= liabilities(&w.vault)
}

fn surplus(w: &World) -> u128 {
    u128::from(w.balance) - liabilities(&w.vault)
}

fn stage(pending: &Option<PendingWithdrawal>) -> Option<u8> {
    pending.as_ref().map(|record| record.stage)
}

fn closed(status: u8) -> bool {
    status == NOTE_STATUS_CLOSED || status == NOTE_STATUS_RETIRED
}

/// The tracked note's share of `total_credits`.
fn note_credits(note: &NoteState) -> u128 {
    if note.status == NOTE_STATUS_ACTIVE || note.status == NOTE_STATUS_PENDING {
        u128::from(note.deposit_amount)
    } else {
        0
    }
}

/// The tracked note's share of `deferred_payouts`.
fn note_parked(pending: &Option<PendingWithdrawal>) -> u128 {
    match pending {
        Some(record) if record.stage == PENDING_STAGE_PAYOUT_PARKED => u128::from(record.final_balance),
        _ => 0,
    }
}

/// Per-note shape: status 0 = note PDA absent.
fn note_ok(w: &World) -> bool {
    let status = w.note.status;
    let known = matches!(status, 0 | NOTE_STATUS_ACTIVE | NOTE_STATUS_PENDING)
        || closed(status);
    let shape = match &w.pending {
        None => status != NOTE_STATUS_PENDING,
        Some(record) => {
            (record.stage == PENDING_STAGE_OPEN
                && status == NOTE_STATUS_PENDING
                && record.final_balance.checked_add(record.conceded) == Some(record.state_balance)
                && record.state_balance <= w.note.deposit_amount)
                || ((record.stage == PENDING_STAGE_PAYOUT_PARKED
                    || record.stage == PENDING_STAGE_RENT_PARKED)
                    && closed(status))
        }
    };
    let absent = status != 0 || (w.pending.is_none() && w.note.deposit_amount == 0 && !w.paid);
    let paid = !w.paid || (closed(status) && stage(&w.pending).map_or(true, |s| s == PENDING_STAGE_RENT_PARKED));
    known && shape && absent && paid
}

/// The vault invariant: the books equal the sum of the notes' shares, and the
/// vault token balance covers them.
fn invariant(w: &World) -> bool {
    note_ok(w)
        && u128::from(w.vault.total_credits) == u128::from(w.rest_credits) + note_credits(&w.note)
        && u128::from(w.vault.deferred_payouts)
            == u128::from(w.rest_deferred) + note_parked(&w.pending)
        && solvent(w)
}

/// Pending-record transitions an instruction may make.
fn transition_allowed(op: u8, before: Option<u8>, after: Option<u8>) -> bool {
    match (before, after) {
        (b, a) if b == a => true,
        (None, Some(PENDING_STAGE_OPEN)) => op == ESCAPE,
        (Some(PENDING_STAGE_OPEN), None) => op == CHALLENGE || op == FINALIZE,
        (Some(PENDING_STAGE_OPEN), Some(PENDING_STAGE_PAYOUT_PARKED | PENDING_STAGE_RENT_PARKED)) => {
            op == FINALIZE
        }
        (Some(PENDING_STAGE_PAYOUT_PARKED), None | Some(PENDING_STAGE_RENT_PARKED)) => op == RELEASE,
        (Some(PENDING_STAGE_RENT_PARKED), None) => op == REFUND_RENT,
        _ => false,
    }
}

/// Properties of one successful step from an arbitrary solvent state.
fn check_solvent_step(before: &World, after: &World, fx: &Effect) {
    let paid = fx.payout.map_or(0, |(_, amount)| amount);
    assert!(solvent(after), "solvency");
    assert!(
        liabilities(&after.vault) + u128::from(paid) == liabilities(&before.vault) + u128::from(fx.credited),
        "liabilities move by exactly the USDC moved"
    );
    assert!(surplus(after) == surplus(before) + u128::from(fx.donated), "surplus is donations only");
    if let Some((account, _)) = fx.payout {
        assert!(account == fx.bound, "paid only to the bound account");
        assert!(account != after.vault.vault_token, "never to the vault itself");
    }
}

/// Properties of one successful step from a state satisfying `invariant`.
fn check_invariant_step(op: u8, before: &World, after: &mut World, fx: &Effect) {
    check_solvent_step(before, after, fx);
    let user_payout = fx.payout.is_some() && matches!(op, CLOSE | FINALIZE | RELEASE);
    if user_payout {
        assert!(!before.paid, "a note is paid at most once");
        after.paid = true;
    }
    assert!(invariant(after), "invariant");
    let (stage_before, stage_after) = (stage(&before.pending), stage(&after.pending));
    assert!(transition_allowed(op, stage_before, stage_after), "stage transition");
    if let (Some(old), Some(new)) = (&before.pending, &after.pending) {
        assert!(old.destination == new.destination && old.deadline == new.deadline);
        if old.stage != PENDING_STAGE_OPEN {
            assert!(old.final_balance == new.final_balance, "a parked payout is frozen");
        }
    }
    let paid = fx.payout.map_or(0, |(_, amount)| amount);
    let deposit = u128::from(before.note.deposit_amount);
    match op {
        CLOSE => {
            assert!(u128::from(paid) + u128::from(fx.accrued) == deposit, "close splits the deposit");
        }
        FINALIZE => {
            assert!(paid == 0 || fx.parked == 0);
            assert!(
                u128::from(paid) + u128::from(fx.parked) + u128::from(fx.accrued) == deposit,
                "finalize splits the deposit"
            );
            assert!(u128::from(paid.max(fx.parked)) <= deposit);
        }
        RELEASE => {
            assert!(stage_before == Some(PENDING_STAGE_PAYOUT_PARKED));
            let record = before.pending.as_ref().unwrap();
            assert!(fx.payout == Some((record.destination, record.final_balance)), "release pays the parked amount to the bound account");
        }
        CLAIM_EXPIRED => assert!(paid == 0 && u128::from(fx.accrued) == deposit),
        RAISE => {
            let (conceded, bound) = fx.conceded.unwrap();
            let record = after.pending.as_ref().unwrap();
            assert!(u128::from(conceded) <= bound, "concession within the solvency bound");
            assert!(conceded <= record.state_balance && record.final_balance <= before.note.deposit_amount);
        }
        _ => {}
    }
}

fn any_world() -> World {
    World {
        vault: any_vault(),
        balance: kani::any(),
        note: any_note(),
        pending: any_pending(),
        rest_credits: kani::any(),
        rest_deferred: kani::any(),
        paid: kani::any(),
    }
}

/// One instruction from any solvent state (no other assumption on the note,
/// the pending record or the buckets).
fn solvent_step(op: u8) {
    let mut w = any_world();
    kani::assume(solvent(&w));
    let before = w.clone();
    match step(&mut w, op) {
        Ok(fx) => {
            check_solvent_step(&before, &w, &fx);
            if matches!(op, CLOSE | FINALIZE | RELEASE | WITHDRAW_TREASURY) {
                kani::cover!(fx.payout.is_some(), "a payout succeeds");
            }
            kani::cover!(true, "the instruction succeeds");
        }
        Err(revert) => {
            assert!(revert != Revert::TokenInsufficientFunds, "the vault always holds the payout");
            assert!(revert != Revert::Solvency, "ensure_solvency never has to reject");
        }
    }
}

// ---- 1. Solvency per instruction ------------------------------------------

harness! {
    fn solvency_deposit() {
        solvent_step(DEPOSIT);
    }
}

harness! {
    fn solvency_donation_only_adds_surplus() {
        solvent_step(DONATE);
    }
}

harness! {
    fn solvency_close() {
        solvent_step(CLOSE);
    }
}

harness! {
    fn solvency_escape() {
        solvent_step(ESCAPE);
    }
}

harness! {
    fn solvency_challenge() {
        solvent_step(CHALLENGE);
    }
}

harness! {
    fn solvency_raise_concession() {
        solvent_step(RAISE);
    }
}

harness! {
    fn solvency_finalize_paid_or_parked() {
        let mut w = any_world();
        kani::assume(solvent(&w));
        let before = w.clone();
        match step(&mut w, FINALIZE) {
            Ok(fx) => {
                check_solvent_step(&before, &w, &fx);
                assert!(
                    u128::from(fx.parked) + u128::from(fx.payout.map_or(0, |(_, amount)| amount))
                        + u128::from(fx.accrued)
                        == u128::from(before.note.deposit_amount)
                );
                kani::cover!(fx.parked > 0, "payout parked");
                kani::cover!(fx.payout.is_some(), "payout paid");
            }
            Err(revert) => {
                assert!(revert != Revert::TokenInsufficientFunds);
                assert!(revert != Revert::Solvency);
            }
        }
    }
}

harness! {
    fn solvency_release_escape_payout() {
        solvent_step(RELEASE);
    }
}

harness! {
    fn solvency_refund_pending_rent() {
        solvent_step(REFUND_RENT);
    }
}

harness! {
    fn solvency_claim_expired() {
        solvent_step(CLAIM_EXPIRED);
    }
}

harness! {
    fn solvency_withdraw_treasury() {
        solvent_step(WITHDRAW_TREASURY);
    }
}

harness! {
    fn solvency_retire_closed_leaf() {
        solvent_step(RETIRE);
    }
}

harness! {
    fn solvency_set_paused() {
        solvent_step(SET_PAUSED);
    }
}

harness! {
    /// `ensure_solvency` accepts exactly the solvent states, including when the
    /// liability sum overflows u64, and only for the pinned vault token account.
    fn ensure_solvency_is_exactly_the_invariant() {
        let vault = any_vault();
        let balance: u64 = kani::any();
        let w = World {
            vault: vault.clone(),
            balance,
            note: any_note(),
            pending: None,
            rest_credits: 0,
            rest_deferred: 0,
            paid: false,
        };
        assert!(program_solvency_check(&vault, VAULT_TOKEN, balance) == solvent(&w));
        let other = any_key();
        kani::assume(other != VAULT_TOKEN);
        assert!(!program_solvency_check(&vault, other, balance));
    }
}

// ---- 2. Arithmetic ----------------------------------------------------------

harness! {
    /// `close_note_liability` is total (never panics) and exact: it succeeds iff
    /// the payout fits the deposit, the deposit is still credited, and the
    /// treasury does not overflow; then liabilities fall by exactly the payout.
    fn close_note_liability_is_checked_and_exact() {
        let mut vault = any_vault();
        let before = vault.clone();
        let (deposit, final_balance): (u64, u64) = (kani::any(), kani::any());
        let ok = close_note_liability(&mut vault, deposit, final_balance).is_ok();
        let fits = final_balance <= deposit
            && deposit <= before.total_credits
            && u128::from(before.treasury_accrued) + u128::from(deposit - final_balance.min(deposit))
                <= u128::from(u64::MAX);
        assert!(ok == fits);
        if ok {
            assert!(vault.total_credits == before.total_credits - deposit);
            assert!(vault.treasury_accrued == before.treasury_accrued + (deposit - final_balance));
            assert!(vault.deferred_payouts == before.deferred_payouts);
            assert!(liabilities(&vault) + u128::from(final_balance) == liabilities(&before));
        }
    }
}

harness! {
    fn required_vault_tokens_is_the_exact_sum() {
        let vault = any_vault();
        match required_vault_tokens(&vault) {
            Ok(sum) => assert!(u128::from(sum) == liabilities(&vault)),
            Err(_) => assert!(liabilities(&vault) > u128::from(u64::MAX)),
        }
    }
}

// ---- 3. Payout bounds ---------------------------------------------------------

harness! {
    /// `apply_raise_concession` never panics (its unchecked `-` and `as u64`)
    /// for any pending record, and a successful raise stays within the solvency
    /// bound and the state balance, strictly increases the concession and keeps
    /// `final_balance + conceded == state_balance`.
    fn raise_concession_is_bounded() {
        let vault = any_vault();
        let note = any_note();
        let mut pending = PendingWithdrawal {
            vault: VAULT_STATE,
            note_id: NOTE_ID,
            nullifier: NULLIFIER,
            next_nullifier: SUCCESSOR,
            state_balance: kani::any(),
            conceded: kani::any(),
            final_balance: kani::any(),
            destination: any_key(),
            deadline: kani::any(),
            bump: 255,
            rent_payer: RENT_PAYER,
            stage: kani::any(),
        };
        let before = pending.clone();
        let bound: u128 = kani::any();
        let amount: u128 = kani::any();
        let now: u64 = kani::any();
        let payload = evidence(&vault, pending.nullifier, bound);
        let ok = apply_raise_concession(&vault, &note, &mut pending, &payload, NOTE_ID, amount, now).is_ok();
        if ok {
            assert!(u128::from(pending.conceded) <= bound);
            assert!(u128::from(pending.conceded) <= amount);
            // The `conceded as u64` cast (lib.rs:1420) is lossless.
            assert!(
                u128::from(pending.conceded)
                    == amount.min(bound).min(u128::from(before.state_balance))
            );
            assert!(pending.conceded <= pending.state_balance);
            assert!(pending.conceded > before.conceded);
            assert!(pending.final_balance + pending.conceded == pending.state_balance);
            assert!(pending.state_balance == before.state_balance);
            assert!(pending.destination == before.destination && pending.deadline == before.deadline);
            assert!(pending.stage == before.stage);
            if before.final_balance.checked_add(before.conceded) == Some(before.state_balance)
                && before.state_balance <= note.deposit_amount
            {
                assert!(pending.final_balance < before.final_balance);
                assert!(pending.final_balance <= note.deposit_amount);
            }
        } else {
            assert!(pending.conceded == before.conceded && pending.final_balance == before.final_balance);
        }
        kani::cover!(ok, "a raise succeeds");
    }
}

// ---- 1-4. Inductive invariant, one harness per instruction ------------------
//
// Together these prove: from any state satisfying `invariant` (any number of
// other notes, folded into `rest_*`), every instruction keeps it, moves the
// books by exactly the USDC moved, pays only the bound account and at most
// once per note, and makes only the allowed pending-stage transitions; checked
// math, Token outflows and `ensure_solvency` never fail from such a state.
// (One harness per op: a symbolic op makes CBMC execute every arm at once.)

fn invariant_step(op: u8) {
    let mut w = any_world();
    kani::assume(invariant(&w));
    let before = w.clone();
    match step(&mut w, op) {
        Ok(fx) => {
            check_invariant_step(op, &before, &mut w, &fx);
            kani::cover!(true, "the instruction succeeds");
        }
        Err(revert) => {
            assert!(revert != Revert::Math, "checked math never fails on reachable books");
            assert!(revert != Revert::TokenInsufficientFunds);
            assert!(revert != Revert::Solvency);
        }
    }
}

harness! {
    fn invariant_deposit() {
        invariant_step(DEPOSIT);
    }
}

harness! {
    fn invariant_deposit_other_note() {
        invariant_step(DEPOSIT_OTHER);
    }
}

harness! {
    fn invariant_donation() {
        invariant_step(DONATE);
    }
}

harness! {
    fn invariant_close() {
        invariant_step(CLOSE);
    }
}

harness! {
    fn invariant_escape() {
        invariant_step(ESCAPE);
    }
}

harness! {
    fn invariant_challenge() {
        invariant_step(CHALLENGE);
    }
}

harness! {
    fn invariant_raise_concession() {
        invariant_step(RAISE);
    }
}

harness! {
    fn invariant_finalize() {
        invariant_step(FINALIZE);
    }
}

harness! {
    fn invariant_release_escape_payout() {
        invariant_step(RELEASE);
    }
}

harness! {
    fn invariant_refund_pending_rent() {
        invariant_step(REFUND_RENT);
    }
}

harness! {
    fn invariant_claim_expired() {
        invariant_step(CLAIM_EXPIRED);
    }
}

harness! {
    fn invariant_retire_closed_leaf() {
        invariant_step(RETIRE);
    }
}

harness! {
    fn invariant_withdraw_treasury() {
        invariant_step(WITHDRAW_TREASURY);
    }
}

harness! {
    fn invariant_set_paused() {
        invariant_step(SET_PAUSED);
    }
}

// ---- Base case and reachability: runs from a freshly initialized vault -------

/// Runs `ops` in order from a freshly initialized vault (empty books, any
/// pre-funded balance); an aborted transaction leaves the state as it was.
/// Returns the final state and a bitmask of the steps that succeeded.
fn genesis_run(ops: &[u8]) -> (World, u32) {
    let mut vault = any_vault();
    vault.total_credits = 0;
    vault.treasury_accrued = 0;
    vault.deferred_payouts = 0;
    let mut note = any_note();
    note.status = 0;
    note.deposit_amount = 0;
    let mut w = World {
        vault,
        balance: kani::any(),
        note,
        pending: None,
        rest_credits: 0,
        rest_deferred: 0,
        paid: false,
    };
    assert!(invariant(&w), "the invariant holds at genesis");
    let mut done = 0u32;
    for (index, &op) in ops.iter().enumerate() {
        let before = w.clone();
        match step(&mut w, op) {
            Ok(fx) => {
                check_invariant_step(op, &before, &mut w, &fx);
                done |= 1 << index;
            }
            Err(_) => w = before,
        }
    }
    (w, done)
}

harness! {
    /// Deposit, escape, parked finalize, release, rent refund.
    fn genesis_parked_payout_lifecycle() {
        let (w, done) = genesis_run(&[DEPOSIT, ESCAPE, FINALIZE, RELEASE, REFUND_RENT]);
        kani::cover!(done == 0b00111 && w.vault.deferred_payouts > 0, "payout parked");
        kani::cover!(done == 0b01111 && w.pending.is_none() && w.paid, "released, rent refunded");
        kani::cover!(done == 0b11111 && w.paid, "released with rent parked, then refunded");
    }
}

harness! {
    /// Deposit, escape, raised concession, defeat by challenge, mutual close,
    /// leaf retirement.
    fn genesis_concession_challenge_close() {
        let (w, done) = genesis_run(&[DEPOSIT, ESCAPE, RAISE, CHALLENGE, CLOSE, RETIRE]);
        kani::cover!(done == 0b111111 && w.paid, "every step succeeds");
    }
}

harness! {
    /// Another note's deposit, a deposit, a donation, an expiry claim and a
    /// treasury withdrawal.
    fn genesis_expiry_and_treasury() {
        let (w, done) =
            genesis_run(&[DEPOSIT_OTHER, DEPOSIT, DONATE, CLAIM_EXPIRED, WITHDRAW_TREASURY]);
        kani::cover!(
            done == 0b11111 && w.vault.treasury_accrued == 0 && w.vault.total_credits > 0,
            "every step succeeds"
        );
    }
}
