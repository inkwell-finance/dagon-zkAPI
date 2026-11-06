//! Exit decisions of the concession exit (C4, E0–E6) as pure functions of
//! local facts.
//!
//! Nothing here reads the network or the clock: callers pass `now`, the
//! server's readings and chain facts in, so the native wallet and the browser
//! SDK decide identically on the same inputs.

use serde::{Deserialize, Serialize};

/// E0: `must_initiate_by = expiry − 43,200`.
pub const INITIATE_MARGIN_SECONDS: u64 = 43_200;
/// E2: within this long of `must_initiate_by` a fresh state escapes with
/// nothing conceded instead of asking for a clearance.
pub const MUTUAL_CUTOFF_SECONDS: u64 = 3_600;
/// E3: the slack after a request's settlement deadline before escaping.
pub const SETTLEMENT_GRACE_SECONDS: u64 = 900;
/// C4: `now + W + 900 + 3,600 > must_initiate_by` refuses new requests.
pub const NEAR_EXPIRY_MARGIN_SECONDS: u64 = 900 + 3_600;
/// A record whose latest server reading is `unknown` is resolved once that
/// reading was taken this long after the request's `request_time`: the
/// server rejects a stale `request_time`, so it can no longer reserve it.
pub const UNKNOWN_READING_RESOLVES_AFTER_SECONDS: u64 = 1_200;
/// E3's `unsettled_request_escape_after_seconds` knob: default and clamp.
pub const DEFAULT_UNSETTLED_ESCAPE_AFTER_SECONDS: u64 = 43_200;
pub const MIN_UNSETTLED_ESCAPE_AFTER_SECONDS: u64 = 3_600;
pub const MAX_UNSETTLED_ESCAPE_AFTER_SECONDS: u64 = 604_800;
/// E4: an exit proof's `valid_until` is `now + VALIDITY` (`valid_until`
/// stops an abandoned exit proof from landing later).
pub const EXIT_PROOF_VALIDITY_SECONDS: u64 = 10_800;
/// E6: a released exit proof is dead once a finalized block's timestamp is
/// past its `valid_until` by more than this.
pub const LOCK_RELEASE_MARGIN_SECONDS: u64 = 900;

/// Dispositions of a request released at a state.
pub mod disposition {
    /// Transmitted (or about to be); no successor installed yet.
    pub const PENDING: &str = "pending";
    /// The server refused it before reserving its nullifier.
    pub const DISCARDED_STALE_ROOT: &str = "discarded_stale_root";
    /// A correctly signed successor failed S3, S4 or S5: handled exactly like
    /// a withheld successor.
    pub const INVALID_SUCCESSOR: &str = "invalid_successor";
}

/// E0: the latest second at which an exit decision may start. The note's
/// local `expiry_ts` is a lower bound of the vault's claimable time (a pause
/// or a defeat grace only raises it), so this is never too late.
pub fn must_initiate_by(expiry_ts: u64) -> u64 {
    expiry_ts.saturating_sub(INITIATE_MARGIN_SECONDS)
}

/// C4: whether a new request must be refused because the note is too close
/// to expiry for its settlement to finish before an exit must start.
/// `settlement_window` is the deployment's `settlement_window_seconds` (W).
pub fn note_near_expiry(now: u64, settlement_window: u64, must_initiate_by: u64) -> bool {
    now.saturating_add(settlement_window)
        .saturating_add(NEAR_EXPIRY_MARGIN_SECONDS)
        > must_initiate_by
}

/// E3's knob, clamped to 3,600–604,800 seconds; `None` is the default.
pub fn unsettled_escape_after(configured: Option<u64>) -> u64 {
    configured
        .unwrap_or(DEFAULT_UNSETTLED_ESCAPE_AFTER_SECONDS)
        .clamp(
            MIN_UNSETTLED_ESCAPE_AFTER_SECONDS,
            MAX_UNSETTLED_ESCAPE_AFTER_SECONDS,
        )
}

/// The server's `nullifier_status` for a request's nullifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerReading {
    Unknown,
    Reserved,
    Finalized,
    ClearanceReserved,
    ExitDeferred,
    ExitedUnsigned,
    /// The server could not be asked (timeout, 5xx, 429, invalid answer).
    Unavailable,
}

impl ServerReading {
    /// Map a `RecoveryResponseV2.nullifier_status`. Anything unrecognised is
    /// `Unavailable`, which never resolves a record.
    pub fn from_nullifier_status(status: &str) -> Self {
        match status {
            "unknown" => Self::Unknown,
            "reserved" => Self::Reserved,
            "finalized" => Self::Finalized,
            "clearance_reserved" => Self::ClearanceReserved,
            "exit_deferred" => Self::ExitDeferred,
            "exited_unsigned" => Self::ExitedUnsigned,
            _ => Self::Unavailable,
        }
    }
}

/// One server reading and the second it was taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reading {
    pub status: ServerReading,
    pub observed_at: u64,
}

/// A request released (transmitted, or possibly transmitted) at the state
/// being exited.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleasedRecord {
    pub client_request_id: String,
    /// The record's latest disposition ([`disposition`]).
    pub disposition: String,
    /// The request's public `request_time` (seconds).
    pub request_time: u64,
    /// When the record was created (seconds).
    pub created_at: u64,
    /// The latest server reading of the request's nullifier, if any.
    #[serde(default)]
    pub reading: Option<Reading>,
}

/// Record classes of E1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordClass {
    /// The server cannot have reserved it, or can no longer.
    ResolvedUnreserved,
    /// The server may hold a reservation for it.
    Unresolved,
}

/// Classify one released record. An `invalid_successor` record is
/// unresolved: the server reserved and finalized that request, and its
/// successor is treated as withheld (E3).
pub fn classify(record: &ReleasedRecord) -> RecordClass {
    if record.disposition == disposition::DISCARDED_STALE_ROOT {
        return RecordClass::ResolvedUnreserved;
    }
    if record.disposition == disposition::INVALID_SUCCESSOR {
        return RecordClass::Unresolved;
    }
    match record.reading {
        Some(Reading {
            status: ServerReading::Unknown,
            observed_at,
        }) if observed_at
            >= record
                .request_time
                .saturating_add(UNKNOWN_READING_RESOLVES_AFTER_SECONDS) =>
        {
            RecordClass::ResolvedUnreserved
        }
        Some(Reading {
            status: ServerReading::ClearanceReserved,
            ..
        }) => RecordClass::ResolvedUnreserved,
        _ => RecordClass::Unresolved,
    }
}

/// E2's fresh state: nothing was released (`bound_at_state == 0`), or every
/// released record is resolved and unreserved.
pub fn state_is_fresh(bound_at_state: u128, records: &[ReleasedRecord]) -> bool {
    bound_at_state == 0
        || records
            .iter()
            .all(|record| classify(record) == RecordClass::ResolvedUnreserved)
}

/// How an attempted mutual close ended when it did not produce a close.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutualOutcome {
    /// The clearance answer was `nullifier_used`: the server claims a
    /// reservation at this state.
    NullifierUsed,
    /// Any other refusal, or the server was unreachable.
    RefusedOrUnreachable,
}

/// A user's explicit choice to exit before `T` (E3 "forced early exit").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EarlyExit {
    /// Concede nothing; an honest challenger raises to the actual charge.
    ConcedeNothing,
    /// Concede `bound_at_state`.
    ConcedeBound,
}

/// Everything the exit decision depends on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitFacts {
    pub now: u64,
    pub must_initiate_by: u64,
    /// W, the deployment's `settlement_window_seconds`.
    pub settlement_window: u64,
    /// E3's knob after [`unsettled_escape_after`].
    pub unsettled_escape_after: u64,
    pub bound_at_state: u128,
    /// Every request released at the state.
    pub records: Vec<ReleasedRecord>,
    /// The server's settlement deadline for the state's nullifier, if it
    /// reported one.
    #[serde(default)]
    pub settlement_deadline_reported: Option<u64>,
    /// The charge of a finalized response for this state's nullifier that
    /// passes S1, S2, S4 and S6 but cannot be installed (ε or journal lost).
    #[serde(default)]
    pub lost_epsilon_charge: Option<u128>,
    /// How an attempted mutual close ended, if one was attempted.
    #[serde(default)]
    pub mutual_outcome: Option<MutualOutcome>,
    /// The user's explicit early-exit choice, if any.
    #[serde(default)]
    pub early_exit: Option<EarlyExit>,
}

/// Why an escape concedes what it does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscapeReason {
    /// Too close to `must_initiate_by` for a clearance.
    MutualCutoff,
    /// The clearance was refused (not `nullifier_used`) or the server was
    /// unreachable.
    MutualRefused,
    /// The server finalized the state but its successor cannot be
    /// installed: concede `min(charge, bound_at_state)` at once.
    LostEpsilon,
    /// At or after `T`: concede `bound_at_state`.
    AtDeadline,
    /// The user exits before `T`.
    ForcedEarly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ExitDecision {
    /// Clearance, then a mutual close.
    Mutual,
    /// Escape with this concession.
    Escape { conceded: u128, reason: EscapeReason },
    /// Wait until `until`, then decide again.
    Wait { until: u64 },
}

/// E3's `T` for the newest released record created at `created_at`:
/// `min(min(settlement_deadline_reported, created_at + W) + 900,
///      created_at + unsettled_escape_after, must_initiate_by)`.
pub fn escape_deadline(
    created_at: u64,
    settlement_window: u64,
    settlement_deadline_reported: Option<u64>,
    unsettled_escape_after: u64,
    must_initiate_by: u64,
) -> u64 {
    let settled_by = created_at.saturating_add(settlement_window);
    let settled_by =
        settlement_deadline_reported.map_or(settled_by, |reported| reported.min(settled_by));
    settled_by
        .saturating_add(SETTLEMENT_GRACE_SECONDS)
        .min(created_at.saturating_add(unsettled_escape_after))
        .min(must_initiate_by)
}

/// E2 and E3: what to do from the newest installed state.
pub fn decide(facts: &ExitFacts) -> ExitDecision {
    let bound = facts.bound_at_state;
    let newest_release = |unresolved_only: bool| {
        facts
            .records
            .iter()
            .filter(|record| !unresolved_only || classify(record) == RecordClass::Unresolved)
            .map(|record| record.created_at)
            .max()
    };
    let wait_or_escape = |created_at: u64| -> ExitDecision {
        let deadline = escape_deadline(
            created_at,
            facts.settlement_window,
            facts.settlement_deadline_reported,
            facts.unsettled_escape_after,
            facts.must_initiate_by,
        );
        if facts.now >= deadline {
            return ExitDecision::Escape {
                conceded: bound,
                reason: EscapeReason::AtDeadline,
            };
        }
        match facts.early_exit {
            Some(EarlyExit::ConcedeNothing) => ExitDecision::Escape {
                conceded: 0,
                reason: EscapeReason::ForcedEarly,
            },
            Some(EarlyExit::ConcedeBound) => ExitDecision::Escape {
                conceded: bound,
                reason: EscapeReason::ForcedEarly,
            },
            None => ExitDecision::Wait { until: deadline },
        }
    };
    if let Some(charge) = facts.lost_epsilon_charge {
        return ExitDecision::Escape {
            conceded: charge.min(bound),
            reason: EscapeReason::LostEpsilon,
        };
    }
    if state_is_fresh(bound, &facts.records) {
        if facts.now >= facts.must_initiate_by.saturating_sub(MUTUAL_CUTOFF_SECONDS) {
            return ExitDecision::Escape {
                conceded: 0,
                reason: EscapeReason::MutualCutoff,
            };
        }
        return match facts.mutual_outcome {
            None => ExitDecision::Mutual,
            // The server claims a reservation: wait from the newest released
            // record. With no record there is nothing to wait for, and the
            // escape concedes the bound (zero when nothing left the device).
            Some(MutualOutcome::NullifierUsed) => match newest_release(false) {
                Some(created_at) => wait_or_escape(created_at),
                None => ExitDecision::Escape {
                    conceded: bound,
                    reason: EscapeReason::AtDeadline,
                },
            },
            Some(MutualOutcome::RefusedOrUnreachable) => ExitDecision::Escape {
                conceded: 0,
                reason: EscapeReason::MutualRefused,
            },
        };
    }
    // A released request is unresolved. By the write order a released
    // request always has a record, so the fallback to `now` only covers
    // inconsistent data.
    wait_or_escape(newest_release(true).unwrap_or(facts.now))
}

/// A released exit proof, as E6 sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleasedExit {
    /// 0 escape, 1 mutual close.
    pub kind: u8,
    pub valid_until: u64,
}

/// The vault's view of the note.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoteChainStatus {
    Active,
    PendingWithdrawal,
    Closed,
}

/// E6: the local second after which every released proof is dead (the
/// largest `valid_until + 900`), or `None` when none was released.
pub fn lock_dead_after(released: &[ReleasedExit]) -> Option<u64> {
    released
        .iter()
        .map(|proof| {
            proof
                .valid_until
                .saturating_add(LOCK_RELEASE_MARGIN_SECONDS)
        })
        .max()
}

/// E6: whether `exit_lock` may be released. `note` was read at a finalized
/// block whose timestamp is `finalized_block_timestamp`; `now` is this
/// device's clock.
///
/// A chain reading alone never releases a lock whose exit proof may still
/// land: the device's own clock must also be past every released proof's
/// `valid_until + 900`. A `Closed` note releases the lock.
pub fn lock_releasable(
    released: &[ReleasedExit],
    user_cancels: bool,
    note: NoteChainStatus,
    finalized_block_timestamp: Option<u64>,
    now: u64,
) -> bool {
    if note == NoteChainStatus::Closed {
        return true;
    }
    let Some(dead_after) = lock_dead_after(released) else {
        return user_cancels;
    };
    now > dead_after
        && note == NoteChainStatus::Active
        && finalized_block_timestamp.is_some_and(|timestamp| timestamp > dead_after)
}

/// E5: what a finalized escape payout shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum PayoutMatch {
    /// `paid == B − c_final`. `concession_exceeded_bound` alerts a payout
    /// below `B − bound_at_state`; the record still closes.
    Matches {
        conceded_final: u128,
        concession_exceeded_bound: bool,
    },
    Mismatch,
}

/// E5: accept a payout `paid` of an escape from a state with balance
/// `state_balance`, initiated conceding `conceded_at_init` and raised to each
/// of `raises`, iff `paid == B − c_final` with `c_final` the largest of them.
pub fn match_escape_payout(
    paid: u128,
    state_balance: u128,
    conceded_at_init: u128,
    raises: &[u128],
    bound_at_state: Option<u128>,
) -> PayoutMatch {
    let conceded_final = raises.iter().copied().fold(conceded_at_init, u128::max);
    let Some(expected) = state_balance.checked_sub(conceded_final) else {
        return PayoutMatch::Mismatch;
    };
    if paid != expected {
        return PayoutMatch::Mismatch;
    }
    PayoutMatch::Matches {
        conceded_final,
        concession_exceeded_bound: bound_at_state
            .is_some_and(|bound| paid < state_balance.saturating_sub(bound)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const W: u64 = 21_905;
    const BOUND: u128 = 500;

    fn record(disposition: &str, created_at: u64, reading: Option<(ServerReading, u64)>) -> ReleasedRecord {
        ReleasedRecord {
            client_request_id: format!("r{created_at}"),
            disposition: disposition.into(),
            request_time: created_at,
            created_at,
            reading: reading.map(|(status, observed_at)| Reading {
                status,
                observed_at,
            }),
        }
    }

    fn facts(now: u64, bound: u128, records: Vec<ReleasedRecord>) -> ExitFacts {
        ExitFacts {
            now,
            must_initiate_by: must_initiate_by(10_000_000),
            settlement_window: W,
            unsettled_escape_after: unsettled_escape_after(None),
            bound_at_state: bound,
            records,
            settlement_deadline_reported: None,
            lost_epsilon_charge: None,
            mutual_outcome: None,
            early_exit: None,
        }
    }

    #[test]
    fn a_fresh_state_closes_mutually_then_escapes_conceding_nothing() {
        let fresh = facts(1_000, 0, vec![]);
        assert_eq!(decide(&fresh), ExitDecision::Mutual);
        let refused = ExitFacts {
            mutual_outcome: Some(MutualOutcome::RefusedOrUnreachable),
            ..fresh.clone()
        };
        assert_eq!(
            decide(&refused),
            ExitDecision::Escape {
                conceded: 0,
                reason: EscapeReason::MutualRefused
            }
        );
        let late = facts(must_initiate_by(10_000_000) - 3_600, 0, vec![]);
        assert_eq!(
            decide(&late),
            ExitDecision::Escape {
                conceded: 0,
                reason: EscapeReason::MutualCutoff
            }
        );
        // A discarded (never reserved) request leaves the state fresh.
        let discarded = facts(
            1_000,
            BOUND,
            vec![record(disposition::DISCARDED_STALE_ROOT, 900, None)],
        );
        assert_eq!(decide(&discarded), ExitDecision::Mutual);
    }

    /// Threat: withholding operator. With a request in flight the client
    /// waits for settlement, then escapes conceding exactly `b_k`.
    #[test]
    fn a_request_in_flight_waits_then_concedes_the_bound() {
        let created = 100_000;
        let records = vec![record(disposition::PENDING, created, Some((ServerReading::Reserved, created + 10)))];
        let t = created + W + SETTLEMENT_GRACE_SECONDS;
        assert_eq!(
            decide(&facts(created + 60, BOUND, records.clone())),
            ExitDecision::Wait { until: t }
        );
        assert_eq!(
            decide(&facts(t, BOUND, records.clone())),
            ExitDecision::Escape {
                conceded: BOUND,
                reason: EscapeReason::AtDeadline
            }
        );
        // A signed but invalid successor is withheld: same rule.
        let invalid = vec![record(disposition::INVALID_SUCCESSOR, created, None)];
        assert_eq!(
            decide(&facts(t, BOUND, invalid)),
            ExitDecision::Escape {
                conceded: BOUND,
                reason: EscapeReason::AtDeadline
            }
        );
        // Lost ε: concede min(reported charge, b_k) at once.
        let lost = ExitFacts {
            lost_epsilon_charge: Some(120),
            ..facts(created + 60, BOUND, records.clone())
        };
        assert_eq!(
            decide(&lost),
            ExitDecision::Escape {
                conceded: 120,
                reason: EscapeReason::LostEpsilon
            }
        );
        // Near expiry the wait is cut at must_initiate_by.
        let near = ExitFacts {
            must_initiate_by: created + 1_000,
            ..facts(created + 1_000, BOUND, records)
        };
        assert_eq!(
            decide(&near),
            ExitDecision::Escape {
                conceded: BOUND,
                reason: EscapeReason::AtDeadline
            }
        );
    }

    #[test]
    fn nullifier_used_on_a_fresh_looking_state_waits_from_the_newest_release() {
        let records = vec![record(disposition::DISCARDED_STALE_ROOT, 5_000, None)];
        let used = ExitFacts {
            mutual_outcome: Some(MutualOutcome::NullifierUsed),
            ..facts(5_100, BOUND, records)
        };
        assert_eq!(
            decide(&used),
            ExitDecision::Wait {
                until: 5_000 + W + SETTLEMENT_GRACE_SECONDS
            }
        );
        let nothing_released = ExitFacts {
            mutual_outcome: Some(MutualOutcome::NullifierUsed),
            ..facts(5_100, 0, vec![])
        };
        assert_eq!(
            decide(&nothing_released),
            ExitDecision::Escape {
                conceded: 0,
                reason: EscapeReason::AtDeadline
            }
        );
    }

    #[test]
    fn unknown_readings_resolve_only_after_twenty_minutes() {
        let fresh = record(disposition::PENDING, 1_000, Some((ServerReading::Unknown, 2_199)));
        assert_eq!(classify(&fresh), RecordClass::Unresolved);
        let late = record(disposition::PENDING, 1_000, Some((ServerReading::Unknown, 2_200)));
        assert_eq!(classify(&late), RecordClass::ResolvedUnreserved);
        assert_eq!(
            classify(&record(disposition::PENDING, 0, Some((ServerReading::ExitDeferred, 1)))),
            RecordClass::Unresolved
        );
        assert_eq!(
            ServerReading::from_nullifier_status("bogus"),
            ServerReading::Unavailable
        );
    }

    #[test]
    fn near_expiry_uses_the_window_and_margins() {
        let by = 1_000_000;
        assert!(!note_near_expiry(by - W - 4_500, W, by));
        assert!(note_near_expiry(by - W - 4_499, W, by));
        assert_eq!(must_initiate_by(100_000), 100_000 - 43_200);
        assert_eq!(unsettled_escape_after(Some(1)), 3_600);
        assert_eq!(unsettled_escape_after(Some(u64::MAX)), 604_800);
    }

    /// Threat: replay of an abandoned exit proof. The lock stays until every
    /// released proof is past `valid_until + 900` on the local clock and at
    /// a finalized block.
    #[test]
    fn a_lock_waits_for_released_proofs_to_die() {
        let escape = [ReleasedExit {
            kind: 0,
            valid_until: 10_000,
        }];
        let active = NoteChainStatus::Active;
        assert_eq!(lock_dead_after(&escape), Some(10_900));
        assert!(!lock_releasable(&escape, true, active, Some(u64::MAX), 10_900));
        assert!(lock_releasable(&escape, false, active, Some(10_901), 10_901));
        assert!(!lock_releasable(&escape, false, active, Some(10_900), 99_999));
        assert!(!lock_releasable(
            &escape,
            false,
            NoteChainStatus::PendingWithdrawal,
            Some(99_999),
            99_999
        ));
        assert!(lock_releasable(&escape, false, NoteChainStatus::Closed, None, 0));
        assert!(lock_releasable(&[], true, active, None, 0));
        assert!(!lock_releasable(&[], false, active, None, 0));
    }

    /// Threat: under-concession raised by evidence; the payout matcher follows
    /// the largest raise and flags a concession above the bound.
    #[test]
    fn the_payout_matcher_follows_the_largest_raise() {
        assert_eq!(
            match_escape_payout(700, 1_000, 100, &[200, 300], Some(400)),
            PayoutMatch::Matches {
                conceded_final: 300,
                concession_exceeded_bound: false
            }
        );
        assert_eq!(
            match_escape_payout(900, 1_000, 100, &[300], Some(400)),
            PayoutMatch::Mismatch
        );
        assert_eq!(
            match_escape_payout(500, 1_000, 0, &[500], Some(400)),
            PayoutMatch::Matches {
                conceded_final: 500,
                concession_exceeded_bound: true
            }
        );
    }
}
