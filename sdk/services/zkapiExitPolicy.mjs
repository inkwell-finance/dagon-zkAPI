// Exit rules of the concession exit (docs/design/concession-exit.md §6.3-§6.4)
// as pure functions over local data. Nothing here reads the network or the
// clock: callers pass `now` in seconds and every server or chain reading.

export const EXIT_TIMING = Object.freeze({
    // valid_until = now + this. An exit proof the vault has not accepted by
    // then is dead on-chain (ExitProofExpired).
    exitProofValiditySeconds: 10_800,
    // A prepared exit proof is reused only while it stays valid this long.
    exitProofReuseMarginSeconds: 600,
    // A released exit proof freezes its state until valid_until + this, so
    // clock skew cannot let a request race a landing exit.
    exitProofReleaseMarginSeconds: 900,
    // E3: slack after the request's settlement deadline before an escape
    // concedes the whole bound.
    settlementSlackSeconds: 900,
    // E3: with no settlement deadline known, the longest a request may stay
    // unsettled before the wallet escapes conceding its bound.
    unsettledEscapeAfterSeconds: 43_200,
    // must_initiate_by = expiry - this.
    mustInitiateMarginSeconds: 43_200
});

export const EARLY_CONCESSIONS = Object.freeze(['zero', 'bound']);

function exitError(message, code) {
    return Object.assign(new Error(message), { code });
}

function seconds(value, label) {
    const number = Number(value);
    if (!Number.isSafeInteger(number) || number < 0) {
        throw exitError(`${label} must be a non-negative integer.`, 'exit_input_invalid');
    }
    return number;
}

function amount(value, label) {
    let parsed;
    try {
        parsed = BigInt(value ?? 0);
    } catch {
        throw exitError(`${label} must be an integer amount.`, 'exit_input_invalid');
    }
    if (parsed < 0n) throw exitError(`${label} must not be negative.`, 'exit_input_invalid');
    return parsed;
}

/** The valid_until of an exit proof made at `now`. */
export function exitProofValidUntil(now) {
    return seconds(now, 'now') + EXIT_TIMING.exitProofValiditySeconds;
}

/** Whether a prepared, never-released exit proof may be reused at `now`. */
export function reusableExitProof(validUntil, now) {
    if (validUntil == null) return false;
    return seconds(validUntil, 'valid_until') > seconds(now, 'now') + EXIT_TIMING.exitProofReuseMarginSeconds;
}

/**
 * The local second until which a released exit proof can still land, or
 * null when none was released. While it is live the state stays frozen: no
 * request proof, no cancel and no reselection of the balance.
 */
export function exitProofLiveUntil(releasedValidUntil) {
    if (releasedValidUntil == null) return null;
    return seconds(releasedValidUntil, 'valid_until') + EXIT_TIMING.exitProofReleaseMarginSeconds;
}

/**
 * Whether a released exit proof can still land. `valid_until` was derived
 * from this device's clock, but the vault checks it against block time, so a
 * device clock running ahead of the chain must not thaw the state while the
 * proof is still accepted on-chain (a successor spent meanwhile would defeat
 * the escape). The proof is dead only once both this device's `now` and
 * `chainTime` (a finalized block time from the host-pinned RPC, in seconds)
 * are past valid_until + margin; an unknown `chainTime` (RPC failure) keeps
 * the state frozen. This matches the native wallet's E6 rule.
 */
export function exitProofLive(releasedValidUntil, now, chainTime = null) {
    const until = exitProofLiveUntil(releasedValidUntil);
    if (until == null) return false;
    if (seconds(now, 'now') <= until) return true;
    return chainTime == null || seconds(chainTime, 'chain time') <= until;
}

/** must_initiate_by: the latest second an exit decision may still wait for. */
export function mustInitiateBy(expiryTs) {
    return Math.max(0, seconds(expiryTs, 'expiry') - EXIT_TIMING.mustInitiateMarginSeconds);
}

/**
 * E3.1: the second from which an escape at a state with a request in flight
 * concedes its bound: min(settlement deadline + slack, created + unsettled
 * limit, must_initiate_by). The settlement deadline is the lease's
 * settle_after when the server reported one.
 */
export function escapeAt({ createdAt, settleAfter = null, expiryTs }) {
    const created = seconds(createdAt, 'request creation time');
    const unsettled = created + EXIT_TIMING.unsettledEscapeAfterSeconds;
    const reported = settleAfter == null ? NaN : Number(settleAfter);
    const settlement = Number.isSafeInteger(reported) && reported > 0
        ? Math.min(reported + EXIT_TIMING.settlementSlackSeconds, unsettled)
        : unsettled;
    return Math.min(settlement, mustInitiateBy(expiryTs));
}

/**
 * The concession of an escape from the newest installed state (E2/E3).
 *
 * - No request released at the state (or every one resolved unreserved):
 *   concede nothing.
 * - The operator answered the state's request with a signed successor the
 *   wallet cannot install (S3/S4/S5 failed): concede min(reported charge, b)
 *   at once; the server finalized the nullifier, so waiting gains nothing.
 * - A request is in flight or its successor is withheld: from escapeAt on,
 *   concede the bound b; earlier, an escape the user forces concedes 0
 *   ('zero', the operator then raises to the settled charge) or b ('bound');
 *   otherwise wait.
 *
 * Every concession is at most b, so the payout is at least B - b (G1).
 * Returns { action: 'escape' | 'wait', conceded: bigint | null, rule, escapeAt? }.
 */
export function chooseEscapeConcession({ now, expiryTs, boundAtState = 0, inFlight = null,
    earlyConcession = null }) {
    const current = seconds(now, 'now');
    const bound = amount(boundAtState, 'bound_at_state');
    if (earlyConcession != null && !EARLY_CONCESSIONS.includes(earlyConcession)) {
        throw exitError('Choose the early escape concession: zero or bound.', 'exit_input_invalid');
    }
    if (!inFlight) return { action: 'escape', conceded: 0n, rule: 'fresh' };
    if (inFlight.invalidSuccessorCharge != null) {
        const charge = amount(inFlight.invalidSuccessorCharge, 'reported charge');
        return { action: 'escape', conceded: charge < bound ? charge : bound, rule: 'invalid_successor' };
    }
    const T = escapeAt({ createdAt: inFlight.createdAt, settleAfter: inFlight.settleAfter, expiryTs });
    if (current >= T) return { action: 'escape', conceded: bound, rule: 'in_flight', escapeAt: T };
    if (earlyConcession === 'bound') return { action: 'escape', conceded: bound, rule: 'forced_bound', escapeAt: T };
    if (earlyConcession === 'zero') return { action: 'escape', conceded: 0n, rule: 'forced_zero', escapeAt: T };
    return { action: 'wait', conceded: null, rule: 'wait_settlement', escapeAt: T };
}

/**
 * E5: an escape's on-chain payout against its record. The vault pays
 * B - max(c, raised), so a payout is accepted when it is at most the initial
 * f = B - c_init; a smaller payout means the operator raised the concession
 * with request evidence. Every raise is capped by the evidence's bound, which
 * for an honest wallet is the state's single bound b (C2); a payout below
 * B - b is still the vault's final word, so it is accepted with an alert.
 */
export function matchEscapePayout({ stateBalance, concededAtInit, boundAtState = null, paid }) {
    const B = amount(stateBalance, 'state balance');
    const cInit = amount(concededAtInit, 'initial concession');
    const value = amount(paid, 'payout');
    if (cInit > B) return { accepted: false, reason: 'record_invalid' };
    const upper = B - cInit;
    const accepted = value <= upper;
    const bound = boundAtState == null ? null : amount(boundAtState, 'bound_at_state');
    const floor = bound == null ? null : (B > bound ? B - bound : 0n);
    return {
        accepted,
        concededFinal: accepted ? B - value : null,
        raised: accepted && value < upper,
        alert: accepted && floor != null && value < floor ? 'concession_exceeded_bound' : null,
        reason: accepted ? null : 'payout_mismatch'
    };
}
