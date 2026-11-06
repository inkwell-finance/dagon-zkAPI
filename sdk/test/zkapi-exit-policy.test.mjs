import assert from 'node:assert/strict';
import test from 'node:test';
import { EXIT_TIMING, chooseEscapeConcession, escapeAt, exitProofLive, exitProofLiveUntil, exitProofValidUntil,
    matchEscapePayout, mustInitiateBy, reusableExitProof } from '../services/zkapiExitPolicy.mjs';

const NOW = 1_800_000_000;
const EXPIRY = NOW + 30 * 86_400;

test('a fresh state escapes conceding nothing', () => {
    assert.deepEqual(chooseEscapeConcession({ now: NOW, expiryTs: EXPIRY, boundAtState: 50_000 }),
        { action: 'escape', conceded: 0n, rule: 'fresh' });
});

test('withheld successor: after the settlement window the honest escape concedes exactly its bound (c = b)', () => {
    const inFlight = { createdAt: NOW - 600, settleAfter: NOW - 120 };
    const T = escapeAt({ createdAt: inFlight.createdAt, settleAfter: inFlight.settleAfter, expiryTs: EXPIRY });
    assert.equal(T, NOW - 120 + EXIT_TIMING.settlementSlackSeconds);
    assert.deepEqual(chooseEscapeConcession({ now: T, expiryTs: EXPIRY, boundAtState: 50_000, inFlight }),
        { action: 'escape', conceded: 50_000n, rule: 'in_flight', escapeAt: T });
    // Before T the wallet waits unless the user forces the escape.
    assert.equal(chooseEscapeConcession({ now: T - 1, expiryTs: EXPIRY, boundAtState: 50_000, inFlight }).action, 'wait');
    assert.equal(chooseEscapeConcession({ now: T - 1, expiryTs: EXPIRY, boundAtState: 50_000, inFlight,
        earlyConcession: 'zero' }).conceded, 0n);
    assert.equal(chooseEscapeConcession({ now: T - 1, expiryTs: EXPIRY, boundAtState: 50_000, inFlight,
        earlyConcession: 'bound' }).conceded, 50_000n);
    assert.throws(() => chooseEscapeConcession({ now: NOW, expiryTs: EXPIRY, inFlight, earlyConcession: 'all' }),
        { code: 'exit_input_invalid' });
});

test('no settlement deadline: the unsettled limit and must_initiate_by bound the wait', () => {
    assert.equal(escapeAt({ createdAt: NOW, expiryTs: EXPIRY }), NOW + EXIT_TIMING.unsettledEscapeAfterSeconds);
    const nearExpiry = NOW + 13 * 3_600;
    assert.equal(mustInitiateBy(nearExpiry), NOW + 3_600);
    assert.equal(escapeAt({ createdAt: NOW, settleAfter: NOW + 86_400, expiryTs: nearExpiry }), NOW + 3_600);
    // A server-reported deadline can never extend past the unsettled limit.
    assert.equal(escapeAt({ createdAt: NOW, settleAfter: NOW + 10 * 86_400, expiryTs: EXPIRY }),
        NOW + EXIT_TIMING.unsettledEscapeAfterSeconds);
});

test('an invalid signed successor concedes min(reported charge, b) at once', () => {
    const decide = charge => chooseEscapeConcession({ now: NOW, expiryTs: EXPIRY, boundAtState: 50_000,
        inFlight: { createdAt: NOW, invalidSuccessorCharge: charge } });
    assert.deepEqual(decide('20000'), { action: 'escape', conceded: 20_000n, rule: 'invalid_successor' });
    // An overcharging operator cannot push the concession past the bound.
    assert.equal(decide(50_001).conceded, 50_000n);
});

test('exit proofs carry a short validity deadline and freeze their state until it passes (C3)', () => {
    const validUntil = exitProofValidUntil(NOW);
    assert.equal(validUntil, NOW + EXIT_TIMING.exitProofValiditySeconds);
    assert.equal(reusableExitProof(validUntil, NOW), true);
    assert.equal(reusableExitProof(validUntil, validUntil - EXIT_TIMING.exitProofReuseMarginSeconds), false);
    assert.equal(reusableExitProof(null, NOW), false);
    assert.equal(exitProofLiveUntil(null), null);
    assert.equal(exitProofLive(null, NOW), false);
    assert.equal(exitProofLiveUntil(validUntil), validUntil + EXIT_TIMING.exitProofReleaseMarginSeconds);
    assert.equal(exitProofLive(validUntil, validUntil + EXIT_TIMING.exitProofReleaseMarginSeconds), true);
    const dead = validUntil + EXIT_TIMING.exitProofReleaseMarginSeconds + 1;
    assert.equal(exitProofLive(validUntil, dead, dead), false);
});

test('a device clock running ahead of the chain never thaws a proof the vault still accepts (C3/E6)', () => {
    const validUntil = exitProofValidUntil(NOW);
    const until = exitProofLiveUntil(validUntil);
    // The device thinks the proof is dead, but the chain's finalized block time
    // still accepts it: the state stays frozen.
    assert.equal(exitProofLive(validUntil, until + 3_600, validUntil), true);
    assert.equal(exitProofLive(validUntil, until + 3_600, until), true);
    // An unreadable chain clock fails closed.
    assert.equal(exitProofLive(validUntil, until + 3_600), true);
    assert.equal(exitProofLive(validUntil, until + 3_600, null), true);
    // A device clock behind the chain still waits for its own deadline.
    assert.equal(exitProofLive(validUntil, until, until + 3_600), true);
    assert.equal(exitProofLive(validUntil, until + 1, until + 1), false);
    assert.throws(() => exitProofLive(validUntil, until + 1, -1), { code: 'exit_input_invalid' });
});

test('payouts: honest withheld escape pays B - b; a raise lowers f; nothing pays more than the declared f', () => {
    const B = 2_000_000;
    // Withheld successor, c = b: the operator cannot raise further, payout B - b.
    assert.deepEqual(matchEscapePayout({ stateBalance: B, concededAtInit: 50_000, boundAtState: 50_000, paid: B - 50_000 }),
        { accepted: true, concededFinal: 50_000n, raised: false, alert: null, reason: null });
    // Under-concession raised to the settled charge.
    const raised = matchEscapePayout({ stateBalance: B, concededAtInit: 0, boundAtState: 50_000, paid: B - 31_000 });
    assert.equal(raised.raised, true);
    assert.equal(raised.concededFinal, 31_000n);
    assert.equal(matchEscapePayout({ stateBalance: B, concededAtInit: 0, boundAtState: 50_000, paid: B - 50_001 }).alert,
        'concession_exceeded_bound');
    assert.equal(matchEscapePayout({ stateBalance: B, concededAtInit: 10, paid: B }).accepted, false);
    assert.equal(matchEscapePayout({ stateBalance: 5, concededAtInit: 6, paid: 0 }).reason, 'record_invalid');
});
