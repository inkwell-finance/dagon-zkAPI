import assert from 'node:assert/strict';
import test from 'node:test';
import { deriveExpiryRecords } from '../services/zkapiExpiryHistory.mjs';

const deposit = (noteId = 7, extra = {}) => ({ recordId: `test:deposit:${noteId}`,
    deploymentId: 'test', status: 'confirmed', noteId, amount: 2_000_000,
    expiryTs: 1000, ...extra });

test('clock expiry creates only an informational deadline, never an automatic refund or transfer', () => {
    assert.deepEqual(deriveExpiryRecords([deposit()], [], 999_999), []);
    assert.deepEqual(deriveExpiryRecords([deposit()], [], NaN), []);
    const rows = deriveExpiryRecords([deposit(), deposit(8, { expiryTs: null }),
        deposit(9, { status: 'pending' })], [], 1_000_000);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].type, 'expiry');
    assert.equal(rows[0].status, 'expired');
    assert.equal(rows[0].createdAt, 1_000_000);
    assert.match(rows[0].detail, /No automatic refund/);
    assert.match(rows[0].detail, /does not transfer funds/);
});

test('a verified close or a started escape suppresses the deadline; other records do not', () => {
    const closed = { deploymentId: 'test', noteId: 7, phase: 'closed', payoutVerified: true };
    assert.deepEqual(deriveExpiryRecords([deposit()], [closed], 2_000_000), []);
    const escape = { deploymentId: 'test', noteId: 7, mode: 'escape', phase: 'pending',
        chainStatus: 'pending_withdrawal', startBlockNumber: 12 };
    assert.deepEqual(deriveExpiryRecords([deposit()], [escape], 2_000_000), []);
    for (const record of [{ ...closed, payoutVerified: false }, { ...closed, phase: 'closed_unconfirmed' },
        { ...closed, deploymentId: 'other' }, { ...closed, noteId: 8 }, { ...escape, startBlockNumber: 0 },
        { ...escape, chainStatus: 'active' }]) {
        assert.equal(deriveExpiryRecords([deposit()], [record], 2_000_000)[0].status, 'expired');
    }
});
