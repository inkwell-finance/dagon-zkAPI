import assert from 'node:assert/strict';
import test from 'node:test';
import { normalizeWalletError, walletErrorMessage } from '../services/zkapiWalletError.mjs';

const values = new Map();
globalThis.localStorage = {
    getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, String(value)),
    removeItem: key => values.delete(key)
};
globalThis.sessionStorage = globalThis.localStorage;
globalThis.window = new EventTarget();
globalThis.window.location = { search: '', hostname: 'localhost' };
globalThis.zkapiWallet = (await import('../wallet.js')).default;
const { ZkapiClient } = await import('../services/zkapiClient.js');
const { default: runtime } = await import('../services/browserWalletRuntime.js');

const HASH = '0x34e298c17052af34acbbd1f1fd0e910f023af7938c5ff1656dd4bd669140ae48';
const VAULT = `0x${'12'.repeat(20)}`;
const DESTINATION = `0x${'34'.repeat(20)}`;

function receipt(overrides = {}) {
    return {
        transactionHash: HASH,
        status: '0x1',
        blockNumber: '0x18b6939',
        logs: [{
            address: VAULT,
            topics: [globalThis.zkapiWallet.ABI.mutualCloseEvent,
                `0x${globalThis.zkapiWallet.abiWord(18)}`],
            data: `0x${globalThis.zkapiWallet.abiWord(99)}${globalThis.zkapiWallet.abiWord(1972567)}${globalThis.zkapiWallet.addressWord(DESTINATION)}`
        }],
        ...overrides
    };
}

test('plain and nested provider errors retain useful messages and transaction classification', () => {
    const plain = { code: 4001, message: 'User rejected the request.', data: { reason: 'Canceled' } };
    const error = normalizeWalletError(plain);
    assert.ok(error instanceof Error);
    assert.equal(error.message, plain.message);
    assert.equal(error.code, 4001);
    assert.equal(error.cause, plain);
    assert.equal(error.data, plain.data);
    assert.equal(walletErrorMessage({ error: { message: 'RPC temporarily unavailable' } }), 'RPC temporarily unavailable');
    assert.equal(walletErrorMessage({ message: { message: 'Receipt lookup failed' } }), 'Receipt lookup failed');
    const cyclic = {};
    cyclic.cause = cyclic;
    assert.equal(walletErrorMessage(cyclic), 'The wallet could not complete this request.');
    assert.equal(walletErrorMessage(new Error('[object Object]')), 'The wallet could not complete this request.');
});

test('a transient receipt RPC failure recovers without resending or reporting a failed payment', async t => {
    const client = new ZkapiClient();
    const mined = receipt();
    const calls = [];
    t.mock.method(globalThis, 'setTimeout', callback => { queueMicrotask(callback); return 1; });
    globalThis.ethereum = {
        async request(request) {
            calls.push(request);
            assert.equal(request.method, 'eth_getTransactionReceipt');
            assert.deepEqual(request.params, [HASH]);
            if (calls.length === 1) throw { code: -32603, message: 'Internal JSON-RPC error.' };
            if (calls.length === 2) return null;
            return mined;
        }
    };
    assert.equal(await client.waitForReceipt(HASH), mined);
    assert.equal(calls.length, 3);
});

test('unavailable receipt RPC retains the submitted hash and readable error after bounded retries', async t => {
    const client = new ZkapiClient();
    client.config = { funding: { chain_id: 1 } };
    let receiptReads = 0;
    let sends = 0;
    let journaledHash = null;
    t.mock.method(globalThis, 'setTimeout', callback => { queueMicrotask(callback); return 1; });
    globalThis.ethereum = {
        async request({ method }) {
            if (method === 'eth_chainId') return '0x1';
            if (method === 'eth_estimateGas') return '0x50000';
            if (method === 'eth_sendTransaction') { sends += 1; return HASH; }
            if (method === 'eth_getTransactionReceipt') {
                receiptReads += 1;
                throw { code: -32603, message: 'Receipt service temporarily unavailable' };
            }
            throw new Error(`Unexpected RPC ${method}`);
        }
    };
    await assert.rejects(client.sendContractTransaction(DESTINATION, VAULT, '0x00', hash => { journaledHash = hash; }), error => {
        assert.equal(error.message, 'Receipt service temporarily unavailable');
        assert.equal(error.code, -32603);
        assert.equal(error.transactionStage, 'receipt');
        assert.equal(error.transactionHash, HASH);
        assert.equal(error.broadcastPossible, true);
        return true;
    });
    assert.equal(sends, 1);
    assert.equal(receiptReads, 3);
    assert.equal(journaledHash, HASH);
});

test('definite wallet rejection preserves its code and never enters receipt polling', async () => {
    const client = new ZkapiClient();
    globalThis.ethereum = {
        async request({ method }) {
            if (method === 'eth_estimateGas') return '0x50000';
            if (method === 'eth_sendTransaction') throw { code: 4001, message: 'User rejected the request.' };
            throw new Error(`Unexpected RPC ${method}`);
        }
    };
    await assert.rejects(client.sendContractTransaction(DESTINATION, VAULT, '0x00'), error => {
        assert.equal(error.code, 4001);
        assert.equal(error.message, 'User rejected the request.');
        assert.equal(error.broadcastPossible, false);
        return true;
    });
});

test('mined reverts remain failures with their receipt attached', async () => {
    const reverted = receipt({ status: '0x0' });
    globalThis.ethereum = { request: async () => reverted };
    await assert.rejects(new ZkapiClient().waitForReceipt(HASH), error => {
        assert.match(error.message, /reverted/);
        assert.equal(error.transactionReceipt, reverted);
        return true;
    });
});

test('mutual-close recovery of a mined payment completes through event and vault verification', async t => {
    const client = new ZkapiClient();
    const plan = {
        mode: 'mutual', phase: 'submitted', destination: DESTINATION,
        transactionHash: HASH, clearanceReserved: true,
        public_inputs: { note_id: 18, final_balance: 1972567 }
    };
    client.browserMode = true;
    client.config = { funding: { chain_id: 1, contract_address: VAULT } };
    client.wallet = { has_note: true, note: { note_id: 18, current_balance: 1972567 } };
    t.mock.method(client, 'settleActiveLease', async () => {});
    t.mock.method(client, 'connectWallet', async () => DESTINATION);
    t.mock.method(client, 'waitForReceipt', async () => { throw { code: -32603, message: 'Receipt provider unavailable' }; });
    t.mock.method(client, 'refresh', async () => client.snapshot());
    let vaultChecks = 0;
    t.mock.method(client, 'readBrowserWithdrawalStatus', async noteId => {
        assert.equal(noteId, 18);
        vaultChecks += 1;
        return { status: 'closed', observed_block: 25913660 };
    });
    t.mock.method(runtime, 'currentPreparedWithdrawal', async () => plan);
    t.mock.method(runtime, 'getDepositHistory', async () => []);
    t.mock.method(runtime, 'snapshot', () => ({ runtime: { preparedWithdrawal: plan } }));
    const detached = [];
    t.mock.method(runtime, 'detachClosedWithdrawal', async record => { detached.push(record); });
    const mined = receipt();
    globalThis.ethereum = { request: async ({ method, params }) => {
        assert.equal(method, 'eth_getTransactionReceipt');
        assert.deepEqual(params, [HASH]);
        return mined;
    } };
    const result = await client.performWithdrawal('mutual');
    assert.equal(result.status, 'closed');
    assert.equal(result.receipt, mined);
    assert.equal(vaultChecks, 1);
    assert.equal(detached.length, 1);
    assert.equal(detached[0].transactionHash, HASH);
    assert.equal(detached[0].finalBalance, 1972567);
    assert.equal(detached[0].closeBlockNumber, Number(BigInt(mined.blockNumber)));
    assert.equal(detached[0].payoutVerified, true);
    assert.equal(client.withdrawal, null);

    // The matching payment is already mined; an unavailable second RPC must
    // leave its submitted plan available for background/reload reconciliation.
    const confirmedStatus = client.readBrowserWithdrawalStatus;
    client.readBrowserWithdrawalStatus = async () => { throw { code: -32603, message: 'RPC temporarily unavailable' }; };
    await assert.rejects(client.performWithdrawal('mutual'), error => {
        assert.equal(error.withdrawalConfirmationPending, true);
        assert.equal(error.transactionHash, HASH);
        assert.match(error.shortMessage, /transaction was mined.*checked automatically/i);
        assert.equal(error.message, 'RPC temporarily unavailable');
        return true;
    });
    assert.equal(detached.length, 1);
    assert.equal((await runtime.currentPreparedWithdrawal()).transactionHash, HASH);
    client.readBrowserWithdrawalStatus = confirmedStatus;

    // A successful receipt for another note is not proof of this payout.
    mined.logs[0].topics[1] = `0x${globalThis.zkapiWallet.abiWord(19)}`;
    await assert.rejects(client.performWithdrawal('mutual'), /event did not match/);
    assert.equal(detached.length, 1);
});

test('vault reads: a defeated note is plainly Active, status 4 is reserved, pending escapes expose their concession', async () => {
    const client = new ZkapiClient();
    client.config = { funding: { chain_id: 1, contract_address: VAULT } };
    const word = globalThis.zkapiWallet.abiWord;
    const chain = { status: 1, nullifierState: 2 };
    const calls = [];
    globalThis.ethereum = {
        async request({ method, params }) {
            if (method === 'eth_chainId') return '0x1';
            if (method === 'eth_blockNumber') return '0x10';
            assert.equal(method, 'eth_call');
            calls.push(params);
            const data = params[0].data;
            if (data === `0x${globalThis.zkapiWallet.ABI.notes}${word(7)}`) {
                return `0x${[0, 0, 0, chain.status, 0, 0].map(word).join('')}`;
            }
            if (data === `0x${globalThis.zkapiWallet.ABI.pendingWithdrawals}${word(7)}`) {
                return `0x${[1, 0x99, 0x9a, 2_000_000, 70_000, 1_930_000].map(word).join('')}${globalThis.zkapiWallet.addressWord(DESTINATION)}${word(1_900_000_000)}`;
            }
            assert.equal(data, `0x${globalThis.zkapiWallet.ABI.nullifierState}${word(0x99)}`);
            return `0x${word(chain.nullifierState)}`;
        }
    };
    // No restoration step exists: the leaf never left the tree.
    assert.deepEqual(await client.readBrowserWithdrawalStatus(7),
        { status: 'active', note_id: 7, challenge_deadline: null, observed_block: 16 });
    assert.equal(await client.readNullifierState('0x99', 16), 2);
    assert.equal(calls.at(-1)[1], '0x10');
    chain.status = 4;
    await assert.rejects(client.readBrowserWithdrawalStatus(7), /unknown note status 4/);
    chain.status = 2;
    assert.deepEqual(await client.readBrowserWithdrawalStatus(7), {
        status: 'pending_withdrawal', note_id: 7, withdrawal_nullifier: `0x${word(0x99)}`,
        next_nullifier: `0x${word(0x9a)}`, state_balance: 2_000_000, conceded: 70_000, final_balance: 1_930_000,
        destination: DESTINATION, challenge_deadline: 1_900_000_000, observed_block: 16
    });
    assert.equal(client.restoreChallengedNoteOnChain, undefined);
});

test('escape payouts accept raises up to the bound and reject payouts above the declared f', () => {
    const client = new ZkapiClient();
    const record = { stateBalance: 2_000_000, concededAtInit: 0, boundAtState: 50_000, finalBalance: 2_000_000 };
    assert.equal(client.initialFinalBalance(record), 2_000_000n);
    assert.deepEqual(client.escapePayout(record, 2_000_000n), { accepted: true, concededFinal: 0n, raised: false, alert: null, reason: null });
    const raised = client.escapePayout(record, 1_970_000n);
    assert.equal(raised.accepted, true);
    assert.equal(raised.raised, true);
    assert.equal(raised.concededFinal, 30_000n);
    assert.deepEqual(client.escapePayoutPatch({ amount: 1_970_000n, ...raised }),
        { finalBalance: 1_970_000, conceded: 30_000, concessionRaised: true });
    assert.deepEqual(client.escapePayoutPatch({ amount: 1_970_000n, deferred: true, ...raised }),
        { finalBalance: 1_970_000, conceded: 30_000, concessionRaised: true, payoutDeferred: true });
    assert.equal(client.escapePayout(record, 1_900_000n).alert, 'concession_exceeded_bound');
    assert.equal(client.escapePayout(record, 2_000_001n).accepted, false);
    // A record without concession terms (another tab's late escape) must match exactly.
    assert.equal(client.escapePayout({ finalBalance: 5 }, 5n).accepted, true);
    assert.equal(client.escapePayout({ finalBalance: 5 }, 4n).accepted, false);
});
