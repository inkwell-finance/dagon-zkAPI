import assert from 'node:assert/strict';
import test from 'node:test';
import { BrowserWalletRuntime } from '../services/browserWalletRuntime.js';
import { ZkapiClient } from '../services/zkapiClient.js';
import { walletErrorMessage } from '../services/zkapiWalletError.mjs';
import { base58Encode } from '../services/zkapiSolanaTransport.mjs';
import { nativeFunding, nativeQuote } from './helpers/native-fixtures.mjs';

const funding = nativeFunding();
const DESTINATION = base58Encode(new Uint8Array(32).fill(12));

function successorHarness({ response = null, worker = null, preparedWithdrawal = null } = {}) {
    const runtime = new BrowserWalletRuntime();
    const q = nativeQuote(funding);
    const request = { client_request_id: 'withheld-request', payload: JSON.stringify({ mode: 'openrouter_ephemeral_lease', version: 1, billing_quote: q }),
        public_inputs: { request_nullifier: '0x42', solvency_bound: 50_000 } };
    runtime.config = { funding, wallet_core: {}, proving_keys: { request: {} } };
    runtime.runtime = { state: { note_id: 1, current_balance: 2_000_000, current_anchor: '0x7', bound_at_state: 50_000 },
        journal: { nullifier: '0x42', created_at_ms: Date.now(), prepared_request: request }, preparedWithdrawal };
    runtime.commit = async next => { runtime.runtime = next; };
    runtime.remoteJson = async url => {
        assert.match(url, /\/v2\/requests\/withheld-request$/);
        return { nullifier_status: 'reserved', request_response: response
            && { ...response, response_payload: JSON.stringify({ billing_quote: q }) } };
    };
    runtime.worker = { call: worker || (async () => assert.fail('a withheld successor is never installed')) };
    return runtime;
}

test('a settled request whose successor is withheld freezes requests and is never re-sent', async () => {
    const runtime = successorHarness();
    // Not yet settled: nothing is concluded.
    assert.equal(await runtime.installRecoveredResponse('withheld-request'), false);
    assert.equal(runtime.runtime.journal.withheldObservedAt, undefined);
    // Settled (lease finalized) without a signed successor: withheld.
    assert.equal(await runtime.installRecoveredResponse('withheld-request', undefined, { settled: true }), false);
    assert.ok(runtime.runtime.journal.withheldObservedAt > 0);
    await assert.rejects(runtime.prepareLeaseRequest(), { code: 'successor_withheld' });
    assert.equal(runtime.snapshot().config.successor_withheld, true);
    await runtime.rememberRequestSettlement({ settle_after: 1_800_000_000 });
    assert.equal(runtime.runtime.journal.settleAfter, 1_800_000_000);
});

test('a signed successor failing S3-S5 is treated as withheld and records the reported charge', async () => {
    const runtime = successorHarness({
        response: { charge_applied: 70_000 },
        worker: async operation => {
            assert.equal(operation, 'completeResponse');
            throw new Error('invalid_successor: S4 next anchor is not next_anchor(N)');
        }
    });
    await assert.rejects(runtime.installRecoveredResponse('withheld-request'), { code: 'successor_withheld' });
    assert.deepEqual({ ...runtime.runtime.journal.invalidSuccessor, observedAt: 0 },
        { reason: 'invalid_successor: S4 next anchor is not next_anchor(N)', charge: '70000', observedAt: 0 });
    assert.equal(runtime.runtime.state.current_anchor, '0x7', 'the state is not replaced');
    await assert.rejects(runtime.prepareLeaseRequest(), { code: 'successor_withheld' });
    // Any other failure (e.g. a forged signature) is not withholding.
    const forged = successorHarness({ response: { charge_applied: 1 },
        worker: async () => { throw new Error('successor_signature_invalid: S6'); } });
    await assert.rejects(forged.installRecoveredResponse('withheld-request'), /successor_signature_invalid/);
    assert.equal(forged.runtime.journal.invalidSuccessor, undefined);
});

test('a settlement receipt must carry the exact SOL/USD quote the request proved', async () => {
    const runtime = successorHarness({ response: { charge_applied: 1 },
        worker: async () => assert.fail('a receipt with another quote is never installed') });
    const original = runtime.remoteJson;
    runtime.remoteJson = async url => {
        const recovery = await original(url);
        const payload = JSON.parse(recovery.request_response.response_payload);
        payload.billing_quote = { ...payload.billing_quote, price: '100000000001' };
        recovery.request_response.response_payload = JSON.stringify(payload);
        return recovery;
    };
    await assert.rejects(runtime.installRecoveredResponse('withheld-request'), /authorized SOL\/USD quote/);
});

test('a successor arriving after an exit proof left the device is not installed while that proof can land (E4.6)', async () => {
    const now = Math.floor(Date.now() / 1000);
    const runtime = successorHarness({ response: { charge_applied: 1 },
        preparedWithdrawal: { mode: 'escape', releasedValidUntil: now + 3_600 } });
    assert.equal(await runtime.installRecoveredResponse('withheld-request'), false);
    assert.equal(runtime.runtime.journal.prepared_request.client_request_id, 'withheld-request');
    const installed = successorHarness({ response: { charge_applied: 1 },
        preparedWithdrawal: { mode: 'escape', releasedValidUntil: now - 1_000 },
        worker: async () => ({ note_id: 1, current_balance: 1_999_999, current_anchor: '0x8', bound_at_state: 0 }) });
    installed.readFinalizedChainTime = async () => now;
    assert.equal(await installed.installRecoveredResponse('withheld-request'), true);
    assert.equal(installed.runtime.state.current_anchor, '0x8');
    assert.equal(installed.runtime.journal, null);
});

test('a device clock ahead of the cluster keeps a released exit proof frozen until the pinned RPC agrees (C3/E6)', async t => {
    const now = Math.floor(Date.now() / 1000);
    // The device clock says valid_until + 900 has passed (it runs ~1 h fast);
    // the program checks the cluster's block time, which still accepts the proof.
    const releasedValidUntil = now - 1_000;
    const chainStillValid = releasedValidUntil - 2_600;
    const install = () => successorHarness({ response: { charge_applied: 1 },
        preparedWithdrawal: { mode: 'escape', releasedValidUntil },
        worker: async () => ({ note_id: 1, current_balance: 1_999_999, current_anchor: '0x8', bound_at_state: 0 }) });
    const calls = [];
    t.mock.method(globalThis, 'fetch', async (url, init) => {
        assert.equal(url, funding.rpc_url, 'chain time comes only from the pinned RPC');
        const { method } = JSON.parse(init.body);
        calls.push(method);
        const result = method === 'getGenesisHash' ? funding.genesis_hash
            : method === 'getSlot' ? 77
                : method === 'getBlockTime' ? chainStillValid
                    : assert.fail(`Unexpected RPC ${method}`);
        return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result }));
    });
    const fast = install();
    assert.equal(await fast.installRecoveredResponse('withheld-request'), false);
    assert.equal(fast.runtime.state.current_anchor, '0x7', 'the successor is not installed');
    assert.equal(fast.runtime.journal.prepared_request.client_request_id, 'withheld-request');
    assert.deepEqual(calls, ['getGenesisHash', 'getSlot', 'getBlockTime']);
    // An unreachable or failing RPC fails closed.
    const offline = install();
    offline.readFinalizedChainTime = async () => { throw new TypeError('Failed to fetch'); };
    assert.equal(await offline.installRecoveredResponse('withheld-request'), false);
    assert.equal(offline.runtime.state.current_anchor, '0x7');
    // Once the cluster's finalized time is also past valid_until + 900, the successor installs.
    const dead = install();
    dead.readFinalizedChainTime = async () => releasedValidUntil + 901;
    assert.equal(await dead.installRecoveredResponse('withheld-request'), true);
    assert.equal(dead.runtime.state.current_anchor, '0x8');
});

function escapeHarness() {
    const runtime = successorHarness();
    runtime.manifest = { deployment_id: 'offline-escape' };
    runtime.init = async () => {};
    runtime.reload = async () => runtime.runtime;
    runtime.walletStatus = async () => ({ has_note: true });
    return runtime;
}

test('escape remains available when the operator is offline, refuses recovery, or returns malformed receipts', async t => {
    for (const failure of [
        new TypeError('Failed to fetch'),
        Object.assign(new Error('operator refuses recovery'), { status: 503 }),
        new Error('successor_signature_invalid: S6'),
        Object.assign(new Error('recovery deadline expired'), { name: 'TimeoutError' })
    ]) {
        await t.test(failure.message, async () => {
            const runtime = escapeHarness();
            runtime.runtime.state.expiry_ts = Math.floor(Date.now() / 1000) + 86_400;
            runtime.runtime.journal.created_at_ms = Date.now() - 86_400_000;
            const journal = structuredClone(runtime.runtime.journal);
            let recoveries = 0;
            runtime.remoteJson = async (_url, { signal }) => {
                assert.ok(signal instanceof AbortSignal, 'operator recovery has a bounded deadline');
                recoveries++;
                throw failure;
            };
            runtime.worker = { call: async (operation, payload) => {
                assert.equal(operation, 'prepareWithdrawal');
                assert.equal(payload.args.mode, 'escape');
                assert.equal(payload.args.destination, DESTINATION);
                assert.equal(payload.args.conceded, '50000');
                return { mode: 'escape', proof: 'offline-proof', public_inputs: {
                    note_id: 1, has_clearance: false, conceded: 50_000,
                    final_balance: 1_950_000, valid_until: Number(payload.args.valid_until),
                    withdrawal_nullifier: '0x42', next_nullifier: '0x43'
                } };
            } };
            const plan = await runtime.prepareWithdrawal('escape', DESTINATION);
            assert.equal(plan.public_inputs.final_balance, 1_950_000);
            assert.equal(plan.destination, DESTINATION);
            assert.equal(plan.concessionRule, 'in_flight');
            assert.equal(recoveries, 2, 'both pre-settlement and locked recovery are advisory');
            assert.deepEqual(runtime.runtime.journal, journal, 'no evidence of an unsettled request is discarded');
            assert.equal(runtime.runtime.state.bound_at_state, 50_000);
            await runtime.markPreparedWithdrawalReleased();
            assert.ok(runtime.runtime.preparedWithdrawal.releasedValidUntil > 0, 'the offline exit still freezes requests');
        });
    }
});

test('failed operator recovery still blocks mutual close and cannot bypass escape timing', async () => {
    const runtime = escapeHarness();
    runtime.runtime.state.expiry_ts = Math.floor(Date.now() / 1000) + 30 * 86_400;
    runtime.remoteJson = async () => { throw new Error('operator offline'); };
    await assert.rejects(runtime.prepareWithdrawal('mutual', DESTINATION), /operator offline/);
    await assert.rejects(runtime.prepareWithdrawal('escape', DESTINATION), { code: 'escape_wait' });
    assert.ok(runtime.runtime.journal);
    assert.equal(runtime.runtime.preparedWithdrawal, null);
});

test('a journaled Solana withdrawal is resumed, never re-proved for another destination or mode', async () => {
    const runtime = escapeHarness();
    runtime.runtime.journal = null;
    runtime.runtime.state.expiry_ts = Math.floor(Date.now() / 1000) + 86_400;
    const journaled = { mode: 'escape', noteId: 1, destination: DESTINATION, public_inputs: { note_id: 1 },
        proof: 'saved-proof', solanaJournal: { stages: [{ phase: 'signed' }] } };
    runtime.runtime.preparedWithdrawal = journaled;
    runtime.remoteJson = async () => assert.fail('a journaled exit needs no operator');
    runtime.worker = { call: async () => assert.fail('a journaled exit is never re-proved') };
    assert.equal(await runtime.prepareWithdrawal('escape', DESTINATION), journaled);
    const other = base58Encode(new Uint8Array(32).fill(13));
    await assert.rejects(runtime.prepareWithdrawal('escape', other), /different withdrawal is already prepared/);
    await assert.rejects(runtime.prepareWithdrawal('mutual', DESTINATION), /different withdrawal is already prepared/);
});

test('startup recovery is advisory even when fallback or successor recovery rejects asynchronously', async () => {
    for (const status of ['missing', 'finalized']) {
        const runtime = successorHarness();
        const journal = structuredClone(runtime.runtime.journal);
        runtime.remoteJson = async url => {
            if (url.includes('/openrouter/leases/')) {
                if (status === 'missing') throw Object.assign(new Error('missing lease'), { status: 404 });
                return { status: 'finalized' };
            }
            throw new TypeError('operator recovery unavailable');
        };
        assert.equal(await runtime.recoverPendingLocked({ quiet: true }), false);
        assert.deepEqual(runtime.runtime.journal, journal);
        await assert.rejects(runtime.recoverPendingLocked(), /operator recovery unavailable/);
    }
});

test('a canceled escape keeps its released proof frozen until the proof is dead on both clocks (C3)', async () => {
    const now = Math.floor(Date.now() / 1000);
    const runtime = escapeHarness();
    runtime.runtime.preparedWithdrawal = { mode: 'escape', noteId: 1, destination: DESTINATION,
        public_inputs: { note_id: 1, valid_until: now + 600 }, releasedValidUntil: now + 600 };
    await assert.rejects(runtime.clearPreparedWithdrawal(), { code: 'exit_proof_live' });
    await assert.rejects(runtime.prepareLeaseRequest(), /Finish the prepared withdrawal/);
    // Past valid_until + 900 on this device, but the cluster disagrees or is unreachable.
    const deviceDead = now - 1_000;
    runtime.runtime.preparedWithdrawal.releasedValidUntil = deviceDead;
    runtime.readFinalizedChainTime = async () => deviceDead;
    await assert.rejects(runtime.clearPreparedWithdrawal(), { code: 'exit_proof_live' });
    runtime.readFinalizedChainTime = async () => { throw new TypeError('Failed to fetch'); };
    await assert.rejects(runtime.clearPreparedWithdrawal(), { code: 'exit_proof_live' });
    // A stage that already finalized on Solana is resumed, never discarded.
    runtime.readFinalizedChainTime = async () => deviceDead + 901;
    runtime.runtime.preparedWithdrawal.solanaJournal = { stages: [{ phase: 'finalized' }] };
    await assert.rejects(runtime.clearPreparedWithdrawal(), /already finalized on Solana/);
    // When both clocks are past it and nothing landed, cancel releases every lock.
    runtime.runtime.preparedWithdrawal.solanaJournal = { stages: [{ phase: 'submitted' }] };
    await runtime.clearPreparedWithdrawal();
    assert.equal(runtime.runtime.preparedWithdrawal, null);
    // A mutual close reserved the server's clearance and is never canceled.
    runtime.runtime.preparedWithdrawal = { mode: 'mutual', noteId: 1, clearanceReserved: true };
    await assert.rejects(runtime.clearPreparedWithdrawal(), /mutual-close authorization/);
});

test('withdrawal destinations are canonical Solana accounts and never the vault state', async () => {
    const client = new ZkapiClient();
    client.config = { funding };
    client.performWithdrawal = async (mode, _status, options) => ({ mode, ...options });
    assert.deepEqual(await client.withdraw('escape', () => {}, { destination: DESTINATION }),
        { mode: 'escape', destination: DESTINATION, earlyConcession: null });
    assert.deepEqual(await client.withdraw('mutual'), { mode: 'mutual', destination: null, earlyConcession: null });
    await assert.rejects(client.withdraw('escape', () => {}, { destination: `0x${'12'.repeat(20)}` }), /base58|Solana/);
    await assert.rejects(client.withdraw('escape', () => {}, { destination: funding.vault_state }), /vault state account/);
});

test('deposits and withdrawals require a Wallet Standard Solana account on the pinned cluster', async () => {
    const client = new ZkapiClient();
    client.config = { funding };
    client.emitChange = () => {};
    await assert.rejects(client.connectSolanaWallet(), /Choose a Solana wallet/);
    assert.throws(() => client.setSolanaWallet({}), /Wallet Standard/);
    const account = { address: DESTINATION, publicKey: new Uint8Array(32).fill(12),
        chains: ['solana:mainnet'], features: ['solana:signTransaction'] };
    const wallet = { features: { 'standard:connect': { connect: async () => {} } }, accounts: [account] };
    client.setSolanaWallet(wallet);
    await assert.rejects(client.connectSolanaWallet(), /no account that can sign on solana:localnet/);
    account.chains = ['solana:localnet'];
    assert.deepEqual(await client.connectSolanaWallet(), { wallet, account, address: DESTINATION });
    account.publicKey = new Uint8Array(32).fill(13);
    await assert.rejects(client.connectSolanaWallet(), /does not match its public key/);
});

test('wallet errors keep their useful message without printing objects', () => {
    assert.equal(walletErrorMessage({ error: { message: 'RPC temporarily unavailable' } }), 'RPC temporarily unavailable');
    assert.equal(walletErrorMessage({ message: { message: 'Signature request rejected' } }), 'Signature request rejected');
    const cyclic = {};
    cyclic.cause = cyclic;
    assert.equal(walletErrorMessage(cyclic), 'The wallet could not complete this request.');
    assert.equal(walletErrorMessage(new Error('[object Object]')), 'The wallet could not complete this request.');
});
