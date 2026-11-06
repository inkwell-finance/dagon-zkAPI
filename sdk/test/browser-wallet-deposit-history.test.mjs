import { nativeFunding } from './helpers/native-fixtures.mjs';
import assert from 'node:assert/strict';
import test from 'node:test';

const clone = value => value === undefined ? undefined : structuredClone(value);

// A transactional IndexedDB boundary: writes remain private to a transaction
// until completion, including when an injected history write fails. The tests
// exercise the real wallet store and runtime rather than source-code patterns.
function memoryIndexedDb() {
    const stores = new Map([
        ['runtime', new Map()], ['archives', new Map()], ['withdrawals', new Map()]
    ]);
    const keyPaths = new Map([['archives', 'archiveId'], ['withdrawals', 'recordId']]);
    let version = 2;
    let failDepositWrite = false;
    const database = {
        close() {},
        objectStoreNames: { contains: name => stores.has(name) },
        createObjectStore(name, options = {}) {
            stores.set(name, new Map());
            keyPaths.set(name, options.keyPath);
        },
        transaction(names, mode) {
            const allowed = Array.isArray(names) ? names : [names];
            const working = new Map(allowed.map(name => [name, new Map(stores.get(name))]));
            let timer;
            const transaction = {
                aborted: false, completed: false, pending: 0,
                abort() {
                    if (this.aborted || this.completed) return;
                    this.aborted = true;
                    clearTimeout(timer);
                    setTimeout(() => this.onabort?.(), 0);
                },
                scheduleCompletion() {
                    clearTimeout(timer);
                    if (this.aborted || this.pending) return;
                    timer = setTimeout(() => {
                        if (this.aborted || this.pending) return;
                        if (mode === 'readwrite') {
                            for (const [name, values] of working) stores.set(name, values);
                        }
                        this.completed = true;
                        this.oncomplete?.();
                    }, 0);
                },
                objectStore(name) {
                    if (!working.has(name)) throw new Error(`Unknown object store: ${name}`);
                    const values = working.get(name);
                    const request = operation => {
                        const pending = {};
                        transaction.pending += 1;
                        queueMicrotask(() => {
                            try {
                                if (transaction.aborted) return;
                                pending.result = operation();
                                pending.onsuccess?.();
                            } catch (error) {
                                pending.error = error;
                                transaction.error = error;
                                pending.onerror?.();
                                transaction.abort();
                            } finally {
                                transaction.pending -= 1;
                                transaction.scheduleCompletion();
                            }
                        });
                        return pending;
                    };
                    return {
                        get: key => request(() => clone(values.get(key))),
                        getAll: () => request(() => [...values.values()].map(clone)),
                        put: (value, key) => request(() => {
                            if (name === 'deposits' && failDepositWrite) {
                                failDepositWrite = false;
                                throw new Error('Simulated history storage failure');
                            }
                            const resolved = key ?? value[keyPaths.get(name)];
                            values.set(resolved, clone(value));
                            return resolved;
                        }),
                        delete: key => request(() => values.delete(key))
                    };
                }
            };
            return transaction;
        }
    };
    return {
        stores,
        clear() { for (const values of stores.values()) values.clear(); },
        failNextDepositWrite() { failDepositWrite = true; },
        open(_name, requestedVersion) {
            const request = {};
            queueMicrotask(() => {
                request.result = database;
                if (requestedVersion > version) {
                    const oldVersion = version;
                    version = requestedVersion;
                    request.onupgradeneeded?.({ oldVersion, newVersion: version });
                }
                request.onsuccess?.();
            });
            return request;
        }
    };
}


const values = new Map();
globalThis.localStorage = {
    getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, String(value))
};
globalThis.sessionStorage = globalThis.localStorage;
globalThis.window = new EventTarget();
globalThis.window.location = { search: '', hostname: 'localhost' };
globalThis.indexedDB = memoryIndexedDb();
const { readBrowserWalletSnapshot, updateBrowserWithdrawal, writeBrowserWallet }
    = await import('../services/browserWalletStore.js');
const { default: singleton } = await import('../services/browserWalletRuntime.js');
const { base58Encode } = await import('../services/zkapiSolanaTransport.mjs');

const DEPLOYMENT = 'dagon-localnet-test';
const OTHER_DEPLOYMENT = 'dagon-devnet-test';
const SIGNATURE = base58Encode(new Uint8Array(64).fill(7));
const state = (noteId = 7, amount = 2_000_000) => ({
    note_id: noteId, deposit_amount: amount, current_balance: 123,
    secret: 'private-note-secret', current_commitment: 'private-commitment'
});
const plan = (overrides = {}) => ({
    operationId: 'deposit-operation', next_note_id: 7, amount: 2_000_000,
    secret: 'private-note-secret', commitment: '0x123', phase: 'prepared',
    createdAt: 1000, ...overrides
});
const journaled = (overrides = {}) => plan({ solanaJournal: { operationId: 'deposit-operation', stages: [] }, ...overrides });
function seedRuntime(value) {
    indexedDB.stores.get('runtime').set('active', clone({ deploymentId: DEPLOYMENT, ...value }));
}
function makeRuntime() {
    const runtime = new singleton.constructor();
    runtime.manifest = { deployment_id: DEPLOYMENT, billing_asset: 'native_sol' };
    runtime.config = { wallet_core: {}, funding: nativeFunding() };
    runtime.init = async () => runtime.snapshot();
    runtime.walletStatus = async () => ({ has_note: Boolean(runtime.runtime.state) });
    runtime.worker = { call: async (method, payload) => {
        assert.equal(method, 'confirmDeposit');
        return state(payload.args.note_id, payload.args.amount);
    } };
    return runtime;
}
const confirmArgs = (extra = {}) => ({
    operationId: 'deposit-operation', secret: 'private-note-secret',
    note_id: 7, amount: 2_000_000, commitment: '0x123', expiry_ts: 9999,
    ...extra
});
function assertSanitized(records) {
    assert.doesNotMatch(JSON.stringify(records), /private-note-secret|private-commitment|proof|clearance|0x123/);
}

test.beforeEach(() => indexedDB.clear());

test('migration recovers original deposits from notes, archives and withdrawal states without invented dates', async () => {
    seedRuntime({ state: state(), updatedAt: 98765 });
    const original = clone(indexedDB.stores.get('runtime').get('active'));
    indexedDB.stores.get('archives').set('old', {
        archiveId: `${DEPLOYMENT}:6:4000`, archivedAt: 4001, state: state(6, 5_000_000)
    });
    indexedDB.stores.get('archives').set('duplicate', {
        archiveId: `${DEPLOYMENT}:7:7000`, archivedAt: 7000, state: state()
    });
    indexedDB.stores.get('archives').set('other', {
        archiveId: `${OTHER_DEPLOYMENT}:7:4000`, archivedAt: 4000, state: state(7, 9_000_000)
    });
    indexedDB.stores.get('withdrawals').set('withdrawal', {
        recordId: 'withdrawal', deploymentId: DEPLOYMENT, createdAt: 3000,
        state: state(5, 4_000_000), phase: 'pending'
    });
    indexedDB.stores.get('withdrawals').set('no-original-amount', {
        recordId: 'no-original-amount', deploymentId: DEPLOYMENT,
        state: { note_id: 4, current_balance: 55 }
    });
    const snapshot = await readBrowserWalletSnapshot(DEPLOYMENT);
    assert.deepEqual(snapshot.deposits.map(row => row.amount).sort(), [2_000_000, 4_000_000, 5_000_000]);
    for (const row of snapshot.deposits) {
        assert.equal(row.status, 'confirmed');
        assert.equal(row.createdAt, null);
        assert.equal(row.confirmedAt, null);
        assert.equal(row.transactionHash, null);
    }
    assertSanitized(snapshot.deposits);
    assert.deepEqual(indexedDB.stores.get('runtime').get('active'), original);
    indexedDB.stores.get('runtime').clear();
    indexedDB.stores.get('archives').clear();
    indexedDB.stores.get('withdrawals').clear();
    assert.deepEqual((await readBrowserWalletSnapshot(DEPLOYMENT)).deposits, snapshot.deposits);
    assert.equal((await readBrowserWalletSnapshot(OTHER_DEPLOYMENT)).deposits[0].amount, 9_000_000);
});

test('confirmed deposits retain their Solana signature across spending, a new note and runtime reload', async () => {
    seedRuntime({ pendingDeposit: journaled() });
    const runtime = makeRuntime();
    await runtime.confirmDeposit(confirmArgs({ transactionHash: SIGNATURE }));
    const confirmed = runtime.snapshot().deposits;
    assert.equal(confirmed.length, 1);
    assert.equal(confirmed[0].status, 'confirmed');
    assert.equal(confirmed[0].transactionHash, SIGNATURE);
    assert.equal(confirmed[0].createdAt, 1000);
    assert.ok(confirmed[0].confirmedAt > 1000);
    assert.equal(confirmed[0].operationId, 'deposit-operation');
    assert.equal((await readBrowserWalletSnapshot(DEPLOYMENT)).runtime.pendingDeposit, null);
    const current = (await readBrowserWalletSnapshot(DEPLOYMENT)).runtime;
    await writeBrowserWallet({ ...current, state: { ...state(), current_balance: 1 } });
    assert.deepEqual((await readBrowserWalletSnapshot(DEPLOYMENT)).deposits, confirmed);
    await writeBrowserWallet({ deploymentId: DEPLOYMENT, state: state(8, 3_000_000) });
    const reloaded = makeRuntime();
    await reloaded.reload();
    assert.equal(reloaded.snapshot().deposits.length, 2);
    assert.deepEqual(reloaded.snapshot().deposits.find(row => row.noteId === 7), confirmed[0]);
    assertSanitized(reloaded.snapshot().deposits);
});

test('only a canonical Solana signature is recorded as the deposit transaction', async () => {
    for (const transactionHash of [`0x${'ab'.repeat(32)}`, 'not-a-signature', base58Encode(new Uint8Array(32).fill(1))]) {
        indexedDB.clear();
        seedRuntime({ pendingDeposit: journaled() });
        const runtime = makeRuntime();
        await runtime.confirmDeposit(confirmArgs({ transactionHash }));
        assert.equal(runtime.snapshot().deposits[0].transactionHash, null, transactionHash);
        assert.equal(runtime.snapshot().deposits[0].status, 'confirmed');
    }
});

test('exact deposit commit succeeds independently of worker status and survives reload', async () => {
    seedRuntime({ pendingDeposit: journaled() });
    const runtime = makeRuntime();
    runtime.walletStatus = async () => { throw new Error('Status worker unavailable'); };
    const result = await runtime.confirmDeposit(confirmArgs({ transactionHash: SIGNATURE }));
    assert.deepEqual(result, {
        status: 'confirmed', operationId: 'deposit-operation', noteId: 7,
        amount: 2_000_000, transactionHash: SIGNATURE
    });
    const reloaded = makeRuntime();
    await reloaded.reload();
    assert.equal(reloaded.snapshot().runtime.pendingDeposit, null);
    assert.equal(reloaded.snapshot().runtime.state.note_id, 7);
    assert.equal(reloaded.snapshot().deposits[0].status, 'confirmed');
    assert.equal(reloaded.snapshot().deposits[0].transactionHash, SIGNATURE);
});

test('unsigned preparations are omitted and a journaled deposit stays pending until confirmation', async () => {
    seedRuntime({ pendingDeposit: plan() });
    assert.equal((await readBrowserWalletSnapshot(DEPLOYMENT)).deposits.length, 0);
    await writeBrowserWallet({ deploymentId: DEPLOYMENT, pendingDeposit: journaled() });
    const reloaded = makeRuntime();
    await reloaded.reload();
    const rows = reloaded.snapshot().deposits;
    assert.equal(rows.length, 1);
    assert.equal(rows[0].status, 'pending');
    assert.equal(rows[0].pendingPhase, 'submitting');
    assert.equal(rows[0].confirmedAt, null);
    const pending = reloaded.snapshot().config.pending_deposit;
    assert.equal(pending.operation_id, 'deposit-operation');
    assert.equal(pending.phase, 'submitting');
    assert.equal(pending.funding_quote_available, false, 'a journaled deposit is never re-quoted');
    assertSanitized(rows);
    assert.equal(indexedDB.stores.get('deposits').size, 0);
});

test('failed confirmation and failed atomic history write retain pending recovery and never record a deposit', async () => {
    seedRuntime({ pendingDeposit: journaled() });
    const runtime = makeRuntime();
    await assert.rejects(runtime.confirmDeposit(confirmArgs({ amount: 1 })), /does not match/);
    runtime.worker.call = async () => { throw new Error('Invalid confirmation'); };
    await assert.rejects(runtime.confirmDeposit(confirmArgs()), /Invalid confirmation/);
    runtime.worker.call = async () => state();
    indexedDB.failNextDepositWrite();
    await assert.rejects(runtime.confirmDeposit(confirmArgs({ transactionHash: SIGNATURE })), /history storage failure/);
    const snapshot = await readBrowserWalletSnapshot(DEPLOYMENT);
    assert.equal(snapshot.runtime.state, null);
    assert.equal(snapshot.runtime.pendingDeposit.secret, plan().secret);
    assert.equal(snapshot.deposits.length, 1);
    assert.equal(snapshot.deposits[0].status, 'pending');
    assert.equal(indexedDB.stores.get('deposits').size, 0);
    // The unchanged durable plan can be confirmed successfully after retry.
    await runtime.confirmDeposit(confirmArgs({ transactionHash: SIGNATURE }));
    assert.equal(runtime.snapshot().deposits[0].status, 'confirmed');
});

test('withdrawal finality preserves deposit metadata before sanitizing the last recovery state', async () => {
    indexedDB.stores.get('withdrawals').set('old-return', {
        recordId: 'old-return', deploymentId: DEPLOYMENT, revision: 1,
        state: state(1, 8_000_000), phase: 'finalizing', mode: 'escape',
        proof: 'private-proof', withdrawalNullifier: 'private-nullifier',
        solanaFinalizeOperationId: 'finalize-1', solanaFinalizationJournal: { stages: [] },
        createdAt: 4000, transactionHash: SIGNATURE
    });
    await assert.rejects(updateBrowserWithdrawal('old-return', { phase: 'closed' }, { expectedRevision: 7 }),
        /changed while its status was being checked/);
    await updateBrowserWithdrawal('old-return', { phase: 'closed', finalizeTransactionHash: SIGNATURE }, { sanitize: true });
    const snapshot = await readBrowserWalletSnapshot(DEPLOYMENT);
    const [record] = snapshot.withdrawals;
    for (const field of ['state', 'proof', 'withdrawalNullifier', 'solanaFinalizationJournal', 'solanaFinalizeOperationId']) {
        assert.equal(record[field], undefined, field);
    }
    assert.equal(record.finalizeTransactionHash, SIGNATURE, 'the public finalization signature stays');
    assert.equal(snapshot.deposits.length, 1);
    assert.equal(snapshot.deposits[0].amount, 8_000_000);
    assert.equal(snapshot.deposits[0].transactionHash, null, 'a withdrawal signature is not a deposit transaction');
    assert.equal(snapshot.deposits[0].createdAt, null, 'a withdrawal date is not a deposit date');
    assertSanitized(snapshot.deposits);
    await assert.rejects(updateBrowserWithdrawal('old-return', { phase: 'pending' }), /cannot return to an earlier phase/);
});

test('prefunding drafts persist and rebase across reload without pending deposits or secret regeneration', async () => {
    seedRuntime({});
    const runtime = makeRuntime();
    let generated = 0;
    let root = '0x1';
    runtime.worker = { call: async method => {
        assert.equal(method, 'generateDeposit');
        generated += 1;
        return { secret: `secret-${generated}`, registration_commitment: `0x${generated}` };
    } };
    runtime.nextDepositPath = async expected => ({ note_id: 3, active_root: expected ?? root, siblings: [root] });
    const draft = await runtime.prepareDepositQuote(2_000_000, '0x1');
    assert.equal(draft.secret, 'secret-1');
    assert.equal((await readBrowserWalletSnapshot(DEPLOYMENT)).runtime.pendingDeposit, null);
    assert.equal((await readBrowserWalletSnapshot(DEPLOYMENT)).deposits.length, 0);
    root = '0x2';
    const reloaded = makeRuntime();
    reloaded.worker = runtime.worker;
    reloaded.nextDepositPath = runtime.nextDepositPath;
    await reloaded.reload();
    const rebased = await reloaded.prepareDepositQuote(2_000_000, '0x2');
    assert.equal(rebased.operationId, draft.operationId);
    assert.equal(rebased.secret, draft.secret);
    assert.equal(rebased.active_root, '0x2');
    assert.equal(generated, 1, 'the same amount keeps its secret');
    const promoted = await reloaded.prepareDeposit(2_000_000, { preparedOperationId: draft.operationId });
    assert.equal(promoted.operationId, draft.operationId);
    assert.equal(promoted.phase, 'prepared');
    await assert.rejects(reloaded.prepareDeposit(2_000_000, { preparedOperationId: 'other-tab-quote' }),
        /quote changed in another tab/);
    // Once a Solana journal exists the plan can never change amount or re-quote.
    await writeBrowserWallet({ deploymentId: DEPLOYMENT, pendingDeposit: { ...promoted, solanaJournal: { stages: [] } } });
    await reloaded.reload();
    await assert.rejects(reloaded.prepareDeposit(3_000_000), /previous Solana deposit is unfinished/);
    await assert.rejects(reloaded.prepareDepositQuote(2_000_000, '0x2'), /Recover the existing private balance or deposit/);
});
