import { sameFelt as sameFeltValue } from './zkapiActiveRoot.mjs';
import { base58Decode } from './zkapiSolanaTransport.mjs';

const DB_NAME = 'zkapi-browser-wallet-v1';
const DB_VERSION = 3;
const RUNTIME_STORE = 'runtime';
const ARCHIVE_STORE = 'archives';
const WITHDRAWAL_STORE = 'withdrawals';
const DEPOSIT_STORE = 'deposits';
const RUNTIME_KEY = 'active';

const EMPTY_RUNTIME = Object.freeze({
    version: 1,
    deploymentId: null,
    state: null,
    journal: null,
    pendingDeposit: null,
    depositQuote: null,
    preparedWithdrawal: null,
    lease: null,
    updatedAt: 0
});

let databasePromise = null;
let fallbackLock = Promise.resolve();

function requestResult(request) {
    return new Promise((resolve, reject) => {
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error || new Error('IndexedDB request failed.'));
    });
}

function transactionDone(transaction) {
    return new Promise((resolve, reject) => {
        transaction.oncomplete = () => resolve();
        transaction.onabort = () => reject(transaction.error || new Error('IndexedDB transaction aborted.'));
        transaction.onerror = () => reject(transaction.error || new Error('IndexedDB transaction failed.'));
    });
}

function openDatabase() {
    if (databasePromise) return databasePromise;
    let opening;
    opening = new Promise((resolve, reject) => {
        const request = indexedDB.open(DB_NAME, DB_VERSION);
        request.onupgradeneeded = () => {
            const database = request.result;
            if (!database.objectStoreNames.contains(RUNTIME_STORE)) {
                database.createObjectStore(RUNTIME_STORE);
            }
            if (!database.objectStoreNames.contains(ARCHIVE_STORE)) {
                database.createObjectStore(ARCHIVE_STORE, { keyPath: 'archiveId' });
            }
            if (!database.objectStoreNames.contains(WITHDRAWAL_STORE)) {
                database.createObjectStore(WITHDRAWAL_STORE, { keyPath: 'recordId' });
            }
            if (!database.objectStoreNames.contains(DEPOSIT_STORE)) {
                database.createObjectStore(DEPOSIT_STORE, { keyPath: 'recordId' });
            }
        };
        request.onsuccess = () => {
            const database = request.result;
            // A second browser tab may load newer wallet code while this tab is
            // still open. Closing here lets the upgrader proceed instead of
            // stranding durable withdrawal recovery behind a blocked DB.
            database.onversionchange = () => {
                if (databasePromise === opening) databasePromise = null;
                database.close();
            };
            resolve(database);
        };
        request.onerror = () => {
            if (databasePromise === opening) databasePromise = null;
            reject(request.error || new Error('Unable to open the browser wallet database.'));
        };
        request.onblocked = () => {
            if (databasePromise === opening) databasePromise = null;
            reject(new Error('A different tab is blocking the browser wallet upgrade.'));
        };
    });
    databasePromise = opening;
    return opening;
}

function normalizeRuntime(value) {
    return {
        ...EMPTY_RUNTIME,
        ...(value || {}),
        version: 1
    };
}

function durableTransaction(database, stores) {
    try {
        return database.transaction(stores, 'readwrite', { durability: 'strict' });
    } catch {
        return database.transaction(stores, 'readwrite');
    }
}

function positiveTimestamp(value) {
    return Number.isSafeInteger(Number(value)) && Number(value) > 0 ? Number(value) : null;
}

/** A canonical base58 Solana transaction signature, or null. */
function solanaSignature(value) {
    if (typeof value !== 'string') return null;
    try {
        base58Decode(value, 64, 'Solana transaction signature');
        return value;
    } catch {
        return null;
    }
}

function depositRecord(state, deploymentId, metadata = {}) {
    const noteId = Number(state?.note_id);
    const amount = Number(state?.deposit_amount);
    if (!deploymentId || state?.note_id == null || !Number.isSafeInteger(noteId) || noteId < 0
        || !Number.isSafeInteger(amount) || amount <= 0) return null;
    // This explicit allowlist is also the public payment-history shape. Never
    // copy a private state, commitment, secret, proof, or recovery plan here.
    return {
        recordId: `${deploymentId}:deposit:${noteId}`,
        type: 'deposit',
        deploymentId,
        operationId: typeof metadata.operationId === 'string' ? metadata.operationId : null,
        noteId,
        amount,
        expiryTs: positiveTimestamp(state?.expiry_ts ?? metadata.expiryTs),
        status: 'confirmed',
        createdAt: positiveTimestamp(metadata.createdAt),
        confirmedAt: positiveTimestamp(metadata.confirmedAt),
        transactionHash: solanaSignature(metadata.transactionHash)
    };
}

function mergeDepositRecord(records, candidate, store) {
    if (!candidate) return;
    const previous = records.get(candidate.recordId);
    const next = previous ? {
        ...candidate,
        // A reconstruction from note state has no date or signature evidence.
        // It must not replace what the confirming client recorded.
        createdAt: previous.createdAt || candidate.createdAt,
        confirmedAt: previous.confirmedAt || candidate.confirmedAt,
        transactionHash: previous.transactionHash || candidate.transactionHash,
        operationId: previous.operationId || candidate.operationId,
        expiryTs: previous.expiryTs || candidate.expiryTs
    } : candidate;
    if (JSON.stringify(previous) !== JSON.stringify(next)) store?.put(next);
    records.set(next.recordId, next);
}

function archiveDeploymentId(archive) {
    if (archive.deploymentId) return archive.deploymentId;
    const parts = String(archive.archiveId || '').split(':');
    const timestamp = parts.pop();
    const noteId = parts.pop();
    return /^\d+$/.test(timestamp || '') && String(archive.state?.note_id) === noteId
        ? parts.join(':') || null : null;
}

function depositRecordMap(records) {
    return new Map(records.map(record => depositRecord({
        note_id: record.noteId, deposit_amount: record.amount, expiry_ts: record.expiryTs
    }, record.deploymentId, record)).filter(Boolean).map(record => [record.recordId, record]));
}

// A deposit whose Solana journal exists may already have signed or landed
// transactions; it is shown as pending until its note is confirmed.
function pendingDepositRecords(runtime, deploymentId) {
    const pending = !deploymentId || runtime.deploymentId === deploymentId ? runtime.pendingDeposit : null;
    if (!pending?.solanaJournal) return [];
    const record = depositRecord({ note_id: pending.next_note_id, deposit_amount: pending.amount },
        runtime.deploymentId, pending);
    if (!record) return [];
    return [{ ...record, recordId: `${record.deploymentId}:deposit-pending:${record.operationId || record.noteId}`,
        status: 'pending', pendingPhase: 'submitting', createdAt: positiveTimestamp(pending.createdAt),
        confirmedAt: null }];
}

/** Project public rows without another fallible storage operation after commit. */
export function projectBrowserDeposits(runtime, records, deploymentId, depositConfirmation = {}) {
    const history = depositRecordMap((records || []).filter(record => record.status === 'confirmed'));
    mergeDepositRecord(history, depositRecord(runtime.state, runtime.deploymentId, depositConfirmation));
    const confirmed = [...history.values()].filter(record => !deploymentId || record.deploymentId === deploymentId);
    const pending = pendingDepositRecords(runtime, deploymentId).filter(record => !confirmed.some(deposit =>
        deposit.deploymentId === record.deploymentId
        && (deposit.operationId && record.operationId
            ? deposit.operationId === record.operationId
            : deposit.noteId === record.noteId && deposit.amount === record.amount)));
    return [...confirmed, ...pending].sort((left, right) =>
        Number(right.createdAt || right.confirmedAt || 0) - Number(left.createdAt || left.confirmedAt || 0));
}

/** Read recovery state and payment history from one consistent snapshot. */
export async function readBrowserWalletSnapshot(deploymentId = null) {
    const database = await openDatabase();
    const transaction = durableTransaction(database,
        [RUNTIME_STORE, WITHDRAWAL_STORE, ARCHIVE_STORE, DEPOSIT_STORE]);
    const [runtimeValue, records, archives, deposits] = await Promise.all([
        requestResult(transaction.objectStore(RUNTIME_STORE).get(RUNTIME_KEY)),
        requestResult(transaction.objectStore(WITHDRAWAL_STORE).getAll()),
        requestResult(transaction.objectStore(ARCHIVE_STORE).getAll()),
        requestResult(transaction.objectStore(DEPOSIT_STORE).getAll())
    ]);
    const runtime = normalizeRuntime(runtimeValue);
    const depositStore = transaction.objectStore(DEPOSIT_STORE);
    const history = depositRecordMap(deposits);
    mergeDepositRecord(history, depositRecord(runtime.state, runtime.deploymentId), depositStore);
    for (const record of records) {
        mergeDepositRecord(history, depositRecord(record.state, record.deploymentId), depositStore);
    }
    for (const archive of archives) {
        mergeDepositRecord(history, depositRecord(archive.state, archiveDeploymentId(archive)), depositStore);
    }
    await transactionDone(transaction);
    return {
        runtime,
        deposits: projectBrowserDeposits(runtime, [...history.values()], deploymentId),
        withdrawals: records
            .filter(record => !deploymentId || record.deploymentId === deploymentId)
            .sort((left, right) => Number(right.updatedAt || 0) - Number(left.updatedAt || 0))
    };
}

/**
 * Commit the entire private wallet snapshot in one IndexedDB write. The caller
 * must put a write-ahead journal here before transmitting a proved request and
 * clear it only in the same write that installs the verified next note state.
 */
export async function writeBrowserWallet(next, { depositConfirmation = null } = {}) {
    const database = await openDatabase();
    const transaction = durableTransaction(database, [RUNTIME_STORE, DEPOSIT_STORE]);
    const value = normalizeRuntime({ ...next, updatedAt: Date.now() });
    const depositStore = transaction.objectStore(DEPOSIT_STORE);
    const [current, deposits] = await Promise.all([
        requestResult(transaction.objectStore(RUNTIME_STORE).get(RUNTIME_KEY)),
        requestResult(depositStore.getAll())
    ]);
    const history = depositRecordMap(deposits);
    mergeDepositRecord(history, depositRecord(current?.state, current?.deploymentId), depositStore);
    mergeDepositRecord(history, depositRecord(value.state, value.deploymentId, depositConfirmation || {}), depositStore);
    transaction.objectStore(RUNTIME_STORE).put(value, RUNTIME_KEY);
    await transactionDone(transaction);
    return value;
}

export async function listBrowserWithdrawals(deploymentId = null) {
    const database = await openDatabase();
    const transaction = database.transaction(WITHDRAWAL_STORE, 'readonly');
    const records = await requestResult(transaction.objectStore(WITHDRAWAL_STORE).getAll());
    await transactionDone(transaction);
    return records
        .filter(record => !deploymentId || record.deploymentId === deploymentId)
        .sort((left, right) => Number(right.updatedAt || 0) - Number(left.updatedAt || 0));
}

/**
 * Move a chain-confirmed escape out of the selected wallet slot atomically.
 * The complete private state stays in the recovery record: a defeat returns
 * the note to Active, and the record must still prove what this device held.
 * An escape may leave with the request it made at the same state still in
 * flight (its successor withheld); that journal moves into the record, since
 * the escape's concession already pays for it.
 */
export async function detachBrowserEscapeWithdrawal(record) {
    if (!record?.recordId || record.noteId == null) {
        throw new Error('A pending escape requires a durable note identity.');
    }
    const database = await openDatabase();
    const transaction = durableTransaction(database, [RUNTIME_STORE, WITHDRAWAL_STORE]);
    const runtimeStore = transaction.objectStore(RUNTIME_STORE);
    const current = normalizeRuntime(await requestResult(runtimeStore.get(RUNTIME_KEY)));
    if (!current.state || Number(current.state.note_id) !== Number(record.noteId)) {
        transaction.abort();
        throw new Error('The selected private note changed before the escape could be saved.');
    }
    const withdrawalNullifier = current.preparedWithdrawal?.withdrawalNullifier
        || current.preparedWithdrawal?.public_inputs?.withdrawal_nullifier
        || record.withdrawalNullifier
        || null;
    const journalAtEscapedState = Boolean(current.journal) && withdrawalNullifier != null
        && sameFeltValue(current.journal.nullifier, withdrawalNullifier);
    if ((current.journal && !journalAtEscapedState) || (current.lease && !current.journal) || current.pendingDeposit) {
        transaction.abort();
        throw new Error('Finish the other private-balance operation before saving this escape.');
    }
    const now = Date.now();
    const durableRecord = {
        ...record,
        deploymentId: record.deploymentId || current.deploymentId,
        state: current.state,
        preparedWithdrawal: current.preparedWithdrawal,
        ...(current.journal ? { inFlightJournal: current.journal } : {}),
        clearanceReserved: current.preparedWithdrawal?.clearanceReserved === true
            || record.clearanceReserved === true,
        withdrawalNullifier,
        revision: 1,
        createdAt: Number(record.createdAt || now),
        updatedAt: now
    };
    transaction.objectStore(WITHDRAWAL_STORE).put(durableRecord);
    const next = normalizeRuntime({
        deploymentId: current.deploymentId,
        pendingDeposit: current.pendingDeposit,
        updatedAt: now
    });
    runtimeStore.put(next, RUNTIME_KEY);
    await transactionDone(transaction);
    return { runtime: next, withdrawal: durableRecord };
}

/**
 * Move a finalized mutual close out of the selected wallet slot without
 * deleting its recovery material in the same step; the caller sanitizes the
 * record once its closed state is recorded.
 */
export async function detachBrowserClosedWithdrawal(record) {
    if (!record?.recordId || record.noteId == null || !record.closeBlockNumber) {
        throw new Error('A closing withdrawal requires a durable note and slot identity.');
    }
    const database = await openDatabase();
    const transaction = durableTransaction(database, [RUNTIME_STORE, WITHDRAWAL_STORE]);
    const runtimeStore = transaction.objectStore(RUNTIME_STORE);
    const current = normalizeRuntime(await requestResult(runtimeStore.get(RUNTIME_KEY)));
    if (!current.state || Number(current.state.note_id) !== Number(record.noteId)) {
        transaction.abort();
        throw new Error('The selected private note changed before its close could be saved.');
    }
    if (current.journal || current.lease || current.pendingDeposit) {
        transaction.abort();
        throw new Error('Finish the other private-balance operation before saving this close.');
    }
    const now = Date.now();
    const durableRecord = {
        ...record,
        deploymentId: record.deploymentId || current.deploymentId,
        phase: 'closed_unconfirmed',
        state: current.state,
        preparedWithdrawal: current.preparedWithdrawal,
        clearanceReserved: current.preparedWithdrawal?.clearanceReserved === true
            || current.preparedWithdrawal?.mode === 'mutual'
            || record.clearanceReserved === true,
        withdrawalNullifier: current.preparedWithdrawal?.withdrawalNullifier
            || current.preparedWithdrawal?.public_inputs?.withdrawal_nullifier
            || record.withdrawalNullifier
            || null,
        revision: 1,
        createdAt: Number(record.createdAt || now),
        closedAt: Number(record.closedAt || now),
        updatedAt: now
    };
    transaction.objectStore(WITHDRAWAL_STORE).put(durableRecord);
    const next = normalizeRuntime({
        deploymentId: current.deploymentId,
        pendingDeposit: current.pendingDeposit,
        updatedAt: now
    });
    runtimeStore.put(next, RUNTIME_KEY);
    await transactionDone(transaction);
    return { runtime: next, withdrawal: durableRecord };
}

export async function updateBrowserWithdrawal(recordId, changes = {}, {
    sanitize = false,
    expectedRevision = null
} = {}) {
    const database = await openDatabase();
    const transaction = durableTransaction(database, [WITHDRAWAL_STORE, DEPOSIT_STORE]);
    const store = transaction.objectStore(WITHDRAWAL_STORE);
    const current = await requestResult(store.get(recordId));
    if (!current) {
        transaction.abort();
        throw new Error('The durable withdrawal record was not found.');
    }
    if (expectedRevision != null && Number(current.revision) !== Number(expectedRevision)) {
        transaction.abort();
        throw new Error('The withdrawal changed while its status was being checked.');
    }
    if (current.phase === 'closed' && changes.phase && changes.phase !== 'closed') {
        transaction.abort();
        throw new Error('A completed withdrawal cannot return to an earlier phase.');
    }
    const next = {
        ...current,
        ...changes,
        revision: Number(current.revision || 0) + 1,
        updatedAt: Date.now()
    };
    if (sanitize) {
        // Preserve the original deposit before finality removes the last copy
        // of the note's private recovery state.
        const depositStore = transaction.objectStore(DEPOSIT_STORE);
        const deposits = await requestResult(depositStore.getAll());
        mergeDepositRecord(depositRecordMap(deposits),
            depositRecord(current.state, current.deploymentId), depositStore);
        delete next.state;
        delete next.preparedWithdrawal;
        delete next.proof;
        delete next.withdrawalNullifier;
        delete next.inFlightJournal;
        delete next.solanaFinalizeOperationId;
        delete next.solanaFinalizationJournal;
    }
    store.put(next);
    await transactionDone(transaction);
    return next;
}

export async function requestPersistentStorage() {
    if (!navigator.storage?.persist) return false;
    try {
        if (await navigator.storage.persisted?.()) return true;
        return await navigator.storage.persist();
    } catch {
        return false;
    }
}

/** Serialize all wallet mutations across tabs. */
export async function withBrowserWalletLock(deploymentId, operation) {
    // The selected runtime uses one same-origin IndexedDB key. All deployment
    // manifests therefore share one mutation lock; deployment-scoped locks
    // could otherwise overwrite each other from separate tabs.
    const lockName = 'zkapi-wallet:active-runtime';
    if (navigator.locks?.request) {
        return navigator.locks.request(lockName, { mode: 'exclusive' }, operation);
    }
    const previous = fallbackLock;
    let release;
    fallbackLock = new Promise((resolve) => { release = resolve; });
    await previous;
    try {
        return await operation();
    } finally {
        release();
    }
}

export function createWalletChannel(deploymentId, onChange) {
    if (typeof BroadcastChannel === 'undefined') return { postMessage() {}, close() {} };
    const channel = new BroadcastChannel('zkapi-wallet:active-runtime');
    channel.addEventListener('message', (event) => onChange?.(event.data));
    return channel;
}
