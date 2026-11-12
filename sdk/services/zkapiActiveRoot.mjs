// Deposit and request proofs carry a Merkle path to the vault's active root;
// exits are leaf-bound and never read a root.
export function sameFelt(left, right) {
    try {
        return BigInt(left) === BigInt(right);
    } catch {
        return false;
    }
}

export const INDEXER_LAG_MAX_WAIT_MS = 12_000;
const INDEXER_LAG_INITIAL_DELAY_MS = 250;
const INDEXER_LAG_MAX_DELAY_MS = 2_000;

// The indexer mirrors the finalized vault on its own poll, so right after a
// deposit (or any vault update) its snapshot can lack the newest note or root.
// That is lag, not an inconsistency: retry the snapshot with bounded backoff
// and only hand a snapshot that holds `requiredNoteId` at the expected root to
// the proof worker. `expectedActiveRoot` is a fixed root or an async reader
// that is re-read on every attempt, so a vault that moves on while we wait is
// followed. Without either constraint the first snapshot is returned.
export async function waitForTreeSnapshot(loadSnapshot, {
    requiredNoteId = null,
    expectedActiveRoot = null,
    signal = null,
    maxWaitMs = INDEXER_LAG_MAX_WAIT_MS,
    initialDelayMs = INDEXER_LAG_INITIAL_DELAY_MS,
    maxDelayMs = INDEXER_LAG_MAX_DELAY_MS,
    now = Date.now,
    sleep = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds))
} = {}) {
    const readExpectedRoot = typeof expectedActiveRoot === 'function'
        ? expectedActiveRoot
        : async () => expectedActiveRoot;
    const deadline = now() + maxWaitMs;
    let delayMs = initialDelayMs;
    while (true) {
        signal?.throwIfAborted();
        const [snapshot, root] = await Promise.all([loadSnapshot(), readExpectedRoot()]);
        signal?.throwIfAborted();
        const holdsNote = requiredNoteId == null
            || Number(snapshot?.next_note_id) > Number(requiredNoteId);
        const atRoot = root == null || sameFelt(snapshot?.root, root);
        if (holdsNote && atRoot) return snapshot;
        if (now() + delayMs > deadline) break;
        await sleep(delayMs);
        signal?.throwIfAborted();
        if (now() > deadline) break;
        delayMs = Math.min(delayMs * 2, maxDelayMs);
    }
    const error = new Error('The zkAPI indexer is still catching up with the latest vault root. Try again in a few seconds.');
    error.code = 'indexer_root_lag';
    throw error;
}
