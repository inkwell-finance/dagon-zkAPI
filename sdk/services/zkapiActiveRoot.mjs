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

// Retry only a mismatch against the expected finalized root. A missing note
// at a matching root is inconsistent, not lag: retrying based on the private
// note ID would let a malicious indexer probe it with fabricated note counts.
// `expectedActiveRoot` is a fixed root or an async reader re-read each attempt,
// so a vault that moves while we wait is followed. Without a root constraint
// there is no trusted lag signal, so the first snapshot is checked once.
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
        const atRoot = root == null || sameFelt(snapshot?.root, root);
        if (atRoot) {
            if (requiredNoteId != null && !(Number(snapshot?.next_note_id) > Number(requiredNoteId))) {
                const error = new Error('The zkAPI indexer snapshot is inconsistent with the required note.');
                error.code = 'indexer_inconsistent';
                throw error;
            }
            return snapshot;
        }
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
