const CONTRACT_ERRORS = Object.freeze({
    '0x09bde339': {
        code: 'invalid_proof',
        message: 'The vault rejected the withdrawal proof. Refresh the page and prepare the withdrawal again.'
    },
    '0x607447de': {
        code: 'stale_root',
        message: 'The vault changed while the deposit was being prepared. The Merkle path and proof must be refreshed.'
    },
    '0x947e59c5': {
        code: 'replayed_nullifier',
        message: 'This private state was already used or reserved. Check the withdrawal’s on-chain status before retrying.'
    },
    '0x4e8225b5': {
        code: 'superseded_state',
        message: 'The vault already saw this balance spent from a newer state, so this copy is outdated. Exit from the device holding the newest state.'
    },
    '0x3725bf1c': {
        code: 'exit_proof_expired',
        message: 'This withdrawal proof passed its validity deadline. Prepare the withdrawal again.'
    },
    '0xc8ae3189': {
        code: 'note_mismatch',
        message: 'The withdrawal proof does not match the note the vault stores.'
    },
    '0x1e9a749a': {
        code: 'note_expired',
        message: 'This private note has expired and can no longer be withdrawn.'
    },
    '0x9e87fac8': {
        code: 'vault_paused',
        message: 'The vault is paused. Exits reopen automatically when the pause ends or reaches its maximum length.'
    },
    '0xf06506c5': {
        code: 'challenge_expired',
        message: 'The escape’s challenge window has already closed.'
    },
    '0xd91d0281': {
        code: 'not_successor_nullifier',
        message: 'The escape does not publish a valid successor nullifier, or the evidence is not a request from that successor.'
    },
    '0xb9ab99df': {
        code: 'nullifier_mismatch',
        message: 'The concession evidence is not a request from the escaped state.'
    },
    '0xc0b6879e': {
        code: 'concession_not_raised',
        message: 'The escape already concedes at least this amount.'
    },
    '0x61a83aab': {
        code: 'note_not_active',
        message: 'This private note is no longer active. Check its on-chain withdrawal status.'
    },
    '0xc52e3eff': {
        code: 'invalid_balance',
        message: 'The withdrawal balance is not valid for this private note.'
    },
    '0x9722445b': {
        code: 'invalid_deployment',
        message: 'The withdrawal proof does not match this zkAPI deployment.'
    },
    '0x3be553f2': {
        code: 'not_pending_withdrawal',
        message: 'This note does not have an escape withdrawal waiting to be finalized.'
    },
    '0xf4b3b1bc': {
        code: 'native_transfer_failed',
        message: 'The vault could not return ETH to the withdrawal address.'
    },
    '0x2723e9c2': {
        code: 'invalid_native_value',
        message: 'The ETH transaction value does not match the private-note amount.'
    },
    '0x151f07fe': {
        code: 'challenge_not_expired',
        message: 'The escape safety window has not finished yet.'
    }
});

function matchingSelector(value) {
    if (typeof value !== 'string') return null;
    for (const match of value.matchAll(/0x[0-9a-fA-F]{8,}/g)) {
        const selector = match[0].slice(0, 10).toLowerCase();
        if (CONTRACT_ERRORS[selector]) return selector;
    }
    return null;
}

export function contractRevertSelector(error) {
    const queue = [error];
    const seen = new Set();
    while (queue.length) {
        const value = queue.shift();
        if (value == null || seen.has(value)) continue;
        if (typeof value === 'string') {
            const selector = matchingSelector(value);
            if (selector) return selector;
            try {
                queue.push(JSON.parse(value));
            } catch {
                // Most provider messages are plain text rather than JSON.
            }
            continue;
        }
        if (typeof value !== 'object') continue;
        seen.add(value);
        for (const nested of Object.values(value)) queue.push(nested);
    }
    return null;
}

export function contractEstimateError(error) {
    const selector = contractRevertSelector(error);
    const detail = selector ? CONTRACT_ERRORS[selector] : null;
    const providerMessage = error?.shortMessage || error?.message || String(error);
    const wrapped = new Error(detail?.message
        || `Transaction simulation failed: ${providerMessage}`);
    wrapped.name = 'ZkapiContractError';
    wrapped.code = detail?.code || 'gas_estimation_failed';
    wrapped.selector = selector;
    wrapped.cause = error;
    return wrapped;
}
