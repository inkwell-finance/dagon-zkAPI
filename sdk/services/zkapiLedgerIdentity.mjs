const U64_MAX = 18_446_744_073_709_551_615n;

/**
 * Parse a protocol chain identity without ever passing through Number. Solana
 * chain IDs are full u64 values derived from the genesis hash, so they are
 * carried as canonical decimal strings.
 */
export function chainIdBigInt(value, label = 'chain ID') {
    let parsed;
    if (typeof value === 'bigint') {
        parsed = value;
    } else if (typeof value === 'number') {
        if (!Number.isSafeInteger(value) || value < 0) {
            throw new TypeError(`${label} must be an exact unsigned 64-bit integer.`);
        }
        parsed = BigInt(value);
    } else if (typeof value === 'string' && /^(?:0|[1-9][0-9]*)$/.test(value)) {
        parsed = BigInt(value);
    } else {
        throw new TypeError(`${label} must be a canonical unsigned decimal integer.`);
    }
    if (parsed < 0n || parsed > U64_MAX) {
        throw new RangeError(`${label} is outside the unsigned 64-bit range.`);
    }
    return parsed;
}

/** Canonical, lossless comparison/storage key for a protocol chain identity. */
export function canonicalChainId(value, label = 'chain ID') {
    return chainIdBigInt(value, label).toString(10);
}

export function sameChainId(left, right) {
    try {
        return canonicalChainId(left) === canonicalChainId(right);
    } catch {
        return false;
    }
}

export { U64_MAX };
