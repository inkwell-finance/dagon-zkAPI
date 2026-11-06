// Wallet Standard wallets may reject with a serialized error object instead of
// an Error. Keep the useful message without printing the object.
export function walletErrorMessage(error, fallback = 'The wallet could not complete this request.') {
    const seen = new Set();
    const message = (value, depth = 0) => {
        if (depth > 5 || value == null) return null;
        if (typeof value === 'string') {
            const text = value.trim();
            return text && text !== '[object Object]' ? text : null;
        }
        if (typeof value !== 'object' || seen.has(value)) return null;
        seen.add(value);
        for (const field of ['shortMessage', 'message', 'reason', 'error', 'cause', 'originalError', 'data']) {
            const found = message(value[field], depth + 1);
            if (found) return found;
        }
        return null;
    };
    return message(error) || fallback;
}
