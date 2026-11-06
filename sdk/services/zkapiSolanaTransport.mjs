const MESSAGE_FORMAT = 'solana-legacy-message-v1';
const SIGNED_TRANSACTION_FORMAT = 'solana-legacy-transaction-v1';
const PACKET_LIMIT = 1_232;
const ZERO_SIGNATURE_BYTES = 64;

function bytes(value, label) {
    if (value instanceof Uint8Array) return new Uint8Array(value);
    if (Array.isArray(value) && value.every(byte => Number.isInteger(byte) && byte >= 0 && byte <= 255)) {
        return Uint8Array.from(value);
    }
    throw new TypeError(`${label} must be a byte array.`);
}

function equalBytes(left, right) {
    return left.length === right.length && left.every((value, index) => value === right[index]);
}

function readShortVec(input, offset, label) {
    let value = 0;
    let shift = 0;
    for (let count = 0; count < 3; count += 1) {
        if (offset >= input.length) throw new Error(`${label} is truncated.`);
        const byte = input[offset++];
        value |= (byte & 0x7f) << shift;
        if ((byte & 0x80) === 0) {
            if (count > 0 && byte === 0) throw new Error(`${label} has a noncanonical length.`);
            return { value, offset };
        }
        shift += 7;
    }
    throw new Error(`${label} length is outside the legacy transaction limit.`);
}

function publicKeyBytes(value, label) {
    const result = bytes(value, label);
    if (result.length !== 32) throw new Error(`${label} must contain 32 bytes.`);
    return result;
}

/** Decode enough of a legacy Solana message to enforce the pinned signer and program. */
export function inspectPreparedSolanaMessage(value) {
    const message = bytes(value, 'prepared Solana message');
    if (message.length < 3 + 1 + 32 + 32 + 1 || message.length + 65 > PACKET_LIMIT) {
        throw new Error('Prepared Solana message is outside the packet limit.');
    }
    const requiredSignatures = message[0];
    if (requiredSignatures !== 1) {
        throw new Error('Dagon Solana wallet operations must require exactly one signature.');
    }
    let cursor = 3;
    const accountCount = readShortVec(message, cursor, 'Solana account list');
    cursor = accountCount.offset;
    if (accountCount.value < 2 || accountCount.value > 255) {
        throw new Error('Prepared Solana message has an invalid account list.');
    }
    const accountsEnd = cursor + accountCount.value * 32;
    if (accountsEnd + 32 > message.length) throw new Error('Prepared Solana account list is truncated.');
    const accounts = Array.from({ length: accountCount.value }, (_, index) => (
        message.slice(cursor + index * 32, cursor + (index + 1) * 32)
    ));
    cursor = accountsEnd + 32; // Skip recent blockhash.
    const instructionCount = readShortVec(message, cursor, 'Solana instruction list');
    cursor = instructionCount.offset;
    if (instructionCount.value < 1 || instructionCount.value > 3) {
        throw new Error('Each prepared Dagon Solana transaction must contain one vault instruction and at most two compute-budget instructions.');
    }
    let program;
    let vaultAccounts;
    const budgets = new Set();
    for (let index = 0; index < instructionCount.value; index += 1) {
        if (cursor >= message.length) throw new Error('Prepared Solana instruction is truncated.');
        const programIndex = message[cursor++];
        if (programIndex >= accounts.length) throw new Error('Prepared Solana program index is invalid.');
        const instructionAccounts = readShortVec(message, cursor, 'Solana instruction accounts');
        const accountsStart = instructionAccounts.offset;
        cursor = accountsStart + instructionAccounts.value;
        if (cursor > message.length) throw new Error('Prepared Solana instruction accounts are truncated.');
        const indices = message.slice(accountsStart, cursor);
        if (indices.some(accountIndex => accountIndex >= accounts.length)) {
            throw new Error('Prepared Solana instruction account index is invalid.');
        }
        const data = readShortVec(message, cursor, 'Solana instruction data');
        cursor = data.offset + data.value;
        if (cursor > message.length) throw new Error('Prepared Solana instruction data is truncated.');
        program = accounts[programIndex];
        if (index === instructionCount.value - 1) {
            vaultAccounts = Array.from(indices, accountIndex => accounts[accountIndex]);
            continue;
        }
        // Only the ledger's bounded heap/CU requests may precede the vault.
        // In particular never accept a priority-fee instruction from the server.
        const kind = message[data.offset];
        if (!equalBytes(program, COMPUTE_BUDGET_PROGRAM) || indices.length !== 0
            || data.value !== 5 || ![1, 2].includes(kind) || budgets.has(kind)) {
            throw new Error('Prepared Solana compute budget is not authorized.');
        }
        const amount = new DataView(message.buffer, message.byteOffset + data.offset + 1, 4)
            .getUint32(0, true);
        if (kind === 1 ? amount < 32_768 || amount > 262_144 || amount % 1_024 !== 0
            : amount === 0 || amount > 1_400_000) {
            throw new Error('Prepared Solana compute budget exceeds its limit.');
        }
        budgets.add(kind);
    }
    if (cursor !== message.length) throw new Error('Prepared Solana instruction data is malformed.');
    return Object.freeze({ message, accounts, payer: accounts[0], program, vaultAccounts });
}

export function unsignedSolanaTransaction(message) {
    const inspected = inspectPreparedSolanaMessage(message);
    const transaction = new Uint8Array(1 + ZERO_SIGNATURE_BYTES + inspected.message.length);
    transaction[0] = 1;
    transaction.set(inspected.message, 1 + ZERO_SIGNATURE_BYTES);
    return transaction;
}

function signedTransaction(value, expectedMessage) {
    const transaction = bytes(value, 'signed Solana transaction');
    if (transaction.length > PACKET_LIMIT || transaction.length !== expectedMessage.length + 65
        || transaction[0] !== 1 || !equalBytes(transaction.slice(65), expectedMessage)) {
        throw new Error('The wallet changed the prepared Solana transaction message.');
    }
    const signature = transaction.slice(1, 65);
    if (signature.every(byte => byte === 0)) throw new Error('The wallet returned an unsigned Solana transaction.');
    return { transaction, signature };
}

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const BASE58_INDEX = new Map(Array.from(BASE58_ALPHABET, (character, index) => [character, index]));
const COMPUTE_BUDGET_PROGRAM = base58Decode('ComputeBudget111111111111111111111111111111', 32);

export function base58Encode(value) {
    const input = bytes(value, 'base58 input');
    if (!input.length) return '';
    const digits = [0];
    for (const byte of input) {
        let carry = byte;
        for (let index = 0; index < digits.length; index += 1) {
            const current = digits[index] * 256 + carry;
            digits[index] = current % 58;
            carry = Math.floor(current / 58);
        }
        while (carry) {
            digits.push(carry % 58);
            carry = Math.floor(carry / 58);
        }
    }
    let result = '';
    for (let index = 0; index < input.length - 1 && input[index] === 0; index += 1) result += '1';
    for (let index = digits.length - 1; index >= 0; index -= 1) result += BASE58_ALPHABET[digits[index]];
    return result;
}

export function base58Decode(value, expectedLength = null, label = 'base58 value') {
    if (typeof value !== 'string' || !value) throw new TypeError(`${label} must be a base58 string.`);
    const output = [0];
    for (const character of value) {
        const digit = BASE58_INDEX.get(character);
        if (digit == null) throw new TypeError(`${label} contains a non-base58 character.`);
        let carry = digit;
        for (let index = 0; index < output.length; index += 1) {
            const current = output[index] * 58 + carry;
            output[index] = current & 0xff;
            carry = current >> 8;
        }
        while (carry) {
            output.push(carry & 0xff);
            carry >>= 8;
        }
    }
    let leadingZeroes = 0;
    while (leadingZeroes < value.length - 1 && value[leadingZeroes] === '1') leadingZeroes += 1;
    const decoded = Uint8Array.from([
        ...new Uint8Array(leadingZeroes),
        ...output.reverse()
    ]);
    if (expectedLength != null && decoded.length !== expectedLength) {
        throw new Error(`${label} must decode to ${expectedLength} bytes.`);
    }
    if (base58Encode(decoded) !== value) throw new Error(`${label} is not canonically encoded.`);
    return decoded;
}

function validatedTransaction(prepared, account, programId, vaultState) {
    if (!prepared || prepared.format !== MESSAGE_FORMAT) {
        throw new Error(`Prepared wallet transaction must use ${MESSAGE_FORMAT}.`);
    }
    if (!Array.isArray(prepared.required_signers) || prepared.required_signers.length !== 1) {
        throw new Error('Prepared wallet transaction has an invalid signer set.');
    }
    const accountKey = publicKeyBytes(account?.publicKey, 'wallet account public key');
    const requiredSigner = publicKeyBytes(prepared.required_signers[0], 'required signer');
    const pinnedProgram = publicKeyBytes(programId, 'pinned Dagon program ID');
    const pinnedVault = publicKeyBytes(vaultState, 'pinned Dagon vault state');
    const inspected = inspectPreparedSolanaMessage(prepared.bytes);
    if (!equalBytes(requiredSigner, accountKey) || !equalBytes(inspected.payer, accountKey)) {
        throw new Error('Prepared Solana transaction requires a different wallet account.');
    }
    if (!equalBytes(inspected.program, pinnedProgram)) {
        throw new Error('Prepared Solana transaction targets a different program.');
    }
    // Every vault-program wallet instruction takes the vault as account zero.
    // An unused key or trailing Anchor remaining-account is not a deployment pin.
    if (!inspected.vaultAccounts.length || !equalBytes(inspected.vaultAccounts[0], pinnedVault)) {
        throw new Error('Prepared Solana transaction does not use the pinned vault state.');
    }
    if (!Number.isSafeInteger(prepared.last_valid_height) || prepared.last_valid_height <= 0) {
        throw new Error('Prepared Solana transaction omitted its last valid block height.');
    }
    return inspected.message;
}

/**
 * Validate every prepared message before any wallet prompt is opened.
 *
 * Keeping this as a public, side-effect-free gate lets the durable journal
 * reject a foreign or malformed operation before it stores recovery bytes.
 */
export function validatePreparedSolanaOperation({ operation, payer, programId, vaultState }) {
    const transactions = operation?.transactions;
    if (!Array.isArray(transactions) || transactions.length === 0) {
        throw new Error('Prepared Solana operation contains no transactions.');
    }
    const account = { publicKey: publicKeyBytes(payer, 'wallet payer') };
    return Object.freeze(transactions.map(prepared => validatedTransaction(
        prepared,
        account,
        programId,
        vaultState
    )));
}

/**
 * Sign, durably journal, submit, and confirm an ordered Solana operation.
 *
 * `onSigned` is deliberately before `sendSignedTransaction`: callers persist
 * the deterministic signature and signed bytes before any broadcast can occur.
 * Supplying `signedTransactions[index]` resumes without opening the wallet.
 */
export async function submitPreparedSolanaOperation({
    wallet,
    account,
    chain,
    operation,
    programId,
    vaultState,
    signedTransactions = [],
    startIndex = 0,
    onSigned = async () => {},
    onSubmitted = async () => {},
    onConfirmed = async () => {},
    sendSignedTransaction,
    confirmTransaction,
    onProgress = () => {}
}) {
    const transactions = operation?.transactions;
    if (!Array.isArray(transactions) || transactions.length === 0) {
        throw new Error('Prepared Solana operation contains no transactions.');
    }
    if (!Number.isSafeInteger(startIndex) || startIndex < 0 || startIndex > transactions.length) {
        throw new Error('Solana operation recovery index is invalid.');
    }
    if (typeof sendSignedTransaction !== 'function' || typeof confirmTransaction !== 'function') {
        throw new TypeError('Solana submission and confirmation callbacks are required.');
    }
    if (typeof chain !== 'string' || !chain.startsWith('solana:')) {
        throw new Error('A Wallet Standard Solana chain identifier is required.');
    }
    const signer = wallet?.features?.['solana:signTransaction'];
    if (!signer || typeof signer.signTransaction !== 'function') {
        throw new Error('The selected wallet does not support durable Solana transaction signing.');
    }
    if (!account?.features?.includes?.('solana:signTransaction') || !account?.chains?.includes?.(chain)) {
        throw new Error('The selected wallet account does not support this Solana cluster.');
    }
    const results = [];
    for (let index = startIndex; index < transactions.length; index += 1) {
        const prepared = transactions[index];
        const message = validatedTransaction(prepared, account, programId, vaultState);
        let signed;
        const saved = signedTransactions[index];
        if (saved) {
            signed = signedTransaction(saved, message);
            onProgress({ phase: 'resuming', index, total: transactions.length });
        } else {
            onProgress({ phase: 'signing', index, total: transactions.length });
            const outputs = await signer.signTransaction({
                account,
                chain,
                transaction: unsignedSolanaTransaction(message)
            });
            if (!Array.isArray(outputs) || outputs.length !== 1) {
                throw new Error('The wallet returned an invalid Solana signing response.');
            }
            signed = signedTransaction(outputs[0]?.signedTransaction, message);
            await onSigned({
                index,
                total: transactions.length,
                signature: base58Encode(signed.signature),
                signedTransaction: signed.transaction,
                format: SIGNED_TRANSACTION_FORMAT,
                lastValidHeight: prepared.last_valid_height
            });
        }
        const signature = base58Encode(signed.signature);
        onProgress({ phase: 'submitting', index, total: transactions.length, signature });
        const submitted = await sendSignedTransaction({
            index,
            signature,
            format: SIGNED_TRANSACTION_FORMAT,
            bytes: signed.transaction,
            lastValidHeight: prepared.last_valid_height
        });
        if (submitted != null && String(submitted) !== signature) {
            throw new Error('The Solana RPC returned a different transaction signature.');
        }
        await onSubmitted({
            index,
            total: transactions.length,
            signature,
            lastValidHeight: prepared.last_valid_height
        });
        onProgress({ phase: 'confirming', index, total: transactions.length, signature });
        const confirmation = await confirmTransaction({
            index,
            signature,
            lastValidHeight: prepared.last_valid_height
        });
        await onConfirmed({
            index,
            total: transactions.length,
            signature,
            lastValidHeight: prepared.last_valid_height,
            confirmation
        });
        results.push(Object.freeze({
            index,
            signature,
            lastValidHeight: prepared.last_valid_height,
            confirmation
        }));
    }
    return Object.freeze(results);
}

export { MESSAGE_FORMAT, SIGNED_TRANSACTION_FORMAT };
