import { browserSdkTransport } from '../configure.js';
import { canonicalChainId, sameChainId } from './zkapiLedgerIdentity.mjs';
import { base58Decode, base58Encode, inspectPreparedSolanaMessage }
    from './zkapiSolanaTransport.mjs';
import { parseUnits } from './zkapiNativeEth.mjs';

export const LAMPORTS_PER_SOL = 1_000_000_000n;
const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);
const UPGRADEABLE_LOADER = 'BPFLoaderUpgradeab1e11111111111111111111111';
const VAULT_DISCRIMINATOR = Uint8Array.from([228, 196, 82, 165, 98, 210, 235, 152]);
const NOTE_DISCRIMINATOR = Uint8Array.from([148, 41, 201, 122, 175, 58, 113, 83]);
const PENDING_DISCRIMINATOR = Uint8Array.from([61, 103, 179, 177, 148, 199, 63, 171]);
const VAULT_STATE_LENGTH = 375;
const NOTE_STATE_LENGTH = 110;
const PENDING_STATE_LENGTH = 173;
// Status 3 was the removed two-phase "challenged" state and stays reserved.
// A closed note keeps its leaf until a permissionless retirement.
const NOTE_STATUSES = new Map([
    [1, 'active'], [2, 'pending_withdrawal'], [4, 'closed'], [5, 'retired']
]);
const FELT = /^0x[0-9a-f]{64}$/i;
const FEED = /^0x[0-9a-f]{64}$/i;
const unsigned = value => /^(?:0|[1-9]\d*)$/.test(String(value));
const signed = value => /^(?:0|-?[1-9]\d*)$/.test(String(value));

function exactInteger(value, label, { minimum = null, maximum = null } = {}) {
    if (!(typeof value === 'number' && Number.isSafeInteger(value))
        && !(typeof value === 'string' && signed(value))) {
        throw new Error(`${label} must be an exact integer.`);
    }
    const parsed = BigInt(value);
    if ((minimum != null && parsed < BigInt(minimum)) || (maximum != null && parsed > BigInt(maximum))) {
        throw new Error(`${label} is outside its allowed range.`);
    }
    return parsed;
}

function account(value, label) {
    return base58Decode(value, 32, label);
}

function trustedRpcUrl(value) {
    const url = new URL(value);
    if (url.username || url.password || url.search || url.hash || (url.protocol !== 'https:'
        && !(url.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(url.hostname)))) {
        throw new Error('The native SOL deployment requires a credential-free trusted HTTPS or loopback RPC.');
    }
    return url.href;
}

export function isNativeSolFunding(funding) {
    return funding?.billing_asset === 'native_sol'
        && funding?.ledger_backend === 'dagon.solana.groth16.v1';
}

export function validateSolanaFunding(funding) {
    if (!isNativeSolFunding(funding)) {
        throw new Error('Unsupported Solana billing or ledger backend.');
    }
    if (typeof funding.chain_id !== 'string') {
        throw new Error('Solana chain IDs must be canonical decimal strings.');
    }
    canonicalChainId(funding.chain_id, 'Solana chain ID');
    if (!FELT.test(funding.contract_address || '') || /^0x0{64}$/i.test(funding.contract_address)
        || funding.billing_unit !== 'lamports'
        || String(funding.base_units_per_asset) !== String(LAMPORTS_PER_SOL)
        || !String(funding.wallet_standard_chain || '').startsWith('solana:')
        || !FEED.test(funding.pyth_feed_id || '')) {
        throw new Error('The native SOL deployment has invalid protocol or billing configuration.');
    }
    for (const [value, label] of [
        [funding.program_id, 'Solana program ID'],
        [funding.vault_state, 'Solana vault state'],
        [funding.genesis_hash, 'Solana genesis hash'],
        [funding.pyth_receiver_program, 'Pyth receiver program'],
        [funding.pyth_price_account, 'Pyth price account']
    ]) account(value, label);
    trustedRpcUrl(funding.rpc_url || funding.demo_rpc_url);
    if (!Number.isSafeInteger(funding.pyth_max_age_seconds)
        || funding.pyth_max_age_seconds < 1 || funding.pyth_max_age_seconds > 60
        || !Number.isSafeInteger(funding.pyth_max_confidence_bps)
        || funding.pyth_max_confidence_bps < 1 || funding.pyth_max_confidence_bps > 100) {
        throw new Error('The native SOL deployment has invalid Pyth safety bounds.');
    }
    return funding;
}

export function validateSolanaQuote(quote, funding, {
    now = Math.floor(Date.now() / 1000), allowExpired = false
} = {}) {
    validateSolanaFunding(funding);
    const price = exactInteger(quote?.price, 'Pyth price', { minimum: 1, maximum: (1n << 63n) - 1n });
    const confidence = exactInteger(quote?.confidence, 'Pyth confidence', { minimum: 0, maximum: (1n << 64n) - 1n });
    const exponent = exactInteger(quote?.exponent, 'Pyth exponent', { minimum: -18, maximum: 18 });
    const publishedAt = exactInteger(quote?.published_at, 'Pyth publication time', { minimum: 1, maximum: MAX_SAFE });
    const expiresAt = exactInteger(quote?.expires_at, 'Pyth expiry time', { minimum: 1, maximum: MAX_SAFE });
    const postedSlot = exactInteger(quote?.posted_slot, 'Pyth posted slot', { minimum: 1, maximum: (1n << 64n) - 1n });
    const lower = price - confidence;
    if (!quote || quote.asset !== 'native_sol' || quote.source !== 'pyth_receiver'
        || quote.credit_unit !== 'lamports'
        || String(quote.base_units_per_asset) !== String(LAMPORTS_PER_SOL)
        || !sameChainId(quote.chain_id, funding.chain_id)
        || String(quote.deployment_binding).toLowerCase() !== funding.contract_address.toLowerCase()
        || quote.backend !== funding.ledger_backend || quote.network !== funding.network
        || quote.vault !== funding.vault_state || quote.receiver_program !== funding.pyth_receiver_program
        || quote.price_account !== funding.pyth_price_account
        || String(quote.feed_id).toLowerCase() !== funding.pyth_feed_id.toLowerCase()
        || expiresAt !== publishedAt + BigInt(funding.pyth_max_age_seconds)
        || publishedAt > BigInt(now) || (!allowExpired && expiresAt <= BigInt(now))
        || lower <= 0n || confidence * 10_000n > price * BigInt(funding.pyth_max_confidence_bps)
        || postedSlot <= 0n || exponent < -18n || exponent > 18n) {
        throw new Error('The SOL/USD quote is invalid or stale. Please check again.');
    }
    return quote;
}

function priceRatio(quote) {
    const price = BigInt(quote.price) - BigInt(quote.confidence);
    const exponent = BigInt(quote.exponent);
    return exponent < 0n
        ? { numerator: price, denominator: 10n ** (-exponent) }
        : { numerator: price * 10n ** exponent, denominator: 1n };
}

export function solanaUnitsForUsd(usd, quote) {
    const micros = parseUnits(usd, 6);
    const price = priceRatio(quote);
    const numerator = micros * LAMPORTS_PER_SOL * price.denominator;
    const denominator = price.numerator * 1_000_000n;
    const amount = (numerator + denominator - 1n) / denominator;
    if (micros <= 0n || amount <= 0n || amount > MAX_SAFE) {
        throw new Error('Choose a smaller positive deposit amount.');
    }
    return amount;
}

export function solanaUsdMicros(amount, quote) {
    const units = BigInt(amount);
    if (units < 0n || units > MAX_SAFE) throw new Error('The native SOL amount exceeds the safe ledger range.');
    const price = priceRatio(quote);
    return units * price.numerator * 1_000_000n / (LAMPORTS_PER_SOL * price.denominator);
}

export function sameSolanaQuote(left, right) {
    return ['asset', 'source', 'credit_unit', 'base_units_per_asset', 'chain_id', 'deployment_binding',
        'backend', 'network', 'vault', 'receiver_program', 'price_account', 'feed_id', 'price',
        'confidence', 'exponent', 'published_at', 'expires_at', 'posted_slot']
        .every(key => String(left?.[key]).toLowerCase() === String(right?.[key]).toLowerCase());
}

export async function solanaRpc(funding, method, params, signal) {
    const response = await browserSdkTransport(funding.demo_rpc_url || funding.rpc_url, {
        method: 'POST', headers: { 'content-type': 'application/json' }, credentials: 'omit',
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }), signal, cache: 'no-store'
    }, { preferProxy: true });
    if (!response.ok) throw new Error('The Solana RPC is unavailable. Please check again.');
    const body = await response.json();
    if (body.error || body.result == null) throw new Error(`The Solana RPC rejected ${method}.`);
    return body.result;
}

/**
 * The pinned RPC's finalized block time (seconds): the clock the program
 * checks an exit proof's valid_until against.
 */
export async function readFinalizedSolanaTime(funding, { signal = AbortSignal.timeout(20_000) } = {}) {
    validateSolanaFunding(funding);
    if (await solanaRpc(funding, 'getGenesisHash', [], signal) !== funding.genesis_hash) {
        throw new Error('The Solana RPC is on the wrong cluster.');
    }
    const slot = await solanaRpc(funding, 'getSlot', [{ commitment: 'finalized' }], signal);
    if (!Number.isSafeInteger(slot) || slot < 0) throw new Error('The Solana RPC returned an invalid finalized slot.');
    const time = await solanaRpc(funding, 'getBlockTime', [slot], signal);
    if (!Number.isSafeInteger(time) || time < 0) throw new Error('The Solana RPC returned an invalid block time.');
    return time;
}

function base64(value) {
    const bytes = value instanceof Uint8Array ? value : Uint8Array.from(value || []);
    if (typeof btoa === 'function') {
        return btoa(String.fromCharCode(...bytes));
    }
    return Buffer.from(bytes).toString('base64');
}

function abortableDelay(milliseconds, signal) {
    return new Promise((resolve, reject) => {
        const timer = setTimeout(resolve, milliseconds);
        signal?.addEventListener('abort', () => {
            clearTimeout(timer);
            reject(signal.reason || new DOMException('The operation was aborted.', 'AbortError'));
        }, { once: true });
    });
}

/** Submit the exact journaled bytes and require the RPC to echo their signature. */
export async function sendSignedSolanaTransaction(funding, {
    bytes,
    signature
}, { signal = AbortSignal.timeout(20_000) } = {}) {
    validateSolanaFunding(funding);
    base58Decode(signature, 64, 'Solana transaction signature');
    const returned = await solanaRpc(funding, 'sendTransaction', [base64(bytes), {
        encoding: 'base64',
        skipPreflight: false,
        preflightCommitment: 'confirmed',
        maxRetries: 3
    }], signal);
    if (returned !== signature) {
        throw new Error('The Solana RPC returned a different transaction signature.');
    }
    return returned;
}

/**
 * Wait for backend finality, checking blockhash expiry only while the signature
 * is still wholly unknown. A processed transaction may finalize after its
 * recent blockhash has aged out, so expiry never overrides observed status.
 */
export async function confirmFinalizedSolanaTransaction(funding, {
    signature,
    lastValidHeight
}, {
    signal = AbortSignal.timeout(90_000),
    pollIntervalMs = 500
} = {}) {
    validateSolanaFunding(funding);
    base58Decode(signature, 64, 'Solana transaction signature');
    if (!Number.isSafeInteger(lastValidHeight) || lastValidHeight <= 0) {
        throw new Error('The prepared Solana transaction has no valid block-height deadline.');
    }
    if (!Number.isSafeInteger(pollIntervalMs) || pollIntervalMs < 0 || pollIntervalMs > 10_000) {
        throw new Error('The Solana confirmation polling interval is invalid.');
    }
    while (true) {
        const response = await solanaRpc(funding, 'getSignatureStatuses', [[signature], {
            searchTransactionHistory: true
        }], signal);
        if (!response || !Array.isArray(response.value) || response.value.length !== 1) {
            throw new Error('The Solana RPC returned malformed signature status.');
        }
        const status = response.value[0];
        if (status?.err != null) {
            const error = new Error('The Solana transaction failed on-chain.');
            error.transactionError = status.err;
            error.slot = status.slot;
            throw error;
        }
        if (status && (status.confirmationStatus === 'finalized' || status.confirmations === null)) {
            if (!Number.isSafeInteger(status.slot) || status.slot < 0) {
                throw new Error('The Solana RPC returned an invalid finalized slot.');
            }
            return Object.freeze({
                signature,
                slot: String(status.slot),
                confirmationStatus: 'finalized'
            });
        }
        if (!status) {
            const height = await solanaRpc(funding, 'getBlockHeight', [{ commitment: 'finalized' }], signal);
            if (!Number.isSafeInteger(height) || height < 0) {
                throw new Error('The Solana RPC returned an invalid finalized block height.');
            }
            if (height > lastValidHeight) {
                const error = new Error('The signed Solana transaction expired before it was observed.');
                error.code = 'solana_blockhash_expired';
                error.lastValidHeight = lastValidHeight;
                error.observedHeight = height;
                throw error;
            }
        }
        await abortableDelay(pollIntervalMs, signal);
    }
}

function accountData(value, label) {
    if (!Array.isArray(value?.data) || value.data[1] !== 'base64' || typeof value.data[0] !== 'string') {
        throw new Error(`${label} did not return canonical base64 account data.`);
    }
    if (typeof atob === 'function') {
        const decoded = atob(value.data[0]);
        return Uint8Array.from(decoded, character => character.charCodeAt(0));
    }
    return Uint8Array.from(Buffer.from(value.data[0], 'base64'));
}

function littleU32(bytes, offset = 0) {
    return (bytes[offset] | bytes[offset + 1] << 8 | bytes[offset + 2] << 16
        | bytes[offset + 3] << 24) >>> 0;
}

function littleU64(bytes, offset) {
    let result = 0n;
    for (let index = 7; index >= 0; index -= 1) {
        result = result << 8n | BigInt(bytes[offset + index]);
    }
    return result;
}

function equalBytes(left, right) {
    return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

function felt(bytes) {
    return `0x${Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('')}`;
}

function assertDiscriminator(bytes, discriminator, label, expectedLength) {
    if (bytes.length !== expectedLength || !equalBytes(bytes.slice(0, 8), discriminator)) {
        throw new Error(`${label} has invalid canonical account data.`);
    }
}

export function decodeSolanaVaultState(value) {
    const bytes = value instanceof Uint8Array ? value : Uint8Array.from(value || []);
    assertDiscriminator(bytes, VAULT_DISCRIMINATOR, 'Solana vault', VAULT_STATE_LENGTH);
    return Object.freeze({
        version: bytes[8],
        bump: bytes[9],
        paused: bytes[10] !== 0,
        authority: base58Encode(bytes.slice(11, 43)),
        treasury: base58Encode(bytes.slice(43, 75)),
        genesisHash: base58Encode(bytes.slice(75, 107)),
        chainId: littleU64(bytes, 107).toString(),
        protocolBinding: felt(bytes.slice(115, 147)),
        root: felt(bytes.slice(147, 179)),
        nextNoteId: littleU32(bytes, 179),
        noteTtl: littleU64(bytes, 183).toString(),
        challengePeriod: littleU64(bytes, 191).toString(),
        requestChargeCap: littleU64(bytes, 199).toString(),
        totalCredits: littleU64(bytes, 207).toString(),
        stateSigningKeyX: felt(bytes.slice(215, 247)),
        stateSigningKeyY: felt(bytes.slice(247, 279)),
        clearanceSigningKeyX: felt(bytes.slice(279, 311)),
        clearanceSigningKeyY: felt(bytes.slice(311, 343)),
        pausedAt: littleU64(bytes, 343).toString(),
        lastPauseEnd: littleU64(bytes, 351).toString(),
        totalPausedDuration: littleU64(bytes, 359).toString(),
        // Operator share retained by exits; swept by a permissionless call.
        treasuryAccrued: littleU64(bytes, 367).toString()
    });
}

export function decodeSolanaNoteState(value) {
    const bytes = value instanceof Uint8Array ? value : Uint8Array.from(value || []);
    assertDiscriminator(bytes, NOTE_DISCRIMINATOR, 'Solana note', NOTE_STATE_LENGTH);
    const status = NOTE_STATUSES.get(bytes[92]);
    if (!status) throw new Error('Solana note has an invalid status.');
    return Object.freeze({
        vault: base58Encode(bytes.slice(8, 40)),
        noteId: littleU32(bytes, 40),
        commitment: felt(bytes.slice(44, 76)),
        amount: littleU64(bytes, 76).toString(),
        expiry: littleU64(bytes, 84).toString(),
        status,
        bump: bytes[93],
        claimableAfter: littleU64(bytes, 94).toString(),
        pausedOffset: littleU64(bytes, 102).toString()
    });
}

export function decodeSolanaPendingWithdrawal(value) {
    const bytes = value instanceof Uint8Array ? value : Uint8Array.from(value || []);
    assertDiscriminator(bytes, PENDING_DISCRIMINATOR, 'Solana pending withdrawal', PENDING_STATE_LENGTH);
    const decoded = Object.freeze({
        vault: base58Encode(bytes.slice(8, 40)),
        noteId: littleU32(bytes, 40),
        nullifier: felt(bytes.slice(44, 76)),
        nextNullifier: felt(bytes.slice(76, 108)),
        stateBalance: littleU64(bytes, 108).toString(),
        conceded: littleU64(bytes, 116).toString(),
        finalBalance: littleU64(bytes, 124).toString(),
        destination: base58Encode(bytes.slice(132, 164)),
        deadline: littleU64(bytes, 164).toString(),
        bump: bytes[172]
    });
    if (BigInt(decoded.finalBalance) + BigInt(decoded.conceded) !== BigInt(decoded.stateBalance)) {
        throw new Error('Solana pending withdrawal has an inconsistent concession.');
    }
    return decoded;
}

async function finalizedAccount(funding, address, signal) {
    const result = await solanaRpc(funding, 'getAccountInfo', [address, {
        commitment: 'finalized', encoding: 'base64'
    }], signal);
    if (!result?.value) throw new Error(`Pinned Solana account ${address} does not exist.`);
    return result.value;
}

async function finalizedAccounts(funding, addresses, signal) {
    if (!Array.isArray(addresses) || addresses.length === 0 || addresses.length > 256) {
        throw new Error('A bounded Solana account list is required.');
    }
    for (const address of addresses) account(address, 'Solana account');
    const result = await solanaRpc(funding, 'getMultipleAccounts', [addresses, {
        commitment: 'finalized', encoding: 'base64'
    }], signal);
    if (!result || !Number.isSafeInteger(result.context?.slot) || result.context.slot < 0
        || !Array.isArray(result.value) || result.value.length !== addresses.length) {
        throw new Error('The Solana RPC returned malformed finalized accounts.');
    }
    return { slot: result.context.slot, values: result.value };
}

export async function assertSolanaVault(funding, { signal = AbortSignal.timeout(20_000) } = {}) {
    validateSolanaFunding(funding);
    const genesis = await solanaRpc(funding, 'getGenesisHash', [], signal);
    if (genesis !== funding.genesis_hash) throw new Error('The Solana RPC is on the wrong cluster.');
    const vault = await finalizedAccount(funding, funding.vault_state, signal);
    if (vault.owner !== funding.program_id || vault.executable !== false) {
        throw new Error('The pinned Solana vault is not owned by the configured program.');
    }
    const state = decodeSolanaVaultState(accountData(vault, 'Solana vault'));
    // `paused` is deliberately not an identity check: exits, finalization and
    // deposit confirmation must stay available while the owner keeps the flag
    // set (the program reopens exits after MAX_PAUSE_DURATION). New deposits
    // check `state.paused` themselves.
    if (state.version !== 1
        || state.genesisHash !== funding.genesis_hash
        || state.chainId !== funding.chain_id
        || state.protocolBinding.toLowerCase() !== funding.contract_address.toLowerCase()) {
        throw new Error('The pinned Solana vault runtime identity is invalid.');
    }
    const program = await finalizedAccount(funding, funding.program_id, signal);
    const programData = accountData(program, 'Solana program');
    if (program.owner !== UPGRADEABLE_LOADER || program.executable !== true
        || programData.length !== 36 || littleU32(programData) !== 2) {
        throw new Error('The pinned Solana program is not a canonical loader-v3 deployment.');
    }
    const programDataAddress = base58Encode(programData.slice(4, 36));
    const deployment = await finalizedAccount(funding, programDataAddress, signal);
    const deploymentData = accountData(deployment, 'Solana program data');
    if (deployment.owner !== UPGRADEABLE_LOADER || deployment.executable !== false
        || deploymentData.length < 13 || littleU32(deploymentData) !== 3
        || deploymentData[12] !== 0) {
        throw new Error('The pinned Solana program still has an upgrade authority.');
    }
    if (await solanaRpc(funding, 'getGenesisHash', [], signal) !== funding.genesis_hash) {
        throw new Error('The Solana RPC changed cluster during validation.');
    }
    return state;
}

/** New deposits only: the program refuses them while the pause flag is set. */
export function assertSolanaDepositsOpen(state) {
    if (state.paused) throw new Error('The Dagon vault is paused. New deposits reopen when its owner unpauses it.');
    return state;
}

/** Read and validate the semantic note or pending account referenced by a prepared operation. */
export async function readFinalizedSolanaOperationState(funding, operation, {
    noteId,
    signal = AbortSignal.timeout(20_000)
} = {}) {
    validateSolanaFunding(funding);
    if (!Number.isSafeInteger(noteId) || noteId < 0 || noteId > 0xffff_ffff) {
        throw new Error('A valid Solana note ID is required.');
    }
    const transactions = operation?.transactions;
    if (!Array.isArray(transactions) || transactions.length === 0) {
        throw new Error('The prepared Solana operation has no transactions.');
    }
    const inspected = inspectPreparedSolanaMessage(transactions.at(-1).bytes);
    const addresses = [...new Set(inspected.accounts.map(base58Encode))];
    const response = await finalizedAccounts(funding, addresses, signal);
    let note = null;
    let pending = null;
    for (let index = 0; index < addresses.length; index += 1) {
        const entry = response.values[index];
        if (!entry || entry.owner !== funding.program_id || entry.executable !== false) continue;
        const data = accountData(entry, `Solana operation account ${addresses[index]}`);
        if (data.length === NOTE_STATE_LENGTH && equalBytes(data.slice(0, 8), NOTE_DISCRIMINATOR)) {
            const candidate = decodeSolanaNoteState(data);
            if (candidate.vault === funding.vault_state && candidate.noteId === noteId) {
                if (note) throw new Error('The prepared Solana operation references duplicate note accounts.');
                note = Object.freeze({ ...candidate, address: addresses[index] });
            }
        } else if (data.length === PENDING_STATE_LENGTH
            && equalBytes(data.slice(0, 8), PENDING_DISCRIMINATOR)) {
            const candidate = decodeSolanaPendingWithdrawal(data);
            if (candidate.vault === funding.vault_state && candidate.noteId === noteId) {
                if (pending) throw new Error('The prepared Solana operation references duplicate pending accounts.');
                pending = Object.freeze({ ...candidate, address: addresses[index] });
            }
        }
    }
    return Object.freeze({ slot: String(response.slot), note, pending });
}

export async function readSolanaQuote(funding, { signal = AbortSignal.timeout(20_000) } = {}) {
    validateSolanaFunding(funding);
    const response = await browserSdkTransport(`${funding.protocol_server_url.replace(/\/+$/, '')}/v2/billing/quote`, {
        method: 'GET', credentials: 'omit', cache: 'no-store', signal
    });
    if (!response.ok) throw new Error('The Dagon SOL billing quote is unavailable.');
    return validateSolanaQuote(await response.json(), funding);
}

export { UPGRADEABLE_LOADER };
