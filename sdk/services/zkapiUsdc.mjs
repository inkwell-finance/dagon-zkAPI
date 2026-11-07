import { PublicKey, SystemProgram, TransactionInstruction } from '@solana/web3.js';
import { browserSdkTransport } from '../configure.js';
import { canonicalChainId } from './zkapiLedgerIdentity.mjs';
import { base58Decode, base58Encode, inspectPreparedSolanaMessage }
    from './zkapiSolanaTransport.mjs';

export function parseUnits(value, decimals) {
    const match = String(value).trim().match(new RegExp(`^(\\d+)(?:\\.(\\d{0,${decimals}}))?$`));
    if (!match) throw new Error(`Enter a positive amount with no more than ${decimals} decimal places.`);
    return BigInt(match[1]) * (10n ** BigInt(decimals))
        + BigInt((match[2] || '').padEnd(decimals, '0') || '0');
}

export function formatUnits(value, decimals) {
    const amount = BigInt(value);
    if (amount < 0n) throw new Error('Amounts cannot be negative.');
    const scale = 10n ** BigInt(decimals);
    const fraction = (amount % scale).toString().padStart(decimals, '0').replace(/0+$/, '');
    return `${amount / scale}${fraction ? `.${fraction}` : ''}`;
}

// The vault's only asset: Circle USDC under the classic SPL Token program
// (`dagon_zkapi_vault::token`). One base unit is one micro-USDC, which the
// operator bills as one micro-USD. Token-2022 is rejected everywhere.
export const USDC_MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
export const USDC_DECIMALS = 6;
export const MICRO_USDC_PER_USDC = 1_000_000n;
export const TOKEN_PROGRAM_ID = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
export const TOKEN_2022_PROGRAM_ID = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb';
export const ASSOCIATED_TOKEN_PROGRAM_ID = 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL';
const SYSTEM_PROGRAM_ID = '11111111111111111111111111111111';
const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);
const UPGRADEABLE_LOADER = 'BPFLoaderUpgradeab1e11111111111111111111111';
const VAULT_DISCRIMINATOR = Uint8Array.from([228, 196, 82, 165, 98, 210, 235, 152]);
const NOTE_DISCRIMINATOR = Uint8Array.from([148, 41, 201, 122, 175, 58, 113, 83]);
const PENDING_DISCRIMINATOR = Uint8Array.from([61, 103, 179, 177, 148, 199, 63, 171]);
// sha256("global:execute_deposit")[..8], the Anchor instruction discriminator.
const EXECUTE_DEPOSIT_DISCRIMINATOR = Uint8Array.from([247, 103, 46, 184, 88, 188, 56, 46]);
const VAULT_STATE_LENGTH = 448;
const NOTE_STATE_LENGTH = 110;
const PENDING_STATE_LENGTH = 206;
// Classic SPL Token account: mint 0..32, owner 32..64, amount 64..72, state 108.
const TOKEN_ACCOUNT_LENGTH = 165;
const TOKEN_ACCOUNT_INITIALIZED = 1;
const TOKEN_ACCOUNT_FROZEN = 2;
// Status 3 was the removed two-phase "challenged" state and stays reserved.
// A closed note keeps its leaf until a permissionless retirement.
const NOTE_STATUSES = new Map([
    [1, 'active'], [2, 'pending_withdrawal'], [4, 'closed'], [5, 'retired']
]);
// PendingWithdrawal.stage: only an open escape is challengeable or
// finalizable; a parked payout waits for `release_escape_payout`; a paid
// escape whose escaper address became executable parks only its rent.
const PENDING_STAGES = new Map([[0, 'open'], [1, 'payout_parked'], [2, 'rent_parked']]);
const FELT = /^0x[0-9a-f]{64}$/i;
const utf8 = value => new TextEncoder().encode(value);

function account(value, label) {
    return base58Decode(value, 32, label);
}

function trustedRpcUrl(value) {
    const url = new URL(value);
    if (url.username || url.password || url.search || url.hash || (url.protocol !== 'https:'
        && !(url.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(url.hostname)))) {
        throw new Error('The Dagon USDC deployment requires a credential-free trusted HTTPS or loopback RPC.');
    }
    return url.href;
}

export function isUsdcFunding(funding) {
    return funding?.billing_asset === 'usdc'
        && funding?.ledger_backend === 'dagon.solana.groth16.v1';
}

export function validateSolanaFunding(funding) {
    if (!isUsdcFunding(funding)) {
        throw new Error('Unsupported Solana billing or ledger backend.');
    }
    if (typeof funding.chain_id !== 'string') {
        throw new Error('Solana chain IDs must be canonical decimal strings.');
    }
    canonicalChainId(funding.chain_id, 'Solana chain ID');
    if (!FELT.test(funding.contract_address || '') || /^0x0{64}$/i.test(funding.contract_address)
        || funding.billing_unit !== 'micro_usdc'
        || String(funding.base_units_per_asset) !== String(MICRO_USDC_PER_USDC)
        || !String(funding.wallet_standard_chain || '').startsWith('solana:')) {
        throw new Error('The Dagon USDC deployment has invalid protocol or billing configuration.');
    }
    if (funding.usdc_mint !== USDC_MINT || funding.token_program !== TOKEN_PROGRAM_ID
        || funding.associated_token_program !== ASSOCIATED_TOKEN_PROGRAM_ID) {
        throw new Error('The Dagon deployment must settle in Circle USDC under the classic SPL Token program.');
    }
    for (const [value, label] of [
        [funding.program_id, 'Solana program ID'],
        [funding.vault_state, 'Solana vault state'],
        [funding.genesis_hash, 'Solana genesis hash']
    ]) account(value, label);
    trustedRpcUrl(funding.rpc_url);
    return funding;
}

/** USDC base units (micro-USD) of a positive decimal amount with at most six decimals. */
export function usdcBaseUnits(value) {
    const amount = parseUnits(value, USDC_DECIMALS);
    if (amount <= 0n || amount > MAX_SAFE) throw new Error('Choose a smaller positive USDC amount.');
    return amount;
}

/** The next f64 below a positive finite `value` (Rust `f64::next_down`). */
function nextDown(value) {
    const view = new DataView(new ArrayBuffer(8));
    view.setFloat64(0, value);
    view.setBigUint64(0, view.getBigUint64(0) - 1n);
    return view.getFloat64(0);
}

/**
 * The OpenRouter child-key limit the server must set for a request proof:
 * `solvency_bound` micro-USD as dollars, never rounded above the bound. This
 * mirrors `zkapi-serverd` `pricing::micro_usd_to_usd`: `bound / 1e6`, stepped
 * one ulp down when that quotient times 1e6 exceeds the bound.
 */
export function leaseLimitUsd(solvencyBound) {
    const bound = BigInt(solvencyBound);
    if (bound <= 0n || bound > MAX_SAFE) throw new Error('The request bound is outside the lease range.');
    const micros = Number(bound);
    const scale = Number(MICRO_USDC_PER_USDC);
    const candidate = micros / scale;
    return candidate * scale > micros ? nextDown(candidate) : candidate;
}

function publicKey(value, label) {
    return new PublicKey(account(value, label));
}

/** The canonical USDC associated token account of `owner` (base58). */
export function usdcAssociatedTokenAddress(owner) {
    return PublicKey.findProgramAddressSync([
        publicKey(owner, 'USDC account owner').toBytes(),
        new PublicKey(TOKEN_PROGRAM_ID).toBytes(),
        new PublicKey(USDC_MINT).toBytes()
    ], new PublicKey(ASSOCIATED_TOKEN_PROGRAM_ID))[0].toBase58();
}

/** The vault's own USDC token account: PDA `["vault-token", vault_state]` of the program. */
export function vaultTokenAddress(programId, vaultState) {
    return PublicKey.findProgramAddressSync(
        [utf8('vault-token'), publicKey(vaultState, 'Solana vault state').toBytes()],
        publicKey(programId, 'Solana program ID')
    )[0].toBase58();
}

/**
 * The exact account list of the ATA program's `CreateIdempotent` for the
 * canonical USDC account of `owner`, rent paid by `payer`.
 */
export function usdcAccountCreationKeys({ payer, owner }) {
    return [
        { pubkey: publicKey(payer, 'USDC account rent payer'), isSigner: true, isWritable: true },
        { pubkey: new PublicKey(usdcAssociatedTokenAddress(owner)), isSigner: false, isWritable: true },
        { pubkey: publicKey(owner, 'USDC account owner'), isSigner: false, isWritable: false },
        { pubkey: new PublicKey(USDC_MINT), isSigner: false, isWritable: false },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
        { pubkey: new PublicKey(TOKEN_PROGRAM_ID), isSigner: false, isWritable: false }
    ];
}

/** Associated Token Account program `CreateIdempotent` (instruction data `[1]`). */
export function createUsdcAccountIdempotentInstruction({ payer, owner }) {
    return new TransactionInstruction({
        programId: new PublicKey(ASSOCIATED_TOKEN_PROGRAM_ID),
        keys: usdcAccountCreationKeys({ payer, owner }),
        data: Uint8Array.of(1)
    });
}

export async function solanaRpc(funding, method, params, signal) {
    const response = await browserSdkTransport(funding.rpc_url, {
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
        treasuryToken: base58Encode(bytes.slice(43, 75)),
        mint: base58Encode(bytes.slice(75, 107)),
        vaultToken: base58Encode(bytes.slice(107, 139)),
        vaultTokenBump: bytes[139],
        genesisHash: base58Encode(bytes.slice(140, 172)),
        chainId: littleU64(bytes, 172).toString(),
        protocolBinding: felt(bytes.slice(180, 212)),
        root: felt(bytes.slice(212, 244)),
        nextNoteId: littleU32(bytes, 244),
        noteTtl: littleU64(bytes, 248).toString(),
        challengePeriod: littleU64(bytes, 256).toString(),
        requestChargeCap: littleU64(bytes, 264).toString(),
        totalCredits: littleU64(bytes, 272).toString(),
        stateSigningKeyX: felt(bytes.slice(280, 312)),
        stateSigningKeyY: felt(bytes.slice(312, 344)),
        clearanceSigningKeyX: felt(bytes.slice(344, 376)),
        clearanceSigningKeyY: felt(bytes.slice(376, 408)),
        pausedAt: littleU64(bytes, 408).toString(),
        lastPauseEnd: littleU64(bytes, 416).toString(),
        totalPausedDuration: littleU64(bytes, 424).toString(),
        // Operator share retained by exits; swept by a permissionless call.
        treasuryAccrued: littleU64(bytes, 432).toString(),
        // Escape payouts parked until `release_escape_payout` can credit them.
        deferredPayouts: littleU64(bytes, 440).toString()
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
    const stage = PENDING_STAGES.get(bytes[205]);
    if (!stage) throw new Error('Solana pending withdrawal has an invalid stage.');
    const decoded = Object.freeze({
        vault: base58Encode(bytes.slice(8, 40)),
        noteId: littleU32(bytes, 40),
        nullifier: felt(bytes.slice(44, 76)),
        nextNullifier: felt(bytes.slice(76, 108)),
        stateBalance: littleU64(bytes, 108).toString(),
        conceded: littleU64(bytes, 116).toString(),
        finalBalance: littleU64(bytes, 124).toString(),
        // The proof-bound payout token account.
        destination: base58Encode(bytes.slice(132, 164)),
        deadline: littleU64(bytes, 164).toString(),
        bump: bytes[172],
        // The escaper: the only refund target of the record's rent.
        rentPayer: base58Encode(bytes.slice(173, 205)),
        stage
    });
    if (BigInt(decoded.finalBalance) + BigInt(decoded.conceded) !== BigInt(decoded.stateBalance)) {
        throw new Error('Solana pending withdrawal has an inconsistent concession.');
    }
    return decoded;
}

/** Decode classic SPL Token account data. */
export function decodeUsdcTokenAccount(value) {
    const bytes = value instanceof Uint8Array ? value : Uint8Array.from(value || []);
    if (bytes.length !== TOKEN_ACCOUNT_LENGTH) throw new Error('The USDC token account has invalid data.');
    const mint = base58Encode(bytes.slice(0, 32));
    const state = bytes[108];
    return Object.freeze({
        mint,
        owner: base58Encode(bytes.slice(32, 64)),
        amount: littleU64(bytes, 64).toString(),
        state,
        frozen: state === TOKEN_ACCOUNT_FROZEN,
        // The vault program's `creditable`: initialized, unfrozen, USDC mint.
        creditable: state === TOKEN_ACCOUNT_INITIALIZED && mint === USDC_MINT
    });
}

/**
 * Read a classic-Token USDC account at confirmed commitment; `null` when the
 * account does not exist. Token-2022 and foreign-owner accounts are refused.
 */
export async function readUsdcTokenAccount(funding, address, { signal = AbortSignal.timeout(20_000) } = {}) {
    validateSolanaFunding(funding);
    account(address, 'USDC token account');
    const result = await solanaRpc(funding, 'getAccountInfo', [address, {
        commitment: 'confirmed', encoding: 'base64'
    }], signal);
    if (!result?.value) return null;
    if (result.value.owner === TOKEN_2022_PROGRAM_ID) {
        throw new Error('Token-2022 accounts cannot hold Dagon USDC.');
    }
    if (result.value.owner !== TOKEN_PROGRAM_ID || result.value.executable !== false) {
        throw new Error(`Solana account ${address} is not a classic SPL Token account.`);
    }
    return Object.freeze({ address,
        ...decodeUsdcTokenAccount(accountData(result.value, 'USDC token account')) });
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

/** The vault state's USDC pins: the profile mint and the vault-token PDA. */
export function assertVaultUsdcAccounts(state, funding) {
    if (state.mint !== funding.usdc_mint
        || state.vaultToken !== vaultTokenAddress(funding.program_id, funding.vault_state)) {
        throw new Error('The pinned Solana vault does not hold Circle USDC in its canonical vault token account.');
    }
    return state;
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
    assertVaultUsdcAccounts(state, funding);
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

/**
 * Check the operator-prepared deposit before it is journaled or signed: its
 * final transaction must be the vault's `execute_deposit` moving USDC from
 * the wallet's canonical USDC account into the vault's token account, with
 * the wallet as operation owner, rent payer and token authority, the pinned
 * USDC mint and the classic Token program (never Token-2022).
 */
export function validatePreparedSolanaDeposit(operation, { funding, payer }) {
    validateSolanaFunding(funding);
    const transactions = operation?.transactions;
    if (!Array.isArray(transactions) || transactions.length === 0) {
        throw new Error('The prepared Solana deposit has no transactions.');
    }
    const inspected = inspectPreparedSolanaMessage(transactions.at(-1).bytes);
    const metas = inspected.instructionAccounts;
    const key = index => base58Encode(metas[index].pubkey);
    if (base58Encode(inspected.program) !== funding.program_id
        || inspected.instructionData.length !== 12
        || !equalBytes(inspected.instructionData.slice(0, 8), EXECUTE_DEPOSIT_DISCRIMINATOR)
        || metas.length !== 10) {
        throw new Error('The prepared Solana deposit does not end with the vault deposit instruction.');
    }
    if (key(8) === TOKEN_2022_PROGRAM_ID) {
        throw new Error('The prepared Solana deposit uses Token-2022; Dagon accepts only classic SPL Token USDC.');
    }
    if (key(8) !== TOKEN_PROGRAM_ID) {
        throw new Error('The prepared Solana deposit uses an unknown token program.');
    }
    if (key(7) !== funding.usdc_mint) {
        throw new Error('The prepared Solana deposit moves a token other than Circle USDC.');
    }
    const expected = [
        [0, funding.vault_state, true, false],
        [3, payer, true, true],
        [4, payer, false, true],
        [5, usdcAssociatedTokenAddress(payer), true, false],
        [6, vaultTokenAddress(funding.program_id, funding.vault_state), true, false],
        [9, SYSTEM_PROGRAM_ID, false, false]
    ];
    for (const [index, address, writable, signer] of expected) {
        const meta = metas[index];
        if (key(index) !== address || (writable && !meta.isWritable) || (signer && !meta.isSigner)) {
            throw new Error('The prepared Solana deposit does not move USDC from this wallet into the pinned vault.');
        }
    }
    return operation;
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

export { UPGRADEABLE_LOADER };
