// Program-free CCTP flows (Phase 1, design §4.3): the per-note emergency key
// `ek` (D5) is the CCTP mint recipient's owner, the vault depositor and the
// outbound burn owner. A relayer only pays SOL; every action it pays for is
// settled atomically by a capped USDC fee inside the exact transaction the
// browser signs with `ek` (no relay debt).
//
// Everything a relayer or Iris returns is validated here before `ek` signs or
// the wallet acts on it: the fee payer, the complete instruction list with
// every account and privilege (address lookup tables resolved on chain), the
// relay fee against the wallet's caps, the CCTP maxFee against the user's
// policy, the atomic deposit payload and emergency-key ownership, and every field and
// attester signature of a Circle message. Funds never leave ATA(ek) except into
// the vault note, the relay fee account (≤ cap) or a CCTP burn to the user's
// chosen recipient.
import { AddressLookupTableAccount, Keypair, PublicKey, Transaction, TransactionInstruction,
    VersionedTransaction } from '@solana/web3.js';
import { ed25519 } from '@noble/curves/ed25519';
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';
import { sha256 } from '@noble/hashes/sha256';
import { browserSdkOptions, browserSdkTransport } from '../configure.js';
import {
    CCTP_DOMAINS,
    EVM_CCTP,
    FINALITY_FAST,
    FINALITY_STANDARD,
    MESSAGE_TRANSMITTER_V2,
    SOLANA_DOMAIN,
    TOKEN_MESSENGER_MINTER_V2,
    decodeHook,
    decodeInboundIntent,
    decodeMessageSentEvent,
    decodeMessageV2,
    deriveEmergencyKey,
    depositForBurnInstruction,
    encodeForwardHook,
    encodeInboundHook,
    encodeInboundIntent,
    encodeMessageV2,
    evmApproveCalldata,
    evmBytes32,
    evmDepositForBurnWithHookCalldata,
    irisClient,
    receiveMessageInstruction,
    usedNonce
} from './zkapiCctp.mjs';
import {
    TOKEN_PROGRAM_ID,
    USDC_DECIMALS,
    assertSolanaDepositsOpen,
    assertSolanaVault,
    confirmFinalizedSolanaTransaction,
    createUsdcAccountIdempotentInstruction,
    decodeSolanaNoteState,
    decodeSolanaPendingWithdrawal,
    parseUnits,
    readUsdcTokenAccount,
    sendSignedSolanaTransaction,
    solanaRpc,
    usdcAssociatedTokenAddress,
    validateSolanaFunding,
    vaultTokenAddress
} from './zkapiUsdc.mjs';
import { base58Decode, base58Encode } from './zkapiSolanaTransport.mjs';
import { solanaExitInstruction } from './zkapiSolanaExit.mjs';
import { requestPersistentStorage } from './browserWalletStore.js';
import { assertEvmRecipient, burnUsdcOnEvm, claimCctpOnEvm, ensureEvmChain, evmAddress, readErc20Balance,
    requestEvmAccount } from './zkapiCctpEvm.mjs';

/** User-side relay fee caps per ek-signed transaction kind (USDC base units), from the shared contract. */
export const CCTP_FEE_CAPS = Object.freeze({
    deposit: 400_000n, receive: 0n, close: 750_000n, escape: 750_000n, burn: 50_000n, sweep: 50_000n
});

/**
 * User-side caps on the CCTP `maxFee` a burn authorizes (Circle's protocol fee
 * plus its Forwarding Service fee): max(minimum, bps × amount). Iris quotes
 * above the cap are refused; the authorized maxFee never exceeds it.
 * - inbound: EVM → Solana with ATA creation (≈ $0.25 forward + ≤ 2 bp): ≤ max(0.50 USDC, 0.5 %).
 * - outboundForward: Solana → EVM forwarded (≈ $0.05–0.07 on L2s, $0.7–1.2 to Ethereum): ≤ max(1.50 USDC, 0.5 %).
 * - outboundSelf: Solana → EVM self-claimed (protocol fee only, 1 bp Fast): ≤ max(0.10 USDC, 0.1 %).
 */
export const CCTP_FEE_POLICY = Object.freeze({
    inbound: Object.freeze({ minimum: 500_000n, bps: 50 }),
    outboundForward: Object.freeze({ minimum: 1_500_000n, bps: 50 }),
    outboundSelf: Object.freeze({ minimum: 100_000n, bps: 10 })
});

/** Circle's mainnet CCTP V2 attesters (MessageTransmitterV2 state, Solana and EVM), threshold 2. */
export const CIRCLE_ATTESTERS = Object.freeze({
    'mainnet-beta': Object.freeze(['0x725b06f73ff761ef5390e39315e2bfbf60d33f96',
        '0x52ed4cbff8dce6a19748043f3240ec03c834bcef'])
});

const DEFAULT_IRIS_URLS = Object.freeze({
    'mainnet-beta': 'https://iris-api.circle.com',
    devnet: 'https://iris-api-sandbox.circle.com',
    testnet: 'https://iris-api-sandbox.circle.com'
});

/** Every tunable of the CCTP flows; hosts override via configureBrowserSdk({ cctp }) or per call. */
export const CCTP_DEFAULTS = Object.freeze({
    feeCaps: CCTP_FEE_CAPS,
    feePolicy: CCTP_FEE_POLICY,
    // Pinned attester EVM addresses; `null` = CIRCLE_ATTESTERS for the network (required elsewhere).
    attesters: null,
    attestationThreshold: 2,
    irisUrl: null,
    relayUrl: null,
    evmChains: null,
    // Circle's fee-recipient USDC account for receive_message; `null` = the mainnet one.
    feeRecipientTokenAccount: null,
    refundDelaySeconds: 72 * 60 * 60,
    priorityWindowSeconds: 2 * 60 * 60,
    receiveFallbackMs: 3 * 60_000,
    arrivalTimeoutMs: 45 * 60_000,
    attestationTimeoutMs: 30 * 60_000,
    exitTimeoutMs: 5 * 60_000,
    pollIntervalMs: 3_000,
    forwardFeeHeadroomBps: 2_500,
    minFeeHeadroom: 10_000n,
    standardOnlySources: Object.freeze(['avalanche', 'polygon', 'sonic', 'sei', 'monad', 'hyperevm']),
    evmReceipt: Object.freeze({})
});

const SYSTEM_PROGRAM_ID = '11111111111111111111111111111111';
const COMPUTE_BUDGET_PROGRAM_ID = 'ComputeBudget111111111111111111111111111111';
const LOOKUP_TABLE_PROGRAM_ID = 'AddressLookupTab1e1111111111111111111111111';
const FIELD_ORDER = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const SECP256K1_HALF_N = secp256k1.CURVE.n >> 1n;
const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);
const U64_MAX = (1n << 64n) - 1n;
const DEPOSIT_PAYLOAD_LENGTH = 344;
const TRANSFER_CHECKED = 12;
const ZERO32 = new Uint8Array(32);
const SOLANA_TX_FORMATS = Object.freeze(['solana-legacy-transaction-v1', 'solana-v0-transaction-v1']);
const utf8 = value => new TextEncoder().encode(value);
const anchorDiscriminator = (namespace, name) => sha256(utf8(`${namespace}:${name}`)).slice(0, 8);
const EXECUTE_DEPOSIT_DISCRIMINATOR = anchorDiscriminator('global', 'execute_deposit');
const RECEIVE_MESSAGE_DISCRIMINATOR = anchorDiscriminator('global', 'receive_message');
const DEPOSIT_PHASES_IN_FLIGHT = new Set(['signed', 'submitted']);
const DEPOSIT_PHASES_BEFORE_BURN = new Set(['backup_required', 'planned']);

// ---------------------------------------------------------------------------
// Small byte helpers

export function toHex(bytes) {
    return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}

export function fromHex(value, label = 'hex bytes') {
    const body = typeof value === 'string' ? value.replace(/^0x/i, '') : null;
    if (body === null || body.length % 2 || !/^[0-9a-f]*$/i.test(body)) {
        throw new TypeError(`${label} must be hex.`);
    }
    return Uint8Array.from({ length: body.length / 2 }, (_, index) => parseInt(body.slice(index * 2, index * 2 + 2), 16));
}

function equalBytes(left, right) {
    return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

function concat(...parts) {
    const output = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
    let offset = 0;
    for (const part of parts) {
        output.set(part, offset);
        offset += part.length;
    }
    return output;
}

function u32le(value) {
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(0, value, true);
    return bytes;
}

function u64le(value) {
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigUint64(0, BigInt(value), true);
    return bytes;
}

function readU16(bytes, offset) {
    return bytes[offset] | bytes[offset + 1] << 8;
}

function readU32(bytes, offset) {
    return new DataView(bytes.buffer, bytes.byteOffset).getUint32(offset, true);
}

function readU64(bytes, offset) {
    return new DataView(bytes.buffer, bytes.byteOffset).getBigUint64(offset, true);
}

function base64Bytes(value) {
    if (typeof atob === 'function') return Uint8Array.from(atob(value), character => character.charCodeAt(0));
    return Uint8Array.from(Buffer.from(value, 'base64'));
}

function decimal(value, label) {
    if (typeof value === 'bigint') {
        if (value < 0n) throw new Error(`${label} must not be negative.`);
        return value;
    }
    if ((typeof value === 'string' && /^(0|[1-9][0-9]*)$/.test(value))
        || (Number.isSafeInteger(value) && value >= 0)) return BigInt(value);
    throw new Error(`${label} must be a non-negative integer.`);
}

/** A canonical, non-zero BN254 felt as its 32 big-endian bytes (the vault's encoding). */
export function feltBytes(value, label = 'commitment') {
    const felt = BigInt(value);
    if (felt <= 0n || felt >= FIELD_ORDER) throw new Error(`The ${label} is not a canonical non-zero field element.`);
    return fromHex(felt.toString(16).padStart(64, '0'));
}

function cctpError(message, code, extra = {}) {
    return Object.assign(new Error(message), { code, ...extra });
}

function sleep(milliseconds, signal) {
    return new Promise((resolve, reject) => {
        const timer = setTimeout(resolve, milliseconds);
        signal?.addEventListener('abort', () => {
            clearTimeout(timer);
            reject(signal.reason || new DOMException('The operation was aborted.', 'AbortError'));
        }, { once: true });
    });
}

// ---------------------------------------------------------------------------
// Options and fee rules

/** Merge the SDK defaults, the host's `configureBrowserSdk({ cctp })` and per-call overrides. */
export function resolveCctpOptions(overrides = {}) {
    const configured = browserSdkOptions().cctp || {};
    const merged = { ...CCTP_DEFAULTS, ...configured, ...overrides };
    const feeCaps = { ...CCTP_FEE_CAPS };
    for (const [kind, value] of Object.entries({ ...(configured.feeCaps || {}), ...(overrides.feeCaps || {}) })) {
        if (!(kind in CCTP_FEE_CAPS)) throw new TypeError(`Unknown CCTP fee cap ${kind}.`);
        feeCaps[kind] = decimal(value, `CCTP ${kind} fee cap`);
        if (feeCaps[kind] > CCTP_FEE_CAPS[kind]) throw new RangeError(`CCTP ${kind} fee cap may only be lowered.`);
    }
    merged.feeCaps = Object.freeze(feeCaps);
    const feePolicy = {};
    for (const direction of Object.keys(CCTP_FEE_POLICY)) {
        const entry = { ...CCTP_FEE_POLICY[direction], ...(configured.feePolicy?.[direction] || {}),
            ...(overrides.feePolicy?.[direction] || {}) };
        if (!Number.isSafeInteger(entry.bps) || entry.bps < 0 || entry.bps > 10_000) {
            throw new TypeError(`CCTP fee policy ${direction} bps is invalid.`);
        }
        feePolicy[direction] = Object.freeze({ minimum: decimal(entry.minimum, `CCTP ${direction} fee minimum`), bps: entry.bps });
    }
    merged.feePolicy = Object.freeze(feePolicy);
    merged.evmChains = Object.freeze({ ...EVM_CCTP, ...(configured.evmChains || {}), ...(overrides.evmChains || {}) });
    merged.minFeeHeadroom = decimal(merged.minFeeHeadroom, 'CCTP fee headroom');
    if (merged.attesters !== null) {
        merged.attesters = Object.freeze(merged.attesters.map(address => evmAddress(address, 'CCTP attester')));
    }
    if (!Number.isSafeInteger(merged.attestationThreshold) || merged.attestationThreshold < 1) {
        throw new TypeError('CCTP attestation threshold is invalid.');
    }
    for (const key of ['refundDelaySeconds', 'priorityWindowSeconds', 'receiveFallbackMs', 'arrivalTimeoutMs',
        'attestationTimeoutMs', 'exitTimeoutMs', 'pollIntervalMs', 'forwardFeeHeadroomBps']) {
        if (!Number.isSafeInteger(merged[key]) || merged[key] < 0) throw new TypeError(`CCTP option ${key} is invalid.`);
    }
    return Object.freeze(merged);
}

/** The EVM CCTP deployment and CCTP domain of a named chain. */
export function cctpEvmChain(name, options = resolveCctpOptions()) {
    const chain = options.evmChains[name];
    const domain = chain?.domain ?? CCTP_DOMAINS[name];
    if (!chain || !Number.isSafeInteger(domain) || domain === SOLANA_DOMAIN) {
        throw cctpError(`CCTP chain ${name} is not configured.`, 'cctp_chain_unknown');
    }
    return Object.freeze({
        name,
        domain,
        chainId: chain.chainId,
        usdc: evmAddress(chain.usdc, `${name} USDC`),
        tokenMessenger: evmAddress(chain.tokenMessenger, `${name} TokenMessengerV2`),
        messageTransmitter: evmAddress(chain.messageTransmitter, `${name} MessageTransmitterV2`)
    });
}

/** Relay fee cap of one ek-signed transaction of `kind`. */
export function relayFeeCap(kind, caps = CCTP_FEE_CAPS) {
    if (!(kind in caps)) throw new TypeError(`Unknown relay fee kind ${kind}.`);
    return BigInt(caps[kind]);
}

/** The user's CCTP maxFee ceiling for `direction` and transfer `amount`. */
export function cctpFeePolicyCap(direction, amount, policy = CCTP_FEE_POLICY) {
    const entry = policy[direction];
    if (!entry) throw new TypeError(`Unknown CCTP fee direction ${direction}.`);
    const proportional = BigInt(amount) * BigInt(entry.bps) / 10_000n;
    return proportional > BigInt(entry.minimum) ? proportional : BigInt(entry.minimum);
}

function feeEntry(fees, threshold) {
    if (!Array.isArray(fees)) throw cctpError('Circle returned malformed CCTP fees.', 'cctp_fees_invalid');
    return fees.find(entry => Number(entry?.finalityThreshold) === threshold) || null;
}

function protocolFee(amount, bps) {
    const scaled = Math.round(Number(bps) * 100);
    if (!Number.isSafeInteger(scaled) || scaled < 0 || scaled > 1_000_000) {
        throw cctpError('Circle returned an invalid CCTP fee rate.', 'cctp_fees_invalid');
    }
    return (BigInt(amount) * BigInt(scaled) + 999_999n) / 1_000_000n;
}

/**
 * maxFee for a burn: the Fast protocol fee (if Fast) + Circle's high forward
 * fee (if forwarded) + headroom, never above `policyCap`. A quote whose base
 * fee alone exceeds the policy cap is refused. Fast falls back to Standard
 * when Circle does not offer it for the route (D3).
 */
export function cctpMaxFee({ fees, amount, finality = 'fast', forward = true, fastAllowed = true, policyCap,
    headroomBps = CCTP_DEFAULTS.forwardFeeHeadroomBps, minHeadroom = CCTP_DEFAULTS.minFeeHeadroom }) {
    if (!['fast', 'standard'].includes(finality)) throw new TypeError('CCTP finality must be fast or standard.');
    if (typeof policyCap !== 'bigint' || policyCap <= 0n) throw new TypeError('A CCTP fee policy cap is required.');
    let threshold = finality === 'fast' && fastAllowed ? FINALITY_FAST : FINALITY_STANDARD;
    let entry = feeEntry(fees, threshold);
    if (!entry && threshold === FINALITY_FAST) {
        threshold = FINALITY_STANDARD;
        entry = feeEntry(fees, threshold);
    }
    if (!entry) throw cctpError('Circle offers no CCTP route for this transfer.', 'cctp_route_unavailable');
    const protocol = threshold === FINALITY_FAST ? protocolFee(amount, entry.minimumFee) : 0n;
    const forwardFee = forward ? decimal(String(entry.forwardFee?.high ?? ''), 'Circle forward fee') : 0n;
    const baseFee = protocol + forwardFee;
    if (baseFee > policyCap) {
        throw cctpError(`Circle's CCTP fee quote (${baseFee} base units) exceeds this wallet's fee policy (${policyCap}).`,
            'cctp_fee_above_policy', { quoted: baseFee, policyCap });
    }
    const headroom = baseFee * BigInt(headroomBps) / 10_000n;
    const padded = baseFee + (headroom > BigInt(minHeadroom) ? headroom : BigInt(minHeadroom));
    return Object.freeze({ maxFee: padded < policyCap ? padded : policyCap, baseFee, minFinalityThreshold: threshold,
        protocolFee: protocol, forwardFee });
}

// ---------------------------------------------------------------------------
// Relay HTTP client

export class CctpRelayError extends Error {
    constructor(message, status, code, data = null) {
        super(message);
        this.name = 'CctpRelayError';
        this.status = status;
        this.code = code;
        this.data = data;
        this.relayUnavailable = ['relay_disabled', 'relayer_unavailable', 'relayer_unreachable'].includes(code);
    }
}

/** zkapi-serverd relay client (contract "Relay HTTP API"). */
export function cctpRelayClient(baseUrl, transport = browserSdkTransport) {
    const root = String(baseUrl || '').replace(/\/+$/, '');
    if (!root) throw new TypeError('A relay base URL is required.');
    const call = async (path, body = null) => {
        let response;
        try {
            response = await transport(`${root}${path}`, body === null
                ? { method: 'GET', cache: 'no-store' }
                : { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
        } catch (cause) {
            throw Object.assign(new CctpRelayError('The CCTP relayer cannot be reached.', 0, 'relayer_unreachable'),
                { cause });
        }
        let payload = null;
        try {
            payload = await response.json();
        } catch {
            payload = null;
        }
        if (!response.ok) {
            const error = payload?.error || {};
            throw new CctpRelayError(error.message || `CCTP relay HTTP ${response.status}`, response.status,
                error.code || (response.status === 404 ? 'relay_disabled' : 'relay_error'), payload);
        }
        if (!payload || typeof payload !== 'object') {
            throw new CctpRelayError('The CCTP relayer returned malformed JSON.', response.status, 'relay_malformed');
        }
        return payload;
    };
    return Object.freeze({
        info: () => call('/v2/relay'),
        prepareDeposit: body => call('/v2/relay/deposits/prepare', body),
        prepareReceive: body => call('/v2/relay/receives/prepare', body),
        prepareExit: body => call('/v2/relay/exits/prepare', body),
        finalizeEscape: body => call('/v2/relay/escapes/finalize', body),
        prepareBurn: body => call('/v2/relay/burns/prepare', body),
        prepareSweep: body => call('/v2/relay/sweeps/prepare', body),
        submit: body => call('/v2/relay/submit', body)
    });
}

/** Validate GET /v2/relay against the deployment. */
export function validateRelayInfo(info, funding) {
    try {
        base58Decode(info?.relayer, 32, 'relayer');
        base58Decode(info?.fee_account, 32, 'relay fee account');
    } catch {
        throw cctpError('The CCTP relayer returned invalid keys.', 'relay_malformed');
    }
    if (info.usdc_mint !== funding.usdc_mint) {
        throw cctpError('The CCTP relayer serves a different USDC mint.', 'relay_malformed');
    }
    const quotes = {};
    for (const kind of Object.keys(CCTP_FEE_CAPS)) quotes[kind] = decimal(info.quotes?.[kind], `relay ${kind} quote`);
    return Object.freeze({ relayer: info.relayer, feeAccount: info.fee_account, quotes: Object.freeze(quotes),
        burnMinimum: decimal(info.burn_minimum, 'relay burn minimum'),
        irisUrl: typeof info.iris_url === 'string' ? info.iris_url : null });
}

// ---------------------------------------------------------------------------
// Circle messages and attestations

/**
 * Verify `attestation` over keccak256(`message`): exactly `threshold`
 * 65-byte (r ‖ s ‖ v) secp256k1 signatures, low-s, v ∈ {27, 28}, recovered
 * signers strictly ascending and all in the pinned `attesters` set (what
 * MessageTransmitterV2 enforces on chain).
 */
export function verifyCctpAttestation(message, attestation, { attesters, threshold = 2 }) {
    const reject = reason => {
        throw cctpError(`The Circle attestation ${reason}.`, 'cctp_attestation_invalid');
    };
    if (!Array.isArray(attesters) || attesters.length < threshold) reject('cannot be checked: no pinned attesters');
    const signatures = fromHex(attestation, 'CCTP attestation');
    if (signatures.length !== 65 * threshold) reject('has the wrong number of signatures');
    const digest = keccak_256(fromHex(message, 'CCTP message'));
    const pinned = new Set(attesters.map(address => address.toLowerCase()));
    let previous = -1n;
    for (let index = 0; index < threshold; index += 1) {
        const signature = signatures.slice(index * 65, index * 65 + 65);
        const v = signature[64];
        if (v !== 27 && v !== 28) reject('has an invalid recovery byte');
        let address;
        try {
            const parsed = secp256k1.Signature.fromCompact(signature.slice(0, 64));
            if (parsed.s > SECP256K1_HALF_N) reject('has a high-s signature');
            const point = parsed.addRecoveryBit(v - 27).recoverPublicKey(digest);
            address = `0x${toHex(keccak_256(point.toRawBytes(false).slice(1)).slice(12))}`;
        } catch (error) {
            if (error.code === 'cctp_attestation_invalid') throw error;
            reject('has an unrecoverable signature');
        }
        const ordinal = BigInt(address);
        if (ordinal <= previous) reject('signers are not strictly ascending');
        if (!pinned.has(address)) reject(`is signed by unknown attester ${address}`);
        previous = ordinal;
    }
    return true;
}

// Iris fills the nonce, the executed finality, feeExecuted and expirationBlock;
// every other byte of an attested Solana-source message is the burn's own.
const IRIS_FILLED_RANGES = Object.freeze([[12, 44], [144, 148], [148 + 164, 148 + 196], [148 + 196, 148 + 228]]);

function sameExceptIrisFields(attested, source) {
    if (attested.length !== source.length) return false;
    return attested.every((byte, index) => byte === source[index]
        || IRIS_FILLED_RANGES.some(([start, end]) => index >= start && index < end));
}

/** Every planned/source-controlled field of an inbound EVM → Solana message. */
export function assertInboundMessage(message, expected) {
    const body = message.body;
    const finalityOk = expected.minFinalityThreshold === FINALITY_FAST
        ? [FINALITY_FAST, FINALITY_STANDARD].includes(message.finalityThresholdExecuted)
        : message.finalityThresholdExecuted === FINALITY_STANDARD;
    if (message.version !== 1 || body.version !== 1
        || message.sourceDomain !== expected.sourceDomain || message.destinationDomain !== SOLANA_DOMAIN
        || !equalBytes(message.sender, evmBytes32(expected.tokenMessenger))
        || !equalBytes(message.recipient, new PublicKey(TOKEN_MESSENGER_MINTER_V2).toBytes())
        || !equalBytes(message.destinationCaller, ZERO32)
        || message.minFinalityThreshold !== expected.minFinalityThreshold || !finalityOk
        || !equalBytes(body.burnToken, evmBytes32(expected.usdc))
        || !equalBytes(body.mintRecipient, base58Decode(expected.ata, 32))
        || body.amount !== BigInt(expected.amount)
        || !equalBytes(body.messageSender, evmBytes32(expected.burner))
        || body.maxFee !== BigInt(expected.maxFee)
        || body.feeExecuted > body.maxFee || body.feeExecuted >= body.amount
        || !equalBytes(body.hookData, fromHex(expected.hook))) {
        throw cctpError('Circle attested a different burn than this deposit planned.', 'cctp_message_mismatch');
    }
    return message;
}

/**
 * An outbound Solana → EVM message: byte-identical to the on-chain MessageSent
 * event of the validated burn except for the fields Iris fills, and carrying
 * this burn's domain, recipient, caller, amount, max fee, finality and hook.
 */
export function assertOutboundMessage(attestedBytes, eventBytes, burn) {
    const message = decodeMessageV2(attestedBytes);
    const target = burn.target;
    if (!sameExceptIrisFields(attestedBytes, eventBytes)
        || message.version !== 1 || message.body.version !== 1
        || message.sourceDomain !== SOLANA_DOMAIN || message.destinationDomain !== target.destinationDomain
        || !equalBytes(message.destinationCaller, fromHex(target.destinationCaller))
        || message.minFinalityThreshold !== target.minFinalityThreshold
        || !equalBytes(message.body.mintRecipient, fromHex(target.mintRecipient))
        || message.body.amount !== BigInt(burn.amount)
        || message.body.maxFee !== BigInt(target.maxCctpFee)
        || message.body.feeExecuted > message.body.maxFee
        || !equalBytes(message.body.hookData, fromHex(target.hookData))) {
        throw cctpError('Circle attested a different burn.', 'cctp_message_mismatch');
    }
    return message;
}

// ---------------------------------------------------------------------------
// Transaction decoding and exact matching

function readShortVec(bytes, offset) {
    let value = 0;
    for (let index = 0; index < 3; index += 1) {
        if (offset + index >= bytes.length) throw new Error('Solana transaction is truncated.');
        const byte = bytes[offset + index];
        value |= (byte & 0x7f) << (7 * index);
        if ((byte & 0x80) === 0) return { value, offset: offset + index + 1 };
    }
    throw new Error('Solana transaction has an invalid length prefix.');
}

/**
 * Decode a signed legacy or v0 Solana transaction (wire format) without
 * trusting any field. A v0 message's lookups are resolved against
 * `lookupTables` (`{ address, addresses }`, read from the chain by the caller).
 */
export function decodeTransaction(value, lookupTables = []) {
    const bytes = value instanceof Uint8Array ? value : Uint8Array.from(value || []);
    if (bytes.length > 1232) throw new Error('Solana transaction exceeds the packet limit.');
    let cursor = 0;
    const signatureCount = readShortVec(bytes, cursor);
    cursor = signatureCount.offset;
    const signatures = [];
    for (let index = 0; index < signatureCount.value; index += 1) {
        if (cursor + 64 > bytes.length) throw new Error('Solana transaction signatures are truncated.');
        signatures.push(bytes.slice(cursor, cursor + 64));
        cursor += 64;
    }
    const message = bytes.slice(cursor);
    if (message.length < 4) throw new Error('Solana message is truncated.');
    let offset = 0;
    let version = 'legacy';
    if (message[0] & 0x80) {
        if ((message[0] & 0x7f) !== 0) throw new Error('Unsupported Solana message version.');
        version = 0;
        offset = 1;
    }
    const header = { numRequiredSignatures: message[offset], numReadonlySigned: message[offset + 1],
        numReadonlyUnsigned: message[offset + 2] };
    offset += 3;
    const keyCount = readShortVec(message, offset);
    offset = keyCount.offset;
    if (offset + keyCount.value * 32 + 32 > message.length) throw new Error('Solana account keys are truncated.');
    const staticKeys = Array.from({ length: keyCount.value },
        (_, index) => base58Encode(message.slice(offset + index * 32, offset + (index + 1) * 32)));
    offset += keyCount.value * 32;
    const recentBlockhash = base58Encode(message.slice(offset, offset + 32));
    offset += 32;
    if (header.numRequiredSignatures !== signatures.length || header.numRequiredSignatures === 0
        || header.numRequiredSignatures > staticKeys.length
        || header.numReadonlySigned >= header.numRequiredSignatures
        || header.numReadonlyUnsigned > staticKeys.length - header.numRequiredSignatures) {
        throw new Error('Solana transaction header is invalid.');
    }
    const instructionCount = readShortVec(message, offset);
    offset = instructionCount.offset;
    const raw = [];
    for (let index = 0; index < instructionCount.value; index += 1) {
        if (offset >= message.length) throw new Error('Solana instruction is truncated.');
        const programIndex = message[offset++];
        const accountCount = readShortVec(message, offset);
        offset = accountCount.offset;
        const indices = message.slice(offset, offset + accountCount.value);
        offset += accountCount.value;
        const dataLength = readShortVec(message, offset);
        offset = dataLength.offset;
        const data = message.slice(offset, offset + dataLength.value);
        offset += dataLength.value;
        if (offset > message.length || indices.length !== accountCount.value) throw new Error('Solana instruction is malformed.');
        raw.push({ programIndex, indices, data });
    }
    const lookups = [];
    if (version === 0) {
        const lookupCount = readShortVec(message, offset);
        offset = lookupCount.offset;
        for (let index = 0; index < lookupCount.value; index += 1) {
            if (offset + 32 > message.length) throw new Error('Solana lookup table is truncated.');
            const address = base58Encode(message.slice(offset, offset + 32));
            offset += 32;
            const writable = readShortVec(message, offset);
            const writableIndexes = message.slice(writable.offset, writable.offset + writable.value);
            offset = writable.offset + writable.value;
            const readonly = readShortVec(message, offset);
            const readonlyIndexes = message.slice(readonly.offset, readonly.offset + readonly.value);
            offset = readonly.offset + readonly.value;
            if (offset > message.length) throw new Error('Solana lookup table is truncated.');
            lookups.push({ address, writableIndexes, readonlyIndexes });
        }
    }
    if (offset !== message.length) throw new Error('Solana transaction has trailing bytes.');
    const resolve = (lookup, indexes) => {
        const table = lookupTables.find(entry => entry.address === lookup.address);
        if (!table) throw new Error(`Solana lookup table ${lookup.address} was not resolved.`);
        return Array.from(indexes, entry => {
            if (entry >= table.addresses.length) throw new Error('Solana lookup index is out of range.');
            return table.addresses[entry];
        });
    };
    const loadedWritable = lookups.flatMap(lookup => resolve(lookup, lookup.writableIndexes));
    const loadedReadonly = lookups.flatMap(lookup => resolve(lookup, lookup.readonlyIndexes));
    const accountKeys = [...staticKeys, ...loadedWritable, ...loadedReadonly];
    const privilege = index => {
        if (index >= staticKeys.length) {
            return { isSigner: false, isWritable: index < staticKeys.length + loadedWritable.length };
        }
        return {
            isSigner: index < header.numRequiredSignatures,
            isWritable: index < header.numRequiredSignatures
                ? index < header.numRequiredSignatures - header.numReadonlySigned
                : index < staticKeys.length - header.numReadonlyUnsigned
        };
    };
    const instructions = raw.map(({ programIndex, indices, data }) => {
        if (programIndex >= staticKeys.length || indices.some(entry => entry >= accountKeys.length)) {
            throw new Error('Solana instruction account index is invalid.');
        }
        return Object.freeze({
            programId: accountKeys[programIndex],
            accounts: Array.from(indices, entry => Object.freeze({ pubkey: accountKeys[entry], ...privilege(entry) })),
            data
        });
    });
    return Object.freeze({ bytes, version, signatures, message, header, staticKeys, accountKeys, recentBlockhash,
        lookups, instructions, privileges: accountKeys.map((_, index) => privilege(index)) });
}

/** Back-compatible name: legacy transactions only. */
export function decodeLegacyTransaction(value) {
    const decoded = decodeTransaction(value);
    if (decoded.version !== 'legacy') throw new Error('Only legacy Solana transactions are accepted.');
    return decoded;
}

function meta(pubkey, isSigner = false, isWritable = false) {
    return { pubkey: String(pubkey), isSigner, isWritable };
}

function instruction(programId, keys, data) {
    return { programId: String(programId), keys, data };
}

/** SPL Token TransferChecked (USDC, 6 decimals). */
export function transferCheckedInstruction({ source, mint, destination, authority, amount }) {
    return instruction(TOKEN_PROGRAM_ID, [meta(source, false, true), meta(mint), meta(destination, false, true),
        meta(authority, true, false)], concat(Uint8Array.of(TRANSFER_CHECKED), u64le(amount), Uint8Array.of(USDC_DECIMALS)));
}

/** The vault's `execute_deposit` with a relayer owner and `ek` depositor (ExecuteDeposit account order). */
export function executeDepositInstruction({ funding, operation, note, owner, depositor, noteId }) {
    return instruction(funding.program_id, [
        meta(funding.vault_state, false, true), meta(operation, false, true), meta(note, false, true),
        meta(owner, true, true), meta(depositor, true, false), meta(usdcAssociatedTokenAddress(depositor), false, true),
        meta(vaultTokenAddress(funding.program_id, funding.vault_state), false, true), meta(funding.usdc_mint),
        meta(TOKEN_PROGRAM_ID), meta(SYSTEM_PROGRAM_ID)
    ], concat(EXECUTE_DEPOSIT_DISCRIMINATOR, u32le(noteId)));
}

function plainInstruction(value) {
    if (value instanceof TransactionInstruction) {
        return instruction(value.programId.toBase58(), value.keys.map(key => meta(key.pubkey.toBase58(),
            key.isSigner, key.isWritable)), Uint8Array.from(value.data));
    }
    return value;
}

function computeBudgetMatches(actual, kind) {
    if (actual.programId !== COMPUTE_BUDGET_PROGRAM_ID || actual.accounts.length !== 0
        || actual.data.length !== 5 || actual.data[0] !== kind) return false;
    const value = readU32(actual.data, 1);
    return kind === 1
        ? value >= 32_768 && value <= 262_144 && value % 1_024 === 0
        : value > 0 && value <= 1_400_000;
}

function signatureEmpty(signature) {
    return signature.every(byte => byte === 0);
}

/**
 * Require `bytes` to be exactly the expected transaction: version, fee payer,
 * signer set, the ordered instruction list (program, data, accounts) and every
 * account privilege (lookup-table accounts included) equal to the union of
 * what those instructions need. `presigned` keys must carry valid signatures,
 * `unsigned` keys none.
 */
export function assertExactTransaction(bytes, { label, feePayer, presigned = [], unsigned = [], instructions,
    version = 'legacy', lookupTables = [] }) {
    const reject = reason => {
        throw cctpError(`The relayer's ${label} transaction ${reason}; it was not signed.`, 'cctp_relay_tx_rejected');
    };
    let decoded;
    try {
        decoded = decodeTransaction(bytes, lookupTables);
    } catch (error) {
        reject(`is malformed (${error.message})`);
    }
    if (decoded.version !== version) reject(`is not a ${version} transaction`);
    const signers = [...presigned, ...unsigned];
    if (decoded.accountKeys[0] !== feePayer) reject('has a different fee payer');
    if (new Set(decoded.accountKeys).size !== decoded.accountKeys.length) reject('repeats an account key');
    const signerKeys = decoded.staticKeys.slice(0, decoded.header.numRequiredSignatures);
    if (signerKeys.length !== signers.length || !signers.every(key => signerKeys.includes(key))) {
        reject('requires a different set of signers');
    }
    if (decoded.instructions.length !== instructions.length) {
        const programs = list => list.join(', ');
        reject(`has a different instruction list (got [${programs(decoded.instructions.map(ix => ix.programId))}], `
            + `expected [${programs(instructions.map(ix => (ix.computeBudget ? COMPUTE_BUDGET_PROGRAM_ID
                : plainInstruction(ix).programId)))}])`);
    }
    const expected = new Map([[feePayer, { isSigner: true, isWritable: true }]]);
    const merge = (key, isSigner, isWritable) => {
        const previous = expected.get(key) || { isSigner: false, isWritable: false };
        expected.set(key, { isSigner: previous.isSigner || isSigner, isWritable: previous.isWritable || isWritable });
    };
    instructions.forEach((wanted, index) => {
        const actual = decoded.instructions[index];
        if (wanted.computeBudget) {
            if (!computeBudgetMatches(actual, wanted.computeBudget)) reject(`has an unauthorized instruction ${index}`);
            merge(COMPUTE_BUDGET_PROGRAM_ID, false, false);
            return;
        }
        const plain = plainInstruction(wanted);
        if (actual.programId !== plain.programId || !equalBytes(actual.data, Uint8Array.from(plain.data))
            || actual.accounts.length !== plain.keys.length
            || plain.keys.some((key, keyIndex) => actual.accounts[keyIndex].pubkey !== key.pubkey)) {
            reject(`instruction ${index} differs from the expected instruction`);
        }
        merge(plain.programId, false, false);
        for (const key of plain.keys) merge(key.pubkey, key.isSigner, key.isWritable);
    });
    if (decoded.accountKeys.length !== expected.size) reject('references unexpected accounts');
    decoded.accountKeys.forEach((key, index) => {
        const wanted = expected.get(key);
        const actual = decoded.privileges[index];
        if (!wanted || wanted.isSigner !== actual.isSigner || wanted.isWritable !== actual.isWritable) {
            reject(`grants different privileges to ${key}`);
        }
    });
    for (const key of unsigned) {
        if (!signatureEmpty(decoded.signatures[signerKeys.indexOf(key)])) reject('already carries a signature for this wallet');
    }
    for (const key of presigned) {
        const signature = decoded.signatures[signerKeys.indexOf(key)];
        let valid = false;
        try {
            valid = !signatureEmpty(signature) && ed25519.verify(signature, decoded.message, base58Decode(key, 32));
        } catch {
            valid = false;
        }
        if (!valid) reject(`is not validly signed by ${key}`);
    }
    return decoded;
}

/** The signature list and message bytes of a signed transaction (no field interpretation). */
function splitSignedTransaction(value) {
    const bytes = value instanceof Uint8Array ? value : Uint8Array.from(value || []);
    const count = readShortVec(bytes, 0);
    const end = count.offset + count.value * 64;
    if (end >= bytes.length) throw new Error('Solana transaction signatures are truncated.');
    return { signatures: Array.from({ length: count.value },
        (_, index) => bytes.slice(count.offset + index * 64, count.offset + (index + 1) * 64)), message: bytes.slice(end) };
}

/**
 * Add `keypairs`' signatures to a validated transaction (legacy or v0)
 * without changing its message or any signature already present.
 */
export function signTransactionWith(bytes, keypairs) {
    const before = splitSignedTransaction(bytes);
    const transaction = VersionedTransaction.deserialize(Uint8Array.from(bytes));
    if (!equalBytes(transaction.message.serialize(), before.message)) {
        throw new Error('The Solana transaction message does not round-trip.');
    }
    transaction.sign(keypairs);
    const signed = transaction.serialize();
    const after = splitSignedTransaction(signed);
    if (!equalBytes(after.message, before.message) || after.signatures.length !== before.signatures.length
        || before.signatures.some((signature, index) => !signatureEmpty(signature)
            && !equalBytes(signature, after.signatures[index]))) {
        throw new Error('Signing changed the Solana transaction.');
    }
    return Object.freeze({ bytes: signed, signature: base58Encode(after.signatures[0]) });
}

function preparedTransaction(transaction, label) {
    if (!SOLANA_TX_FORMATS.includes(transaction?.format) || !Number.isSafeInteger(transaction?.last_valid_height)
        || !Array.isArray(transaction?.bytes)) {
        throw cctpError(`The relayer returned an unsupported ${label} transaction.`, 'cctp_relay_tx_rejected');
    }
    return { bytes: Uint8Array.from(transaction.bytes), version: transaction.format === 'solana-v0-transaction-v1' ? 0 : 'legacy',
        format: transaction.format, lastValidHeight: transaction.last_valid_height,
        lookupTables: transaction.lookup_tables || [] };
}

/** An ek-co-signed prepare: the unsigned transaction and its opaque `/v2/relay/submit` token. */
function preparedForSubmit(response, label) {
    const token = response?.submit_token;
    if (typeof token !== 'string' || !token || token.length > 4096) {
        throw cctpError(`The relayer returned an invalid ${label} submit token.`, 'cctp_relay_tx_rejected');
    }
    return { ...preparedTransaction(response.transaction, label), submitToken: token };
}

/**
 * Verify a `/v2/relay/submit` response against the ek-signed transaction the
 * wallet sent: the same format and lifetime, byte-identical message bytes
 * (decoded with the same lookup tables), the emergency key's signature
 * unchanged, and every required signature (relayer, MessageSent event for
 * burns, ek) present and valid over the message. Returns the complete
 * transaction to journal and confirm.
 */
export function verifyRelaySubmission(response, { sent, ek, format, lastValidHeight, lookupTables = [],
    label = 'relay' }) {
    const reject = reason => {
        throw cctpError(`The relayer's submitted ${label} transaction ${reason}; it was not accepted.`,
            'cctp_relay_tx_rejected');
    };
    const transaction = response?.transaction;
    if (transaction?.format !== format || transaction?.last_valid_height !== lastValidHeight
        || !Array.isArray(transaction?.bytes)) {
        reject('has a different format or lifetime');
    }
    let full;
    let original;
    try {
        full = decodeTransaction(Uint8Array.from(transaction.bytes), lookupTables);
        original = decodeTransaction(Uint8Array.from(sent), lookupTables);
    } catch (error) {
        reject(`is malformed (${error.message})`);
    }
    if (!equalBytes(full.message, original.message)) reject('differs from the message this wallet signed');
    const ekIndex = original.staticKeys.slice(0, original.header.numRequiredSignatures).indexOf(ek);
    if (ekIndex < 0 || signatureEmpty(original.signatures[ekIndex])
        || !equalBytes(full.signatures[ekIndex], original.signatures[ekIndex])) {
        reject('changed the emergency-key signature');
    }
    full.signatures.forEach((signature, index) => {
        let valid = false;
        try {
            valid = !signatureEmpty(signature)
                && ed25519.verify(signature, full.message, base58Decode(full.staticKeys[index], 32));
        } catch {
            valid = false;
        }
        if (!valid) reject(`is not validly signed by ${full.staticKeys[index]}`);
    });
    const signature = base58Encode(full.signatures[0]);
    if (response.signature !== signature) reject('reports a different transaction signature');
    return Object.freeze({ bytes: full.bytes, signature, lastValidHeight });
}

/**
 * Read the address lookup tables a v0 transaction uses from the pinned RPC:
 * owned by the lookup-table program, active, and agreeing with what the
 * relayer reported. Lookups resolve against the on-chain contents.
 */
export async function readLookupTables(funding, reported, signal = AbortSignal.timeout(20_000)) {
    if (!Array.isArray(reported) || reported.length > 4) {
        throw cctpError('The relayer reported invalid lookup tables.', 'cctp_relay_tx_rejected');
    }
    const tables = [];
    for (const entry of reported) {
        base58Decode(entry?.address, 32, 'lookup table');
        const result = await solanaRpc(funding, 'getAccountInfo', [entry.address,
            { commitment: 'confirmed', encoding: 'base64' }], signal);
        const account = result?.value;
        if (!account || account.owner !== LOOKUP_TABLE_PROGRAM_ID || account.executable !== false) {
            throw cctpError(`Lookup table ${entry.address} is not an address lookup table.`, 'cctp_relay_tx_rejected');
        }
        const state = AddressLookupTableAccount.deserialize(base64Bytes(account.data[0]));
        const addresses = state.addresses.map(key => key.toBase58());
        if (BigInt(state.deactivationSlot) !== U64_MAX || !Array.isArray(entry.addresses)
            || entry.addresses.length > addresses.length
            || entry.addresses.some((address, index) => address !== addresses[index])) {
            throw cctpError(`Lookup table ${entry.address} differs from its on-chain contents.`, 'cctp_relay_tx_rejected');
        }
        tables.push(Object.freeze({ address: entry.address, addresses }));
    }
    return tables;
}

// ---------------------------------------------------------------------------
// Relay transaction validators

function notePda(funding, noteId) {
    return PublicKey.findProgramAddressSync([utf8('note'), base58Decode(funding.vault_state, 32), u32le(noteId)],
        new PublicKey(funding.program_id))[0].toBase58();
}

function pendingPda(funding, noteId) {
    return PublicKey.findProgramAddressSync([utf8('pending'), base58Decode(funding.vault_state, 32), u32le(noteId)],
        new PublicKey(funding.program_id))[0].toBase58();
}

function relayFee(fee, maxFee, label) {
    const value = decimal(fee, `relay ${label} fee`);
    if (value > BigInt(maxFee)) {
        throw cctpError(`The relayer asked for a ${label} fee above this wallet's cap.`, 'relay_fee_above_cap');
    }
    return value;
}

function feeTransfer(funding, ek, feeAccount, fee) {
    return fee > 0n ? [transferCheckedInstruction({ source: usdcAssociatedTokenAddress(ek), mint: funding.usdc_mint,
        destination: feeAccount, authority: ek, amount: fee })] : [];
}

/**
 * Atomic ek-owned deposit: rent advance, initialize, write, compute budget,
 * execute, USDC fee, rent refund. The signed message carries the complete
 * payload. An RPC observation of a relayer-owned buffer is not authorization:
 * its owner could cancel and recreate the same PDA after that observation.
 */
export function validateRelayDepositTransaction(bytes, { funding, relayer, ek, feeAccount, operation, note,
    noteId, commitment, amount, fee, maxFee, operationRent, noteRent, lookupTables = [] }) {
    const charged = relayFee(fee, maxFee, 'deposit');
    const reject = () => { throw cctpError('The atomic deposit does not bind this note and its emergency-key owner.',
        'cctp_relay_tx_rejected'); };
    const decoded = decodeTransaction(bytes, lookupTables);
    const init = decoded.instructions[1]?.data;
    const write = decoded.instructions[2]?.data;
    if (!init || init.length !== 83 || !write || write.length !== 14 + DEPOSIT_PAYLOAD_LENGTH
        || !equalBytes(init.slice(0, 8), anchorDiscriminator('global', 'initialize_operation'))
        || !equalBytes(write.slice(0, 8), anchorDiscriminator('global', 'write_operation'))
        || init[40] !== 1 || readU16(init, 41) !== DEPOSIT_PAYLOAD_LENGTH
        || readU16(write, 8) !== 0 || readU32(write, 10) !== DEPOSIT_PAYLOAD_LENGTH) reject();
    const payload = write.slice(14);
    const expectedOperation = PublicKey.findProgramAddressSync([utf8('operation'),
        base58Decode(funding.vault_state, 32), base58Decode(ek, 32), init.slice(8, 40)],
    new PublicKey(funding.program_id))[0].toBase58();
    if (operation !== expectedOperation || note !== notePda(funding, noteId)
        || !equalBytes(keccak_256(payload), init.slice(43, 75))
        || readU32(payload, 0) !== noteId || !equalBytes(payload.slice(4, 36), feltBytes(commitment))
        || readU64(payload, 36) !== BigInt(amount) || readU32(payload, 84) !== 256) reject();
    const bufferRent = decimal(operationRent, 'operation rent');
    const permanentRent = decimal(noteRent, 'note rent');
    const solTransfer = (from, to, lamports) => instruction(SYSTEM_PROGRAM_ID,
        [meta(from, true, true), meta(to, false, true)], concat(u32le(2), u64le(lamports)));
    return assertExactTransaction(bytes, {
        label: 'deposit', feePayer: relayer, presigned: [], unsigned: [relayer, ek],
        version: 0, lookupTables,
        instructions: [
            solTransfer(relayer, ek, bufferRent + permanentRent),
            instruction(funding.program_id, [meta(funding.vault_state), meta(operation, false, true),
                meta(ek, true, true), meta(SYSTEM_PROGRAM_ID)], init),
            instruction(funding.program_id, [meta(funding.vault_state), meta(operation, false, true),
                meta(ek, true)], write),
            { computeBudget: 1 }, { computeBudget: 2 },
            executeDepositInstruction({ funding, operation, note, owner: ek, depositor: ek, noteId }),
            ...feeTransfer(funding, ek, feeAccount, charged),
            solTransfer(ek, relayer, bufferRent)
        ]
    });
}

/**
 * The relayer-signed fallback receive (v0, fee 0, ATA(ek) must already exist):
 * exactly [SetComputeUnitLimit(≤ 1.4M, no price), receive_message(payer =
 * caller = relayer, recipient = ATA(ek))] of exactly `message`, with an
 * attestation by the pinned attesters. The wallet does not sign it (nothing of
 * ek's is spent); it checks and broadcasts it.
 */
export function validateRelayReceiveTransaction(bytes, { funding, relayer, ek, fee, message, lookupTables, attesters,
    threshold, feeRecipientTokenAccount = null, version = 0 }) {
    if (decimal(fee, 'relay receive fee') !== 0n) {
        throw cctpError('A relayed receive is free; the relayer asked for a fee.', 'relay_fee_above_cap');
    }
    let decoded;
    try {
        decoded = decodeTransaction(bytes, lookupTables);
    } catch (error) {
        throw cctpError(`The relayer's receive transaction is malformed (${error.message}).`, 'cctp_relay_tx_rejected');
    }
    // Take the attestation from the transaction, but only for the exact
    // message the wallet validated, and only if the pinned attesters signed it.
    const receive = decoded.instructions[1];
    if (!receive || receive.programId !== MESSAGE_TRANSMITTER_V2
        || !equalBytes(receive.data.slice(0, 8), RECEIVE_MESSAGE_DISCRIMINATOR) || receive.data.length < 16) {
        throw cctpError('The relayer\'s receive transaction does not receive the transfer.', 'cctp_relay_tx_rejected');
    }
    const messageLength = readU32(receive.data, 8);
    const embedded = receive.data.slice(12, 12 + messageLength);
    const attestationLength = embedded.length === messageLength && receive.data.length >= 16 + messageLength
        ? readU32(receive.data, 12 + messageLength) : 0;
    const attestation = receive.data.slice(16 + messageLength, 16 + messageLength + attestationLength);
    if (!equalBytes(embedded, fromHex(message, 'CCTP message'))) {
        throw cctpError('The relayer receives a different CCTP message.', 'cctp_relay_tx_rejected');
    }
    verifyCctpAttestation(message, `0x${toHex(attestation)}`, { attesters, threshold });
    return assertExactTransaction(bytes, {
        label: 'receive',
        feePayer: relayer,
        presigned: [relayer],
        version,
        lookupTables,
        instructions: [
            { computeBudget: 2 },
            receiveMessageInstruction({ payer: relayer, caller: relayer, message: embedded, attestation,
                recipientTokenAccount: usdcAssociatedTokenAddress(ek), mint: funding.usdc_mint,
                ...(feeRecipientTokenAccount ? { feeRecipientTokenAccount } : {}) })
        ]
    });
}

/**
 * The ek-signed exit (v0 or legacy): [heap, CU limit, CreateIdempotent(ATA(ek))
 * (mutual only), execute_close | execute_escape(owner = relayer, destination =
 * ATA(ek)) of exactly this proof, TransferChecked(fee) iff fee > 0].
 */
export async function validateRelayExitTransaction(bytes, { funding, kind, relayer, ek, feeAccount, fee, maxFee,
    publicInputs, proof, lookupTables = [], version = 0 }) {
    const amount = relayFee(fee, maxFee, kind === 'mutual' ? 'close' : 'escape');
    if (kind === 'mutual' && amount > BigInt(publicInputs.final_balance)) {
        throw cctpError('The relayer\'s close fee exceeds the payout.', 'relay_fee_above_cap');
    }
    const ata = usdcAssociatedTokenAddress(ek);
    const exit = await solanaExitInstruction(funding, kind, { payer: relayer, destination: ata,
        public_inputs: publicInputs, proof });
    return assertExactTransaction(bytes, {
        label: kind === 'mutual' ? 'close' : 'escape',
        feePayer: relayer,
        presigned: [],
        unsigned: [relayer, ek],
        version,
        lookupTables,
        instructions: [
            { computeBudget: 1 },
            { computeBudget: 2 },
            ...(kind === 'mutual' ? [createUsdcAccountIdempotentInstruction({ payer: relayer, owner: ek })] : []),
            exit,
            ...feeTransfer(funding, ek, feeAccount, amount)
        ]
    });
}

/**
 * The ek-signed burn: [TransferChecked(fee) iff fee > 0,
 * deposit_for_burn(_with_hook)] exactly as this wallet builds it, signed only
 * by the relayer (fee payer, event rent payer), the fresh event keypair and ek.
 */
export function validateRelayBurnTransaction(bytes, { funding, relayer, ek, feeAccount, eventAccount, fee, maxFee,
    amount, balance, target }) {
    const relayAmount = relayFee(fee, maxFee, 'burn');
    const burned = decimal(amount, 'burn amount');
    if (burned !== BigInt(balance) - relayAmount || burned <= BigInt(target.maxCctpFee)) {
        throw cctpError('The relayer\'s burn does not move exactly the remaining balance.', 'cctp_relay_tx_rejected');
    }
    base58Decode(eventAccount, 32, 'message_sent_event_account');
    if ([relayer, ek].includes(eventAccount)) throw cctpError('The relayer reused a key as the event account.', 'cctp_relay_tx_rejected');
    return assertExactTransaction(bytes, {
        label: 'burn',
        feePayer: relayer,
        presigned: [],
        unsigned: [relayer, eventAccount, ek],
        instructions: [
            ...feeTransfer(funding, ek, feeAccount, relayAmount),
            depositForBurnInstruction({
                owner: new PublicKey(ek),
                eventRentPayer: new PublicKey(relayer),
                burnTokenAccount: new PublicKey(usdcAssociatedTokenAddress(ek)),
                messageSentEventData: new PublicKey(eventAccount),
                amount: burned,
                destinationDomain: target.destinationDomain,
                mintRecipient: new PublicKey(target.mintRecipient),
                destinationCaller: new PublicKey(target.destinationCaller),
                maxFee: BigInt(target.maxCctpFee),
                minFinalityThreshold: target.minFinalityThreshold,
                hookData: target.hookData
            })
        ]
    });
}

/** The ek-signed sweep: [TransferChecked(fee) iff fee > 0, TransferChecked(rest → destination)]. */
export function validateRelaySweepTransaction(bytes, { funding, relayer, ek, feeAccount, destination, fee, maxFee,
    amount, balance }) {
    const relayAmount = relayFee(fee, maxFee, 'sweep');
    const moved = decimal(amount, 'sweep amount');
    if (moved !== BigInt(balance) - relayAmount || moved <= 0n) {
        throw cctpError('The relayer\'s sweep does not move exactly the remaining balance.', 'cctp_relay_tx_rejected');
    }
    return assertExactTransaction(bytes, {
        label: 'sweep',
        feePayer: relayer,
        presigned: [],
        unsigned: [relayer, ek],
        instructions: [
            ...feeTransfer(funding, ek, feeAccount, relayAmount),
            transferCheckedInstruction({ source: usdcAssociatedTokenAddress(ek), mint: funding.usdc_mint, destination,
                authority: ek, amount: moved })
        ]
    });
}

/** D7 refund policy: only after `refund_after` unless the user forces it. */
export function assertRefundAllowed(intent, { now = Math.floor(Date.now() / 1000), force = false } = {}) {
    const refundAfter = Number(intent.refundAfter);
    if (!force && now < refundAfter) {
        throw cctpError(`This deposit can be refunded from ${new Date(refundAfter * 1000).toISOString()}; pass { force: true } to refund now.`,
            'cctp_refund_too_early', { refundAfter });
    }
    return true;
}

// ---------------------------------------------------------------------------
// Chain reads

async function ekBalance(funding, ek, signal) {
    const account = await readUsdcTokenAccount(funding, usdcAssociatedTokenAddress(ek), signal ? { signal } : undefined);
    if (account && !account.creditable) {
        throw cctpError('The emergency-key USDC account is frozen.', 'cctp_ata_frozen');
    }
    return account ? BigInt(account.amount) : 0n;
}

async function accountExists(funding, address, signal) {
    const result = await solanaRpc(funding, 'getAccountInfo', [address, { commitment: 'confirmed', encoding: 'base64' }],
        signal || AbortSignal.timeout(20_000));
    return result?.value || null;
}

async function nonceUsed(funding, nonce, signal) {
    const account = await accountExists(funding, usedNonce(nonce).toBase58(), signal);
    if (account?.owner !== MESSAGE_TRANSMITTER_V2) return false;
    const data = base64Bytes(account.data?.[0] || '');
    return equalBytes(data, Uint8Array.of(212, 222, 157, 252, 130, 71, 179, 238, 1));
}

/** Note and pending-withdrawal state of `noteId` at finalized commitment. */
export async function readFinalizedNoteState(funding, noteId, signal = AbortSignal.timeout(20_000)) {
    const note = notePda(funding, noteId);
    const pending = pendingPda(funding, noteId);
    const response = await solanaRpc(funding, 'getMultipleAccounts', [[note, pending],
        { commitment: 'finalized', encoding: 'base64' }], signal);
    if (!Array.isArray(response?.value) || response.value.length !== 2) {
        throw new Error('The Solana RPC returned malformed accounts.');
    }
    const decode = (entry, decoder, address) => {
        if (!entry) return null;
        if (entry.owner !== funding.program_id || entry.executable !== false) {
            throw new Error(`Solana account ${address} is not owned by the vault program.`);
        }
        const decoded = decoder(base64Bytes(entry.data[0]));
        if (decoded.vault !== funding.vault_state || decoded.noteId !== noteId) {
            throw new Error(`Solana account ${address} belongs to a different note.`);
        }
        return Object.freeze({ ...decoded, address });
    };
    return Object.freeze({
        slot: String(response.context?.slot ?? 0),
        note: decode(response.value[0], decodeSolanaNoteState, note),
        pending: decode(response.value[1], decodeSolanaPendingWithdrawal, pending)
    });
}

async function latestBlockhash(funding, signal) {
    const result = await solanaRpc(funding, 'getLatestBlockhash', [{ commitment: 'finalized' }], signal);
    const value = result?.value;
    base58Decode(value?.blockhash, 32, 'recent blockhash');
    if (!Number.isSafeInteger(value?.lastValidBlockHeight)) throw new Error('The Solana RPC returned an invalid blockhash.');
    return value;
}

// A relay's last_valid_height is unsigned metadata, not an expiry proof.
// Observe the exact blockhash in the trusted RPC's queue, then capture an
// upper bound on its lifetime from a head at least as new as that observation.
async function relayExpiryHeight(funding, bytes, signal, requireValid = true) {
    const blockhash = VersionedTransaction.deserialize(Uint8Array.from(bytes)).message.recentBlockhash;
    const seen = await solanaRpc(funding, 'isBlockhashValid',
        [blockhash, { commitment: 'processed' }], signal);
    if (!Number.isSafeInteger(seen?.context?.slot) || (requireValid && seen.value !== true)) {
        throw cctpError('The prepared relay blockhash is not valid at the trusted RPC.', 'cctp_relay_tx_rejected');
    }
    const head = await solanaRpc(funding, 'getLatestBlockhash',
        [{ commitment: 'processed', minContextSlot: seen.context.slot }], signal);
    const height = head?.value?.lastValidBlockHeight;
    if (!Number.isSafeInteger(height) || height < 0) throw new Error('The Solana RPC returned an invalid blockhash lifetime.');
    return height;
}

// ---------------------------------------------------------------------------
// The emergency key as a Wallet Standard signer (self-funded paths reuse the
// existing single-signer journaled flows with ek as payer).

export function emergencyKeyWallet(keypair, chain) {
    const publicKey = keypair.publicKey.toBytes();
    const account = Object.freeze({ address: keypair.publicKey.toBase58(), publicKey, chains: [chain],
        features: ['solana:signTransaction'] });
    const wallet = Object.freeze({
        features: {
            'solana:signTransaction': {
                signTransaction: async ({ transaction }) => {
                    const signed = VersionedTransaction.deserialize(Uint8Array.from(transaction));
                    signed.sign([keypair]);
                    return [{ signedTransaction: signed.serialize() }];
                }
            }
        }
    });
    return { wallet, account };
}

function ekFromSecret(secret) {
    const derived = deriveEmergencyKey(BigInt(secret));
    return Object.freeze({ keypair: derived.keypair, publicKey: derived.publicKey.toBase58(), seed: toHex(derived.seed) });
}

function ekFromSeed(seed) {
    const keypair = Keypair.fromSeed(fromHex(seed, 'emergency key seed'));
    return Object.freeze({ keypair, publicKey: keypair.publicKey.toBase58(), seed });
}

function toWeb3(plain) {
    return new TransactionInstruction({
        programId: new PublicKey(plain.programId),
        keys: plain.keys.map(key => ({ pubkey: new PublicKey(key.pubkey), isSigner: key.isSigner, isWritable: key.isWritable })),
        data: Uint8Array.from(plain.data)
    });
}

/**
 * The transaction can never land: its blockhash expired (on chain, or as the
 * relay reports on submit) or it failed on chain. Only then is it re-prepared.
 */
function isFinalFailure(error) {
    return ['solana_blockhash_expired', 'relay_transaction_expired'].includes(error?.code)
        || error?.transactionError != null;
}

/** The attested inbound transfer that funded ATA(ek): the relay's sponsorship credential, if known. */
function inboundCredential(plan) {
    const attested = plan?.cctp?.attested;
    return attested ? { source_domain: plan.cctp.sourceDomain, message: attested.message,
        attestation: attested.attestation } : null;
}

/**
 * Sign a validated, unsigned relay transaction with ek: the journal record to
 * persist before `/v2/relay/submit` (no signature until the relay returns it).
 */
async function ekSignedRecord(prepared, ek, funding, lookupTables = [], signal) {
    const expiryHeight = await relayExpiryHeight(funding, prepared.bytes, signal);
    const signed = signTransactionWith(prepared.bytes, [ek.keypair]);
    return { signature: null, bytes: Array.from(signed.bytes), submitToken: prepared.submitToken,
        format: prepared.format, lastValidHeight: prepared.lastValidHeight, expiryHeight, lookupTables };
}

// ---------------------------------------------------------------------------
// Flows

const report = (onStatus, phase, message, extra = {}) => {
    try {
        onStatus?.({ phase, message, ...extra });
    } catch (error) {
        console.warn('A CCTP status listener failed.', error);
    }
};

function backupPayload(plan) {
    return Object.freeze({
        recoveryScope: 'Emergency-key funds and never-used notes only. Used notes require their latest private state and pending-request journal.',
        operationId: plan.operationId,
        secret: plan.secret,
        commitment: plan.commitment,
        emergencyKey: plan.cctp.ekPublicKey,
        emergencyAccount: plan.cctp.ata,
        sourceChain: plan.cctp.sourceChain,
        burner: plan.cctp.burner,
        burnAmount: plan.cctp.burnAmount,
        authorizedCctpFee: plan.cctp.maxFee,
        minFinalityThreshold: plan.cctp.minFinalityThreshold,
        burnTxHash: plan.cctp.burnTxHash || null,
        refundAfter: plan.cctp.refundAfter,
        intent: plan.cctp.intent,
        hook: plan.cctp.hook,
        storagePersisted: plan.cctp.storagePersisted
    });
}

/**
 * The program-free CCTP wallet. `runtime` is the BrowserWalletRuntime (its
 * durable plan/record methods are the journal); every phase is persisted
 * before the next network side effect, so each flow resumes after a reload by
 * calling it again.
 */
export class ZkapiCctpWallet {
    constructor({ runtime, options = {}, transport = browserSdkTransport, now = () => Date.now() } = {}) {
        if (!runtime) throw new TypeError('A browser wallet runtime is required.');
        this.runtime = runtime;
        this.overrides = options;
        this.transport = transport;
        this.now = now;
    }

    get options() {
        return resolveCctpOptions(this.overrides);
    }

    get funding() {
        return validateSolanaFunding(this.runtime.config?.funding);
    }

    /** The pinned attester set: configured, else Circle's for the network; never Iris-supplied. */
    get attestation() {
        const options = this.options;
        const attesters = options.attesters || CIRCLE_ATTESTERS[this.funding.network] || null;
        if (!attesters) {
            throw cctpError(`No Circle attesters are pinned for ${this.funding.network}; configure cctp.attesters.`,
                'cctp_attesters_unconfigured');
        }
        return { attesters, threshold: options.attestationThreshold };
    }

    relay() {
        return cctpRelayClient(this.options.relayUrl || this.funding.protocol_server_url, this.transport);
    }

    async relayInfo() {
        return validateRelayInfo(await this.relay().info(), this.funding);
    }

    /** Relay info, or a clear "funds are safe in ATA(ek)" error carrying the self-funded path. */
    async requireRelay(ek, kind) {
        try {
            return await this.relayInfo();
        } catch (error) {
            if (!error.relayUnavailable) throw error;
            throw await this.relayUnavailableError(ek, kind, error);
        }
    }

    async relayUnavailableError(ek, kind, cause) {
        let balance = null;
        try {
            balance = ek ? String(await ekBalance(this.funding, ek)) : null;
        } catch {
            balance = null;
        }
        const ata = ek ? usdcAssociatedTokenAddress(ek) : null;
        return cctpError(ek
            ? `No CCTP relayer is available. Your USDC is safe in your emergency-key account ${ata} (owner ${ek}). Fund ${ek} with about 0.005 SOL and retry with { selfFunded: true }, or try again later.`
            : 'No CCTP relayer is available. Nothing was spent; try again later.',
        'relay_unavailable', { cause, emergencyKey: ek, emergencyAccount: ata, balance, kind, selfFundedAvailable: Boolean(ek) });
    }

    /** Iris: the configured URL, Circle's for the network, else the relayer's (local iris-sim). */
    async iris() {
        let url = this.options.irisUrl || DEFAULT_IRIS_URLS[this.funding.network] || null;
        if (!url) {
            try {
                url = (await this.relayInfo()).irisUrl;
            } catch (error) {
                if (!error.relayUnavailable) throw error;
            }
        }
        if (!url) throw cctpError('No Circle Iris URL is configured for this network.', 'cctp_iris_unconfigured');
        return irisClient(url, (target, init) => this.transport(target, init));
    }

    /**
     * Poll Iris for the burn in `txHash` until it is attested; the message is
     * returned only after `check(decoded, bytes)` and the attester signatures
     * pass. Returns null on timeout.
     */
    async waitForAttestation(iris, sourceDomain, txHash, { timeoutMs, signal, check }) {
        const deadline = this.now() + (timeoutMs ?? this.options.attestationTimeoutMs);
        const pinned = this.attestation;
        while (true) {
            let response = null;
            try {
                response = await iris.messages(sourceDomain, txHash);
            } catch (error) {
                if (error?.status === 429) await sleep(this.options.pollIntervalMs * 4, signal);
            }
            const entries = Array.isArray(response?.messages) ? response.messages : [];
            if (entries.length > 1) throw cctpError('Iris returned several messages for one burn.', 'cctp_message_mismatch');
            const entry = entries[0];
            if (entry?.status === 'complete' && typeof entry.attestation === 'string' && entry.attestation !== 'PENDING') {
                const bytes = fromHex(entry.message, 'CCTP message');
                const decoded = decodeMessageV2(bytes);
                await check(decoded, bytes);
                verifyCctpAttestation(entry.message, entry.attestation, pinned);
                return Object.freeze({ message: `0x${toHex(bytes)}`, attestation: entry.attestation, decoded });
            }
            if (this.now() >= deadline) return null;
            await sleep(this.options.pollIntervalMs, signal);
        }
    }

    /**
     * Broadcast a journaled signed transaction and wait for finality. A send
     * error is not final (a resent transaction may already be processed, a
     * transient preflight may pass later): only finality or blockhash expiry is.
     */
    async broadcast(signed, { signal } = {}) {
        const funding = this.funding;
        const options = signal ? { signal } : undefined;
        let sendError = null;
        try {
            await sendSignedSolanaTransaction(funding, { bytes: Uint8Array.from(signed.bytes), signature: signed.signature }, options);
        } catch (error) {
            sendError = error;
        }
        try {
            return await confirmFinalizedSolanaTransaction(funding,
                { signature: signed.signature, lastValidHeight: signed.expiryHeight ?? signed.lastValidHeight }, options);
        } catch (error) {
            if (sendError && !error.sendError) error.sendError = sendError;
            throw error;
        }
    }

    /**
     * POST a journaled ek-signed relay transaction (`signature: null`) to
     * `/v2/relay/submit` with its token. The relay signs and broadcasts it; the
     * complete transaction it returns is verified and merged into the record
     * (journal it before confirming). Re-submitting the same token and bytes is
     * idempotent. A relay's expiry claim is checked against finalized height,
     * including after key rotation or a simulation rejection:
     * once finalized block height passes the RPC-derived `expiryHeight` it either
     * landed (each flow checks chain state) or never will, which is reported as
     * `relay_transaction_expired` too.
     */
    async submitRelayed(record, ek, label, signal, persist) {
        if (!Number.isSafeInteger(record.expiryHeight)) {
            // Existing journals predate the RPC-derived bound. Persist one
            // conservative fresh lifetime before retrying, even if already old.
            record = { ...record, expiryHeight: await relayExpiryHeight(this.funding, record.bytes, signal, false) };
            await persist(record);
        }
        let response;
        try {
            response = await this.relay().submit({ token: record.submitToken, transaction: Array.from(record.bytes) });
        } catch (error) {
            if (await this.blockhashExpired(record.expiryHeight, signal)) {
                throw cctpError(`The relay did not submit the ${label} transaction and its blockhash has expired.`,
                    'relay_transaction_expired', { cause: error, lastValidHeight: record.lastValidHeight });
            }
            if (error.code === 'relay_transaction_expired') {
                throw cctpError(`The ${label} transaction is not yet past its finalized lifetime. Resume it later.`,
                    'cctp_relay_pending', { cause: error });
            }
            throw error;
        }
        const verified = verifyRelaySubmission(response, { sent: record.bytes, ek, format: record.format,
            lastValidHeight: record.lastValidHeight, lookupTables: record.lookupTables || [], label });
        return { ...record, bytes: Array.from(verified.bytes), signature: verified.signature, submittedAt: this.now() };
    }

    /** Whether the finalized block height is past `lastValidHeight` (false if the RPC cannot tell). */
    async blockhashExpired(lastValidHeight, signal) {
        try {
            const height = await solanaRpc(this.funding, 'getBlockHeight', [{ commitment: 'finalized' }],
                signal || AbortSignal.timeout(20_000));
            return Number.isSafeInteger(height) && height > lastValidHeight;
        } catch {
            return false;
        }
    }

    // =======================================================================
    // Inbound

    /** The persisted CCTP deposit plan (or null). */
    async currentDeposit() {
        const plan = await this.runtime.pendingDeposit();
        return plan?.cctp ? plan : null;
    }

    async updateDeposit(plan, changes) {
        return this.runtime.updateCctpDeposit(plan.operationId, current => ({
            ...current,
            ...(changes.plan || {}),
            cctp: { ...current.cctp, ...(changes.cctp || {}), updatedAt: this.now() }
        }));
    }

    /**
     * cctpDeposit: burn USDC on an EVM chain into ATA(ek) and deposit it into
     * the vault as a new note. A new plan stops in `backup_required` until the
     * backup is acknowledged (`onBackup` resolving, or acknowledgeBackup()).
     * Call again with no arguments to resume after a reload at any phase.
     */
    async deposit({ sourceChain, amount, finality = 'fast', evmProvider = null, onStatus = () => {},
        onBackup = null, burnTxHash = null, selfFunded = false, signal = null } = {}) {
        let plan = await this.currentDeposit();
        if (!plan) {
            plan = await this.planDeposit({ sourceChain, amount, finality, evmProvider, onStatus });
        } else if (sourceChain && plan.cctp.sourceChain !== sourceChain) {
            throw cctpError('A different CCTP deposit is unfinished. Resume or cancel it first.', 'cctp_deposit_pending');
        }
        if (plan.cctp.phase === 'backup_required') {
            if (!onBackup) {
                report(onStatus, 'backup_required', 'Save the emergency backup. It restores transit funds and never-used notes, not a used note’s private state.');
                return Object.freeze({ status: 'backup_required', backup: backupPayload(plan) });
            }
            report(onStatus, 'backup', 'Save the emergency backup before burning. After private spending, keep the latest wallet state and request journal too.');
            if (await onBackup(backupPayload(plan)) === false) {
                return Object.freeze({ status: 'backup_required', backup: backupPayload(plan) });
            }
            plan = await this.acknowledgeBackup(plan.operationId);
        }
        if (plan.cctp.phase === 'recovered') {
            const hash = burnTxHash || plan.cctp.burnTxHash;
            if (!hash || !plan.cctp.minFinalityThreshold) {
                throw cctpError('Recovered emergency funds can be swept or refunded. Resuming the inbound transfer also needs its burn hash and original finality.',
                    'cctp_burn_hash_unknown', { emergencyAccount: plan.cctp.ata });
            }
            if (!/^0x[0-9a-f]{64}$/i.test(hash)) throw new TypeError('Invalid burn transaction hash.');
            plan = await this.updateDeposit(plan, { cctp: { phase: 'burn_requested', burnTxHash: hash } });
        }
        if (plan.cctp.phase === 'planned') plan = await this.burnOnEvm(plan, { evmProvider, onStatus });
        if (plan.cctp.phase === 'burn_requested' && !plan.cctp.burnTxHash) {
            if (!burnTxHash) {
                throw cctpError('The EVM burn may have been sent but its hash was not saved. Pass the transaction hash as { burnTxHash } to resume, or refund or sweep later.',
                    'cctp_burn_hash_unknown', { emergencyAccount: plan.cctp.ata });
            }
            if (!/^0x[0-9a-f]{64}$/i.test(burnTxHash)) throw new TypeError('burnTxHash must be a 0x-prefixed 32-byte hash.');
            plan = await this.updateDeposit(plan, { cctp: { burnTxHash: burnTxHash.toLowerCase() } });
        }
        if (!['arrived', 'signed', 'submitted', 'deposited'].includes(plan.cctp.phase)) {
            plan = await this.waitForArrival(plan, { onStatus, signal });
        }
        if (selfFunded && DEPOSIT_PHASES_IN_FLIGHT.has(plan.cctp.phase)) {
            // An ek-signed relay deposit is re-submitted with its token (the relay
            // may already have broadcast it) and a submitted one is rebroadcast
            // (its bytes need no relayer) until it lands or expires; only then
            // may the self-funded path spend ATA(ek).
            plan = await this.relayDeposit(plan, { onStatus, signal, resumeOnly: true });
        }
        if (plan.cctp.phase !== 'deposited') {
            plan = selfFunded
                ? await this.selfFundedDeposit(plan, { onStatus, signal })
                : await this.relayDeposit(plan, { onStatus, signal });
        }
        report(onStatus, 'confirming', 'Verifying the finalized private note…');
        const confirmed = await this.runtime.confirmSolanaDeposit();
        report(onStatus, 'complete', 'Private USDC balance is ready.');
        return confirmed;
    }

    /** Record that the user saved the backup of a planned deposit; the burn may now be requested. */
    async acknowledgeBackup(operationId = null) {
        const plan = await this.currentDeposit();
        if (!plan || (operationId && plan.operationId !== operationId)) {
            throw cctpError('There is no CCTP deposit backup to acknowledge.', 'cctp_nothing_to_acknowledge');
        }
        if (plan.cctp.phase !== 'backup_required') return plan;
        return this.updateDeposit(plan, { cctp: { phase: 'planned', backupAcknowledgedAt: this.now() } });
    }

    /** The backup of the current CCTP deposit (secret, emergency key, intent) for export. */
    async depositBackup() {
        const plan = await this.currentDeposit();
        return plan ? backupPayload(plan) : null;
    }

    /**
     * Import an initial backup without ever initiating another source burn.
     * Emergency funds are immediately sweepable/refundable. Restoring a note
     * is explicit and restricted to a note that has never authorized a request.
     */
    async importBackup(backup, { restoreUnspentNote = false, noteId = null, burnTxHash = null } = {}) {
        if (!backup || typeof backup !== 'object') throw new TypeError('A CCTP backup is required.');
        const ek = ekFromSecret(backup.secret);
        const chain = cctpEvmChain(backup.sourceChain, this.options);
        const intent = decodeInboundIntent(fromHex(backup.intent));
        const hook = encodeInboundHook({ ataOwner: ek.keypair.publicKey, intent });
        const reject = () => { throw cctpError('The CCTP backup has inconsistent identities or refund details.', 'cctp_backup_invalid'); };
        if (backup.emergencyKey !== ek.publicKey || backup.emergencyAccount !== usdcAssociatedTokenAddress(ek.publicKey)
            || !equalBytes(intent.emergencyOwner.toBytes(), ek.keypair.publicKey.toBytes())
            || !equalBytes(intent.commitment, feltBytes(backup.commitment))
            || !equalBytes(hook, fromHex(backup.hook))
            || intent.refund.domain !== chain.domain
            || !equalBytes(intent.refund.recipient, evmBytes32(backup.burner))
            || !equalBytes(intent.refund.destinationCaller, ZERO32)
            || !equalBytes(intent.refund.hookData, encodeForwardHook())
            || Number(intent.refundAfter) !== backup.refundAfter) reject();
        const hash = burnTxHash || backup.burnTxHash || null;
        if (hash && !/^0x[0-9a-f]{64}$/i.test(hash)) reject();
        if (backup.minFinalityThreshold != null && ![1000, 2000].includes(backup.minFinalityThreshold)) reject();
        const amount = decimal(backup.burnAmount, 'backup burn amount');
        const maxFee = decimal(backup.authorizedCctpFee, 'backup CCTP fee');
        if (amount <= maxFee || maxFee > cctpFeePolicyCap('inbound', amount, this.options.feePolicy)) reject();
        const plan = {
            operationId: String(backup.operationId || `recovered-${ek.publicKey}`),
            secret: backup.secret, commitment: backup.commitment, phase: 'cctp', amount: null,
            next_note_id: null, active_root: null, zero_path: null, createdAt: this.now(),
            cctp: { version: 2, phase: 'recovered', ekPublicKey: ek.publicKey,
                ata: backup.emergencyAccount, sourceChain: backup.sourceChain, sourceDomain: chain.domain,
                chainId: String(chain.chainId), burner: evmAddress(backup.burner), burnAmount: String(amount),
                maxFee: String(maxFee), minFinalityThreshold: backup.minFinalityThreshold ?? null,
                intent: backup.intent, hook: backup.hook, refundAfter: backup.refundAfter,
                burnTxHash: hash, backupAcknowledgedAt: this.now(), storagePersisted: false }
        };
        let note = null;
        if (restoreUnspentNote) {
            if (noteId == null) {
                const accounts = await solanaRpc(this.funding, 'getProgramAccounts', [this.funding.program_id, {
                    commitment: 'finalized', encoding: 'base64', filters: [{ dataSize: 110 },
                        { memcmp: { offset: 8, bytes: this.funding.vault_state } },
                        { memcmp: { offset: 44, bytes: base58Encode(feltBytes(backup.commitment)) } }]
                }], AbortSignal.timeout(20_000));
                if (!Array.isArray(accounts) || accounts.length !== 1) {
                    throw cctpError('Select the noteId to recover: no unique note matches this backup.', 'cctp_recovery_note_ambiguous');
                }
                noteId = decodeSolanaNoteState(base64Bytes(accounts[0].account.data[0])).noteId;
            }
            if (!Number.isSafeInteger(noteId) || noteId < 0 || noteId > 0xffffffff) reject();
            const state = await readFinalizedNoteState(this.funding, noteId);
            note = state.note;
            if (!note || state.pending || note.status !== 'active'
                || !Number.isSafeInteger(Number(note.amount)) || !Number.isSafeInteger(Number(note.expiry))
                || BigInt(note.commitment) !== BigInt(backup.commitment)) {
                throw cctpError('This is not an active, never-exited note matching the backup.', 'cctp_recovery_note_invalid');
            }
        }
        await this.runtime.importCctpBackup(plan, note);
        return Object.freeze({ status: note ? 'unspent_note_restored' : 'emergency_key_restored',
            emergencyKey: ek.publicKey, emergencyAccount: plan.cctp.ata,
            recoveryScope: 'Used notes require their latest private state and pending-request journal.' });
    }

    async planDeposit({ sourceChain, amount, finality, evmProvider }) {
        const options = this.options;
        const chain = cctpEvmChain(sourceChain, options);
        if (!evmProvider) throw new TypeError('An EIP-1193 EVM provider is required for a CCTP deposit.');
        const burnAmount = typeof amount === 'bigint' ? amount : parseUnits(String(amount ?? ''), USDC_DECIMALS);
        if (burnAmount <= 0n || burnAmount > MAX_SAFE) throw new Error('Enter a positive USDC amount.');
        this.attestation; // Attesters must be pinned before anything is burned.
        const relay = await this.requireRelay(null, 'deposit');
        const burner = await requestEvmAccount(evmProvider);
        await ensureEvmChain(evmProvider, chain.chainId);
        const evmBalance = await readErc20Balance(evmProvider, chain.usdc, burner);
        if (evmBalance < burnAmount) {
            throw cctpError(`Your ${sourceChain} USDC balance is below this amount.`, 'evm_insufficient_usdc');
        }
        const iris = await this.iris();
        const inbound = cctpMaxFee({
            fees: await iris.fees(chain.domain, SOLANA_DOMAIN, { forward: true, includeRecipientSetup: true }),
            amount: burnAmount, finality, forward: true,
            fastAllowed: !options.standardOnlySources.includes(sourceChain),
            policyCap: cctpFeePolicyCap('inbound', burnAmount, options.feePolicy),
            headroomBps: options.forwardFeeHeadroomBps, minHeadroom: options.minFeeHeadroom
        });
        // The refund burns back from Solana: Standard there is ~17 s and free.
        const refund = cctpMaxFee({
            fees: await iris.fees(SOLANA_DOMAIN, chain.domain, { forward: true }), amount: burnAmount,
            finality: 'standard', forward: true, policyCap: cctpFeePolicyCap('outboundForward', burnAmount, options.feePolicy),
            headroomBps: options.forwardFeeHeadroomBps, minHeadroom: options.minFeeHeadroom
        });
        const caps = options.feeCaps;
        if (burnAmount <= inbound.maxFee + caps.deposit) {
            throw cctpError('This amount does not cover the CCTP and relay fees.', 'cctp_amount_too_small');
        }
        const nowSeconds = BigInt(Math.floor(this.now() / 1000));
        const plan = await this.runtime.beginCctpDeposit(({ secret, commitment }) => {
            const ek = ekFromSecret(secret);
            const intent = {
                version: 1,
                commitment: feltBytes(commitment),
                emergencyOwner: new PublicKey(ek.publicKey),
                maxRelayerFee: caps.deposit,
                priorityRelayer: new PublicKey(relay.relayer),
                priorityUntil: nowSeconds + BigInt(options.priorityWindowSeconds),
                refundAfter: nowSeconds + BigInt(options.refundDelaySeconds),
                refund: {
                    domain: chain.domain,
                    recipient: evmBytes32(burner),
                    destinationCaller: ZERO32,
                    maxCctpFee: refund.maxFee,
                    minFinality: refund.minFinalityThreshold,
                    hookData: encodeForwardHook({ createAtaOwner: null })
                }
            };
            const intentBytes = encodeInboundIntent(intent);
            const hook = encodeInboundHook({ ataOwner: new PublicKey(ek.publicKey), intent });
            const decoded = decodeHook(hook);
            if (!decoded?.forward || !decoded.intent
                || !equalBytes(encodeInboundIntent(decoded.intent), intentBytes)) {
                throw new Error('The inbound CCTP hook does not round-trip.');
            }
            return {
                version: 2,
                phase: 'backup_required',
                sourceChain,
                sourceDomain: chain.domain,
                chainId: String(chain.chainId),
                burner,
                burnAmount: String(burnAmount),
                maxFee: String(inbound.maxFee),
                minFinalityThreshold: inbound.minFinalityThreshold,
                ekPublicKey: ek.publicKey,
                ata: usdcAssociatedTokenAddress(ek.publicKey),
                relayer: relay.relayer,
                intent: toHex(intentBytes),
                hook: toHex(hook),
                refundAfter: Number(intent.refundAfter),
                storagePersisted: null,
                backupAcknowledgedAt: null,
                burnTxHash: null,
                approveTxHash: null,
                attested: null,
                receive: null,
                createdAt: this.now()
            };
        });
        // The secret is durable in IndexedDB before any EVM prompt. Whether the
        // browser also promised not to evict it is recorded and shown in the
        // backup; the backup is mandatory either way.
        const storagePersisted = await requestPersistentStorage();
        return this.updateDeposit(plan, { cctp: { storagePersisted } });
    }

    async burnOnEvm(plan, { evmProvider, onStatus }) {
        if (!plan.cctp.backupAcknowledgedAt) {
            throw cctpError('Save and acknowledge the note backup before the burn.', 'cctp_backup_required');
        }
        if (!evmProvider) throw new TypeError('An EIP-1193 EVM provider is required to burn on the source chain.');
        const chain = cctpEvmChain(plan.cctp.sourceChain, this.options);
        const burner = await requestEvmAccount(evmProvider);
        if (burner !== plan.cctp.burner) {
            throw cctpError(`Switch your EVM wallet to ${plan.cctp.burner}: this deposit refunds to that address.`,
                'evm_account_mismatch');
        }
        await ensureEvmChain(evmProvider, chain.chainId);
        const amount = BigInt(plan.cctp.burnAmount);
        if (await readErc20Balance(evmProvider, chain.usdc, burner) < amount) {
            throw cctpError(`Your ${plan.cctp.sourceChain} USDC balance is below this amount.`, 'evm_insufficient_usdc');
        }
        const ata = plan.cctp.ata;
        if (ata !== usdcAssociatedTokenAddress(plan.cctp.ekPublicKey)) throw new Error('The CCTP deposit plan is corrupt.');
        report(onStatus, 'approving', 'Approve USDC for Circle\'s TokenMessenger in your EVM wallet…');
        let current = plan;
        await burnUsdcOnEvm({
            provider: evmProvider,
            chain,
            from: burner,
            amount,
            approveCalldata: evmApproveCalldata(chain.tokenMessenger, amount),
            burnCalldata: evmDepositForBurnWithHookCalldata({
                amount,
                destinationDomain: SOLANA_DOMAIN,
                mintRecipient: base58Decode(ata, 32),
                burnToken: chain.usdc,
                destinationCaller: ZERO32,
                maxFee: BigInt(plan.cctp.maxFee),
                minFinalityThreshold: plan.cctp.minFinalityThreshold,
                hookData: fromHex(plan.cctp.hook)
            }),
            onApproveHash: async hash => {
                current = await this.updateDeposit(current, { cctp: { approveTxHash: hash } });
            },
            onBurnRequested: async () => {
                report(onStatus, 'burning', 'Confirm the CCTP burn in your EVM wallet…');
                current = await this.updateDeposit(current, { cctp: { phase: 'burn_requested' } });
            },
            onBurnHash: async hash => {
                current = await this.updateDeposit(current, { cctp: { burnTxHash: hash } });
                report(onStatus, 'burn_sent', 'Burn sent. Waiting for it to confirm…', { transactionHash: hash });
            },
            receiptOptions: this.options.evmReceipt
        });
        return this.updateDeposit(current, { cctp: { phase: 'burned', burnedAt: this.now() } });
    }

    /**
     * Attestation first, then arrival. The fully validated attested message
     * fixes the net mint (amount − feeExecuted) and its nonce; the deposit
     * counts as arrived only once that nonce is used on Solana and ATA(ek)
     * holds the net mint (less any receive fee this wallet paid). Dust or other
     * transfers to ATA(ek) never stand in for the transfer.
     */
    async waitForArrival(plan, { onStatus, signal }) {
        const funding = this.funding;
        const options = this.options;
        const iris = await this.iris();
        const chain = cctpEvmChain(plan.cctp.sourceChain, options);
        let current = plan;
        const deadline = this.now() + options.arrivalTimeoutMs;
        report(onStatus, 'attesting', 'Waiting for Circle to attest the burn…');
        while (true) {
            if (!current.cctp.attested) {
                const attested = await this.waitForAttestation(iris, current.cctp.sourceDomain, current.cctp.burnTxHash, {
                    timeoutMs: 0, signal,
                    check: decoded => assertInboundMessage(decoded, { sourceDomain: current.cctp.sourceDomain,
                        tokenMessenger: chain.tokenMessenger, usdc: chain.usdc, ata: current.cctp.ata,
                        amount: current.cctp.burnAmount, burner: current.cctp.burner, maxFee: current.cctp.maxFee,
                        minFinalityThreshold: current.cctp.minFinalityThreshold, hook: current.cctp.hook })
                });
                if (attested) {
                    const body = attested.decoded.body;
                    current = await this.updateDeposit(current, { cctp: { phase: 'attested', attestedAt: this.now(),
                        attested: { message: attested.message, attestation: attested.attestation,
                            nonce: toHex(attested.decoded.nonce), feeExecuted: String(body.feeExecuted),
                            netAmount: String(body.amount - body.feeExecuted) } } });
                    report(onStatus, 'attested', 'Circle attested the burn. Waiting for the mint on Solana…');
                }
            }
            if (current.cctp.attested) {
                if (current.cctp.receive && !current.cctp.receive.finalizedAt) {
                    current = await this.finishFallbackReceive(current, { onStatus, signal });
                }
                const available = this.availableAfterArrival(current);
                const minted = await nonceUsed(funding, fromHex(current.cctp.attested.nonce), signal);
                const balance = await ekBalance(funding, current.cctp.ekPublicKey, signal);
                if (minted && balance >= available) {
                    report(onStatus, 'arrived', 'USDC arrived in your emergency-key account on Solana.',
                        { balance: String(balance) });
                    return this.updateDeposit(current, { cctp: { phase: 'arrived', arrivedAt: this.now(),
                        arrived: String(available), excess: String(balance - available) } });
                }
                const lastTry = current.cctp.receiveAttemptedAt || current.cctp.attestedAt;
                if (!minted && !current.cctp.receive && this.now() - lastTry >= options.receiveFallbackMs) {
                    const expiration = decodeMessageV2(fromHex(current.cctp.attested.message)).body.expirationBlock;
                    const expired = expiration !== 0n && expiration <= BigInt(await solanaRpc(funding,
                        'getSlot', [{ commitment: 'confirmed' }], signal || AbortSignal.timeout(20_000)));
                    if (expired) {
                        await iris.reattest(fromHex(current.cctp.attested.nonce));
                        current = await this.updateDeposit(current, { cctp: { phase: 'burned', attested: null,
                            receiveAttemptedAt: this.now() } });
                    } else {
                        current = await this.requestFallbackReceive(current, { onStatus, signal });
                    }
                }
            }
            if (this.now() > deadline) {
                throw cctpError(`The USDC has not arrived yet. It is safe: it can only reach ${current.cctp.ata}. Resume later.`,
                    'cctp_arrival_pending', { emergencyAccount: current.cctp.ata, transactionHash: current.cctp.burnTxHash });
            }
            await sleep(options.pollIntervalMs, signal);
        }
    }

    /** USDC of this transfer available in ATA(ek): the net mint less any receive fee this wallet paid. */
    availableAfterArrival(plan) {
        const paid = plan.cctp.receive?.finalizedAt ? BigInt(plan.cctp.receive.fee) : 0n;
        return BigInt(plan.cctp.attested.netAmount) - paid;
    }

    /**
     * Circle's forwarder is late: the relayer prepares and signs a free
     * receive_message into the existing ATA(ek); the wallet checks it exactly
     * and broadcasts it. Retried at most every `receiveFallbackMs`.
     */
    async requestFallbackReceive(plan, { onStatus, signal }) {
        const funding = this.funding;
        report(onStatus, 'receiving', 'Asking the relayer to receive the attested transfer…');
        let current = await this.updateDeposit(plan, { cctp: { receiveAttemptedAt: this.now() } });
        let relay;
        let response;
        try {
            relay = await this.relayInfo();
            response = await this.relay().prepareReceive({ source_domain: plan.cctp.sourceDomain,
                transaction_hash: plan.cctp.burnTxHash, owner: plan.cctp.ekPublicKey,
                max_fee: String(relayFeeCap('receive', this.options.feeCaps)) });
        } catch (error) {
            // Unavailable subsidy never prevents Circle's forwarder or an
            // independently funded receive from completing the same transfer.
            if (error.relayUnavailable || ['insufficient_funds', 'rate_limited', 'receive_below_minimum',
                'receive_budget_exhausted', 'receive_address_limited', 'relay_loss_budget_exhausted',
                'relay_failure_limited'].includes(error.code)) {
                return this.updateDeposit(current, { cctp: { receiveRefused: { code: error.code, at: this.now() } } });
            }
            throw error;
        }
        if (response.recipient_token_account !== plan.cctp.ata) {
            throw cctpError('The relayer would receive the transfer into a different account.', 'cctp_relay_tx_rejected');
        }
        if (response.transaction == null) return current; // Already received (Circle's forwarder or anyone else).
        const prepared = preparedTransaction(response.transaction, 'receive');
        const lookupTables = await readLookupTables(funding, prepared.lookupTables, signal || undefined);
        const decoded = validateRelayReceiveTransaction(prepared.bytes, { funding, relayer: relay.relayer,
            ek: plan.cctp.ekPublicKey, fee: response.fee, message: plan.cctp.attested.message, lookupTables,
            ...this.attestation, feeRecipientTokenAccount: this.options.feeRecipientTokenAccount,
            version: prepared.version });
        current = await this.updateDeposit(current, { cctp: { receive: {
            signature: base58Encode(decoded.signatures[0]), bytes: Array.from(prepared.bytes),
            lastValidHeight: prepared.lastValidHeight, fee: '0', preparedAt: this.now() } } });
        return this.finishFallbackReceive(current, { onStatus, signal });
    }

    async finishFallbackReceive(plan, { onStatus, signal }) {
        report(onStatus, 'receiving', 'Submitting the relayer-signed receive…');
        try {
            await this.broadcast(plan.cctp.receive, { signal });
        } catch (error) {
            // Expired or failed (e.g. Circle's forwarder used the nonce first).
            if (!isFinalFailure(error)) throw error;
            return this.updateDeposit(plan, { cctp: { receive: null,
                failedReceives: [...(plan.cctp.failedReceives || []), plan.cctp.receive.signature] } });
        }
        return this.updateDeposit(plan, { cctp: { receive: { ...plan.cctp.receive, finalizedAt: this.now() } } });
    }

    /**
     * Fresh vault path + atomic ek-owned deposit, validated exhaustively and
     * signed with ek. Phase `signed`: the ek-signed bytes and submit token are
     * journaled and (re-)submitted to the relay; `submitted`: the complete
     * relay-signed bytes are journaled and confirmed (rebroadcast if needed).
     * `resumeOnly` finishes an in-flight deposit but never prepares a new one
     * (the plan is returned in `arrived` once it can no longer land).
     */
    async relayDeposit(plan, { onStatus, signal, resumeOnly = false }) {
        const funding = this.funding;
        const ek = ekFromSecret(plan.secret);
        if (ek.publicKey !== plan.cctp.ekPublicKey) throw new Error('The CCTP deposit plan does not match its secret.');
        let current = plan;
        for (let attempt = 0; attempt < 3; attempt += 1) {
            if (!DEPOSIT_PHASES_IN_FLIGHT.has(current.cctp.phase)) {
                if (resumeOnly) return current;
                current = await this.prepareRelayDeposit(current, ek, { onStatus, signal });
            }
            try {
                if (current.cctp.phase === 'signed') {
                    report(onStatus, 'submitting', 'Submitting the emergency-key deposit to the relayer…');
                    const deposit = await this.submitRelayed(current.cctp.deposit, ek.publicKey, 'deposit', signal,
                        deposit => this.updateDeposit(current, { cctp: { deposit } }));
                    current = await this.updateDeposit(current, { cctp: { phase: 'submitted', deposit } });
                }
                report(onStatus, 'submitting', 'Confirming the emergency-key deposit transaction…',
                    { signature: current.cctp.deposit.signature });
                await this.broadcast(current.cctp.deposit, { signal });
                return this.updateDeposit(current, { cctp: { phase: 'deposited', depositedAt: this.now() } });
            } catch (error) {
                // Expired or failed: it can never land. Only then re-stage.
                const state = await readFinalizedNoteState(funding, current.cctp.deposit.noteId);
                if (state.note && BigInt(state.note.commitment) === BigInt(current.commitment)) {
                    return this.updateDeposit(current, { cctp: { phase: 'deposited', depositedAt: this.now() } });
                }
                if (!isFinalFailure(error)) throw error;
                const failed = current.cctp.deposit.signature;
                current = await this.updateDeposit(current, { cctp: { phase: 'arrived', deposit: null,
                    failedDeposits: [...(current.cctp.failedDeposits || []), ...(failed ? [failed] : [])] } });
            }
        }
        throw cctpError('The deposit could not be executed after three attempts. Your USDC is safe in your emergency-key account.',
            'cctp_deposit_failed', { emergencyAccount: plan.cctp.ata });
    }

    async prepareRelayDeposit(plan, ek, { onStatus, signal }) {
        const funding = this.funding;
        const options = this.options;
        const relay = await this.requireRelay(ek.publicKey, 'deposit');
        // Only this transfer's net mint is deposited; anything else in ATA(ek) stays sweepable.
        const available = this.availableAfterArrival(plan);
        const balance = await ekBalance(funding, ek.publicKey, signal);
        if (balance < available) {
            throw cctpError('The emergency-key account no longer holds the arrived transfer.', 'cctp_arrival_missing',
                { emergencyAccount: plan.cctp.ata });
        }
        const cap = relayFeeCap('deposit', options.feeCaps);
        const quoted = relay.quotes.deposit;
        report(onStatus, 'preparing', 'Reading the vault and preparing the atomic deposit…');
        const vault = assertSolanaDepositsOpen(await assertSolanaVault(funding));
        const path = await this.runtime.nextDepositPath(vault.root);
        const attempt = async fee => {
            const amount = available - fee;
            if (amount <= 0n) {
                throw cctpError('The arrived USDC does not cover the relay fee. Sweep or refund it instead.',
                    'cctp_amount_too_small', { emergencyAccount: plan.cctp.ata });
            }
            const staged = await this.updateDeposit(plan, { plan: { amount: Number(amount), next_note_id: path.note_id,
                active_root: path.active_root, zero_path: path.siblings } });
            const inbound = inboundCredential(plan);
            const response = await this.relay().prepareDeposit({
                depositor: ek.publicKey,
                expected_note_id: Number(path.note_id),
                commitment: staged.commitment,
                amount: String(amount),
                zero_path: path.siblings,
                max_fee: String(cap),
                ...(inbound ? { inbound } : {})
            });
            return { staged, response, amount };
        };
        let result;
        try {
            result = await attempt(quoted < cap ? quoted : cap);
        } catch (error) {
            // insufficient_funds: the fee rose above the quote; 409 invalid_request:
            // "prepare again". Both retry once with the full cap reserved.
            const retry = error.code === 'insufficient_funds' && quoted < cap
                || error.status === 409 && error.code === 'invalid_request';
            if (!retry) throw error;
            result = await attempt(cap);
        }
        const { staged, response, amount } = result;
        const fee = decimal(response.fee, 'relay deposit fee');
        if (fee + amount > available) throw cctpError('The relayer\'s fee exceeds the arrived transfer.', 'cctp_relay_tx_rejected');
        const noteId = Number(path.note_id);
        const prepared = preparedForSubmit(response, 'deposit');
        const lookupTables = await readLookupTables(funding, prepared.lookupTables, signal || undefined);
        const rent = async size => String(await solanaRpc(funding, 'getMinimumBalanceForRentExemption',
            [size, { commitment: 'confirmed' }], signal || AbortSignal.timeout(20_000)));
        const [operationRent, noteRent] = await Promise.all([rent(154 + DEPOSIT_PAYLOAD_LENGTH), rent(110)]);
        if (response.operation_rent !== operationRent || response.note_rent !== noteRent) {
            throw cctpError('The relayer returned incorrect deposit rents.', 'cctp_relay_tx_rejected');
        }
        validateRelayDepositTransaction(prepared.bytes, { funding, relayer: relay.relayer, ek: ek.publicKey,
            feeAccount: relay.feeAccount, operation: response.operation, note: response.note, noteId, fee, maxFee: cap,
            commitment: staged.commitment, amount, operationRent, noteRent, lookupTables });
        return this.updateDeposit(staged, { cctp: { phase: 'signed', deposit: {
            noteId, operation: response.operation, note: response.note, fee: String(fee), amount: String(amount),
            ...await ekSignedRecord(prepared, ek, funding, lookupTables, signal), signedAt: this.now()
        } } });
    }

    /** No relayer: ek pays SOL itself through the ledger's single-signer deposit of this transfer. */
    async selfFundedDeposit(plan, { onStatus, signal }) {
        const funding = this.funding;
        const ek = ekFromSecret(plan.secret);
        if (!plan.solanaJournal) {
            const available = this.availableAfterArrival(plan);
            if (await ekBalance(funding, ek.publicKey, signal) < available) {
                throw cctpError('The emergency-key account no longer holds the arrived transfer.', 'cctp_arrival_missing');
            }
            await this.assertEkHasSol(ek.publicKey);
            const vault = assertSolanaDepositsOpen(await assertSolanaVault(funding));
            const path = await this.runtime.nextDepositPath(vault.root);
            await this.updateDeposit(plan, { plan: { amount: Number(available), next_note_id: path.note_id,
                active_root: path.active_root, zero_path: path.siblings }, cctp: { selfFunded: true } });
        }
        const { wallet, account } = emergencyKeyWallet(ek.keypair, funding.wallet_standard_chain);
        report(onStatus, 'submitting', 'Submitting the self-funded emergency-key deposit…');
        await this.runtime.submitSolanaOperation('deposit', { wallet, account, signal });
        const current = await this.currentDeposit();
        return this.updateDeposit(current, { cctp: { phase: 'deposited', depositedAt: this.now() } });
    }

    async assertEkHasSol(ek) {
        const balance = await solanaRpc(this.funding, 'getBalance', [ek, { commitment: 'confirmed' }],
            AbortSignal.timeout(20_000));
        if (!Number.isSafeInteger(balance?.value) || balance.value <= 0) {
            throw cctpError(`Fund the emergency key ${ek} with about 0.005 SOL to pay its own network fees.`,
                'cctp_ek_needs_sol', { emergencyKey: ek });
        }
    }

    /** Give up a deposit whose burn was never requested (the secret is archived, never deleted). */
    async cancelDeposit() {
        const plan = await this.currentDeposit();
        if (!plan) return false;
        if (!DEPOSIT_PHASES_BEFORE_BURN.has(plan.cctp.phase)) {
            throw cctpError('This CCTP deposit may already be burning; resume it, refund or sweep instead.', 'cctp_deposit_pending');
        }
        await this.runtime.archiveCctpDeposit(plan.operationId, 'canceled');
        return true;
    }

    // =======================================================================
    // Refund and sweep (inbound funds still in ATA(ek))

    /**
     * cctpRefund: burn ATA(ek) back to the intent's refund target (D7). The
     * intent's maxCctpFee is the authorized ceiling; a higher current quote
     * needs an explicit `maxCctpFee` (≤ the fee policy), which is persisted.
     */
    async refund({ force = false, maxCctpFee = null, selfFunded = false, onStatus = () => {}, signal = null } = {}) {
        let plan = await this.currentDeposit();
        if (!plan) throw cctpError('There is no CCTP deposit to refund.', 'cctp_nothing_to_refund');
        if (DEPOSIT_PHASES_IN_FLIGHT.has(plan.cctp.phase) || plan.cctp.phase === 'deposited') {
            throw cctpError('This CCTP deposit is already being deposited into the vault.', 'cctp_deposit_pending');
        }
        if (DEPOSIT_PHASES_BEFORE_BURN.has(plan.cctp.phase)) {
            throw cctpError('Nothing was burned for this deposit; cancel it instead.', 'cctp_nothing_to_refund');
        }
        const intent = decodeInboundIntent(fromHex(plan.cctp.intent));
        assertRefundAllowed(intent, { now: Math.floor(this.now() / 1000), force });
        if (maxCctpFee != null) {
            const authorized = this.authorizeFee('outboundForward', maxCctpFee, await ekBalance(this.funding, plan.cctp.ekPublicKey));
            plan = await this.updateDeposit(plan, { cctp: { refundMaxCctpFee: String(authorized) } });
        }
        const ek = ekFromSecret(plan.secret);
        const target = {
            destinationDomain: intent.refund.domain,
            mintRecipient: Uint8Array.from(intent.refund.recipient),
            destinationCaller: Uint8Array.from(intent.refund.destinationCaller),
            minFinalityThreshold: intent.refund.minFinality,
            hookData: Uint8Array.from(intent.refund.hookData),
            maxCctpFee: BigInt(plan.cctp.refundMaxCctpFee ?? intent.refund.maxCctpFee)
        };
        const result = await this.burnFromEk(ek, target, plan.cctp.refundBurn || null, {
            persist: async burn => this.updateDeposit(await this.currentDeposit(), { cctp: { refundBurn: burn } }),
            inbound: inboundCredential(plan), selfFunded, onStatus, signal
        });
        await this.runtime.archiveCctpDeposit(plan.operationId, 'refunded', { refundBurn: result });
        return result;
    }

    /** A user-chosen CCTP maxFee, refused above the wallet's fee policy for `direction`. */
    authorizeFee(direction, value, amount) {
        const fee = decimal(value, 'maxCctpFee');
        const cap = cctpFeePolicyCap(direction, amount, this.options.feePolicy);
        if (fee <= 0n || fee > cap) {
            throw cctpError(`The CCTP fee ${fee} is above this wallet's fee policy (${cap}).`, 'cctp_fee_above_policy',
                { policyCap: cap });
        }
        return fee;
    }

    /** cctpSweep: emergency transfer of ATA(ek) to any Solana USDC account. */
    async sweep({ to, recordId = null, selfFunded = false, onStatus = () => {}, signal = null } = {}) {
        const funding = this.funding;
        const source = await this.sweepSource(recordId);
        const ek = source.ek;
        if (source.pending) {
            // A journaled sweep may already be on the network: finish it first.
            try {
                report(onStatus, 'sweeping', 'Resuming the saved emergency-key sweep…');
                return await this.finishSweep(source, source.pending, ek, { onStatus, signal });
            } catch (error) {
                if (!isFinalFailure(error)) throw error;
                // An ek-signed sweep the relay never confirmed may still have landed
                // before it expired: only ek-signed transactions move ATA(ek) funds.
                const pending = source.pending;
                if (!pending.signature && await ekBalance(funding, ek.publicKey, signal) < BigInt(pending.amount)) {
                    await source.complete({ ...pending, landedUnseen: true });
                    report(onStatus, 'complete', 'The emergency-key USDC was moved.');
                    return Object.freeze({ signature: null, destination: pending.destination, amount: pending.amount });
                }
            }
        }
        const destination = await this.sweepDestination(to, ek.publicKey);
        const balance = await ekBalance(funding, ek.publicKey, signal);
        if (balance <= 0n) throw cctpError('The emergency-key account holds no USDC.', 'cctp_nothing_to_sweep');
        let record;
        if (selfFunded) {
            await this.assertEkHasSol(ek.publicKey);
            const blockhash = await latestBlockhash(funding, signal);
            const transaction = new Transaction({ feePayer: ek.keypair.publicKey, blockhash: blockhash.blockhash,
                lastValidBlockHeight: blockhash.lastValidBlockHeight });
            transaction.add(toWeb3(transferCheckedInstruction({ source: usdcAssociatedTokenAddress(ek.publicKey),
                mint: funding.usdc_mint, destination, authority: ek.publicKey, amount: balance })));
            transaction.sign(ek.keypair);
            record = { signature: base58Encode(transaction.signature), bytes: Array.from(transaction.serialize()),
                lastValidHeight: blockhash.lastValidBlockHeight, destination, amount: String(balance) };
        } else {
            const relay = await this.requireRelay(ek.publicKey, 'sweep');
            const cap = relayFeeCap('sweep', this.options.feeCaps);
            const response = await this.relay().prepareSweep({ owner: ek.publicKey, destination, max_fee: String(cap),
                ...(source.inbound ? { inbound: source.inbound } : {}) });
            const prepared = preparedForSubmit(response, 'sweep');
            validateRelaySweepTransaction(prepared.bytes, { funding, relayer: relay.relayer, ek: ek.publicKey,
                feeAccount: relay.feeAccount, destination, fee: response.fee, maxFee: cap, amount: response.amount, balance });
            record = { ...await ekSignedRecord(prepared, ek, funding, [], signal), destination,
                amount: String(decimal(response.amount, 'sweep amount')) };
        }
        await source.persist({ sweep: record });
        return this.finishSweep(source, record, ek, { onStatus, signal });
    }

    /** Submit (relay, once journaled) and confirm a sweep, then complete its source. */
    async finishSweep(source, record, ek, { onStatus, signal }) {
        let sweep = record;
        if (!sweep.signature) {
            report(onStatus, 'sweeping', 'Submitting the emergency-key sweep to the relayer…');
            sweep = await this.submitRelayed(sweep, ek.publicKey, 'sweep', signal, sweep => source.persist({ sweep }));
            await source.persist({ sweep });
        }
        report(onStatus, 'sweeping', 'Sending the emergency-key sweep…', { signature: sweep.signature });
        await this.broadcast(sweep, { signal });
        await source.complete(sweep);
        report(onStatus, 'complete', 'The emergency-key USDC was moved.');
        return Object.freeze({ signature: sweep.signature, destination: sweep.destination, amount: sweep.amount });
    }

    async sweepSource(recordId) {
        if (recordId) {
            const record = await this.runtime.currentWithdrawal(recordId);
            if (!record?.cctpExit) throw cctpError('That withdrawal has no CCTP emergency key.', 'cctp_nothing_to_sweep');
            if (record.cctpExit.burn && !record.cctpExit.burn.finalizedAt && !record.cctpExit.burn.expired) {
                throw cctpError('A burn from this emergency key is in flight. Resume it first.', 'cctp_burn_pending');
            }
            return {
                ek: ekFromSeed(record.cctpExit.ekSeed),
                pending: record.cctpExit.sweep && !record.cctpExit.sweep.finalizedAt ? record.cctpExit.sweep : null,
                persist: async changes => {
                    const latest = await this.runtime.currentWithdrawal(recordId);
                    return this.runtime.updateWithdrawal(recordId, { cctpExit: { ...latest.cctpExit, ...changes } });
                },
                complete: async sweep => {
                    const latest = await this.runtime.currentWithdrawal(recordId);
                    return this.runtime.updateWithdrawal(recordId, { cctpExit: { ...latest.cctpExit,
                        phase: 'swept', sweep: { ...sweep, finalizedAt: this.now() } } });
                }
            };
        }
        const plan = await this.currentDeposit();
        if (!plan) throw cctpError('There is no CCTP deposit or exit to sweep.', 'cctp_nothing_to_sweep');
        if (plan.cctp.refundBurn && !plan.cctp.refundBurn.finalizedAt && !plan.cctp.refundBurn.expired) {
            throw cctpError('A refund burn is in flight. Resume the refund before sweeping.', 'cctp_burn_pending');
        }
        if (DEPOSIT_PHASES_IN_FLIGHT.has(plan.cctp.phase) || plan.cctp.phase === 'deposited') {
            throw cctpError('This CCTP deposit is already being deposited into the vault.', 'cctp_deposit_pending');
        }
        return {
            ek: ekFromSecret(plan.secret),
            pending: plan.cctp.sweep || null,
            // A transit sweep carries the attested inbound transfer as the relay's sponsorship credential.
            inbound: inboundCredential(plan),
            persist: async changes => this.updateDeposit(await this.currentDeposit(), { cctp: changes }),
            complete: sweep => this.runtime.archiveCctpDeposit(plan.operationId, 'swept', { sweep })
        };
    }

    async sweepDestination(to, ek) {
        const funding = this.funding;
        base58Decode(to, 32, 'sweep destination');
        const direct = await readUsdcTokenAccount(funding, to);
        const account = direct || await readUsdcTokenAccount(funding, usdcAssociatedTokenAddress(to));
        if (!account?.creditable) {
            throw cctpError('The sweep destination must be an existing, unfrozen USDC account (or a wallet that has one).',
                'usdc_destination_not_creditable');
        }
        if (account.address === usdcAssociatedTokenAddress(ek)) {
            throw cctpError('The sweep destination is the emergency-key account itself.', 'usdc_destination_not_creditable');
        }
        return account.address;
    }

    // =======================================================================
    // Outbound

    /**
     * A burn of the whole ATA(ek) balance (minus the relay fee) to `target`,
     * whose maxCctpFee is the user-authorized ceiling (never raised here).
     * `burn` is the journaled burn when resuming: an ek-signed relay burn
     * (no signature yet) is re-submitted with its token, which returns the
     * relay-broadcast transaction; one that expired unseen is replaced (it can
     * no longer land). `inbound` is the relay's sponsorship credential, if any.
     */
    async burnFromEk(ek, target, burn, { persist, inbound = null, selfFunded, onStatus, signal }) {
        for (let attempt = 0; !burn?.finalizedAt; attempt += 1) {
            if (attempt >= 3) {
                throw cctpError('The CCTP burn did not land after three attempts. Your USDC is safe in your emergency-key account.',
                    'cctp_burn_failed', { emergencyKey: ek.publicKey });
            }
            if (!burn || burn.expired) {
                burn = await this.prepareEkBurn(ek, target, { inbound, selfFunded, onStatus, signal });
                await persist(burn);
            }
            try {
                if (!burn.signature) {
                    report(onStatus, 'burning', 'Submitting the CCTP burn to the relayer…');
                    burn = await this.submitRelayed(burn, ek.publicKey, 'burn', signal, persist);
                    await persist(burn);
                }
                report(onStatus, 'burning', 'Submitting the CCTP burn on Solana…', { signature: burn.signature });
                await this.broadcast(burn, { signal });
            } catch (error) {
                if (!isFinalFailure(error)) throw error;
                // An ek-signed burn the relay never confirmed may still have landed
                // before it expired: its fresh event account then has a history.
                const landed = burn.signature ? null : await this.landedBurnSignature(burn.eventAccount, signal);
                burn = landed ? { ...burn, signature: landed, landedUnseen: true } : { ...burn, expired: true };
                await persist(burn);
                if (!landed) continue;
            }
            burn = { ...burn, finalizedAt: this.now() };
            await persist(burn);
        }
        if (!burn.attestation) {
            report(onStatus, 'attesting', 'Waiting for Circle to attest the Solana burn…');
            let eventBytes = await this.readMessageSent(burn.eventAccount, signal);
            if (!eventBytes) {
                // Circle permits the rent payer to reclaim MessageSent after five
                // days. Reconstruct the source-controlled bytes from the validated,
                // finalized burn; a pinned Circle attestation still authenticates
                // the message. Never depend on the continued existence of the event.
                const chain = Object.values({ ...EVM_CCTP, ...this.options.evmChains })
                    .find(value => value.domain === burn.target.destinationDomain);
                if (!chain) throw cctpError('Unknown burn destination domain.', 'cctp_message_mismatch');
                eventBytes = encodeMessageV2({
                    version: 1, sourceDomain: SOLANA_DOMAIN, destinationDomain: burn.target.destinationDomain,
                    nonce: new Uint8Array(32), sender: base58Decode(TOKEN_MESSENGER_MINTER_V2, 32),
                    recipient: evmBytes32(chain.tokenMessenger), destinationCaller: fromHex(burn.target.destinationCaller),
                    minFinalityThreshold: burn.target.minFinalityThreshold, finalityThresholdExecuted: 0,
                    body: { version: 1, burnToken: base58Decode(this.funding.usdc_mint, 32),
                        mintRecipient: fromHex(burn.target.mintRecipient), amount: BigInt(burn.amount),
                        messageSender: base58Decode(ek.publicKey, 32), maxFee: BigInt(burn.target.maxCctpFee),
                        feeExecuted: 0n, expirationBlock: 0n, hookData: fromHex(burn.target.hookData) }
                });
            }
            const attested = await this.waitForAttestation(await this.iris(), SOLANA_DOMAIN, burn.signature, {
                signal, check: (_decoded, bytes) => assertOutboundMessage(bytes, eventBytes, burn)
            });
            if (!attested) {
                throw cctpError('Circle has not attested the burn yet. It is final on Solana; resume later.',
                    'cctp_attestation_pending', { signature: burn.signature });
            }
            burn = { ...burn, attestation: { message: attested.message, attestation: attested.attestation },
                attestedAt: this.now() };
            await persist(burn);
        }
        report(onStatus, 'attested', 'Circle attested the burn.');
        return burn;
    }

    /** The message bytes of a finalized burn's MessageSent event account (MessageTransmitterV2-owned). */
    async readMessageSent(eventAccount, signal) {
        const account = await accountExists(this.funding, eventAccount, signal);
        if (!account) return null; // A finalized event can legitimately have been reclaimed.
        if (account.owner !== MESSAGE_TRANSMITTER_V2) {
            throw cctpError('The burn\'s MessageSent account has the wrong owner.',
                'cctp_message_mismatch');
        }
        return Uint8Array.from(decodeMessageSentEvent(base64Bytes(account.data[0])).message);
    }

    /**
     * The signature of an expired, never-confirmed burn that landed anyway: the
     * oldest successful finalized transaction of its fresh event account (the
     * burn created it). Null when the account has no history (it never landed).
     * The attestation of that signature is still checked against the burn.
     */
    async landedBurnSignature(eventAccount, signal) {
        const history = await solanaRpc(this.funding, 'getSignaturesForAddress', [eventAccount,
            { commitment: 'finalized', limit: 1000 }], signal || AbortSignal.timeout(20_000));
        if (!Array.isArray(history)) throw new Error('The Solana RPC returned a malformed signature history.');
        const landed = history.filter(entry => entry?.err == null && typeof entry?.signature === 'string');
        if (landed.length) return landed.at(-1).signature;
        if (await accountExists(this.funding, eventAccount, signal)) {
            throw cctpError('The burn landed but the RPC returned no history for it. Resume it later.', 'cctp_burn_pending',
                { eventAccount });
        }
        return null;
    }

    /**
     * Build and sign (self-funded) or obtain, validate and ek-sign (relay; to
     * be submitted) one burn of ATA(ek).
     */
    async prepareEkBurn(ek, target, { inbound = null, selfFunded, onStatus, signal }) {
        const funding = this.funding;
        const options = this.options;
        const balance = await ekBalance(funding, ek.publicKey, signal);
        if (balance <= 0n) throw cctpError('The emergency-key account holds no USDC to burn.', 'cctp_nothing_to_burn');
        const forward = target.hookData.length > 0;
        // The authorized maxCctpFee is never raised here: a higher current quote
        // stops for a new explicit authorization.
        const fresh = cctpMaxFee({
            fees: await (await this.iris()).fees(SOLANA_DOMAIN, target.destinationDomain, { forward }),
            amount: balance, finality: target.minFinalityThreshold === FINALITY_FAST ? 'fast' : 'standard',
            forward, policyCap: cctpFeePolicyCap(forward ? 'outboundForward' : 'outboundSelf', balance, options.feePolicy),
            headroomBps: options.forwardFeeHeadroomBps, minHeadroom: options.minFeeHeadroom
        });
        if (fresh.baseFee > BigInt(target.maxCctpFee)) {
            throw cctpError(`Circle now quotes ${fresh.baseFee} base units, above the authorized CCTP fee ${target.maxCctpFee}. Authorize a new { maxCctpFee } to continue.`,
                'cctp_fee_above_authorized', { quoted: fresh.baseFee, suggested: fresh.maxFee,
                    authorized: BigInt(target.maxCctpFee) });
        }
        const wire = {
            destinationDomain: target.destinationDomain,
            mintRecipient: toHex(target.mintRecipient),
            destinationCaller: toHex(target.destinationCaller),
            maxCctpFee: String(target.maxCctpFee),
            minFinalityThreshold: target.minFinalityThreshold,
            hookData: toHex(target.hookData)
        };
        if (selfFunded) {
            await this.assertEkHasSol(ek.publicKey);
            if (balance <= BigInt(target.maxCctpFee)) throw cctpError('The balance does not cover the CCTP fee.', 'cctp_amount_too_small');
            const event = Keypair.generate();
            const blockhash = await latestBlockhash(funding, signal);
            const transaction = new Transaction({ feePayer: ek.keypair.publicKey, blockhash: blockhash.blockhash,
                lastValidBlockHeight: blockhash.lastValidBlockHeight });
            transaction.add(depositForBurnInstruction({
                owner: ek.keypair.publicKey, eventRentPayer: ek.keypair.publicKey,
                burnTokenAccount: usdcAssociatedTokenAddress(ek.publicKey),
                messageSentEventData: event.publicKey, amount: balance,
                destinationDomain: target.destinationDomain, mintRecipient: target.mintRecipient,
                destinationCaller: target.destinationCaller, maxFee: BigInt(target.maxCctpFee),
                minFinalityThreshold: target.minFinalityThreshold, hookData: target.hookData
            }));
            transaction.sign(ek.keypair, event);
            return { signature: base58Encode(transaction.signature), bytes: Array.from(transaction.serialize()),
                lastValidHeight: blockhash.lastValidBlockHeight, eventAccount: event.publicKey.toBase58(),
                amount: String(balance), fee: '0', target: wire, selfFunded: true, signedAt: this.now() };
        }
        const relay = await this.requireRelay(ek.publicKey, 'burn');
        const cap = relayFeeCap('burn', options.feeCaps);
        report(onStatus, 'preparing_burn', 'Preparing the CCTP burn. Exits below $5 are not relayed by default; exit on Solana, sweep, or use your own SOL.');
        const response = await this.relay().prepareBurn({
            owner: ek.publicKey,
            destination_domain: target.destinationDomain,
            mint_recipient: wire.mintRecipient,
            destination_caller: wire.destinationCaller,
            max_cctp_fee: wire.maxCctpFee,
            min_finality_threshold: target.minFinalityThreshold,
            hook_data: wire.hookData,
            max_fee: String(cap),
            ...(inbound ? { inbound } : {})
        });
        const prepared = preparedForSubmit(response, 'burn');
        if (prepared.version !== 'legacy') throw cctpError('The relayer returned an unexpected burn format.', 'cctp_relay_tx_rejected');
        validateRelayBurnTransaction(prepared.bytes, { funding, relayer: relay.relayer, ek: ek.publicKey,
            feeAccount: relay.feeAccount, eventAccount: response.message_sent_event_account, fee: response.fee,
            maxFee: cap, amount: response.amount, balance, target });
        return { ...await ekSignedRecord(prepared, ek, funding, [], signal), eventAccount: response.message_sent_event_account,
            amount: String(response.amount), fee: String(response.fee), target: wire, signedAt: this.now() };
    }

    /**
     * cctpExit: close (mutual) or escape the note into ATA(ek), then burn it
     * to `recipient` on `destinationChain`. The CCTP fee ceiling is fixed and
     * persisted when the exit is proved (returned as `authorizedCctpFee`). With
     * no active note, an unfinished CCTP exit is resumed instead.
     */
    async exit({ kind, destinationChain, recipient, finality = 'fast', claim = 'forward', earlyConcession = null,
        waitForChallenge = false, selfFunded = false, onStatus = () => {}, signal = null } = {}) {
        const funding = this.funding;
        const options = this.options;
        const secret = await this.runtime.cctpNoteSecret();
        if (!secret) {
            const open = await this.openExitRecord();
            if (open) return this.resumeExit(open.recordId, { waitForChallenge, selfFunded, onStatus, signal });
            throw cctpError('There is no active private note to withdraw.', 'cctp_no_note');
        }
        if (!['mutual', 'escape'].includes(kind)) throw new TypeError('A CCTP exit is mutual or escape.');
        if (!['forward', 'self'].includes(claim)) throw new TypeError('claim must be forward or self.');
        if (!['fast', 'standard'].includes(finality)) throw new TypeError('CCTP finality must be fast or standard.');
        const chain = cctpEvmChain(destinationChain, options);
        const to = assertEvmRecipient(recipient, chain);
        this.attestation; // Attesters must be pinned before the note is spent.
        const ek = ekFromSecret(secret);
        const destination = usdcAssociatedTokenAddress(ek.publicKey);
        let prepared = await this.runtime.currentPreparedWithdrawal();
        if (prepared?.cctp && (prepared.cctp.recipient !== to || prepared.cctp.destinationDomain !== chain.domain
            || prepared.mode !== kind)) {
            throw cctpError('A different CCTP exit is already prepared for this balance.', 'cctp_exit_pending');
        }
        if (!prepared?.cctp?.exitTx && !prepared?.solanaJournal) {
            if (selfFunded) {
                await this.assertEkHasSol(ek.publicKey);
                const { wallet, account } = emergencyKeyWallet(ek.keypair, funding.wallet_standard_chain);
                await this.runtime.ensureUsdcPayoutAccount(destination, { wallet, account });
            } else {
                const relay = await this.requireRelay(ek.publicKey, kind);
                const held = await ekBalance(funding, ek.publicKey, signal);
                if (kind === 'escape' && held < relay.quotes.escape) {
                    // The escape's relay fee is prepaid from ATA(ek) in the same transaction.
                    throw cctpError(`A relayed escape prepays its fee: send at least ${relay.quotes.escape} USDC base units to ${destination}, or escape with { selfFunded: true }.`,
                        'cctp_escape_fee_required', { emergencyAccount: destination, required: relay.quotes.escape,
                            balance: held });
                }
                if (!prepared) {
                    // The exit is irreversible and the relay refuses burns below its
                    // minimum: refuse now instead of stranding the payout in ATA(ek).
                    // Worst-case quotes err toward refusing, never toward stranding.
                    const noteBalance = await this.runtime.cctpNoteBalance() ?? 0n;
                    const left = noteBalance + held - (kind === 'mutual' ? relay.quotes.close : relay.quotes.escape)
                        - relay.quotes.burn;
                    const expected = left > 0n ? left : 0n;
                    if (expected < relay.burnMinimum) {
                        throw cctpError(`This exit would leave about ${expected} USDC base units to burn, below the relayed CCTP minimum of ${relay.burnMinimum}. Nothing was spent: withdraw on Solana instead, or exit with { selfFunded: true }.`,
                            'cctp_exit_below_minimum', { expected, minimum: relay.burnMinimum });
                    }
                }
            }
            report(onStatus, 'proving', kind === 'mutual'
                ? 'Requesting clearance and generating the withdrawal proof…'
                : 'Generating the unilateral escape proof locally…');
            prepared = await this.runtime.prepareWithdrawal(kind, destination, { earlyConcession });
            let maxCctpFee = prepared.cctp?.maxCctpFee;
            if (!maxCctpFee) {
                const amount = BigInt(prepared.public_inputs.final_balance);
                const forward = claim === 'forward';
                maxCctpFee = String(cctpMaxFee({
                    fees: await (await this.iris()).fees(SOLANA_DOMAIN, chain.domain, { forward }),
                    amount, finality, forward,
                    policyCap: cctpFeePolicyCap(forward ? 'outboundForward' : 'outboundSelf', amount, options.feePolicy),
                    headroomBps: options.forwardFeeHeadroomBps, minHeadroom: options.minFeeHeadroom
                }).maxFee);
            }
            prepared = await this.runtime.updatePreparedWithdrawalCctp(prepared.operationId, {
                version: 2, kind, destinationChain, destinationDomain: chain.domain, recipient: to, finality, claim,
                ekPublicKey: ek.publicKey, ekSeed: ek.seed, maxCctpFee, phase: 'proved', createdAt: this.now(),
                ...(prepared.cctp || {})
            });
            report(onStatus, 'authorized', `CCTP fee ceiling for this exit: ${maxCctpFee} USDC base units.`,
                { authorizedCctpFee: maxCctpFee });
        }
        return this.submitExit(prepared, { selfFunded, waitForChallenge, onStatus, signal });
    }

    /** The oldest CCTP exit record that still needs this wallet (finalize, burn or attestation). */
    async openExitRecord() {
        const records = await this.runtime.listCctpExitRecords();
        return records.find(record => !['swept', 'attested', 'claimable', 'claimed'].includes(record.cctpExit.phase)) || null;
    }

    async submitExit(prepared, { selfFunded, waitForChallenge, onStatus, signal }) {
        const funding = this.funding;
        const ek = ekFromSeed(prepared.cctp.ekSeed);
        const destination = usdcAssociatedTokenAddress(ek.publicKey);
        if (prepared.destination !== destination) throw new Error('The prepared CCTP exit has a different destination.');
        const noteId = Number(prepared.noteId ?? prepared.public_inputs?.note_id);
        let outcome;
        if (selfFunded || prepared.solanaJournal) {
            const { wallet, account } = emergencyKeyWallet(ek.keypair, funding.wallet_standard_chain);
            report(onStatus, 'submitting', 'Submitting the self-funded exit with the emergency key…');
            await this.runtime.submitSolanaOperation('withdrawal', { wallet, account, signal });
            outcome = await this.runtime.confirmSolanaWithdrawal();
        } else {
            let current = prepared;
            for (let attempt = 0; ; attempt += 1) {
                if (attempt >= 3) {
                    throw cctpError('The exit did not land after three attempts. Resume it later.', 'cctp_exit_failed');
                }
                if (!current.cctp.exitTx) current = await this.prepareRelayExit(current, ek, { onStatus, signal });
                try {
                    if (!current.cctp.exitTx.signature) {
                        report(onStatus, 'submitting', 'Submitting the emergency-key exit transaction to the relayer…');
                        const exitTx = await this.submitRelayed(current.cctp.exitTx, ek.publicKey, 'exit', signal,
                            exitTx => this.runtime.updatePreparedWithdrawalCctp(current.operationId, { ...current.cctp, exitTx }));
                        current = await this.runtime.updatePreparedWithdrawalCctp(current.operationId, { ...current.cctp,
                            phase: 'exit_submitted', exitTx });
                    }
                    report(onStatus, 'submitting', 'Confirming the emergency-key exit transaction…',
                        { signature: current.cctp.exitTx.signature });
                    await this.broadcast(current.cctp.exitTx, { signal });
                    break;
                } catch (error) {
                    if (!isFinalFailure(error)) throw error;
                    const state = await readFinalizedNoteState(funding, noteId);
                    if (state.note?.status !== 'active') break; // It landed after all.
                    const failed = current.cctp.exitTx.signature;
                    current = await this.runtime.updatePreparedWithdrawalCctp(current.operationId, { ...current.cctp,
                        exitTx: null, phase: 'proved',
                        failedExits: [...(current.cctp.failedExits || []), ...(failed ? [failed] : [])] });
                }
            }
            report(onStatus, 'confirming', 'Waiting for the exit to finalize on Solana…');
            const state = await this.waitForNoteState(noteId, current.mode === 'mutual'
                ? note => note.note?.status === 'closed' && !note.pending
                : note => note.note?.status === 'pending_withdrawal' && note.pending?.stage === 'open', signal);
            outcome = await this.runtime.recordSolanaWithdrawalState(current, state, current.cctp.exitTx?.signature || null);
        }
        return this.resumeExit(outcome.record.recordId, { waitForChallenge, selfFunded, onStatus, signal });
    }

    async prepareRelayExit(prepared, ek, { onStatus, signal }) {
        const funding = this.funding;
        const kind = prepared.mode;
        const relay = await this.requireRelay(ek.publicKey, kind);
        const cap = relayFeeCap(kind === 'mutual' ? 'close' : 'escape', this.options.feeCaps);
        await this.runtime.markPreparedWithdrawalReleased();
        report(onStatus, 'preparing_exit', 'Asking the relayer to prepare the exit transaction…');
        let response;
        try {
            response = await this.relay().prepareExit({ kind, destination_owner: ek.publicKey,
                public_inputs: prepared.public_inputs, proof: prepared.proof, max_fee: String(cap) });
        } catch (error) {
            if (error.relayUnavailable) throw await this.relayUnavailableError(ek.publicKey, kind, error);
            throw error;
        }
        if (response.destination !== usdcAssociatedTokenAddress(ek.publicKey)) {
            throw cctpError('The relayer would pay the exit to a different account.', 'cctp_relay_tx_rejected');
        }
        const tx = preparedForSubmit(response, 'exit');
        const lookupTables = await readLookupTables(funding, tx.lookupTables, signal || undefined);
        const fee = decimal(response.fee, 'relay exit fee');
        await validateRelayExitTransaction(tx.bytes, { funding, kind, relayer: relay.relayer, ek: ek.publicKey,
            feeAccount: relay.feeAccount, fee, maxFee: cap, publicInputs: prepared.public_inputs, proof: prepared.proof,
            lookupTables, version: tx.version });
        // Journaled before /v2/relay/submit: a crash re-submits the same token and bytes.
        return this.runtime.updatePreparedWithdrawalCctp(prepared.operationId, { ...prepared.cctp, phase: 'exit_signed',
            exitTx: { ...await ekSignedRecord(tx, ek, funding, lookupTables, signal), fee: String(fee), signedAt: this.now() } });
    }

    async waitForNoteState(noteId, done, signal) {
        const deadline = this.now() + this.options.exitTimeoutMs;
        while (true) {
            const state = await readFinalizedNoteState(this.funding, noteId);
            if (done(state)) return state;
            if (this.now() > deadline) {
                throw cctpError('The exit has not finalized yet. Resume it later.', 'cctp_exit_pending', { noteId });
            }
            await sleep(this.options.pollIntervalMs, signal);
        }
    }

    /**
     * Drive a detached CCTP exit record: escape finalization, then the burn and
     * attestation. `maxCctpFee` re-authorizes a higher CCTP fee ceiling (≤ the
     * fee policy) when Circle's quote rose above the one fixed at proving time.
     */
    async resumeExit(recordId, { waitForChallenge = false, selfFunded = false, maxCctpFee = null, onStatus = () => {},
        signal = null } = {}) {
        let record = await this.runtime.currentWithdrawal(recordId);
        if (!record?.cctpExit) throw cctpError('That withdrawal is not a CCTP exit.', 'cctp_exit_unknown');
        const ek = ekFromSeed(record.cctpExit.ekSeed);
        if (record.mode === 'escape' && ['pending', 'finalizing'].includes(record.phase)) {
            const waitMs = Number(record.challengeDeadline) * 1000 - this.now();
            if (waitMs > 0 && !waitForChallenge) {
                return Object.freeze({ status: 'pending_withdrawal', recordId, challengeDeadline: record.challengeDeadline,
                    emergencyKey: ek.publicKey, authorizedCctpFee: record.cctpExit.maxCctpFee });
            }
            if (waitMs > 0) {
                report(onStatus, 'challenge', 'Waiting for the escape challenge window to end…');
                await sleep(waitMs + 1_000, signal);
            }
            record = await this.finalizeEscape(record, ek, { selfFunded, onStatus, signal });
        }
        if (record.phase === 'payout_parked') {
            if (selfFunded) {
                const { wallet, account } = emergencyKeyWallet(ek.keypair, this.funding.wallet_standard_chain);
                await this.runtime.ensureUsdcPayoutAccount(record.destination, { wallet, account });
                await this.runtime.submitSolanaEscapePayoutRelease(recordId, { wallet, account, signal });
            } else {
                record = await this.finalizeEscape(record, ek, { selfFunded, onStatus, signal });
            }
            record = await this.runtime.currentWithdrawal(recordId);
            if (record.phase !== 'closed') throw cctpError('The escape payout is still parked.', 'cctp_exit_pending');
        }
        if (record.phase !== 'closed') throw cctpError('The exit has not paid out yet.', 'cctp_exit_pending');
        let exitPlan = record.cctpExit;
        if (maxCctpFee != null) {
            const authorized = this.authorizeFee(exitPlan.claim === 'forward' ? 'outboundForward' : 'outboundSelf',
                maxCctpFee, await ekBalance(this.funding, ek.publicKey));
            await this.runtime.updateWithdrawal(recordId, { cctpExit: { ...exitPlan, maxCctpFee: String(authorized) } });
            exitPlan = (await this.runtime.currentWithdrawal(recordId)).cctpExit;
        }
        const chain = cctpEvmChain(exitPlan.destinationChain, this.options);
        const target = {
            destinationDomain: chain.domain,
            mintRecipient: evmBytes32(exitPlan.recipient),
            destinationCaller: ZERO32,
            minFinalityThreshold: exitPlan.finality === 'fast' ? FINALITY_FAST : FINALITY_STANDARD,
            hookData: exitPlan.claim === 'forward' ? encodeForwardHook({ createAtaOwner: null }) : new Uint8Array(0),
            maxCctpFee: BigInt(exitPlan.maxCctpFee)
        };
        const burn = await this.burnFromEk(ek, target, exitPlan.burn || null, {
            persist: async next => {
                const latest = await this.runtime.currentWithdrawal(recordId);
                return this.runtime.updateWithdrawal(recordId, { cctpExit: { ...latest.cctpExit, burn: next,
                    phase: next.attestation ? (exitPlan.claim === 'forward' ? 'attested' : 'claimable')
                        : next.finalizedAt ? 'burned' : 'burn_signed' } });
            },
            selfFunded, onStatus, signal
        });
        report(onStatus, 'complete', exitPlan.claim === 'forward'
            ? 'Burn attested. Circle\'s Forwarding Service mints the USDC to your recipient.'
            : 'Burn attested. Claim it on the destination chain with cctpClaim().');
        return Object.freeze({ status: exitPlan.claim === 'forward' ? 'attested' : 'claimable', recordId,
            signature: burn.signature, message: burn.attestation.message, attestation: burn.attestation.attestation });
    }

    async finalizeEscape(record, ek, { selfFunded, onStatus, signal }) {
        const funding = this.funding;
        const noteId = Number(record.noteId);
        if (selfFunded) {
            const { wallet, account } = emergencyKeyWallet(ek.keypair, funding.wallet_standard_chain);
            await this.runtime.submitSolanaFinalization(record.recordId, { wallet, account, signal });
            return this.runtime.currentWithdrawal(record.recordId);
        }
        report(onStatus, 'finalizing', 'Asking the relayer to finalize the escape…');
        let response;
        try {
            response = await this.relay().finalizeEscape({ note_id: noteId });
        } catch (error) {
            if (error.relayUnavailable) throw await this.relayUnavailableError(ek.publicKey, 'escape', error);
            throw error;
        }
        if (!['finalize', 'release'].includes(response.action)) {
            throw cctpError('The relayer returned an unknown escape action.', 'relay_malformed');
        }
        const kind = response.action;
        const state = await this.waitForNoteState(noteId, current => kind === 'release'
            ? current.pending?.stage !== 'payout_parked'
            : current.pending?.stage !== 'open' && current.note?.status !== 'pending_withdrawal', signal);
        await this.runtime.recordSolanaPendingRecordState(record.recordId, kind, state, response.signature || null);
        return this.runtime.currentWithdrawal(record.recordId);
    }

    /** Self-claim an attested outbound burn on its EVM destination (claim: 'self'). */
    async claim({ recordId, evmProvider }) {
        const record = await this.runtime.currentWithdrawal(recordId);
        const attestation = record?.cctpExit?.burn?.attestation;
        if (!attestation) throw cctpError('This exit has no attested burn to claim.', 'cctp_attestation_pending');
        const chain = cctpEvmChain(record.cctpExit.destinationChain, this.options);
        const claimed = await claimCctpOnEvm({ provider: evmProvider, chain, message: attestation.message,
            attestation: attestation.attestation, receiptOptions: this.options.evmReceipt });
        await this.runtime.updateWithdrawal(recordId, { cctpExit: { ...record.cctpExit, phase: 'claimed',
            claimTransactionHash: claimed.transactionHash } });
        return claimed;
    }

    /** Emergency facts for the UI: where the funds are and which key controls them. */
    async emergencyInfo({ recordId = null } = {}) {
        let ek;
        if (recordId) {
            const record = await this.runtime.currentWithdrawal(recordId);
            if (!record?.cctpExit) return null;
            ek = record.cctpExit.ekPublicKey;
        } else {
            const plan = await this.currentDeposit();
            if (!plan) return null;
            ek = plan.cctp.ekPublicKey;
        }
        let relay = null;
        try {
            relay = await this.relayInfo();
        } catch (error) {
            if (!error.relayUnavailable) throw error;
        }
        return Object.freeze({ emergencyKey: ek, emergencyAccount: usdcAssociatedTokenAddress(ek),
            balance: String(await ekBalance(this.funding, ek)), relayAvailable: Boolean(relay),
            selfFundedAvailable: true });
    }
}

export { DEFAULT_IRIS_URLS, notePda as cctpNotePda, pendingPda as cctpPendingPda };
