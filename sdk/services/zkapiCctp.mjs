// Circle CCTP V2 core for the program-free Phase 1 flows: emergency key,
// InboundIntent/CctpTarget encoding, forwarding hooks, V2 message codec,
// Solana CCTP PDAs and instructions, EVM calldata and an Iris client.
// Layouts and discriminators: circlefin/solana-cctp-contracts (programs/v2,
// IDL), circlefin/evm-cctp-contracts (src/v2) and Circle's Forwarding
// Service docs; golden vectors in sdk/test/fixtures/cctp-vectors.json.
import { Keypair, PublicKey, SystemProgram, TransactionInstruction } from '@solana/web3.js';
import { sha256 } from '@noble/hashes/sha256';
import { keccak_256 } from '@noble/hashes/sha3';
import { hkdf } from '@noble/hashes/hkdf';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { ASSOCIATED_TOKEN_PROGRAM_ID, TOKEN_PROGRAM_ID, USDC_MINT } from './zkapiUsdc.mjs';

export const SOLANA_DOMAIN = 5;
export const FINALITY_FAST = 1000;
export const FINALITY_STANDARD = 2000;
export const MESSAGE_TRANSMITTER_V2 = 'CCTPV2Sm4AdWt5296sk4P66VBZ7bEhcARwFaaS9YPbeC';
export const TOKEN_MESSENGER_MINTER_V2 = 'CCTPV2vPZJS2u2BBsUoscuikbYjnpFmbFsvVuJdgUMQe';
// token_messenger.fee_recipient on mainnet (state; Circle may rotate it).
export const CCTP_FEE_RECIPIENT = '4BPnUzFDibVcWQ5zzixGodRUHwqDxHYpUPdPYus3Bn56';

export const CCTP_DOMAINS = Object.freeze({
    ethereum: 0, avalanche: 1, optimism: 2, arbitrum: 3, solana: 5, base: 6, polygon: 7, sui: 8, aptos: 9,
    unichain: 10, linea: 11, codex: 12, sonic: 13, worldchain: 14, monad: 15, sei: 16, bnb: 17, xdc: 18,
    hyperevm: 19, ink: 21, plume: 22, starknet: 25, arc: 26, stellar: 27, edge: 28
});

const EVM_TOKEN_MESSENGER_V2 = '0x28b5a0e9C621a5BadaA536219b3a228C8168cf5d';
const EVM_MESSAGE_TRANSMITTER_V2 = '0x81D40F21F12A8F0E3252Bccb954D722d4c464B64';
const evmChain = (chainId, domain, usdc) => Object.freeze({
    chainId, domain, tokenMessenger: EVM_TOKEN_MESSENGER_V2, messageTransmitter: EVM_MESSAGE_TRANSMITTER_V2, usdc
});
export const EVM_CCTP = Object.freeze({
    ethereum: evmChain(1, 0, '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48'),
    optimism: evmChain(10, 2, '0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85'),
    arbitrum: evmChain(42161, 3, '0xaf88d065e77c8cC2239327C5EDb3A432268e5831'),
    base: evmChain(8453, 6, '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913')
});

const anchorDiscriminator = name => sha256(new TextEncoder().encode(`global:${name}`)).slice(0, 8);
export const CCTP_DISCRIMINATORS = Object.freeze({
    receiveMessage: anchorDiscriminator('receive_message'),
    depositForBurn: anchorDiscriminator('deposit_for_burn'),
    depositForBurnWithHook: anchorDiscriminator('deposit_for_burn_with_hook'),
    reclaimEventAccount: anchorDiscriminator('reclaim_event_account')
});
const MESSAGE_SENT_DISCRIMINATOR = Uint8Array.from([131, 100, 133, 56, 166, 225, 151, 60]);

const MESSAGE_VERSION = 1;
const BURN_MESSAGE_VERSION = 1;
const HEADER_BYTES = 148;
const BURN_BODY_BYTES = 228;
const MAX_MESSAGE_BODY_BYTES = 8192;
const MAX_TARGET_HOOK_BYTES = 96;
const INTENT_VERSION = 1;
const FORWARD_MAGIC = 'cctp-forward';
const INBOUND_TAG = new TextEncoder().encode('DGNZK-IN');
const EK_INFO = 'dagon-zkapi/cctp-ek/v1';
const INTENT_DOMAIN = new TextEncoder().encode('dagon-zkapi/cctp-intent/v1');
const U64_MAX = (1n << 64n) - 1n;
const I64_MIN = -(1n << 63n);
const I64_MAX = (1n << 63n) - 1n;
const U256_MAX = (1n << 256n) - 1n;
const utf8 = text => new TextEncoder().encode(text);

function concat(...parts) {
    const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
    let offset = 0;
    for (const part of parts) { out.set(part, offset); offset += part.length; }
    return out;
}

function equalBytes(a, b) {
    return a.length === b.length && a.every((value, index) => value === b[index]);
}

function toBytes(value, label) {
    // A Node Buffer's slice() aliases its pool; view it as a plain Uint8Array so slice() copies.
    if (value instanceof Uint8Array) return value.constructor === Uint8Array ? value : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    if (typeof value === 'string' && /^0x([0-9a-f]{2})*$/i.test(value)) return hexToBytes(value.slice(2));
    throw new TypeError(`${label} must be bytes or 0x-prefixed hex.`);
}

function publicKey(value, label) {
    if (value instanceof PublicKey) return value;
    if (value instanceof Uint8Array && value.length === 32) return new PublicKey(value);
    if (typeof value === 'string') {
        try { return new PublicKey(value); } catch { /* reported below */ }
    }
    throw new TypeError(`${label} must be a Solana public key.`);
}

/** 32 bytes from a PublicKey, base58 key, Uint8Array(32) or 0x-hex of 32 (or 20, left-padded) bytes. */
function bytes32(value, label) {
    if (value instanceof PublicKey) return value.toBytes();
    if (value instanceof Uint8Array) {
        if (value.length !== 32) throw new TypeError(`${label} must be 32 bytes.`);
        return Uint8Array.from(value);
    }
    if (typeof value === 'string' && /^0x[0-9a-f]{40}$/i.test(value)) return evmBytes32(value);
    if (typeof value === 'string' && /^0x[0-9a-f]{64}$/i.test(value)) return hexToBytes(value.slice(2));
    if (typeof value === 'string') return publicKey(value, label).toBytes();
    throw new TypeError(`${label} must be 32 bytes.`);
}

function integer(value, label, min, max) {
    let result;
    if (typeof value === 'bigint') result = value;
    else if (typeof value === 'number' && Number.isSafeInteger(value)) result = BigInt(value);
    else if (typeof value === 'string' && /^-?\d+$/.test(value)) result = BigInt(value);
    else throw new TypeError(`${label} must be an integer.`);
    if (result < min || result > max) throw new RangeError(`${label} is out of range.`);
    return result;
}
const u8 = (value, label) => Number(integer(value, label, 0n, 255n));
const u32 = (value, label) => Number(integer(value, label, 0n, 0xffffffffn));
const u64 = (value, label) => integer(value, label, 0n, U64_MAX);
const i64 = (value, label) => integer(value, label, I64_MIN, I64_MAX);
const u256 = (value, label) => integer(value, label, 0n, U256_MAX);

function u32le(value) { const out = new Uint8Array(4); new DataView(out.buffer).setUint32(0, value, true); return out; }
function u32be(value) { const out = new Uint8Array(4); new DataView(out.buffer).setUint32(0, value, false); return out; }
function u16le(value) { const out = new Uint8Array(2); new DataView(out.buffer).setUint16(0, value, true); return out; }
function u64le(value) { const out = new Uint8Array(8); new DataView(out.buffer).setBigUint64(0, value, true); return out; }
function i64le(value) { const out = new Uint8Array(8); new DataView(out.buffer).setBigInt64(0, value, true); return out; }
function u256be(value) { return hexToBytes(value.toString(16).padStart(64, '0')); }
const borshBytes = bytes => concat(u32le(bytes.length), bytes);

class Reader {
    constructor(bytes, label) { this.bytes = bytes; this.offset = 0; this.label = label; }
    take(length) {
        if (this.offset + length > this.bytes.length) throw new Error(`${this.label} is truncated.`);
        const out = this.bytes.slice(this.offset, this.offset + length);
        this.offset += length;
        return out;
    }
    view(length) { const bytes = this.take(length); return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength); }
    u8() { return this.take(1)[0]; }
    u16() { return this.view(2).getUint16(0, true); }
    u32() { return this.view(4).getUint32(0, true); }
    u64() { return this.view(8).getBigUint64(0, true); }
    i64() { return this.view(8).getBigInt64(0, true); }
    vec() { return this.take(this.u32()); }
    end() { if (this.offset !== this.bytes.length) throw new Error(`${this.label} has trailing bytes.`); }
}

// ---------------------------------------------------------------- emergency key

/**
 * Per-note emergency key (design D5): ed25519 from
 * HKDF-SHA256(ikm = secret as 32-byte big-endian, salt = empty,
 * info = "dagon-zkapi/cctp-ek/v1", L = 32).
 */
export function deriveEmergencyKey(secret) {
    let ikm;
    if (typeof secret === 'bigint') {
        if (secret <= 0n || secret > U256_MAX) throw new RangeError('Note secret must be a nonzero 256-bit value.');
        ikm = u256be(secret);
    } else if (secret instanceof Uint8Array && secret.length === 32) {
        if (secret.every(byte => byte === 0)) throw new RangeError('Note secret must be nonzero.');
        ikm = Uint8Array.from(secret);
    } else {
        throw new TypeError('Note secret must be a bigint or 32 bytes.');
    }
    const seed = hkdf(sha256, ikm, new Uint8Array(0), utf8(EK_INFO), 32);
    const keypair = Keypair.fromSeed(seed);
    return { seed, publicKey: keypair.publicKey, keypair };
}

// ---------------------------------------------------------------- intent / target (design §5.1)

/** Borsh CctpTarget {domain u32, recipient [32], destination_caller [32], max_cctp_fee u64, min_finality u32, hook_data Vec<u8>}. */
export function encodeCctpTarget(target) {
    if (!target || typeof target !== 'object') throw new TypeError('CCTP target is required.');
    const domain = u32(target.domain, 'CCTP target domain');
    if (domain === SOLANA_DOMAIN) throw new RangeError('A CCTP target cannot be Solana.');
    const recipient = bytes32(target.recipient, 'CCTP target recipient');
    if (recipient.every(byte => byte === 0)) throw new RangeError('CCTP target recipient must be nonzero.');
    const destinationCaller = bytes32(target.destinationCaller ?? new Uint8Array(32), 'CCTP target destination caller');
    const minFinality = u32(target.minFinality, 'CCTP target finality');
    if (minFinality !== FINALITY_FAST && minFinality !== FINALITY_STANDARD) throw new RangeError('CCTP target finality must be 1000 or 2000.');
    const hookData = toBytes(target.hookData ?? new Uint8Array(0), 'CCTP target hook data');
    if (hookData.length > MAX_TARGET_HOOK_BYTES) throw new RangeError(`CCTP target hook data exceeds ${MAX_TARGET_HOOK_BYTES} bytes.`);
    return concat(u32le(domain), recipient, destinationCaller, u64le(u64(target.maxCctpFee, 'CCTP target max fee')),
        u32le(minFinality), borshBytes(hookData));
}

function readCctpTarget(reader) {
    const target = {
        domain: reader.u32(), recipient: reader.take(32), destinationCaller: reader.take(32),
        maxCctpFee: reader.u64(), minFinality: reader.u32(), hookData: reader.vec()
    };
    encodeCctpTarget(target);
    return target;
}

/** Borsh InboundIntent v1 (design §5.1). */
export function encodeInboundIntent(intent) {
    if (!intent || typeof intent !== 'object') throw new TypeError('Inbound intent is required.');
    const version = u8(intent.version ?? INTENT_VERSION, 'Inbound intent version');
    if (version !== INTENT_VERSION) throw new RangeError('Only inbound intent version 1 is supported.');
    const commitment = bytes32(intent.commitment, 'Inbound intent commitment');
    if (commitment.every(byte => byte === 0)) throw new RangeError('Inbound intent commitment must be nonzero.');
    return concat(Uint8Array.of(version), commitment,
        publicKey(intent.emergencyOwner, 'Inbound intent emergency owner').toBytes(),
        u64le(u64(intent.maxRelayerFee, 'Inbound intent relayer fee cap')),
        publicKey(intent.priorityRelayer ?? PublicKey.default, 'Inbound intent priority relayer').toBytes(),
        i64le(i64(intent.priorityUntil ?? 0n, 'Inbound intent priority deadline')),
        i64le(i64(intent.refundAfter, 'Inbound intent refund time')),
        encodeCctpTarget(intent.refund));
}

export function decodeInboundIntent(bytes) {
    const reader = new Reader(toBytes(bytes, 'Inbound intent'), 'Inbound intent');
    const version = reader.u8();
    if (version !== INTENT_VERSION) throw new Error(`Unsupported inbound intent version ${version}.`);
    const intent = {
        version, commitment: reader.take(32), emergencyOwner: new PublicKey(reader.take(32)), maxRelayerFee: reader.u64(),
        priorityRelayer: new PublicKey(reader.take(32)), priorityUntil: reader.i64(), refundAfter: reader.i64(),
        refund: readCctpTarget(reader)
    };
    reader.end();
    if (intent.commitment.every(byte => byte === 0)) throw new Error('Inbound intent commitment must be nonzero.');
    return intent;
}

/** keccak256("dagon-zkapi/cctp-intent/v1" ‖ forwarderId ‖ borsh(intent)). */
export function intentId(intent, forwarderId) {
    return keccak_256(concat(INTENT_DOMAIN, publicKey(forwarderId, 'Forwarder program ID').toBytes(), encodeInboundIntent(intent)));
}

// ---------------------------------------------------------------- hooks

/**
 * Circle Forwarding Service `cctp-forward` v0 hook: magic (24) ‖ u32 BE 0 ‖
 * u32 BE len ‖ circle data. Without an owner it is the static 32-byte hook;
 * with one it requests ATA creation (len 33, flag 1, owner 32).
 */
export function encodeForwardHook({ createAtaOwner = null } = {}) {
    const magic = new Uint8Array(24);
    magic.set(utf8(FORWARD_MAGIC));
    if (createAtaOwner == null) return concat(magic, u32be(0), u32be(0));
    return concat(magic, u32be(0), u32be(33), Uint8Array.of(1), publicKey(createAtaOwner, 'ATA owner').toBytes());
}

/** Inbound hook (design D2): forward hook with ATA creation for `ataOwner`, then "DGNZK-IN" ‖ u16 LE len ‖ borsh(intent). */
export function encodeInboundHook({ ataOwner, intent }) {
    const encoded = encodeInboundIntent(intent);
    if (encoded.length > 0xffff) throw new RangeError('Inbound intent is too large.');
    return concat(encodeForwardHook({ createAtaOwner: ataOwner }), INBOUND_TAG, u16le(encoded.length), encoded);
}

/**
 * Parses hook data: `forward` is the `cctp-forward` header (or null),
 * `developerData` the bytes after Circle's reserved space, `intent` the
 * DGNZK-IN preimage when the developer data carries one.
 */
export function decodeHook(bytes) {
    const hook = toBytes(bytes, 'Hook data');
    const magic = new Uint8Array(24);
    magic.set(utf8(FORWARD_MAGIC));
    let forward = null;
    let developerData = hook;
    if (hook.length >= 32 && equalBytes(hook.subarray(0, 24), magic)) {
        const view = new DataView(hook.buffer, hook.byteOffset, hook.byteLength);
        const version = view.getUint32(24, false);
        const length = view.getUint32(28, false);
        if (32 + length > hook.length) throw new Error('Forward hook is truncated.');
        const circleData = hook.slice(32, 32 + length);
        let createAta = false; let ataOwner = null;
        if (version === 0 && length > 0) {
            if (length < 33 || circleData[0] !== 1) throw new Error('Unsupported forward hook Circle data.');
            createAta = true;
            ataOwner = new PublicKey(circleData.slice(1, 33));
        }
        forward = { version, circleData, createAta, ataOwner };
        developerData = hook.slice(32 + length);
    }
    let intent = null;
    if (developerData.length >= INBOUND_TAG.length && equalBytes(developerData.subarray(0, INBOUND_TAG.length), INBOUND_TAG)) {
        const reader = new Reader(developerData.slice(INBOUND_TAG.length), 'Inbound hook');
        const encoded = reader.take(reader.u16());
        reader.end();
        intent = decodeInboundIntent(encoded);
    }
    return { forward, intent, developerData: Uint8Array.from(developerData) };
}

// ---------------------------------------------------------------- message V2

function bodyBytes(body) {
    if (body instanceof Uint8Array) return body;
    const hookData = toBytes(body.hookData ?? new Uint8Array(0), 'Burn hook data');
    return concat(u32be(u32(body.version ?? BURN_MESSAGE_VERSION, 'Burn message version')),
        bytes32(body.burnToken, 'Burn token'), bytes32(body.mintRecipient, 'Mint recipient'),
        u256be(u256(body.amount, 'Burn amount')), bytes32(body.messageSender, 'Message sender'),
        u256be(u256(body.maxFee ?? 0n, 'Max fee')), u256be(u256(body.feeExecuted ?? 0n, 'Fee executed')),
        u256be(u256(body.expirationBlock ?? 0n, 'Expiration block')), hookData);
}

/** CCTP V2 message: 148-byte header (big-endian) ‖ BurnMessageV2 body (228 bytes ‖ hook data). */
export function encodeMessageV2(message) {
    const body = bodyBytes(message.body);
    if (body.length > MAX_MESSAGE_BODY_BYTES) throw new RangeError('Message body exceeds 8192 bytes.');
    return concat(u32be(u32(message.version ?? MESSAGE_VERSION, 'Message version')),
        u32be(u32(message.sourceDomain, 'Source domain')), u32be(u32(message.destinationDomain, 'Destination domain')),
        bytes32(message.nonce ?? new Uint8Array(32), 'Nonce'), bytes32(message.sender, 'Sender'),
        bytes32(message.recipient, 'Recipient'), bytes32(message.destinationCaller ?? new Uint8Array(32), 'Destination caller'),
        u32be(u32(message.minFinalityThreshold, 'Min finality threshold')),
        u32be(u32(message.finalityThresholdExecuted ?? 0, 'Finality threshold executed')), body);
}

export function decodeMessageV2(bytes) {
    const data = toBytes(bytes, 'CCTP message');
    if (data.length < HEADER_BYTES + BURN_BODY_BYTES) throw new Error('CCTP message is too short for a burn message.');
    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    const word = offset => BigInt(`0x${bytesToHex(data.subarray(offset, offset + 32))}`);
    const b = HEADER_BYTES;
    return {
        version: view.getUint32(0), sourceDomain: view.getUint32(4), destinationDomain: view.getUint32(8),
        nonce: data.slice(12, 44), sender: data.slice(44, 76), recipient: data.slice(76, 108), destinationCaller: data.slice(108, 140),
        minFinalityThreshold: view.getUint32(140), finalityThresholdExecuted: view.getUint32(144),
        body: {
            version: view.getUint32(b), burnToken: data.slice(b + 4, b + 36), mintRecipient: data.slice(b + 36, b + 68),
            amount: word(b + 68), messageSender: data.slice(b + 100, b + 132), maxFee: word(b + 132),
            feeExecuted: word(b + 164), expirationBlock: word(b + 196), hookData: data.slice(b + 228)
        }
    };
}

/** keccak256(message): the digest attesters sign. */
export function messageHash(bytes) {
    return keccak_256(toBytes(bytes, 'CCTP message'));
}

/** MessageSent event account {rent_payer, created_at, message} (owner: MessageTransmitterV2). */
export function decodeMessageSentEvent(bytes) {
    const reader = new Reader(toBytes(bytes, 'MessageSent account'), 'MessageSent account');
    if (!equalBytes(reader.take(8), MESSAGE_SENT_DISCRIMINATOR)) throw new Error('Not a CCTP MessageSent account.');
    const event = { rentPayer: new PublicKey(reader.take(32)), createdAt: reader.i64(), message: reader.vec() };
    reader.end();
    return event;
}

// ---------------------------------------------------------------- Solana PDAs

const MT = () => new PublicKey(MESSAGE_TRANSMITTER_V2);
const TMM = () => new PublicKey(TOKEN_MESSENGER_MINTER_V2);
const pda = (seeds, program) => PublicKey.findProgramAddressSync(seeds, program)[0];

function associatedTokenAddress(owner, mint) {
    return pda([owner.toBytes(), new PublicKey(TOKEN_PROGRAM_ID).toBytes(), mint.toBytes()], new PublicKey(ASSOCIATED_TOKEN_PROGRAM_ID));
}

/** Every fixed Solana CCTP V2 account for `mint` (USDC by default). */
export function cctpAccounts(mint = USDC_MINT) {
    const mintKey = publicKey(mint, 'CCTP mint');
    return {
        messageTransmitterProgram: MT(),
        tokenMessengerMinterProgram: TMM(),
        messageTransmitter: pda([utf8('message_transmitter')], MT()),
        messageTransmitterAuthority: pda([utf8('message_transmitter_authority'), TMM().toBytes()], MT()),
        messageTransmitterEventAuthority: pda([utf8('__event_authority')], MT()),
        tokenMessenger: pda([utf8('token_messenger')], TMM()),
        tokenMinter: pda([utf8('token_minter')], TMM()),
        senderAuthority: pda([utf8('sender_authority')], TMM()),
        tokenMessengerEventAuthority: pda([utf8('__event_authority')], TMM()),
        localToken: pda([utf8('local_token'), mintKey.toBytes()], TMM()),
        custody: pda([utf8('custody'), mintKey.toBytes()], TMM()),
        feeRecipientTokenAccount: associatedTokenAddress(new PublicKey(CCTP_FEE_RECIPIENT), mintKey),
        mint: mintKey,
        tokenProgram: new PublicKey(TOKEN_PROGRAM_ID),
        systemProgram: SystemProgram.programId
    };
}

export function remoteTokenMessenger(domain) {
    return pda([utf8('remote_token_messenger'), utf8(String(u32(domain, 'Remote domain')))], TMM());
}

export function tokenPair(domain, remoteToken) {
    return pda([utf8('token_pair'), utf8(String(u32(domain, 'Remote domain'))), bytes32(remoteToken, 'Remote token')], TMM());
}

export function usedNonce(nonce) {
    return pda([utf8('used_nonce'), bytes32(nonce, 'Nonce')], MT());
}

export function denylistAccount(owner) {
    return pda([utf8('denylist_account'), publicKey(owner, 'Denylist owner').toBytes()], TMM());
}

// ---------------------------------------------------------------- Solana instructions

const meta = (pubkey, isWritable = false, isSigner = false) => ({ pubkey, isSigner, isWritable });

/**
 * MessageTransmitterV2 `receive_message` with TokenMessengerMinterV2's
 * remaining accounts. The recipient token account must already exist.
 */
export function receiveMessageInstruction({ payer, caller = payer, message, attestation, recipientTokenAccount, feeRecipientTokenAccount, mint = USDC_MINT }) {
    const messageBytes = toBytes(message, 'CCTP message');
    const attestationBytes = toBytes(attestation, 'Attestation');
    const decoded = decodeMessageV2(messageBytes);
    if (decoded.destinationDomain !== SOLANA_DOMAIN) throw new Error('CCTP message is not for Solana.');
    if (!equalBytes(decoded.recipient, TMM().toBytes())) throw new Error('CCTP message recipient is not TokenMessengerMinterV2.');
    if (attestationBytes.length === 0 || attestationBytes.length % 65 !== 0) throw new Error('Attestation must be 65-byte signatures.');
    const mintRecipient = new PublicKey(decoded.body.mintRecipient);
    const recipient = recipientTokenAccount == null ? mintRecipient : publicKey(recipientTokenAccount, 'Recipient token account');
    if (!recipient.equals(mintRecipient)) throw new Error('Recipient token account differs from the message mint recipient.');
    const accounts = cctpAccounts(mint);
    const payerKey = publicKey(payer, 'Payer');
    return new TransactionInstruction({
        programId: MT(),
        keys: [
            meta(payerKey, true, true), meta(publicKey(caller, 'Caller'), false, true),
            meta(accounts.messageTransmitterAuthority), meta(accounts.messageTransmitter),
            meta(usedNonce(decoded.nonce), true), meta(TMM()), meta(SystemProgram.programId),
            meta(accounts.messageTransmitterEventAuthority), meta(MT()),
            meta(accounts.tokenMessenger), meta(remoteTokenMessenger(decoded.sourceDomain)), meta(accounts.tokenMinter),
            meta(accounts.localToken, true), meta(tokenPair(decoded.sourceDomain, decoded.body.burnToken)),
            meta(feeRecipientTokenAccount == null ? accounts.feeRecipientTokenAccount : publicKey(feeRecipientTokenAccount, 'Fee recipient token account'), true),
            meta(recipient, true), meta(accounts.custody, true), meta(accounts.tokenProgram),
            meta(accounts.tokenMessengerEventAuthority), meta(TMM())
        ],
        data: concat(CCTP_DISCRIMINATORS.receiveMessage, borshBytes(messageBytes), borshBytes(attestationBytes))
    });
}

/** TokenMessengerMinterV2 `deposit_for_burn`, or `deposit_for_burn_with_hook` iff `hookData` is non-empty. */
export function depositForBurnInstruction({ owner, eventRentPayer, burnTokenAccount, messageSentEventData, amount, destinationDomain,
    mintRecipient, destinationCaller = new Uint8Array(32), maxFee, minFinalityThreshold, hookData = new Uint8Array(0), mint = USDC_MINT }) {
    const ownerKey = publicKey(owner, 'Burn owner');
    const amountValue = u64(amount, 'Burn amount');
    const maxFeeValue = u64(maxFee, 'Burn max fee');
    if (amountValue === 0n || amountValue <= maxFeeValue) throw new RangeError('Burn amount must exceed the max fee.');
    const domain = u32(destinationDomain, 'Destination domain');
    if (domain === SOLANA_DOMAIN) throw new RangeError('Destination domain cannot be Solana.');
    const recipient = bytes32(mintRecipient, 'Mint recipient');
    if (recipient.every(byte => byte === 0)) throw new RangeError('Mint recipient must be nonzero.');
    const hook = toBytes(hookData, 'Hook data');
    if (hook.length > MAX_MESSAGE_BODY_BYTES - BURN_BODY_BYTES) throw new RangeError('Hook data is too large.');
    const accounts = cctpAccounts(mint);
    const params = concat(u64le(amountValue), u32le(domain), recipient, bytes32(destinationCaller, 'Destination caller'),
        u64le(maxFeeValue), u32le(u32(minFinalityThreshold, 'Min finality threshold')));
    const data = hook.length
        ? concat(CCTP_DISCRIMINATORS.depositForBurnWithHook, params, borshBytes(hook))
        : concat(CCTP_DISCRIMINATORS.depositForBurn, params);
    return new TransactionInstruction({
        programId: TMM(),
        keys: [
            meta(ownerKey, false, true), meta(publicKey(eventRentPayer, 'Event rent payer'), true, true),
            meta(accounts.senderAuthority),
            meta(burnTokenAccount == null ? associatedTokenAddress(ownerKey, accounts.mint) : publicKey(burnTokenAccount, 'Burn token account'), true),
            meta(denylistAccount(ownerKey)), meta(accounts.messageTransmitter, true), meta(accounts.tokenMessenger),
            meta(remoteTokenMessenger(domain)), meta(accounts.tokenMinter), meta(accounts.localToken, true),
            meta(accounts.mint, true), meta(publicKey(messageSentEventData, 'MessageSent event account'), true, true),
            meta(MT()), meta(TMM()), meta(accounts.tokenProgram), meta(SystemProgram.programId),
            meta(accounts.tokenMessengerEventAuthority), meta(TMM())
        ],
        data
    });
}

/** MessageTransmitterV2 `reclaim_event_account` (5 days after the burn; payee = the burn's event rent payer). */
export function reclaimEventAccountInstruction({ payee, messageSentEventData, attestation, destinationMessage }) {
    return new TransactionInstruction({
        programId: MT(),
        keys: [meta(publicKey(payee, 'Payee'), true, true), meta(cctpAccounts().messageTransmitter, true),
            meta(publicKey(messageSentEventData, 'MessageSent event account'), true)],
        data: concat(CCTP_DISCRIMINATORS.reclaimEventAccount, borshBytes(toBytes(attestation, 'Attestation')),
            borshBytes(toBytes(destinationMessage, 'Destination message')))
    });
}

// ---------------------------------------------------------------- EVM calldata

const selector = signature => keccak_256(utf8(signature)).slice(0, 4);
const EVM_SELECTORS = Object.freeze({
    approve: selector('approve(address,uint256)'),
    depositForBurnWithHook: selector('depositForBurnWithHook(uint256,uint32,bytes32,address,bytes32,uint256,uint32,bytes)'),
    receiveMessage: selector('receiveMessage(bytes,bytes)')
});

/** A 20-byte EVM address left-padded to bytes32. */
export function evmBytes32(address) {
    if (typeof address !== 'string' || !/^0x[0-9a-f]{40}$/i.test(address)) throw new TypeError('EVM address must be 0x-prefixed 20-byte hex.');
    return concat(new Uint8Array(12), hexToBytes(address.slice(2)));
}

const word = value => u256be(value);
function abiDynamic(bytes) {
    const padded = new Uint8Array(Math.ceil(bytes.length / 32) * 32);
    padded.set(bytes);
    return concat(word(BigInt(bytes.length)), padded);
}
const hex = bytes => `0x${bytesToHex(bytes)}`;

export function evmApproveCalldata(spender, amount) {
    return hex(concat(EVM_SELECTORS.approve, evmBytes32(spender), word(u256(amount, 'Approve amount'))));
}

export function evmDepositForBurnWithHookCalldata({ amount, destinationDomain, mintRecipient, burnToken, destinationCaller = new Uint8Array(32),
    maxFee, minFinalityThreshold, hookData }) {
    const amountValue = u256(amount, 'Burn amount');
    const maxFeeValue = u256(maxFee, 'Burn max fee');
    if (amountValue === 0n || maxFeeValue >= amountValue) throw new RangeError('Burn amount must exceed the max fee.');
    const recipient = bytes32(mintRecipient, 'Mint recipient');
    if (recipient.every(byte => byte === 0)) throw new RangeError('Mint recipient must be nonzero.');
    const hook = toBytes(hookData, 'Hook data');
    if (!hook.length) throw new RangeError('depositForBurnWithHook requires hook data.');
    return hex(concat(EVM_SELECTORS.depositForBurnWithHook, word(amountValue), word(BigInt(u32(destinationDomain, 'Destination domain'))),
        recipient, evmBytes32(burnToken), bytes32(destinationCaller, 'Destination caller'), word(maxFeeValue),
        word(BigInt(u32(minFinalityThreshold, 'Min finality threshold'))), word(256n), abiDynamic(hook)));
}

/** MessageTransmitterV2 `receiveMessage(bytes message, bytes attestation)`. */
export function evmReceiveMessageCalldata(message, attestation) {
    const messageBytes = toBytes(message, 'CCTP message');
    const attestationBytes = toBytes(attestation, 'Attestation');
    const head = 64n;
    const tail = abiDynamic(messageBytes);
    return hex(concat(EVM_SELECTORS.receiveMessage, word(head), word(head + BigInt(tail.length)), tail, abiDynamic(attestationBytes)));
}

// ---------------------------------------------------------------- Iris

/** Thin client over Circle's attestation API (`iris-api.circle.com`) or the local iris-sim. */
export function irisClient(baseUrl, fetchImpl = globalThis.fetch) {
    const base = String(baseUrl).replace(/\/+$/, '');
    async function request(path, init, { notFound } = {}) {
        const response = await fetchImpl(`${base}${path}`, init);
        if (response.status === 404 && notFound) return notFound();
        if (!response.ok) {
            const error = new Error(`Iris ${path} failed with HTTP ${response.status}.`);
            error.status = response.status;
            throw error;
        }
        return response.json();
    }
    const domainPath = (value, label) => String(u32(value, label));
    return {
        messages(sourceDomain, transactionHash) {
            if (typeof transactionHash !== 'string' || !transactionHash) throw new TypeError('Transaction hash is required.');
            return request(`/v2/messages/${domainPath(sourceDomain, 'Source domain')}?transactionHash=${encodeURIComponent(transactionHash)}`,
                undefined, { notFound: () => ({ messages: [] }) });
        },
        fees(sourceDomain, destinationDomain, { forward = false, includeRecipientSetup = false } = {}) {
            const query = new URLSearchParams();
            if (forward) query.set('forward', 'true');
            if (includeRecipientSetup) query.set('includeRecipientSetup', 'true');
            const suffix = query.size ? `?${query}` : '';
            return request(`/v2/burn/USDC/fees/${domainPath(sourceDomain, 'Source domain')}/${domainPath(destinationDomain, 'Destination domain')}${suffix}`);
        },
        reattest(nonce) {
            return request(`/v2/reattest/${hex(bytes32(nonce, 'Nonce'))}`, { method: 'POST' });
        },
        publicKeys() {
            return request('/v2/publicKeys');
        }
    };
}
