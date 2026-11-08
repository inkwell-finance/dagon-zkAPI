// Test-only local stand-in for Circle's Iris attestation API (V2 paths and
// response shapes as observed on iris-api.circle.com; see
// local://cctp-facts.md §4). It reads source burns from the Solana localnet
// (MessageSent event account) or an EVM RPC (MessageSent log), fills the
// fields Iris fills (nonce, finalityThresholdExecuted, feeExecuted,
// expirationBlock) and signs keccak256(message) with the local test
// attesters (low-s, ascending). It can also synthesize source burns.
import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { keccak_256 } from '@noble/hashes/sha3';
import { secp256k1 } from '@noble/curves/secp256k1';
import { PublicKey } from '@solana/web3.js';
import { base58Decode } from '../../../sdk/services/zkapiSolanaTransport.mjs';
import { CCTP_DISCRIMINATORS, EVM_CCTP, SOLANA_DOMAIN, TOKEN_MESSENGER_MINTER_V2, decodeHook, decodeMessageSentEvent, decodeMessageV2,
    encodeMessageV2, evmBytes32, messageHash } from '../../../sdk/services/zkapiCctp.mjs';
import { CCTP_REMOTE_USDC, rpc } from './validator.mjs';

function evmChainName(domain) {
    const name = Object.keys(EVM_CCTP).find(key => EVM_CCTP[key].domain === domain);
    if (!name) throw new Error(`no EVM CCTP deployment known for domain ${domain}`);
    return name;
}

const MESSAGE_SENT_TOPIC = `0x${Buffer.from(keccak_256(new TextEncoder().encode('MessageSent(bytes)'))).toString('hex')}`;
const hex = bytes => `0x${Buffer.from(bytes).toString('hex')}`;
const fromHex = text => Buffer.from(String(text).replace(/^0x/, ''), 'hex');
const FAST = 1000; const STANDARD = 2000;
// Live Iris (2026-11-07): Fast to Solana from Ethereum 1, OP 1.3, Arbitrum 1.4, Base 1.3 bps; Solana outbound 1 bp.
export const DEFAULT_FAST_FEE_BPS = Object.freeze({ '0-5': 1, '2-5': 1.3, '3-5': 1.4, '6-5': 1.3, '5-0': 1, '5-2': 1, '5-3': 1, '5-6': 1 });
// Forward fees in USDC base units (live medians, rounded): to Solana, to Solana with ATA setup, from Solana to EVM.
export const DEFAULT_FORWARD_FEE = Object.freeze({ toSolana: 114_000n, toSolanaWithSetup: 246_000n, toEvm: 54_000n });
// Blocks per ~24 h on the destination (Solana: slots, as observed on mainnet).
const EXPIRY_WINDOW = Object.freeze({ 5: 432_000n, 0: 7_200n, 2: 43_200n, 3: 7_200n, 6: 43_200n });

/** Sign a 32-byte digest with each key (ascending addresses) as r‖s‖v (v = 27/28, low-s). */
export function attest(digest, attesters, threshold = attesters.length) {
    const sorted = [...attesters].sort((a, b) => (a.address < b.address ? -1 : 1)).slice(0, threshold);
    return Buffer.concat(sorted.map(({ privateKey }) => {
        const signature = secp256k1.sign(digest, fromHex(privateKey), { lowS: true });
        return Buffer.concat([Buffer.from(signature.toCompactRawBytes()), Buffer.from([27 + signature.recovery])]);
    }));
}

function sourceMessageFromSolanaTransaction(tx) {
    const keys = [...tx.transaction.message.accountKeys, ...(tx.meta?.loadedAddresses?.writable ?? []), ...(tx.meta?.loadedAddresses?.readonly ?? [])];
    const instructions = [...tx.transaction.message.instructions, ...(tx.meta?.innerInstructions ?? []).flatMap(inner => inner.instructions)];
    const events = [];
    for (const ix of instructions) {
        if (keys[ix.programIdIndex] !== TOKEN_MESSENGER_MINTER_V2) continue;
        const data = Buffer.from(base58Decode(ix.data));
        const disc = data.subarray(0, 8);
        if (disc.equals(Buffer.from(CCTP_DISCRIMINATORS.depositForBurn)) || disc.equals(Buffer.from(CCTP_DISCRIMINATORS.depositForBurnWithHook))) {
            events.push(keys[ix.accounts[11]]);
        }
    }
    return events;
}

function decodeEvmMessageSentLog(data) {
    const bytes = fromHex(data);
    const offset = Number(BigInt(hex(bytes.subarray(0, 32))));
    const length = Number(BigInt(hex(bytes.subarray(offset, offset + 32))));
    return bytes.subarray(offset + 32, offset + 32 + length);
}

function decodedMessageJson(message) {
    const decoded = decodeMessageV2(message);
    const solana = domain => domain === SOLANA_DOMAIN;
    const addr = (bytes, domain) => (solana(domain) ? new PublicKey(bytes).toBase58() : `0x${Buffer.from(bytes).subarray(12).toString('hex')}`);
    const hookData = decoded.body.hookData.length ? hex(decoded.body.hookData) : null;
    return {
        sourceDomain: String(decoded.sourceDomain), destinationDomain: String(decoded.destinationDomain), nonce: hex(decoded.nonce),
        sender: addr(decoded.sender, decoded.sourceDomain), recipient: addr(decoded.recipient, decoded.destinationDomain),
        destinationCaller: hex(decoded.destinationCaller), minFinalityThreshold: String(decoded.minFinalityThreshold),
        finalityThresholdExecuted: String(decoded.finalityThresholdExecuted), messageBody: hex(message.subarray(148)),
        decodedMessageBody: {
            burnToken: addr(decoded.body.burnToken, decoded.sourceDomain), mintRecipient: addr(decoded.body.mintRecipient, decoded.destinationDomain),
            amount: String(decoded.body.amount), messageSender: addr(decoded.body.messageSender, decoded.sourceDomain),
            maxFee: String(decoded.body.maxFee), feeExecuted: String(decoded.body.feeExecuted), expirationBlock: String(decoded.body.expirationBlock), hookData
        },
        decodedCctpXMessageBody: null
    };
}

/**
 * Start the simulator. `attesters` = [{privateKey, address}] (from
 * cctp-attesters.json), `evmRpcUrls` = {domain: url} for EVM sources and
 * destinations, `fastFeeBps` = {"src-dst": bps}, `forwardFee` = base units.
 */
export async function startIrisSim({ port = 0, host = '127.0.0.1', attesters, threshold = attesters.length, solanaRpcUrl, evmRpcUrls = {},
    fastFeeBps = DEFAULT_FAST_FEE_BPS, forwardFee = DEFAULT_FORWARD_FEE, expiryWindow = EXPIRY_WINDOW, log = () => {} }) {
    if (!attesters?.length || threshold < 1 || threshold > attesters.length) throw new Error('iris-sim needs at least `threshold` attester keys');
    const records = []; // {sourceDomain, transactionHash, index, source: Buffer, message, attestation, nonce, status, forwardState, forwardTxHash, delayReason, sequence}
    const byTx = new Map();
    const synthesized = new Map();
    let sequence = 0;
    const fees = { ...DEFAULT_FORWARD_FEE, ...Object.fromEntries(Object.entries(forwardFee).map(([k, v]) => [k, BigInt(v)])) };

    const fastBps = (src, dst) => fastFeeBps[`${src}-${dst}`];
    function fastFee(amount, src, dst) {
        const bps = fastBps(src, dst);
        if (bps === undefined) return null;
        return amount * BigInt(Math.round(bps * 1000)) / 10_000_000n;
    }
    async function destinationHeight(domain) {
        if (domain === SOLANA_DOMAIN) return BigInt(await rpc(solanaRpcUrl, 'getSlot', [{ commitment: 'confirmed' }]));
        const url = evmRpcUrls[domain];
        if (!url) throw new Error(`iris-sim has no RPC for destination domain ${domain}`);
        return BigInt(await rpc(url, 'eth_blockNumber', []));
    }

    /** Iris-side fields for a source message, then sign. */
    async function attestRecord(record, { refreshExpiry = true } = {}) {
        const source = decodeMessageV2(record.source);
        const amount = source.body.amount;
        const hook = source.body.hookData.length ? decodeHook(source.body.hookData) : { forward: null };
        const forwarding = hook.forward !== null && source.destinationCaller.every(byte => byte === 0);
        const forward = !forwarding ? 0n
            : source.destinationDomain === SOLANA_DOMAIN ? (hook.forward.createAta ? fees.toSolanaWithSetup : fees.toSolana) : fees.toEvm;
        const fast = source.minFinalityThreshold <= FAST ? fastFee(amount, source.sourceDomain, source.destinationDomain) : null;
        let finality = STANDARD; let fee = 0n; let delayReason = null; let forwardEligible = forwarding;
        if (fast !== null && source.body.maxFee >= fast + forward) { finality = FAST; fee = fast + forward; }
        else if (forwarding && source.body.maxFee >= forward) { fee = forward; if (fast !== null) delayReason = 'insufficient_fee'; }
        else { forwardEligible = false; if (fast !== null) delayReason = 'insufficient_fee'; }
        if (fee >= amount) throw new Error('iris-sim: fee would not be below the amount');
        let expirationBlock = 0n;
        if (finality === FAST) {
            const window = BigInt(expiryWindow[source.destinationDomain] ?? 43_200n);
            expirationBlock = refreshExpiry || record.expirationBlock === undefined ? await destinationHeight(source.destinationDomain) + window : record.expirationBlock;
        }
        const message = encodeMessageV2({ ...source, nonce: record.nonce, finalityThresholdExecuted: finality,
            body: { ...source.body, feeExecuted: fee, expirationBlock } });
        record.expirationBlock = expirationBlock;
        record.message = message;
        record.attestation = attest(messageHash(message), attesters, threshold);
        record.status = 'complete';
        record.delayReason = delayReason;
        record.forwardState ??= forwardEligible ? 'PENDING' : undefined;
        record.sequence = ++sequence;
        log(`iris-sim attested ${record.sourceDomain}->${source.destinationDomain} nonce ${hex(record.nonce)} finality ${finality} fee ${fee}`);
        return record;
    }

    function newRecord(sourceDomain, transactionHash, index, source) {
        const u32be = value => { const out = Buffer.alloc(4); out.writeUInt32BE(value); return out; };
        const nonce = keccak_256(Buffer.concat([Buffer.from('iris-sim'), u32be(sourceDomain), Buffer.from(transactionHash), u32be(index)]));
        return { sourceDomain, transactionHash, index, source: Buffer.from(source), nonce };
    }

    async function fetchSourceMessages(sourceDomain, transactionHash) {
        if (synthesized.has(`${sourceDomain}:${transactionHash}`)) return [synthesized.get(`${sourceDomain}:${transactionHash}`)];
        if (sourceDomain === SOLANA_DOMAIN) {
            const tx = await rpc(solanaRpcUrl, 'getTransaction', [transactionHash, { encoding: 'json', maxSupportedTransactionVersion: 0, commitment: 'confirmed' }]);
            if (!tx || tx.meta?.err) return [];
            const out = [];
            for (const account of sourceMessageFromSolanaTransaction(tx)) {
                const info = (await rpc(solanaRpcUrl, 'getAccountInfo', [account, { encoding: 'base64', commitment: 'confirmed' }])).value;
                if (info) out.push(decodeMessageSentEvent(Buffer.from(info.data[0], 'base64')).message);
            }
            return out;
        }
        const url = evmRpcUrls[sourceDomain];
        if (!url) return [];
        const receipt = await rpc(url, 'eth_getTransactionReceipt', [transactionHash]);
        if (!receipt || receipt.status !== '0x1') return [];
        return receipt.logs.filter(entry => entry.address.toLowerCase() === EVM_CCTP[evmChainName(sourceDomain)].messageTransmitter.toLowerCase() && entry.topics[0] === MESSAGE_SENT_TOPIC)
            .map(entry => decodeEvmMessageSentLog(entry.data));
    }

    async function messagesFor(sourceDomain, transactionHash) {
        const key = `${sourceDomain}:${transactionHash}`;
        if (!byTx.has(key)) {
            const sources = await fetchSourceMessages(sourceDomain, transactionHash);
            if (!sources.length) return [];
            const created = [];
            for (const [index, source] of sources.entries()) {
                const decoded = decodeMessageV2(source);
                if (decoded.sourceDomain !== sourceDomain) throw new Error(`burn ${transactionHash} is not from domain ${sourceDomain}`);
                const record = newRecord(sourceDomain, transactionHash, index, source);
                await attestRecord(record);
                created.push(record);
            }
            records.push(...created);
            byTx.set(key, created);
        }
        return byTx.get(key);
    }

    const recordJson = record => ({
        attestation: hex(record.attestation), message: hex(record.message), eventNonce: hex(record.nonce), cctpVersion: 2,
        status: record.status, decodedMessage: decodedMessageJson(record.message), delayReason: record.delayReason,
        ...(record.forwardState ? { forwardState: record.forwardState } : {}), ...(record.forwardTxHash ? { forwardTxHash: record.forwardTxHash } : {})
    });

    function feesJson(src, dst, query) {
        const forward = query.get('forward') === 'true';
        const setup = query.get('includeRecipientSetup') === 'true' && dst === SOLANA_DOMAIN;
        const base = dst === SOLANA_DOMAIN ? (setup ? fees.toSolanaWithSetup : fees.toSolana) : fees.toEvm;
        const forwardFeeJson = forward ? { forwardFee: { low: Number(base * 99n / 100n), med: Number(base), high: Number(base * 108n / 100n) } } : {};
        const bps = fastBps(src, dst);
        return [...(bps === undefined ? [] : [{ finalityThreshold: FAST, minimumFee: bps, ...forwardFeeJson }]),
            { finalityThreshold: STANDARD, minimumFee: 0, ...forwardFeeJson }];
    }

    /**
     * A source-chain burn as the remote TokenMessengerV2 would emit it
     * (sender = remote TokenMessenger, burnToken = remote USDC); returns the
     * fake transaction hash to query `/v2/messages/{src}` with.
     */
    function synthesizeBurn({ sourceDomain, destinationDomain = SOLANA_DOMAIN, mintRecipient, amount, maxFee = 0n, minFinalityThreshold = FAST,
        hookData = new Uint8Array(0), messageSender = `0x${'11'.repeat(20)}`, destinationCaller = new Uint8Array(32) }) {
        if (destinationDomain !== SOLANA_DOMAIN) throw new Error('synthesized burns target Solana');
        const remoteUsdc = CCTP_REMOTE_USDC[sourceDomain];
        if (!remoteUsdc) throw new Error(`no remote USDC for domain ${sourceDomain}`);
        const source = encodeMessageV2({ sourceDomain, destinationDomain, sender: evmBytes32(EVM_CCTP.base.tokenMessenger),
            recipient: new PublicKey(TOKEN_MESSENGER_MINTER_V2).toBytes(), destinationCaller, minFinalityThreshold,
            body: { burnToken: evmBytes32(remoteUsdc), mintRecipient, amount: BigInt(amount), messageSender: evmBytes32(messageSender), maxFee: BigInt(maxFee), hookData } });
        const transactionHash = hex(randomBytes(32));
        synthesized.set(`${sourceDomain}:${transactionHash}`, source);
        return { transactionHash, sourceMessage: source };
    }

    async function reattest(nonceHex) {
        const record = records.find(entry => hex(entry.nonce) === String(nonceHex).toLowerCase());
        if (!record) return null;
        await attestRecord(record);
        return record;
    }

    async function readBody(request) {
        let body = '';
        for await (const chunk of request) body += chunk;
        return body ? JSON.parse(body) : {};
    }

    const server = createServer(async (request, response) => {
        const send = (status, body) => {
            response.writeHead(status, { 'content-type': 'application/json' });
            response.end(JSON.stringify(body, (_, value) => (typeof value === 'bigint' ? value.toString() : value)));
        };
        try {
            const url = new URL(request.url, 'http://iris-sim');
            let match;
            if (request.method === 'GET' && (match = url.pathname.match(/^\/v2\/messages\/(\d+)$/))) {
                const transactionHash = url.searchParams.get('transactionHash');
                const nonce = url.searchParams.get('nonce');
                const solanaSource = Number(match[1]) === SOLANA_DOMAIN;
                const wellFormed = !transactionHash || (solanaSource ? /^[1-9A-HJ-NP-Za-km-z]{64,88}$/ : /^0x[0-9a-fA-F]{64}$/).test(transactionHash);
                if ((!transactionHash && !nonce) || !wellFormed) return send(400, { code: 400, message: 'Bad request.' });
                let found = [];
                if (transactionHash) found = await messagesFor(Number(match[1]), transactionHash);
                else if (nonce) found = records.filter(entry => entry.sourceDomain === Number(match[1]) && hex(entry.nonce) === nonce.toLowerCase());
                if (!found.length) return send(404, { error: 'Message not found for provided parameters' });
                return send(200, { messages: found.map(recordJson) });
            }
            if (request.method === 'POST' && (match = url.pathname.match(/^\/v2\/reattest\/(0x[0-9a-fA-F]{64})$/))) {
                const record = await reattest(match[1]);
                if (!record) return send(404, { code: 404, message: 'Not found.' });
                return send(200, { message: 'Re-attestation successfully requested for nonce.', nonce: hex(record.nonce) });
            }
            if (request.method === 'GET' && (match = url.pathname.match(/^\/v2\/burn\/USDC\/fees\/(\d+)\/(\d+)$/))) {
                return send(200, feesJson(Number(match[1]), Number(match[2]), url.searchParams));
            }
            if (request.method === 'GET' && url.pathname === '/v2/publicKeys') {
                return send(200, { publicKeys: attesters.map(({ privateKey }) => ({ publicKey: hex(secp256k1.getPublicKey(fromHex(privateKey), false)), cctpVersion: 2 })) });
            }
            // Simulator-only endpoints (forwarding-sim and tests).
            if (request.method === 'GET' && url.pathname === '/sim/messages') {
                const since = Number(url.searchParams.get('since') ?? 0);
                return send(200, { sequence, messages: records.filter(entry => entry.sequence > since).map(entry => ({ sequence: entry.sequence, ...recordJson(entry) })) });
            }
            if (request.method === 'POST' && url.pathname === '/sim/burns') {
                const body = await readBody(request);
                const burn = synthesizeBurn({ ...body, mintRecipient: body.mintRecipient.startsWith('0x') ? fromHex(body.mintRecipient) : new PublicKey(body.mintRecipient).toBytes(),
                    hookData: body.hookData ? fromHex(body.hookData) : new Uint8Array(0), destinationCaller: body.destinationCaller ? fromHex(body.destinationCaller) : new Uint8Array(32) });
                return send(200, { transactionHash: burn.transactionHash, sourceMessage: hex(burn.sourceMessage) });
            }
            if (request.method === 'POST' && url.pathname === '/sim/forward') {
                const body = await readBody(request);
                const record = records.find(entry => hex(entry.nonce) === String(body.nonce).toLowerCase());
                if (!record) return send(404, { error: 'unknown nonce' });
                record.forwardState = body.forwardState;
                if (body.forwardTxHash) { record.forwardTxHash = body.forwardTxHash; record.destinationMintTxHash = body.forwardTxHash; }
                return send(200, { ok: true });
            }
            return send(404, { code: 404, message: 'Not found.' });
        } catch (error) {
            log(`iris-sim error: ${error.stack ?? error}`);
            return send(500, { code: 500, message: String(error.message ?? error) });
        }
    });
    await new Promise((done, fail) => { server.once('error', fail); server.listen(port, host, done); });
    const address = server.address();
    return {
        url: `http://${host}:${address.port}`,
        synthesizeBurn,
        records,
        close: () => new Promise(done => { server.closeAllConnections?.(); server.close(() => done()); })
    };
}
