import assert from 'node:assert/strict';
import test from 'node:test';
import { hkdfSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { keccak_256 } from '@noble/hashes/sha3';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
// @noble/curves ships with @solana/web3.js; used here only to check real attestations.
import { secp256k1 } from '@noble/curves/secp256k1';
import { Keypair, PublicKey } from '@solana/web3.js';

import {
    CCTP_DISCRIMINATORS, CCTP_DOMAINS, EVM_CCTP, FINALITY_FAST, FINALITY_STANDARD, MESSAGE_TRANSMITTER_V2, SOLANA_DOMAIN,
    TOKEN_MESSENGER_MINTER_V2, cctpAccounts, decodeHook, decodeInboundIntent, decodeMessageSentEvent, decodeMessageV2,
    denylistAccount, depositForBurnInstruction, deriveEmergencyKey, encodeCctpTarget, encodeForwardHook, encodeInboundHook,
    encodeInboundIntent, encodeMessageV2, evmApproveCalldata, evmBytes32, evmDepositForBurnWithHookCalldata,
    evmReceiveMessageCalldata, intentId, irisClient, messageHash, receiveMessageInstruction, reclaimEventAccountInstruction,
    remoteTokenMessenger, tokenPair, usedNonce
} from '../services/zkapiCctp.mjs';

const vectors = JSON.parse(readFileSync(new URL('./fixtures/cctp-vectors.json', import.meta.url), 'utf8'));
const hex = bytes => `0x${bytesToHex(bytes)}`;
const keysOf = ix => ix.keys.map(k => ({ pubkey: k.pubkey.toBase58(), signer: k.isSigner, writable: k.isWritable }));
const intentFrom = input => ({ ...input, maxRelayerFee: BigInt(input.maxRelayerFee), priorityUntil: BigInt(input.priorityUntil),
    refundAfter: BigInt(input.refundAfter), refund: { ...input.refund, maxCctpFee: BigInt(input.refund.maxCctpFee) } });
const messageFrom = input => ({ ...input, body: { ...input.body, amount: BigInt(input.body.amount), maxFee: BigInt(input.body.maxFee),
    feeExecuted: BigInt(input.body.feeExecuted), expirationBlock: BigInt(input.body.expirationBlock) } });

test('discriminators equal the Circle V2 IDL', () => {
    // examples/target/idl/{message_transmitter_v2,token_messenger_minter_v2}.json @ ec16e95d
    assert.deepEqual([...CCTP_DISCRIMINATORS.receiveMessage], [38, 144, 127, 225, 31, 225, 238, 25]);
    assert.deepEqual([...CCTP_DISCRIMINATORS.depositForBurn], [215, 60, 61, 46, 114, 55, 128, 176]);
    assert.deepEqual([...CCTP_DISCRIMINATORS.depositForBurnWithHook], [111, 245, 62, 131, 204, 108, 223, 155]);
    assert.deepEqual([...CCTP_DISCRIMINATORS.reclaimEventAccount], [94, 198, 180, 159, 131, 236, 15, 174]);
    assert.deepEqual(Object.fromEntries(Object.entries(CCTP_DISCRIMINATORS).map(([k, v]) => [k, [...v]])), vectors.discriminators);
});

test('constants and mainnet PDAs', () => {
    assert.equal(SOLANA_DOMAIN, 5);
    assert.equal(FINALITY_FAST, 1000);
    assert.equal(FINALITY_STANDARD, 2000);
    assert.equal(MESSAGE_TRANSMITTER_V2, 'CCTPV2Sm4AdWt5296sk4P66VBZ7bEhcARwFaaS9YPbeC');
    assert.equal(TOKEN_MESSENGER_MINTER_V2, 'CCTPV2vPZJS2u2BBsUoscuikbYjnpFmbFsvVuJdgUMQe');
    assert.equal(CCTP_DOMAINS.base, 6);
    assert.equal(CCTP_DOMAINS.arbitrum, 3);
    assert.deepEqual(EVM_CCTP.base, { chainId: 8453, domain: 6, tokenMessenger: '0x28b5a0e9C621a5BadaA536219b3a228C8168cf5d',
        messageTransmitter: '0x81D40F21F12A8F0E3252Bccb954D722d4c464B64', usdc: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913' });
    // Live mainnet accounts (getAccountInfo, 2026-11-07).
    const accounts = cctpAccounts();
    assert.equal(accounts.messageTransmitter.toBase58(), 'W1k5ijkaSTo5iA5zChNpfzcy796fLhkBxfmJuR8W8HU');
    assert.equal(accounts.tokenMessenger.toBase58(), 'AawthJCGRmggpfv9MMWV6Jmo9cue4gL9wUZgRBShg58W');
    assert.equal(accounts.tokenMinter.toBase58(), 'E1bQJ8eMMn3zmeSewW3HQ8zmJr7KR75JonbwAtWx2bux');
    assert.equal(accounts.localToken.toBase58(), 'CRBBbuLCyrkQy4dCTHxqstSmDQv4ajBeUVb9qUdMVaP1');
    assert.equal(accounts.custody.toBase58(), '6xTBTqJMBr5m7BKqVxmW2x11DfqUwtD3TJsqpxELx72L');
    assert.equal(accounts.feeRecipientTokenAccount.toBase58(), '6zNSMmZGMhNyqZMHkx2L63DLuqh5qoqBhaQJPJD7Fvt3');
    assert.equal(remoteTokenMessenger(6).toBase58(), 'BwmDYtQ7jFj8ddaTmKa7fz9hyuK9n58mvc8G7DYNcKjM');
    assert.equal(remoteTokenMessenger(0).toBase58(), '3EzN2mcmdfSNGXRCAixSpTteK6ywdmFDZZWvkMnznFt9');
    assert.equal(tokenPair(6, EVM_CCTP.base.usdc).toBase58(), '3udrkuozTYGBVMyMdxmXWVTUrnpmSh7kEZiq67A8jTws');
    assert.equal(tokenPair(3, EVM_CCTP.arbitrum.usdc).toBase58(), 'pUDNiGnQsosQMDmiN1cHUbMnH8JYBB7mEkAbxJ1yeg9');
    for (const [name, address] of Object.entries(vectors.pdas)) {
        if (typeof address === 'string') assert.equal(accounts[name].toBase58(), address, name);
    }
    for (const [domain, address] of Object.entries(vectors.pdas.remote_token_messenger)) assert.equal(remoteTokenMessenger(Number(domain)).toBase58(), address);
    for (const [domain, pair] of Object.entries(vectors.pdas.token_pair)) assert.equal(tokenPair(Number(domain), pair.remote_token).toBase58(), pair.address);
    assert.equal(usedNonce(vectors.pdas.used_nonce.nonce).toBase58(), vectors.pdas.used_nonce.address);
    assert.equal(denylistAccount(vectors.pdas.denylist_account.owner).toBase58(), vectors.pdas.denylist_account.address);
});

test('forward hooks match Circle Forwarding Service bytes', () => {
    // developers.circle.com/cctp/concepts/forwarding-service: static v0 hook.
    assert.equal(hex(encodeForwardHook()), '0x636374702d666f72776172640000000000000000000000000000000000000000');
    const owner = new PublicKey(vectors.forward_hook.create_ata_owner);
    const ata = encodeForwardHook({ createAtaOwner: owner });
    assert.equal(ata.length, 65);
    assert.equal(bytesToHex(ata.subarray(24, 32)), '0000000000000021');
    assert.equal(ata[32], 1);
    assert.deepEqual(ata.subarray(33), owner.toBytes());
    assert.equal(hex(ata), vectors.forward_hook.create_ata);
    assert.deepEqual(decodeHook(encodeForwardHook()), { forward: { version: 0, circleData: new Uint8Array(0), createAta: false, ataOwner: null }, intent: null, developerData: new Uint8Array(0) });
});

test('real mainnet receive_message decodes and rebuilds byte-identically', () => {
    const real = vectors.mainnet.receive_message;
    const message = decodeMessageV2(real.message);
    assert.equal(message.version, 1);
    assert.equal(message.sourceDomain, CCTP_DOMAINS.arbitrum);
    assert.equal(message.destinationDomain, SOLANA_DOMAIN);
    assert.equal(bytesToHex(message.nonce), '015070c5badcafc24257c4a18104e53f514913b7bfdfb5220e2005e78b32ea86');
    assert.deepEqual(message.sender, evmBytes32('0x28b5a0e9C621a5BadaA536219b3a228C8168cf5d'));
    assert.deepEqual(message.recipient, new PublicKey(TOKEN_MESSENGER_MINTER_V2).toBytes());
    assert.equal(message.minFinalityThreshold, 1000);
    assert.equal(message.finalityThresholdExecuted, 1000);
    assert.deepEqual(message.body.burnToken, evmBytes32(EVM_CCTP.arbitrum.usdc));
    assert.equal(message.body.amount, 50_000_000n);
    assert.equal(message.body.maxFee, 163_654n);
    assert.equal(message.body.feeExecuted, 7_000n);
    assert.equal(message.body.expirationBlock, 467_095_581n);
    const hook = decodeHook(message.body.hookData);
    assert.equal(hook.forward.createAta, true);
    assert.equal(hook.forward.ataOwner.toBase58(), real.accounts[0]);
    assert.equal(hook.intent, null);
    assert.equal(hex(encodeMessageV2(message)), real.message);

    const ix = receiveMessageInstruction({ payer: real.accounts[0], message: real.message, attestation: real.attestation });
    assert.equal(ix.programId.toBase58(), MESSAGE_TRANSMITTER_V2);
    assert.equal(hex(ix.data), real.data);
    assert.deepEqual(ix.keys.map(k => k.pubkey.toBase58()), real.accounts);

    // The attestation recovers Circle's two enabled attesters, ascending.
    const digest = messageHash(real.message);
    const signatures = hexToBytes(real.attestation.slice(2));
    const signers = [0, 1].map(i => {
        const sig = signatures.subarray(65 * i, 65 * i + 65);
        const point = secp256k1.Signature.fromCompact(sig.subarray(0, 64)).addRecoveryBit(sig[64] - 27).recoverPublicKey(digest);
        return `0x${bytesToHex(keccak_256(point.toRawBytes(false).subarray(1)).subarray(12))}`;
    });
    assert.deepEqual([...signers].sort(), [...vectors.mainnet.attesters].sort());
    assert.ok(signers[0] < signers[1]);
});

test('real mainnet deposit_for_burn_with_hook rebuilds byte-identically', () => {
    const real = vectors.mainnet.deposit_for_burn_with_hook;
    const data = hexToBytes(real.data.slice(2));
    const view = new DataView(data.buffer);
    const hookLength = view.getUint32(96, true);
    const ix = depositForBurnInstruction({
        owner: real.accounts[0], eventRentPayer: real.accounts[1], burnTokenAccount: real.accounts[3], messageSentEventData: real.accounts[11],
        amount: view.getBigUint64(8, true), destinationDomain: view.getUint32(16, true), mintRecipient: data.slice(20, 52),
        destinationCaller: data.slice(52, 84), maxFee: view.getBigUint64(84, true), minFinalityThreshold: view.getUint32(92, true),
        hookData: data.slice(100, 100 + hookLength)
    });
    assert.equal(hex(ix.data), real.data);
    assert.deepEqual(ix.keys.map(k => k.pubkey.toBase58()), real.accounts);
    assert.deepEqual(ix.keys.map(k => [k.isSigner, k.isWritable]).slice(0, 4), [[true, false], [true, true], [false, false], [false, true]]);
});

test('emergency key is HKDF-SHA256 of the 32-byte big-endian secret', () => {
    const v = vectors.emergency_key;
    const secret = BigInt(v.secret);
    const ek = deriveEmergencyKey(secret);
    const expected = new Uint8Array(hkdfSync('sha256', hexToBytes(secret.toString(16).padStart(64, '0')), new Uint8Array(0), 'dagon-zkapi/cctp-ek/v1', 32));
    assert.deepEqual(ek.seed, expected);
    assert.equal(hex(ek.seed), v.seed);
    assert.equal(ek.publicKey.toBase58(), v.public_key);
    assert.ok(ek.keypair.publicKey.equals(Keypair.fromSeed(expected).publicKey));
    assert.equal(deriveEmergencyKey(hexToBytes(secret.toString(16).padStart(64, '0'))).publicKey.toBase58(), v.public_key);
    assert.throws(() => deriveEmergencyKey(0n), /nonzero/);
    assert.throws(() => deriveEmergencyKey(new Uint8Array(31)), /32 bytes/);
});

test('inbound intent borsh, id and hook round trip', () => {
    const v = vectors.inbound_intent;
    const intent = intentFrom(v.input);
    const encoded = encodeInboundIntent(intent);
    assert.equal(hex(encoded), v.borsh);
    assert.equal(encoded.length, 1 + 32 + 32 + 8 + 32 + 8 + 8 + (4 + 32 + 32 + 8 + 4 + 4 + 32));
    const decoded = decodeInboundIntent(encoded);
    assert.equal(decoded.emergencyOwner.toBase58(), v.input.emergencyOwner);
    assert.equal(decoded.refundAfter, 1_794_345_600n);
    assert.equal(decoded.refund.domain, 6);
    assert.equal(hex(encodeInboundIntent(decoded)), v.borsh);
    assert.throws(() => decodeInboundIntent(Uint8Array.from([...encoded, 0])), /trailing/);
    assert.throws(() => decodeInboundIntent(encoded.subarray(0, 50)), /truncated/);

    const domain = new TextEncoder().encode('dagon-zkapi/cctp-intent/v1');
    const id = keccak_256(Uint8Array.from([...domain, ...new PublicKey(v.forwarder_id).toBytes(), ...encoded]));
    assert.deepEqual(intentId(intent, v.forwarder_id), id);
    assert.equal(hex(id), v.intent_id);

    const hook = encodeInboundHook({ ataOwner: intent.emergencyOwner, intent });
    assert.equal(hex(hook), v.inbound_hook);
    assert.equal(new TextDecoder().decode(hook.subarray(65, 73)), 'DGNZK-IN');
    assert.equal(new DataView(hook.buffer, hook.byteOffset).getUint16(73, true), encoded.length);
    const parsed = decodeHook(hook);
    assert.equal(parsed.forward.ataOwner.toBase58(), v.input.emergencyOwner);
    assert.equal(hex(encodeInboundIntent(parsed.intent)), v.borsh);
    assert.throws(() => decodeHook(hook.subarray(0, hook.length - 1)), /truncated/);
    // Node Buffers from the shared pool (nonzero byteOffset, aliasing slice()).
    const pooled = Buffer.concat([Buffer.from([0xee]), Buffer.from(hook)]).subarray(1);
    assert.notEqual(pooled.byteOffset, 0);
    assert.equal(hex(encodeInboundIntent(decodeHook(pooled).intent)), v.borsh);
    assert.equal(hex(encodeInboundIntent(decodeInboundIntent(Buffer.from(encoded)))), v.borsh);
});

test('CctpTarget and intent validation', () => {
    const target = intentFrom(vectors.inbound_intent.input).refund;
    assert.equal(encodeCctpTarget(target).length, 4 + 32 + 32 + 8 + 4 + 4 + 32);
    assert.throws(() => encodeCctpTarget({ ...target, domain: 5 }), /Solana/);
    assert.throws(() => encodeCctpTarget({ ...target, minFinality: 1500 }), /1000 or 2000/);
    assert.throws(() => encodeCctpTarget({ ...target, recipient: new Uint8Array(32) }), /nonzero/);
    assert.throws(() => encodeCctpTarget({ ...target, hookData: new Uint8Array(97) }), /96/);
    assert.throws(() => encodeInboundIntent({ ...intentFrom(vectors.inbound_intent.input), version: 2 }), /version 1/);
    assert.throws(() => encodeInboundIntent({ ...intentFrom(vectors.inbound_intent.input), commitment: new Uint8Array(32) }), /nonzero/);
});

test('message V2 codec and hash', () => {
    const v = vectors.message;
    const bytes = encodeMessageV2(messageFrom(v.input));
    assert.equal(hex(bytes), v.bytes);
    assert.equal(bytes.length, 148 + 228 + hexToBytes(v.input.body.hookData.slice(2)).length);
    assert.equal(hex(messageHash(bytes)), v.hash);
    const decoded = decodeMessageV2(bytes);
    assert.equal(decoded.body.feeExecuted, 249_000n);
    assert.equal(hex(encodeMessageV2(decoded)), v.bytes);
    assert.throws(() => decodeMessageV2(bytes.subarray(0, 375)), /too short/);
    const pooled = Buffer.concat([Buffer.from([0xee]), Buffer.from(bytes)]).subarray(1);
    assert.equal(hex(encodeMessageV2(decodeMessageV2(pooled))), v.bytes);
});

test('MessageSent event account decode', () => {
    const message = hexToBytes(vectors.message.bytes.slice(2));
    const payer = new PublicKey(vectors.receive_message.payer);
    const data = new Uint8Array(8 + 32 + 8 + 4 + message.length);
    data.set([131, 100, 133, 56, 166, 225, 151, 60]);
    data.set(payer.toBytes(), 8);
    new DataView(data.buffer).setBigInt64(40, 1_794_000_000n, true);
    new DataView(data.buffer).setUint32(48, message.length, true);
    data.set(message, 52);
    const event = decodeMessageSentEvent(data);
    assert.ok(event.rentPayer.equals(payer));
    assert.equal(event.createdAt, 1_794_000_000n);
    assert.deepEqual(event.message, message);
    assert.throws(() => decodeMessageSentEvent(data.subarray(1)), /MessageSent/);
});

test('Solana instruction golden vectors', () => {
    const recv = receiveMessageInstruction({ payer: vectors.receive_message.payer, message: vectors.message.bytes, attestation: vectors.receive_message.attestation });
    assert.equal(hex(recv.data), vectors.receive_message.data);
    assert.deepEqual(keysOf(recv), vectors.receive_message.keys);
    assert.equal(recv.keys.length, 20);

    const burnInput = vectors.deposit_for_burn.input;
    const burn = depositForBurnInstruction(burnInput);
    assert.equal(hex(burn.data), vectors.deposit_for_burn.data);
    assert.equal(burn.data.length, 96);
    assert.deepEqual(keysOf(burn), vectors.deposit_for_burn.keys);
    const withHook = depositForBurnInstruction(vectors.deposit_for_burn_with_hook.input);
    assert.equal(hex(withHook.data), vectors.deposit_for_burn_with_hook.data);
    assert.deepEqual(keysOf(withHook), vectors.deposit_for_burn_with_hook.keys);
    assert.equal(withHook.keys.length, 18);

    const reclaim = reclaimEventAccountInstruction(vectors.reclaim_event_account.input);
    assert.equal(hex(reclaim.data), vectors.reclaim_event_account.data);
    assert.deepEqual(keysOf(reclaim), vectors.reclaim_event_account.keys);

    assert.throws(() => depositForBurnInstruction({ ...burnInput, maxFee: burnInput.amount }), /exceed/);
    assert.throws(() => depositForBurnInstruction({ ...burnInput, destinationDomain: 5 }), /Solana/);
    assert.throws(() => receiveMessageInstruction({ payer: vectors.receive_message.payer, message: vectors.message.bytes,
        attestation: vectors.receive_message.attestation, recipientTokenAccount: vectors.receive_message.payer }), /mint recipient/);
});

test('EVM calldata', () => {
    const v = vectors.evm;
    assert.equal(evmApproveCalldata(v.approve.spender, BigInt(v.approve.amount)), v.approve.calldata);
    assert.ok(v.approve.calldata.startsWith('0x095ea7b3'));
    const input = v.deposit_for_burn_with_hook.input;
    const calldata = evmDepositForBurnWithHookCalldata(input);
    assert.equal(calldata, v.deposit_for_burn_with_hook.calldata);
    assert.ok(calldata.startsWith('0x779b432d'));
    const body = hexToBytes(calldata.slice(10));
    const word = i => BigInt(`0x${bytesToHex(body.subarray(32 * i, 32 * i + 32))}`);
    assert.equal(word(0), 25_000_000n);
    assert.equal(word(1), 5n);
    assert.equal(word(7), 256n);
    const hook = hexToBytes(input.hookData.slice(2));
    assert.equal(word(8), BigInt(hook.length));
    assert.deepEqual(body.subarray(288, 288 + hook.length), hook);
    assert.equal(body.length, 288 + Math.ceil(hook.length / 32) * 32);
    const receive = evmReceiveMessageCalldata(v.receive_message.message, v.receive_message.attestation);
    assert.equal(receive, v.receive_message.calldata);
    assert.ok(receive.startsWith('0x57ecfd28'));
    assert.throws(() => evmDepositForBurnWithHookCalldata({ ...input, hookData: '0x' }), /hook/);
    assert.throws(() => evmBytes32('0x1234'), /20-byte/);
});

test('Iris client paths, 404 and fee query', async () => {
    const calls = [];
    const fetchImpl = async (url, init) => {
        calls.push([url, init?.method ?? 'GET']);
        if (url.includes('/v2/messages/6?transactionHash=0xmissing')) return new Response('{"error":"Message not found for provided parameters"}', { status: 404 });
        if (url.includes('/v2/messages/')) return Response.json({ messages: [{ status: 'complete' }] });
        if (url.includes('/fees/')) return Response.json([{ finalityThreshold: 1000, minimumFee: 1.3, forwardFee: { low: 1, med: 2, high: 3 } }]);
        if (url.includes('/reattest/')) return Response.json({ message: 'Re-attestation successfully requested for nonce.' });
        if (url.endsWith('/v2/publicKeys')) return Response.json({ publicKeys: [] });
        return new Response('boom', { status: 500 });
    };
    const iris = irisClient('http://iris.test/', fetchImpl);
    assert.deepEqual(await iris.messages(6, '0xmissing'), { messages: [] });
    assert.deepEqual(await iris.messages(6, '0xabc'), { messages: [{ status: 'complete' }] });
    assert.equal((await iris.fees(6, 5, { forward: true, includeRecipientSetup: true }))[0].forwardFee.med, 2);
    await iris.fees(5, 6);
    await iris.reattest(`0x${'42'.repeat(32)}`);
    await iris.publicKeys();
    assert.deepEqual(calls, [
        ['http://iris.test/v2/messages/6?transactionHash=0xmissing', 'GET'],
        ['http://iris.test/v2/messages/6?transactionHash=0xabc', 'GET'],
        ['http://iris.test/v2/burn/USDC/fees/6/5?forward=true&includeRecipientSetup=true', 'GET'],
        ['http://iris.test/v2/burn/USDC/fees/5/6', 'GET'],
        [`http://iris.test/v2/reattest/0x${'42'.repeat(32)}`, 'POST'],
        ['http://iris.test/v2/publicKeys', 'GET']
    ]);
    await assert.rejects(irisClient('http://iris.test', async () => new Response('x', { status: 429 })).publicKeys(), error => error.status === 429);
});
