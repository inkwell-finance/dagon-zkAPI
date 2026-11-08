// Opt-in CCTP golden test (Linux/WSL): real Circle V2 programs and mainnet
// state on a local validator, real Base contracts on an anvil fork, iris-sim
// as attester and forwarding-sim as Circle's Forwarding Service.
//   DAGON_CCTP_GOLDEN=1 node --test scripts/localnet/cctp/golden.test.mjs
// Env: CCTP_RPC_PORT (18899), CCTP_ANVIL_PORT (18545), MAINNET_RPC_URL, BASE_RPC_URL,
// DAGON_SOLANA_TEST_VALIDATOR, ANVIL, DAGON_CCTP_KEEP=1 keeps the run directory.
import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { Connection, Keypair, PublicKey } from '@solana/web3.js';
import {
    EVM_CCTP, SOLANA_DOMAIN, cctpAccounts, decodeHook, decodeMessageSentEvent, decodeMessageV2, depositForBurnInstruction, deriveEmergencyKey,
    encodeForwardHook, encodeInboundHook, evmApproveCalldata, evmBytes32, evmDepositForBurnWithHookCalldata, evmReceiveMessageCalldata,
    irisClient, receiveMessageInstruction, usedNonce
} from '../../../sdk/services/zkapiCctp.mjs';
import { createUsdcAccountIdempotentInstruction, usdcAssociatedTokenAddress } from '../../../sdk/services/zkapiUsdc.mjs';
import { readTestAttesters, startCctpLocalnet } from './validator.mjs';
import { startIrisSim } from './iris-sim.mjs';
import { startForwardingSim } from './forwarding-sim.mjs';
import { startAnvilFork } from './anvil.mjs';
import { createCctpLookupTable, sendV0, simulateV0 } from './solana-tx.mjs';

const RUN = process.env.DAGON_CCTP_GOLDEN === '1';
const SKIP = !RUN && 'set DAGON_CCTP_GOLDEN=1 (Linux/WSL; needs solana-test-validator, anvil, mainnet Solana + Base RPC)';
const RPC_PORT = Number(process.env.CCTP_RPC_PORT ?? 18899);
const ANVIL_PORT = Number(process.env.CCTP_ANVIL_PORT ?? 18545);
const base = EVM_CCTP.base;
const hex = bytes => `0x${Buffer.from(bytes).toString('hex')}`;

function intentFor(ek, refundRecipient) {
    return {
        version: 1, commitment: randomBytes(32), emergencyOwner: ek.publicKey, maxRelayerFee: 250_000n, priorityRelayer: PublicKey.default,
        priorityUntil: 0n, refundAfter: BigInt(Math.floor(Date.now() / 1000) + 72 * 3600),
        refund: { domain: base.domain, recipient: evmBytes32(refundRecipient), destinationCaller: new Uint8Array(32), maxCctpFee: 60_000n,
            minFinality: 2000, hookData: encodeForwardHook() }
    };
}

async function tokenBalance(connection, address) {
    const info = await connection.getAccountInfo(new PublicKey(address), 'confirmed');
    return info ? Buffer.from(info.data).readBigUInt64LE(64) : null;
}

const ataOf = owner => usdcAssociatedTokenAddress(new PublicKey(owner).toBase58());
const createAta = (payer, owner) => createUsdcAccountIdempotentInstruction({ payer: payer.publicKey.toBase58(), owner: new PublicKey(owner).toBase58() });

async function cleanupAll(steps) {
    for (const step of steps.reverse()) {
        try { await step(); } catch (error) { console.error(error); }
    }
}

test('CCTP golden: Solana localnet (real Circle V2) <-> Base anvil fork', { skip: SKIP, timeout: 20 * 60_000 }, async t => {
    const runDir = await mkdtemp(join(tmpdir(), 'dagon-cctp-golden-'));
    const cleanup = [async () => { if (process.env.DAGON_CCTP_KEEP !== '1') await rm(runDir, { recursive: true, force: true }); }];
    t.after(() => cleanupAll(cleanup));
    const log = message => t.diagnostic(message);

    const localnet = await startCctpLocalnet({ runDir: join(runDir, 'solana'), rpcPort: RPC_PORT, log });
    cleanup.push(localnet.stop);
    const anvil = await startAnvilFork({ port: ANVIL_PORT, logPath: join(runDir, 'anvil.log'), log });
    cleanup.push(anvil.stop);
    const { attesters, threshold } = await readTestAttesters(localnet.cctp.attestersPath);
    assert.equal(threshold, 2);
    assert.deepEqual(attesters.map(a => a.address), [...attesters.map(a => a.address)].sort());
    assert.equal(await anvil.enableAttesters(attesters.map(a => a.address)), 2n);
    const iris = await startIrisSim({ attesters, threshold, solanaRpcUrl: localnet.rpcUrl, evmRpcUrls: { [base.domain]: anvil.rpcUrl }, log });
    cleanup.push(iris.close);
    const connection = new Connection(localnet.rpcUrl, 'confirmed');
    const payer = localnet.payer;
    const feeRecipient = localnet.cctp.feeRecipientTokenAccount;
    assert.equal(feeRecipient, cctpAccounts().feeRecipientTokenAccount.toBase58());
    // A receive_message (20 accounts + message + attestation) only fits a v0 transaction over a lookup table.
    const table = await createCctpLookupTable(connection, payer, { feeRecipientTokenAccount: feeRecipient });
    const tables = [table];
    const evmForwarder = await anvil.newUser();
    const forwarder = startForwardingSim({ irisUrl: iris.url, solanaRpcUrl: localnet.rpcUrl, payer, feeRecipientTokenAccount: feeRecipient,
        lookupTable: table, evm: { [base.domain]: { rpcUrl: anvil.rpcUrl, from: evmForwarder } }, log });
    cleanup.push(forwarder.stop);
    const client = irisClient(iris.url);

    const ek = deriveEmergencyKey(randomBytes(32));
    const ekAta = ataOf(ek.publicKey);
    let ekBalance = 0n;
    const waitQueued = async nonce => {
        for (let i = 0; i < 100 && !forwarder.pending().includes(nonce); i++) await new Promise(done => setTimeout(done, 100));
        assert.ok(forwarder.pending().includes(nonce), `forwarding-sim queued ${nonce} during the outage`);
    };

    await t.test('synthesized Base burn -> real receive_message into a fresh ATA (self-receive)', async st => {
        forwarder.pause();
        st.after(() => forwarder.resume());
        const intent = intentFor(ek, `0x${'ab'.repeat(20)}`);
        const amount = 25_000_000n;
        const burn = iris.synthesizeBurn({ sourceDomain: base.domain, mintRecipient: new PublicKey(ekAta).toBytes(), amount, maxFee: 400_000n,
            minFinalityThreshold: 1000, hookData: encodeInboundHook({ ataOwner: ek.publicKey, intent }) });
        const { messages: [entry] } = await client.messages(base.domain, burn.transactionHash);
        assert.equal(entry.status, 'complete');
        const message = decodeMessageV2(entry.message);
        const fee = amount * 13n / 100_000n + 246_000n; // 1.3 bp Fast + forward fee with ATA setup
        assert.equal(message.finalityThresholdExecuted, 1000);
        assert.equal(message.body.feeExecuted, fee);
        assert.ok(message.body.expirationBlock > BigInt(await connection.getSlot('confirmed')));
        assert.equal(hex(decodeHook(message.body.hookData).intent.commitment), hex(intent.commitment));
        assert.equal(await tokenBalance(connection, ekAta), null);
        const feeBefore = await tokenBalance(connection, feeRecipient);

        await sendV0(connection, [createAta(payer, ek.publicKey),
            receiveMessageInstruction({ payer: payer.publicKey, message: entry.message, attestation: entry.attestation })], [payer], tables);
        ekBalance = amount - fee;
        assert.equal(await tokenBalance(connection, ekAta), ekBalance);
        assert.equal(await tokenBalance(connection, feeRecipient), feeBefore + fee);
        assert.ok(await connection.getAccountInfo(usedNonce(message.nonce), 'confirmed'));
        const replay = await simulateV0(connection, [receiveMessageInstruction({ payer: payer.publicKey, message: entry.message, attestation: entry.attestation })], [payer], tables);
        assert.ok(replay.err, 'a used nonce cannot be received twice');

        const reattest = await client.reattest(message.nonce);
        assert.match(reattest.message, /Re-attestation/);

        // The outage queued the message; after resume the forwarder sees the fallback consumed the nonce and skips it.
        await waitQueued(entry.eventNonce);
        forwarder.resume();
        assert.deepEqual(await forwarder.waitFor(entry.eventNonce), { nonce: entry.eventNonce, destinationDomain: SOLANA_DOMAIN, skipped: 'nonce already used' });
        assert.equal(await tokenBalance(connection, ekAta), ekBalance);
    });

    await t.test('forwarding-sim forwards a synthesized Arbitrum Standard burn (ATA creation for the declared owner)', async () => {
        const owner = Keypair.generate().publicKey;
        const ata = ataOf(owner);
        const amount = 5_000_000n;
        const burn = iris.synthesizeBurn({ sourceDomain: 3, mintRecipient: new PublicKey(ata).toBytes(), amount, maxFee: 300_000n,
            minFinalityThreshold: 2000, hookData: encodeForwardHook({ createAtaOwner: owner }) });
        const { messages: [entry] } = await client.messages(3, burn.transactionHash);
        const message = decodeMessageV2(entry.message);
        assert.equal(message.finalityThresholdExecuted, 2000);
        assert.equal(message.body.expirationBlock, 0n);
        assert.equal(message.body.feeExecuted, 246_000n);
        const result = await forwarder.waitFor(entry.eventNonce);
        assert.equal(result.error, undefined, result.error);
        assert.equal(await tokenBalance(connection, ata), amount - 246_000n);
        assert.equal((await client.messages(3, burn.transactionHash)).messages[0].forwardState, 'COMPLETE');
    });

    await t.test('a message attested during a forwarding outage is forwarded after resume', async st => {
        forwarder.pause();
        st.after(() => forwarder.resume());
        const owner = Keypair.generate().publicKey;
        const ata = ataOf(owner);
        const amount = 4_000_000n;
        const burn = iris.synthesizeBurn({ sourceDomain: 2, mintRecipient: new PublicKey(ata).toBytes(), amount, maxFee: 300_000n,
            minFinalityThreshold: 2000, hookData: encodeForwardHook({ createAtaOwner: owner }) });
        const { messages: [entry] } = await client.messages(2, burn.transactionHash);
        assert.equal(entry.forwardState, 'PENDING');
        await waitQueued(entry.eventNonce);
        assert.equal(await tokenBalance(connection, ata), null, 'nothing is forwarded during the outage');
        assert.equal(forwarder.results.find(result => result.nonce === entry.eventNonce), undefined);
        forwarder.resume();
        const result = await forwarder.waitFor(entry.eventNonce);
        assert.equal(result.error, undefined, result.error);
        assert.ok(result.txHash);
        assert.equal(await tokenBalance(connection, ata), amount - 246_000n);
        assert.equal((await client.messages(2, burn.transactionHash)).messages[0].forwardState, 'COMPLETE');
        assert.deepEqual(forwarder.pending(), []);
    });

    await t.test('real deposit_for_burn_with_hook from a Solana key -> iris-sim -> forwarded receiveMessage mints on Base', async () => {
        const recipient = `0x${randomBytes(20).toString('hex')}`;
        const event = Keypair.generate();
        const amount = 10_000_000n;
        const signature = await sendV0(connection, [depositForBurnInstruction({ owner: ek.publicKey, eventRentPayer: payer.publicKey,
            messageSentEventData: event.publicKey, amount, destinationDomain: base.domain, mintRecipient: evmBytes32(recipient),
            maxFee: 100_000n, minFinalityThreshold: 1000, hookData: encodeForwardHook() })], [payer, ek.keypair, event]);
        ekBalance -= amount;
        assert.equal(await tokenBalance(connection, ekAta), ekBalance);
        const sent = decodeMessageSentEvent((await connection.getAccountInfo(event.publicKey, 'confirmed')).data);
        assert.ok(sent.rentPayer.equals(payer.publicKey));
        const { messages: [entry] } = await client.messages(SOLANA_DOMAIN, signature);
        const message = decodeMessageV2(entry.message);
        assert.equal(message.sourceDomain, SOLANA_DOMAIN);
        assert.deepEqual(message.body.messageSender, ek.publicKey.toBytes());
        assert.equal(message.finalityThresholdExecuted, 1000);
        const fee = amount / 10_000n + 54_000n; // 1 bp Fast + forward fee to EVM
        assert.equal(message.body.feeExecuted, fee);
        const result = await forwarder.waitFor(entry.eventNonce);
        assert.equal(result.error, undefined, result.error);
        assert.equal(await anvil.usdcBalance(recipient), amount - fee);
        assert.ok(await anvil.nonceUsed(message.nonce));
    });

    await t.test('real deposit_for_burn (no hook, Standard) from Solana -> self-claimed receiveMessage on Base via the EIP-1193 shim', async () => {
        const claimer = await anvil.newUser();
        const provider = anvil.provider([claimer]);
        const event = Keypair.generate();
        const amount = 3_000_000n;
        const signature = await sendV0(connection, [depositForBurnInstruction({ owner: ek.publicKey, eventRentPayer: payer.publicKey,
            messageSentEventData: event.publicKey, amount, destinationDomain: base.domain, mintRecipient: evmBytes32(claimer),
            maxFee: 0n, minFinalityThreshold: 2000 })], [payer, ek.keypair, event]);
        ekBalance -= amount;
        const { messages: [entry] } = await client.messages(SOLANA_DOMAIN, signature);
        assert.equal(entry.forwardState, undefined);
        const [from] = await provider.request({ method: 'eth_requestAccounts' });
        const hash = await provider.request({ method: 'eth_sendTransaction', params: [{ from, to: base.messageTransmitter, data: evmReceiveMessageCalldata(entry.message, entry.attestation) }] });
        let receipt = null;
        for (let i = 0; i < 120 && !receipt; i++) receipt = await provider.request({ method: 'eth_getTransactionReceipt', params: [hash] }) ?? await new Promise(done => setTimeout(() => done(null), 250));
        assert.equal(receipt.status, '0x1');
        assert.equal(await anvil.usdcBalance(claimer), amount);
    });

    await t.test('real Base depositForBurnWithHook (minted via masterMinter) -> iris-sim reads the log -> forwarded receive on Solana', async () => {
        const user = await anvil.newUser();
        const provider = anvil.provider([user]);
        const amount = 20_000_000n;
        await anvil.mintUsdc(user, 50_000_000n);
        assert.equal(await anvil.usdcBalance(user), 50_000_000n);
        const ek2 = deriveEmergencyKey(randomBytes(32));
        const ata = ataOf(ek2.publicKey);
        const hookData = encodeInboundHook({ ataOwner: ek2.publicKey, intent: intentFor(ek2, user) });
        const wait = async hash => {
            for (let i = 0; i < 240; i++) {
                const receipt = await provider.request({ method: 'eth_getTransactionReceipt', params: [hash] });
                if (receipt) { assert.equal(receipt.status, '0x1'); return receipt; }
                await new Promise(done => setTimeout(done, 250));
            }
            throw new Error('not mined');
        };
        await wait(await provider.request({ method: 'eth_sendTransaction', params: [{ from: user, to: base.usdc, data: evmApproveCalldata(base.tokenMessenger, amount) }] }));
        const burnHash = await provider.request({ method: 'eth_sendTransaction', params: [{ from: user, to: base.tokenMessenger,
            data: evmDepositForBurnWithHookCalldata({ amount, destinationDomain: SOLANA_DOMAIN, mintRecipient: new PublicKey(ata), burnToken: base.usdc,
                maxFee: 300_000n, minFinalityThreshold: 1000, hookData }) }] });
        await wait(burnHash);
        assert.equal(await anvil.usdcBalance(user), 30_000_000n);
        const { messages: [entry] } = await client.messages(base.domain, burnHash);
        const message = decodeMessageV2(entry.message);
        assert.equal(message.sourceDomain, base.domain);
        assert.deepEqual(message.body.messageSender, evmBytes32(user));
        const fee = amount * 13n / 100_000n + 246_000n;
        assert.equal(message.body.feeExecuted, fee);
        const result = await forwarder.waitFor(entry.eventNonce);
        assert.equal(result.error, undefined, result.error);
        assert.equal(await tokenBalance(connection, ata), amount - fee);
    });
});

test('CCTP golden variants: MT paused + denylist, TokenMinter paused', { skip: SKIP, timeout: 20 * 60_000 }, async t => {
    const runDir = await mkdtemp(join(tmpdir(), 'dagon-cctp-variants-'));
    t.after(() => (process.env.DAGON_CCTP_KEEP === '1' ? undefined : rm(runDir, { recursive: true, force: true })));
    const log = message => t.diagnostic(message);
    for (const variant of ['mt-paused', 'minter-paused']) {
        await t.test(variant, async () => {
            const denied = Keypair.generate();
            const localnet = await startCctpLocalnet({ runDir: join(runDir, variant), rpcPort: RPC_PORT, cctp: { variant, denylist: [denied.publicKey.toBase58()] }, log });
            const steps = [localnet.stop];
            try {
                const { attesters, threshold } = await readTestAttesters(localnet.cctp.attestersPath);
                const iris = await startIrisSim({ attesters, threshold, solanaRpcUrl: localnet.rpcUrl, log });
                steps.push(iris.close);
                const connection = new Connection(localnet.rpcUrl, 'confirmed');
                const payer = localnet.payer;
                const tables = [await createCctpLookupTable(connection, payer, { feeRecipientTokenAccount: localnet.cctp.feeRecipientTokenAccount })];
                const owner = Keypair.generate().publicKey;
                const burn = iris.synthesizeBurn({ sourceDomain: 0, mintRecipient: new PublicKey(ataOf(owner)).toBytes(), amount: 2_000_000n, minFinalityThreshold: 2000 });
                const { messages: [entry] } = await irisClient(iris.url).messages(0, burn.transactionHash);
                await sendV0(connection, [createAta(payer, owner)], [payer]);
                const receive = await simulateV0(connection, [receiveMessageInstruction({ payer: payer.publicKey, message: entry.message, attestation: entry.attestation,
                    feeRecipientTokenAccount: localnet.cctp.feeRecipientTokenAccount })], [payer], tables);
                assert.ok(receive.err, `${variant}: receive must fail`);
                assert.match(receive.logs, /ProgramPaused/);

                await sendV0(connection, [createAta(payer, denied.publicKey)], [payer]);
                const event = Keypair.generate();
                const burnDenied = await simulateV0(connection, [depositForBurnInstruction({ owner: denied.publicKey, eventRentPayer: payer.publicKey,
                    messageSentEventData: event.publicKey, amount: 1n, destinationDomain: base.domain, mintRecipient: evmBytes32(`0x${'cd'.repeat(20)}`),
                    maxFee: 0n, minFinalityThreshold: 2000 })], [payer, denied, event]);
                assert.ok(burnDenied.err, 'a denylisted owner cannot burn');
                assert.match(burnDenied.logs, /DenylistedAccount/);
            } finally {
                await cleanupAll(steps);
            }
        });
    }
});
