// Test-only: the full local CCTP stack for end-to-end tests (Linux/WSL).
// `stack.mjs --cctp` (verified immutable vault, cloned USDC/Token/ATA,
// Circle CCTP V2 with local attesters, parity) + Base anvil fork with the
// test attesters + iris-sim + forwarding-sim (in process, as
// `harness.mjs --attach-solana` runs them) + dagon-zkapi-indexerd +
// dagon-zkapi serverd with the relay (docs/SOLANA_SERVER.md "Running the
// relay against a localnet"). The relayer and its fee account are fresh
// keys; the fee account is a dedicated USDC ATA so fee receipts are exact.
import { spawn } from 'node:child_process';
import { createWriteStream } from 'node:fs';
import { readFile, writeFile } from 'node:fs/promises';
import net from 'node:net';
import { join, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { Connection, Keypair, PublicKey, Transaction, TransactionInstruction } from '@solana/web3.js';
import { EVM_CCTP } from '../../../sdk/services/zkapiCctp.mjs';
import { createUsdcAccountIdempotentInstruction, usdcAssociatedTokenAddress } from '../../../sdk/services/zkapiUsdc.mjs';
import { startLocalStack } from '../stack.mjs';
import { readTestAttesters } from './validator.mjs';
import { startIrisSim } from './iris-sim.mjs';
import { startForwardingSim } from './forwarding-sim.mjs';
import { startAnvilFork } from './anvil.mjs';
import { confirmSignature } from './solana-tx.mjs';

export const STATE_SEED = '0x1';
export const CLEAR_SEED = '0x2';
/** The relay's SOL price (DAGON_E2E_SOL_USD overrides) and margin; quotes must fit the SDK fee caps. */
export const RELAYER_SOL_USD = process.env.DAGON_E2E_SOL_USD ?? '150';
export const RELAYER_MARGIN_BPS = 2000;

export async function freePort() {
    const server = net.createServer();
    await new Promise((done, fail) => { server.once('error', fail); server.listen(0, '127.0.0.1', done); });
    const { port } = server.address();
    await new Promise(done => server.close(done));
    return port;
}

async function json(url, init) {
    const response = await fetch(url, { ...init, signal: AbortSignal.timeout(30_000) });
    const text = await response.text();
    let body = null;
    try { body = text ? JSON.parse(text) : null; } catch { body = { raw: text }; }
    return { status: response.status, body };
}

export async function waitFor(label, fn, timeoutMs = 60_000) {
    const deadline = Date.now() + timeoutMs;
    let last;
    while (Date.now() < deadline) {
        try { const value = await fn(); if (value) return value; } catch (error) { last = error; }
        await delay(250);
    }
    throw new Error(`Timeout: ${label}${last ? ` (${last.message})` : ''}`);
}

const loadKeypair = async path => Keypair.fromSecretKey(Uint8Array.from(JSON.parse(await readFile(path, 'utf8'))));

/** Sends a legacy transaction (fee payer = signers[0]) and waits for confirmation. */
export async function sendLegacy(connection, instructions, signers) {
    const { blockhash, lastValidBlockHeight } = await connection.getLatestBlockhash('confirmed');
    const transaction = new Transaction({ feePayer: signers[0].publicKey, blockhash, lastValidBlockHeight }).add(...instructions);
    transaction.sign(...signers);
    return confirmSignature(connection, await connection.sendRawTransaction(transaction.serialize(), { preflightCommitment: 'confirmed' }));
}

/**
 * `cctp`: {variant, denylist} for stack.mjs. `openrouterApiBase` /
 * `openrouterManagementKey`: the lease provider (the gateway); a dead
 * loopback base when leases are not exercised.
 */
export async function startCctpE2eStack({ root, runDir, binDir = join(root, 'target/release'), rpcPort = 18899, anvilPort = 18545,
    cctp = { variant: 'normal', denylist: [] }, openrouterApiBase = 'http://127.0.0.1:9/api', openrouterManagementKey = 'unused-e2e-key',
    serverEnv = {}, log = () => {} }) {
    root = resolve(root);
    process.env.ZKAPI_STATE_SEED = STATE_SEED;
    process.env.ZKAPI_CLEAR_SEED = CLEAR_SEED;
    const stops = [];
    const children = new Set();
    const stopAll = async () => {
        for (const stop of stops.reverse()) { try { await stop(); } catch (error) { log(`stop: ${error.message}`); } }
    };
    try {
        const stack = await startLocalStack({ root, runDir: join(runDir, 'stack'), binDir, rpcPort, cctp, log });
        stops.push(stack.stop);
        const connection = new Connection(stack.rpcUrl, 'confirmed');
        const payer = await loadKeypair(stack.payerKeypairPath);
        const faucet = await loadKeypair(stack.usdcFaucetKeypairPath);
        const authority = await loadKeypair(stack.authorityKeypairPath);
        const { attesters, threshold } = await readTestAttesters(stack.cctp.attestersPath);

        const anvil = await startAnvilFork({ port: anvilPort, logPath: join(runDir, 'anvil.log'), log });
        stops.push(anvil.stop);
        await anvil.enableAttesters(attesters.map(attester => attester.address));
        const base = EVM_CCTP.base.domain;
        const iris = await startIrisSim({ attesters, threshold, solanaRpcUrl: stack.rpcUrl, evmRpcUrls: { [base]: anvil.rpcUrl }, log });
        stops.push(iris.close);
        const forwarder = startForwardingSim({ irisUrl: iris.url, solanaRpcUrl: stack.rpcUrl, payer,
            feeRecipientTokenAccount: stack.cctp.feeRecipientTokenAccount,
            evm: { [base]: { rpcUrl: anvil.rpcUrl, from: await anvil.newUser() } }, log });
        stops.push(forwarder.stop);

        // Relayer: dedicated low-balance key; fee account: a fresh owner's USDC ATA (stands in for the Zoneless relayer's).
        const relayer = Keypair.generate();
        const relayerKeyPath = join(runDir, 'relayer.json');
        await writeFile(relayerKeyPath, JSON.stringify(Array.from(relayer.secretKey)), { mode: 0o600 });
        await confirmSignature(connection, await connection.requestAirdrop(relayer.publicKey, 5_000_000_000));
        const feeOwner = Keypair.generate();
        const feeAccount = usdcAssociatedTokenAddress(feeOwner.publicKey.toBase58());
        await sendLegacy(connection, [toWeb3(createUsdcAccountIdempotentInstruction({ payer: payer.publicKey.toBase58(),
            owner: feeOwner.publicKey.toBase58() }))], [payer]);

        const indexerUrl = `http://127.0.0.1:${await freePort()}`;
        const launch = (name, args, env = {}) => {
            const out = createWriteStream(join(runDir, `${name}.log`), { flags: 'a' });
            const child = spawn(args[0], args.slice(1), { cwd: root, stdio: ['ignore', 'pipe', 'pipe'],
                env: { PATH: process.env.PATH, HOME: process.env.HOME, RUST_LOG: 'warn,zkapi=info,zkapi_serverd=info,zkapi_indexerd=info', ...env } });
            child.stdout.pipe(out);
            child.stderr.pipe(out);
            children.add(child);
            child.once('exit', () => children.delete(child));
            return child;
        };
        const kill = async child => {
            if (!child || child.exitCode !== null || child.signalCode !== null) return;
            const exited = new Promise(done => child.once('exit', done));
            child.kill('SIGINT');
            await Promise.race([exited, delay(5_000)]);
            if (child.exitCode === null && child.signalCode === null) { child.kill('SIGKILL'); await exited; }
        };
        stops.push(async () => { for (const child of [...children]) await kill(child); });
        launch('indexer', [join(binDir, 'dagon-zkapi-indexerd'), '--solana-identity', stack.identityPath, '--rpc-url', stack.rpcUrl,
            '--listen', indexerUrl.slice('http://'.length), '--poll-interval-ms', '200']);

        const relayEnv = { ZKAPI_RELAYER_KEY: relayerKeyPath, ZKAPI_RELAYER_FEE_ACCOUNT: feeAccount,
            ZKAPI_RELAYER_SOL_USD: RELAYER_SOL_USD, ZKAPI_RELAYER_MARGIN_BPS: String(RELAYER_MARGIN_BPS), ZKAPI_CCTP_IRIS_URL: iris.url };
        const serverPort = await freePort();
        const serverUrl = `http://127.0.0.1:${serverPort}`;
        let server = null;
        let serverRuns = 0;
        const readVaultRoot = async () => {
            const info = await connection.getAccountInfo(new PublicKey(stack.identity.vault_state), 'finalized');
            return `0x${Buffer.from(info.data.subarray(212, 244)).toString('hex')}`;
        };
        /** (Re)start serverd on the same port and database; `relay: false` runs it without the relay. */
        async function startServer({ relay = true } = {}) {
            await kill(server);
            serverRuns += 1;
            server = launch(`server-${serverRuns}`, [join(binDir, 'dagon-zkapi'), '--proof-setup-dir', join(root, 'protocol/setup/v2'), 'serverd',
                '--solana-identity', stack.identityPath, '--solana-rpc-url', stack.rpcUrl, '--listen', `127.0.0.1:${serverPort}`,
                '--indexer-url', indexerUrl, '--root-poll-interval-ms', '200', '--db-path', join(runDir, 'server.db'),
                '--state-seed', STATE_SEED, '--clear-seed', CLEAR_SEED,
                '--openrouter-api-base', openrouterApiBase, '--openrouter-management-key', openrouterManagementKey],
            { ...(relay ? relayEnv : {}), ...serverEnv });
            const child = server;
            await waitFor('zkAPI server at the finalized vault root', async () => {
                if (child.exitCode !== null) throw new Error(`serverd exited ${child.exitCode} (see server-${serverRuns}.log)`);
                const health = await json(`${serverUrl}/health`);
                return health.status === 200 && BigInt(health.body.current_root) === BigInt(await readVaultRoot());
            }, 120_000);
            if (relay) await waitFor('relay info', async () => (await json(`${serverUrl}/v2/relay`)).status === 200, 30_000);
        }
        async function stopServer() { await kill(server); server = null; }
        await waitFor('indexer snapshot', async () => (await json(`${indexerUrl}/v1/tree/snapshot`)).status === 200, 60_000);
        await startServer();
        const attestation = (await json(`${serverUrl}/v1/attestation`)).body;

        return {
            root, runDir, stack, connection, payer, faucet, authority, anvil, iris, forwarder, relayer, feeOwner, feeAccount,
            indexerUrl, serverUrl, attestation, startServer, stopServer, json,
            deployment: { protocol_server_url: serverUrl, indexer_url: indexerUrl, rpc_url: stack.rpcUrl,
                state_signing_key: attestation.state_signing_key, clearance_signing_key: attestation.clearance_signing_key },
            stop: stopAll
        };
    } catch (error) {
        await stopAll();
        throw error;
    }
}

export function toWeb3(plain) {
    return new TransactionInstruction({ programId: new PublicKey(plain.programId),
        keys: plain.keys.map(key => ({ pubkey: new PublicKey(key.pubkey), isSigner: key.isSigner, isWritable: key.isWritable })),
        data: Buffer.from(plain.data) });
}
