#!/usr/bin/env node
// Real-serverd lease scenario on the SOLANA vault against a running vcii server. Solana counterpart of
// scripts/v2-vcii-lease.mjs (EVM). See docs/solana-vcii-lease.md.
//   Real: solana-test-validator, the actual dagon-zkapi-vault SBF program (made immutable with
//         `solana program set-upgrade-authority --final`; the validator's own 'none' stores Some(1111..), which serverd rejects),
//         native-SOL deposit with the Solana Merkle-transition Groth16 proof, Groth16 wallet request proofs,
//         `dagon-zkapi serverd --ledger solana` (immutable-program gate, genesis pin, finalized vault + Pyth reads),
//         its OpenRouterProvisioner talking to vcii /zk/v1/keys, usage settlement.
//   Mock: the Pyth SOL/USD account. A PriceUpdateV2 account (official SDK serialization, Full verification, real feed ID,
//         receiver-program owner) is refreshed continuously (--refresh-ms, default 400 ms like the real feed) by
//         solana/dev/mock-pyth-writer, loaded at the receiver program ID, as a small random walk around $150.00 +/- $0.01
//         that stays inside serverd's quote tolerance. No Wormhole/guardian verification.
//   --scenario jump: the price also jumps 2% down while the first proof is being generated; serverd must answer a retriable
//         409 native_quote_stale and the client re-quotes, re-proves and succeeds.
//   --client clientd --clientd-bin PATH: the CLIENT is zkapi-clientd instead of the Rust helper, end to end: `solana init` (on-chain
//         verification; a wrong program pin and a wrong helper SHA-256 pin are refused), `solana deposit` (SIGKILLed once its signed
//         transactions are journaled, then resumed), `serve`, `lease export --usd 3` + paid MCP calls on vcii with a daemon crash/restart
//         and a pause inside the idle period, automatic settlement when the limit is used up, a second lease (`--usd 2`) settled by the
//         idle period alone (`--idle-seconds`, default 40), and `solana withdraw --all` to a fresh address whose lamports are checked on
//         chain. A small loopback proxy sits between clientd and serverd to count lease POSTs and (jump scenario) hold the first until
//         the finalized feed shows the jump. The helper binary is zkapi-solana-wallet built with `--features dev` (it also creates the vault).
// Needs Linux with Node 24 and Agave (solana-test-validator). Loopback only.
//   VCII_ZK_BASE=http://127.0.0.1:8813/zk VCII_ZK_MANAGEMENT_KEY=... node scripts/solana-vcii-lease.mjs \
//     --bin-dir /target/sol-host/release --sbf-dir /target/sbf --key-dir /scratch --output-dir .zkapi/solana-acceptance
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import fs from 'node:fs/promises';
import { createWriteStream, rmSync } from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const VAULT_PROGRAM_ID = '7NdY5ZVP2He8gSiDHZbkfmNfSgKWV2tkZmZgty2C1d8H'; // declare_id! in solana/programs/dagon-zkapi-vault
const PYTH_RECEIVER = 'rec5EKMGg6MxZYaMdyBfgwp4d5rB9T1VQH5pJv5LtFJ';
const PYTH_SOL_USD_ACCOUNT = '7UVimffxr9ow1uXYxsr4LHAcV58mLzhmwaeKvJ1pjLiE'; // Pyth's sponsored SOL/USD shard-0 address
const LAMPORTS_PER_SOL = 1_000_000_000n;
const DEPOSIT = 1_000_000_000; // 1 SOL
const CAP = 12_000_000; // lamports per request: ~1.80 USD at $150, enough for one 1.5-credit vcii call
const LEASE_TTL_SECONDS = 3600;
const PYTH = { price: 15_000_000_000, conf: 1_000_000, exponent: -8 }; // $150.00 +/- $0.01
const WALK_BPS = 20; // the walk stays within +/-20 bps of its center, so any two prices differ by < 50 bps (serverd tolerance)
const JUMP_BPS = 200; // 'jump' scenario: -2%, far beyond the 50 bps tolerance
const MAX_QUOTE_ATTEMPTS = 4;
const VCII_ZK_BASE = process.env.VCII_ZK_BASE;
const VCII_ZK_MANAGEMENT_KEY = process.env.VCII_ZK_MANAGEMENT_KEY;
const VCII_BASE = process.env.VCII_BASE ?? VCII_ZK_BASE?.replace(/\/zk\/?$/, '');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const json = value => JSON.stringify(value, (_, v) => typeof v === 'bigint' ? v.toString() : v, 2);
const localAgent = new http.Agent({ keepAlive: false, proxyEnv: {} });

function loopback(url) {
    const parsed = new URL(url);
    assert.equal(parsed.protocol, 'http:', 'this test permits only loopback HTTP');
    assert.equal(parsed.hostname, '127.0.0.1', 'this test never calls public networks');
    return parsed;
}

async function localJSON(url, { method = 'GET', value, headers = {} } = {}) {
    const parsed = loopback(url);
    return new Promise((resolve, reject) => {
        const outgoing = http.request(parsed, { method, agent: localAgent,
            headers: { 'content-type': 'application/json', ...headers } }, incoming => {
            const chunks = [];
            incoming.on('data', chunk => chunks.push(chunk));
            incoming.on('error', reject);
            incoming.on('end', () => {
                try { resolve({ status: incoming.statusCode, value: JSON.parse(Buffer.concat(chunks).toString()) }); }
                catch (error) { reject(error); }
            });
        });
        outgoing.setTimeout(30_000, () => outgoing.destroy(new Error('Local HTTP request timed out')));
        outgoing.on('error', reject);
        outgoing.end(value === undefined ? undefined : JSON.stringify(value));
    });
}

function options(args) {
    const parsed = {
        binDir: path.join(ROOT, 'target/release'), sbfDir: path.join(ROOT, 'solana/target/deploy'),
        keyDir: path.join(ROOT, '.zkapi/solana-keys'), outputDir: path.join(ROOT, '.zkapi/solana-acceptance'),
        refreshMs: 400, idleSeconds: 40, scenario: 'steady', client: 'helper', clientdBin: null, proofSetupDir: path.join(ROOT, 'protocol/setup/v2'),
    };
    for (let i = 0; i < args.length; i++) {
        if (args[i] === '--help') return { help: true };
        const key = { '--bin-dir': 'binDir', '--sbf-dir': 'sbfDir', '--key-dir': 'keyDir', '--output-dir': 'outputDir',
            '--refresh-ms': 'refreshMs', '--idle-seconds': 'idleSeconds', '--scenario': 'scenario', '--client': 'client', '--clientd-bin': 'clientdBin',
            '--proof-setup-dir': 'proofSetupDir' }[args[i]];
        assert.ok(key && args[i + 1], `Unknown or incomplete option: ${args[i]}`);
        if (key === 'refreshMs' || key === 'idleSeconds') parsed[key] = Number(args[++i]);
        else if (key === 'scenario' || key === 'client') parsed[key] = args[++i];
        else parsed[key] = path.resolve(args[++i]);
    }
    assert.ok(Number.isSafeInteger(parsed.refreshMs) && parsed.refreshMs >= 100, '--refresh-ms must be >= 100');
    assert.ok(Number.isSafeInteger(parsed.idleSeconds) && parsed.idleSeconds >= 20, '--idle-seconds must be >= 20 (clientd idle settlement period used by the test)');
    assert.ok(['steady', 'jump'].includes(parsed.scenario), '--scenario must be steady or jump');
    assert.ok(['helper', 'clientd'].includes(parsed.client), '--client must be helper or clientd');
    assert.ok(parsed.client !== 'clientd' || parsed.clientdBin, '--client clientd needs --clientd-bin');
    return parsed;
}

// Mirrors the server's conservative integer conversion (floor(price - confidence), ceil on settlement).
function expectedLamports(quote, microUsd) {
    const price = BigInt(quote.price) - BigInt(quote.confidence);
    assert.ok(quote.exponent < 0 && quote.exponent >= -18);
    const scale = 10n ** BigInt(-quote.exponent);
    // micro-USD per lamport = price / scale * 1e6 / 1e9
    const numerator = BigInt(microUsd) * LAMPORTS_PER_SOL * scale;
    const denominator = price * 1_000_000n;
    return (numerator + denominator - 1n) / denominator;
}

async function main() {
    const opts = options(process.argv.slice(2));
    if (opts.help) {
        console.log('Usage: VCII_ZK_BASE=... VCII_ZK_MANAGEMENT_KEY=... node scripts/solana-vcii-lease.mjs [--bin-dir D] [--sbf-dir D] [--key-dir D] [--output-dir D] [--refresh-ms 400] [--scenario steady|jump] [--client helper|clientd --clientd-bin PATH]\n'
            + 'Runs a disposable loopback solana-test-validator, real serverd, real proofs, mock Pyth account. See docs/solana-vcii-lease.md.');
        return;
    }
    const runDir = path.join(opts.outputDir, `${new Date().toISOString().replaceAll(':', '-')}-${randomUUID().slice(0, 8)}`);
    await fs.mkdir(runDir, { recursive: true, mode: 0o700 });
    await fs.mkdir(opts.keyDir, { recursive: true, mode: 0o700 });
    const children = new Set();
    const servers = new Set();
    let interrupted = false;
    let updater;
    const onSignal = () => { interrupted = true; for (const child of children) child.kill('SIGINT'); };
    process.on('SIGINT', onSignal);
    process.on('SIGTERM', onSignal);
    const check = () => { if (interrupted) throw new Error('Local acceptance test interrupted'); };
    async function waitFor(label, fn, timeout = 30_000) {
        const end = Date.now() + timeout;
        let last;
        while (Date.now() < end) {
            check();
            try { const value = await fn(); if (value) return value; } catch (error) { last = error; }
            await delay(200);
        }
        throw new Error(`Timeout: ${label}${last ? ` (${last.message})` : ''}`);
    }
    function launch(command, args, log, { interactive = false, env = {} } = {}) {
        check();
        const out = createWriteStream(path.join(runDir, log), { flags: 'a', mode: 0o600 });
        // No inherited credentials, proxies, HOME or provider settings.
        const child = spawn(command, args, { cwd: ROOT, env: { PATH: process.env.PATH,
            RUST_LOG: 'warn,zkapi=info,zkapi_serverd=info,zkapi_indexerd=info,r1cs=warn', ...env },
            stdio: [interactive ? 'pipe' : 'ignore', 'pipe', 'pipe'] });
        if (!interactive) child.stdout.pipe(out, { end: false });
        child.stderr.pipe(out, { end: false });
        child.once('error', error => out.write(error.message));
        child.once('close', () => { children.delete(child); out.end(); });
        children.add(child);
        return child;
    }
    async function stop(child) {
        if (!child?.pid || child.exitCode !== null || child.signalCode !== null) return;
        const done = new Promise(resolve => child.once('exit', resolve));
        child.kill('SIGINT');
        await Promise.race([done, delay(3000)]);
        if (child.exitCode === null && child.signalCode === null) {
            child.kill('SIGKILL');
            await Promise.race([done, delay(2000)]);
        }
    }
    async function freePort() {
        const server = net.createServer();
        await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
        const port = server.address().port;
        await new Promise(resolve => server.close(resolve));
        return port;
    }
    async function request(url, { method = 'GET', value, headers = {} } = {}) {
        check();
        return localJSON(url, { method, value, headers });
    }
    async function get(url) {
        const result = await request(url);
        assert.equal(result.status, 200, `${new URL(url).pathname}: ${result.value.error_code ?? result.status}`);
        return result.value;
    }
    let rpcId = 0;
    async function rpc(url, method, params = []) {
        const result = await request(url, { method: 'POST', value: { jsonrpc: '2.0', id: ++rpcId, method, params } });
        assert.equal(result.status, 200);
        if (result.value.error) throw new Error(`${method}: ${JSON.stringify(result.value.error)}`);
        return result.value.result;
    }
    function helper(name) {
        const child = launch(path.join(opts.binDir, 'zkapi-solana-wallet'), [path.join(ROOT, 'protocol/setup/v2')],
            `${name}-wallet.log`, { interactive: true });
        const lines = readline.createInterface({ input: child.stdout });
        let nextId = 0;
        const pending = new Map();
        const rejectAll = error => { for (const item of pending.values()) item.reject(error); pending.clear(); };
        lines.on('line', line => {
            try {
                const response = JSON.parse(line);
                const item = pending.get(response.id);
                assert.ok(item, 'unexpected helper response');
                pending.delete(response.id);
                if (response.ok) item.resolve(response.result);
                else item.reject(new Error(`Helper ${item.command}: ${response.error}`));
            } catch (error) { rejectAll(error); }
        });
        child.once('error', rejectAll);
        child.once('close', code => rejectAll(new Error(`Helper exited (${code})`)));
        return async (command, data = {}) => {
            check();
            const id = ++nextId;
            return new Promise((resolve, reject) => {
                const timer = setTimeout(() => { pending.delete(id); reject(new Error(`Helper ${command} timed out`)); }, 240_000);
                pending.set(id, { command, resolve: value => { clearTimeout(timer); resolve(value); }, reject: error => { clearTimeout(timer); reject(error); } });
                child.stdin.write(JSON.stringify({ id, command, ...data }) + '\n');
            });
        };
    }

    try {
        console.log('Starting local Solana v2 acceptance: real validator/program/proofs/serverd, mock Pyth account.');
        const wallet = helper('primary');
        const pyth = helper('pyth');
        const signingKeys = await wallet('public_keys');
        assert.equal(signingKeys.circuit_id, 'zkapi-v2-note-bound-v1');

        // Throwaway keypairs live in --key-dir (never printed; only public keys are).
        const payerFile = path.join(opts.keyDir, 'payer.json');
        const updaterFile = path.join(opts.keyDir, 'pyth-updater.json');
        const payerKey = (await wallet('keygen', { path: payerFile })).pubkey;
        const updaterKey = (await wallet('keygen', { path: updaterFile })).pubkey;
        const deployerFile = path.join(opts.keyDir, 'deployer.json');
        const deployerKey = (await wallet('keygen', { path: deployerFile })).pubkey;
        console.log(`payer (public) ${payerKey}; mock-pyth updater (public) ${updaterKey}`);

        // Validator: immutable vault program (upgrade authority none), mock receiver program, pre-created price account.
        const priceFile = path.join(runDir, 'pyth-sol-usd-account.json');
        await wallet('pyth_account_file', { address: PYTH_SOL_USD_ACCOUNT, path: priceFile, authority: updaterKey, ...PYTH });
        const rpcPort = await freePort();
        const rpcUrl = `http://127.0.0.1:${rpcPort}`;
        const faucetPort = await freePort();
        const gossipPort = await freePort();
        const portBase = (opts.scenario === 'jump' ? 31_000 : 20_000) + Math.floor(Math.random() * 900) * 10;
        launch('solana-test-validator', ['--reset', '--quiet', '--ledger', path.join('/tmp', `zksol-ledger-${randomUUID().slice(0, 8)}`),
            '--bind-address', '127.0.0.1', '--rpc-port', String(rpcPort), '--faucet-port', String(faucetPort), '--gossip-port', String(gossipPort),
            '--dynamic-port-range', `${portBase}-${portBase + 99}`,
            '--upgradeable-program', VAULT_PROGRAM_ID, path.join(opts.sbfDir, 'dagon_zkapi_vault.so'), deployerKey,
            '--bpf-program', PYTH_RECEIVER, path.join(opts.sbfDir, 'mock_pyth_writer.so'),
            '--account', PYTH_SOL_USD_ACCOUNT, priceFile], 'validator.log');
        await waitFor('validator startup', async () => await rpc(rpcUrl, 'getHealth') === 'ok', 120_000);
        const genesisHash = await rpc(rpcUrl, 'getGenesisHash');
        console.log(`validator up at ${rpcUrl}; genesis ${genesisHash} (local, pinned into serverd)`);

        await wallet('chain_connect', { rpc_url: rpcUrl });
        await pyth('chain_connect', { rpc_url: rpcUrl });
        await wallet('airdrop', { pubkey: payerKey, lamports: 5 * Number(LAMPORTS_PER_SOL) });
        await wallet('airdrop', { pubkey: deployerKey, lamports: Number(LAMPORTS_PER_SOL) });
        // Revoke the upgrade authority for good: serverd's startup gate requires an immutable program.
        const finalize = spawnSync('solana', ['--url', rpcUrl, '--keypair', deployerFile, 'program', 'set-upgrade-authority',
            VAULT_PROGRAM_ID, '--upgrade-authority', deployerFile, '--final'], { encoding: 'utf8', env: { PATH: process.env.PATH } });
        assert.equal(finalize.status, 0, `set-upgrade-authority --final failed: ${finalize.stderr}`);
        const shown = spawnSync('solana', ['--url', rpcUrl, '--keypair', deployerFile, 'program', 'show', VAULT_PROGRAM_ID],
            { encoding: 'utf8', env: { PATH: process.env.PATH } }).stdout;
        console.log('program show:', shown.split(/\r?\n/).filter(l => /^(Program Id|Authority|Data Length)/.test(l)).join(' | '));
        assert.match(shown, /Authority: none/);
        await pyth('airdrop', { pubkey: updaterKey, lamports: Number(LAMPORTS_PER_SOL) });
        // Continuous refresher, like the real feed: every --refresh-ms a new publication (random walk within +/-WALK_BPS of
        // `center`; `center` only moves in the 'jump' scenario). serverd accepts a quote that is no longer the latest as long as
        // the lower-bound price has not fallen more than its tolerance (--native-quote-tolerance-bps, default 50).
        let center = PYTH.price;
        let walk = 0;
        let publications = 0;
        const nextPrice = () => {
            walk = Math.max(-WALK_BPS, Math.min(WALK_BPS, walk + Math.round((Math.random() * 2 - 1) * 3)));
            return Math.round(center * (1 + walk / 10_000));
        };
        const refreshPyth = () => pyth('pyth_update', { keypair: updaterFile, address: PYTH_SOL_USD_ACCOUNT, ...PYTH, price: nextPrice() })
            .then(value => { publications++; return value; });
        await refreshPyth();
        const pythStart = Date.now();
        let updaterFailure;
        updater = (async () => {
            while (!interrupted && !updater?.stop) {
                const started = Date.now();
                try { await refreshPyth(); } catch (error) { updaterFailure = error; }
                await delay(Math.max(0, opts.refreshMs - (Date.now() - started)));
            }
        })();
        updater.stop = false;

        const vault = await wallet('vault_init', { keypair: payerFile, request_charge_cap: CAP });
        assert.equal(vault.program_id, VAULT_PROGRAM_ID);
        assert.equal(vault.genesis_hash, genesisHash);
        console.log(`vault initialized: state PDA ${vault.vault_state}; proof chain id ${vault.chain_id}`);
        const indexerPort = await freePort();
        const indexerUrl = `http://127.0.0.1:${indexerPort}`;
        launch(path.join(opts.binDir, 'dagon-zkapi-indexerd'), ['--ledger', 'solana', '--listen', `127.0.0.1:${indexerPort}`,
            '--rpc-url', rpcUrl, '--program-id', vault.program_id, '--vault-state', vault.vault_state, '--poll-interval-ms', '500'], 'indexer.log');
        await waitFor('finalized indexer ready', async () => (await get(`${indexerUrl}/v1/tree/snapshot`)).next_note_id === 0);
        await wallet('attach_indexer', { indexer_url: indexerUrl });
        if (opts.client === 'helper') {
            const primary = await wallet('deposit', { amount: DEPOSIT });
            assert.equal(primary.state.note.current_balance, DEPOSIT);
            assert.equal(primary.state.note.is_genesis, true);
            // The finalized indexer trails the chain by a few seconds; the ledger refuses a snapshot that disagrees with the vault.
            const afterDeposit = await waitFor('indexer catches up with the deposit', async () => wallet('vault_snapshot'), 120_000);
            assert.equal(afterDeposit.next_note_id, 1);
            assert.ok(BigInt(afterDeposit.vault_lamports) >= BigInt(DEPOSIT), 'vault must hold the deposited lamports');
            console.log(`deposited ${DEPOSIT} lamports into the Solana vault (finalized); vault now holds ${afterDeposit.vault_lamports} lamports (incl. rent)`);
        }

        const serverPort = await freePort();
        const serverUrl = `http://127.0.0.1:${serverPort}`;
        const dbPath = path.join(runDir, 'server.db');
        launch(path.join(opts.binDir, 'dagon-zkapi'), ['--request-charge-cap', String(CAP), '--proof-setup-dir', path.join(ROOT, 'protocol/setup/v2'),
            'serverd', '--ledger', 'solana', '--solana-rpc-url', rpcUrl, '--solana-program-id', vault.program_id,
            '--solana-vault-state', vault.vault_state, '--solana-genesis-hash', genesisHash, '--solana-network', 'localnet',
            '--pyth-price-account', PYTH_SOL_USD_ACCOUNT, '--pyth-max-age-seconds', '60',
            '--listen', `127.0.0.1:${serverPort}`, '--openrouter-api-base', VCII_ZK_BASE,
            '--openrouter-lease-ttl-seconds', String(LEASE_TTL_SECONDS),
            '--openrouter-settlement-grace-seconds', '1', '--openrouter-settlement-poll-seconds', '1',
            '--indexer-url', indexerUrl, '--db-path', dbPath, '--state-seed', '0x1', '--clear-seed', '0x2', '--root-poll-interval-ms', '500'], 'server.log',
            { env: { ZKAPI_OPENROUTER_MANAGEMENT_KEY: VCII_ZK_MANAGEMENT_KEY } });
        const health = await waitFor('serverd ready (immutability gate, finalized vault, finalized Pyth)', async () => get(`${serverUrl}/health`), 120_000);
        const noteRoot = (await waitFor('indexer snapshot', async () => wallet('wallet_snapshot_tree'))).root;
        await waitFor('serverd root equals the finalized vault root', async () => BigInt((await get(`${serverUrl}/health`)).current_root) === BigInt(noteRoot));
        assert.deepEqual((await get(`${serverUrl}/v1/attestation`)).state_signing_key, signingKeys.state_signing_key);
        console.log('serverd ready: immutable program, vault pins and finalized Pyth quote accepted');

        async function mcpCall(key, tool) {
            const res = await fetch(`${VCII_BASE}/mcp`, { method: 'POST', headers: { authorization: `Bearer ${key}`,
                accept: 'application/json, text/event-stream', 'content-type': 'application/json' },
                body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: tool, arguments: {} } }) });
            return { status: res.status, text: (await res.text()).slice(0, 400) };
        }
        // --client clientd: zkapi-clientd is the whole client. Only the vault's creation and the validator belong to the harness;
        // `solana init` verifies the chain, `solana deposit` funds the note, `serve` leases and settles, `solana withdraw` pays it out.
        async function runWithClientd() {
            // clientd insists on a private (0700) config directory, which the bind-mounted run directory cannot guarantee, and the
            // wallet file holds the note secret: keep both in a fresh private temp directory and remove it at the end.
            const clientdDir = await fs.mkdtemp(path.join(os.tmpdir(), 'zkapi-clientd-'));
            const cfgDir = path.join(clientdDir, 'config');
            process.once('exit', () => rmSync(clientdDir, { recursive: true, force: true }));
            const walletFile = path.join(cfgDir, 'zkapi', 'solana', vault.vault_state, 'wallet.json');
            const proxyStats = { posts: [], expires: 0, quotes: 0 };
            let jumpTriggered = false;
            // Loopback proxy between clientd and serverd: counts lease POSTs and, in the 'jump' scenario, holds the first one until
            // the finalized feed (which serverd reads) shows the 2% drop, so that the proof made on the earlier quote is stale.
            const proxy = http.createServer(async (req, res) => {
                try {
                    const chunks = [];
                    for await (const chunk of req) chunks.push(chunk);
                    const body = Buffer.concat(chunks);
                    let entry;
                    if (req.method === 'GET' && req.url === '/v2/billing/quote') proxyStats.quotes++;
                    if (req.method === 'POST' && req.url.endsWith('/expire')) proxyStats.expires++;
                    if (req.method === 'POST' && req.url === '/v2/openrouter/leases') {
                        const request = JSON.parse(body.toString());
                        entry = { n: proxyStats.posts.length + 1, id: request.client_request_id, nullifier: request.public_inputs.request_nullifier,
                            bodyHash: createHash('sha256').update(body).digest('hex'), quote: JSON.parse(request.payload).billing_quote, body };
                        proxyStats.posts.push(entry);
                        if (opts.scenario === 'jump' && !jumpTriggered) {
                            jumpTriggered = true;
                            center = Math.round(PYTH.price * (1 - JUMP_BPS / 10_000)); walk = 0;
                            console.log(`!! price jumps -${JUMP_BPS} bps while attempt ${entry.n} proof is in flight (new center ${center}); holding its POST until the finalized feed shows it`);
                            await waitFor('finalized feed reflects the jump', async () =>
                                BigInt((await get(`${serverUrl}/v2/billing/quote`)).price) * 10_000n < BigInt(entry.quote.price) * BigInt(10_000 - 2 * 50), 90_000);
                        }
                    }
                    const upstream = await fetch(serverUrl + req.url, { method: req.method,
                        headers: body.length ? { 'content-type': 'application/json' } : {}, body: body.length ? body : undefined });
                    const text = await upstream.text();
                    if (entry) {
                        entry.status = upstream.status;
                        try { entry.code = JSON.parse(text).error_code; entry.retriable = JSON.parse(text).retriable; } catch { /* not JSON */ }
                        console.log(`proxy: lease POST #${entry.n} (${entry.id.slice(0, 22)}...) -> HTTP ${entry.status} ${entry.code ?? ''} ${entry.retriable === undefined ? '' : `retriable=${entry.retriable}`}`);
                    }
                    res.writeHead(upstream.status, { 'content-type': 'application/json' });
                    res.end(text);
                } catch (error) {
                    console.error(`proxy error: ${error.message}`);
                    res.writeHead(502); res.end();
                }
            });
            servers.add(proxy);
            const proxyPort = await freePort();
            await new Promise(resolve => proxy.listen(proxyPort, '127.0.0.1', resolve));
            const listenPort = await freePort();
            const apiUrl = `http://127.0.0.1:${listenPort}`;

            function spawnCli(args, cfg = cfgDir) {
                check();
                const log = createWriteStream(path.join(runDir, 'clientd-cli.log'), { flags: 'a', mode: 0o600 });
                const child = spawn(opts.clientdBin, ['--config-dir', cfg, ...args], { cwd: ROOT, env: { PATH: process.env.PATH },
                    stdio: ['ignore', 'pipe', 'pipe'] });
                children.add(child);
                let stdout = '';
                let stderr = '';
                child.stdout.on('data', chunk => { stdout += chunk; }); // never logged: `lease export` prints the key here
                child.stderr.on('data', chunk => { stderr += chunk; log.write(chunk); });
                const done = new Promise((resolve, reject) => {
                    child.once('error', reject);
                    child.once('close', (code, signal) => { children.delete(child); log.end(); resolve({ code, signal, stdout, stderr }); });
                });
                return { child, done };
            }
            const cli = (args, cfg) => spawnCli(args, cfg).done;
            async function cliOk(args, cfg) {
                const result = await cli(args, cfg);
                assert.equal(result.code, 0, `zkapi-clientd ${args.slice(0, 2).join(' ')} failed: ${result.stderr.trim().split('\n').slice(-3).join(' | ')}`);
                return result.stdout;
            }
            async function startDaemon() {
                const daemon = launch(opts.clientdBin, ['--config-dir', cfgDir, 'serve'], 'clientd.log');
                await waitFor('zkapi-clientd serve', async () => (await fetch(`${apiUrl}/healthz`)).status === 200, 30_000);
                return daemon;
            }
            const readWallet = async () => JSON.parse(await fs.readFile(walletFile, 'utf8'));
            const sol = lamports => `${Number(lamports) / 1e9} SOL`;

            // The helper clientd runs (a dev build here: it also has the validator-only commands the harness itself uses). Its
            // SHA-256 is pinned in the profile, and clientd checks the pin and the protocol handshake before every run.
            const helperBin = path.join(opts.binDir, 'zkapi-solana-wallet');
            const helperSha = createHash('sha256').update(await fs.readFile(helperBin)).digest('hex');
            const version = spawnSync(helperBin, ['--version'], { encoding: 'utf8', env: { PATH: process.env.PATH } });
            console.log(`wallet helper: ${version.stdout.trim()}; sha256 ${helperSha}`);
            const deployment = { server_url: `http://127.0.0.1:${proxyPort}`, indexer_url: indexerUrl, rpc_url: rpcUrl, inference_base: `${VCII_ZK_BASE.replace(/\/+$/, '')}/v1`, cluster: 'localnet',
                program_id: vault.program_id, vault_state: vault.vault_state, genesis_hash: genesisHash,
                state_signing_key: signingKeys.state_signing_key, clearance_signing_key: signingKeys.clearance_signing_key, min_lease_lamports: CAP };
            const proverFlags = ['--prover', helperBin, '--proof-setup-dir', opts.proofSetupDir];

            const deploymentFile = path.join(clientdDir, 'deployment.json');
            await fs.writeFile(deploymentFile, JSON.stringify(deployment), { mode: 0o600 });

            // Negative checks first: a wrong pin never produces a profile.
            const wrongDir = path.join(clientdDir, 'wrong-config');
            const wrongFile = path.join(clientdDir, 'wrong-deployment.json');
            await fs.writeFile(wrongFile, JSON.stringify({ ...deployment, program_id: PYTH_RECEIVER }), { mode: 0o600 });
            const wrongProgram = await cli(['solana', 'init', '--deployment', wrongFile, ...proverFlags, '--prover-sha256', helperSha], wrongDir);
            console.log(`init with a wrong program id pin -> exit ${wrongProgram.code}: ${wrongProgram.stderr.trim().replace(/^zkapi-clientd: /, '')}`);
            assert.notEqual(wrongProgram.code, 0, 'a deployment pinning the wrong program must be refused');
            assert.match(wrongProgram.stderr, /on-chain verification failed/);
            await assert.rejects(fs.access(path.join(wrongDir, 'config.json')), 'a refused init must not save a profile');
            const wrongHash = await cli(['solana', 'init', '--deployment', deploymentFile, ...proverFlags, '--prover-sha256', '0'.repeat(64)], wrongDir);
            assert.notEqual(wrongHash.code, 0, 'a helper that is not the pinned binary must be refused');
            console.log(`init with a wrong helper SHA-256 pin -> exit ${wrongHash.code}: ${wrongHash.stderr.trim().replace(/^zkapi-clientd: /, '')}`);

            const initOut = await cliOk(['solana', 'init', '--deployment', deploymentFile, ...proverFlags, '--prover-sha256', helperSha,
                '--settle-idle-seconds', String(opts.idleSeconds), '--listen', `127.0.0.1:${listenPort}`]);
            console.log(initOut.trim());
            assert.match(initOut, /Verified on chain/);
            const pinned = JSON.parse(await fs.readFile(path.join(cfgDir, 'config.json'), 'utf8')).zkapi.solana;
            assert.equal(pinned.chain_id, vault.chain_id, 'clientd must derive the same proof chain id as the vault init');
            assert.equal(pinned.prover_sha256, helperSha);
            const verified = JSON.parse(await cliOk(['solana', 'verify']));
            assert.equal(verified.verified, true);

            // Exercise the actual direct cancellation on chain: stage just the first transaction of a disposable deposit,
            // cancel its buffer, and prove the payer recovered the rent (only transaction fees remain spent).
            await wallet('connect', { rpc_url: rpcUrl, indexer_url: indexerUrl, network: 'localnet',
                program_id: vault.program_id, vault_state: vault.vault_state, genesis_hash: genesisHash });
            const beforeStage = BigInt((await rpc(rpcUrl, 'getBalance', [payerKey, { commitment: 'finalized' }])).value);
            const disposable = await wallet('deposit_params');
            const preparedStage = await wallet('deposit_prepare', { payer: payerKey, commitment: disposable.registration_commitment, amount: DEPOSIT });
            const signedStage = await wallet('sign_operation', { keypair: payerFile, operation: preparedStage.operation });
            await wallet('submit_signed', { signed: { transactions: signedStage.signed.transactions.slice(0, 1) }, finalize: true });
            const cancel = await wallet('cancel_prepare', { payer: payerKey, operation_id: preparedStage.operation.operation_id });
            const signedCancel = await wallet('sign_operation', { keypair: payerFile, operation: cancel.operation });
            await wallet('submit_signed', { signed: signedCancel.signed, finalize: true });
            await assert.rejects(wallet('cancel_prepare', { payer: payerKey, operation_id: preparedStage.operation.operation_id }), /staged buffer is absent/);
            const afterCancel = BigInt((await rpc(rpcUrl, 'getBalance', [payerKey, { commitment: 'finalized' }])).value);
            assert.ok(beforeStage - afterCancel > 0n && beforeStage - afterCancel <= 100_000n, 'cancel must return the buffer rent, leaving only transaction fees spent');
            assert.equal((await wallet('vault_snapshot')).next_note_id, 0, 'the cancelled operation must not deposit a note');
            console.log(`BUFFER CLEANUP: real staged operation cancelled and confirmed absent; rent returned, ${beforeStage - afterCancel} lamports spent on fees.`);

            // Fund the note from the harness's local keypair file. The first run is SIGKILLed once its signed transactions are
            // journaled but before they are final; the second finds the journal and finishes from the chain.
            console.log(`depositing ${sol(DEPOSIT)} from keypair file payer.json (public ${payerKey}) with zkapi-clientd solana deposit`);
            const depositArgs = ['solana', 'deposit', '--keypair', payerFile, '--sol', String(DEPOSIT / 1e9), '--confirm'];
            const first = spawnCli(depositArgs);
            const interruptedAt = Date.now();
            let journaled;
            await waitFor('the deposit journal with signed transactions', async () => {
                try { journaled = (await readWallet()).deposit; } catch { return false; }
                return journaled?.signed ? true : first.child.exitCode !== null;
            }, 300_000);
            first.child.kill('SIGKILL');
            const killed = await first.done;
            const midway = await readWallet();
            if (killed.signal === 'SIGKILL' && midway.deposit) {
                console.log(`deposit SIGKILLed ${((Date.now() - interruptedAt) / 1000).toFixed(1)}s in; journal holds note ${midway.deposit.note_id}, ${midway.deposit.signed.transactions.length} signed transactions, no note yet: ${midway.state === null}`);
                assert.equal(midway.state, null, 'the note must not be installed before the deposit is final');
                assert.ok(midway.deposit.secret, 'the note secret must be journaled before the chain is touched');
                const pendingStatus = JSON.parse(await cliOk(['solana', 'status']));
                assert.equal(pendingStatus.wallet.pending_deposit, true);
            } else {
                console.log('deposit finished before it could be interrupted; the crash check is skipped for this run');
            }
            const depositOut = JSON.parse(await cliOk(depositArgs.slice(0, 2).concat(['--keypair', payerFile, '--confirm'])));
            console.log('DEPOSIT via clientd (resumed from the journal):', JSON.stringify(depositOut));
            assert.equal(depositOut.kind, 'deposit');
            assert.equal(depositOut.lamports, DEPOSIT);
            assert.equal(depositOut.private_balance_lamports, String(DEPOSIT));
            assert.ok(depositOut.signature, 'the deposit result carries the executing transaction signature');
            const funded = JSON.parse(await cliOk(['solana', 'status']));
            assert.equal(funded.wallet.private_balance_lamports, String(DEPOSIT));
            assert.equal(funded.wallet.pending_deposit ?? false, false);
            assert.ok(!(await fs.readFile(walletFile, 'utf8')).includes('"deposit":{'), 'the deposit journal must be cleared');
            const afterDeposit = await waitFor('indexer catches up with the clientd deposit', async () => {
                const snapshot = await wallet('vault_snapshot');
                return snapshot.next_note_id === 1 && snapshot;
            }, 120_000);
            assert.ok(BigInt(afterDeposit.vault_lamports) >= BigInt(DEPOSIT), 'the vault must hold the deposited lamports');
            console.log(`clientd deposited ${sol(DEPOSIT)} (tx ${depositOut.signature.slice(0, 16)}...); vault holds ${afterDeposit.vault_lamports} lamports`);
            const treeRoot = (await waitFor('indexer snapshot', async () => wallet('wallet_snapshot_tree'))).root;
            await waitFor('serverd root equals the finalized vault root after the deposit', async () => BigInt((await get(`${serverUrl}/health`)).current_root) === BigInt(treeRoot), 120_000);

            let daemon = await startDaemon();
            const lastQuote = () => proxyStats.posts.filter(p => p.status === 201).at(-1).quote;
            let charged = 0n;

            // Lease 1 (3 USD): one paid call, a pause shorter than the idle period (still open: the key is in use), a second call that
            // uses the limit up, and clientd settles it on its own.
            let started = Date.now();
            const exported = await cli(['lease', 'export', '--usd', '3', '--confirm']);
            assert.equal(exported.code, 0, `zkapi-clientd lease export failed: ${exported.stderr.trim().split('\n').slice(-2).join(' | ')}`);
            const key = exported.stdout.trim();
            assert.match(key, /^vcii_zk_/, 'lease export must print the key minted by vcii');
            console.log(`lease export succeeded in ${((Date.now() - started) / 1000).toFixed(1)}s; key length ${key.length} (key redacted)`);
            const { posts } = proxyStats;
            console.log(`serverd saw ${posts.length} lease POST(s): ${posts.map(p => `#${p.n} HTTP ${p.status}${p.code ? ` ${p.code}` : ''}`).join(', ')}; ${proxyStats.expires} /expire check(s); ${proxyStats.quotes} quote read(s)`);
            assert.equal(new Set(posts.map(p => p.bodyHash)).size, posts.length, 'a proof must never be sent twice');
            assert.equal(new Set(posts.map(p => p.id)).size, posts.length, 'every attempt must use a fresh request id');
            const accepted = posts.at(-1);
            assert.equal(accepted.status, 201);
            if (opts.scenario === 'jump') {
                assert.deepEqual(posts.map(p => p.status), [409, 201]);
                assert.equal(posts[0].code, 'native_quote_stale');
                assert.equal(posts[0].retriable, true);
                assert.ok(proxyStats.expires >= 1, 'clientd must confirm non-acceptance with serverd before re-proving');
            } else {
                assert.deepEqual(posts.map(p => p.status), [201], 'a price walk inside the tolerance must never be refused');
            }
            assert.ok(!(await fs.readFile(walletFile, 'utf8')).includes(key), 'the exported key must not be stored in the wallet file');
            const replay = await request(`${serverUrl}/v2/openrouter/leases`, { method: 'POST', value: JSON.parse(accepted.body.toString()) });
            assert.equal(replay.status, 409, 'active lease replay must not mint another runtime key');
            const call = await mcpCall(key, 'market_pulse');
            console.log(`vcii /mcp tools/call market_pulse with the clientd-exported key -> HTTP ${call.status}`, call.text.slice(0, 160).replace(/\s+/g, ' '));
            assert.equal(call.status, 200);
            assert.equal(JSON.parse(await cliOk(['lease', 'status'])).pending_request, true);

            // Crash safety: SIGKILL the daemon mid-lease; the restarted one finds the open lease (and its idle clock) in the wallet file.
            daemon.kill('SIGKILL');
            await new Promise(resolve => daemon.once('close', resolve));
            daemon = await startDaemon();
            const pending = JSON.parse(await cliOk(['lease', 'status']));
            assert.equal(pending.pending_request, true);
            assert.ok(pending.settle_after > Date.now() / 1000, 'the open lease must survive a daemon crash');
            console.log(`daemon killed and restarted: lease still open until ${new Date(pending.lease_expires_at * 1000).toISOString()}`);

            // A key in use is never settled under its user: wait most of the idle period, still open, then use the key again.
            await delay(Math.floor(opts.idleSeconds * 0.5 * 1000));
            const mid = JSON.parse(await cliOk(['lease', 'status']));
            assert.equal(mid.pending_request, true, 'a key inside its idle period must stay open');
            console.log(`${(opts.idleSeconds * 0.5).toFixed(0)}s after the first call (idle period ${opts.idleSeconds}s) the lease is still open; usage seen so far ${mid.lease_usage_usd} USD, idle settlement at ${new Date(mid.idle_settle_at * 1000).toISOString()}`);
            assert.ok(mid.lease_usage_usd >= 1.5, 'clientd must have read the first call from serverd');
            const second = await mcpCall(key, 'market_pulse');
            assert.equal(second.status, 200, 'the second call (using the 3 USD limit up) must succeed');
            started = Date.now();
            await waitFor('clientd settles the exhausted lease by itself', async () => !(await cliOk(['lease', 'status']).then(JSON.parse)).pending_request, 240_000);
            const exhaustedAfter = (Date.now() - started) / 1000;
            console.log(`lease 1 settled by clientd ${exhaustedAfter.toFixed(1)}s after its limit was used up (no 'lease settle' was run)`);
            assert.ok(exhaustedAfter < opts.idleSeconds, 'exhaustion must settle sooner than the idle period');
            charged += expectedLamports(accepted.quote, 3_000_000);
            const afterOne = JSON.parse(await cliOk(['solana', 'status']));
            assert.equal(BigInt(afterOne.wallet.private_balance_lamports), BigInt(DEPOSIT) - charged, 'note balance must drop by exactly the settled charge (2 x 1.5 USD, ceil)');
            assert.equal((await mcpCall(key, 'market_pulse')).status, 401, 'after settlement the key is refused');
            console.log(`SETTLEMENT 1 (limit used up): note balance ${afterOne.wallet.private_balance_lamports} = ${DEPOSIT} - ${charged}`);

            // Lease 2 (2 USD): one call, then nothing. clientd settles it once the key has been idle for the idle period.
            const exported2 = await cli(['lease', 'export', '--usd', '2', '--confirm']);
            assert.equal(exported2.code, 0, `second lease export failed: ${exported2.stderr.trim().split('\n').slice(-2).join(' | ')}`);
            const key2 = exported2.stdout.trim();
            const accepted2 = proxyStats.posts.filter(p => p.status === 201).at(-1);
            assert.notEqual(accepted2.id, accepted.id);
            assert.equal((await mcpCall(key2, 'market_pulse')).status, 200);
            const lastCall = Date.now();
            await waitFor('clientd settles the idle lease by itself', async () => !(await cliOk(['lease', 'status']).then(JSON.parse)).pending_request, 300_000);
            const idleAfter = (Date.now() - lastCall) / 1000;
            console.log(`lease 2 settled by clientd ${idleAfter.toFixed(1)}s after its last use (idle period ${opts.idleSeconds}s; no 'lease settle' was run)`);
            assert.ok(idleAfter >= opts.idleSeconds * 0.75, `the idle lease settled after ${idleAfter}s, before its idle period`);
            charged += expectedLamports(accepted2.quote, 1_500_000);
            const afterTwo = JSON.parse(await cliOk(['solana', 'status']));
            assert.equal(BigInt(afterTwo.wallet.private_balance_lamports), BigInt(DEPOSIT) - charged);
            assert.equal((await mcpCall(key2, 'market_pulse')).status, 401, 'after idle settlement the key is refused');
            console.log(`SETTLEMENT 2 (idle): note balance ${afterTwo.wallet.private_balance_lamports} = ${DEPOSIT} - ${charged}`);
            const clientdLog = await fs.readFile(path.join(runDir, 'clientd.log'), 'utf8');
            assert.match(clientdLog, /Settling the open Solana lease early: its spending limit is used up/);
            assert.match(clientdLog, /Settling the open Solana lease early: it saw no new usage/);

            // Withdraw everything to a fresh address, with the daemon running (it owns the wallet file, so the CLI asks it to).
            const destFile = path.join(opts.keyDir, `withdraw-destination-${randomUUID().slice(0, 8)}.json`);
            const destination = (await wallet('keygen', { path: destFile })).pubkey;
            assert.equal((await rpc(rpcUrl, 'getBalance', [destination, { commitment: 'finalized' }])).value, 0, 'the destination must start empty');
            const remaining = BigInt(DEPOSIT) - charged;
            const withdrawal = await cli(['solana', 'withdraw', '--to', destination, '--all', '--confirm']);
            assert.equal(withdrawal.code, 0, `solana withdraw failed: ${withdrawal.stderr.trim().split('\n').slice(-2).join(' | ')}`);
            assert.match(withdrawal.stderr, /daemon is running/, 'with the daemon up, the withdrawal goes through its management API');
            const paidOut = JSON.parse(withdrawal.stdout);
            console.log('WITHDRAWAL via clientd:', JSON.stringify(paidOut));
            assert.equal(paidOut.kind, 'withdrawal');
            assert.equal(paidOut.destination, destination);
            assert.equal(BigInt(paidOut.lamports), remaining);
            assert.ok(paidOut.signature);
            const arrived = await waitFor('the withdrawn lamports at the destination', async () => {
                const balance = (await rpc(rpcUrl, 'getBalance', [destination, { commitment: 'finalized' }])).value;
                return balance > 0 && BigInt(balance);
            }, 60_000);
            // The vault pays the note's remaining balance and closes the note account, whose rent goes to the destination too.
            const noteRent = BigInt(await rpc(rpcUrl, 'getMinimumBalanceForRentExemption', [94]));
            console.log(`destination ${destination} now holds ${arrived} lamports (${sol(arrived)}) = remaining balance ${remaining} + closed note account rent ${noteRent}`);
            assert.equal(arrived, remaining + noteRent, 'the destination must receive the note\'s remaining balance plus the closed note account\'s rent');
            const closed = JSON.parse(await cliOk(['solana', 'status']));
            assert.equal(closed.wallet.has_note, false);
            assert.equal(closed.wallet.pending_withdrawal ?? false, false);
            const history = (await readWallet()).history.map(h => `${h.kind} ${h.lamports} ${h.signature.slice(0, 12)}...`);
            console.log('wallet history:', history.join(' | '));
            assert.equal(history.length, 2);
            const noMore = await cli(['lease', 'export', '--usd', '2', '--confirm']);
            assert.notEqual(noMore.code, 0, 'a closed note must not open another lease');
            console.log(`after the withdrawal a lease is refused: ${noMore.stderr.trim().replace(/^zkapi-clientd: /, '').slice(0, 120)}`);
            assert.equal(updaterFailure, undefined, `Pyth refresh failed: ${updaterFailure?.message}`);
            console.log(`PASS (${opts.scenario}): zkapi-clientd init (on-chain verified; wrong program pin and wrong helper pin refused) -> deposit (SIGKILLed and resumed) -> lease export -> paid MCP calls -> daemon crash/restart -> key in use stays open -> exhausted lease settled -> idle lease settled -> withdraw --all to a fresh address.`);
        }
        if (opts.client === 'clientd') {
            await runWithClientd();
            return;
        }
        const tree = await waitFor('indexer snapshot', async () => wallet('wallet_snapshot_tree'));
        const merkle = await wallet('tree_path', { args: { snapshot: tree, note_id: 0, require_existing: true } });
        // quote -> prove (~13 s) -> lease, re-quoting and re-proving on a retriable native_quote_stale (bounded).
        const id0 = `vcii-${randomUUID()}`;
        let quote, prepared, id, lease, issuedAt;
        let jumped = false;
        for (let attempt = 1; ; attempt++) {
            assert.ok(attempt <= MAX_QUOTE_ATTEMPTS, `native_quote_stale persisted after ${MAX_QUOTE_ATTEMPTS} attempts`);
            quote = await get(`${serverUrl}/v2/billing/quote`);
            assert.equal(quote.asset, 'native_sol');
            console.log(`QUOTE (attempt ${attempt}):`, JSON.stringify({ asset: quote.asset, source: quote.source, price: quote.price, confidence: quote.confidence,
                exponent: quote.exponent, feed_account: quote.feed_account, publish_time: quote.publish_time, posted_slot: quote.posted_slot }));
            const payload = JSON.stringify({ mode: 'openrouter_ephemeral_lease', version: 1, billing_quote: quote });
            id = attempt === 1 ? id0 : `vcii-${randomUUID()}`;
            const publishedBefore = publications;
            if (opts.scenario === 'jump' && !jumped) {
                jumped = true;
                setTimeout(() => { center = Math.round(PYTH.price * (1 - JUMP_BPS / 10_000)); walk = 0;
                    console.log(`!! price jumps -${JUMP_BPS} bps mid-proof (new center ${center})`); }, 1000);
            }
            prepared = await wallet('prepare_request', { args: { payload, active_root: merkle.active_root,
                merkle_siblings: merkle.siblings, client_request_id: id, request_time: Math.floor(Date.now() / 1000), created_at_ms: Date.now() } });
            if (opts.scenario === 'jump' && attempt === 1) {
                // serverd reads Pyth at finalized commitment (~15 s behind the tip here), so on a fast prover the jump may not be
                // visible yet; a slower proof would simply have taken this long. Wait until the finalized feed shows it.
                await waitFor('finalized feed reflects the jump', async () =>
                    BigInt((await get(`${serverUrl}/v2/billing/quote`)).price) * 10_000n < BigInt(quote.price) * BigInt(10_000 - 2 * 50), 60_000);
            }
            issuedAt = Math.floor(Date.now() / 1000);
            const latest = await get(`${serverUrl}/v2/billing/quote`);
            console.log(`${publications - publishedBefore} newer Pyth publications during proving; quote age at lease submission: ${issuedAt - quote.publish_time}s (server limit 60s); `
                + `quote is ${latest.publish_time > quote.publish_time || latest.posted_slot > quote.posted_slot ? 'NOT the latest' : 'still the latest'} `
                + `(latest price ${latest.price} vs quoted ${quote.price})`);
            const issued = await request(`${serverUrl}/v2/openrouter/leases`, { method: 'POST', value: prepared.request });
            if (issued.status === 201) { lease = issued.value; break; }
            assert.ok(issued.status === 409 && issued.value.error_code === 'native_quote_stale' && issued.value.retriable === true,
                `lease rejected: ${issued.status} ${JSON.stringify(issued.value).slice(0, 300)}`);
            console.log(`lease refused: HTTP 409 ${issued.value.error_code} retriable=${issued.value.retriable}; nothing reserved, re-quoting and re-proving`);
            assert.equal(opts.scenario, 'jump', 'a price walk inside the tolerance must never be refused');
            await wallet('discard_request');
        }
        if (opts.scenario === 'jump') assert.ok(jumped && id !== id0, 'the jump scenario must have exercised the retry');
        assert.match(lease.api_key, /^vcii_zk_/, 'serverd must hand back the key minted by vcii');
        const { api_key: _redacted, ...leaseMeta } = lease;
        console.log('LEASE (key redacted):', JSON.stringify(leaseMeta));
        console.log(`lease key length ${lease.api_key.length}; expires_at - issued ~ ${lease.expires_at - issuedAt}s (serverd --openrouter-lease-ttl-seconds ${LEASE_TTL_SECONDS}); ${publications} Pyth publications in ${((Date.now() - pythStart) / 1000).toFixed(0)}s (one per ${((Date.now() - pythStart) / publications).toFixed(0)} ms on average)`);
        const replay = await request(`${serverUrl}/v2/openrouter/leases`, { method: 'POST', value: prepared.request });
        assert.equal(replay.status, 409, 'active lease replay must not mint another runtime key');
        const call = await mcpCall(lease.api_key, 'market_pulse');
        console.log(`vcii /mcp tools/call market_pulse with the serverd-issued key -> HTTP ${call.status}`, call.text.slice(0, 160).replace(/\s+/g, ' '));
        assert.equal(call.status, 200);
        const retired = await request(`${serverUrl}/v2/openrouter/leases/${id}`, { method: 'POST', value: prepared.request });
        assert.ok(retired.status === 200 || (retired.status === 409 && retired.value.error_code === 'lease_settlement_pending'),
            `retirement failed: ${retired.status}/${retired.value.error_code}`);
        const recovery = await waitFor('settlement from vcii usage', async () => {
            const found = await get(`${serverUrl}/v2/requests/${id}`);
            return found.request_response && found;
        }, 90_000);
        const response = recovery.request_response;
        const expected = expectedLamports(quote, 1_500_000);
        console.log('SETTLEMENT: charge_applied (lamports) =', response.charge_applied, `(expected ${expected}: 1.5 USD at the accepted quote's price minus confidence, ceil)`,
            'response_payload =', response.response_payload);
        assert.equal(JSON.parse(response.response_payload).usage_usd, 1.5, 'vcii usage (1 credit x 1.5 USD) must reach the settled charge');
        assert.equal(BigInt(response.charge_applied), expected, 'charge must equal the ceil-converted vcii usage at the accepted quote');
        const completed = await wallet('complete_response', { response });
        assert.equal(completed.pending_request, false);
        assert.equal(completed.state.note.current_balance, DEPOSIT - Number(expected), 'note balance must drop by exactly the settled charge');
        console.log(`wallet accepted the server-signed settlement: note balance ${completed.state.note.current_balance} lamports`);
        const after = await mcpCall(lease.api_key, 'market_pulse');
        console.log(`after settlement the key is refused: HTTP ${after.status}`);
        assert.equal(after.status, 401);
        assert.equal(updaterFailure, undefined, `Pyth refresh failed: ${updaterFailure?.message}`);
        console.log('PASS: Solana vault deposit -> proof -> serverd lease via vcii -> MCP call with the issued key -> usage settled to the note -> key refused.');
    } catch (error) {
        console.error(`FAIL: ${error.stack ?? error.message}`);
        process.exitCode = 1;
    } finally {
        if (updater) updater.stop = true;
        for (const child of [...children]) await stop(child);
        for (const server of servers) {
            server.closeAllConnections();
            await new Promise(resolve => server.close(resolve));
        }
        process.off('SIGINT', onSignal);
        process.off('SIGTERM', onSignal);
    }
}

assert.ok(VCII_ZK_BASE && VCII_ZK_MANAGEMENT_KEY, 'set VCII_ZK_BASE and VCII_ZK_MANAGEMENT_KEY');
await main();
