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
// Needs Linux with Node 24 and Agave (solana-test-validator). Loopback only.
//   VCII_ZK_BASE=http://127.0.0.1:8813/zk VCII_ZK_MANAGEMENT_KEY=... node scripts/solana-vcii-lease.mjs \
//     --bin-dir /target/sol-host/release --sbf-dir /target/sbf --key-dir /scratch --output-dir .zkapi/solana-acceptance
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import fs from 'node:fs/promises';
import { createWriteStream } from 'node:fs';
import http from 'node:http';
import net from 'node:net';
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
        refreshMs: 400, scenario: 'steady',
    };
    for (let i = 0; i < args.length; i++) {
        if (args[i] === '--help') return { help: true };
        const key = { '--bin-dir': 'binDir', '--sbf-dir': 'sbfDir', '--key-dir': 'keyDir', '--output-dir': 'outputDir',
            '--refresh-ms': 'refreshMs', '--scenario': 'scenario' }[args[i]];
        assert.ok(key && args[i + 1], `Unknown or incomplete option: ${args[i]}`);
        if (key === 'refreshMs') parsed[key] = Number(args[++i]);
        else if (key === 'scenario') parsed[key] = args[++i];
        else parsed[key] = path.resolve(args[++i]);
    }
    assert.ok(Number.isSafeInteger(parsed.refreshMs) && parsed.refreshMs >= 100, '--refresh-ms must be >= 100');
    assert.ok(['steady', 'jump'].includes(parsed.scenario), '--scenario must be steady or jump');
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
        console.log('Usage: VCII_ZK_BASE=... VCII_ZK_MANAGEMENT_KEY=... node scripts/solana-vcii-lease.mjs [--bin-dir D] [--sbf-dir D] [--key-dir D] [--output-dir D] [--refresh-ms 400] [--scenario steady|jump]\n'
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
        if (!interactive) child.stdout.pipe(out);
        child.stderr.pipe(out);
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
        const child = launch(path.join(opts.binDir, 'examples/solana_acceptance_wallet'), [path.join(ROOT, 'protocol/setup/v2')],
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
        const portBase = 20_000 + Math.floor(Math.random() * 900) * 10;
        launch('solana-test-validator', ['--reset', '--quiet', '--ledger', path.join('/tmp', `zksol-ledger-${randomUUID().slice(0, 8)}`),
            '--bind-address', '127.0.0.1', '--rpc-port', String(rpcPort), '--faucet-port', String(faucetPort),
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
        const primary = await wallet('deposit', { amount: DEPOSIT });
        assert.equal(primary.state.note.current_balance, DEPOSIT);
        assert.equal(primary.state.note.is_genesis, true);
        // The finalized indexer trails the chain by a few seconds; the ledger refuses a snapshot that disagrees with the vault.
        const afterDeposit = await waitFor('indexer catches up with the deposit', async () => wallet('vault_snapshot'), 120_000);
        assert.equal(afterDeposit.next_note_id, 1);
        assert.ok(BigInt(afterDeposit.vault_lamports) >= BigInt(DEPOSIT), 'vault must hold the deposited lamports');
        console.log(`deposited ${DEPOSIT} lamports into the Solana vault (finalized); vault now holds ${afterDeposit.vault_lamports} lamports (incl. rent)`);

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
