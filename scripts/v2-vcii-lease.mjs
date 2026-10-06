#!/usr/bin/env node
// Real-serverd lease scenario against a running vcii server (instead of the provider mock).
// Real: Anvil vault, indexer, Groth16 wallet proofs, zkapi serverd, its OpenRouterProvisioner talking to vcii /zk/v1/keys,
// settlement. Mock: only the ETH price oracle. See docs/v2-acceptance.md and H:\intel\docscii\ZKAPI.md.
//   VCII_ZK_BASE=http://host:8810/zk VCII_ZK_MANAGEMENT_KEY=... [VCII_BASE=http://host:8810] node scripts/v2-vcii-lease.mjs
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import fs from 'node:fs/promises';
import { createWriteStream } from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import path from 'node:path';
import readline from 'node:readline';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CHAIN_ID = 31337;
const GWEI = 1_000_000_000n;
const DEPOSIT = 1_000_000;
const EXTRA_DEPOSIT = 10_000;
const CAP = 700_000; // gwei per request: ~1.75 USD at the mock price, enough for one 1.5-credit vcii call
const LEASE_TTL_SECONDS = 3600;
const VCII_ZK_BASE = process.env.VCII_ZK_BASE;
const VCII_ZK_MANAGEMENT_KEY = process.env.VCII_ZK_MANAGEMENT_KEY;
const VCII_BASE = process.env.VCII_BASE ?? VCII_ZK_BASE?.replace(/\/zk\/?$/, '');
const MOCK_USAGE_MICRO_USD = 1_000;
const MOCK_PRICE = 250_000_000_000n; // $2,500 / ETH, eight decimal places.
const WITHDRAWAL_TUPLE = 'tuple(uint16,uint64,address,uint256,uint256,uint256,uint256,uint256,uint32,uint128,address,uint256,bool,uint256)';
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const json = value => JSON.stringify(value, (_, v) => typeof v === 'bigint' ? v.toString() : v, 2);
// Explicit agents bypass Node's optional global environment-proxy support.
const localAgent = new http.Agent({ keepAlive: false, proxyEnv: {} });

function loopback(url) {
    const parsed = new URL(url);
    assert.equal(parsed.protocol, 'http:', 'this test permits only loopback HTTP');
    assert.equal(parsed.hostname, '127.0.0.1', 'this test never calls public networks');
    assert.equal(parsed.username + parsed.password, '');
    return parsed;
}

async function body(req) {
    const chunks = [];
    let bytes = 0;
    for await (const chunk of req) {
        bytes += chunk.length;
        assert.ok(bytes < 1_048_576, 'oversized local HTTP request');
        chunks.push(chunk);
    }
    return JSON.parse(Buffer.concat(chunks).toString() || '{}');
}

function respond(res, status, value) {
    res.writeHead(status, { 'content-type': 'application/json' });
    res.end(JSON.stringify(value));
}

export async function localJSON(url, { method = 'GET', value, headers = {} } = {}) {
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

// Exported so the accounting mock itself can be tested without starting the chain.
export function mockProvider(managementKey = 'local-only-management-key') {
    const keys = new Map();
    const events = [];
    let pendingCreateFailures = 0;
    const handler = async (req, res) => {
        try {
            const pathname = new URL(req.url, 'http://127.0.0.1').pathname;
            if (pathname === '/v1/chat/completions' && req.method === 'POST') {
                const key = [...keys.values()].find(k => req.headers.authorization === `Bearer ${k.key}`);
                if (!key || key.disabled || key.deleted || Date.parse(key.expires_at) <= Date.now()) {
                    return respond(res, 401, { error: 'invalid or retired local runtime key' });
                }
                const request = await body(req);
                if (request.model !== 'local/mock-model' || request.max_tokens !== 8 || request.stream !== false
                    || request.messages?.length !== 1 || request.messages[0].role !== 'user'
                    || request.messages[0].content !== 'Reply with the word OK.') {
                    return respond(res, 400, { error: 'unexpected acceptance-test inference request' });
                }
                if (key.usage_micro_usd + MOCK_USAGE_MICRO_USD > Math.floor(key.limit * 1_000_000)) {
                    return respond(res, 402, { error: 'local runtime key spending limit reached' });
                }
                key.usage_micro_usd += MOCK_USAGE_MICRO_USD;
                key.calls += 1;
                events.push({ type: 'inference', hash: key.hash, usage_micro_usd: key.usage_micro_usd });
                return respond(res, 200, { id: `local-${key.calls}`, object: 'chat.completion',
                    choices: [{ index: 0, message: { role: 'assistant', content: 'OK' }, finish_reason: 'stop' }],
                    usage: { prompt_tokens: 6, completion_tokens: 1, total_tokens: 7, cost: MOCK_USAGE_MICRO_USD / 1_000_000 } });
            }
            if (req.headers.authorization !== `Bearer ${managementKey}`) {
                return respond(res, 401, { error: 'local management authentication required' });
            }
            if (pathname === '/v1/keys' && req.method === 'POST') {
                const value = await body(req);
                assert.ok(value.limit > 0 && value.limit <= 1, 'bounded local key limit required');
                assert.equal(value.include_byok_in_limit, true);
                assert.ok(Date.parse(value.expires_at) > Date.now());
                if (pendingCreateFailures > 0) {
                    pendingCreateFailures--;
                    events.push({ type: 'create_failed', name: value.name });
                    return respond(res, 503, { error: 'injected local key creation failure' });
                }
                const hash = randomUUID();
                const key = { ...value, hash, key: `local-runtime-${randomUUID()}`, disabled: false,
                    deleted: false, usage_micro_usd: 0, calls: 0 };
                keys.set(hash, key);
                events.push({ type: 'issued', hash, limit_usd: key.limit });
                return respond(res, 200, { key: key.key, data: { ...value, hash } });
            }
            const match = /^\/v1\/keys\/([0-9a-f-]+)$/.exec(pathname);
            const key = match && keys.get(match[1]);
            if (!key || key.deleted) return respond(res, 404, { error: 'unknown local key' });
            if (req.method === 'PATCH') {
                assert.deepEqual(await body(req), { disabled: true });
                key.disabled = true;
                events.push({ type: 'disabled', hash: key.hash });
            } else if (req.method === 'DELETE') {
                assert.equal(key.disabled, true, 'production settlement must disable before deleting');
                key.deleted = true;
                events.push({ type: 'deleted', hash: key.hash });
                return respond(res, 200, { deleted: true });
            } else if (req.method === 'GET') {
                events.push({ type: 'usage_read', hash: key.hash, usage_micro_usd: key.usage_micro_usd, disabled: key.disabled });
            } else {
                return respond(res, 405, { error: 'unsupported local mock operation' });
            }
            return respond(res, 200, { data: { hash: key.hash, usage: key.usage_micro_usd / 1_000_000,
                byok_usage: 0, disabled: key.disabled } });
        } catch (error) {
            respond(res, 400, { error: error.message });
        }
    };
    return { handler, keys, events, failNextCreate: () => { pendingCreateFailures++; } };
}

function options(args) {
    const parsed = { binDir: path.join(ROOT, 'target/release'), outputDir: path.join(ROOT, '.zkapi/acceptance') };
    for (let i = 0; i < args.length; i++) {
        if (args[i] === '--help') return { help: true };
        const key = { '--bin-dir': 'binDir', '--output-dir': 'outputDir' }[args[i]];
        assert.ok(key && args[i + 1], `Unknown or incomplete option: ${args[i]}`);
        parsed[key] = path.resolve(args[++i]);
    }
    return parsed;
}

function linkBytecode(artifact, addresses) {
    let bytecode = artifact.bytecode.object;
    for (const [source, libraries] of Object.entries(artifact.bytecode.linkReferences ?? {})) {
        for (const [name, references] of Object.entries(libraries)) {
            const address = addresses[`${source}:${name}`];
            assert.match(address ?? '', /^0x[0-9a-fA-F]{40}$/);
            for (const ref of references) {
                assert.equal(ref.length, 20);
                const offset = 2 + ref.start * 2;
                bytecode = bytecode.slice(0, offset) + address.slice(2).toLowerCase() + bytecode.slice(offset + 40);
            }
        }
    }
    assert.match(bytecode, /^0x[0-9a-fA-F]+$/, 'unlinked Solidity library');
    return bytecode;
}

async function main() {
    const opts = options(process.argv.slice(2));
    if (opts.help) {
        console.log('Usage: node scripts/v2-acceptance.mjs [--bin-dir target/release] [--output-dir .zkapi/acceptance]\nRuns only disposable loopback services, with mock provider and oracle. See docs/v2-acceptance.md.');
        return;
    }
    const { AbiCoder, Contract, ContractFactory, FetchRequest, JsonRpcProvider } = await import(
        pathToFileURL(path.join(ROOT, 'docker/aws/signer/node_modules/ethers/lib.esm/index.js')).href);
    const coder = AbiCoder.defaultAbiCoder();
    const started = Date.now();
    const runDir = path.join(opts.outputDir, `${new Date().toISOString().replaceAll(':', '-')}-${randomUUID().slice(0, 8)}`);
    await fs.mkdir(runDir, { recursive: true, mode: 0o700 });
    await fs.chmod(runDir, 0o700);
    const readJSON = async p => JSON.parse(await fs.readFile(p, 'utf8'));
    const save = (name, value) => fs.writeFile(path.join(runDir, name), json(value), { mode: 0o600 });
    const children = new Set();
    const servers = new Set();
    let provider;
    let interrupted = false;
    const onSignal = () => {
        interrupted = true;
        for (const child of children) child.kill('SIGINT');
    };
    process.on('SIGINT', onSignal);
    process.on('SIGTERM', onSignal);
    const check = () => { if (interrupted) throw new Error('Local acceptance test interrupted'); };
    async function waitFor(label, fn, timeout = 30_000) {
        const end = Date.now() + timeout;
        let last;
        while (Date.now() < end) {
            check();
            try { const value = await fn(); if (value) return value; } catch (error) { last = error; }
            await delay(100);
        }
        throw new Error(`Timeout: ${label}${last ? ` (${last.message})` : ''}`);
    }
    function launch(command, args, log, interactive = false) {
        check();
        const out = createWriteStream(path.join(runDir, log), { flags: 'a', mode: 0o600 });
        // No inherited credentials, network proxies, HOME, or provider settings.
        const child = spawn(command, args, { cwd: ROOT, env: { PATH: process.env.PATH,
            RUST_LOG: 'warn,zkapi=info,zkapi_serverd=info,zkapi_indexerd=info,r1cs=warn' },
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
        await Promise.race([done, delay(2000)]);
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
    async function serve(handler) {
        const server = http.createServer((req, res) => Promise.resolve(handler(req, res)).catch(error => respond(res, 500, { error: error.message })));
        await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
        servers.add(server);
        return `http://127.0.0.1:${server.address().port}`;
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
    function wallet(name) {
        const child = launch(path.join(opts.binDir, 'examples/v2_acceptance_wallet'), [path.join(ROOT, 'protocol/setup/v2')], `${name}-wallet.log`, true);
        const lines = readline.createInterface({ input: child.stdout });
        let nextId = 0;
        const pending = new Map();
        const rejectAll = error => { for (const item of pending.values()) item.reject(error); pending.clear(); };
        lines.on('line', line => {
            try {
                const response = JSON.parse(line);
                const item = pending.get(response.id);
                assert.ok(item, 'unexpected wallet response');
                pending.delete(response.id);
                if (response.ok) item.resolve(response.result);
                else item.reject(new Error(`Wallet ${item.command}: ${response.error}`));
            } catch (error) { rejectAll(error); }
        });
        child.once('error', rejectAll);
        child.once('close', code => rejectAll(new Error(`Wallet helper exited (${code})`)));
        return async (command, data = {}) => {
            check();
            const id = ++nextId;
            return new Promise((resolve, reject) => {
                const timer = setTimeout(() => { pending.delete(id); reject(new Error(`Wallet ${command} timed out`)); }, 120_000);
                pending.set(id, { command, resolve: value => { clearTimeout(timer); resolve(value); }, reject: error => { clearTimeout(timer); reject(error); } });
                child.stdin.write(JSON.stringify({ id, command, ...data }) + '\n');
            });
        };
    }

    try {
        console.log('Starting local v2 acceptance: real proofs and services, mock provider and oracle.');
        const client = wallet('primary');
        const signingKeys = await client('public_keys');
        assert.equal(signingKeys.circuit_id, 'zkapi-v2-note-bound-v1');
        const port = await freePort();
        const rpcUrl = `http://127.0.0.1:${port}`;
        launch('anvil', ['--host', '127.0.0.1', '--port', String(port), '--chain-id', String(CHAIN_ID),
            '--mnemonic', 'test test test test test test test test test test test junk', '--silent'], 'anvil.log');
        await waitFor('Anvil startup', async () => await rpc(rpcUrl, 'eth_chainId') === '0x7a69');
        const ethersRpc = new FetchRequest(rpcUrl);
        const getLocalUrl = FetchRequest.createGetUrlFunc({ agent: localAgent });
        ethersRpc.getUrlFunc = (req, signal) => { loopback(req.url); return getLocalUrl(req, signal); };
        provider = new JsonRpcProvider(ethersRpc, CHAIN_ID, { staticNetwork: true, cacheTimeout: -1 });
        const accounts = await rpc(rpcUrl, 'eth_accounts');
        const signer = await provider.getSigner(accounts[0]);
        const challengerAccount = accounts[1];
        const destination = accounts[2];
        const treasury = accounts[3];
        const artifact = name => readJSON(path.join(ROOT, `protocol/contracts/out/${name}.sol/${name}.json`));
        const poseidonArtifact = await artifact('Bn254Poseidon');
        const adapterArtifact = await artifact('Groth16ProofAdapter');
        const vaultArtifact = await artifact('ZkApiVault');
        const poseidon = await new ContractFactory(poseidonArtifact.abi, linkBytecode(poseidonArtifact, {}), signer).deploy();
        await poseidon.waitForDeployment();
        const adapter = await new ContractFactory(adapterArtifact.abi, linkBytecode(adapterArtifact, {}), signer).deploy();
        await adapter.waitForDeployment();
        const deployed = await new ContractFactory(vaultArtifact.abi, linkBytecode(vaultArtifact,
            { 'src/libraries/Bn254Poseidon.sol:Bn254Poseidon': await poseidon.getAddress() }), signer).deploy(
            treasury, 30 * 86400, 86400, CAP, await adapter.getAddress(), signingKeys.state_signing_key.x,
            signingKeys.state_signing_key.y, signingKeys.clearance_signing_key.x, signingKeys.clearance_signing_key.y, accounts[0]);
        const deployment = await deployed.deploymentTransaction().wait();
        const vaultAddress = await deployed.getAddress();
        const vault = new Contract(vaultAddress, vaultArtifact.abi, signer);
        const usedNullifierCall = new RegExp(`^${vault.interface.getFunction('usedNullifiers').selector}[0-9a-fA-F]{64}$`);
        assert.equal(await vault.challengePeriod(), 86400n);
        const config = { protocol_version: 2, chain_id: CHAIN_ID, contract_address: vaultAddress,
            request_charge_cap: CAP, policy_charge_cap: 0, policy_enabled: false,
            state_signing_key: signingKeys.state_signing_key, clearance_signing_key: signingKeys.clearance_signing_key };
        await client('init', { config });
        const indexerPort = await freePort();
        const indexerUrl = `http://127.0.0.1:${indexerPort}`;
        launch(path.join(opts.binDir, 'zkapi-indexerd'), ['--listen', `127.0.0.1:${indexerPort}`, '--rpc-url', rpcUrl,
            '--contract-address', vaultAddress, '--from-block', String(deployment.blockNumber), '--poll-interval-ms', '100',
            '--cursor-path', path.join(runDir, 'indexer.json')], 'indexer.log');
        async function synchronizedTree() {
            const chainRoot = await vault.currentRoot();
            return waitFor('indexer root matches actual chain', async () => {
                const snapshot = await get(`${indexerUrl}/v1/tree/snapshot`);
                return BigInt(snapshot.root) === chainRoot && snapshot;
            });
        }
        async function treePath(walletClient, noteId, requireExisting = true) {
            return walletClient('tree_path', { args: { snapshot: await synchronizedTree(), note_id: noteId, require_existing: requireExisting } });
        }
        async function deposit(walletClient, amount) {
            const snapshot = await synchronizedTree();
            const params = await walletClient('deposit_params');
            const merkle = await walletClient('tree_path', { args: { snapshot, note_id: snapshot.next_note_id, require_existing: false } });
            const commitment = `0x${BigInt(params.registration_commitment).toString(16).padStart(64, '0')}`;
            const receipt = await (await vault.deposit(commitment, amount, merkle.siblings, { value: BigInt(amount) * GWEI })).wait();
            const noteId = snapshot.next_note_id;
            const note = await vault.notes(noteId);
            assert.equal(note[1], BigInt(amount)); assert.equal(note[3], 1n);
            const status = await walletClient('confirm_deposit', { args: { note_id: noteId, amount, expiry_ts: Number(note[2]) } });
            await synchronizedTree();
            return { noteId, receipt, status };
        }
        const primary = await deposit(client, DEPOSIT);
        assert.equal(primary.noteId, 0);
        assert.equal(primary.status.state.note.is_genesis, true);
        assert.equal(primary.status.state.note.current_balance, DEPOSIT);
        await save('deposit-receipt.json', primary.receipt);
        console.log('Deposited a fresh genesis note; starting the actual HTTP protocol server.');
        const feed = '0x0000000000000000000000000000000000001234';
        const quoteTimestamp = Math.floor(Date.now() / 1000) - 1;
        const oracleUrl = await serve(async (req, res) => {
            const call = await body(req);
            const target = call.params?.[0];
            let result;
            if (call.method === 'eth_call' && target?.to?.toLowerCase() === feed) {
                if (target.data === '0x313ce567') result = coder.encode(['uint256'], [8]);
                else {
                    assert.equal(call.params[1], 'finalized', 'oracle rounds must use finalized reads');
                    assert.ok(target.data === '0xfeaf968c' || target.data === `0x9a6fc8f5${(123n).toString(16).padStart(64, '0')}`);
                    result = coder.encode(['uint80', 'int256', 'uint256', 'uint256', 'uint80'], [123, MOCK_PRICE, quoteTimestamp, quoteTimestamp, 123]);
                }
            } else {
                const vaultRead = call.method === 'eth_call' && target?.to?.toLowerCase() === vaultAddress.toLowerCase()
                    && (target.data === '0x4d1352fd' || usedNullifierCall.test(target.data));
                assert.ok(call.method === 'eth_chainId' || vaultRead, 'unexpected oracle RPC read');
                if (vaultRead) assert.equal(call.params[1], 'latest', 'vault authorization must use the current chain state');
                result = await rpc(rpcUrl, call.method, call.params);
            }
            respond(res, 200, { jsonrpc: '2.0', id: call.id, result });
        });
        const serverPort = await freePort();
        const serverUrl = `http://127.0.0.1:${serverPort}`;
        const dbPath = path.join(runDir, 'server.db');
        launch(path.join(opts.binDir, 'zkapi'), ['--chain-id', String(CHAIN_ID), '--contract-address', vaultAddress,
            '--request-charge-cap', String(CAP), '--proof-setup-dir', path.join(ROOT, 'protocol/setup/v2'), 'serverd',
            '--listen', `127.0.0.1:${serverPort}`, '--openrouter-api-base', VCII_ZK_BASE,
            '--openrouter-management-key', VCII_ZK_MANAGEMENT_KEY, '--openrouter-lease-ttl-seconds', String(LEASE_TTL_SECONDS),
            '--openrouter-settlement-grace-seconds', '1', '--openrouter-settlement-poll-seconds', '1',
            '--native-billing-rpc-url', oracleUrl, '--native-price-feed-address', feed,
            '--db-path', dbPath, '--state-seed', '0x1', '--clear-seed', '0x2', '--indexer-url', indexerUrl,
            '--root-poll-interval-ms', '100'], 'server.log');
        await waitFor('actual server ready at chain root', async () => BigInt((await get(`${serverUrl}/health`)).current_root) === await vault.currentRoot());
        assert.deepEqual((await get(`${serverUrl}/v1/attestation`)).state_signing_key, signingKeys.state_signing_key);
        const settlements = [];

        async function mcpCall(key, tool) {
            const res = await fetch(`${VCII_BASE}/mcp`, { method: 'POST', headers: { authorization: `Bearer ${key}`,
                accept: 'application/json, text/event-stream', 'content-type': 'application/json' },
                body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: tool, arguments: {} } }) });
            return { status: res.status, text: (await res.text()).slice(0, 400) };
        }
        const label = 'vcii';
        const merkle = await treePath(client, primary.noteId);
        const quote = await get(`${serverUrl}/v2/billing/quote`);
        const payload = JSON.stringify({ mode: 'openrouter_ephemeral_lease', version: 1, billing_quote: quote });
        const id = `vcii-${randomUUID()}`;
        const prepared = await client('prepare_request', { args: { payload, active_root: merkle.active_root,
            merkle_siblings: merkle.siblings, client_request_id: id, request_time: Math.floor(Date.now() / 1000), created_at_ms: Date.now() } });
        const issuedAt = Math.floor(Date.now() / 1000);
        const issued = await request(`${serverUrl}/v2/openrouter/leases`, { method: 'POST', value: prepared.request });
        assert.equal(issued.status, 201, `lease rejected: ${issued.value.error_code ?? issued.status}`);
        const lease = issued.value;
        assert.match(lease.api_key, /^vcii_zk_/, 'serverd must hand back the key minted by vcii');
        const { api_key: _redacted, ...leaseMeta } = lease;
        console.log('LEASE (key redacted):', JSON.stringify(leaseMeta));
        console.log(`lease key length ${lease.api_key.length}; expires_at - issued ~ ${lease.expires_at - issuedAt}s (serverd --openrouter-lease-ttl-seconds ${LEASE_TTL_SECONDS})`);
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
        }, 60_000);
        const response = recovery.request_response;
        console.log('SETTLEMENT: charge_applied (gwei) =', response.charge_applied, 'response_payload =', response.response_payload);
        assert.equal(JSON.parse(response.response_payload).usage_usd, 1.5, 'vcii usage (1 credit x 1.5 USD) must reach the settled charge');
        const completed = await client('complete_response', { response });
        assert.equal(completed.pending_request, false);
        const after = await mcpCall(lease.api_key, 'market_pulse');
        console.log(`after settlement the key is refused: HTTP ${after.status}`);
        assert.equal(after.status, 401);
        console.log('PASS: real serverd + real proof + vcii lease provisioning, MCP call with the issued key, usage settled to the note.');
    } catch (error) {
        console.error(`FAIL: ${error.message}`);
        process.exitCode = 1;
    } finally {
        provider?.destroy();
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
