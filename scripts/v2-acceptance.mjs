#!/usr/bin/env node
// Entirely local acceptance test. The provider and price feed are explicit mocks;
// wallet cryptography, HTTP server, SQLite archive, indexer, vault and challenger are real.
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
// Use a signer-supported chain ID on a disposable, unforked loopback chain.
const CHAIN_ID = 11155111;
const GWEI = 1_000_000_000n;
const DEPOSIT = 1_000_000;
const EXTRA_DEPOSIT = 10_000;
const CAP = 50_000;
const MOCK_USAGE_MICRO_USD = 1_000;
const MOCK_PRICE = 250_000_000_000n; // $2,500 / ETH, eight decimal places.
// Types.WithdrawalPublicInputs: leaf-bound, root-free exits (concession exit).
// 0 version, 1 chain, 2 vault, 3 registration, 4-7 keys, 8 noteId, 9 deposit,
// 10 expiry, 11 finalBalance, 12 destination, 13 N, 14 hasClearance, 15 N⁺,
// 16 conceded, 17 validUntil.
const WITHDRAWAL_TUPLE = 'tuple(uint16,uint64,address,uint256,uint256,uint256,uint256,uint256,uint32,uint128,uint64,uint128,address,uint256,bool,uint256,uint128,uint64)';
const CHALLENGE_PERIOD = 86400;
const EXIT_PROOF_TTL = 3 * 3600;
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
    const parsed = { binDir: path.join(ROOT, 'target/release'), outputDir: path.join(ROOT, '.zkapi/acceptance'),
        adversaryBin: path.join(ROOT, 'target/adversary/debug/dagon-zkapi') };
    for (let i = 0; i < args.length; i++) {
        if (args[i] === '--help') return { help: true };
        const key = { '--bin-dir': 'binDir', '--output-dir': 'outputDir', '--adversary-bin': 'adversaryBin' }[args[i]];
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
        console.log('Usage: node scripts/v2-acceptance.mjs [--bin-dir target/release] [--adversary-bin target/adversary/debug/dagon-zkapi] [--output-dir .zkapi/acceptance]\nRuns only disposable loopback services, with mock provider and oracle. See docs/v2-acceptance.md.');
        return;
    }
    const { AbiCoder, Contract, ContractFactory, FetchRequest, HDNodeWallet, JsonRpcProvider } = await import(
        pathToFileURL(path.join(ROOT, 'docker/aws/signer/node_modules/ethers/lib.esm/index.js')).href);
    const { createSigner } = await import('../docker/aws/signer/signer.mjs');
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
        assert.equal(signingKeys.circuit_id, 'zkapi-v2-concession-v1');
        const port = await freePort();
        const rpcUrl = `http://127.0.0.1:${port}`;
        launch('anvil', ['--host', '127.0.0.1', '--port', String(port), '--chain-id', String(CHAIN_ID),
            '--mnemonic', 'test test test test test test test test test test test junk', '--silent'], 'anvil.log');
        await waitFor('Anvil startup', async () => await rpc(rpcUrl, 'eth_chainId') === `0x${CHAIN_ID.toString(16)}`);
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
            treasury, 30 * 86400, CHALLENGE_PERIOD, CAP, await adapter.getAddress(), signingKeys.state_signing_key.x,
            signingKeys.state_signing_key.y, signingKeys.clearance_signing_key.x, signingKeys.clearance_signing_key.y, accounts[0]);
        const deployment = await deployed.deploymentTransaction().wait();
        const vaultAddress = await deployed.getAddress();
        const vault = new Contract(vaultAddress, vaultArtifact.abi, signer);
        const usedNullifierCall = new RegExp(`^${vault.interface.getFunction('usedNullifiers').selector}[0-9a-fA-F]{64}$`);
        const currentRootCall = vault.interface.getFunction('currentRoot').selector;
        const nextNoteIdCall = vault.interface.getFunction('nextNoteId').selector;
        const challengePeriodCall = vault.interface.getFunction('challengePeriod').selector;
        assert.equal(await vault.challengePeriod(), BigInt(CHALLENGE_PERIOD));
        const config = { protocol_version: 2, chain_id: CHAIN_ID, contract_address: vaultAddress,
            request_charge_cap: CAP, policy_charge_cap: 0, policy_enabled: false,
            state_signing_key: signingKeys.state_signing_key, clearance_signing_key: signingKeys.clearance_signing_key };
        await client('init', { config });
        const indexerPort = await freePort();
        const indexerUrl = `http://127.0.0.1:${indexerPort}`;
        launch(path.join(opts.binDir, 'dagon-zkapi-indexerd'), ['--listen', `127.0.0.1:${indexerPort}`, '--ledger', 'ethereum', '--rpc-url', rpcUrl,
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
        const mock = mockProvider();
        const providerUrl = await serve(mock.handler);
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
                const toVault = call.method === 'eth_call' && target?.to?.toLowerCase() === vaultAddress.toLowerCase();
                const vaultRead = toVault && (target.data === '0x4d1352fd' || usedNullifierCall.test(target.data));
                // The server's credit ledger also refreshes the root through this RPC.
                const rootRead = toVault && (target.data === currentRootCall || target.data === nextNoteIdCall);
                // Startup checks --challenge-period-seconds against the vault.
                const periodRead = toVault && target.data === challengePeriodCall;
                assert.ok(call.method === 'eth_chainId' || vaultRead || rootRead || periodRead, 'unexpected oracle RPC read');
                if (vaultRead) assert.equal(call.params[1], 'latest', 'vault authorization must use the current chain state');
                result = await rpc(rpcUrl, call.method, call.params);
            }
            respond(res, 200, { jsonrpc: '2.0', id: call.id, result });
        });
        // An honest server, and (later) a test-only server built with the
        // `adversary` feature that settles requests but withholds every successor.
        async function startServer(name, binary, extra = []) {
            const port = await freePort();
            const url = `http://127.0.0.1:${port}`;
            const db = path.join(runDir, `${name}.db`);
            const child = launch(binary, ['--chain-id', String(CHAIN_ID), '--contract-address', vaultAddress,
                '--request-charge-cap', String(CAP), '--proof-setup-dir', path.join(ROOT, 'protocol/setup/v2'), 'serverd',
                '--ledger', 'evm',
                '--listen', `127.0.0.1:${port}`, '--openrouter-api-base', providerUrl,
                '--openrouter-management-key', 'local-only-management-key', '--openrouter-lease-ttl-seconds', '300',
                '--openrouter-settlement-grace-seconds', '1', '--openrouter-settlement-poll-seconds', '1',
                '--native-billing-rpc-url', oracleUrl, '--native-price-feed-address', feed,
                '--db-path', db, '--state-seed', '0x1', '--clear-seed', '0x2', '--indexer-url', indexerUrl,
                '--root-poll-interval-ms', '100', ...extra], `${name}.log`);
            await waitFor(`${name} ready at chain root`, async () => BigInt((await get(`${url}/health`)).current_root) === await vault.currentRoot());
            return { url, db, child };
        }
        const { url: serverUrl, db: dbPath } = await startServer('server', path.join(opts.binDir, 'dagon-zkapi'));
        assert.deepEqual((await get(`${serverUrl}/v1/attestation`)).state_signing_key, signingKeys.state_signing_key);
        const settlements = [];
        const expectedCharge = Number((BigInt(MOCK_USAGE_MICRO_USD) * 1_000_000_000n * 100_000_000n + MOCK_PRICE * 1_000_000n - 1n)
            / (MOCK_PRICE * 1_000_000n));
        // A real request through the HTTP server, used and retired; returns once
        // the server settled it. A withholding server never signs the successor.
        async function requestAndSettle(label, walletClient, noteId, url) {
            const merkle = await treePath(walletClient, noteId);
            const quote = await get(`${url}/v2/billing/quote`);
            const payload = JSON.stringify({ mode: 'openrouter_ephemeral_lease', version: 1, billing_quote: quote });
            const id = `acceptance-${label}-${randomUUID()}`;
            const prepared = await walletClient('prepare_request', { args: { payload, active_root: merkle.active_root,
                merkle_siblings: merkle.siblings, client_request_id: id, request_time: Math.floor(Date.now() / 1000), created_at_ms: Date.now() } });
            const issued = await request(`${url}/v2/openrouter/leases`, { method: 'POST', value: prepared.request });
            assert.equal(issued.status, 201, `lease rejected: ${issued.value.error_code ?? issued.status}`);
            const lease = issued.value;
            const key = [...mock.keys.values()].find(k => k.key === lease.api_key);
            assert.ok(key);
            const inference = await request(`${lease.openrouter_api_base}/chat/completions`, { method: 'POST',
                headers: { authorization: `Bearer ${lease.api_key}` }, value: { model: 'local/mock-model',
                    messages: [{ role: 'user', content: 'Reply with the word OK.' }], max_tokens: 8, stream: false } });
            assert.equal(inference.status, 200);
            const retired = await request(`${url}/v2/openrouter/leases/${id}`, { method: 'POST', value: prepared.request });
            assert.ok(retired.status === 200 || (retired.status === 409 && retired.value.error_code === 'lease_settlement_pending'));
            const settled = await waitFor('settled lease charge', async () => {
                const status = await get(`${url}/v2/openrouter/leases/${id}`);
                return status.status === 'finalized' && status.charge_applied != null && status;
            });
            assert.equal(Number(settled.charge_applied), expectedCharge);
            return { id, prepared, settled };
        }
        async function inferenceAndSettlement(label) {
            const merkle = await treePath(client, primary.noteId);
            const quote = await get(`${serverUrl}/v2/billing/quote`);
            const payload = JSON.stringify({ mode: 'openrouter_ephemeral_lease', version: 1, billing_quote: quote });
            const id = `acceptance-${label}-${randomUUID()}`;
            const prepared = await client('prepare_request', { args: { payload, active_root: merkle.active_root,
                merkle_siblings: merkle.siblings, client_request_id: id, request_time: Math.floor(Date.now() / 1000), created_at_ms: Date.now() } });
            const issued = await request(`${serverUrl}/v2/openrouter/leases`, { method: 'POST', value: prepared.request });
            assert.equal(issued.status, 201, `lease rejected: ${issued.value.error_code ?? issued.status}`);
            const lease = issued.value;
            assert.equal(lease.openrouter_api_base, `${providerUrl}/v1`);
            assert.equal(lease.key_source, 'openrouter');
            const key = [...mock.keys.values()].find(k => k.key === lease.api_key);
            assert.ok(key); assert.equal(key.usage_micro_usd, 0);
            const issuedCount = mock.keys.size;
            const replay = await request(`${serverUrl}/v2/openrouter/leases`, { method: 'POST', value: prepared.request });
            assert.equal(replay.status, 409, 'active lease replay must not mint another runtime key');
            assert.equal(mock.keys.size, issuedCount);
            const inference = await request(`${lease.openrouter_api_base}/chat/completions`, { method: 'POST',
                headers: { authorization: `Bearer ${lease.api_key}` }, value: { model: 'local/mock-model',
                    messages: [{ role: 'user', content: 'Reply with the word OK.' }], max_tokens: 8, stream: false } });
            assert.equal(inference.status, 200); assert.equal(inference.value.choices[0].message.content, 'OK');
            assert.equal(key.calls, 1); assert.equal(key.usage_micro_usd, MOCK_USAGE_MICRO_USD);
            const retired = await request(`${serverUrl}/v2/openrouter/leases/${id}`, { method: 'POST', value: prepared.request });
            assert.ok(retired.status === 200 || (retired.status === 409 && retired.value.error_code === 'lease_settlement_pending'),
                `retirement failed: ${retired.status}/${retired.value.error_code}`);
            const recovery = await waitFor('cryptographic usage settlement from HTTP recovery', async () => {
                const found = await get(`${serverUrl}/v2/requests/${id}`);
                return found.request_response && found;
            });
            const response = recovery.request_response;
            assert.equal(response.charge_applied, expectedCharge);
            assert.equal(JSON.parse(response.response_payload).usage_usd, MOCK_USAGE_MICRO_USD / 1_000_000);
            assert.equal(key.disabled, true); assert.equal(key.deleted, true);
            assert.deepEqual(mock.events.filter(event => event.hash === key.hash).map(event => event.type),
                ['issued', 'inference', 'disabled', 'usage_read', 'deleted']);
            const beforeTamper = await client('status');
            const tampered = structuredClone(response);
            tampered.next_state_signature.s = `0x${(BigInt(tampered.next_state_signature.s) ^ 1n).toString(16)}`;
            await assert.rejects(client('complete_response', { response: tampered }), /signature/i,
                'client must reject a forged state signature');
            assert.deepEqual(await client('status'), beforeTamper, 'failed completion must preserve wallet and pending journal');
            const completed = await client('complete_response', { response });
            assert.equal(completed.pending_request, false);
            assert.equal(completed.state.note.is_genesis, false);
            const record = { label, client_request_id: id, request_nullifier: prepared.request.public_inputs.request_nullifier,
                archived_root: prepared.request.public_inputs.active_root, provider_calls: key.calls,
                provider_usage_micro_usd: key.usage_micro_usd, charge_gwei: expectedCharge, state: completed,
                verified_signed_settlement: true, tampered_signature_rejected_without_state_change: true,
                active_lease_replay_did_not_mint_key: true, runtime_key_revoked: key.deleted };
            settlements.push(record);
            await save(`${label}-settlement.json`, { ...record, response });
            return { request: prepared.request, response, record };
        }
        const balance = address => rpc(rpcUrl, 'eth_getBalance', [address, 'latest']).then(BigInt);
        const chainNow = async () => Number((await provider.getBlock('latest')).timestamp);
        const validUntil = async () => (await chainNow()) + EXIT_PROOF_TTL;
        const escapeArgs = async (conceded = 0) => ({ mode: 'escape', destination, conceded: String(conceded), valid_until: String(await validUntil()) });
        const decodeInputs = plan => [...coder.decode([WITHDRAWAL_TUPLE], plan.inputs_abi)[0]];
        const parsedLogs = (receipt, name) => receipt.logs.map(log => {
            try { return vault.interface.parseLog(log); } catch { return null; }
        }).filter(event => event?.name === name);
        async function reverts(promise, errorName) {
            await assert.rejects(promise, error => {
                const data = error?.data ?? error?.info?.error?.data ?? error?.error?.data;
                const decoded = data ? vault.interface.parseError(data) : null;
                assert.equal(decoded?.name, errorName, `expected ${errorName}, got ${decoded?.name ?? error.shortMessage ?? error.message}`);
                return true;
            });
        }
        async function advance(seconds) {
            await rpc(rpcUrl, 'evm_increaseTime', [seconds]);
            await rpc(rpcUrl, 'anvil_mine', ['0x1']);
        }
        const requestTuple = inputs => [inputs.protocol_version, inputs.chain_id, inputs.contract_address, inputs.active_root,
            inputs.state_signing_key_x, inputs.state_signing_key_y, inputs.request_time, inputs.solvency_bound,
            inputs.request_nullifier, inputs.authorization_tag, inputs.anonymous_commitment_x, inputs.anonymous_commitment_y].map(BigInt);
        const proofHex = request => `0x${Buffer.from(request.proof.proof, 'base64').toString('hex')}`;
        // Close, finalize and the expiry sweep accrue the operator share in the
        // vault (gwei units); anyone pays it out with withdrawTreasury().
        const owed = () => vault.treasuryAccrued();

        // ---- Honest history S0 -> S1 -> S2 -> S3 on the primary note ----
        await client('snapshot', { name: 'S0' });
        const first = await inferenceAndSettlement('first');
        await client('snapshot', { name: 'S1' });
        const second = await inferenceAndSettlement('second');
        await client('snapshot', { name: 'S2' });
        const third = await inferenceAndSettlement('third');
        console.log('Three real settlements S0 -> S3; now a stale escape from S1 with a front-running deposit.');
        const N = settlement => BigInt(settlement.request.public_inputs.request_nullifier);
        const B = index => DEPOSIT - settlements.slice(0, index).reduce((sum, item) => sum + item.charge_gwei, 0);
        const extraClient = wallet('unrelated');
        await extraClient('init', { config });

        // ---- Stale escape from S1 (spent: S2 was spent by the third request) is defeated ----
        const stale = await client('prepare_withdrawal', { snapshot: 'S1', args: await escapeArgs(0) });
        const staleInputs = decodeInputs(stale);
        assert.equal(staleInputs[11], BigInt(B(1)));
        assert.equal(staleInputs[13], N(second), 'escape nullifier is the one the second request spent');
        assert.equal(staleInputs[15], N(third), 'successor nullifier is the one the third request spent');
        assert.equal(staleInputs[16], 0n);
        // Front-run: a deposit lands between proving and initiation. Exits are
        // leaf-bound, so the root change cannot invalidate the escape.
        const rootBefore = await vault.currentRoot();
        const unrelated = await deposit(extraClient, EXTRA_DEPOSIT);
        assert.notEqual(await vault.currentRoot(), rootBefore);
        const balances = { vault: await balance(vaultAddress), destination: await balance(destination), treasury: await owed() };
        const initiated = await (await vault.initiateEscapeWithdrawal(staleInputs, stale.proof_hex)).wait();
        await save('stale-escape-initiation-receipt.json', initiated);
        let pending = await vault.pendingWithdrawals(primary.noteId);
        assert.equal(pending[0], true);
        assert.equal(pending[2], N(third));
        assert.equal(await vault.nullifierState(N(second)), 1n);
        assert.equal(await vault.nullifierState(N(third)), 1n);
        await assert.rejects(vault.finalizeEscapeWithdrawal.staticCall(primary.noteId), 'an escape waits its challenge period');
        await rpc(rpcUrl, 'anvil_mine', ['0x2']);
        console.log('Starting the challenger on the honest server archive.');
        const challengeTxs = [];
        // The production signer, not Anvil's unlocked sendTransaction path,
        // must accept every daemon read and sign each real challenge.
        const challengeKey = HDNodeWallet.fromPhrase(
            'test test test test test test test test test test test junk', undefined, "m/44'/60'/0'/0/1");
        const challengeSigner = createSigner({
            privateKey: challengeKey.privateKey, vault: vaultAddress, chainId: BigInt(CHAIN_ID),
            rpc: (method, params) => rpc(rpcUrl, method, params),
        });
        assert.equal(challengeSigner.sender, challengerAccount.toLowerCase());
        const challengerRpc = await serve(async (req, res) => {
            const call = await body(req);
            if (call.method === 'eth_sendTransaction') {
                const tx = call.params[0];
                assert.equal(tx.from.toLowerCase(), challengerAccount.toLowerCase());
                assert.equal(tx.to.toLowerCase(), vaultAddress.toLowerCase());
                assert.equal(tx.value ?? '0x0', '0x0');
                assert.ok(['challengeEscapeWithdrawal', 'raiseEscapeConcession'].includes(vault.interface.parseTransaction(tx).name));
            }
            try {
                const result = await challengeSigner.handle(call.method, call.params);
                if (call.method === 'eth_sendTransaction') challengeTxs.push(result);
                respond(res, 200, { jsonrpc: '2.0', id: call.id, result });
            } catch (error) {
                respond(res, 200, { jsonrpc: '2.0', id: call.id, error: { code: -32000, message: error.message } });
            }
        });
        const checkpoint = path.join(runDir, 'challenger.json');
        const challenger = launch(path.join(opts.binDir, 'dagon-zkapi-challenged'), ['--ledger', 'evm', '--rpc-url', challengerRpc,
            '--sender', challengerAccount, '--chain-id', String(CHAIN_ID),
            '--contract-address', vaultAddress, '--from-block', String(deployment.blockNumber), '--confirmations', '2',
            '--db-path', dbPath, '--checkpoint', checkpoint, '--proof-setup-dir', path.join(ROOT, 'protocol/setup/v2'),
            '--poll-interval-ms', '100'], 'challenger.log');
        const minedChallengerTx = async index => {
            const hash = await waitFor(`challenger transaction ${index}`, async () => challengeTxs[index], 60_000);
            const receipt = await waitFor('mined challenger transaction', () => provider.getTransactionReceipt(hash));
            assert.equal(receipt.status, 1);
            const transaction = await provider.getTransaction(hash);
            return { hash, receipt, decoded: vault.interface.parseTransaction({ data: transaction.data }) };
        };
        const defeat = await minedChallengerTx(0);
        assert.equal(defeat.decoded.name, 'challengeEscapeWithdrawal');
        assert.deepEqual([...defeat.decoded.args[1]].map(BigInt), requestTuple(third.request.public_inputs),
            'the defeat carries the archived request at the successor nullifier');
        assert.equal(defeat.decoded.args[2].toLowerCase(), proofHex(third.request));
        const defeated = parsedLogs(defeat.receipt, 'EscapeWithdrawalDefeated');
        assert.equal(defeated.length, 1);
        assert.equal(defeated[0].args.nullifier, N(second));
        assert.equal(defeated[0].args.nextNullifier, N(third));
        assert.equal((await vault.notes(primary.noteId))[3], 1n, 'a defeat returns the note to Active; its leaf never left');
        assert.equal((await vault.pendingWithdrawals(primary.noteId))[0], false);
        assert.equal(await vault.nullifierState(N(second)), 2n, 'the escaped nullifier is flagged challenged');
        assert.equal(await vault.nullifierState(N(third)), 0n, 'the successor nullifier is released');
        assert.equal(await balance(vaultAddress), balances.vault);
        assert.equal(await balance(destination), balances.destination);
        assert.equal(await owed(), balances.treasury);
        // Replays: the same proof, and the genesis state whose successor is now challenged.
        await reverts(vault.initiateEscapeWithdrawal.staticCall(staleInputs, stale.proof_hex), 'ReplayedNullifier');
        const genesisEscape = await client('prepare_withdrawal', { snapshot: 'S0', args: await escapeArgs(0) });
        const genesisInputs = decodeInputs(genesisEscape);
        assert.equal(genesisInputs[15], N(second));
        await reverts(vault.initiateEscapeWithdrawal.staticCall(genesisInputs, genesisEscape.proof_hex), 'SupersededState');
        await save('defeat-receipt.json', defeat.receipt);

        // ---- Under-conceding escape from S2 is raised to its settled charge ----
        console.log('Escape from S2 conceding 0: the challenger raises it to the third request’s settled charge.');
        const underConceded = await client('prepare_withdrawal', { snapshot: 'S2', args: await escapeArgs(0) });
        const underInputs = decodeInputs(underConceded);
        assert.equal(underInputs[13], N(third));
        const S3successor = BigInt((await client('status')).withdrawal_nullifier);
        assert.equal(underInputs[15], S3successor, 'its successor is the newest state S3, never spent');
        const underInitiated = await (await vault.initiateEscapeWithdrawal(underInputs, underConceded.proof_hex)).wait();
        await rpc(rpcUrl, 'anvil_mine', ['0x2']);
        const raise = await minedChallengerTx(1);
        assert.equal(raise.decoded.name, 'raiseEscapeConcession');
        assert.deepEqual([...raise.decoded.args[1]].map(BigInt), requestTuple(third.request.public_inputs));
        const raised = parsedLogs(raise.receipt, 'EscapeConcessionRaised');
        assert.equal(raised.length, 1);
        assert.equal(raised[0].args.conceded, BigInt(third.record.charge_gwei));
        pending = await vault.pendingWithdrawals(primary.noteId);
        assert.equal(pending[3], BigInt(B(2)));
        assert.equal(pending[4], BigInt(third.record.charge_gwei));
        assert.equal(pending[5], BigInt(B(3)), 'a raise caps the payout at the newest state balance');
        // Double spend of N⁺: the newest state's nullifier is consumed on-chain,
        // so the server refuses any request from S3.
        const s3Quote = await get(`${serverUrl}/v2/billing/quote`);
        const s3Path = await treePath(client, primary.noteId);
        const s3Request = await client('prepare_request', { args: { payload: JSON.stringify({ mode: 'openrouter_ephemeral_lease', version: 1, billing_quote: s3Quote }),
            active_root: s3Path.active_root, merkle_siblings: s3Path.siblings, client_request_id: `acceptance-after-exit-${randomUUID()}`,
            request_time: Math.floor(Date.now() / 1000), created_at_ms: Date.now() } });
        const refused = await request(`${serverUrl}/v2/openrouter/leases`, { method: 'POST', value: s3Request.request });
        assert.equal(refused.status, 409);
        assert.equal(refused.value.error_code, 'nullifier_used');
        await stop(challenger);
        await advance(CHALLENGE_PERIOD + 1);
        const raisedBalances = { destination: await balance(destination), treasury: await owed() };
        const raisedFinal = await (await vault.finalizeEscapeWithdrawal(primary.noteId)).wait();
        assert.equal(await balance(destination) - raisedBalances.destination, BigInt(B(3)) * GWEI);
        assert.equal(await owed() - raisedBalances.treasury, BigInt(DEPOSIT - B(3)));
        assert.equal((await vault.notes(primary.noteId))[3], 3n);

        // ---- Fresh note: cooperative close with c = 0 and a validity deadline ----
        const clearance = await request(`${serverUrl}/v2/withdraw/clearance`, { method: 'POST',
            value: { withdrawal_nullifier: (await extraClient('status')).withdrawal_nullifier } });
        assert.equal(clearance.status, 200);
        const close = await extraClient('prepare_withdrawal', { args: { mode: 'mutual', destination, conceded: '0',
            valid_until: String(await validUntil()), clearance: clearance.value } });
        const closeInputs = decodeInputs(close);
        assert.equal(closeInputs[14], true);
        assert.equal(closeInputs[15], 0n);
        assert.equal(closeInputs[16], 0n);
        const closeBalances = { destination: await balance(destination) };
        const closeReceipt = await (await vault.mutualClose(closeInputs, close.proof_hex)).wait();
        assert.equal((await vault.notes(unrelated.noteId))[3], 3n);
        assert.equal(await balance(destination) - closeBalances.destination, BigInt(EXTRA_DEPOSIT) * GWEI);

        // ---- Withheld successor: an honest escape conceding its bound is paid B - b ----
        console.log('Starting a test-only withholding server; the honest wallet escapes conceding exactly its bound.');
        const withholding = await startServer('withholding-server', opts.adversaryBin, ['--adversary', 'withhold']);
        const victim = wallet('withheld');
        await victim('init', { config });
        const victimNote = await deposit(victim, DEPOSIT);
        const withheld = await requestAndSettle('withheld', victim, victimNote.noteId, withholding.url);
        const recovery = await get(`${withholding.url}/v2/requests/${withheld.id}`);
        assert.equal(recovery.request_response ?? null, null, 'the withholding server never signs the successor');
        assert.equal((await victim('status')).pending_request, true);
        const bound = Number(withheld.prepared.request.public_inputs.solvency_bound);
        assert.equal(bound, CAP);
        // Recovery availability must not be a prerequisite for unilateral exit.
        // Keep the real archived evidence, but take the operator fully offline
        // before proving and submitting the victim's escape.
        await stop(withholding.child);
        const honestEscape = await victim('prepare_withdrawal', { args: await escapeArgs(bound) });
        const honestInputs = decodeInputs(honestEscape);
        assert.equal(honestInputs[11], BigInt(DEPOSIT - bound));
        assert.equal(honestInputs[16], BigInt(bound));
        const escapeBalances = { destination: await balance(destination), treasury: await owed(), vault: await balance(vaultAddress) };
        const honestInitiated = await (await vault.initiateEscapeWithdrawal(honestInputs, honestEscape.proof_hex)).wait();
        // The operator's only evidence is the request at N: it cannot defeat
        // (that needs N⁺) and cannot raise past the bound already conceded.
        // ABI arguments: the address slot must be an address string, not a word.
        const requestArgs = inputs => requestTuple(inputs).map((word, index) => index === 2
            ? `0x${word.toString(16).padStart(40, '0')}` : word);
        const evidence = [requestArgs(withheld.prepared.request.public_inputs), proofHex(withheld.prepared.request)];
        await reverts(vault.challengeEscapeWithdrawal.staticCall(victimNote.noteId, ...evidence), 'NotSuccessorNullifier');
        await reverts(vault.raiseEscapeConcession.staticCall(victimNote.noteId, ...evidence, BigInt(DEPOSIT)), 'ConcessionNotRaised');
        await advance(CHALLENGE_PERIOD + 1);
        const honestFinal = await (await vault.finalizeEscapeWithdrawal(victimNote.noteId)).wait();
        assert.equal(await balance(destination) - escapeBalances.destination, BigInt(DEPOSIT - bound) * GWEI, 'G1: paid B - b');
        assert.equal(await owed() - escapeBalances.treasury, BigInt(bound));
        assert.equal(escapeBalances.vault - await balance(vaultAddress), BigInt(DEPOSIT - bound) * GWEI,
            'only the user payout leaves the vault; the bound accrues to the treasury');

        // ---- Bounded pause, then the expiry sweep ----
        console.log('Bounded pause: exits reopen after the maximum pause; the expiry sweep waits for the paused time.');
        const sleeper = wallet('expiring');
        await sleeper('init', { config });
        const sleeperNote = await deposit(sleeper, EXTRA_DEPOSIT);
        const claimableBefore = await vault.claimableAt(sleeperNote.noteId);
        await (await vault.pause()).wait();
        const maxPause = Number(await vault.MAX_PAUSE_DURATION());
        const pausedEscape = await sleeper('prepare_withdrawal', { args: await escapeArgs(0) });
        await reverts(vault.initiateEscapeWithdrawal.staticCall(decodeInputs(pausedEscape), pausedEscape.proof_hex), 'Paused');
        await advance(maxPause + 1);
        assert.equal(await vault.claimableAt(sleeperNote.noteId) - claimableBefore >= BigInt(maxPause), true,
            'paused time extends the expiry sweep');
        // The pause expired on its own: exits reopen without any owner action.
        const reopened = await sleeper('prepare_withdrawal', { args: await escapeArgs(0) });
        await vault.initiateEscapeWithdrawal.staticCall(decodeInputs(reopened), reopened.proof_hex);
        await (await vault.unpause()).wait();
        await reverts(vault.pause.staticCall(), 'PauseCooldown');
        const claimableAt = Number(await vault.claimableAt(sleeperNote.noteId));
        await reverts(vault.claimExpired.staticCall(sleeperNote.noteId), 'NoteNotExpired');
        await advance(claimableAt - await chainNow() + 1);
        const sweepBalances = { treasury: await owed() };
        const swept = await (await vault.claimExpired(sleeperNote.noteId)).wait();
        assert.equal(parsedLogs(swept, 'ExpiredClaimed').length, 1);
        assert.equal(await owed() - sweepBalances.treasury, BigInt(EXTRA_DEPOSIT));
        assert.equal((await vault.notes(sleeperNote.noteId))[3], 3n);
        // Permissionless payout of everything the treasury accrued.
        const accrued = await owed();
        const treasuryBefore = await balance(treasury);
        const treasuryPaid = await (await vault.withdrawTreasury()).wait();
        const paidEvents = parsedLogs(treasuryPaid, 'TreasuryWithdrawn');
        assert.equal(paidEvents.length, 1);
        assert.equal(paidEvents[0].args.amount, accrued);
        assert.equal(await balance(treasury) - treasuryBefore, accrued * GWEI);
        assert.equal(await owed(), 0n);
        assert.ok([...mock.keys.values()].every(key => key.deleted));

        const hashes = {};
        for (const file of [fileURLToPath(import.meta.url), path.join(ROOT, 'crates/zkapi-serverd/examples/v2_acceptance_wallet.rs'),
            path.join(ROOT, 'docker/aws/signer/signer.mjs'),
            ...['dagon-zkapi', 'dagon-zkapi-indexerd', 'dagon-zkapi-challenged', 'examples/v2_acceptance_wallet'].map(file => path.join(opts.binDir, file)),
            opts.adversaryBin,
            ...['request.pk', 'request.vk', 'withdrawal.pk', 'withdrawal.vk'].map(file => path.join(ROOT, 'protocol/setup/v2', file))]) {
            hashes[path.relative(ROOT, file)] = createHash('sha256').update(await fs.readFile(file)).digest('hex');
        }
        const gitOutput = args => {
            const result = spawnSync('git', args, { cwd: ROOT, encoding: 'utf8', maxBuffer: 1024 * 1024 * 1024 });
            assert.equal(result.status, 0, `git ${args.join(' ')} failed: ${result.error?.message ?? result.stderr}`);
            return result.stdout;
        };
        const result = { passed: true, timestamp: new Date().toISOString(), elapsed_wall_seconds: (Date.now() - started) / 1000,
            source_commit: gitOutput(['rev-parse', 'HEAD']).trim(),
            source_dirty: gitOutput(['status', '--porcelain']).trim().length > 0,
            tracked_source_diff_sha256: createHash('sha256').update(gitOutput(['diff', '--binary', 'HEAD'])).digest('hex'),
            artifact_sha256: hashes,
            network: { chain_id: CHAIN_ID, kind: 'disposable loopback Anvil', fork: false, public_rpc: false },
            coverage: { wallet: 'production browser wallet Rust APIs; fresh random genesis notes',
                proof_system: 'real checked-in Groth16 proving keys and deployed verifier (concession-exit circuit)',
                server: 'actual dagon-zkapi EVM serverd routes and SQLite archive, plus a test-only --adversary withhold build',
                indexer: 'actual dagon-zkapi-indexerd', challenger: 'actual dagon-zkapi-challenged EVM daemon (defeat and raise)',
                challenge_signer: 'production AWS createSigner RPC allowlist, fee checks and signed raw transactions',
                provider: 'loopback mock management and inference HTTP service',
                oracle: 'loopback mock price feed; chain, native-vault identity and live nullifiers checked against actual Anvil',
                external_provider_verified: false, oa_station_verified: false, live_network_verified: false },
            deposit: { transaction: primary.receipt.hash, note_id: primary.noteId, amount_gwei: DEPOSIT, genuine_genesis: true },
            settlements, mock_provider_events: mock.events,
            stale_escape_defeated: { initiation: initiated.hash, defeat: defeat.hash, front_running_deposit: unrelated.receipt.hash,
                escaped_nullifier_challenged: true, successor_released: true, note_active: true, no_payout: true,
                replay_reverted: 'ReplayedNullifier', older_state_reverted: 'SupersededState' },
            under_concession_raised: { initiation: underInitiated.hash, raise: raise.hash, raised_to_gwei: third.record.charge_gwei,
                finalization: raisedFinal.hash, user_payout_gwei: B(3), treasury_payout_gwei: DEPOSIT - B(3),
                successor_request_refused: 'nullifier_used' },
            mutual_close: { transaction: closeReceipt.hash, user_payout_gwei: EXTRA_DEPOSIT, conceded: 0 },
            withheld_successor: { note_id: victimNote.noteId, request: withheld.id, settled_charge_gwei: Number(withheld.settled.charge_applied),
                bound_gwei: bound, initiation: honestInitiated.hash, finalization: honestFinal.hash,
                user_payout_gwei: DEPOSIT - bound, treasury_payout_gwei: bound, defeat_reverted: 'NotSuccessorNullifier',
                raise_reverted: 'ConcessionNotRaised' },
            bounded_pause: { max_pause_seconds: maxPause, exits_reopened_without_unpause: true, re_pause_reverted: 'PauseCooldown',
                expiry_sweep: swept.hash, swept_gwei: EXTRA_DEPOSIT },
            all_runtime_keys_revoked: true };
        await save('result.json', result);
        console.log(`PASS: stale escape defeated (front-run deposit harmless) → under-conceded escape raised and paid B₃ → mutual close → withheld successor escaped at c = b and paid B − b → bounded pause and expiry sweep.\nEvidence: ${runDir}`);
    } catch (error) {
        await save('failure.json', { passed: false, error: error.message, stack: error.stack });
        console.error(`FAIL: ${error.message}\nEvidence: ${runDir}`);
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

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    await main();
}
