import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';

const skip = process.platform === 'win32' && 'POSIX launcher test; run under WSL or Linux';
const script = resolve('docker/aws/run-daemon.sh');
const binaries = ['dagon-zkapi', 'dagon-zkapi-indexerd', 'dagon-zkapi-challenged', 'dagon-zkapi-pyth-pusher'];

// Run the real launcher against harmless executables that echo their argv.
async function launch(role, extraEnv = {}) {
    const dir = await mkdtemp(join(tmpdir(), 'dagon-zkapi-launcher-'));
    try {
        for (const name of binaries) {
            await writeFile(join(dir, name), `#!/bin/sh\nprintf '%s\\n' "$@"\n`, { mode: 0o755 });
        }
        const identity = join(dir, 'identity.json');
        await writeFile(identity, '{}\n');
        const env = {
            PATH: `${dir}:/usr/local/bin:/usr/bin:/bin`,
            ZKAPI_SOLANA_IDENTITY: identity,
            SOLANA_RPC_URL: 'https://solana.example',
            ZKAPI_STATE_SEED: 'test-state-seed',
            ZKAPI_CLEAR_SEED: 'test-clear-seed',
            ZKAPI_CHALLENGE_SOLANA_KEYPAIR: '/run/dagon-zkapi/challenge-keypair.json',
            ZKAPI_PYTH_PUSHER_KEYPAIR: '/run/dagon-zkapi/pyth-pusher-keypair.json',
            PYTH_HERMES_API_KEY: 'test-hermes-api-key',
            ...extraEnv,
        };
        for (const [key, value] of Object.entries(env)) if (value === undefined) delete env[key];
        const result = spawnSync('/bin/sh', [script, role], { env, encoding: 'utf8', timeout: 5000 });
        return { result, identity, env };
    } finally {
        await rm(dir, { recursive: true, force: true });
    }
}

// Shared parameters are compiled in, so each daemon receives exactly the
// identity file, RPC URL, fixed service paths and (server) optional OA org;
// secrets (seeds, the Hermes API key) never reach argv.
function expectedArgs(role, identity, proofs) {
    switch (role) {
        case 'server':
            return ['--proof-setup-dir', proofs, 'serverd', '--solana-identity', identity,
                '--solana-rpc-url', 'https://solana.example', '--listen', '0.0.0.0:3000',
                '--indexer-url', 'http://indexer:3001', '--db-path', '/data/server.db'];
        case 'indexer':
            return ['--solana-identity', identity, '--rpc-url', 'https://solana.example',
                '--listen', '0.0.0.0:3001'];
        case 'challenger':
            return ['--solana-identity', identity, '--solana-rpc-url', 'https://solana.example',
                '--solana-keypair', '/run/dagon-zkapi/challenge-keypair.json',
                '--db-path', '/data/server.db', '--checkpoint', '/data/challenges.json',
                '--proof-setup-dir', proofs];
        case 'pyth-pusher':
            return ['--solana-identity', identity, '--solana-rpc-url', 'https://solana.example',
                '--payer-keypair', '/run/dagon-zkapi/pyth-pusher-keypair.json', '--listen', '0.0.0.0:3002'];
    }
}

for (const role of ['server', 'indexer', 'challenger', 'pyth-pusher']) {
    for (const override of [null, '/custom/proofs']) {
        test(`${role} launches from identity file with ${override ? 'explicit' : 'default'} proof artifacts`, { skip }, async () => {
            const { result, identity } = await launch(role, override ? { ZKAPI_PROOF_SETUP_DIR: override } : {});
            assert.equal(result.status, 0, `${result.error?.stack ?? ''}\n${result.stderr}`);
            const args = result.stdout.trim().split('\n');
            assert.deepEqual(args, expectedArgs(role, identity, override || '/srv/zkapi/protocol/setup/v2'));
            assert.ok(!result.stdout.includes('test-state-seed'));
            assert.ok(!result.stdout.includes('test-clear-seed'));
            assert.ok(!result.stdout.includes('test-hermes-api-key'));
        });
    }
}

test('server refuses the development signing seeds', { skip }, async () => {
    const { result } = await launch('server', { ZKAPI_STATE_SEED: '0x1' });
    assert.equal(result.status, 1);
    assert.equal(result.stdout, '');
    assert.match(result.stderr, /development signing seeds/);
});

test('launcher refuses a missing identity file', { skip }, async () => {
    const { result } = await launch('indexer', { ZKAPI_SOLANA_IDENTITY: '/nonexistent/identity.json' });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /identity file is not readable/);
});

test('launcher requires the Solana RPC URL', { skip }, async () => {
    const { result } = await launch('server', { SOLANA_RPC_URL: undefined });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /Missing required environment variable: SOLANA_RPC_URL/);
});

test('server passes the OA org URL when configured', { skip }, async () => {
    const { result, identity } = await launch('server', { OA_ORG_URL: 'https://org.example' });
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(result.stdout.trim().split('\n'), [
        ...expectedArgs('server', identity, '/srv/zkapi/protocol/setup/v2'), '--oa-org-url', 'https://org.example',
    ]);
});

test('pyth-pusher requires the payer keypair and the Hermes API key', { skip }, async () => {
    for (const name of ['ZKAPI_PYTH_PUSHER_KEYPAIR', 'PYTH_HERMES_API_KEY']) {
        const { result } = await launch('pyth-pusher', { [name]: undefined });
        assert.equal(result.status, 1);
        assert.equal(result.stdout, '');
        assert.match(result.stderr, new RegExp(`Missing required environment variable: ${name}`));
    }
});

test('pyth-pusher passes the optional Hermes URL, priority fee and balance alarm', { skip }, async () => {
    const { result, identity } = await launch('pyth-pusher', { PYTH_HERMES_URL: 'https://hermes.example',
        ZKAPI_PYTH_PUSHER_PRIORITY_FEE_MICRO_LAMPORTS: '20000', ZKAPI_PYTH_PUSHER_MIN_BALANCE_LAMPORTS: '5000000000' });
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(result.stdout.trim().split('\n'), [
        ...expectedArgs('pyth-pusher', identity, ''), '--hermes-url', 'https://hermes.example',
        '--priority-fee-micro-lamports', '20000', '--min-balance-lamports', '5000000000',
    ]);
    assert.ok(!result.stdout.includes('test-hermes-api-key'));
});

test('compose keeps sponsor fallback independent and isolates the pusher secret mount', async () => {
    const compose = await readFile(resolve('docker/aws/compose.yml'), 'utf8');
    const section = name => compose.match(new RegExp(`^  ${name}:\\r?\\n([\\s\\S]*?)(?=^  [a-z][\\w-]*:|^networks:)`, 'm'))?.[1];
    const server = section('server');
    const pusher = section('pyth-pusher');
    assert.ok(server && pusher);
    assert.doesNotMatch(server, /pyth-pusher/);
    assert.match(pusher, /source: .*\/pyth-pusher-keypair\.json/);
    assert.match(pusher, /target: \/run\/dagon-zkapi\/pyth-pusher-keypair\.json/);
    assert.match(pusher, /create_host_path: false/);
    assert.doesNotMatch(pusher, /:\/run\/dagon-zkapi:ro/);
    assert.doesNotMatch(pusher, /server\.env|challenge\.env/);
});
