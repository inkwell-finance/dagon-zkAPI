import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';

const skip = process.platform === 'win32' && 'POSIX launcher test; run under WSL or Linux';
const script = resolve('docker/aws/run-daemon.sh');
const binaries = ['dagon-zkapi', 'dagon-zkapi-indexerd', 'dagon-zkapi-challenged'];

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
// secrets (seeds) never reach argv.
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
    }
}

for (const role of ['server', 'indexer', 'challenger']) {
    for (const override of [null, '/custom/proofs']) {
        test(`${role} launches from identity file with ${override ? 'explicit' : 'default'} proof artifacts`, { skip }, async () => {
            const { result, identity } = await launch(role, override ? { ZKAPI_PROOF_SETUP_DIR: override } : {});
            assert.equal(result.status, 0, `${result.error?.stack ?? ''}\n${result.stderr}`);
            const args = result.stdout.trim().split('\n');
            assert.deepEqual(args, expectedArgs(role, identity, override || '/srv/zkapi/protocol/setup/v2'));
            assert.ok(!result.stdout.includes('test-state-seed'));
            assert.ok(!result.stdout.includes('test-clear-seed'));
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

test('launcher refuses an unknown role', { skip }, async () => {
    const { result } = await launch('price-pusher');
    assert.equal(result.status, 2);
    assert.equal(result.stdout, '');
    assert.match(result.stderr, /Usage: dagon-zkapi-run server\|indexer\|challenger/);
});
