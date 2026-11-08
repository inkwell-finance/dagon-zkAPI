import assert from 'node:assert/strict';
import { mkdir, mkdtemp, writeFile, rm, readFile } from 'node:fs/promises';
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

// The shipped gateway (docker/aws/nginx.conf) rate-limits CCTP relay routes
// per client IP; the relay's in-memory per-key/global limits are a backstop.
const gatewayConfig = resolve('docker/aws/nginx.conf');

async function gatewayDirectives() {
    return (await readFile(gatewayConfig, 'utf8'))
        .split(/\r?\n/)
        .map((line) => line.replace(/^\s*#.*$/, '').trim())
        .filter(Boolean)
        .join('\n');
}

// Body of the first `<opener> {` block, matching braces outside quotes.
function block(config, opener) {
    const start = config.indexOf(`${opener} {`);
    assert.notEqual(start, -1, `missing block: ${opener}`);
    let depth = 0;
    let quote = null;
    for (let i = config.indexOf('{', start); i < config.length; i++) {
        const c = config[i];
        if (quote) {
            if (c === quote) quote = null;
        } else if (c === "'" || c === '"') {
            quote = c;
        } else if (c === '{') {
            depth++;
        } else if (c === '}' && --depth === 0) {
            return config.slice(config.indexOf('{', start) + 1, i);
        }
    }
    assert.fail(`unterminated block: ${opener}`);
}

test('gateway rate-limits relay routes per client IP', async () => {
    const config = await gatewayDirectives();
    const keyMap = block(config, 'map $request_method $relay_client');
    assert.match(keyMap, /^OPTIONS "";$/m);
    assert.match(keyMap, /^default \$binary_remote_addr;$/m);
    assert.match(config, /^limit_req_zone \$relay_client zone=relay_ops:\d+m rate=30r\/m;$/m);
    assert.match(config, /^limit_req_zone \$relay_client zone=relay_info:\d+m rate=60r\/m;$/m);
    assert.match(config, /^limit_req_status 429;$/m);

    const ops = block(config, 'location /v2/relay/');
    assert.match(ops, /^limit_req zone=relay_ops burst=10 nodelay;$/m);
    assert.match(ops, /^error_page 429 = @relay_rate_limited;$/m);
    assert.match(ops, /^proxy_pass \$server_upstream;$/m);
    const info = block(config, 'location = /v2/relay');
    assert.match(info, /^limit_req zone=relay_info burst=20 nodelay;$/m);
    assert.match(info, /^error_page 429 = @relay_rate_limited;$/m);
    assert.match(info, /^proxy_pass \$server_upstream;$/m);

    const limited = block(config, 'location @relay_rate_limited');
    const body = limited.match(/^return 429 '([^']*)';$/m);
    assert.ok(body, 'rate-limit location must return 429 with a body');
    const envelope = JSON.parse(body[1]);
    assert.deepEqual(Object.keys(envelope), ['error']);
    assert.equal(envelope.error.code, 'rate_limited');
    assert.equal(typeof envelope.error.message, 'string');
    assert.match(limited, /^default_type application\/json;$/m);
    assert.match(limited, /^add_header Retry-After 60 always;$/m);
    assert.match(limited, /^add_header Access-Control-Allow-Origin "\*" always;$/m);
});

test('gateway trusts X-Forwarded-For only from private peers', async () => {
    const config = await gatewayDirectives();
    assert.match(config, /^real_ip_header X-Forwarded-For;$/m);
    assert.match(config, /^real_ip_recursive on;$/m);
    const trusted = [...config.matchAll(/^set_real_ip_from (\S+);$/gm)].map((m) => m[1]);
    assert.deepEqual(trusted.sort(), [
        '10.0.0.0/8',
        '127.0.0.1',
        '172.16.0.0/12',
        '192.168.0.0/16',
        '::1',
        'fc00::/7',
    ]);
});

const nginxMissing = process.platform === 'win32'
    ? 'nginx -t needs a POSIX nginx; run under WSL or Linux'
    : spawnSync('nginx', ['-v']).error && 'nginx binary not installed';

test('gateway config passes nginx -t', { skip: nginxMissing }, async () => {
    const dir = await mkdtemp(join(tmpdir(), 'dagon-zkapi-gateway-'));
    try {
        // Keep nginx's compiled-in default error log inside the scratch prefix.
        await mkdir(join(dir, 'logs'));
        const result = spawnSync('nginx', ['-t', '-p', dir, '-c', gatewayConfig], { encoding: 'utf8' });
        assert.equal(result.status, 0, result.stderr);
    } finally {
        await rm(dir, { recursive: true, force: true });
    }
});
