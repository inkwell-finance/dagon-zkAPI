import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';

function shellPath(value) {
    if (process.platform !== 'win32') return value;
    return `/mnt/${value[0].toLowerCase()}${value.slice(2).replaceAll('\\', '/')}`;
}

// Exercise both shipped backends through the real launcher with harmless
// executables. Solana is the default; EVM must be selected explicitly.
for (const backend of ['solana', 'evm']) {
    for (const role of ['server', 'challenger']) {
        for (const override of [null, '/custom/proofs']) {
            test(`${backend} ${role} launches with ${override ? 'explicit' : 'default'} proof artifacts`, {
                skip: process.platform === 'win32' && 'POSIX launcher test; exercised under WSL in Windows CI',
            }, async () => {
                const bin = await mkdtemp(join(tmpdir(), 'dagon-zkapi-launcher-'));
                try {
                    for (const name of ['dagon-zkapi', 'dagon-zkapi-challenged']) {
                        await writeFile(join(bin, name), `#!/bin/sh\nprintf '%s\\n' "$@"\n`, { mode: 0o755 });
                    }
                    const env = {
                        PATH: process.platform === 'win32'
                            ? `${shellPath(bin)}:/usr/local/bin:/usr/bin:/bin`
                            : `${bin}:/usr/local/bin:/usr/bin:/bin`,
                        LEDGER_BACKEND: backend,
                        CIRCUIT_ID: 'zkapi-v2-concession-v1',
                        REQUEST_CHARGE_CAP: '50000',
                        ZKAPI_STATE_SEED: 'test-state-seed',
                        ZKAPI_CLEAR_SEED: 'test-clear-seed',
                        SOLANA_PROGRAM_ID: 'Program1111111111111111111111111111111111',
                        SOLANA_VAULT_STATE: 'Vault11111111111111111111111111111111111',
                        SOLANA_GENESIS_HASH: 'Genesis111111111111111111111111111111111',
                        SOLANA_RPC_URL: 'https://solana.example',
                        PYTH_PRICE_ACCOUNT: 'Price1111111111111111111111111111111111',
                        ZKAPI_CHALLENGE_SOLANA_RPC_URL: 'https://solana-challenge.example',
                        ZKAPI_CHALLENGE_SOLANA_KEYPAIR: '/run/dagon-zkapi/challenge-keypair.json',
                        CHAIN_ID: '11155111',
                        VAULT_ADDRESS: '0x0000000000000000000000000000000000000001',
                        DEPLOY_BLOCK: '1',
                        ZKAPI_NATIVE_BILLING_RPC_URL: 'https://ethereum.example',
                        ZKAPI_NATIVE_PRICE_FEED_ADDRESS: '0x0000000000000000000000000000000000000003',
                        ZKAPI_CHALLENGE_RPC_URL: 'http://signer:8547',
                        ZKAPI_CHALLENGE_SENDER: '0x0000000000000000000000000000000000000002',
                    };
                    if (override) env.ZKAPI_PROOF_SETUP_DIR = override;
                    const script = shellPath(resolve('docker/aws/run-daemon.sh'));
                    const result = process.platform === 'win32'
                        ? spawnSync('C:\\Windows\\System32\\bash.exe', [
                            '-lc', 'exec env "$@"', 'dagon-launcher-test',
                            ...Object.entries(env).map(([key, value]) => `${key}=${value}`),
                            script, role,
                        ], { encoding: 'utf8', timeout: 5000 })
                        : spawnSync('/bin/sh', [script, role], { env, encoding: 'utf8', timeout: 5000 });
                    assert.equal(result.status, 0, `${result.error?.stack ?? ''}\nsignal=${result.signal ?? ''}\n${result.stderr}`);
                    const args = result.stdout.trim().split('\n');
                    assert.equal(args[args.indexOf('--ledger') + 1], backend);
                    const index = args.indexOf('--proof-setup-dir');
                    assert.ok(index >= 0);
                    assert.equal(args[index + 1], override || '/srv/zkapi/protocol/setup/v2');
                    if (role === 'server' && backend === 'solana') {
                        assert.equal(args[args.indexOf('--solana-program-id') + 1], env.SOLANA_PROGRAM_ID);
                        assert.equal(args[args.indexOf('--pyth-price-account') + 1], env.PYTH_PRICE_ACCOUNT);
                        assert.ok(!args.includes('--native-billing-rpc-url'));
                    }
                    if (role === 'server' && backend === 'evm') {
                        assert.equal(args[args.indexOf('--native-billing-rpc-url') + 1], env.ZKAPI_NATIVE_BILLING_RPC_URL);
                        assert.equal(args[args.indexOf('--native-price-feed-address') + 1], env.ZKAPI_NATIVE_PRICE_FEED_ADDRESS);
                        assert.ok(!args.includes('--solana-rpc-url'));
                    }
                    assert.ok(!result.stdout.includes('test-state-seed'));
                    assert.ok(!result.stdout.includes('test-clear-seed'));
                } finally {
                    await rm(bin, { recursive: true, force: true });
                }
            });
        }
    }
}

// The launcher's circuit pin is the migration gate: an environment written for
// the legacy note-bound vault must not start concession-exit images against it.
for (const circuit of ['zkapi-v2-note-bound-v1', 'legacy-unbound']) {
    test(`launcher refuses the ${circuit} circuit pin`, {
        skip: process.platform === 'win32' && 'POSIX launcher test; exercised under WSL in Windows CI',
    }, () => {
        const env = {
            PATH: '/usr/local/bin:/usr/bin:/bin',
            LEDGER_BACKEND: 'evm',
            CIRCUIT_ID: circuit,
            CHAIN_ID: '11155111',
            VAULT_ADDRESS: '0x0000000000000000000000000000000000000001',
            DEPLOY_BLOCK: '1',
        };
        const result = spawnSync('/bin/sh', [resolve('docker/aws/run-daemon.sh'), 'indexer'],
            { env, encoding: 'utf8', timeout: 5000 });
        assert.equal(result.status, 1);
        assert.equal(result.stdout, '');
        assert.match(result.stderr, /requires the zkapi-v2-concession-v1 circuit and a fresh vault/);
    });
}
