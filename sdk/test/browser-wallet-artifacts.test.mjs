import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';
import test from 'node:test';
const __dirname = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const root = __dirname;

function sha256(file) {
    return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function sourceBlockAt(source, markerIndex) {
    assert.ok(markerIndex >= 0, 'source block marker is missing');
    const blockStart = source.indexOf('{', markerIndex);
    assert.ok(blockStart >= 0, 'source block opening brace is missing');
    let depth = 0;
    for (let index = blockStart; index < source.length; index += 1) {
        if (source[index] === '{') depth += 1;
        if (source[index] === '}') {
            depth -= 1;
            if (depth === 0) return source.slice(blockStart, index + 1);
        }
    }
    assert.fail('source block closing brace is missing');
}

function sourceMethodAt(source, marker) {
    const markerIndex = source.indexOf(marker);
    assert.ok(markerIndex >= 0, `source method marker is missing: ${marker}`);
    const parametersStart = source.indexOf('(', markerIndex);
    assert.ok(parametersStart >= 0, `source method parameters are missing: ${marker}`);

    let parameterDepth = 0;
    let parametersEnd = -1;
    for (let index = parametersStart; index < source.length; index += 1) {
        if (source[index] === '(') parameterDepth += 1;
        if (source[index] === ')') {
            parameterDepth -= 1;
            if (parameterDepth === 0) {
                parametersEnd = index;
                break;
            }
        }
    }
    assert.ok(parametersEnd >= 0, `source method parameters do not close: ${marker}`);

    const bodyStart = source.indexOf('{', parametersEnd);
    assert.ok(bodyStart >= 0, `source method body is missing: ${marker}`);
    return source.slice(markerIndex, bodyStart) + sourceBlockAt(source, bodyStart);
}

test('browser build contains every wallet WASM operation', () => {
    const bytes = fs.readFileSync(path.join(__dirname, 'wasm/zkapi_browser_bg.wasm'));
    const module = new WebAssembly.Module(bytes);
    const exports = new Set(WebAssembly.Module.exports(module).map(entry => entry.name));
    for (const name of [
        'browser_circuit_id',
        'browser_generate_deposit',
        'browser_confirm_deposit',
        'browser_wallet_status',
        'browser_tree_path',
        'browser_prepare_request',
        'browserrequestprover_new',
        'browserrequestprover_prepare_request',
        'browser_complete_response',
        'browser_withdrawal_nullifier',
        'browser_successor_nullifier',
        'browser_check_unrecoverable_response',
        'browser_prepare_withdrawal'
    ]) {
        assert.ok(exports.has(name), `missing WASM export ${name}`);
    }
});

test('browser worker retains the decoded request prover and retries failed initialization', () => {
    const glue = fs.readFileSync(path.join(__dirname, 'wasm/zkapi_browser.js'), 'utf8');
    const worker = fs.readFileSync(path.join(__dirname, 'services/zkapiWasmWorker.js'), 'utf8');
    const runtime = fs.readFileSync(path.join(__dirname, 'services/browserWalletRuntime.js'), 'utf8');

    assert.match(glue, /export class BrowserRequestProver/);
    assert.match(worker, /const requestProvers = new Map\(\)/);
    assert.match(worker, /new BrowserRequestProver\(bytes\)/);
    assert.match(worker, /case 'preloadRequestProver':\s*await loadRequestProver\(payload\.provingKey\)/);
    assert.match(worker, /return parse\(prover\.prepare_request\(/);
    assert.match(worker, /if \(provingKeys\.get\(cacheKey\) === promise\) provingKeys\.delete\(cacheKey\)/);
    assert.match(worker, /requestProvers\.delete\(cacheKey\)/);
    assert.doesNotMatch(worker, /\bbrowser_prepare_request\b/);
    assert.match(runtime, /prewarmRequestProver\(\)/);
    assert.match(runtime, /this\.worker\.call\('preloadRequestProver'/);
    assert.match(runtime, /if \(this\.runtime\.state \|\| this\.runtime\.pendingDeposit\)/);
    const prepareDeposit = sourceMethodAt(runtime, 'async prepareDeposit(amount)');
    const walletStatus = sourceMethodAt(runtime, 'async walletStatus()');
    assert.match(prepareDeposit, /void this\.prewarmRequestProver\(\)/);
    assert.ok(
        prepareDeposit.indexOf('void this.prewarmRequestProver()')
            > prepareDeposit.indexOf('await withBrowserWalletLock'),
        'deposit warm-up must not block its lightweight worker preparation'
    );
    assert.match(walletStatus, /const status = await this\.worker\.call\('walletStatus'/);
    assert.match(walletStatus, /void this\.prewarmRequestProver\(\)/);
    assert.ok(
        walletStatus.indexOf('void this.prewarmRequestProver()')
            > walletStatus.indexOf("await this.worker.call('walletStatus'"),
        'funded-page warm-up must begin only after initial wallet status resolves'
    );
});

test('static proving keys match the concession-exit development setup hashes', () => {
    assert.equal(
        sha256(path.join(root, 'assets/proofs/request.pk')),
        '28db26517500ebd2376b88fe729820912ebcbc2f92830e816ea894e968ad8591'
    );
    assert.equal(
        sha256(path.join(root, 'assets/proofs/withdrawal.pk')),
        '30c7cccf1b0fc2ab136b37273c5c19e84e90bf388a35088157dccc053efb479a'
    );
});

test('packaged Solana configs are generated copies of solana/profile, never hand-written values', () => {
    const repository = path.resolve(root, '..');
    assert.equal(
        sha256(path.join(root, 'assets/config/profile.json')),
        sha256(path.join(repository, 'solana/profile/shared.json'))
    );
    const sources = fs.readdirSync(path.join(repository, 'solana/profile')).filter(name => name.endsWith('.identity.json')).sort();
    const packaged = fs.readdirSync(path.join(root, 'assets/config')).sort();
    assert.deepEqual(packaged, ['profile.json', ...sources].sort());
    for (const name of sources) {
        assert.equal(sha256(path.join(root, 'assets/config', name)), sha256(path.join(repository, 'solana/profile', name)), name);
    }
    const manifest = JSON.parse(fs.readFileSync(path.join(root, 'assets/manifest.json'), 'utf8'));
    const profile = JSON.parse(fs.readFileSync(path.join(root, 'assets/config/profile.json'), 'utf8'));
    assert.equal(manifest.circuitId, profile.protocol.circuit_id);
    for (const name of packaged) {
        assert.equal(manifest.files[`assets/config/${name}`], sha256(path.join(root, 'assets/config', name)), name);
    }
    // No deployment trust anchor is checked in: each build derives it.
    for (const file of fs.readdirSync(path.join(root, 'services'))) {
        const source = fs.readFileSync(path.join(root, 'services', file), 'utf8');
        assert.doesNotMatch(source, /7NdY5ZVP2He8gSiDHZbkfmNfSgKWV2tkZmZgty2C1d8H|rec5EKMGg6MxZYaMdyBfgwp4d5rB9T1VQH5pJv5LtFJ/, file);
    }
});

test('browser direct requests derive output headroom from the proof-backed dollar budget', async () => {
    const compat = await import(pathToFileURL(path.join(__dirname, 'services/zkapiRequestCompat.mjs')));
    assert.deepEqual(
        compat.ensureDirectCompletionLimit(
            { model: 'anthropic/claude-opus-5' },
            {
                spendingLimitUsd: 2,
                model: {
                    pricing: { completion: '0.000025' },
                    top_provider: { max_completion_tokens: 128_000 }
                }
            }
        ),
        { model: 'anthropic/claude-opus-5', max_tokens: 36_000 }
    );
    assert.deepEqual(
        compat.ensureDirectCompletionLimit({ model: 'openai/gpt-5.6-sol' }, { spendingLimitUsd: 5 }),
        { model: 'openai/gpt-5.6-sol', max_tokens: 90_000 }
    );
    assert.deepEqual(
        compat.ensureDirectCompletionLimit({ model: 'example/model' }),
        { model: 'example/model' }
    );
    assert.equal(compat.ensureDirectCompletionLimit({ max_tokens: 32 }).max_tokens, 32);
    assert.equal(compat.ensureDirectCompletionLimit({ max_completion_tokens: 48 }).max_completion_tokens, 48);
    assert.deepEqual(
        compat.ensureDirectCompletionLimit({ max_output_tokens: 64 }),
        { max_tokens: 64 }
    );
});

test('the escape window shown to the user is the finalized vault challenge period', () => {
    const client = fs.readFileSync(path.join(__dirname, 'services/zkapiClient.js'), 'utf8');
    const runtime = fs.readFileSync(path.join(__dirname, 'services/browserWalletRuntime.js'), 'utf8');
    assert.match(runtime, /this\.vaultState = await assertSolanaVault\(this\.config\.funding\)/);
    assert.match(sourceMethodAt(client, 'async refresh('), /browserWalletRuntime\.vaultState\?\.challengePeriod/);
});

test('browser exits are leaf-bound: no root read, Merkle path or root retry', () => {
    const runtime = fs.readFileSync(path.join(__dirname, 'services/browserWalletRuntime.js'), 'utf8');
    const client = fs.readFileSync(path.join(__dirname, 'services/zkapiClient.js'), 'utf8');
    const prepare = sourceMethodAt(runtime, 'async prepareWithdrawal(mode,');
    assert.doesNotMatch(prepare, /treePath|active_root|merkle_siblings|expectedActiveRoot/);
    assert.match(prepare, /valid_until: String\(validUntil\)/);
    const withdraw = sourceMethodAt(client, 'async performWithdrawal(');
    assert.doesNotMatch(withdraw, /currentRoot|expectedActiveRoot|stale_root|restoreChallenged|restore_required/);
    assert.doesNotMatch(client, /restoreChallengedNote|restore_required/);
    assert.doesNotMatch(runtime, /challenges\/restore\/prepare|siblings: plan\.siblings/);
});

test('active root synchronization waits for the indexer and fails closed', async () => {
    const roots = await import(pathToFileURL(path.join(__dirname, 'services/zkapiActiveRoot.mjs')));
    const instant = { maxWaitMs: 1_000, initialDelayMs: 1, sleep: async () => {} };
    let calls = 0;
    const current = await roots.waitForTreeSnapshot(async () => {
        calls += 1;
        return { root: calls === 1 ? '0x10' : '0x11', next_note_id: 1 };
    }, { expectedActiveRoot: 17n, ...instant });
    assert.equal(current.root, '0x11');
    assert.equal(calls, 2);
    assert.equal(roots.sameFelt('0x11', 17n), true);

    await assert.rejects(
        roots.waitForTreeSnapshot(
            async () => ({ root: '0x12', next_note_id: 1 }),
            { expectedActiveRoot: '0x13', ...instant, maxWaitMs: 2 }
        ),
        error => error.code === 'indexer_root_lag'
    );

    let unconstrained = 0;
    await roots.waitForTreeSnapshot(async () => {
        unconstrained += 1;
        return { root: '0x1', next_note_id: 0 };
    }, instant);
    assert.equal(unconstrained, 1, 'a snapshot with no required note or root is read once');
});

test('a snapshot missing the requested note is indexer lag, retried with bounded backoff', async () => {
    const roots = await import(pathToFileURL(path.join(__dirname, 'services/zkapiActiveRoot.mjs')));
    const lagPolls = 4;
    let clock = 0;
    const waits = [];
    const timing = {
        now: () => clock,
        sleep: async milliseconds => { waits.push(milliseconds); clock += milliseconds; }
    };
    let polls = 0;
    const snapshot = await roots.waitForTreeSnapshot(async () => {
        polls += 1;
        return polls <= lagPolls
            ? { root: '0x1', next_note_id: 5 }
            : { root: '0x2', next_note_id: 6 };
    }, { requiredNoteId: 5, expectedActiveRoot: '0x2', ...timing });
    assert.equal(snapshot.next_note_id, 6);
    assert.equal(polls, lagPolls + 1);
    assert.deepEqual(waits, [250, 500, 1_000, 2_000]);

    // A vault that moves on while we wait is followed: the root is re-read.
    let vaultRoot = '0x2';
    polls = 0;
    const moved = await roots.waitForTreeSnapshot(async () => {
        polls += 1;
        if (polls === 2) vaultRoot = '0x3';
        return { root: '0x3', next_note_id: 7 };
    }, { requiredNoteId: 5, expectedActiveRoot: async () => vaultRoot, ...timing });
    assert.equal(moved.root, '0x3');

    clock = 0;
    waits.length = 0;
    await assert.rejects(
        roots.waitForTreeSnapshot(
            async () => ({ root: '0x1', next_note_id: 5 }),
            { requiredNoteId: 5, ...timing }
        ),
        error => error.code === 'indexer_root_lag'
    );
    assert.ok(clock <= roots.INDEXER_LAG_MAX_WAIT_MS, `waited ${clock}ms`);
    assert.ok(clock >= 10_000, `gave the indexer ${clock}ms`);
});

test('only a never-journaled prepared deposit can be re-planned or replaced', async () => {
    const { BrowserWalletRuntime } = await import(pathToFileURL(path.join(__dirname, 'services/browserWalletRuntime.js')));
    const runtime = new BrowserWalletRuntime();
    assert.equal(runtime.canReplanPendingDeposit({ operationId: 'deposit-1', phase: 'prepared' }), true);
    assert.equal(runtime.canReplanPendingDeposit({ operationId: 'deposit-1' }), true);
    assert.equal(runtime.canReplanPendingDeposit({ operationId: 'deposit-1', phase: 'prepared',
        solanaJournal: { stages: [] } }), false);
    assert.equal(runtime.canReplanPendingDeposit({ phase: 'prepared' }), false);
    assert.equal(runtime.canReplanPendingDeposit(null), false);
    const source = fs.readFileSync(path.join(__dirname, 'services/browserWalletRuntime.js'), 'utf8');
    assert.match(sourceMethodAt(source, 'async prepareDeposit(amount)'),
        /if \(!this\.canReplanPendingDeposit\(pending\)\)[\s\S]*A previous Solana deposit is unfinished/);
});

test('browser deposits refresh an unsigned Merkle path against the finalized vault root before submission', () => {
    const runtime = fs.readFileSync(path.join(__dirname, 'services/browserWalletRuntime.js'), 'utf8');
    const client = fs.readFileSync(path.join(__dirname, 'services/zkapiClient.js'), 'utf8');
    const refresh = sourceMethodAt(runtime, 'async refreshPendingDeposit(');
    assert.match(refresh, /async refreshPendingDeposit\(amount, expectedActiveRoot = null,/);
    assert.match(refresh, /if \(!this\.canReplanPendingDeposit\(pending\)\)/);
    assert.match(refresh, /const refreshed = \{[\s\S]*\.\.\.pending,[\s\S]*next_note_id: path\.note_id,[\s\S]*active_root: path\.active_root,[\s\S]*zero_path: path\.siblings/);
    assert.doesNotMatch(refresh, /secret:/);
    const deposit = sourceMethodAt(client, 'async performDeposit(');
    assert.match(deposit, /const vault = assertSolanaDepositsOpen\(await assertSolanaVault\(funding\)\);[\s\S]*await browserWalletRuntime\.refreshPendingDeposit\([\s\S]*Number\(amount\),[\s\S]*vault\.root/);
    assert.ok(deposit.indexOf('refreshPendingDeposit') < deposit.indexOf("submitSolanaOperation('deposit'"));
});
