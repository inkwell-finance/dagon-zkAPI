import assert from 'node:assert/strict';
import test from 'node:test';
import { BrowserWalletRuntime } from '../services/browserWalletRuntime.js';
import { nativeFunding } from './helpers/native-fixtures.mjs';

const CIRCUIT_ID = 'zkapi-v2-concession-v1';

function manifest() {
    return {
        ...nativeFunding(),
        protocol_version: 2,
        proof_backend: 'groth16_bn254',
        deployment_id: 'dagon-localnet-test',
        protocol_server_url: 'https://server.example',
        indexer_url: 'https://indexer.example',
        request_charge_cap: 1000,
        state_signing_key: { x: '0x1', y: '0x2' },
        clearance_signing_key: { x: '0x3', y: '0x4' },
        proof_setup: {
            circuit_id: CIRCUIT_ID,
            request_proving_key_sha256: 'aa'.repeat(32),
            withdrawal_proving_key_sha256: 'bb'.repeat(32)
        },
        privacy_mode: {
            openrouter_inference_base: 'https://openrouter.ai/api/v1',
            verifier_url: 'https://verifier.example'
        }
    };
}

const trustedPins = deployment => ({ ...deployment, ...deployment.proof_setup, ...deployment.privacy_mode });

test('browser rejects missing, legacy, and unknown circuits with migration guidance', () => {
    const runtime = new BrowserWalletRuntime();
    // The note-bound circuit has no concession exit: its vaults let an
    // operator that withholds a successor take the deposit.
    for (const circuitId of [undefined, '', 'legacy-unbound', 'zkapi-v2-note-bound-v1', 'unknown-future-circuit']) {
        const deployment = manifest();
        deployment.proof_setup.circuit_id = circuitId;
        assert.throws(() => runtime.validateManifest(deployment), error => {
            assert.equal(error.code, 'incompatible_proof_circuit');
            assert.match(error.message, /Funding is unavailable/);
            assert.match(error.message, /new vault/);
            assert.match(error.message, /existing funds and recovery data/);
            return true;
        });
    }
    const legacy = manifest();
    delete legacy.proof_setup;
    assert.throws(() => runtime.validateManifest(legacy), { code: 'incompatible_proof_circuit' });
    assert.doesNotThrow(() => runtime.validateManifest(manifest()));
});

test('browser requires its trusted configuration to pin the same circuit', () => {
    const runtime = new BrowserWalletRuntime();
    const deployment = manifest();
    runtime.browserConfig = { trusted_deployment: trustedPins(deployment) };
    runtime.validateManifestTrust(deployment);
    delete runtime.browserConfig.trusted_deployment.circuit_id;
    assert.throws(() => runtime.validateManifestTrust(deployment), /pinned proof circuit/);
    runtime.browserConfig.trusted_deployment.circuit_id = 'legacy-unbound';
    assert.throws(() => runtime.validateManifestTrust(deployment), /pinned proof circuit/);
});

test('every Solana identity, Pyth and RPC pin must match the trusted configuration', () => {
    const deployment = manifest();
    for (const [field, changed] of [
        ['network', 'devnet'], ['program_id', deployment.vault_state], ['vault_state', deployment.program_id],
        ['genesis_hash', deployment.program_id], ['wallet_standard_chain', 'solana:devnet'],
        ['pyth_receiver_program', deployment.program_id], ['pyth_price_account', deployment.program_id],
        ['pyth_feed_id', `0x${'01'.repeat(32)}`], ['pyth_max_age_seconds', 60], ['pyth_max_confidence_bps', 50],
        ['rpc_url', 'https://other-rpc.example'], ['chain_id', '1'], ['contract_address', `0x${'22'.repeat(32)}`],
        ['request_charge_cap', 2000]
    ]) {
        const runtime = new BrowserWalletRuntime();
        runtime.browserConfig = { trusted_deployment: trustedPins(deployment) };
        assert.throws(() => runtime.validateManifestTrust({ ...deployment, [field]: changed }), /changed its pinned/, field);
    }
});

test('an operator without an OA verifier pins none, and a manifest cannot add one', () => {
    const deployment = manifest();
    deployment.privacy_mode.verifier_url = null;
    const runtime = new BrowserWalletRuntime();
    runtime.browserConfig = { trusted_deployment: { ...trustedPins(deployment), verifier_url: null } };
    runtime.validateManifestTrust(deployment);
    assert.throws(() => runtime.validateManifestTrust({ ...deployment,
        privacy_mode: { ...deployment.privacy_mode, verifier_url: 'https://verifier.example' } }), /OA verifier/);
});

test('funding a legacy deployment fails before any proof worker or wallet storage mutation', async t => {
    const originalLocation = globalThis.location;
    const originalStorage = globalThis.localStorage;
    t.after(() => {
        globalThis.location = originalLocation;
        globalThis.localStorage = originalStorage;
    });
    globalThis.location = { href: 'https://host.example/', search: '' };
    globalThis.localStorage = {
        getItem: () => null,
        setItem: () => assert.fail('legacy funding must not persist deployment selection'),
        removeItem: () => assert.fail('no stored selection to remove')
    };
    const runtime = new BrowserWalletRuntime();
    runtime.loadBrowserConfig = async () => ({ deployment_manifest_url: 'https://server.example/config.json' });
    runtime.directJson = async () => {
        const legacy = manifest();
        delete legacy.proof_setup;
        return legacy;
    };
    await assert.rejects(runtime.prepareDeposit(1000), { code: 'incompatible_proof_circuit' });
    assert.equal(runtime.worker, null);
    assert.equal(runtime.initialized, false);
});

test('non-Solana deployments are rejected before deployment selection, worker creation or wallet writes', async t => {
    const oldLocation = globalThis.location;
    const oldStorage = globalThis.localStorage;
    t.after(() => { globalThis.location = oldLocation; globalThis.localStorage = oldStorage; });
    globalThis.location = { href: 'https://host.example/', search: '' };
    globalThis.localStorage = {
        getItem: () => null,
        setItem: () => assert.fail('unsupported deployments must not change saved selection'),
        removeItem: () => assert.fail('no stored selection to remove')
    };
    for (const changes of [{ billing_asset: 'erc20' }, { billing_asset: undefined },
        { ledger_backend: 'other.groth16.v1' }, { billing_unit: 'microlamports' }]) {
        const runtime = new BrowserWalletRuntime();
        runtime.loadBrowserConfig = async () => ({ deployment_manifest_url: 'https://server.example/config.json' });
        runtime.directJson = async () => ({ ...manifest(), ...changes });
        await assert.rejects(runtime.prepareDeposit(1000), /Unsupported Solana billing or ledger backend|invalid protocol or billing configuration/);
        assert.equal(runtime.worker, null);
        assert.equal(runtime.initialized, false);
    }
});

test('operator manifest loss or replacement leaves a pin-validated exit-only wallet', async () => {
    for (const unavailable of [true, false]) {
        const runtime = new BrowserWalletRuntime();
        const deployment = manifest();
        runtime.browserConfig = { trusted_deployment: trustedPins(deployment) };
        runtime.directJson = async () => {
            if (unavailable) throw new TypeError('operator offline');
            return { ...deployment, contract_address: `0x${'99'.repeat(32)}` };
        };
        const restored = await runtime.loadDeploymentManifest('https://server.example/config.json');
        assert.equal(restored.contract_address, deployment.contract_address);
        assert.equal(restored.proof_setup.withdrawal_proving_key_sha256, deployment.proof_setup.withdrawal_proving_key_sha256);
        assert.equal(runtime.exitOnly, true);
        runtime.validateManifest(restored);
        runtime.validateManifestTrust(restored);
        runtime.init = async () => {};
        await assert.rejects(runtime.prepareDeposit(1000), { code: 'deployment_exit_only' });
        await assert.rejects(runtime.prepareLeaseRequest(), { code: 'deployment_exit_only' });
        await assert.rejects(runtime.prepareDepositQuote(1000), { code: 'deployment_exit_only' });
        runtime.directJson = async () => deployment;
        await runtime.loadDeploymentManifest('https://server.example/config.json');
        assert.equal(runtime.exitOnly, false);
    }
});

test('exit-only initialization never falls back to missing or incompatible trusted pins', async () => {
    const runtime = new BrowserWalletRuntime();
    const deployment = manifest();
    runtime.directJson = async () => { throw new TypeError('operator offline'); };
    runtime.browserConfig = {};
    await assert.rejects(runtime.loadDeploymentManifest('https://server.example/config.json'), /operator offline/);
    runtime.browserConfig.trusted_deployment = { ...trustedPins(deployment), circuit_id: 'zkapi-v2-note-bound-v1' };
    await assert.rejects(runtime.loadDeploymentManifest('https://server.example/config.json'), { code: 'incompatible_proof_circuit' });
});
