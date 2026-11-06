import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { buildBrowserSdkAssets, solanaBrowserConfig, verifyBrowserSdkAssets } from '../build.mjs';
import { configureBrowserSdk, browserSdkOptions, browserSdkTransport, beginBrowserSdkInitialization } from '../configure.js';
import { BrowserWalletRuntime } from '../services/browserWalletRuntime.js';

const fixture = async name => JSON.parse(await fs.readFile(new URL(`./fixtures/${name}`, import.meta.url), 'utf8'));

test('SDK imports without a host UI, codec global, wallet connection or network request', async () => {
    assert.equal(globalThis.zkapiWallet, undefined);
    const sdk = await import('../index.js');
    assert.equal(typeof sdk.zkapiClient.init, 'function');
    assert.equal(sdk.zkapiClient.initialized, false);
    assert.equal(sdk.browserWalletRuntime.worker, null);
    assert.deepEqual(sdk.CHAT_SPENDING_TIER_USD, [1, 2, 3, 4.5, 6]);
});

test('operator-free Solana exits bundle for browsers without Node polyfills', async () => {
    const result = await build({
        entryPoints: [fileURLToPath(new URL('../index.js', import.meta.url))],
        bundle: true, platform: 'browser', format: 'esm', write: false,
    });
    assert.equal(result.outputFiles.length, 1);
    assert.ok(result.outputFiles[0].contents.length > 0);
});

test('transport omits account credentials for both direct and opt-in host proxy requests', async () => {
    const originalFetch = globalThis.fetch;
    const calls = [];
    globalThis.fetch = async (...args) => { calls.push(args); return new Response('{}'); };
    try {
        const init = { method: 'POST', credentials: 'include', body: 'public-proof', headers: { 'x-test': 'value' } };
        await browserSdkTransport('https://service.example/leases', init, { preferProxy: true });
        assert.equal(calls[0][1].credentials, 'omit');
        assert.equal(init.credentials, 'include');
        const hints = { preferProxy: true };
        configureBrowserSdk({ transport: async (...args) => { calls.push(args); return new Response('{}'); } });
        await browserSdkTransport('https://service.example/leases', init, hints);
        assert.deepEqual(calls[1][1], { ...init, credentials: 'omit' });
        assert.equal(calls[1][1].body, init.body);
        assert.equal(calls[1][1].headers, init.headers);
        assert.equal(calls[1][2], hints);
    } finally {
        globalThis.fetch = originalFetch;
        configureBrowserSdk({ transport: null });
    }
});

test('host configuration resolves explicit paths and retains trusted same-origin proxy routing', async () => {
    const originalLocation = globalThis.location;
    const originalFetch = globalThis.fetch;
    const calls = [];
    globalThis.location = { href: 'https://host.example/chat/', origin: 'https://host.example' };
    globalThis.fetch = async (...args) => { calls.push(args); return new Response('{}'); };
    try {
        configureBrowserSdk({ configUrl: '/zkapi/browser-config.json', workerUrl: '/zkapi/assets/zkapiWasmWorker.js' });
        const runtime = new BrowserWalletRuntime();
        await runtime.loadBrowserConfig();
        assert.equal(calls[0][0], 'https://host.example/zkapi/browser-config.json');
        assert.equal(calls[0][1].credentials, 'omit');
        const config = await solanaBrowserConfig({ identity: await fixture('localnet.identity.json'),
            deployment: await fixture('localnet.deployment.json'), deploymentApiProxyPath: '/zkapi-deployment/' });
        runtime.browserConfig = config;
        await runtime.remoteFetch(config.trusted_deployment.protocol_server_url + '/v2/requests', { method: 'POST', body: '{"proof":"private-proof"}', credentials: 'include' });
        assert.equal(calls[1][0], 'https://host.example/zkapi-deployment/v2/requests');
        assert.equal(calls[1][1].credentials, 'omit');
        assert.equal(calls[1][1].body, '{"proof":"private-proof"}');
        await runtime.directJson(config.deployment_manifest_url);
        assert.equal(calls[2][1].credentials, 'omit');
        globalThis.fetch = async (...args) => { calls.push(args); return calls.length === 4 ? new Response('', {status:404}) : new Response('{}'); };
        await runtime.remoteFetch(config.trusted_deployment.protocol_server_url + '/v2/requests', { credentials: 'include', body: 'proof', method: 'POST' });
        assert.equal(calls[3][1].credentials, 'omit');
        assert.equal(calls[4][1].credentials, 'omit');
        assert.equal(browserSdkOptions().workerUrl, 'https://host.example/zkapi/assets/zkapiWasmWorker.js');
        const manifest = { ...config.trusted_deployment, privacy_mode: { openrouter_inference_base: 'https://openrouter.ai/api/v1' } };
        assert.equal(runtime.buildClientConfig(manifest, config).proving_keys.request.url, 'https://host.example/zkapi/proofs/request.pk');
    } finally {
        globalThis.location = originalLocation;
        globalThis.fetch = originalFetch;
    }
});

test('packaged proof assets and host-built worker are independent of source submodules', async () => {
    const temp = await fs.mkdtemp(path.join(os.tmpdir(), 'zkapi-sdk-assets-'));
    try {
        const pinned = await verifyBrowserSdkAssets();
        const identity = await fixture('localnet.identity.json');
        const deployment = await fixture('localnet.deployment.json');
        const result = await buildBrowserSdkAssets({ outDir: path.join(temp, 'localnet'), identity, deployment,
            publicPath: '/chat/zkapi/', build });
        assert.equal(result.configUrl, '/chat/zkapi/browser-config.json');
        assert.equal(result.workerUrl, '/chat/zkapi/assets/zkapiWasmWorker.js');
        const trusted = result.config.trusted_deployment;
        assert.equal(trusted.billing_asset, 'native_sol');
        assert.equal(trusted.billing_unit, 'lamports');
        assert.equal(trusted.network, 'localnet');
        assert.equal(trusted.wallet_standard_chain, 'solana:localnet');
        assert.equal(result.config.deployment_api_proxy_path, undefined);
        assert.equal(result.files['proofs/request.pk'], pinned.files['assets/proofs/request.pk']);
        assert.equal(trusted.request_proving_key_sha256, pinned.files['assets/proofs/request.pk']);
        assert.equal(result.files['wasm/zkapi_browser_bg.wasm'], pinned.files['wasm/zkapi_browser_bg.wasm']);
        assert.deepEqual(JSON.parse(await fs.readFile(path.join(result.directory, 'browser-config.json'), 'utf8')), result.config);
        const worker = await fs.readFile(path.join(result.directory, 'assets/zkapiWasmWorker.js'), 'utf8');
        assert.match(worker, /\.\.\/wasm\/zkapi_browser_bg\.wasm/);
        assert.doesNotMatch(worker, /ChatApp|funding-page|networkProxy/);
        // The packaged mainnet-beta identity has no vault yet: a production
        // build refuses it instead of producing an unusable trust anchor.
        await assert.rejects(buildBrowserSdkAssets({ outDir: path.join(temp, 'mainnet'), identity: 'mainnet-beta',
            deployment, build }), /mainnet-beta identity has no vault_authority \(undeployed\)/);
        await assert.rejects(buildBrowserSdkAssets({ outDir: temp, identity: 'unknown-net', deployment, build }),
            /packages no identity/);
        await assert.rejects(buildBrowserSdkAssets({ outDir: temp, identity, deployment, publicPath: '//other.example/', build }),
            /same-origin/);
    } finally { await fs.rm(temp, { recursive: true, force: true }); }
});

test('SDK rejects unsupported options and cannot change its trust/transport configuration after initialization begins', () => {
    for (const mode of ['invalid', 'auto', 'daemon']) {
        assert.throws(() => configureBrowserSdk({ mode }), /Only browser mode is supported/);
    }
    assert.throws(() => configureBrowserSdk({ transport: {} }), /transport/);
    assert.throws(() => configureBrowserSdk({ configUrl: 'https://user:secret@example.com/config' }), /credentials/);
    assert.throws(() => configureBrowserSdk({ ignoredOption: true }), /Unknown/);
    beginBrowserSdkInitialization();
    assert.throws(() => configureBrowserSdk({ configUrl: 'https://other.example/config' }), /before initializing/);
});
