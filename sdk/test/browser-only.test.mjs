import assert from 'node:assert/strict';
import test from 'node:test';
import { ZkapiClient } from '../services/zkapiClient.js';

test('initialization starts the browser wallet without probing a local daemon or honoring its old URL override', async t => {
    const oldWindow = globalThis.window;
    t.after(() => { globalThis.window = oldWindow; });
    globalThis.window = { location: { search: '?zkapiMode=daemon' }, setInterval: () => 1 };
    t.mock.method(globalThis, 'fetch', async () => assert.fail('no same-origin daemon probe'));
    const client = new ZkapiClient();
    const calls = [];
    t.mock.method(client, 'enableBrowserMode', async () => { calls.push('browser'); });
    t.mock.method(client, 'refresh', async () => { calls.push('refresh'); });
    await client.init();
    assert.deepEqual(calls, ['browser', 'refresh']);
    assert.equal(client.browserMode, true);
    assert.equal(client.requestMode, 'direct_openrouter');
    assert.equal(client.billingTokenSymbol, 'USDC');
});

test('background refresh never opens a wallet and coalesces concurrent ticks', async t => {
    const client = new ZkapiClient();
    let release;
    let refreshes = 0;
    t.mock.method(client, 'refresh', () => {
        refreshes += 1;
        return new Promise(resolve => { release = resolve; });
    });
    t.mock.method(client, 'connectSolanaWallet', async () => assert.fail('background refresh must not connect a wallet'));
    const first = client.refreshInBackground();
    const second = client.refreshInBackground();
    assert.equal(first, second);
    release();
    assert.equal(await first, true);
    assert.equal(refreshes, 1);
});
