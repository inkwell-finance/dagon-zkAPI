// Test-only: hosts the browser SDK's real proof worker (sdk/services/zkapiWasmWorker.js)
// in a Node worker thread. It only supplies the Web Worker globals the
// worker uses (`self` with message events and postMessage) and `fetch` for
// the file: URL of its WASM module; the worker code itself is unchanged.
import { parentPort, workerData } from 'node:worker_threads';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const nativeFetch = globalThis.fetch;
globalThis.fetch = async (input, init = {}) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    if (url.protocol === 'file:') {
        const bytes = await readFile(fileURLToPath(url));
        return new Response(bytes, { headers: { 'content-type': url.pathname.endsWith('.wasm') ? 'application/wasm' : 'application/octet-stream' } });
    }
    const { cache: _cache, credentials: _credentials, ...rest } = init;
    for (let attempt = 0; ; attempt += 1) {
        try {
            return await nativeFetch(input, rest);
        } catch (error) {
            // A loopback socket closed under a pooled request: retry once. undici
            // reports only "fetch failed"; keep the cause in the worker's error.
            if (attempt === 0 && error.cause?.code === 'UND_ERR_SOCKET') continue;
            throw new Error(`${error.message} (${input}): ${error.cause?.code ?? ''} ${error.cause?.message ?? error.cause ?? ''}`);
        }
    }
};

const self = new EventTarget();
self.postMessage = message => parentPort.postMessage(message);
self.crypto = globalThis.crypto;
globalThis.self = self;
await import(workerData.url);
// A MessagePort queues messages until it is started by its first listener,
// so nothing posted before the worker module registered its handler is lost.
parentPort.on('message', data => self.dispatchEvent(new MessageEvent('message', { data })));
