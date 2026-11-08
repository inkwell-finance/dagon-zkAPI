// Test-only: runs the REAL browser wallet SDK under Node for the CCTP
// end-to-end tests: BrowserWalletRuntime (journal, deposit/withdrawal
// records, initialization against a trusted deployment), its WASM proof
// worker (sdk/services/zkapiWasmWorker.js in a worker thread) and
// ZkapiCctpWallet. Only the browser platform is supplied here: an in-memory
// transactional IndexedDB, Web Storage, `location`, a Web Worker over
// worker_threads, and a loopback static server for browser-config.json, the
// deployment manifest and the proving keys (built by sdk/build.mjs's
// solanaBrowserConfig from the stack's identity, exactly as for a host).
import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { Worker as ThreadWorker } from 'node:worker_threads';

const clone = value => value === undefined ? undefined : structuredClone(value);

/** A transactional in-memory IndexedDB: writes stay private to a transaction until it completes. */
export function memoryIndexedDb() {
    const stores = new Map();
    const keyPaths = new Map();
    let version = 0;
    const database = {
        close() {},
        objectStoreNames: { contains: name => stores.has(name) },
        createObjectStore(name, options = {}) {
            stores.set(name, new Map());
            keyPaths.set(name, options.keyPath);
        },
        transaction(names, mode) {
            const allowed = Array.isArray(names) ? names : [names];
            const working = new Map(allowed.map(name => [name, new Map(stores.get(name))]));
            let timer;
            const transaction = {
                aborted: false, completed: false, pending: 0,
                abort() {
                    if (this.aborted || this.completed) return;
                    this.aborted = true;
                    clearTimeout(timer);
                    setTimeout(() => this.onabort?.(), 0);
                },
                scheduleCompletion() {
                    clearTimeout(timer);
                    if (this.aborted || this.pending) return;
                    timer = setTimeout(() => {
                        if (this.aborted || this.pending) return;
                        if (mode === 'readwrite') for (const [name, values] of working) stores.set(name, values);
                        this.completed = true;
                        this.oncomplete?.();
                    }, 0);
                },
                objectStore(name) {
                    if (!working.has(name)) throw new Error(`Unknown object store: ${name}`);
                    const values = working.get(name);
                    const request = operation => {
                        const pending = {};
                        transaction.pending += 1;
                        queueMicrotask(() => {
                            try {
                                if (transaction.aborted) return;
                                pending.result = operation();
                                pending.onsuccess?.();
                            } catch (error) {
                                pending.error = error;
                                transaction.error = error;
                                pending.onerror?.();
                                transaction.abort();
                            } finally {
                                transaction.pending -= 1;
                                transaction.scheduleCompletion();
                            }
                        });
                        return pending;
                    };
                    return {
                        get: key => request(() => clone(values.get(key))),
                        getAll: () => request(() => [...values.values()].map(clone)),
                        put: (value, key) => request(() => {
                            const resolved = key ?? value[keyPaths.get(name)];
                            values.set(resolved, clone(value));
                            return resolved;
                        }),
                        delete: key => request(() => values.delete(key))
                    };
                }
            };
            return transaction;
        }
    };
    return {
        stores,
        clear() { for (const values of stores.values()) values.clear(); },
        open(_name, requestedVersion) {
            const request = {};
            queueMicrotask(() => {
                request.result = database;
                if (requestedVersion > version) {
                    const oldVersion = version;
                    version = requestedVersion;
                    request.onupgradeneeded?.({ oldVersion, newVersion: version });
                }
                request.onsuccess?.();
            });
            return request;
        }
    };
}

const workers = new Set();

/** The Web Worker constructor the runtime's WorkerBridge uses, over a worker thread. */
class NodeWebWorker {
    constructor(url) {
        this.thread = new ThreadWorker(new URL('./node-wasm-worker.mjs', import.meta.url), { workerData: { url: String(url) }, execArgv: [] });
        this.thread.unref();
        workers.add(this);
    }
    addEventListener(type, listener) {
        if (type === 'message') this.thread.on('message', data => listener({ data }));
        if (type === 'error') this.thread.on('error', error => listener({ message: error.message }));
    }
    postMessage(message) { this.thread.postMessage(message); }
    terminate() { workers.delete(this); return this.thread.terminate(); }
}

let installed = null;

/**
 * Install the browser platform once per process and start the static
 * deployment server. `setDeployment` (re)points it at a stack; `newWallet`
 * returns a freshly initialized runtime + CCTP wallet on an empty store.
 */
export async function installNodeBrowser({ root }) {
    if (installed) return installed;
    const sdk = join(root, 'sdk');
    const files = new Map();
    const server = http.createServer((request, response) => {
        const body = files.get(new URL(request.url, 'http://127.0.0.1').pathname);
        if (!body) { response.writeHead(404).end(); return; }
        response.writeHead(200, { 'content-type': typeof body === 'string' ? 'application/json' : 'application/octet-stream',
            'cache-control': 'no-store', connection: 'close' }).end(body);
    });
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
    server.unref();
    const origin = `http://127.0.0.1:${server.address().port}`;
    files.set('/proofs/request.pk', await readFile(join(sdk, 'assets/proofs/request.pk')));
    files.set('/proofs/withdrawal.pk', await readFile(join(sdk, 'assets/proofs/withdrawal.pk')));

    const storage = new Map();
    const webStorage = { getItem: key => storage.get(key) ?? null, setItem: (key, value) => storage.set(key, String(value)),
        removeItem: key => storage.delete(key) };
    globalThis.localStorage = webStorage;
    globalThis.sessionStorage = webStorage;
    globalThis.location = { href: `${origin}/`, origin, search: '', hostname: '127.0.0.1' };
    globalThis.indexedDB = memoryIndexedDb();
    globalThis.Worker = NodeWebWorker;
    // No cross-tab channel in a single process (a live BroadcastChannel would also keep Node running).
    delete globalThis.BroadcastChannel;

    const { configureBrowserSdk } = await import(pathToFileURL(join(sdk, 'configure.js')).href);
    const { solanaBrowserConfig } = await import(pathToFileURL(join(sdk, 'build.mjs')).href);
    const { BrowserWalletRuntime } = await import(pathToFileURL(join(sdk, 'services/browserWalletRuntime.js')).href);
    const { ZkapiCctpWallet } = await import(pathToFileURL(join(sdk, 'services/zkapiCctpWallet.mjs')).href);
    configureBrowserSdk({ configUrl: `${origin}/browser-config.json`, workerUrl: pathToFileURL(join(sdk, 'services/zkapiWasmWorker.js')).href });

    let deployed = null;
    installed = {
        origin,
        indexedDB: globalThis.indexedDB,
        /** `deployment`: {protocol_server_url, indexer_url, rpc_url, openrouter_inference_base, state_signing_key, clearance_signing_key}. */
        async setDeployment({ identity, deployment }) {
            const browserConfig = await solanaBrowserConfig({ identity, deployment: {
                schema: 'dagon-zkapi.sdk-deployment.v1', deployment_manifest_url: `${origin}/config.json`, oa_verifier_url: null, ...deployment } });
            const trusted = browserConfig.trusted_deployment;
            // The operator's manifest, as a host serves it: the trusted pins in manifest form.
            const manifest = { ...trusted, protocol_version: 2, proof_backend: 'groth16_bn254',
                proof_setup: { circuit_id: trusted.circuit_id, request_proving_key_sha256: trusted.request_proving_key_sha256,
                    withdrawal_proving_key_sha256: trusted.withdrawal_proving_key_sha256 },
                privacy_mode: { openrouter_inference_base: trusted.openrouter_inference_base, verifier_url: trusted.verifier_url } };
            files.set('/browser-config.json', JSON.stringify(browserConfig));
            files.set('/config.json', JSON.stringify(manifest));
            deployed = { browserConfig, manifest };
            return deployed;
        },
        /** A new browser profile: empty wallet store, a new runtime (and proof worker), a CCTP wallet with `options`. */
        async newWallet({ options = {}, keepStore = false } = {}) {
            if (!deployed) throw new Error('setDeployment first');
            for (const worker of [...workers]) await worker.terminate();
            if (!keepStore) globalThis.indexedDB.clear();
            const runtime = new BrowserWalletRuntime();
            await runtime.init();
            return { runtime, wallet: new ZkapiCctpWallet({ runtime, options }) };
        },
        /** The real WASM `generateDeposit` (a note secret + registration commitment) from a throwaway worker. */
        async generateDeposit() {
            const thread = new NodeWebWorker(pathToFileURL(join(sdk, 'services/zkapiWasmWorker.js')).href);
            try {
                return await new Promise((resolve, reject) => {
                    thread.addEventListener('message', ({ data }) => (data.error ? reject(new Error(data.error)) : resolve(data.result)));
                    thread.addEventListener('error', ({ message }) => reject(new Error(message)));
                    thread.postMessage({ id: 1, operation: 'generateDeposit', payload: {} });
                });
            } finally {
                await thread.terminate();
            }
        },
        async close() {
            for (const worker of [...workers]) await worker.terminate();
            await new Promise(resolve => server.close(resolve));
        }
    };
    return installed;
}

/** Make the runtime's next WASM `generateDeposit` return `preset` (a real one generated earlier). */
export function presetNextDeposit(runtime, preset) {
    const call = runtime.worker.call.bind(runtime.worker);
    let next = preset;
    runtime.worker.call = async (operation, payload) => {
        if (operation === 'generateDeposit' && next) {
            const value = next;
            next = null;
            return value;
        }
        return call(operation, payload);
    };
}
