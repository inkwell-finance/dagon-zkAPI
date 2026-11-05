// Stand-in for the `web-worker` package in the single-file CLI bundle (build.mjs aliases it).
//
// ffjavascript (inside snarkjs) starts its worker threads from a `data:` URL holding the thread's code. `web-worker`
// implements that by loading its OWN file in the new thread, which inside a bundle would run the whole bundle again.
// This shim runs the thread code directly in a node:worker_threads Worker with the small browser-like scope it expects
// (self, postMessage, onmessage, close).
import { Worker as ThreadWorker } from "node:worker_threads";

const SCOPE = `
const { parentPort } = require("node:worker_threads");
globalThis.self = globalThis;
globalThis.postMessage = (data, transfer) => parentPort.postMessage(data, transfer);
globalThis.close = () => process.exit(0);
parentPort.on("message", (data) => globalThis.onmessage?.({ data }));
`;

export default class Worker {
  #thread;
  #listeners = [];

  constructor(url) {
    const match = /^data:[^,]*;base64,(.*)$/.exec(String(url));
    if (!match) throw new Error("this worker shim only runs data: URLs");
    this.#thread = new ThreadWorker(SCOPE + Buffer.from(match[1], "base64").toString("utf8"), { eval: true });
    this.#thread.on("message", (data) => {
      for (const listener of this.#listeners) listener({ data });
    });
  }

  addEventListener(type, listener) {
    if (type === "message") this.#listeners.push(listener);
  }

  postMessage(data, transfer) {
    this.#thread.postMessage(data, transfer);
  }

  terminate() {
    return this.#thread.terminate();
  }
}
