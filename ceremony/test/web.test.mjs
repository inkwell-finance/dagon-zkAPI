import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, test } from "node:test";
import { pathToFileURL } from "node:url";
import { buildAssets } from "../build.mjs";
import { buildApp } from "../coordinator/app.mjs";
import { loadAssets } from "../coordinator/assets.mjs";
import { Coordinator } from "../coordinator/coordinator.mjs";
import { initCeremony } from "../coordinator/init.mjs";
import { terminateThreads, verifyZkey } from "../lib/snark.mjs";
import { readMpcFromBytes } from "../lib/zkey-info.mjs";
import { fakeClock, makeFixture } from "./helpers.mjs";

describe("the web page and its bundles", () => {
  let root, fx, dataDir, web, assets, app;

  before(async () => {
    root = await mkdtemp(join(tmpdir(), "ceremony-web-"));
    web = join(root, "web");
    await mkdir(join(web, "dist"), { recursive: true });
    await buildAssets({ outdir: join(web, "dist"), logLevel: "silent" });
    for (const name of ["index.html", "style.css", "favicon.svg"]) await copyFile(new URL(`../web/${name}`, import.meta.url), join(web, name));
    fx = await makeFixture(join(root, "fixture"));
    dataDir = join(root, "data");
    await initCeremony({ configPath: fx.configPath, r1csDir: fx.r1csDir, dataDir, ptauFile: fx.ptauPath });
    const clock = fakeClock();
    const coordinator = await Coordinator.open({ dataDir, now: clock.now.bind(clock), verify: verifyZkey });
    ({ assets } = await loadAssets(web));
    app = buildApp({ coordinator, assets, now: clock.now.bind(clock) });
  });

  after(async () => {
    await terminateThreads();
    await rm(root, { recursive: true, force: true });
  });

  test("the page references only same-origin files, has no inline script or style, and carries SRI for what it loads", async () => {
    const source = await readFile(new URL("../web/index.html", import.meta.url), "utf8");
    assert.doesNotMatch(source, /https?:\/\//, "no absolute URLs in the HTML");
    assert.doesNotMatch(source, /<script(?![^>]*\bsrc=)[^>]*>/, "no inline script");
    assert.doesNotMatch(source, /\sstyle=|<style/, "no inline style");
    assert.doesNotMatch(await readFile(new URL("../web/style.css", import.meta.url), "utf8"), /@import|url\(\s*["']?https?:/);

    const response = await app.request("/");
    assert.equal(response.status, 200);
    const html = await response.text();
    assert.match(response.headers.get("content-security-policy"), /script-src 'self' 'wasm-unsafe-eval'/);
    assert.match(response.headers.get("content-security-policy"), /connect-src 'self'/);
    assert.doesNotMatch(response.headers.get("content-security-policy"), /unsafe-inline|https?:|\*/);
    for (const name of ["app.js", "style.css"]) {
      const bytes = await readFile(name === "app.js" ? join(web, "dist", "app.js") : join(web, "style.css"));
      assert.ok(html.includes(`integrity="sha256-${createHash("sha256").update(bytes).digest("base64")}"`), `${name} has its SRI hash`);
    }
    assert.doesNotMatch(html, /__[A-Z]+_INTEGRITY__/);
  });

  test("the page defines every statically referenced UI element", async () => {
    const html = await readFile(new URL("../web/index.html", import.meta.url), "utf8");
    const source = await readFile(new URL("../web/app.js", import.meta.url), "utf8");
    const ids = new Set([...html.matchAll(/\bid="([^"]+)"/g)].map((m) => m[1]));
    for (const match of source.matchAll(/\bel(?:\.([a-zA-Z]\w*)|\["([^"]+)"\])/g)) {
      assert.ok(ids.has(match[1] ?? match[2]), `missing UI element ${match[1] ?? match[2]}`);
    }
  });

  test("the bundles are self-contained: no network URLs, no CDN, no dynamic remote imports", async () => {
    for (const name of ["app.js", "worker.js"]) {
      const code = await readFile(join(web, "dist", name), "utf8");
      assert.doesNotMatch(code, /import\(\s*["']https?:/, name);
      assert.doesNotMatch(code, /from\s*["']https?:/, name);
      assert.doesNotMatch(code, /cdn\.|unpkg|jsdelivr|googleapis/i, name);
    }
  });

  test("locked builds reproduce independent bundle SHA256 digests", async () => {
    const second = join(root, "rebuilt");
    await buildAssets({ outdir: second, logLevel: "silent" });
    assert.equal(await readFile(join(web, "dist", "SHA256SUMS"), "utf8"), await readFile(join(second, "SHA256SUMS"), "utf8"));
    for (const name of ["app.js", "worker.js", "contribute.mjs"]) {
      assert.deepEqual(await readFile(join(web, "dist", name)), await readFile(join(second, name)));
    }
  });

  test("the assets are served with ETags and gzip, and the status lists their hashes", async () => {
    const response = await app.request("/worker.js", { headers: { "accept-encoding": "gzip" } });
    assert.equal(response.headers.get("content-encoding"), "gzip");
    assert.match(response.headers.get("content-type"), /javascript/);
    const etag = response.headers.get("etag");
    assert.equal((await app.request("/worker.js", { headers: { "if-none-match": etag } })).status, 304);
    const status = await (await app.request("/api/status")).json();
    assert.equal(status.assets["worker.js"], assets.get("worker.js").sha256);
    assert.equal(status.webReady, true);
  });

  test("the browser build of snarkjs inside worker.js contributes a zkey that verifies (page code path, in Node)", async () => {
    // worker.js is the file the page runs in a Web Worker. Give it the worker scope it expects and send it the same message.
    // the browser build of snarkjs caches its (single-threaded) curve in the same global as the Node build: start clean
    await terminateThreads();
    const outbox = [];
    const done = Promise.withResolvers();
    globalThis.self = {
      postMessage(message) {
        outbox.push(message);
        if (message.type !== "progress") done.resolve(message);
      },
    };
    await import(pathToFileURL(join(web, "dist", "worker.js")).href);
    assert.equal(typeof globalThis.self.onmessage, "function");

    const zkey = new Uint8Array(await readFile(join(dataDir, "rounds", "0000", "withdrawal.zkey")));
    await globalThis.self.onmessage({ data: { id: 7, zkey, name: "Phone", entropyText: "touch,12,40,1.5;touch,13,44,9.5" } });
    const reply = await done.promise;
    assert.equal(reply.type, "done", reply.message);
    assert.equal(reply.id, 7);
    assert.ok(outbox.some((m) => m.type === "progress"), "progress is reported");
    assert.equal(outbox.filter((m) => m.type === "progress").at(-1).fraction, 1);

    // forget the browser build's curve (it has no thread pool to terminate) before the Node build verifies
    globalThis.curve_bn128 = null;
    const mpc = await readMpcFromBytes(reply.zkey);
    assert.equal(mpc.contributions.length, 1);
    assert.equal(mpc.contributions[0].hash, reply.contributionHash);
    assert.equal(mpc.contributions[0].name, "Phone");

    const out = join(root, "from-worker.zkey");
    await writeFile(out, reply.zkey);
    assert.deepEqual(await verifyZkey({ r1cs: join(dataDir, "r1cs", "withdrawal.r1cs"), ptau: join(dataDir, "ptau", "tiny.ptau"), zkey: out }), { ok: true, errors: [] });

    // errors come back as messages, not as an unhandled rejection that would freeze the page
    const failure = Promise.withResolvers();
    globalThis.self.postMessage = (message) => message.type !== "progress" && failure.resolve(message);
    await globalThis.self.onmessage({ data: { id: 8, zkey: new Uint8Array(100), name: "x", entropyText: "" } });
    assert.equal((await failure.promise).type, "error");
  });
});
