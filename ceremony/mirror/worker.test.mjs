// Runs the mirror Worker's sync() under node against a fake R2 binding and a fake coordinator.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { beforeEach, describe, test } from "node:test";

// Workers-only globals the streaming path uses.
crypto.DigestStream = class extends WritableStream {
  constructor(algorithm) {
    assert.equal(algorithm, "SHA-256");
    const hash = createHash("sha256");
    let resolve;
    const digest = new Promise((r) => (resolve = r));
    super({ write: (chunk) => hash.update(chunk), close: () => resolve(new Uint8Array(hash.digest()).buffer) });
    this.digest = digest;
  }
};
globalThis.FixedLengthStream = class extends TransformStream {
  constructor(length) {
    super();
    this.readable.knownLength = length;
  }
};

const { default: worker, sync } = await import("./worker.mjs");

const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
const bytesOf = (n, seed) => Uint8Array.from({ length: n }, (_, i) => (i * 31 + seed) & 0xff);
const text = (s) => new TextEncoder().encode(s);

// Minimal R2 binding: rejects streams of unknown length and verifies `sha256` like R2 does.
class FakeBucket {
  objects = new Map();
  puts = [];
  deletes = [];
  async head(key) {
    const o = this.objects.get(key);
    return o ? { key, size: o.body.byteLength, checksums: o.sha256 ? { sha256: new Uint8Array(Buffer.from(o.sha256, "hex")).buffer } : {} } : null;
  }
  async put(key, value, options = {}) {
    let body;
    if (value instanceof ReadableStream) {
      if (value.knownLength === undefined) throw new TypeError("Provided readable stream must have a known length (request/response body or readable half of FixedLengthStream)");
      body = new Uint8Array(await new Response(value).arrayBuffer());
      if (body.byteLength !== value.knownLength) throw new Error(`length ${body.byteLength} != ${value.knownLength}`);
    } else body = new Uint8Array(value instanceof ArrayBuffer ? value : value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength));
    if (options.sha256 && sha(body) !== options.sha256) throw new Error("put: The SHA-256 checksum you specified did not match what we received.");
    this.objects.set(key, { body, sha256: options.sha256 });
    this.puts.push(key);
  }
  async delete(key) {
    this.objects.delete(key);
    this.deletes.push(key);
  }
  async list({ prefix, cursor }) {
    const keys = [...this.objects.keys()].filter((k) => k.startsWith(prefix)).sort();
    const start = cursor ? Number(cursor) : 0;
    const page = keys.slice(start, start + 2); // tiny pages exercise the cursor loop
    const truncated = start + 2 < keys.length;
    return { objects: page.map((key) => ({ key })), truncated, ...(truncated ? { cursor: String(start + 2) } : {}) };
  }
}

const zkeys = { request: bytesOf(5000, 1), withdrawal: bytesOf(3000, 2) };
const r1cs = { request: bytesOf(700, 3), withdrawal: bytesOf(600, 4) };
const transcript = {
  version: 1,
  ceremony: { name: "test", circuits: ["request", "withdrawal"] },
  rounds: [{ round: 0, kind: "init", circuits: Object.fromEntries(Object.entries(zkeys).map(([id, b]) => [id, { sha256: sha(b), bytes: b.byteLength }])) }],
};
const entry = text(JSON.stringify(transcript.rounds[0]));

let served;
let fetched;
beforeEach(() => {
  served = {
    "transcript.json": { body: text(JSON.stringify(transcript)), gzip: true },
    "ceremony.json": { body: text('{"name":"test"}'), gzip: true },
    "rounds/0000/entry.json": { body: entry, gzip: true },
    "r1cs/request.r1cs": { body: r1cs.request },
    "r1cs/withdrawal.r1cs": { body: r1cs.withdrawal },
    "rounds/0000/request.zkey": { body: zkeys.request },
    "rounds/0000/withdrawal.zkey": { body: zkeys.withdrawal },
  };
  fetched = [];
  // Like a Worker's fetch: a gzip response arrives decoded, chunked, with content-encoding kept and no content-length.
  globalThis.fetch = async (url) => {
    const path = new URL(url).pathname.slice("/files/".length);
    fetched.push(path);
    const file = served[path];
    if (!file) return new Response("{}", { status: 404 });
    const body = new ReadableStream({
      start(c) {
        for (let i = 0; i < file.body.byteLength; i += 1024) c.enqueue(file.body.slice(i, i + 1024));
        c.close();
      },
    });
    const headers = file.gzip ? { "content-encoding": "gzip" } : { "content-length": String(file.body.byteLength) };
    return new Response(body, { headers });
  };
});

describe("ceremony mirror sync", () => {
  test("mirrors gzip JSON without length, replaces unverified zkeys, prunes stale files/ keys, writes transcript.json last", async () => {
    const env = { BUCKET: new FakeBucket() };
    // Left by a run before checksums were stored: right size, wrong bytes, no sha256.
    env.BUCKET.objects.set("files/rounds/0000/request.zkey", { body: bytesOf(5000, 9) });
    env.BUCKET.objects.set("files/r1cs/request.r1cs", { body: r1cs.request });
    env.BUCKET.objects.set("files/rounds/0001/request.zkey", { body: bytesOf(10, 5) }); // from an abandoned ceremony
    env.BUCKET.objects.set("files/closed.json", { body: text("{}") });
    env.BUCKET.objects.set("other/keep.bin", { body: bytesOf(10, 6) });

    await sync(env);

    const get = (k) => env.BUCKET.objects.get(k)?.body;
    assert.deepEqual(get("files/rounds/0000/entry.json"), entry);
    assert.deepEqual(get("files/rounds/0000/request.zkey"), zkeys.request);
    assert.deepEqual(get("files/rounds/0000/withdrawal.zkey"), zkeys.withdrawal);
    assert.equal(env.BUCKET.objects.get("files/rounds/0000/request.zkey").sha256, sha(zkeys.request));
    assert.deepEqual(get("files/r1cs/withdrawal.r1cs"), r1cs.withdrawal);
    assert.equal(new TextDecoder().decode(get("files/transcript.json")), JSON.stringify(transcript));
    assert.ok(get("files/ceremony.json"));
    assert.ok(!fetched.includes("r1cs/request.r1cs"), "present r1cs is not downloaded again");

    assert.equal(env.BUCKET.puts.at(-1), "files/transcript.json");
    assert.equal(env.BUCKET.puts.at(-2), "files/ceremony.json");
    assert.ok(env.BUCKET.puts.every((k) => k.startsWith("files/")));
    assert.ok(env.BUCKET.deletes.every((k) => k.startsWith("files/")));
    assert.deepEqual(env.BUCKET.deletes.sort(), ["files/closed.json", "files/rounds/0001/request.zkey"]);
    assert.ok(get("other/keep.bin"), "keys outside files/ are never touched");

    // A second run finds every zkey current by size and checksum and downloads nothing but the two indexes.
    fetched = [];
    env.BUCKET.puts = [];
    await sync(env);
    assert.deepEqual(fetched, ["transcript.json", "ceremony.json"]);
    assert.deepEqual(env.BUCKET.puts, ["files/ceremony.json", "files/transcript.json"]);
  });

  test("a zkey whose bytes disagree with the transcript is deleted and the transcript is not published", async () => {
    const env = { BUCKET: new FakeBucket() };
    served["rounds/0000/withdrawal.zkey"] = { body: bytesOf(3000, 7) }; // right size, wrong hash
    await assert.rejects(sync(env), /withdrawal\.zkey: .*removed from the mirror/);
    assert.ok(!env.BUCKET.objects.has("files/rounds/0000/withdrawal.zkey"));
    assert.ok(env.BUCKET.deletes.includes("files/rounds/0000/withdrawal.zkey"));
    assert.ok(!env.BUCKET.objects.has("files/transcript.json"));
    assert.ok(!env.BUCKET.objects.has("files/ceremony.json"));
  });

  test("a buffered body over the cap is refused", async () => {
    const env = { BUCKET: new FakeBucket() };
    served["rounds/0000/entry.json"] = { body: new Uint8Array(8 * 1024 * 1024 + 1), gzip: true };
    await assert.rejects(sync(env), /entry\.json: body exceeds/);
    assert.ok(!env.BUCKET.objects.has("files/transcript.json"));
  });

  test("the default export is the cron handler", async () => {
    const env = { BUCKET: new FakeBucket() };
    let pending;
    await worker.scheduled({}, env, { waitUntil: (p) => (pending = p) });
    await pending;
    assert.equal(env.BUCKET.puts.at(-1), "files/transcript.json");
  });
});
