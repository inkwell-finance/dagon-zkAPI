// Runs the mirror Worker's sync() under node against a fake R2 binding and a fake coordinator.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { beforeEach, describe, test } from "node:test";

// Workers-only stream length enforcement; R2 verifies checksums, not a second Worker hash branch.
globalThis.FixedLengthStream = class extends TransformStream {
  constructor(length) {
    let size = 0;
    super({
      transform(chunk, controller) {
        size += chunk.byteLength;
        if (size > length) throw new Error(`length ${size} > ${length}`);
        controller.enqueue(chunk);
      },
      flush() {
        if (size !== length) throw new Error(`length ${size} != ${length}`);
      },
    });
    this.readable.knownLength = length;
  }
};

const { default: worker, sync, mirrorFile, prune, BUFFER_CAP } = await import("./worker.mjs");

const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
const bytesOf = (n, seed) => Uint8Array.from({ length: n }, (_, i) => (i * 31 + seed) & 0xff);
const text = (s) => new TextEncoder().encode(s);

// Minimal R2 binding: rejects streams of unknown length and verifies `sha256` like R2 does.
class FakeBucket {
  objects = new Map();
  puts = [];
  deletes = [];
  streamPuts = [];
  lists = [];
  async head(key) {
    const o = this.objects.get(key);
    return o ? { key, size: o.body.byteLength, checksums: o.sha256 ? { sha256: new Uint8Array(Buffer.from(o.sha256, "hex")).buffer } : {} } : null;
  }
  async put(key, value, options = {}) {
    let body;
    if (value instanceof ReadableStream) {
      this.streamPuts.push(key);
      if (value.knownLength === undefined) throw new TypeError("Provided readable stream must have a known length (request/response body or readable half of FixedLengthStream)");
      body = new Uint8Array(await new Response(value).arrayBuffer());
      if (body.byteLength !== value.knownLength) throw new Error(`length ${body.byteLength} != ${value.knownLength}`);
    } else body = new Uint8Array(value instanceof ArrayBuffer ? value : value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength));
    const checksum = typeof options.sha256 === "string" ? options.sha256 : options.sha256 && Buffer.from(options.sha256).toString("hex");
    if (checksum && sha(body) !== checksum) throw new Error("put: The SHA-256 checksum you specified did not match what we received.");
    this.objects.set(key, { body, sha256: checksum, uploaded: new Date() });
    this.puts.push(key);
  }
  async delete(key) {
    this.objects.delete(key);
    this.deletes.push(key);
  }
  async list({ prefix, cursor }) {
    this.lists.push({ prefix, cursor });
    const keys = [...this.objects.keys()].filter((k) => k.startsWith(prefix)).sort();
    const start = cursor ? Number(cursor) : 0;
    const page = keys.slice(start, start + 2); // tiny pages exercise the cursor loop
    const truncated = start + 2 < keys.length;
    return { objects: page.map((key) => ({ key, uploaded: this.objects.get(key).uploaded ?? new Date(0) })), truncated, ...(truncated ? { cursor: String(start + 2) } : {}) };
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
    if (file.status) return new Response("{}", { status: file.status });
    let offset = 0;
    const body = new ReadableStream({
      pull(c) {
        if (file.error) return c.error(new Error(file.error));
        if (offset === file.body.byteLength) return c.close();
        const end = Math.min(offset + 64 * 1024, file.body.byteLength);
        c.enqueue(file.body.subarray(offset, end));
        offset = end;
      },
    });
    const headers = file.gzip ? { "content-encoding": "gzip" } : file.chunked ? {} : { "content-length": String(file.body.byteLength) };
    return new Response(body, { headers: { ...headers, ...file.headers } });
  };
});

function serveFinalized() {
  const finalized = structuredClone(transcript);
  const contribution = { ...structuredClone(transcript.rounds[0]), round: 1, kind: "contribution" };
  const beacon = { round: 2, kind: "beacon", circuits: {} };
  served["closed.json"] = { body: text('{"round":1,"attestation":"test"}'), gzip: true };
  served["final/FINAL.md"] = { body: text("# Final keys") };
  for (const c of transcript.ceremony.circuits) {
    const key = bytesOf(zkeys[c].byteLength, 8);
    const vk = text(JSON.stringify({ circuit: c }));
    beacon.circuits[c] = { bytes: key.byteLength, sha256: sha(key), verificationKeySha256: sha(vk) };
    served[`rounds/0001/${c}.zkey`] = { body: zkeys[c] };
    served[`rounds/0002/${c}.zkey`] = { body: key };
    served[`final/${c}_final.zkey`] = { body: key, chunked: true };
    served[`final/${c}_verification_key.json`] = { body: vk, gzip: true };
  }
  served["rounds/0001/entry.json"] = { body: text(JSON.stringify(contribution)), gzip: true };
  served["rounds/0002/entry.json"] = { body: text(JSON.stringify(beacon)), gzip: true };
  finalized.rounds.push(contribution, beacon);
  served["transcript.json"] = { body: text(JSON.stringify(finalized)), gzip: true };
}

describe("ceremony mirror sync", () => {
  test("mirrors gzip JSON without length, replaces unverified zkeys, prunes stale files/ keys, writes transcript.json last", async () => {
    const env = { BUCKET: new FakeBucket() };
    // Left by a run before checksums were stored: right size, wrong bytes, no sha256.
    env.BUCKET.objects.set("files/rounds/0000/request.zkey", { body: bytesOf(5000, 9) });
    env.BUCKET.objects.set("files/r1cs/request.r1cs", { body: r1cs.request });
    env.BUCKET.objects.set("files/rounds/0001/request.zkey", { body: bytesOf(10, 5) }); // from an abandoned ceremony
    env.BUCKET.objects.set("files/closed.json", { body: text("{}") });
    env.BUCKET.objects.set("other/keep.bin", { body: bytesOf(10, 6) });
    env.BUCKET.objects.set("files/final/FINAL.md", { body: text("retained") });
    env.BUCKET.objects.set("round1/files/transcript.json", { body: text("{}") });
    env.BUCKET.objects.set("index.html", { body: text("landing page") });

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
    assert.deepEqual(env.BUCKET.deletes, ["files/rounds/0001/request.zkey"]);
    assert.ok(get("files/closed.json"));
    assert.ok(get("files/final/FINAL.md"));
    assert.ok(get("round1/files/transcript.json"));
    assert.ok(get("index.html"));
    assert.ok(get("other/keep.bin"), "keys outside files/ are never touched");

    // A second run downloads only the indexes and probes closure (404 while open).
    fetched = [];
    env.BUCKET.puts = [];
    await sync(env);
    assert.deepEqual(fetched, ["transcript.json", "ceremony.json", "closed.json"]);
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

  test("mirrors closure before a beacon exists, replacing an older checkpoint", async () => {
    const env = { BUCKET: new FakeBucket() };
    env.BUCKET.objects.set("files/closed.json", { body: text("old") });
    served["closed.json"] = { body: text('{"round":0}'), gzip: true };
    await sync(env);
    assert.deepEqual(env.BUCKET.objects.get("files/closed.json").body, served["closed.json"].body);
    assert.ok(env.BUCKET.puts.indexOf("files/closed.json") < env.BUCKET.puts.indexOf("files/transcript.json"));
    assert.deepEqual(env.BUCKET.deletes, []);
  });

  test("a beacon round (without transcript.final) mirrors and verifies every final artifact", async () => {
    serveFinalized();
    const env = { BUCKET: new FakeBucket() };
    env.BUCKET.objects.set("files/final/request_final.zkey", { body: bytesOf(zkeys.request.length, 9), sha256: sha(bytesOf(zkeys.request.length, 9)) });
    await sync(env);
    for (const key of Object.keys(served).filter((k) => k === "closed.json" || k.startsWith("final/"))) {
      assert.deepEqual(env.BUCKET.objects.get(`files/${key}`)?.body, served[key].body, key);
      assert.ok(env.BUCKET.puts.indexOf(`files/${key}`) < env.BUCKET.puts.indexOf("files/transcript.json"));
    }
    assert.ok(env.BUCKET.streamPuts.includes("files/final/request_final.zkey"));
    assert.equal(env.BUCKET.objects.get("files/final/request_final.zkey").sha256, sha(served["final/request_final.zkey"].body));
    assert.deepEqual(env.BUCKET.deletes, []);
  });

  for (const missing of ["closed.json", "final/FINAL.md", "final/request_final.zkey", "final/request_verification_key.json"]) {
    test(`finalization waits for ${missing} before publishing or pruning`, async () => {
      serveFinalized();
      delete served[missing];
      const env = { BUCKET: new FakeBucket() };
      env.BUCKET.objects.set("files/stale", { body: text("keep until success") });
      await assert.rejects(sync(env), /GET .* -> 404/);
      assert.ok(!env.BUCKET.objects.has("files/transcript.json"));
      assert.deepEqual(env.BUCKET.lists, []);
      assert.deepEqual(env.BUCKET.deletes, []);
    });
  }

  for (const key of ["final/request_final.zkey", "final/request_verification_key.json"]) {
    test(`rejects corrupt ${key} against the beacon round hash`, async () => {
      serveFinalized();
      served[key].body = bytesOf(served[key].body.length, 4);
      const env = { BUCKET: new FakeBucket() };
      await assert.rejects(sync(env), /removed from the mirror/);
      assert.ok(!env.BUCKET.objects.has(`files/${key}`));
      assert.ok(!env.BUCKET.objects.has("files/transcript.json"));
      assert.deepEqual(env.BUCKET.lists, []);
    });
  }

  test("a transient closure fetch failure aborts instead of treating closure as absent", async () => {
    served["closed.json"] = { status: 503 };
    const env = { BUCKET: new FakeBucket() };
    env.BUCKET.objects.set("files/closed.json", { body: text("retained") });
    await assert.rejects(sync(env), /closed\.json -> 503/);
    assert.deepEqual(env.BUCKET.lists, []);
    assert.deepEqual(env.BUCKET.deletes, []);
    assert.ok(!env.BUCKET.objects.has("files/transcript.json"));
  });

  for (const [name, file, error] of [
    ["fetch", { status: 503 }, /transcript\.json -> 503/],
    ["parse", { body: text("{"), gzip: true }, /JSON/],
    ["body", { body: text("{}"), error: "connection reset" }, /connection reset/],
  ]) {
    test(`transcript ${name} failure never lists or prunes`, async () => {
      served["transcript.json"] = file;
      const env = { BUCKET: new FakeBucket() };
      env.BUCKET.objects.set("files/stale", { body: text("retained") });
      await assert.rejects(sync(env), error);
      assert.deepEqual(env.BUCKET.lists, []);
      assert.deepEqual(env.BUCKET.deletes, []);
      assert.deepEqual(env.BUCKET.puts, []);
    });
  }

  for (const key of ["transcript.json", "ceremony.json"]) {
    test(`${key} is also capped before publication or pruning`, async () => {
      served[key] = { body: new Uint8Array(BUFFER_CAP + 1), gzip: true };
      const env = { BUCKET: new FakeBucket() };
      await assert.rejects(sync(env), /body exceeds/);
      assert.deepEqual(env.BUCKET.lists, []);
      assert.deepEqual(env.BUCKET.deletes, []);
      assert.deepEqual(env.BUCKET.puts, []);
    });
  }

  test("paging collects all stale keys before deletion, retaining root/archive/close/final keys", async () => {
    const env = { BUCKET: new FakeBucket() };
    const protectedKeys = ["index.html", "round1/a", "files-other/a", "files/closed.json", "files/final/a", "files/ceremony.json", "files/transcript.json", "files/keep"];
    const stale = Array.from({ length: 7 }, (_, i) => `files/stale${i}`);
    for (const key of [...protectedKeys, ...stale]) env.BUCKET.objects.set(key, { body: text(key) });
    assert.equal(await prune(env, ["keep"], new Date()), stale.length);
    assert.deepEqual(env.BUCKET.deletes, stale);
    assert.deepEqual([...env.BUCKET.objects.keys()], protectedKeys);
    assert.ok(env.BUCKET.lists.length > 1);
    assert.ok(env.BUCKET.lists.every((page) => page.prefix === "files/"));
  });

  test("listing may return an empty truncated page; even stray out-of-prefix results are not deleted", async () => {
    const bucket = new FakeBucket();
    let calls = 0;
    bucket.list = async ({ prefix, cursor }) => {
      assert.equal(prefix, "files/");
      if (++calls === 1) return { objects: [], truncated: true, cursor: "opaque" };
      assert.equal(cursor, "opaque");
      return { objects: [{ key: "index.html" }, { key: "round1/a" }, { key: "files/stale", uploaded: new Date(0) }], truncated: false };
    };
    assert.equal(await prune({ BUCKET: bucket }, [], new Date()), 1);
    assert.deepEqual(bucket.deletes, ["files/stale"]);
    assert.equal(calls, 2);
  });

  test("a transient second-page listing failure deletes nothing, after indexes were published", async () => {
    const env = { BUCKET: new FakeBucket() };
    env.BUCKET.objects.set("files/aaa-stale", { body: text("retained") });
    const list = env.BUCKET.list.bind(env.BUCKET);
    env.BUCKET.list = async (options) => {
      if (options.cursor) throw new Error("R2 listing unavailable");
      return list(options);
    };
    await assert.rejects(sync(env), /R2 listing unavailable/);
    assert.equal(env.BUCKET.puts.at(-1), "files/transcript.json");
    assert.deepEqual(env.BUCKET.deletes, []);
  });

  test("an overlapping run's newer uploads are not pruned by an older transcript", async () => {
    const env = { BUCKET: new FakeBucket() };
    env.BUCKET.objects.set("files/rounds/0001/request.zkey", { body: bytesOf(10, 5), uploaded: new Date(0) });
    const put = env.BUCKET.put.bind(env.BUCKET);
    env.BUCKET.put = async (key, value, options) => {
      // A concurrent run that saw round 2 uploads it while this run (which sees only round 0) is in progress.
      if (key === "files/transcript.json") await put("files/rounds/0002/request.zkey", bytesOf(10, 6));
      return put(key, value, options);
    };
    await sync(env);
    assert.deepEqual(env.BUCKET.deletes, ["files/rounds/0001/request.zkey"]);
    assert.ok(env.BUCKET.objects.has("files/rounds/0002/request.zkey"));
  });

  test("pruning tolerates R2 timestamps behind the Worker clock, including the margin boundary", async () => {
    const env = { BUCKET: new FakeBucket() };
    const started = new Date(120_000);
    for (const [key, uploaded] of [["old", 59_999], ["boundary", 60_000], ["skewed", 119_000], ["new", 120_001]]) {
      env.BUCKET.objects.set(`files/${key}`, { body: text(key), uploaded: new Date(uploaded) });
    }
    assert.equal(await prune(env, [], started), 1);
    assert.deepEqual(env.BUCKET.deletes, ["files/old"]);
  });

  test("a transient put failure preserves an unverified legacy zkey and retries until one successful migration", async () => {
    const env = { BUCKET: new FakeBucket() };
    const key = "rounds/0000/request.zkey";
    const old = bytesOf(5000, 9);
    env.BUCKET.objects.set(`files/${key}`, { body: old });
    served[key] = { body: zkeys.request, error: "connection reset" };
    await assert.rejects(sync(env), /request\.zkey: put failed: .*connection reset/);
    assert.deepEqual(env.BUCKET.objects.get(`files/${key}`).body, old);
    assert.deepEqual(env.BUCKET.deletes, []);
    assert.ok(!env.BUCKET.objects.has("files/transcript.json"));
    served[key] = { body: zkeys.request };
    await sync(env);
    assert.deepEqual(env.BUCKET.objects.get(`files/${key}`).body, zkeys.request);
    assert.equal(env.BUCKET.objects.get(`files/${key}`).sha256, sha(zkeys.request));
    fetched = [];
    await sync(env);
    assert.ok(!fetched.includes(key));
  });

  test("a failed put removes an object with a proven stored checksum mismatch", async () => {
    const env = { BUCKET: new FakeBucket() };
    const key = "rounds/0000/request.zkey";
    const old = bytesOf(5000, 9);
    env.BUCKET.objects.set(`files/${key}`, { body: old, sha256: sha(old) });
    served[key] = { body: zkeys.request, error: "connection reset" };
    await assert.rejects(sync(env), /removed from the mirror/);
    assert.deepEqual(env.BUCKET.deletes, [`files/${key}`]);
    assert.ok(!env.BUCKET.objects.has(`files/${key}`));
  });

  test("a failed put removes a legacy object whose stored size disagrees with the transcript", async () => {
    const env = { BUCKET: new FakeBucket() };
    const key = "rounds/0000/request.zkey";
    env.BUCKET.objects.set(`files/${key}`, { body: bytesOf(zkeys.request.byteLength - 1, 9) });
    served[key] = { body: zkeys.request, error: "connection reset" };
    await assert.rejects(sync(env), /removed from the mirror/);
    assert.deepEqual(env.BUCKET.deletes, [`files/${key}`]);
  });

  test("a successful second finalized run skips verified verification keys", async () => {
    serveFinalized();
    const env = { BUCKET: new FakeBucket() };
    await sync(env);
    fetched = [];
    await sync(env);
    assert.ok(!fetched.some((k) => k.endsWith("_verification_key.json") || k.endsWith(".zkey")));
    assert.ok(fetched.includes("final/FINAL.md"));
  });

  test("a failed streamed put keeps an unhashed refreshed file; a current verification key is not refetched", async () => {
    serveFinalized();
    const env = { BUCKET: new FakeBucket() };
    await sync(env);
    served["closed.json"] = { body: served["closed.json"].body, error: "connection reset" };
    const before = env.BUCKET.objects.get("files/closed.json").body;
    fetched = [];
    await assert.rejects(sync(env), /closed\.json: put failed: .*connection reset/);
    assert.deepEqual(env.BUCKET.objects.get("files/closed.json").body, before);
    assert.deepEqual(env.BUCKET.deletes, []);
    assert.ok(!fetched.some((k) => k.endsWith("_verification_key.json") || k.endsWith(".zkey")));
  });

  for (const encoding of [{ chunked: true }, { gzip: true, headers: { "content-length": "42" } }]) {
    test(`streams transcript-sized zkeys with ${encoding.gzip ? "compressed" : "missing"} content-length`, async () => {
      served["rounds/0000/request.zkey"] = { body: zkeys.request, ...encoding };
      const env = { BUCKET: new FakeBucket() };
      await sync(env);
      assert.ok(env.BUCKET.streamPuts.includes("files/rounds/0000/request.zkey"));
      assert.deepEqual(env.BUCKET.objects.get("files/rounds/0000/request.zkey").body, zkeys.request);
    });
  }

  for (const size of [4999, 5001]) {
    test(`rejects a chunked zkey of ${size} bytes when the transcript says 5000`, async () => {
      served["rounds/0000/request.zkey"] = { body: bytesOf(size, 1), chunked: true };
      const env = { BUCKET: new FakeBucket() };
      await assert.rejects(sync(env), /removed from the mirror/);
      assert.ok(!env.BUCKET.objects.has("files/transcript.json"));
      assert.deepEqual(env.BUCKET.lists, []);
    });
  }

  test("a 50 MiB unknown-length zkey is streamed without tee or whole-body digest", async (t) => {
    const chunk = new Uint8Array(64 * 1024).fill(7);
    const count = 800;
    const hash = createHash("sha256");
    for (let i = 0; i < count; i++) hash.update(chunk);
    const expected = { bytes: chunk.length * count, sha256: hash.digest("hex") };
    let pulled = 0;
    globalThis.fetch = async () => {
      const response = new Response(new ReadableStream({
        pull(controller) {
          if (pulled++ < count) controller.enqueue(chunk);
          else controller.close();
        },
      }));
      response.body.tee = () => { throw new Error("must not tee large bodies"); };
      return response;
    };
    t.mock.method(crypto.subtle, "digest", () => { throw new Error("must not buffer large bodies"); });
    let stored = false;
    const bucket = {
      head: async () => null,
      async put(key, body, options) {
        assert.equal(key, "files/rounds/0000/request.zkey");
        assert.ok(body instanceof ReadableStream);
        assert.equal(body.knownLength, expected.bytes);
        assert.equal(options.sha256, expected.sha256);
        let size = 0;
        const received = createHash("sha256");
        for await (const value of body) { size += value.byteLength; received.update(value); }
        assert.equal(size, expected.bytes);
        assert.equal(received.digest("hex"), expected.sha256);
        stored = true;
      },
    };
    assert.equal(await mirrorFile({ BUCKET: bucket }, "rounds/0000/request.zkey", expected), "uploaded");
    assert.ok(stored);
  });

  test("the default export is the cron handler", async () => {
    const env = { BUCKET: new FakeBucket() };
    let pending;
    await worker.scheduled({}, env, { waitUntil: (p) => (pending = p) });
    await pending;
    assert.equal(env.BUCKET.puts.at(-1), "files/transcript.json");
  });
});
