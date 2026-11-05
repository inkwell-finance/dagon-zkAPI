import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, test } from "node:test";
import { SlotQueue, QueueError } from "../coordinator/queue.mjs";
import { RateLimiter } from "../coordinator/ratelimit.mjs";
import { attestationHash, attestationText, normalizeName } from "../lib/attestation.mjs";
import { fetchBeacon } from "../lib/beacon.mjs";
import { validateConfig } from "../lib/config.mjs";
import { fromHex, prettyHash, toHex } from "../lib/hex.mjs";
import { hermezPin } from "../lib/hermez.mjs";
import { ensurePtau } from "../lib/ptau.mjs";
import { readR1csHeader, ptauPowerNeeded } from "../lib/r1cs-info.mjs";
import { parseMpcSection } from "../lib/zkey-info.mjs";
import { fakeClock, r1csBytes, TINY_CIRCUITS } from "./helpers.mjs";

const queueOptions = { slotMs: 600_000, claimMs: 60_000, waitHeartbeatMs: 120_000, maxQueue: 3, maxPerKey: 2, finishedKeepMs: 300_000 };

describe("SlotQueue", () => {
  test("is first in, first out with one active contributor", () => {
    const clock = fakeClock();
    const queue = new SlotQueue({ now: clock.now.bind(clock), ...queueOptions });
    const a = queue.join({ name: "a", key: "k1" });
    const b = queue.join({ name: "b", key: "k2" });
    assert.deepEqual([a.state, b.state, queue.ahead(b)], ["active", "waiting", 1]);
    queue.finish(a, { round: 1 });
    assert.equal(queue.touch(b.token).state, "active");
    assert.equal(queue.touch(a.token).state, "done");
  });

  test("an active slot expires after slotMs unless an upload is in progress", () => {
    const clock = fakeClock();
    const queue = new SlotQueue({ now: clock.now.bind(clock), ...queueOptions });
    const a = queue.join({ name: "a", key: "k1" });
    queue.touch(a.token);
    clock.advance(599_999);
    assert.equal(queue.touch(a.token).state, "active");
    queue.startUpload(a);
    clock.advance(10 * 60_000);
    assert.equal(queue.touch(a.token).state, "active", "an upload in flight is not cut off by the slot clock");
    queue.cancelUpload(a);
    assert.equal(queue.touch(a.token).state, "expired");
  });

  test("a turn nobody connects to is given up after claimMs", () => {
    const clock = fakeClock();
    const queue = new SlotQueue({ now: clock.now.bind(clock), ...queueOptions });
    const a = queue.join({ name: "a", key: "k1" });
    const b = queue.join({ name: "b", key: "k2" });
    clock.advance(61_000);
    queue.tick();
    assert.deepEqual([a.state, b.state], ["expired", "active"]);
  });

  test("waiting tickets that stop polling are dropped", () => {
    const clock = fakeClock();
    const queue = new SlotQueue({ now: clock.now.bind(clock), ...queueOptions });
    const a = queue.join({ name: "a", key: "k1" });
    queue.touch(a.token);
    const b = queue.join({ name: "b", key: "k2" });
    const c = queue.join({ name: "c", key: "k3" });
    clock.advance(100_000);
    queue.touch(a.token);
    queue.touch(c.token);
    clock.advance(30_000);
    queue.tick();
    assert.equal(b.state, "expired");
    assert.equal(c.state, "waiting");
    assert.equal(queue.ahead(c), 1);
  });

  test("limits the queue and tickets per connection; finished tickets are forgotten", () => {
    const clock = fakeClock();
    const queue = new SlotQueue({ now: clock.now.bind(clock), ...queueOptions });
    queue.join({ name: "a", key: "k1" });
    queue.join({ name: "b", key: "k1" });
    assert.throws(() => queue.join({ name: "c", key: "k1" }), (e) => e instanceof QueueError && e.code === "too_many_tickets");
    queue.join({ name: "d", key: "k2" });
    assert.throws(() => queue.join({ name: "e", key: "k3" }), (e) => e.code === "queue_full");
    const first = queue.holder();
    queue.release(first);
    assert.equal(first.state, "expired");
    clock.advance(400_000);
    queue.tick();
    assert.equal(queue.touch(first.token), undefined);
  });
});

describe("RateLimiter", () => {
  test("counts per bucket and connection and resets after the window", () => {
    const clock = fakeClock();
    const limiter = new RateLimiter({ now: clock.now.bind(clock), limits: { join: { max: 2, windowMs: 1000 } } });
    const key = limiter.key("203.0.113.9");
    assert.equal(limiter.key("203.0.113.9"), key);
    assert.notEqual(limiter.key("203.0.113.10"), key);
    assert.deepEqual([limiter.check("join", key), limiter.check("join", key), limiter.check("join", key)], [0, 0, 1]);
    clock.advance(1001);
    assert.equal(limiter.check("join", key), 0);
  });
});

describe("helpers", () => {
  test("hex round trips and snarkjs-style hash layout", () => {
    assert.equal(toHex(fromHex("00ff10")), "00ff10");
    assert.throws(() => fromHex("abc"));
    assert.equal(prettyHash("a".repeat(128)).split("\n").length, 4);
  });

  test("attestations are a fixed text over round and per-circuit contribution hashes", async () => {
    const circuits = [{ id: "request", contributionHash: "aa" }, { id: "withdrawal", contributionHash: "bb" }];
    assert.equal(attestationText(7, circuits), "dagon-zkapi-ceremony-v1\nround:7\nrequest:aa\nwithdrawal:bb\n");
    assert.equal(await attestationHash(7, circuits), createHash("sha256").update(attestationText(7, circuits)).digest("hex"));
  });

  test("names are normalised and restricted", () => {
    assert.equal(normalizeName("  Ada   Lovelace "), "Ada Lovelace");
    assert.equal(normalizeName(""), "Anonymous");
    assert.equal(normalizeName(undefined), "Anonymous");
    assert.throws(() => normalizeName("x".repeat(65)));
    assert.throws(() => normalizeName("bad\u202ename"), /may only contain/);
    assert.throws(() => normalizeName("<script>\u0000"));
  });

  test("the Hermez table pins power 16 as ceremony.json does", async () => {
    const config = JSON.parse(await readFile(new URL("../ceremony.json", import.meta.url), "utf8"));
    validateConfig(config);
    const pin = hermezPin(config.ptau.power);
    assert.equal(pin.hash, config.ptau.hash);
    assert.equal(config.ptau.url, pin.url);
    assert.equal(hermezPin(3), undefined);
  });

  test("ceremony.json validation rejects unsafe or incomplete configurations", async () => {
    const good = JSON.parse(await readFile(new URL("../ceremony.json", import.meta.url), "utf8"));
    const broken = (change) => {
      const copy = structuredClone(good);
      change(copy);
      return () => validateConfig(copy);
    };
    assert.throws(broken((c) => (c.circuits[0].id = "../etc")), /lowercase identifier/);
    assert.throws(broken((c) => (c.circuits[1].id = "request")), /duplicate/);
    assert.throws(broken((c) => (c.ptau.hashAlgorithm = "md5")), /hashAlgorithm/);
    assert.throws(broken((c) => (c.beacon.source = "weather")), /beacon.source/);
    assert.throws(broken((c) => (c.beacon.applyAfter = "tomorrow")), /applyAfter/);
    assert.throws(broken((c) => (c.circuits[0].publicInputs = -1)), /publicInputs/);
  });
});

describe("r1cs and zkey readers", () => {
  test("the hand-made r1cs parses with the counts it was written with", async () => {
    const dir = await mkdtemp(join(tmpdir(), "r1cs-"));
    try {
      for (const [id, circuit] of Object.entries(TINY_CIRCUITS)) {
        await writeFile(join(dir, `${id}.r1cs`), r1csBytes(circuit));
        const header = await readR1csHeader(join(dir, `${id}.r1cs`));
        assert.deepEqual([header.nPubIn, header.nPrvIn, header.nPubOut, header.nConstraints], [circuit.nPubIn, circuit.nPrvIn, 0, circuit.constraints.length]);
        assert.equal(ptauPowerNeeded(header), Math.floor(Math.log2(circuit.constraints.length + circuit.nPubIn)) + 1);
      }
      await writeFile(join(dir, "bad.r1cs"), "nope nope nope");
      await assert.rejects(readR1csHeader(join(dir, "bad.r1cs")), /not an r1cs/);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("a truncated contribution section is rejected, not misread", () => {
    const head = new Uint8Array(68);
    new DataView(head.buffer).setUint32(64, 1, true);
    assert.throws(() => parseMpcSection(head), /truncated/);
  });
});

describe("Powers of Tau pin", () => {
  const bytes = new TextEncoder().encode("pretend this is a 144 MB file");
  const config = { ptau: { url: "https://primary.example/powers.ptau", mirrors: ["https://mirror.example/powers.ptau"], hash: createHash("blake2b512").update(bytes).digest("hex"), hashAlgorithm: "blake2b-512", power: 5 } };

  test("a download whose hash does not match the pin is refused and not kept", async () => {
    const dir = await mkdtemp(join(tmpdir(), "ptau-"));
    try {
      const fetcher = async () => new Response(new TextEncoder().encode("evil file"));
      await assert.rejects(ensurePtau(config, { dir, fetch: fetcher }), /does not match the pinned/);
      await assert.rejects(readFile(join(dir, "powers.ptau")), /ENOENT/);
      await assert.rejects(readFile(join(dir, "powers.ptau.download")), /ENOENT/);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("falls back to a mirror, and then reuses the verified file without downloading", async () => {
    const dir = await mkdtemp(join(tmpdir(), "ptau-"));
    try {
      const calls = [];
      const fetcher = async (url) => {
        calls.push(url);
        return url.startsWith("https://primary") ? new Response("down", { status: 503 }) : new Response(bytes);
      };
      const path = await ensurePtau(config, { dir, fetch: fetcher });
      assert.deepEqual(calls, ["https://primary.example/powers.ptau", "https://mirror.example/powers.ptau"]);
      assert.deepEqual(await readFile(path), Buffer.from(bytes));
      await ensurePtau(config, { dir, fetch: async () => assert.fail("must not download again") });
      await writeFile(path, "tampered on disk");
      await assert.rejects(ensurePtau(config, { dir, fetch: fetcher }), /does not match the pinned/);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("beacon sources", () => {
  const spec = { source: "bitcoin", height: 800000, applyAfter: "2026-01-01T00:00:00Z" };
  const hash = "00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72728a054";
  const apis = ["https://a.example/api", "https://b.example/api"];
  const now = () => Date.parse("2026-06-01T00:00:00Z");
  const serve = (blocks, tip) => async (url) => {
    const [, base, path] = /^(https:\/\/[^/]+\/api)(.*)$/.exec(url);
    if (path === "/blocks/tip/height") return new Response(String(tip));
    return new Response(blocks[base] ?? "", { status: blocks[base] ? 200 : 404 });
  };

  test("bitcoin: both explorers must agree and the block needs 6 confirmations", async () => {
    const ok = await fetchBeacon(spec, { fetch: serve({ [apis[0]]: hash, [apis[1]]: hash }, 800010), now, apis });
    assert.equal(ok.value, hash);
    assert.equal(ok.iterationsExp, 20);
    await assert.rejects(fetchBeacon(spec, { fetch: serve({ [apis[0]]: hash, [apis[1]]: "1".repeat(64) }, 800010), now, apis }), /disagree/);
    await assert.rejects(fetchBeacon(spec, { fetch: serve({ [apis[0]]: hash, [apis[1]]: hash }, 800003), now, apis }), /confirmations/);
  });

  test("nothing is fetched before applyAfter", async () => {
    await assert.rejects(fetchBeacon(spec, { fetch: async () => assert.fail("no request expected"), now: () => Date.parse("2025-12-31T23:59:59Z"), apis }), /may not be applied before/);
  });
});
