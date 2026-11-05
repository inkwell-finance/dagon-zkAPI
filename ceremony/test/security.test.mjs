import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtemp, readFile, rm, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Coordinator, DEFAULT_QUEUE } from "../coordinator/coordinator.mjs";
import { SlotQueue } from "../coordinator/queue.mjs";
import { buildApp } from "../coordinator/app.mjs";
import { Store } from "../coordinator/store.mjs";
import { fetchBeacon, drandRoundTime, DRAND_DEFAULT_CHAIN } from "../lib/beacon.mjs";
import { downloadTo, fetchWithRetry } from "../lib/files.mjs";
import { validateConfig } from "../lib/config.mjs";
import { requireMemory, MIN_MEMORY_BYTES } from "../coordinator/resources.mjs";
import { receiveBundle } from "../coordinator/receive.mjs";
import { encodeBundle } from "../lib/bundle.mjs";
import { sha256Hex } from "../lib/hex.mjs";
import { readMpcFromBytes, readMpcFromFile } from "../lib/zkey-info.mjs";
import { initCeremony } from "../coordinator/init.mjs";
import { attestationHash } from "../lib/attestation.mjs";
import { contributeZkey } from "../lib/contribute-core.mjs";
import { terminateThreads, verifyZkey } from "../lib/snark.mjs";
import { fakeClock, makeFixture } from "./helpers.mjs";
import { readR1csHeader } from "../lib/r1cs-info.mjs";

function coordinatorFixture({ stagingError, uploadMs = 30 } = {}) {
  let time = Date.parse("2026-11-01T00:00:00Z");
  const now = () => time;
  const queue = new SlotQueue({ now, ...DEFAULT_QUEUE });
  const store = { dir: "unused", isClosed: async () => false, requireSpace: async () => {}, newStaging: async () => { if (stagingError) throw new Error("ENOSPC"); return "unused"; }, discard: async () => {} };
  const config = { contributionsCloseAt: "2026-12-04T00:00:00Z", ptau: { url: "https://example.invalid/a.ptau" }, circuits: [{ id: "request" }] };
  const coordinator = new Coordinator({ store, config, queue, now, verify: async () => assert.fail("no verifier may start"), uploadMs });
  coordinator.latest = { round: 0, circuits: { request: { bytes: 10 } } };
  return { coordinator, advance: (t) => { time = t; } };
}

test("queue JSON enforces streamed bytes without or with misleading Content-Length", async () => {
  const { coordinator } = coordinatorFixture();
  const app = buildApp({ coordinator, assets: new Map(), now: Date.now });
  for (const headers of [{}, { "content-length": "1" }]) {
    const result = await app.request("/api/queue", { method: "POST", headers, body: JSON.stringify({ name: "A", padding: "x".repeat(10000) }) });
    assert.equal(result.status, 413);
  }
  assert.equal(coordinator.queue.length(), 0);
});

test("released upload is cancelled and cannot revive its ticket", async () => {
  const { coordinator } = coordinatorFixture({ uploadMs: 1000 });
  const a = await coordinator.join({ name: "A", key: "a" });
  let pulling;
  const pulled = new Promise((resolve) => { pulling = resolve; });
  let cancelled = false;
  const stream = new ReadableStream({ pull() { pulling(); }, cancel() { cancelled = true; } }, { highWaterMark: 0 });
  const upload = coordinator.receive(a, stream, 100);
  const rejected = assert.rejects(upload, /released/);
  await pulled;
  coordinator.queue.release(a);
  const b = await coordinator.join({ name: "B", key: "b" });
  await rejected;
  assert.equal(cancelled, true);
  assert.equal(a.state, "expired");
  assert.equal(b.state, "active");
  assert.throws(() => coordinator.queue.startVerify(a), /no longer owns/);
  await coordinator.settled();
});

test("stalled upload has a real cancellation deadline; staging failure releases uploading state", async () => {
  const { coordinator } = coordinatorFixture();
  const ticket = await coordinator.join({ name: "A", key: "a" });
  await assert.rejects(coordinator.receive(ticket, new ReadableStream(), 100), /too long/);
  assert.equal(ticket.uploading, false);
  const broken = coordinatorFixture({ stagingError: true }).coordinator;
  const t = await broken.join({ name: "B", key: "b" });
  await assert.rejects(broken.receive(t, new ReadableStream(), 100), /ENOSPC/);
  assert.equal(t.uploading, false);
});

test("committed cutoff rejects join, download and upload even without closed.json", async () => {
  const { coordinator, advance } = coordinatorFixture();
  const ticket = await coordinator.join({ name: "A", key: "a" });
  advance(Date.parse(coordinator.config.contributionsCloseAt));
  await assert.rejects(coordinator.join({ name: "B", key: "b" }), /closed/);
  await assert.rejects(coordinator.openRound(ticket, "request"), /closed/);
  await assert.rejects(coordinator.receive(ticket, new ReadableStream(), 100), /closed/);
});

test("post-commit transcript failures are distinguished and recoverable", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ceremony-store-"));
  try {
    const store = new Store(dir);
    await writeFile(store.path("ceremony.json"), JSON.stringify({ name: "test", circuits: [] }));
    const staging = await store.newStaging();
    store.writeTranscript = async () => { throw new Error("ENOSPC"); };
    await assert.rejects(store.promote(staging, { round: 0, kind: "init" }), (e) => e.committed === true);
    assert.equal((await store.latest()).round, 0);
    const repaired = new Store(dir);
    await repaired.writeTranscript();
    assert.equal(JSON.parse(await readFile(store.path("transcript.json"))).rounds.length, 1);
    await store.newStaging();
    await repaired.cleanStaging();
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test("fresh cache downloads are atomic and rate-limit Retry-After is honored", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ceremony-cache-"));
  try {
    const dest = join(dir, "missing", "a.ptau");
    await downloadTo("https://example.invalid", dest, { fetch: async () => new Response("complete") });
    assert.equal(await readFile(dest, "utf8"), "complete");
    const broken = new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("partial"));
        setTimeout(() => controller.error(new Error("transfer interrupted")), 0);
      },
    });
    await assert.rejects(downloadTo("https://example.invalid", dest, { fetch: async () => new Response(broken) }), /transfer interrupted/);
    assert.equal(await readFile(dest, "utf8"), "complete", "failed replacement preserves the complete cache entry");
    let calls = 0;
    const sleeps = [];
    const response = await fetchWithRetry("https://example.invalid", { fetch: async () => ++calls === 1 ? new Response("wait", { status: 429, headers: { "retry-after": "2" } }) : new Response("ok"), sleep: async (ms) => sleeps.push(ms) });
    assert.equal(response.status, 200);
    assert.deepEqual(sleeps, [2000]);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test("drand rejects forged signatures and configurations cannot disguise an old round", async () => {
  const spec = { source: "drand", chain: DRAND_DEFAULT_CHAIN, round: 1, applyAfter: new Date(drandRoundTime(1)).toISOString() };
  await assert.rejects(fetchBeacon(spec, { fetch: async () => Response.json({ round: 1, signature: "00", randomness: "0".repeat(64) }) }), /signature encoding/);
  const config = JSON.parse(await readFile(new URL("../ceremony.json", import.meta.url), "utf8"));
  config.beacon.round = 1;
  assert.throws(() => validateConfig(config), /scheduled drand/);
});

test("shutdown closes admission even while the disk-marker check is pending", async () => {
  const { coordinator } = coordinatorFixture();
  let resolveMarker;
  coordinator.store.isClosed = () => new Promise((resolve) => { resolveMarker = resolve; });
  const pending = coordinator.join({ name: "Late", key: "late" });
  await coordinator.shutdown();
  resolveMarker(false);
  await assert.rejects(pending, /closed/);
  assert.equal(coordinator.queue.length(), 0);
});

test("graceful shutdown finishes and promotes a verification admitted before it", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ceremony-shutdown-"));
  try {
    const fx = await makeFixture(join(dir, "fixture"));
    const dataDir = join(dir, "data");
    await initCeremony({ configPath: fx.configPath, r1csDir: fx.r1csDir, dataDir, ptauFile: fx.ptauPath });
    let started, release;
    const verifying = new Promise((resolve) => { started = resolve; });
    const gate = new Promise((resolve) => { release = resolve; });
    const clock = fakeClock();
    const coordinator = await Coordinator.open({ dataDir, now: clock.now.bind(clock), verify: async (args) => { started(); await gate; return verifyZkey(args); } });
    const ticket = await coordinator.join({ name: "Alice", key: "a" });
    const meta = { v: 1, round: 0, name: "Alice", attestation: "", circuits: [] };
    const zkeys = [];
    for (const id of coordinator.circuitIds) {
      const out = await contributeZkey({ zkey: new Uint8Array(await readFile(join(dataDir, "rounds", "0000", `${id}.zkey`))), name: "Alice", entropyText: "" });
      zkeys.push(out.zkey);
      meta.circuits.push({ id, bytes: out.zkey.length, sha256: await sha256Hex(out.zkey), contributionHash: out.contributionHash });
    }
    meta.attestation = await attestationHash(1, meta.circuits);
    const blob = encodeBundle(meta, zkeys);
    await coordinator.receive(ticket, blob.stream(), blob.size);
    await verifying;
    const stopped = coordinator.shutdown();
    await assert.rejects(coordinator.join({ name: "Late", key: "b" }), /closed/);
    assert.equal((await coordinator.status()).closed, true);
    release();
    await stopped;
    assert.equal(ticket.state, "done", JSON.stringify(ticket.error));
    assert.equal(coordinator.latest.round, 1);
    assert.equal((await new Store(dataDir).latest()).attestation, meta.attestation);
  } finally {
    await terminateThreads();
    await rm(dir, { recursive: true, force: true });
  }
});

test("upload deadline covers the final EOF probe", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ceremony-eof-"));
  const bytes = new Uint8Array(11);
  const meta = { v: 1, round: 0, name: "A", attestation: "0".repeat(64), circuits: [{ id: "request", bytes: 11, sha256: await sha256Hex(bytes), contributionHash: "1".repeat(128) }] };
  const blob = encodeBundle(meta, [bytes]);
  const all = new Uint8Array(await blob.arrayBuffer());
  const stream = new ReadableStream({ start(c) { c.enqueue(all); } });
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new Error("EOF deadline")), 50);
  try {
    await assert.rejects(receiveBundle({ body: stream, contentLength: blob.size, circuitIds: ["request"], round: 0, previousBytes: { request: 10 }, dir, expired: () => false, signal: controller.signal }), /EOF deadline/);
    assert.equal(stream.locked, false);
  } finally { clearTimeout(timer); await rm(dir, { recursive: true, force: true }); }
});

test("deployment memory guard fails closed below the conservative budget", () => {
  assert.throws(() => requireMemory({ limit: MIN_MEMORY_BYTES - 1 }), /at least 4 GiB/);
  assert.equal(requireMemory({ limit: MIN_MEMORY_BYTES }), MIN_MEMORY_BYTES);
});

test("structural upload parsing bounds section scans and MPC allocation before curve work", async () => {
  const bytes = Buffer.alloc(224);
  bytes.write("zkey");
  bytes.writeUInt32LE(1, 4);
  bytes.writeUInt32LE(0xffffffff, 8);
  await assert.rejects(readMpcFromBytes(bytes), /exactly 10 sections/);
  bytes.writeUInt32LE(10, 8);
  bytes.writeUInt32LE(10, 12);
  bytes.writeBigUInt64LE(200n, 16);
  const dir = await mkdtemp(join(tmpdir(), "ceremony-mpc-bound-"));
  try {
    const path = join(dir, "oversized.zkey");
    await writeFile(path, bytes);
    await assert.rejects(readMpcFromFile(path, { maxMpcBytes: 100 }), /permitted contribution growth/);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test("r1cs header parsing bounds section scans and allocation by the actual file", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ceremony-r1cs-bound-"));
  const path = join(dir, "malicious.r1cs");
  const bytes = Buffer.alloc(24);
  bytes.write("r1cs");
  bytes.writeUInt32LE(1, 4);
  try {
    bytes.writeUInt32LE(0xffffffff, 8);
    await writeFile(path, bytes);
    await assert.rejects(readR1csHeader(path), /section count exceeds/);
    bytes.writeUInt32LE(1, 8);
    bytes.writeUInt32LE(1, 12);
    bytes.writeBigUInt64LE(1n << 40n, 16);
    await writeFile(path, bytes);
    await assert.rejects(readR1csHeader(path), /runs past the end/);
    bytes.writeBigUInt64LE(0n, 16);
    await writeFile(path, bytes);
    await assert.rejects(readR1csHeader(path), /exactly 64 bytes/);
    await writeFile(path, bytes.subarray(0, 8));
    await assert.rejects(readR1csHeader(path), /truncated/);
  } finally { await rm(dir, { recursive: true, force: true }); }
});
