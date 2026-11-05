import assert from "node:assert/strict";
import { cp, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, test } from "node:test";
import { serve } from "@hono/node-server";
import { main as contribute } from "../contribute.mjs";
import { buildApp } from "../coordinator/app.mjs";
import { Coordinator } from "../coordinator/coordinator.mjs";
import { finalizeCeremony } from "../coordinator/finalize.mjs";
import { initCeremony } from "../coordinator/init.mjs";
import { childVerifier } from "../coordinator/verify-child.mjs";
import { verifyCeremony, formatReport } from "../verify-ceremony.mjs";
import { attestationHash } from "../lib/attestation.mjs";
import { encodeBundle } from "../lib/bundle.mjs";
import { CeremonyClient, CeremonyError } from "../lib/client.mjs";
import { contributeZkey } from "../lib/contribute-core.mjs";
import { contributeToCeremony } from "../lib/flow.mjs";
import { sha256Hex } from "../lib/hex.mjs";
import { terminateThreads, verifyZkey } from "../lib/snark.mjs";
import { BEACON, CONTRIBUTION, extensionProblem, readMpcFromBytes, readMpcFromFile } from "../lib/zkey-info.mjs";
import { fakeClock, fakeDrand, makeFixture, r1csBytes, TINY_CIRCUITS } from "./helpers.mjs";

const SLOT_MS = 10 * 60_000;
const CIRCUITS = ["request", "withdrawal", "transition"];

describe("ceremony, end to end", { concurrency: false }, () => {
  const clock = fakeClock();
  const drand = fakeDrand({ chain: "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971", round: 424242 });
  let root, fx, dataDir, coordinator, server, url, client;

  const verify = (args) => verifyZkey(args);
  const roundsOnDisk = async () => (await readdir(join(dataDir, "rounds"))).length;
  const stagingLeft = async () => (await readdir(join(dataDir, "staging")).catch(() => [])).length;

  /** Joins and takes a turn, then downloads and contributes to the current round like a real contributor. */
  async function takeTurn(name = "Mallory") {
    const joined = await client.join(name);
    assert.equal(joined.state, "active");
    const status = await client.status();
    const zkeys = [];
    const meta = { v: 1, round: status.round, name, attestation: "", circuits: [] };
    for (const id of CIRCUITS) {
      const { bytes } = await client.download(joined.ticket, id);
      const result = await contributeZkey({ zkey: bytes, name, entropyText: "test" });
      zkeys.push(result.zkey);
      meta.circuits.push({ id, bytes: result.zkey.length, sha256: await sha256Hex(result.zkey), contributionHash: result.contributionHash });
    }
    meta.attestation = await attestationHash(status.round + 1, meta.circuits);
    return { ticket: joined.ticket, meta, zkeys };
  }

  const settle = async (ticket) => {
    await coordinator.settled();
    return client.poll(ticket);
  };

  before(async () => {
    root = await mkdtemp(join(tmpdir(), "ceremony-test-"));
    fx = await makeFixture(join(root, "fixture"));
    dataDir = join(root, "data");
    await initCeremony({ configPath: fx.configPath, r1csDir: fx.r1csDir, dataDir, ptauFile: fx.ptauPath });
    coordinator = await Coordinator.open({ dataDir, now: clock.now.bind(clock), verify, queue: { slotMs: SLOT_MS, waitHeartbeatMs: 5 * 60_000 } });
    const app = buildApp({ coordinator, assets: new Map(), now: clock.now.bind(clock), limits: Object.fromEntries(["join", "poll", "download", "upload", "status", "files"].map((k) => [k, { max: 10_000, windowMs: 60_000 }])) });
    server = serve({ fetch: app.fetch, hostname: "127.0.0.1", port: 0 });
    await new Promise((resolve) => server.once("listening", resolve));
    url = `http://127.0.0.1:${server.address().port}`;
    client = new CeremonyClient({ server: url });
  });

  after(async () => {
    server.close();
    await terminateThreads();
    await rm(root, { recursive: true, force: true });
  });

  test("init made a verifiable round 0 and the API reports it", async () => {
    const status = await client.status();
    assert.equal(status.round, 0);
    assert.equal(status.contributions, 0);
    assert.deepEqual(status.circuits.map((c) => c.id), CIRCUITS);
    assert.deepEqual(status.queue, { length: 0, busy: false, verifying: false, typicalSeconds: 300 });
    assert.equal((await fetch(`${url}/healthz`)).status, 200);
    for (const id of CIRCUITS) {
      const check = await verifyZkey({ r1cs: join(dataDir, "r1cs", `${id}.r1cs`), ptau: join(dataDir, "ptau", "tiny.ptau"), zkey: join(dataDir, "rounds", "0000", `${id}.zkey`) });
      assert.deepEqual(check, { ok: true, errors: [] });
    }
  });

  test("three contributors use the CLI code path and are all accepted", async () => {
    const receipts = [];
    for (const [round, name] of [[1, "Alice"], [2, "Bob \u00e9"], [3, ""]]) {
      const lines = [];
      const receipt = join(root, `receipt-${round}.json`);
      const code = await contribute(["--server", url, "--name", name, "--entropy-text", `typed by ${name || "nobody"}`, "--receipt", receipt], {
        sleep: () => coordinator.settled(),
        out: lines.push.bind(lines),
        err: () => {},
      });
      assert.equal(code, 0, lines.join("\n"));
      const saved = JSON.parse(await readFile(receipt, "utf8"));
      assert.equal(saved.round, round);
      assert.ok(lines.includes(saved.attestation), "the attestation hash is printed");
      receipts.push(saved);
    }
    const transcript = JSON.parse(await readFile(join(dataDir, "transcript.json"), "utf8"));
    assert.deepEqual(transcript.rounds.map((r) => r.kind), ["init", "contribution", "contribution", "contribution"]);
    assert.deepEqual(transcript.rounds.slice(1).map((r) => r.name), ["Alice", "Bob \u00e9", "Anonymous"]);
    for (const receipt of receipts) {
      const entry = transcript.rounds[receipt.round];
      assert.equal(entry.attestation, receipt.attestation);
      assert.equal(await attestationHash(entry.round, CIRCUITS.map((id) => ({ id, contributionHash: entry.circuits[id].contributionHash }))), entry.attestation);
      assert.deepEqual(receipt.contributions.map((c) => c.contributionHash), CIRCUITS.map((id) => entry.circuits[id].contributionHash));
    }
    // every accepted round is publicly downloadable and matches the transcript
    for (const id of CIRCUITS) {
      const response = await fetch(`${url}/files/rounds/0002/${id}.zkey`);
      assert.equal(response.status, 200);
      assert.equal(await sha256Hex(new Uint8Array(await response.arrayBuffer())), transcript.rounds[2].circuits[id].sha256);
    }
    assert.equal((await client.status()).round, 3);
  });

  test("the contribution hash printed by snarkjs-based code equals the one parsed from the zkey", async () => {
    const zkey = new Uint8Array(await readFile(join(dataDir, "rounds", "0000", "request.zkey")));
    const out = await contributeZkey({ zkey, name: "hash check", entropyText: "" });
    const mpc = await readMpcFromBytes(out.zkey);
    assert.equal(mpc.contributions.length, 1);
    assert.equal(mpc.contributions[0].hash, out.contributionHash);
    assert.equal(mpc.contributions[0].name, "hash check");
    // the platform randomness always goes in: the same input and the same typed entropy never give the same key
    const again = await contributeZkey({ zkey, name: "hash check", entropyText: "" });
    assert.notEqual(again.contributionHash, out.contributionHash);
    assert.deepEqual((await verifyZkey({ r1cs: join(dataDir, "r1cs", "request.r1cs"), ptau: join(dataDir, "ptau", "tiny.ptau"), zkey: join(dataDir, "rounds", "0000", "request.zkey") })).ok, true);
  });

  describe("bad uploads are refused and never change the ceremony", () => {
    async function assertUntouched(ticket, round) {
      const state = await settle(ticket);
      assert.equal(state.state, "rejected", JSON.stringify(state));
      assert.equal((await client.status()).round, round);
      assert.equal(await roundsOnDisk(), round + 1);
      assert.equal(await stagingLeft(), 0);
      assert.equal((await client.status()).queue.length, 0, "the slot is free again");
      return state;
    }

    test("a tampered zkey (right size, right hashes, invalid contents) fails snarkjs verification", async () => {
      const { ticket, meta, zkeys } = await takeTurn();
      const bad = zkeys[1].slice();
      bad[Math.floor(bad.length / 3)] ^= 0x01;
      zkeys[1] = bad;
      meta.circuits[1].sha256 = await sha256Hex(bad);
      assert.deepEqual(await client.upload(ticket, encodeBundle(meta, zkeys)), { state: "verifying" });
      const state = await assertUntouched(ticket, 3);
      assert.equal(state.error.circuit, "withdrawal");
      assert.match(state.error.message, /withdrawal/);
    });

    test("a zkey that rewrites history (does not extend the latest round) is refused", async () => {
      const status = await client.status();
      const base = JSON.parse(await readFile(join(dataDir, "transcript.json"), "utf8")).rounds[2];
      const joined = await client.join("Mallory");
      const zkeys = [];
      const meta = { v: 1, round: status.round, name: "Mallory", attestation: "", circuits: [] };
      for (const id of CIRCUITS) {
        // two contributions on top of round 2: the right count and size, a different history
        const first = await contributeZkey({ zkey: new Uint8Array(await readFile(join(dataDir, "rounds", "0002", `${id}.zkey`))), name: "Mallory", entropyText: "" });
        const second = await contributeZkey({ zkey: first.zkey, name: "Mallory", entropyText: "" });
        zkeys.push(second.zkey);
        meta.circuits.push({ id, bytes: second.zkey.length, sha256: await sha256Hex(second.zkey), contributionHash: second.contributionHash });
      }
      assert.ok(base);
      meta.attestation = await attestationHash(status.round + 1, meta.circuits);
      await client.upload(joined.ticket, encodeBundle(meta, zkeys));
      const state = await assertUntouched(joined.ticket, 3);
      assert.match(state.error.message, /altered|contributions/);
    });

    test("the zkeys of another circuit are refused", async () => {
      const { ticket, meta, zkeys } = await takeTurn();
      [zkeys[0], zkeys[1]] = [zkeys[1], zkeys[0]];
      [meta.circuits[0], meta.circuits[1]] = [{ ...meta.circuits[1], id: "request" }, { ...meta.circuits[0], id: "withdrawal" }];
      await assert.rejects(client.upload(ticket, encodeBundle(meta, zkeys)), (error) => error instanceof CeremonyError && error.status === 413);
      // size is the cheap early check; the circuit hash is the real one, covered below. The slot is kept after a malformed upload.
      assert.equal((await client.poll(ticket)).state, "active");
      assert.equal(await stagingLeft(), 0);
      const real = await readMpcFromFile(join(dataDir, "rounds", "0003", "request.zkey"));
      const other = await readMpcFromFile(join(dataDir, "rounds", "0003", "withdrawal.zkey"));
      assert.match(extensionProblem(real, other, { expectedType: CONTRIBUTION }), /circuit hash differs/);
      // give the slot back: let it expire
      clock.advance(SLOT_MS + 1);
      assert.equal((await client.poll(ticket)).state, "expired");
    });

    test("a wrong attestation hash, a name that is not in the zkey and damaged bytes are refused", async () => {
      const a = await takeTurn();
      a.meta.attestation = "0".repeat(64);
      await client.upload(a.ticket, encodeBundle(a.meta, a.zkeys));
      assert.match((await assertUntouched(a.ticket, 3)).error.message, /attestation/);

      const b = await takeTurn("Eve");
      b.meta.name = "Not Eve";
      await client.upload(b.ticket, encodeBundle(b.meta, b.zkeys));
      assert.match((await assertUntouched(b.ticket, 3)).error.message, /declared name/);

      const c = await takeTurn();
      c.meta.circuits[0].sha256 = "f".repeat(64);
      await assert.rejects(client.upload(c.ticket, encodeBundle(c.meta, c.zkeys)), /damaged/);
      assert.equal((await client.poll(c.ticket)).state, "active");
      clock.advance(SLOT_MS + 1);
    });

    test("uploads for another round, truncated bundles and non-bundles are refused", async () => {
      const { ticket, meta, zkeys } = await takeTurn();
      await assert.rejects(client.upload(ticket, encodeBundle({ ...meta, round: 1 }, zkeys)), (error) => error.code === "stale_round");
      await assert.rejects(client.upload(ticket, new Blob(["not a bundle at all"])), (error) => error.code === "bad_upload");
      const whole = encodeBundle(meta, zkeys);
      await assert.rejects(client.upload(ticket, whole.slice(0, whole.size - 10)), (error) => error.code === "bad_upload");
      assert.equal((await client.poll(ticket)).state, "active", "failed transfers keep the slot");
      clock.advance(SLOT_MS + 1);
      assert.equal(await stagingLeft(), 0);
    });
  });

  describe("access control", () => {
    let first;
    let second;

    test("rounds are only served to the contributor whose turn it is", async () => {
      await assert.rejects(client.download("x".repeat(43), "request"), (error) => error.code === "unknown_ticket" && error.status === 401);
      first = await client.join("First");
      second = await client.join("Second");
      assert.equal(first.state, "active");
      assert.deepEqual([second.state, second.ahead], ["waiting", 1]);
      await assert.rejects(client.download(second.ticket, "request"), (error) => error.code === "not_your_turn" && error.status === 409);
      await assert.rejects(client.upload(second.ticket, new Blob([new Uint8Array(100)])), (error) => error.code === "not_your_turn");
      await assert.rejects(client.download(first.ticket, "nope"), (error) => error.code === "unknown_circuit");
      assert.equal((await fetch(`${url}/api/round/request`)).status, 401);
      assert.equal((await fetch(`${url}/api/contribution`, { method: "PUT", body: "x" })).status, 401);
    });

    test("an expired slot passes to the next in line and the old ticket is told so", async () => {
      assert.equal((await client.status()).queue.length, 2);
      const [slow, waiting] = [first.ticket, second.ticket];
      for (let minute = 0; minute < 8; minute += 4) {
        clock.advance(4 * 60_000);
        assert.equal((await client.poll(waiting)).state, "waiting", "a page that keeps checking in keeps its place");
      }
      clock.advance(SLOT_MS - 8 * 60_000 - 1000);
      assert.equal((await client.poll(slow)).state, "active");
      assert.equal((await client.poll(waiting)).state, "waiting");
      clock.advance(2000);
      assert.equal((await client.poll(slow)).state, "expired");
      assert.equal((await client.poll(waiting)).state, "active");
      await assert.rejects(client.download(slow, "request"), (error) => error.code === "slot_expired" && error.status === 410);
      await assert.rejects(client.upload(slow, new Blob(["x"])), (error) => error.code === "slot_expired");
      clock.advance(SLOT_MS + 1);
      assert.equal((await client.poll(waiting)).state, "expired");
      assert.equal((await client.status()).queue.length, 0);
    });

    test("only public files are served", async () => {
      for (const path of ["ptau/tiny.ptau", "staging/", "rounds/0001/", "rounds/%2e%2e/%2e%2e/ptau/tiny.ptau", "ceremony.json.bak", "rounds/0099/request.zkey"]) {
        assert.equal((await fetch(`${url}/files/${path}`)).status, 404, path);
      }
      for (const path of ["ceremony.json", "transcript.json", "r1cs/request.r1cs", "rounds/0001/entry.json"]) {
        assert.equal((await fetch(`${url}/files/${path}`)).status, 200, path);
      }
      const page = await fetch(`${url}/`);
      assert.equal(page.status, 503, "no web assets were built into this test server");
      assert.match(page.headers.get("content-security-policy"), /default-src 'none'/);
    });

    test("the join endpoint is rate limited per connection", async () => {
      const app = buildApp({ coordinator, assets: new Map(), now: clock.now.bind(clock), limits: { join: { max: 2, windowMs: 60_000 }, poll: { max: 5, windowMs: 1000 }, download: { max: 1, windowMs: 1000 }, upload: { max: 1, windowMs: 1000 }, status: { max: 1, windowMs: 1000 }, files: { max: 1, windowMs: 1000 } } });
      const join = () => app.request("/api/queue", { method: "POST", body: JSON.stringify({ name: "rl" }) });
      assert.equal((await join()).status, 201);
      assert.equal((await join()).status, 201);
      const limited = await join();
      assert.equal(limited.status, 429);
      assert.ok(Number(limited.headers.get("retry-after")) > 0);
      clock.advance(SLOT_MS * 5);
      await coordinator.status();
    });
  });

  test("cancelling a waiting contributor gives the place back at once", async () => {
    clock.advance(SLOT_MS * 5);
    const holder = await client.join("Holder");
    assert.equal(holder.state, "active");
    const controller = new AbortController();
    await assert.rejects(
      contributeToCeremony({
        client,
        name: "Impatient",
        entropyText: "",
        contribute: contributeZkey,
        sleep: () => coordinator.settled(),
        signal: controller.signal,
        onEvent: (event) => event.phase === "waiting" && controller.abort(),
      }),
      (error) => error.name === "AbortError",
    );
    assert.equal((await client.status()).queue.length, 1, "only the holder is left");
    await client.leave(holder.ticket);
    assert.equal((await client.status()).queue.length, 0);
  });

  test("a contributor whose slot expires mid-way is put back in the queue and finishes (resume)", async () => {
    clock.advance(SLOT_MS * 5);
    let expiredOnce = false;
    const events = [];
    const result = await contributeToCeremony({
      client,
      name: "Resumer",
      entropyText: "",
      contribute: contributeZkey,
      sleep: () => coordinator.settled(),
      onEvent: (event) => {
        events.push(event.phase);
        if (event.phase === "turn" && !expiredOnce) {
          expiredOnce = true;
          clock.advance(SLOT_MS + 1);
        }
      },
    });
    assert.equal(result.round, 4);
    assert.deepEqual(events.filter((p) => ["turn", "expired"].includes(p)), ["turn", "expired", "turn"]);
  });

  describe("finalize, verify, tamper", () => {
    test("finalize refuses before the committed time, and when the beacon sources disagree", async () => {
      await assert.rejects(finalizeCeremony({ dataDir, fetch: drand.fetch, now: clock.now.bind(clock) }), /may not be applied before 2026-12-01/);
      clock.t = Date.parse("2026-12-02T00:00:00Z");
      const disagreeing = fakeDrand({ chain: "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971", round: 424242, agree: false });
      await assert.rejects(finalizeCeremony({ dataDir, fetch: disagreeing.fetch, now: clock.now.bind(clock) }), /sources disagree/);
      assert.equal(await coordinator.store.isClosed(), false, "nothing was closed by a failed attempt");
    });

    test("finalize applies the beacon, verifies, exports keys and writes the report", async () => {
      const logs = [];
      const { entry, dir } = await finalizeCeremony({ dataDir, fetch: drand.fetch, now: clock.now.bind(clock), log: (m) => logs.push(m) });
      assert.ok(logs.some((l) => l.includes("fetched from https://api.drand.sh/")), "prints where the beacon came from");
      assert.equal(entry.round, 5);
      assert.equal(entry.kind, "beacon");
      assert.equal(entry.beacon.value, drand.randomness);
      const transcript = JSON.parse(await readFile(join(dataDir, "transcript.json"), "utf8"));
      assert.deepEqual(transcript.rounds.map((r) => r.kind), ["init", "contribution", "contribution", "contribution", "contribution", "beacon"]);
      for (const id of CIRCUITS) {
        const vk = JSON.parse(await readFile(join(dir, `${id}_verification_key.json`), "utf8"));
        assert.equal(vk.protocol, "groth16");
        assert.equal(vk.curve, "bn128");
        const mpc = await readMpcFromFile(join(dir, `${id}_final.zkey`));
        assert.equal(mpc.contributions.length, 5);
        assert.equal(mpc.contributions[4].type, BEACON);
        assert.equal(mpc.contributions[4].beaconHash, drand.randomness);
        assert.equal(await sha256Hex(await readFile(join(dir, `${id}_final.zkey`))), entry.circuits[id].sha256);
      }
      const report = await readFile(join(dir, "FINAL.md"), "utf8");
      for (const round of transcript.rounds.slice(1)) for (const id of CIRCUITS) assert.ok(report.includes(round.circuits[id].contributionHash));
      for (const id of CIRCUITS) assert.ok(report.includes(entry.circuits[id].sha256));
      // closed: no new contributors
      await assert.rejects(client.join("Late"), (error) => error.code === "ceremony_closed" && error.status === 410);
      assert.equal((await client.status()).finalized, true);
      assert.equal((await fetch(`${url}/files/final/request_final.zkey`)).status, 200);
      await assert.rejects(finalizeCeremony({ dataDir, fetch: drand.fetch, now: clock.now.bind(clock) }), /already has its final beacon/);
    });

    const options = () => ({ ceremonyFile: fx.configPath, r1csDir: fx.r1csDir, ptauFile: fx.ptauPath, allowCustomPtau: true, fetch: drand.fetch, now: clock.now.bind(clock) });

    test("verify-ceremony passes on a copy of the data directory", async () => {
      const report = await verifyCeremony({ source: dataDir, ...options(), allRounds: true });
      assert.equal(report.ok, true, formatReport(report));
      assert.equal(report.finalized, true);
      const text = formatReport(report);
      assert.match(text, /RESULT: PASS/);
      for (const id of CIRCUITS) assert.ok(text.includes(report.keys[id].zkeySha256));
      assert.ok(report.checks.some((c) => c.ok && /re-fetched from drand/.test(c.name)));
    });

    test("verify-ceremony passes against the live coordinator URL, trusting nothing it says", async () => {
      const dispatch = async (target, init) => (String(target).startsWith(url) ? fetch(target, init) : drand.fetch(target));
      const report = await verifyCeremony({ source: url, ceremonyFile: fx.configPath, r1csDir: fx.r1csDir, ptauFile: fx.ptauPath, cacheDir: join(root, "cache"), allowCustomPtau: true, fetch: dispatch, now: clock.now.bind(clock), requireFinal: true });
      assert.equal(report.ok, true, formatReport(report));
    });

    test("verify-ceremony fails on a different pinned ceremony.json, a different r1cs and a Powers of Tau that is not Hermez", async () => {
      const other = join(root, "other.json");
      const config = JSON.parse(await readFile(fx.configPath, "utf8"));
      config.name = "Another ceremony";
      await writeFile(other, JSON.stringify(config));
      const report = await verifyCeremony({ source: dataDir, ...options(), ceremonyFile: other });
      assert.equal(report.ok, false);
      assert.match(formatReport(report), /FAIL  ceremony.json served by the coordinator equals your pinned copy/);

      const otherR1cs = join(root, "other-r1cs");
      await cp(fx.r1csDir, otherR1cs, { recursive: true });
      await writeFile(join(otherR1cs, "request.r1cs"), r1csBytes({ ...TINY_CIRCUITS.transition }));
      const swapped = await verifyCeremony({ source: dataDir, ...options(), r1csDir: otherR1cs, offline: true });
      assert.equal(swapped.ok, false);
      assert.match(formatReport(swapped), /FAIL  request: r1cs you exported has the sha256 recorded at round 0/);

      const strict = await verifyCeremony({ source: dataDir, ...options(), allowCustomPtau: false, offline: true });
      assert.equal(strict.ok, false);
      assert.ok(strict.checks.some((c) => c.ok === false && /is a Hermez file/.test(c.name)));
    });

    test("tampering with any stored round makes verify-ceremony fail", async () => {
      // 1. a flipped byte in an old round
      const a = join(root, "tamper-a");
      await cp(dataDir, a, { recursive: true });
      const target = join(a, "rounds", "0002", "withdrawal.zkey");
      const bytes = await readFile(target);
      bytes[bytes.length >> 1] ^= 0xff;
      await writeFile(target, bytes);
      const flipped = await verifyCeremony({ source: a, ...options() });
      assert.equal(flipped.ok, false);
      assert.match(formatReport(flipped), /FAIL  round 2 withdrawal\.zkey has the sha256 in the transcript/);

      // 2. a swapped round whose hash was also rewritten in the transcript: the chain itself no longer fits
      const b = join(root, "tamper-b");
      await cp(dataDir, b, { recursive: true });
      await cp(join(dataDir, "rounds", "0001", "request.zkey"), join(b, "rounds", "0002", "request.zkey"));
      const transcript = JSON.parse(await readFile(join(b, "transcript.json"), "utf8"));
      transcript.rounds[2].circuits.request.sha256 = transcript.rounds[1].circuits.request.sha256;
      await writeFile(join(b, "transcript.json"), JSON.stringify(transcript));
      const swapped = await verifyCeremony({ source: b, ...options() });
      assert.equal(swapped.ok, false);
      assert.ok(swapped.checks.some((c) => c.ok === false && /request/.test(c.name)), formatReport(swapped));

      // 3. an edited contributor name or contribution hash in the transcript
      const c = join(root, "tamper-c");
      await cp(dataDir, c, { recursive: true });
      const t3 = JSON.parse(await readFile(join(c, "transcript.json"), "utf8"));
      t3.rounds[3].circuits.transition.contributionHash = "0".repeat(128);
      await writeFile(join(c, "transcript.json"), JSON.stringify(t3));
      const edited = await verifyCeremony({ source: c, ...options() });
      assert.equal(edited.ok, false);

      // 4. a wrong beacon in the transcript
      const d = join(root, "tamper-d");
      await cp(dataDir, d, { recursive: true });
      const t4 = JSON.parse(await readFile(join(d, "transcript.json"), "utf8"));
      t4.rounds[5].beacon.value = "ab".repeat(32);
      await writeFile(join(d, "transcript.json"), JSON.stringify(t4));
      const beacon = await verifyCeremony({ source: d, ...options() });
      assert.equal(beacon.ok, false);
    });

    test("the production verifier runs snarkjs in a child process", async () => {
      const verifyInChild = childVerifier({ timeoutMs: 120_000 });
      const good = await verifyInChild({ r1cs: join(dataDir, "r1cs", "request.r1cs"), ptau: join(dataDir, "ptau", "tiny.ptau"), zkey: join(dataDir, "rounds", "0002", "request.zkey") });
      assert.deepEqual(good, { ok: true, errors: [] });
      const wrongCircuit = await verifyInChild({ r1cs: join(dataDir, "r1cs", "withdrawal.r1cs"), ptau: join(dataDir, "ptau", "tiny.ptau"), zkey: join(dataDir, "rounds", "0002", "request.zkey") });
      assert.equal(wrongCircuit.ok, false);
    });
  });
});
