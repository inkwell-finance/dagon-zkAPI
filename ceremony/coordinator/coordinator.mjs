import { stat } from "node:fs/promises";
import { join } from "node:path";
import { attestationHash, normalizeName } from "../lib/attestation.mjs";
import { loadConfig } from "../lib/config.mjs";
import { hashFile } from "../lib/files.mjs";
import { ptauFileName } from "../lib/ptau.mjs";
import { CONTRIBUTION, extensionProblem, readMpcFromFile } from "../lib/zkey-info.mjs";
import { QueueError, SlotQueue } from "./queue.mjs";
import { receiveBundle } from "./receive.mjs";
import { Store } from "./store.mjs";

export const DEFAULT_QUEUE = {
  slotMs: 25 * 60_000,
  claimMs: 2 * 60_000,
  waitHeartbeatMs: 3 * 60_000,
  maxQueue: 100,
  maxPerKey: 3,
  finishedKeepMs: 15 * 60_000,
};
export const DEFAULT_UPLOAD_MS = 15 * 60_000;
export const POLL_MS = 3000;

export class Coordinator {
  #verifying = Promise.resolve();

  constructor({ store, config, queue, now, verify, uploadMs = DEFAULT_UPLOAD_MS }) {
    this.store = store;
    this.config = config;
    this.queue = queue;
    this.now = now;
    this.verify = verify;
    this.uploadMs = uploadMs;
    this.entries = [];
    this.latest = undefined;
    this.ptauPath = join(store.dir, "ptau", ptauFileName(config));
  }

  /**
   * Opens an initialised data directory and refuses to continue unless everything on disk matches what was recorded:
   * the Powers of Tau file against the pinned hash, the circuits and the newest round against the transcript.
   */
  static async open({ dataDir, now = Date.now, verify, queue = {}, uploadMs, log = () => {} }) {
    const store = new Store(dataDir);
    const config = await loadConfig(store.path("ceremony.json")).catch((error) => {
      throw new Error(`${dataDir} is not an initialised ceremony directory (${error.message}). Run: node coordinator/cli.mjs init`);
    });
    const coordinator = new Coordinator({ store, config, queue: new SlotQueue({ now, ...DEFAULT_QUEUE, ...queue }), now, verify, uploadMs });
    const rounds = await store.rounds();
    if (rounds.length === 0) throw new Error("the data directory has no round 0000; run init first");

    log(`checking the Powers of Tau file against the pinned ${config.ptau.hashAlgorithm} hash`);
    const ptauHash = await hashFile(coordinator.ptauPath, config.ptau.hashAlgorithm).catch(() => "missing");
    if (ptauHash !== config.ptau.hash) throw new Error(`refusing to start: ${coordinator.ptauPath} hashes to ${ptauHash}, ceremony.json pins ${config.ptau.hash}`);

    const first = rounds[0];
    for (const c of config.circuits) {
      const r1csHash = await hashFile(store.path("r1cs", c.r1cs));
      if (r1csHash !== first.circuits[c.id].r1csSha256) throw new Error(`refusing to start: r1cs/${c.r1cs} changed since init`);
    }
    const latest = rounds[rounds.length - 1];
    for (const c of config.circuits) {
      const zkeyHash = await hashFile(join(store.roundDir(latest.round), `${c.id}.zkey`));
      if (zkeyHash !== latest.circuits[c.id].sha256) throw new Error(`refusing to start: round ${latest.round} ${c.id}.zkey does not match the transcript`);
    }
    coordinator.entries = rounds;
    coordinator.latest = latest;
    await store.writeTranscript();
    return coordinator;
  }

  get circuitIds() {
    return this.config.circuits.map((c) => c.id);
  }

  /** Resolves once the verification running right now (if any) has finished; tests and shutdown use this. */
  settled() {
    return this.#verifying;
  }

  async join({ name, key }) {
    if (await this.store.isClosed()) throw new QueueError("ceremony_closed", "The ceremony is closed. Thank you for the interest!", 410);
    let clean;
    try {
      clean = normalizeName(name);
    } catch (error) {
      throw new QueueError("bad_name", error.message, 400);
    }
    return this.queue.join({ name: clean, key });
  }

  /** Ticket for a bearer token, counted as a sign of life. */
  ticket(token) {
    const ticket = token ? this.queue.touch(token) : undefined;
    if (!ticket) throw new QueueError("unknown_ticket", "This ticket is not known (it may have expired). Join the queue again.", 401);
    return ticket;
  }

  view(ticket) {
    const base = { state: ticket.state, queueLength: this.queue.length(), round: this.latest.round, pollMs: POLL_MS, name: ticket.name };
    if (ticket.state === "waiting") {
      const ahead = this.queue.ahead(ticket);
      return { ...base, ahead, etaSeconds: Math.ceil((ahead * this.queue.typicalMs()) / 1000) };
    }
    if (ticket.state === "active") return { ...base, expiresInMs: Math.max(0, ticket.expiresAt - this.now()), slotMs: this.queue.slotMs };
    if (ticket.state === "done") return { ...base, result: ticket.result };
    if (ticket.state === "rejected" || ticket.state === "expired") return { ...base, error: ticket.error };
    return base;
  }

  #requireActive(ticket) {
    if (ticket.state === "expired") throw new QueueError("slot_expired", ticket.error?.message ?? "Your time slot ran out.", 410);
    if (ticket.state !== "active") throw new QueueError("not_your_turn", `It is not your turn yet (ticket is ${ticket.state}).`, 409);
  }

  async openRound(ticket, circuitId) {
    this.#requireActive(ticket);
    if (!this.circuitIds.includes(circuitId)) throw new QueueError("unknown_circuit", `Unknown circuit ${circuitId}.`, 404);
    const path = join(this.store.roundDir(this.latest.round), `${circuitId}.zkey`);
    const info = this.latest.circuits[circuitId];
    return { path, size: (await stat(path)).size, sha256: info.sha256, round: this.latest.round };
  }

  /** Receives the bundle, then verifies it in the background; the client polls its ticket for the outcome. */
  async receive(ticket, body, contentLength) {
    this.#requireActive(ticket);
    if (await this.store.isClosed()) throw new QueueError("ceremony_closed", "The ceremony is closed.", 410);
    if (ticket.uploading) throw new QueueError("busy", "An upload for this ticket is already in progress.", 409);
    this.queue.startUpload(ticket);
    const staging = await this.store.newStaging();
    const previousBytes = Object.fromEntries(this.circuitIds.map((id) => [id, this.latest.circuits[id].bytes]));
    const startedAt = this.now();
    let meta;
    try {
      meta = await receiveBundle({
        body,
        contentLength,
        circuitIds: this.circuitIds,
        round: this.latest.round,
        previousBytes,
        dir: staging,
        expired: () => this.now() - startedAt > this.uploadMs,
      });
      if (meta.name !== normalizeName(meta.name)) throw new QueueError("bad_name", "The contributor name in the bundle is not normalised.", 400);
    } catch (error) {
      // The slot stays with the contributor: a dropped connection should not cost a whole turn.
      this.queue.cancelUpload(ticket);
      await this.store.discard(staging);
      throw error;
    }
    this.queue.startVerify(ticket);
    const job = this.#verifyAndPromote(ticket, meta, staging);
    this.#verifying = job;
    return { state: "verifying" };
  }

  async #verifyAndPromote(ticket, meta, staging) {
    const base = this.latest;
    try {
      const circuits = {};
      const previous = {};
      const added = {};
      // Cheap structural checks for every circuit first, so a bad upload is refused before any pairing work.
      for (const id of this.circuitIds) {
        const zkey = join(staging, `${id}.zkey`);
        const [prev, next] = await Promise.all([readMpcFromFile(join(this.store.roundDir(base.round), `${id}.zkey`)), readMpcFromFile(zkey)]).catch((error) => {
          throw Object.assign(new Error(`the ${id} zkey cannot be read: ${error.message}`), { circuit: id });
        });
        const problem = extensionProblem(prev, next, { expectedType: CONTRIBUTION, expectedName: meta.name });
        if (problem) throw Object.assign(new Error(`${id}: ${problem}`), { circuit: id });
        const last = next.contributions[next.contributions.length - 1];
        if (last.hash !== meta.circuits.find((c) => c.id === id).contributionHash) {
          throw Object.assign(new Error(`${id}: the contribution hash does not match the one announced`), { circuit: id });
        }
        previous[id] = prev;
        added[id] = last.hash;
        circuits[id] = { sha256: meta.circuits.find((c) => c.id === id).sha256, bytes: meta.circuits.find((c) => c.id === id).bytes, contributionHash: last.hash, contributions: next.contributions.length };
      }
      const round = base.round + 1;
      const attestation = await attestationHash(round, this.circuitIds.map((id) => ({ id, contributionHash: added[id] })));
      if (attestation !== meta.attestation) throw new Error("the attestation hash does not match the contribution hashes");

      for (const id of this.circuitIds) {
        const result = await this.verify({ r1cs: this.store.path("r1cs", `${id}.r1cs`), ptau: this.ptauPath, zkey: join(staging, `${id}.zkey`) });
        if (!result.ok) throw Object.assign(new Error(`${id}: snarkjs verification failed: ${result.errors.join("; ") || "invalid zkey"}`), { circuit: id });
      }

      if (await this.store.isClosed()) throw new Error("the ceremony closed while this contribution was being verified");
      if (this.latest !== base) throw new Error("the ceremony moved on while this contribution was being verified");
      const entry = { round, kind: "contribution", time: new Date(this.now()).toISOString(), name: meta.name, attestation, circuits };
      await this.store.promote(staging, entry);
      this.entries.push(entry);
      this.latest = entry;
      this.queue.finish(ticket, { round, attestation, name: meta.name, contributions: this.circuitIds.map((id) => ({ id, contributionHash: added[id], sha256: circuits[id].sha256 })) });
    } catch (error) {
      await this.store.discard(staging).catch(() => {});
      this.queue.reject(ticket, { message: error instanceof Error ? error.message : String(error), circuit: error?.circuit });
    }
  }

  async status() {
    const closed = await this.store.isClosed();
    if (closed && this.latest.kind !== "beacon") {
      // finalize ran (in another process) after this server loaded its rounds
      this.entries = await this.store.rounds();
      this.latest = this.entries[this.entries.length - 1];
    }
    const rounds = this.entries;
    const latest = this.latest;
    this.queue.tick();
    const holder = this.queue.holder();
    return {
      name: this.config.name,
      circuits: this.config.circuits.map((c) => ({ id: c.id, publicInputs: c.publicInputs, ...(latest.circuits[c.id] && { sha256: latest.circuits[c.id].sha256, bytes: latest.circuits[c.id].bytes }) })),
      ptau: this.config.ptau,
      beacon: this.config.beacon,
      round: latest.round,
      contributions: rounds.filter((r) => r.kind === "contribution").length,
      finalized: rounds.some((r) => r.kind === "beacon"),
      closed,
      contributors: rounds.filter((r) => r.kind !== "init").map((r) => ({ round: r.round, kind: r.kind, name: r.name, time: r.time, attestation: r.attestation })),
      queue: { length: this.queue.length(), busy: holder !== undefined, verifying: holder?.state === "verifying", typicalSeconds: Math.round(this.queue.typicalMs() / 1000) },
      slotMinutes: Math.round(this.queue.slotMs / 60_000),
    };
  }
}
