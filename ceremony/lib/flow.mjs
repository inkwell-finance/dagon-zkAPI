import { attestationHash, normalizeName } from "./attestation.mjs";
import { encodeBundle } from "./bundle.mjs";
import { CeremonyError } from "./client.mjs";
import { sha256Hex } from "./hex.mjs";

const RESUMABLE = new Set(["slot_expired", "unknown_ticket", "stale_round"]);
const TRANSIENT_POLL_FAILURES = 5;

/**
 * One whole contribution, the same for the browser page and the CLI: join the queue, wait for the turn, download the
 * latest zkey of every circuit, contribute, upload, wait for the coordinator's verdict.
 *
 * If the slot expires or the queue forgets the ticket, the flow joins again (up to `attempts` times); that is the
 * "resume" behaviour users see.
 *
 * @param {object} args
 * @param {import("./client.mjs").CeremonyClient} args.client
 * @param {string} args.name display name, may be empty
 * @param {string} args.entropyText extra entropy typed or gathered by the contributor, may be empty
 * @param {(args: {zkey: Uint8Array, name: string, entropyText: string, circuit: string, onProgress: (fraction: number) => void}) => Promise<{zkey: Uint8Array, contributionHash: string}>} args.contribute
 * @param {(ms: number) => Promise<void>} args.sleep
 * @param {(event: object) => void} [args.onEvent] progress for the UI: {phase, ...}
 * @param {(ticket: string, blob: Blob, onProgress?: (sent: number, total: number) => void) => Promise<object>} [args.upload]
 * @param {number} [args.attempts]
 * @param {AbortSignal} [args.signal] aborting leaves the queue and rejects with the signal's reason
 */
export async function contributeToCeremony({ client, name, entropyText, contribute, sleep, onEvent = () => {}, upload, attempts = 3, signal }) {
  const display = normalizeName(name);
  const status = await client.status();
  if (status.closed || status.finalized) throw new CeremonyError("ceremony_closed", "The ceremony is closed. Thank you for the interest!");

  async function pollSettled(ticket, isDone) {
    let failures = 0;
    let state = await client.poll(ticket);
    for (;;) {
      signal?.throwIfAborted();
      if (isDone(state)) return state;
      if (state.state === "expired") throw new CeremonyError("slot_expired", state.error?.message ?? "Your place in the queue ran out.");
      if (state.state === "rejected") throw new CeremonyError("rejected", state.error?.message ?? "The contribution was rejected.");
      onEvent({ phase: state.state === "waiting" ? "waiting" : state.state, ahead: state.ahead, queueLength: state.queueLength, etaSeconds: state.etaSeconds });
      await sleep(state.pollMs ?? 3000);
      try {
        state = await client.poll(ticket);
        failures = 0;
      } catch (error) {
        if (error.code !== "network" || ++failures > TRANSIENT_POLL_FAILURES) throw error;
      }
    }
  }

  async function attempt() {
    signal?.throwIfAborted();
    onEvent({ phase: "joining" });
    const { ticket } = await client.join(display);
    try {
      return await takeTurn(ticket);
    } catch (error) {
      // Give the place back at once instead of making the next person wait for a timeout.
      await client.leave(ticket).catch(() => {});
      throw error;
    }
  }

  async function takeTurn(ticket) {
    const turn = await pollSettled(ticket, (s) => s.state === "active");
    onEvent({ phase: "turn", expiresInMs: turn.expiresInMs, slotMs: turn.slotMs, round: turn.round });

    const current = await client.status();
    const circuits = current.circuits.map((c) => c.id);
    const zkeys = [];
    const meta = { v: 1, round: current.round, name: display, attestation: "", circuits: [] };
    for (const [index, id] of circuits.entries()) {
      signal?.throwIfAborted();
      const expected = current.circuits[index].sha256;
      const downloaded = await client.download(ticket, id, (loaded, total) => onEvent({ phase: "downloading", circuit: id, index, total: circuits.length, loaded, size: total }));
      if (downloaded.round !== current.round) throw new CeremonyError("stale_round", "The ceremony moved on while downloading.");
      const actual = await sha256Hex(downloaded.bytes);
      if (actual !== downloaded.sha256 || actual !== expected) throw new CeremonyError("corrupt_download", `The ${id} download does not match the published hash.`);
      const result = await contribute({ zkey: downloaded.bytes, name: display, entropyText, circuit: id, onProgress: (fraction) => onEvent({ phase: "contributing", circuit: id, index, total: circuits.length, fraction }) });
      zkeys.push(result.zkey);
      meta.circuits.push({ id, bytes: result.zkey.length, sha256: await sha256Hex(result.zkey), contributionHash: result.contributionHash });
    }
    signal?.throwIfAborted();
    meta.attestation = await attestationHash(current.round + 1, meta.circuits);
    const blob = encodeBundle(meta, zkeys);

    onEvent({ phase: "uploading", total: blob.size });
    const send = upload ?? ((t, b) => client.upload(t, b));
    for (let tries = 1; ; tries++) {
      try {
        await send(ticket, blob, (sent, total) => onEvent({ phase: "uploading", sent, total }));
        break;
      } catch (error) {
        if (error.code !== "network" || tries >= 3) throw error;
        await sleep(2000);
      }
    }
    onEvent({ phase: "verifying" });
    const done = await pollSettled(ticket, (s) => s.state === "done");
    if (done.result.attestation !== meta.attestation) throw new CeremonyError("attestation_mismatch", "The server computed a different attestation than this device. Do not post it; please report this.");
    return { ...done.result, contributions: meta.circuits };
  }

  for (let n = 1; ; n++) {
    try {
      return await attempt();
    } catch (error) {
      if (!(error instanceof CeremonyError) || !RESUMABLE.has(error.code) || n >= attempts) throw error;
      onEvent({ phase: "expired", attempt: n, message: error.message });
    }
  }
}
