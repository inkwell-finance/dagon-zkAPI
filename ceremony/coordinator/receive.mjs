import { createHash } from "node:crypto";
import { open } from "node:fs/promises";
import { join } from "node:path";
import { BUNDLE_MAGIC, MAX_META_BYTES } from "../lib/bundle.mjs";
import { QueueError } from "./queue.mjs";

const HEX64 = /^[0-9a-f]{64}$/;
const HEX128 = /^[0-9a-f]{128}$/;

/** A contribution adds one ~0.5 KB entry to the zkey; anything beyond this slack is not a contribution. */
export const MAX_GROWTH_BYTES = 4096;

function bad(message, status = 400) {
  return new QueueError("bad_upload", message, status);
}

/** Pulls exact byte counts out of a web ReadableStream, enforcing a wall-clock budget between chunks. */
class Cursor {
  #iterator;
  #rest = new Uint8Array(0);
  #expired;

  constructor(stream, expired) {
    this.#iterator = stream[Symbol.asyncIterator]();
    this.#expired = expired;
  }

  async #next() {
    if (this.#expired()) throw bad("The upload took too long.", 408);
    const { value, done } = await this.#iterator.next();
    if (done) throw bad("The upload ended early.");
    return value;
  }

  async take(length) {
    const out = new Uint8Array(length);
    let filled = 0;
    while (filled < length) {
      if (this.#rest.length === 0) this.#rest = await this.#next();
      const n = Math.min(length - filled, this.#rest.length);
      out.set(this.#rest.subarray(0, n), filled);
      this.#rest = this.#rest.subarray(n);
      filled += n;
    }
    return out;
  }

  /** Streams exactly `length` bytes into `handle` and returns their sha256. */
  async copyTo(handle, length) {
    const hash = createHash("sha256");
    let left = length;
    while (left > 0) {
      if (this.#rest.length === 0) this.#rest = await this.#next();
      const chunk = this.#rest.subarray(0, Math.min(left, this.#rest.length));
      this.#rest = this.#rest.subarray(chunk.length);
      hash.update(chunk);
      await handle.write(chunk);
      left -= chunk.length;
    }
    return hash.digest("hex");
  }

  async atEnd() {
    if (this.#rest.length > 0) return false;
    const { done } = await this.#iterator.next();
    return done === true;
  }
}

/**
 * Writes the circuits of an upload bundle to `dir/<id>.zkey` and returns the validated meta.
 * @param {object} args
 * @param {ReadableStream} args.body
 * @param {number} args.contentLength
 * @param {string[]} args.circuitIds ceremony order
 * @param {number} args.round the round the contributor claims to extend (must equal the latest accepted round)
 * @param {Record<string, number>} args.previousBytes size of each circuit's latest zkey
 * @param {() => boolean} args.expired
 */
export async function receiveBundle({ body, contentLength, circuitIds, round, previousBytes, dir, expired }) {
  const cursor = new Cursor(body, expired);
  const head = await cursor.take(8);
  if (new TextDecoder().decode(head.subarray(0, 4)) !== BUNDLE_MAGIC) throw bad("This is not a contribution bundle.");
  const metaLength = new DataView(head.buffer).getUint32(4);
  if (metaLength < 2 || metaLength > MAX_META_BYTES) throw bad("The bundle header has an invalid size.");
  let meta;
  try {
    meta = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(await cursor.take(metaLength)));
  } catch {
    throw bad("The bundle header is not valid JSON.");
  }

  if (meta?.v !== 1) throw bad("Unsupported bundle version.");
  if (meta.round !== round) throw new QueueError("stale_round", `The ceremony is at round ${round}; this contribution extends round ${meta.round}.`, 409);
  if (typeof meta.name !== "string" || !HEX64.test(meta.attestation ?? "")) throw bad("The bundle header is incomplete.");
  if (!Array.isArray(meta.circuits) || meta.circuits.length !== circuitIds.length) throw bad("The bundle must contain every circuit.");
  let expected = 8 + metaLength;
  meta.circuits.forEach((c, i) => {
    if (c?.id !== circuitIds[i]) throw bad(`Circuit ${i + 1} must be ${circuitIds[i]}.`);
    if (!Number.isInteger(c.bytes) || c.bytes <= previousBytes[c.id] || c.bytes > previousBytes[c.id] + MAX_GROWTH_BYTES) {
      throw bad(`The ${c.id} zkey has an impossible size for one more contribution.`, 413);
    }
    if (!HEX64.test(c.sha256 ?? "") || !HEX128.test(c.contributionHash ?? "")) throw bad(`The ${c.id} entry is incomplete.`);
    expected += c.bytes;
  });
  if (contentLength !== expected) throw bad("The Content-Length does not match the bundle header.");

  for (const c of meta.circuits) {
    const handle = await open(join(dir, `${c.id}.zkey`), "w");
    try {
      const sha256 = await cursor.copyTo(handle, c.bytes);
      if (sha256 !== c.sha256) throw bad(`The ${c.id} zkey arrived damaged (sha256 mismatch).`);
    } finally {
      await handle.close();
    }
  }
  if (!(await cursor.atEnd())) throw bad("The bundle has trailing data.");
  return meta;
}
