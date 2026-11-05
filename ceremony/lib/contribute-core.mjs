import { zKey } from "snarkjs";
import { toHex } from "./hex.mjs";

// The one function both the browser page (inside a Web Worker) and the CLI use to add a contribution to a zkey.
// snarkjs derives its secret from blake2b(64 fresh random bytes from the platform CSPRNG || entropy string), so
// everything passed in `entropyText` only ADDS to the platform randomness; it can never reduce it.

const SECTION_PROGRESS = /^Applying key: (L|H) Section: (\d+)\/(\d+)$/;

/** Fresh platform randomness, hex encoded, for callers that want to show or log nothing but still feed snarkjs. */
export function randomHex(byteLength = 64) {
  return toHex(crypto.getRandomValues(new Uint8Array(byteLength)));
}

/**
 * @param {object} args
 * @param {Uint8Array} args.zkey the previous round's zkey
 * @param {string} args.name contributor display name (already normalised, at most 64 characters)
 * @param {string} args.entropyText extra entropy from the contributor (typed text, pointer movement, ...); may be empty
 * @param {(fraction: number) => void} [args.onProgress] called with 0..1 for this zkey
 * @returns {Promise<{zkey: Uint8Array, contributionHash: string}>} contributionHash is blake2b-512 hex, as `snarkjs zkey verify` prints it
 */
export async function contributeZkey({ zkey, name, entropyText, onProgress }) {
  const input = { type: "mem", data: zkey };
  const output = { type: "mem", initialSize: zkey.length + (1 << 20) };
  const logger = {
    debug(message) {
      const m = SECTION_PROGRESS.exec(message);
      if (m) onProgress?.(((m[1] === "H" ? 1 : 0) + Number(m[2]) / Number(m[3])) / 2);
    },
    info() {},
    warn() {},
    error(message) {
      throw new Error(`snarkjs: ${message}`);
    },
  };
  // Mix in 64 bytes of our own CSPRNG output as well, so the secret does not depend on snarkjs alone.
  const entropy = `${randomHex(64)}|${entropyText}`;
  const hash = await zKey.contribute(input, output, name, entropy, logger);
  onProgress?.(1);
  return { zkey: output.data, contributionHash: toHex(hash) };
}
