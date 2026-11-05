import { createHash } from "node:crypto";
import { open } from "node:fs/promises";
import { toHex } from "./hex.mjs";

// Reads the contribution list (section 10, "MPC params") of a snarkjs groth16 .zkey without loading the file or any
// curve code. Layout (snarkjs src/zkey_utils.js): csHash[64], u32 n, then per contribution
//   deltaAfter G1[64] | g1_s G1[64] | g1_sx G1[64] | g2_spx G2[128] | transcript[64] | u32 type | u32 paramLen | params
// where type 0 = contribution, 1 = beacon, and params are (1,len,name) (2,exp) (3,len,beaconHash) in ascending order.
// The points are stored in Montgomery form; the contribution hash snarkjs prints is blake2b-512 over the same points in
// standard big-endian form (G2 coordinates as c1 then c0) followed by the transcript, so the hash is recomputed here
// from the raw bytes (checked against `snarkjs zkey contribute` in the tests).

const HASHED_BYTES = 64 + 64 + 64 + 128 + 64;
const FIELD_PRIME = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const MONTGOMERY_R_INVERSE = (() => {
  // modular inverse of 2^256 by the extended Euclidean algorithm
  let [r0, r1, s0, s1] = [1n << 256n, FIELD_PRIME, 1n, 0n];
  while (r1 !== 0n) {
    const k = r0 / r1;
    [r0, r1] = [r1, r0 - k * r1];
    [s0, s1] = [s1, s0 - k * s1];
  }
  return ((s0 % FIELD_PRIME) + FIELD_PRIME) % FIELD_PRIME;
})();

/** One 32-byte little-endian Montgomery field element -> 32 bytes big-endian standard form. */
function standardBe(buf, pos, out, outPos) {
  let v = 0n;
  for (let i = 31; i >= 0; i--) v = (v << 8n) | BigInt(buf[pos + i]);
  v = (v * MONTGOMERY_R_INVERSE) % FIELD_PRIME;
  for (let i = 31; i >= 0; i--) {
    out[outPos + i] = Number(v & 0xffn);
    v >>= 8n;
  }
}

function contributionHash(buf, pos) {
  const out = new Uint8Array(HASHED_BYTES);
  // deltaAfter, g1_s, g1_sx: x then y
  for (let i = 0; i < 6; i++) standardBe(buf, pos + i * 32, out, i * 32);
  // g2_spx: (x.c0, x.c1, y.c0, y.c1) stored; hashed as x.c1, x.c0, y.c1, y.c0
  for (const [from, to] of [[0, 1], [1, 0], [2, 3], [3, 2]]) standardBe(buf, pos + 192 + from * 32, out, 192 + to * 32);
  out.set(buf.subarray(pos + 320, pos + 384), 320);
  return createHash("blake2b512").update(out).digest("hex");
}
const SECTION_MPC = 10;

export const CONTRIBUTION = 0;
export const BEACON = 1;

function parseEntry(buf, pos) {
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  if (pos + HASHED_BYTES + 8 > buf.length) throw new Error("truncated contribution entry");
  const type = view.getUint32(pos + HASHED_BYTES, true);
  const paramLen = view.getUint32(pos + HASHED_BYTES + 4, true);
  const end = pos + HASHED_BYTES + 8 + paramLen;
  if (end > buf.length) throw new Error("truncated contribution parameters");
  const entry = { raw: buf.subarray(pos, end), type, name: undefined, numIterationsExp: undefined, beaconHash: undefined };
  entry.hash = contributionHash(buf, pos);
  entry.transcript = toHex(buf.subarray(pos + 320, pos + 384));
  let p = pos + HASHED_BYTES + 8;
  let last = 0;
  while (p < end) {
    const kind = buf[p++];
    if (kind <= last) throw new Error("contribution parameters are not sorted");
    last = kind;
    if (kind === 1) {
      const len = buf[p++];
      entry.name = new TextDecoder("utf-8", { fatal: true }).decode(buf.subarray(p, p + len));
      p += len;
    } else if (kind === 2) {
      entry.numIterationsExp = buf[p++];
    } else if (kind === 3) {
      const len = buf[p++];
      entry.beaconHash = toHex(buf.subarray(p, p + len));
      p += len;
    } else {
      throw new Error("unknown contribution parameter");
    }
  }
  if (p !== end) throw new Error("contribution parameters overrun their length");
  return entry;
}

export function parseMpcSection(buf) {
  if (buf.length < 68) throw new Error("MPC section too short");
  const n = new DataView(buf.buffer, buf.byteOffset, buf.byteLength).getUint32(64, true);
  const contributions = [];
  let pos = 68;
  for (let i = 0; i < n; i++) {
    const entry = parseEntry(buf, pos);
    contributions.push(entry);
    pos += entry.raw.length;
  }
  if (pos !== buf.length) throw new Error("trailing bytes after the last contribution");
  return { csHash: toHex(buf.subarray(0, 64)), contributions };
}

async function readMpc(readAt, size) {
  const head = await readAt(0, 12);
  const headView = new DataView(head.buffer, head.byteOffset, head.byteLength);
  if (head.length < 12 || toHex(head.subarray(0, 4)) !== "7a6b6579") throw new Error("not a zkey file");
  if (headView.getUint32(4, true) !== 1) throw new Error("unsupported zkey version");
  const sections = headView.getUint32(8, true);
  let pos = 12;
  for (let i = 0; i < sections; i++) {
    const sh = await readAt(pos, 12);
    if (sh.length < 12) throw new Error("truncated zkey section table");
    const shView = new DataView(sh.buffer, sh.byteOffset, sh.byteLength);
    const type = shView.getUint32(0, true);
    const len = Number(shView.getBigUint64(4, true));
    pos += 12;
    if (pos + len > size) throw new Error("zkey section runs past the end of the file");
    if (type === SECTION_MPC) return parseMpcSection(await readAt(pos, len));
    pos += len;
  }
  throw new Error("zkey has no contribution section");
}

/** @returns {Promise<{csHash: string, contributions: Array}>} */
export function readMpcFromBytes(bytes) {
  return readMpc((pos, len) => Promise.resolve(bytes.subarray(pos, pos + len)), bytes.length);
}

export async function readMpcFromFile(path) {
  const handle = await open(path, "r");
  try {
    const { size } = await handle.stat();
    return await readMpc(async (pos, len) => {
      const buf = Buffer.alloc(len);
      const { bytesRead } = await handle.read(buf, 0, len, pos);
      return buf.subarray(0, bytesRead);
    }, size);
  } finally {
    await handle.close();
  }
}

/**
 * Checks that `next` is `prev` plus exactly one more contribution. Returns the first problem as a string, or null.
 * `expectedType` is CONTRIBUTION for contributor uploads and BEACON for the final round.
 */
export function extensionProblem(prev, next, { expectedType, expectedName }) {
  if (prev.csHash !== next.csHash) return "the circuit hash differs from the previous round (a different circuit?)";
  if (next.contributions.length !== prev.contributions.length + 1) {
    return `expected ${prev.contributions.length + 1} contributions, found ${next.contributions.length}`;
  }
  for (let i = 0; i < prev.contributions.length; i++) {
    if (Buffer.compare(prev.contributions[i].raw, next.contributions[i].raw) !== 0) return `contribution #${i + 1} was altered`;
  }
  const added = next.contributions[next.contributions.length - 1];
  if (added.type !== expectedType) return expectedType === CONTRIBUTION ? "the new contribution is not an ordinary contribution" : "the new contribution is not a beacon";
  if (expectedName !== undefined && added.name !== expectedName) return "the contribution name inside the zkey does not match the declared name";
  return null;
}
