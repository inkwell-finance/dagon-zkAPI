import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { curves, powersOfTau } from "snarkjs";
import { BN254_SCALAR_FIELD } from "../lib/r1cs-info.mjs";
import { terminateThreads } from "../lib/snark.mjs";

/** Binary snarkjs .r1cs for a hand-written constraint system. Wire order: 1, public inputs, private inputs. */
export function r1csBytes({ nPubIn, nPrvIn, constraints }) {
  const n8 = 32;
  const nWires = 1 + nPubIn + nPrvIn;
  const le = (value) => {
    const out = Buffer.alloc(n8);
    let v = BigInt(value);
    for (let i = 0; i < n8; i++) {
      out[i] = Number(v & 0xffn);
      v >>= 8n;
    }
    return out;
  };
  const fr = (value) => le(((BigInt(value) % BN254_SCALAR_FIELD) + BN254_SCALAR_FIELD) % BN254_SCALAR_FIELD);
  const u32 = (v) => {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(v);
    return b;
  };
  const u64 = (v) => {
    const b = Buffer.alloc(8);
    b.writeBigUInt64LE(BigInt(v));
    return b;
  };
  const section = (type, body) => Buffer.concat([u32(type), u64(body.length), body]);
  const lc = (terms) => Buffer.concat([u32(Object.keys(terms).length), ...Object.entries(terms).flatMap(([wire, coeff]) => [u32(Number(wire)), fr(coeff)])]);

  const header = Buffer.concat([u32(n8), le(BN254_SCALAR_FIELD), u32(nWires), u32(0), u32(nPubIn), u32(nPrvIn), u64(nWires), u32(constraints.length)]);
  const body = Buffer.concat(constraints.flatMap((c) => [lc(c.a), lc(c.b), lc(c.c)]));
  const labels = Buffer.concat(Array.from({ length: nWires }, (_, i) => u64(i)));
  return Buffer.concat([Buffer.from("r1cs"), u32(1), u32(3), section(1, header), section(2, body), section(3, labels)]);
}

/** Three small, different circuits standing in for request / withdrawal / transition. */
export const TINY_CIRCUITS = {
  // x * y = z, z public
  request: { nPubIn: 1, nPrvIn: 2, constraints: [{ a: { 2: 1 }, b: { 3: 1 }, c: { 1: 1 } }] },
  // x * y = z; x * x = w; (w + y) * 1 = v ; z, v public
  withdrawal: {
    nPubIn: 2,
    nPrvIn: 3,
    constraints: [
      { a: { 3: 1 }, b: { 4: 1 }, c: { 1: 1 } },
      { a: { 3: 1 }, b: { 3: 1 }, c: { 5: 1 } },
      { a: { 5: 1, 4: 1 }, b: { 0: 1 }, c: { 2: 1 } },
    ],
  },
  // b * b = a ; a * b = c ; a public
  transition: {
    nPubIn: 1,
    nPrvIn: 2,
    constraints: [
      { a: { 2: 1 }, b: { 2: 1 }, c: { 1: 1 } },
      { a: { 1: 1 }, b: { 2: 1 }, c: { 3: 1 } },
    ],
  },
};

/** Writes the r1cs files, generates a small prepared Powers of Tau file and a ceremony.json pinning it. */
export async function makeFixture(dir, { power = 5, beacon } = {}) {
  await mkdir(dir, { recursive: true });
  const r1csDir = join(dir, "r1cs");
  await mkdir(r1csDir, { recursive: true });
  for (const [id, circuit] of Object.entries(TINY_CIRCUITS)) await writeFile(join(r1csDir, `${id}.r1cs`), r1csBytes(circuit));

  const curve = await curves.getCurveFromName("bn128");
  const ptauPath = join(dir, "tiny.ptau");
  const quiet = { debug() {}, info() {}, warn() {}, error() {} };
  const files = ["a.ptau", "b.ptau"].map((name) => ({ type: "mem", name }));
  await powersOfTau.newAccumulator(curve, power, files[0], quiet);
  await powersOfTau.contribute(files[0], files[1], "fixture", "not secret, test only", quiet);
  const prepared = { type: "mem" };
  await powersOfTau.preparePhase2(files[1], prepared, quiet);
  await writeFile(ptauPath, prepared.data);
  await terminateThreads();

  const config = {
    name: "Test ceremony",
    version: 1,
    curve: "bn128",
    contributionsCloseAt: "2023-09-06T00:00:00Z",
    ptau: { url: "https://example.invalid/tiny.ptau", hash: createHash("blake2b512").update(prepared.data).digest("hex"), hashAlgorithm: "blake2b-512", power },
    circuits: Object.entries(TINY_CIRCUITS).map(([id, c]) => ({ id, r1cs: `${id}.r1cs`, publicInputs: c.nPubIn })),
    beacon: beacon ?? { source: "drand", chain: "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971", round: 424242, applyAfter: "2023-09-07T08:41:30Z", iterationsExp: 10 },
  };
  const configPath = join(dir, "ceremony.json");
  await writeFile(configPath, `${JSON.stringify(config, null, 2)}\n`);
  return { r1csDir, ptauPath, config, configPath, ptauBytes: await readFile(ptauPath) };
}

/** A manually advanced clock: nothing in the suite waits for real time. */
export function fakeClock(start = Date.parse("2023-09-01T12:00:00Z")) {
  return {
    t: start,
    now() {
      return this.t;
    },
    advance(ms) {
      this.t += ms;
    },
  };
}

/** Offline relay fixture for a real, BLS-authenticated historical quicknet round, never a production beacon. */
export function fakeDrand({ chain, round, agree = true }) {
  if (round !== 424242) throw new Error("the authenticated fixture only covers round 424242");
  const signature = "b66f8efb68da63badf91791f3fb9b5ede0b65f5fb2a3bb13ae6af77341bca15c71b358add2821621d96dda82b9b9cc03";
  const randomness = createHash("sha256").update(Buffer.from(signature, "hex")).digest("hex");
  let calls = 0;
  const fetcher = async (url) => {
    const u = new URL(url);
    calls++;
    if (u.pathname !== `/${chain}/public/${round}`) return new Response("not found", { status: 404 });
    const second = u.hostname.startsWith("api2");
    const value = !agree && second ? createHash("sha256").update(Buffer.from("00".repeat(48), "hex")).digest("hex") : randomness;
    const sig = !agree && second ? "00".repeat(48) : signature;
    return Response.json({ round, randomness: value, signature: sig });
  };
  return { fetch: fetcher, randomness, calls: () => calls };
}
