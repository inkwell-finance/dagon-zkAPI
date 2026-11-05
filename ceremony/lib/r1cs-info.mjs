import { open } from "node:fs/promises";

// Header of the snarkjs/circom binary .r1cs format: "r1cs", u32 version, u32 sections, then sections of
// (u32 type, u64 size, data). Section 1 is the header.

export const BN254_SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export async function readR1csHeader(path) {
  const handle = await open(path, "r");
  try {
    const pre = Buffer.alloc(12);
    await handle.read(pre, 0, 12, 0);
    if (pre.toString("latin1", 0, 4) !== "r1cs") throw new Error(`${path} is not an r1cs file`);
    if (pre.readUInt32LE(4) !== 1) throw new Error("unsupported r1cs version");
    const sections = pre.readUInt32LE(8);
    let pos = 12;
    for (let i = 0; i < sections; i++) {
      const sh = Buffer.alloc(12);
      await handle.read(sh, 0, 12, pos);
      const type = sh.readUInt32LE(0);
      const size = Number(sh.readBigUInt64LE(4));
      pos += 12;
      if (type === 1) {
        const buf = Buffer.alloc(size);
        await handle.read(buf, 0, size, pos);
        const n8 = buf.readUInt32LE(0);
        if (n8 !== 32) throw new Error(`unsupported r1cs field size ${n8}`);
        let prime = 0n;
        for (let b = n8 - 1; b >= 0; b--) prime = (prime << 8n) | BigInt(buf[4 + b]);
        const o = 4 + n8;
        return {
          prime,
          nWires: buf.readUInt32LE(o),
          nPubOut: buf.readUInt32LE(o + 4),
          nPubIn: buf.readUInt32LE(o + 8),
          nPrvIn: buf.readUInt32LE(o + 12),
          nConstraints: buf.readUInt32LE(o + 24),
        };
      }
      pos += size;
    }
    throw new Error("r1cs has no header section");
  } finally {
    await handle.close();
  }
}

/** Smallest Powers of Tau power snarkjs accepts for this circuit (zkey_new.js: log2(nConstraints + nPubIn + nPubOut) + 1). */
export function ptauPowerNeeded(header) {
  return Math.floor(Math.log2(header.nConstraints + header.nPubIn + header.nPubOut)) + 1;
}
