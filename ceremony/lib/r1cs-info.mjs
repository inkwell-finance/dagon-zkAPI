import { open } from "node:fs/promises";

// Header of the snarkjs/circom binary .r1cs format: "r1cs", u32 version, u32 sections, then sections of
// (u32 type, u64 size, data). Section 1 is the header.

export const BN254_SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export async function readR1csHeader(path) {
  const handle = await open(path, "r");
  try {
    const { size: fileSize } = await handle.stat();
    const readAt = async (buffer, position) => {
      let offset = 0;
      while (offset < buffer.length) {
        const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, position + offset);
        if (bytesRead === 0) throw new Error("truncated r1cs header or section table");
        offset += bytesRead;
      }
    };
    const pre = Buffer.alloc(12);
    await readAt(pre, 0);
    if (pre.toString("latin1", 0, 4) !== "r1cs") throw new Error(`${path} is not an r1cs file`);
    if (pre.readUInt32LE(4) !== 1) throw new Error("unsupported r1cs version");
    const sections = pre.readUInt32LE(8);
    if (sections > Math.floor((fileSize - 12) / 12)) throw new Error("r1cs section count exceeds the file size");
    const sh = Buffer.alloc(12);
    let pos = 12;
    for (let i = 0; i < sections; i++) {
      await readAt(sh, pos);
      const type = sh.readUInt32LE(0);
      const size = sh.readBigUInt64LE(4);
      pos += 12;
      if (size > BigInt(fileSize - pos)) throw new Error("r1cs section runs past the end of the file");
      if (type === 1) {
        if (size !== 64n) throw new Error("BN254 r1cs header must be exactly 64 bytes");
        const buf = Buffer.alloc(64);
        await readAt(buf, pos);
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
      pos += Number(size);
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
