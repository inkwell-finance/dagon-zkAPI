import { readFile } from "node:fs/promises";
import { zKey } from "snarkjs";

/** snarkjs keeps a pool of worker threads alive until the curve is terminated; call this before a process should end. */
export async function terminateThreads() {
  await globalThis.curve_bn128?.terminate();
}

// snarkjs reports problems through a logger object (and by returning false / -1); keep only the errors.
function errorCollector() {
  const errors = [];
  const logger = {
    debug() {},
    info() {},
    warn() {},
    error(message) {
      errors.push(String(message));
    },
  };
  return { errors, logger };
}

/**
 * Full snarkjs verification of a zkey against the circuit and the Powers of Tau file: recomputes the initial zkey from
 * the r1cs, checks every contribution in the file (including a beacon) and that all sections follow from it.
 * @returns {Promise<{ok: boolean, errors: string[]}>}
 */
export async function verifyZkey({ r1cs, ptau, zkey }) {
  const { errors, logger } = errorCollector();
  try {
    // snarkjs 0.7.6 leaves file handles open (the Powers of Tau in zkey_verify_frominit.js, the zkey on early
    // rejections). Since Node 26 a FileHandle closed by the garbage collector is an uncaught error, so hand it bytes.
    const ok = await zKey.verifyFromR1cs(await inMemory(r1cs), await inMemory(ptau), await inMemory(zkey), logger);
    return { ok: ok === true && errors.length === 0, errors };
  } catch (error) {
    errors.push(error instanceof Error ? error.message : String(error));
    return { ok: false, errors };
  }
}

/** Creates the contribution-free zkey for a circuit. */
export async function newZkey({ r1cs, ptau, zkey }) {
  const { errors, logger } = errorCollector();
  const result = await zKey.newZKey(r1cs, ptau, zkey, logger);
  if (result === -1 || errors.length > 0) throw new Error(`snarkjs zkey new failed: ${errors.join("; ") || "unknown error"}`);
}

/** Applies a public random beacon as the final contribution. */
export async function applyBeacon({ zkeyIn, zkeyOut, name, beaconHex, iterationsExp }) {
  const { errors, logger } = errorCollector();
  const result = await zKey.beacon(zkeyIn, zkeyOut, name, beaconHex, iterationsExp, logger);
  if (result === false || errors.length > 0) throw new Error(`snarkjs zkey beacon failed: ${errors.join("; ") || "unknown error"}`);
}

async function inMemory(file) {
  return typeof file === "string" ? { type: "mem", data: await readFile(file) } : file;
}

