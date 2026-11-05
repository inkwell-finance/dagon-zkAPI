import { readFile } from "node:fs/promises";
import { DRAND_DEFAULT_CHAIN, drandRoundTime } from "./beacon.mjs";

const ID = /^[a-z][a-z0-9-]{0,31}$/;
const HASH_ALGORITHMS = new Set(["blake2b-512", "sha256"]);
const HEX64 = /^[0-9a-f]{64}$/;

/** Node's name for a ceremony.json hashAlgorithm. */
export function nodeHashName(algorithm) {
  return algorithm === "blake2b-512" ? "blake2b512" : algorithm;
}

function fail(message) {
  throw new Error(`ceremony.json: ${message}`);
}

function validateBeacon(beacon) {
  if (beacon === undefined) return;
  if (beacon === null || typeof beacon !== "object") fail("beacon must be an object");
  if (Number.isNaN(Date.parse(beacon.applyAfter)) || !/Z$/.test(beacon.applyAfter)) fail("beacon.applyAfter must be an ISO UTC time such as 2026-12-01T00:00:00Z");
  if (beacon.iterationsExp !== undefined && !(Number.isInteger(beacon.iterationsExp) && beacon.iterationsExp >= 10 && beacon.iterationsExp <= 40)) {
    fail("beacon.iterationsExp must be an integer between 10 and 40");
  }
  if (beacon.source === "drand") {
    if (!Number.isSafeInteger(beacon.round) || beacon.round < 1) fail("a drand beacon needs a positive safe integer round");
    if ((beacon.chain ?? DRAND_DEFAULT_CHAIN) !== DRAND_DEFAULT_CHAIN) fail("beacon.chain must be the authenticated quicknet chain");
    if (Date.parse(beacon.applyAfter) !== drandRoundTime(beacon.round)) fail("beacon.applyAfter must equal the scheduled drand round time");
  } else if (beacon.source === "bitcoin") {
    if (!Number.isInteger(beacon.height) || beacon.height < 1) fail("a bitcoin beacon needs a positive integer height");
  } else {
    fail('beacon.source must be "drand" or "bitcoin"');
  }
}

export function validateConfig(config) {
  if (config === null || typeof config !== "object") fail("not an object");
  if (typeof config.name !== "string" || config.name === "") fail("name is required");
  const ptau = config.ptau;
  if (!ptau || typeof ptau.url !== "string" || !/^[0-9a-f]+$/.test(ptau.hash ?? "")) fail("ptau needs url and a lowercase hex hash");
  if (!HASH_ALGORITHMS.has(ptau.hashAlgorithm)) fail('ptau.hashAlgorithm must be "blake2b-512" or "sha256"');
  if (!Number.isInteger(ptau.power) || ptau.power < 1 || ptau.power > 28) fail("ptau.power must be an integer between 1 and 28");
  if (!Array.isArray(config.circuits) || config.circuits.length === 0) fail("circuits must be a non-empty array");
  const seen = new Set();
  for (const c of config.circuits) {
    if (!ID.test(c.id ?? "")) fail(`circuit id ${JSON.stringify(c.id)} is not a lowercase identifier`);
    if (seen.has(c.id)) fail(`duplicate circuit ${c.id}`);
    seen.add(c.id);
    if (c.r1cs !== `${c.id}.r1cs`) fail(`circuit ${c.id}: r1cs must be "${c.id}.r1cs"`);
    if (!Number.isInteger(c.publicInputs) || c.publicInputs < 0) fail(`circuit ${c.id}: publicInputs must be a non-negative integer`);
    if (c.r1csSha256 !== undefined && !HEX64.test(c.r1csSha256)) fail(`circuit ${c.id}: r1csSha256 must be 64 hex digits`);
  }
  validateBeacon(config.beacon);
  if (!Number.isFinite(Date.parse(config.contributionsCloseAt)) || !/Z$/.test(config.contributionsCloseAt)) fail("contributionsCloseAt must be an ISO UTC timestamp");
  if (config.beacon && Date.parse(config.contributionsCloseAt) >= Date.parse(config.beacon.applyAfter)) fail("contributionsCloseAt must precede beacon.applyAfter");
  return config;
}

export async function loadConfig(path) {
  return validateConfig(JSON.parse(await readFile(path, "utf8")));
}
