import { copyFile, mkdir, stat } from "node:fs/promises";
import { join } from "node:path";
import { loadConfig } from "../lib/config.mjs";
import { hashFile } from "../lib/files.mjs";
import { ensurePtau } from "../lib/ptau.mjs";
import { BN254_SCALAR_FIELD, ptauPowerNeeded, readR1csHeader } from "../lib/r1cs-info.mjs";
import { newZkey, terminateThreads, verifyZkey } from "../lib/snark.mjs";
import { readMpcFromFile } from "../lib/zkey-info.mjs";
import { Store } from "./store.mjs";

/**
 * Creates round 0000: verifies the Powers of Tau file against its pin, checks every r1cs against ceremony.json, and
 * runs `snarkjs zkey new` for each circuit. Refuses to touch a directory that already has a ceremony in it.
 */
export async function initCeremony({ configPath, r1csDir, dataDir, ptauFile, fetch: fetcher = fetch, now = Date.now, log = () => {} }) {
  const config = await loadConfig(configPath);
  if (!config.beacon) throw new Error("ceremony.json must name the final beacon (source, round or height, applyAfter) BEFORE the ceremony starts: it is committed in advance so nobody can pick it after the fact");
  const store = new Store(dataDir);
  if ((await store.rounds()).length > 0) throw new Error(`${dataDir} already contains a ceremony`);
  await mkdir(dataDir, { recursive: true });

  const ptau = await ensurePtau(config, { dir: store.path("ptau"), localFile: ptauFile, fetch: fetcher, log });
  log("Powers of Tau file verified against the pinned hash");

  const circuits = {};
  await mkdir(store.path("r1cs"), { recursive: true });
  for (const c of config.circuits) {
    const source = join(r1csDir, c.r1cs);
    const header = await readR1csHeader(source);
    if (header.prime !== BN254_SCALAR_FIELD) throw new Error(`${c.id}: the r1cs is not over the BN254 scalar field`);
    if (header.nPubOut !== 0) throw new Error(`${c.id}: expected nPubOut = 0 (public inputs are listed as inputs), found ${header.nPubOut}`);
    if (header.nPubIn !== c.publicInputs) throw new Error(`${c.id}: ceremony.json says ${c.publicInputs} public inputs, the r1cs has ${header.nPubIn}`);
    const power = ptauPowerNeeded(header);
    if (power > config.ptau.power) throw new Error(`${c.id}: needs a Powers of Tau of power ${power}, ceremony.json pins power ${config.ptau.power}`);
    const sha = await hashFile(source);
    if (c.r1csSha256 !== undefined && c.r1csSha256 !== sha) throw new Error(`${c.id}: r1cs sha256 ${sha} does not match the pin in ceremony.json`);
    await copyFile(source, store.path("r1cs", c.r1cs));
    circuits[c.id] = { r1csSha256: sha, constraints: header.nConstraints, wires: header.nWires, publicInputs: header.nPubIn, ptauPowerNeeded: power };
    log(`${c.id}: ${header.nConstraints} constraints, ${header.nPubIn} public inputs, needs power ${power}`);
  }

  const staging = await store.newStaging();
  for (const c of config.circuits) {
    const zkey = join(staging, `${c.id}.zkey`);
    log(`${c.id}: snarkjs zkey new`);
    await newZkey({ r1cs: store.path("r1cs", c.r1cs), ptau, zkey });
    const check = await verifyZkey({ r1cs: store.path("r1cs", c.r1cs), ptau, zkey });
    if (!check.ok) throw new Error(`${c.id}: the fresh zkey does not verify: ${check.errors.join("; ")}`);
    const mpc = await readMpcFromFile(zkey);
    circuits[c.id] = { ...circuits[c.id], sha256: await hashFile(zkey), bytes: (await stat(zkey)).size, csHash: mpc.csHash, contributions: 0 };
  }
  await copyFile(configPath, store.path("ceremony.json"));
  await store.promote(staging, { round: 0, kind: "init", time: new Date(now()).toISOString(), circuits });
  await terminateThreads();
  log(`round 0000 written to ${store.roundDir(0)}`);
  return store;
}
