import { copyFile, mkdir, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { zKey } from "snarkjs";
import { fetchBeacon } from "../lib/beacon.mjs";
import { loadConfig } from "../lib/config.mjs";
import { hashFile, writeJsonAtomic } from "../lib/files.mjs";
import { ptauFileName } from "../lib/ptau.mjs";
import { applyBeacon, terminateThreads, verifyZkey } from "../lib/snark.mjs";
import { BEACON, extensionProblem, readMpcFromFile } from "../lib/zkey-info.mjs";
import { Store } from "./store.mjs";

const mdEscape = (text) => String(text).replace(/[\\`*_{}[\]()#+\-.!|<>~]/g, "\\$&");

export function beaconContributionName(spec) {
  return `Final beacon: ${spec.source} ${spec.round ?? spec.height}`;
}

/**
 * Applies the pre-announced public beacon to the newest round of every circuit, verifies the result with snarkjs,
 * exports the verification keys and writes final/ (<id>_final.zkey, <id>_verification_key.json, FINAL.md).
 * Stop the coordinator first; closed.json is written so a server that is still running stops accepting uploads.
 */
export async function finalizeCeremony({ dataDir, fetch: fetcher = fetch, now = Date.now, log = () => {} }) {
  const store = new Store(dataDir);
  const config = await loadConfig(store.path("ceremony.json"));
  const rounds = await store.rounds();
  if (rounds.length === 0) throw new Error("nothing to finalize: no rounds");
  if (rounds.some((r) => r.kind === "beacon")) throw new Error("this ceremony already has its final beacon");
  const base = rounds[rounds.length - 1];
  if (base.kind !== "contribution") throw new Error("the ceremony has no contributions yet");
  if (!config.beacon) throw new Error("ceremony.json names no beacon");

  const beacon = await fetchBeacon(config.beacon, { fetch: fetcher, now });
  log(`beacon: ${beacon.description}`);
  for (const url of beacon.urls) log(`  fetched from ${url}`);
  log(`  value ${beacon.value}, ${beacon.iterationsExp} hash iteration exponent`);

  await writeJsonAtomic(store.path("closed.json"), { time: new Date(now()).toISOString(), reason: "finalize" });
  const ptau = store.path("ptau", ptauFileName(config));
  const staging = await store.newStaging();
  const finalDir = store.path("final");
  await mkdir(finalDir, { recursive: true });
  const circuits = {};
  const vkHashes = {};

  for (const c of config.circuits) {
    const zkey = join(staging, `${c.id}.zkey`);
    log(`${c.id}: applying the beacon`);
    await applyBeacon({ zkeyIn: join(store.roundDir(base.round), `${c.id}.zkey`), zkeyOut: zkey, name: beaconContributionName(config.beacon), beaconHex: beacon.value, iterationsExp: beacon.iterationsExp });
    const [prev, next] = await Promise.all([readMpcFromFile(join(store.roundDir(base.round), `${c.id}.zkey`)), readMpcFromFile(zkey)]);
    const problem = extensionProblem(prev, next, { expectedType: BEACON });
    if (problem) throw new Error(`${c.id}: ${problem}`);
    const last = next.contributions[next.contributions.length - 1];
    if (last.beaconHash !== beacon.value || last.numIterationsExp !== beacon.iterationsExp) throw new Error(`${c.id}: the zkey does not record the beacon that was applied`);

    log(`${c.id}: zkey verify`);
    const check = await verifyZkey({ r1cs: store.path("r1cs", c.r1cs), ptau, zkey });
    if (!check.ok) throw new Error(`${c.id}: the final zkey does not verify: ${check.errors.join("; ")}`);

    const vk = await zKey.exportVerificationKey(zkey);
    const vkPath = join(finalDir, `${c.id}_verification_key.json`);
    await writeFile(vkPath, `${JSON.stringify(vk, null, 2)}\n`);
    vkHashes[c.id] = await hashFile(vkPath);
    circuits[c.id] = { sha256: await hashFile(zkey), bytes: (await stat(zkey)).size, contributionHash: last.hash, contributions: next.contributions.length, verificationKeySha256: vkHashes[c.id] };
  }

  if ((await store.latest()).round !== base.round) throw new Error("a round was added while finalizing; stop the coordinator and run finalize again");
  const entry = {
    round: base.round + 1,
    kind: "beacon",
    time: new Date(now()).toISOString(),
    beacon: { spec: config.beacon, description: beacon.description, urls: beacon.urls, value: beacon.value, iterationsExp: beacon.iterationsExp },
    circuits,
  };
  await store.promote(staging, entry);
  for (const c of config.circuits) await copyFile(join(store.roundDir(entry.round), `${c.id}.zkey`), join(finalDir, `${c.id}_final.zkey`));

  const transcript = await store.writeTranscript();
  await writeFile(join(finalDir, "FINAL.md"), finalReport(config, transcript.rounds));
  await terminateThreads();
  log(`final keys written to ${finalDir}`);
  return { entry, dir: finalDir };
}

export function finalReport(config, rounds) {
  const init = rounds[0];
  const last = rounds[rounds.length - 1];
  const lines = [`# ${mdEscape(config.name)}: final keys`, ""];
  lines.push(`Phase 1: ${config.ptau.url}`, `${config.ptau.hashAlgorithm}: \`${config.ptau.hash}\` (power ${config.ptau.power})`, "");
  lines.push(`Contributions: ${rounds.filter((r) => r.kind === "contribution").length}, final beacon: ${last.beacon.description} (value \`${last.beacon.value}\`, 2^${last.beacon.iterationsExp} iterations)`, "");
  lines.push("## Final keys", "", "| circuit | constraints | r1cs sha256 | final zkey sha256 | verification key sha256 |", "|---|---|---|---|---|");
  for (const c of config.circuits) {
    lines.push(`| ${c.id} | ${init.circuits[c.id].constraints} | \`${init.circuits[c.id].r1csSha256}\` | \`${last.circuits[c.id].sha256}\` | \`${last.circuits[c.id].verificationKeySha256}\` |`);
  }
  lines.push("", "## Contributions", "", "Attestation = sha256 of the text `dagon-zkapi-ceremony-v1`, `round:N`, then one `<circuit>:<contribution hash>` line per circuit.", "");
  lines.push("| round | contributor | time (UTC) | attestation |", "|---|---|---|---|");
  for (const r of rounds.filter((x) => x.kind === "contribution")) lines.push(`| ${r.round} | ${mdEscape(r.name)} | ${r.time} | \`${r.attestation}\` |`);
  for (const c of config.circuits) {
    lines.push("", `### ${c.id}: contribution hashes (blake2b-512)`, "");
    for (const r of rounds.filter((x) => x.kind !== "init")) lines.push(`- round ${r.round} ${r.kind === "beacon" ? "(beacon)" : mdEscape(r.name)}: \`${r.circuits[c.id].contributionHash}\``);
  }
  lines.push("", "## Verify it yourself", "", "```", "node verify-ceremony.mjs <coordinator URL or a copy of the data directory> --ceremony ceremony.json", "```", "");
  return lines.join("\n");
}
