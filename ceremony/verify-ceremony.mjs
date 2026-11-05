#!/usr/bin/env node
// Re-verifies a whole Dagon zkAPI ceremony with no trust in the coordinator.
//
//   node verify-ceremony.mjs https://ceremony.dagon.so --ceremony ceremony.json
//   node verify-ceremony.mjs ./copy-of-the-data-directory --ceremony ceremony.json --r1cs-dir ./my-own-r1cs
//
// What it checks (every line of the report is one check):
//  * ceremony.json equals your pinned copy, and its Powers of Tau pin equals the Hermez hash published by snarkjs
//  * the Powers of Tau file you download from its original source has that hash
//  * the circuits (r1cs) are the ones pinned / the ones you exported yourself
//  * every published round: sha256 against the transcript, each round extends the previous one, contribution hashes
//    and attestation hashes recomputed from the zkey files themselves
//  * the final zkey of every circuit passes `snarkjs zkey verify` from the r1cs and the ptau (this re-derives the
//    initial zkey and checks every contribution and the beacon in the file)
//  * the final beacon matches the value re-fetched from the public source named in ceremony.json
//  * the verification keys, and the sha256 of every final key
import { createHash } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { zKey } from "snarkjs";
import { attestationHash } from "./lib/attestation.mjs";
import { fetchBeacon } from "./lib/beacon.mjs";
import { validateConfig } from "./lib/config.mjs";
import { downloadTo, hashFile } from "./lib/files.mjs";
import { hermezPin } from "./lib/hermez.mjs";
import { ptauFileName } from "./lib/ptau.mjs";
import { BN254_SCALAR_FIELD, ptauPowerNeeded, readR1csHeader } from "./lib/r1cs-info.mjs";
import { terminateThreads, verifyZkey } from "./lib/snark.mjs";
import { DirSource, UrlSource } from "./lib/source.mjs";
import { BEACON, CONTRIBUTION, readMpcFromFile } from "./lib/zkey-info.mjs";

const USAGE = `Usage: node verify-ceremony.mjs <coordinator URL | directory> [options]
  --ceremony FILE     your pinned copy of ceremony.json (recommended: the one committed in the repository)
  --r1cs-dir DIR      r1cs files you exported yourself from the circuits (recommended); otherwise the published ones are used
  --ptau FILE         a Powers of Tau file you already have (it is hash-checked, never trusted)
  --cache DIR         download directory (default: the system temp directory)
  --final-only        download only the final round (the final zkey alone contains every contribution)
  --all-rounds        run the full snarkjs verification on EVERY round, not just the final one (slow)
  --offline           do not re-fetch the beacon value from its public source
  --require-final     fail unless the final beacon has been applied
  --allow-custom-ptau accept a Powers of Tau file that is not in the Hermez list (tests only)
  --json              print the report as JSON`;

/**
 * @returns {Promise<{ok: boolean, finalized: boolean, checks: Array<{ok: boolean|null, name: string, detail?: string}>, keys: Record<string, object>}>}
 */
export async function verifyCeremony({ source: sourceArg, ceremonyFile, r1csDir, ptauFile, cacheDir = join(tmpdir(), "dagon-ceremony-verify"), finalOnly = false, allRounds = false, offline = false, requireFinal = false, allowCustomPtau = false, fetch: fetcher = fetch, now = Date.now, log = () => {} }) {
  const checks = [];
  // ok: true = PASS, false = FAIL, null = informational
  const check = (ok, name, detail) => {
    checks.push({ ok, name, detail });
    return ok;
  };
  const keys = {};
  const source = /^https?:\/\//i.test(sourceArg) ? new UrlSource(sourceArg, { cacheDir, fetch: fetcher, log }) : new DirSource(resolve(sourceArg));

  // 1. configuration
  const published = await source.json("ceremony.json");
  let config = published;
  if (ceremonyFile) {
    const pinned = JSON.parse(await readFile(ceremonyFile, "utf8"));
    const same = JSON.stringify(sortKeys(pinned)) === JSON.stringify(sortKeys(published));
    check(same, "ceremony.json served by the coordinator equals your pinned copy", same ? undefined : "the coordinator is running a different configuration than the one you pinned");
    if (!same) return { ok: false, finalized: false, checks, keys };
    config = pinned;
  } else {
    check(null, "ceremony.json is taken from the coordinator", "pass --ceremony with the copy committed in the repository to pin it independently");
  }
  validateConfig(config);

  const pin = hermezPin(config.ptau.power);
  if (pin) {
    const matches = config.ptau.hashAlgorithm === "blake2b-512" && config.ptau.hash === pin.hash;
    check(matches, `Powers of Tau pin equals the Hermez hash published by snarkjs (power ${config.ptau.power})`, matches ? pin.file : `ceremony.json pins ${config.ptau.hash}, snarkjs lists ${pin.hash}`);
  } else {
    check(allowCustomPtau ? null : false, `Powers of Tau power ${config.ptau.power} is a Hermez file`, "no Hermez file for this power");
  }

  // 2. Powers of Tau
  let ptau = ptauFile ?? (source instanceof DirSource && (await source.exists(`ptau/${ptauFileName(config)}`)) ? await source.file(`ptau/${ptauFileName(config)}`) : undefined);
  if (!ptau) {
    ptau = join(cacheDir, ptauFileName(config));
    const cached = await stat(ptau).then(() => true, () => false);
    if (!cached || (await hashFile(ptau, config.ptau.hashAlgorithm)) !== config.ptau.hash) {
      log(`downloading ${config.ptau.url}`);
      await downloadTo(config.ptau.url, ptau, { fetch: fetcher, algorithm: config.ptau.hashAlgorithm });
    }
  }
  const ptauHash = await hashFile(ptau, config.ptau.hashAlgorithm);
  if (!check(ptauHash === config.ptau.hash, `Powers of Tau file has the pinned ${config.ptau.hashAlgorithm}`, ptauHash === config.ptau.hash ? ptauHash.slice(0, 32) + "..." : `got ${ptauHash}`)) {
    return { ok: false, finalized: false, checks, keys };
  }

  // 3. transcript
  const transcript = await source.json("transcript.json");
  const rounds = transcript.rounds ?? [];
  const contiguous = rounds.length > 0 && rounds.every((r, i) => r.round === i) && rounds[0].kind === "init";
  const kindsOk = rounds.slice(1).every((r, i, rest) => (r.kind === "contribution") || (r.kind === "beacon" && i === rest.length - 1));
  if (!check(contiguous && kindsOk, "transcript is a contiguous sequence: init, contributions, optional final beacon", `${rounds.length} rounds`)) return { ok: false, finalized: false, checks, keys };
  const last = rounds[rounds.length - 1];
  const finalized = last.kind === "beacon";
  const contributionRounds = rounds.filter((r) => r.kind === "contribution");
  check(null, `${contributionRounds.length} contribution(s)${finalized ? " and the final beacon" : ", the final beacon has NOT been applied yet"}`);
  if (requireFinal) check(finalized, "the ceremony is finalized (final beacon applied)");

  // 4. circuits
  const r1csPaths = {};
  for (const c of config.circuits) {
    const initInfo = rounds[0].circuits[c.id];
    const path = r1csDir ? join(r1csDir, c.r1cs) : await source.file(`r1cs/${c.r1cs}`, initInfo.r1csSha256);
    r1csPaths[c.id] = path;
    const sha = await hashFile(path);
    const header = await readR1csHeader(path);
    check(sha === initInfo.r1csSha256, `${c.id}: r1cs ${r1csDir ? "you exported" : "published"} has the sha256 recorded at round 0`, sha);
    if (c.r1csSha256 !== undefined) check(sha === c.r1csSha256, `${c.id}: r1cs sha256 equals the pin in ceremony.json`);
    check(header.prime === BN254_SCALAR_FIELD && header.nPubOut === 0 && header.nPubIn === c.publicInputs && ptauPowerNeeded(header) <= config.ptau.power, `${c.id}: r1cs is BN254, has ${c.publicInputs} public inputs and fits the Powers of Tau`, `${header.nConstraints} constraints`);
    if (r1csDir) {
      const published = await source.file(`r1cs/${c.r1cs}`, initInfo.r1csSha256).catch(() => undefined);
      if (published) check((await hashFile(published)) === sha, `${c.id}: the coordinator's published r1cs equals the one you exported`);
    }
  }

  // 5. rounds
  const zkeyPath = {};
  const lastRound = rounds.length - 1;
  for (const round of rounds) {
    if (finalOnly && round.round !== lastRound) continue;
    for (const c of config.circuits) {
      const rel = `rounds/${String(round.round).padStart(4, "0")}/${c.id}.zkey`;
      const path = await source.file(rel, round.circuits[c.id].sha256);
      zkeyPath[`${round.round}/${c.id}`] = path;
      const sha = await hashFile(path);
      if (!check(sha === round.circuits[c.id].sha256, `round ${round.round} ${c.id}.zkey has the sha256 in the transcript`, sha === round.circuits[c.id].sha256 ? undefined : `got ${sha}, transcript says ${round.circuits[c.id].sha256}`)) {
        return { ok: false, finalized, checks, keys };
      }
    }
  }

  for (const c of config.circuits) {
    const finalMpc = await readMpcFromFile(zkeyPath[`${lastRound}/${c.id}`]);
    check(finalMpc.csHash === rounds[0].circuits[c.id].csHash, `${c.id}: circuit hash inside the final zkey equals the one recorded at round 0`);
    check(finalMpc.contributions.length === lastRound, `${c.id}: the final zkey holds ${lastRound} contribution(s), as many as there are rounds`, `found ${finalMpc.contributions.length}`);
    let consistent = finalMpc.contributions.length === lastRound;
    for (const round of rounds.slice(1)) {
      const entry = finalMpc.contributions[round.round - 1];
      if (!entry) continue;
      const wantType = round.kind === "beacon" ? BEACON : CONTRIBUTION;
      if (entry.hash !== round.circuits[c.id].contributionHash || entry.type !== wantType || (round.kind === "contribution" && entry.name !== round.name)) {
        consistent = false;
        check(false, `${c.id}: round ${round.round} contribution in the zkey matches the transcript`, `transcript says ${round.circuits[c.id].contributionHash}, zkey has ${entry.hash}`);
      }
    }
    check(consistent, `${c.id}: every contribution hash and name in the transcript equals what is inside the final zkey`);

    // every earlier round is exactly the prefix of the final file
    if (!finalOnly) {
      let prefixOk = true;
      for (const round of rounds.slice(0, -1)) {
        const mpc = await readMpcFromFile(zkeyPath[`${round.round}/${c.id}`]);
        const problem = mpc.contributions.length !== round.round ? "wrong number of contributions" : mpc.contributions.find((m, i) => Buffer.compare(m.raw, finalMpc.contributions[i].raw) !== 0) && "does not extend to the final key";
        if (problem) {
          prefixOk = false;
          check(false, `${c.id}: round ${round.round} is a prefix of the final zkey`, problem);
        }
      }
      check(prefixOk, `${c.id}: every published round extends the previous one and is a prefix of the final zkey`);
    }
  }

  // attestations
  let attestationsOk = true;
  for (const round of contributionRounds) {
    const expected = await attestationHash(round.round, config.circuits.map((c) => ({ id: c.id, contributionHash: round.circuits[c.id].contributionHash })));
    if (expected !== round.attestation) {
      attestationsOk = false;
      check(false, `round ${round.round} (${round.name}): the attestation hash is not sha256 of its contribution hashes`);
    }
  }
  check(attestationsOk, "every attestation hash equals sha256 of that round's contribution hashes");

  // 6. snarkjs verification
  for (const c of config.circuits) {
    const targets = allRounds ? rounds.slice(1) : [last];
    for (const round of targets) {
      log(`${c.id}: snarkjs zkey verify, round ${round.round}`);
      const result = await verifyZkey({ r1cs: r1csPaths[c.id], ptau, zkey: zkeyPath[`${round.round}/${c.id}`] });
      check(result.ok, `${c.id}: snarkjs zkey verify passes for round ${round.round} (all ${round.round} contribution(s), re-derived from the r1cs and the Powers of Tau)`, result.errors.join("; ") || undefined);
    }
  }

  // 7. beacon
  if (finalized) {
    const recorded = last.beacon;
    const specSame = JSON.stringify(sortKeys(recorded.spec)) === JSON.stringify(sortKeys(config.beacon));
    check(specSame, "the beacon applied is the one committed in ceremony.json before the ceremony");
    for (const c of config.circuits) {
      const mpc = await readMpcFromFile(zkeyPath[`${lastRound}/${c.id}`]);
      const tail = mpc.contributions[mpc.contributions.length - 1];
      check(tail.type === BEACON && tail.beaconHash === recorded.value && tail.numIterationsExp === recorded.iterationsExp, `${c.id}: the zkey's last contribution is the beacon ${recorded.value.slice(0, 16)}... with 2^${recorded.iterationsExp} iterations`);
    }
    if (offline) {
      check(null, "the beacon value was NOT re-fetched (--offline)", recorded.description);
    } else {
      try {
        const fresh = await fetchBeacon(config.beacon, { fetch: fetcher, now });
        check(fresh.value === recorded.value, `the beacon value equals the one re-fetched from ${fresh.description}`, fresh.urls.join(", "));
      } catch (error) {
        check(false, "the beacon value could be re-fetched from its public source", error.message);
      }
    }
    // 8. verification keys
    for (const c of config.circuits) {
      const vk = await zKey.exportVerificationKey(zkeyPath[`${lastRound}/${c.id}`]);
      const vkJson = `${JSON.stringify(vk, null, 2)}\n`;
      const vkSha = createHash("sha256").update(vkJson).digest("hex");
      keys[c.id] = { zkeySha256: last.circuits[c.id].sha256, verificationKeySha256: vkSha, constraints: rounds[0].circuits[c.id].constraints };
      if (last.circuits[c.id].verificationKeySha256) check(last.circuits[c.id].verificationKeySha256 === vkSha, `${c.id}: the exported verification key equals the one in the transcript`);
      if (await source.exists(`final/${c.id}_final.zkey`).catch(() => false)) {
        const publishedFinal = await source.file(`final/${c.id}_final.zkey`, last.circuits[c.id].sha256);
        check((await hashFile(publishedFinal)) === last.circuits[c.id].sha256, `${c.id}: final/${c.id}_final.zkey equals the last round`);
      }
    }
  } else {
    for (const c of config.circuits) keys[c.id] = { zkeySha256: last.circuits[c.id].sha256, note: "NOT FINAL: no beacon has been applied yet" };
  }

  await terminateThreads();
  return { ok: checks.every((c) => c.ok !== false), finalized, checks, keys };
}

function sortKeys(value) {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value && typeof value === "object") return Object.fromEntries(Object.keys(value).sort().map((k) => [k, sortKeys(value[k])]));
  return value;
}

export function formatReport(report) {
  const lines = report.checks.map((c) => `${c.ok === true ? "PASS" : c.ok === false ? "FAIL" : "INFO"}  ${c.name}${c.detail ? `  [${c.detail}]` : ""}`);
  lines.push("");
  for (const [id, key] of Object.entries(report.keys)) lines.push(`${id}: final zkey sha256 ${key.zkeySha256}${key.verificationKeySha256 ? `\n${" ".repeat(id.length)}  verification_key.json sha256 ${key.verificationKeySha256}` : ""}${key.note ? `  (${key.note})` : ""}`);
  lines.push("", report.ok ? (report.finalized ? "RESULT: PASS" : "RESULT: PASS so far (the ceremony is not finalized)") : `RESULT: FAIL (${report.checks.filter((c) => c.ok === false).length} check(s) failed)`);
  return lines.join("\n");
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  let code = 2;
  try {
    const { positionals, values } = parseArgs({
      allowPositionals: true,
      options: { ceremony: { type: "string" }, "r1cs-dir": { type: "string" }, ptau: { type: "string" }, cache: { type: "string" }, "final-only": { type: "boolean" }, "all-rounds": { type: "boolean" }, offline: { type: "boolean" }, "require-final": { type: "boolean" }, "allow-custom-ptau": { type: "boolean" }, json: { type: "boolean" }, help: { type: "boolean", short: "h" } },
    });
    if (positionals.length !== 1 || values.help) {
      console.error(USAGE);
    } else {
      const report = await verifyCeremony({ source: positionals[0], ceremonyFile: values.ceremony && resolve(values.ceremony), r1csDir: values["r1cs-dir"] && resolve(values["r1cs-dir"]), ptauFile: values.ptau && resolve(values.ptau), cacheDir: values.cache && resolve(values.cache), finalOnly: values["final-only"], allRounds: values["all-rounds"], offline: values.offline, requireFinal: values["require-final"], allowCustomPtau: values["allow-custom-ptau"], log: (m) => console.error(m) });
      console.log(values.json ? JSON.stringify(report, null, 2) : formatReport(report));
      code = report.ok ? 0 : 1;
    }
  } catch (error) {
    console.error(`FAIL  could not complete the verification: ${error instanceof Error ? error.message : error}`);
    code = 1;
  }
  await terminateThreads();
  process.exit(code);
}
