#!/usr/bin/env node
// Contribute to the Dagon zkAPI trusted setup from a terminal. No wallet, no keys, nothing is installed or kept.
//
//   node contribute.mjs --server https://ceremony.dagon.so --name "Alice"
//
// Everything below the argument parsing is shared with the web page (lib/flow.mjs, lib/contribute-core.mjs).
import { writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { CeremonyClient, CeremonyError } from "./lib/client.mjs";
import { contributeZkey } from "./lib/contribute-core.mjs";
import { contributeToCeremony } from "./lib/flow.mjs";
import { prettyHash } from "./lib/hex.mjs";
import { terminateThreads } from "./lib/snark.mjs";

const USAGE = `Usage: node contribute.mjs --server URL [--name NAME] [--entropy-text TEXT] [--receipt FILE]

  --server         the ceremony coordinator, for example https://ceremony.dagon.so
  --name           the name shown in the public transcript (optional; default "Anonymous")
  --entropy-text   anything unpredictable you type; it is mixed into your randomness (optional,
                   the operating system's random generator is always used as well)
  --receipt FILE   where to save your contribution receipt (default: ./dagon-ceremony-receipt-<round>.json)
`;

const mib = (bytes) => (bytes / 2 ** 20).toFixed(1);

/** Runs one contribution. `io` and the network are injectable so tests can drive it in-process. */
export async function main(argv, { fetch: fetcher, sleep = (ms) => new Promise((r) => setTimeout(r, ms)), out = (line) => console.log(line), err = (line) => console.error(line) } = {}) {
  let parsed;
  try {
    parsed = parseArgs({ args: argv, options: { server: { type: "string" }, name: { type: "string", default: "" }, "entropy-text": { type: "string", default: "" }, receipt: { type: "string" }, help: { type: "boolean", short: "h" } } });
  } catch (error) {
    err(`${error.message}\n\n${USAGE}`);
    return 2;
  }
  const { values } = parsed;
  if (values.help || !values.server) {
    (values.help ? out : err)(USAGE);
    return values.help ? 0 : 2;
  }

  const client = new CeremonyClient({ server: values.server, ...(fetcher && { fetch: fetcher }) });
  let lastLine = "";
  const say = (line) => {
    if (line !== lastLine) err(line);
    lastLine = line;
  };
  let lastDecile = -1;
  const onEvent = (event) => {
    if (event.phase === "joining") say("Joining the queue...");
    else if (event.phase === "waiting") say(event.ahead === 0 ? "Next in line..." : `Waiting: ${event.ahead} ahead of you (about ${Math.ceil((event.etaSeconds ?? 0) / 60)} min).`);
    else if (event.phase === "turn") say(`It is your turn. You have ${Math.round(event.expiresInMs / 60000)} minutes.`);
    else if (event.phase === "downloading") say(`Downloading ${event.circuit} (${event.index + 1}/${event.total})${event.size ? `, ${mib(event.size)} MiB` : ""}...`);
    else if (event.phase === "contributing") {
      const decile = Math.floor(event.fraction * 10);
      if (decile !== lastDecile) {
        lastDecile = decile;
        say(`Contributing to ${event.circuit} (${event.index + 1}/${event.total}): ${decile * 10}%`);
      }
    } else if (event.phase === "uploading" && event.sent === undefined) say(`Uploading ${mib(event.total)} MiB...`);
    else if (event.phase === "verifying") say("Uploaded. The coordinator is verifying your contribution (this can take a few minutes)...");
    else if (event.phase === "expired") say(`${event.message} Rejoining the queue...`);
  };

  try {
    const result = await contributeToCeremony({
      client,
      name: values.name,
      entropyText: values["entropy-text"],
      sleep,
      onEvent,
      contribute: contributeZkey,
    });
    const receiptPath = resolve(values.receipt ?? `dagon-ceremony-receipt-${result.round}.json`);
    await writeFile(receiptPath, `${JSON.stringify({ server: values.server, name: result.name, round: result.round, attestation: result.attestation, contributions: result.contributions.map((c) => ({ circuit: c.id, contributionHash: c.contributionHash })) }, null, 2)}\n`);
    out("");
    out(`Thank you! Your contribution is round ${result.round} of the ceremony.`);
    out("");
    out("Your attestation hash (post it publicly so everyone can see their contribution is included):");
    out(result.attestation);
    out("");
    for (const c of result.contributions) out(`${c.id} contribution hash:\n${prettyHash(c.contributionHash)}\n`);
    out(`Suggested post: I contributed randomness to the Dagon zkAPI trusted setup, round ${result.round}. Attestation: ${result.attestation}`);
    out(`Receipt saved to ${receiptPath}. It contains no secrets; nothing secret was ever stored.`);
    return 0;
  } catch (error) {
    err(error instanceof CeremonyError ? `\nStopped: ${error.message}` : `\nUnexpected error: ${error instanceof Error ? error.stack : error}`);
    return 1;
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const code = await main(process.argv.slice(2));
  await terminateThreads();
  process.exit(code);
}
