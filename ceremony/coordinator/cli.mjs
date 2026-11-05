import { parseArgs } from "node:util";
import { resolve } from "node:path";
import { finalizeCeremony } from "./finalize.mjs";
import { initCeremony } from "./init.mjs";

const USAGE = `Usage:
  node coordinator/cli.mjs init     --r1cs-dir DIR [--config ceremony.json] [--ptau FILE] [--data DIR]
  node coordinator/cli.mjs finalize [--data DIR]
DATA_DIR (or --data) defaults to ./data. Start the server with: node coordinator/server.mjs`;

const { positionals, values } = parseArgs({
  allowPositionals: true,
  options: {
    config: { type: "string", default: "ceremony.json" },
    "r1cs-dir": { type: "string" },
    ptau: { type: "string" },
    data: { type: "string" },
  },
});
const dataDir = resolve(values.data ?? process.env.DATA_DIR ?? "data");
const log = (message) => console.log(`[ceremony] ${message}`);

try {
  if (positionals[0] === "init" && values["r1cs-dir"]) {
    await initCeremony({ configPath: resolve(values.config), r1csDir: resolve(values["r1cs-dir"]), dataDir, ptauFile: values.ptau && resolve(values.ptau), log });
  } else if (positionals[0] === "finalize") {
    await finalizeCeremony({ dataDir, log });
  } else {
    console.error(USAGE);
    process.exitCode = 2;
  }
} catch (error) {
  console.error(`[ceremony] ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
}
process.exit();
