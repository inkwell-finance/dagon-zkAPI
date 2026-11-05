import { serve } from "@hono/node-server";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { buildApp } from "./app.mjs";
import { loadAssets } from "./assets.mjs";
import { Coordinator } from "./coordinator.mjs";
import { childVerifier } from "./verify-child.mjs";

// Environment (all optional):
//   DATA_DIR       where the ceremony lives (default ./data; a Railway volume in production)
//   HOST, PORT     listen address (default 0.0.0.0:8788)
//   TRUST_PROXY    "1" behind a proxy that appends the client address to X-Forwarded-For (Railway)
//   SLOT_MINUTES   time one contributor holds the slot (default 25)
//   MAX_QUEUE      people allowed to wait at once (default 100)
//   VERIFY_TIMEOUT_MINUTES   kill a snarkjs verification after this long (default 30)

const env = process.env;
const dataDir = resolve(env.DATA_DIR ?? "data");
const number = (name, fallback) => (env[name] ? Number(env[name]) : fallback);

const coordinator = await Coordinator.open({
  dataDir,
  verify: childVerifier({ timeoutMs: number("VERIFY_TIMEOUT_MINUTES", 30) * 60_000 }),
  queue: { slotMs: number("SLOT_MINUTES", 25) * 60_000, maxQueue: number("MAX_QUEUE", 100) },
  log: (message) => console.log(`[ceremony] ${message}`),
});
const { assets, missing } = await loadAssets(fileURLToPath(new URL("../web", import.meta.url)));
if (missing.length > 0) console.warn(`[ceremony] web assets missing (${missing.join(", ")}); run \`npm run build\``);

const app = buildApp({ coordinator, assets, now: Date.now, trustProxy: env.TRUST_PROXY === "1" });
const server = serve({ fetch: app.fetch, hostname: env.HOST ?? "0.0.0.0", port: number("PORT", 8788) }, (info) => {
  console.log(`[ceremony] "${coordinator.config.name}" listening on http://${info.address}:${info.port}, round ${coordinator.latest.round}, data ${dataDir}`);
});
// A contribution upload is tens of megabytes over whatever link the contributor has.
server.requestTimeout = 20 * 60_000;

for (const signal of ["SIGTERM", "SIGINT"]) {
  process.once(signal, async () => {
    console.log(`[ceremony] ${signal}: finishing the verification in progress, then exiting`);
    server.close();
    await coordinator.settled();
    process.exit(0);
  });
}
