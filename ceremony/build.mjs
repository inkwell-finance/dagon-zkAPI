// Bundles the browser page (web/app.js, web/worker.js) and a single-file CLI (contribute.mjs) into web/dist/ with the
// snarkjs version pinned in package-lock.json. Nothing is loaded from a CDN at runtime; the coordinator serves these
// files from its own origin.
import { build } from "esbuild";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = (path) => fileURLToPath(new URL(path, import.meta.url));

export async function buildAssets({ outdir = root("web/dist"), logLevel = "info" } = {}) {
  await build({
    entryPoints: [root("web/app.js"), root("web/worker.js")],
    outdir,
    bundle: true,
    format: "esm",
    platform: "browser",
    target: ["es2022", "chrome110", "firefox110", "safari16"],
    minify: true,
    legalComments: "none",
    define: { "process.env.NODE_ENV": '"production"' },
    logLevel,
  });

  // The CLI as one file for contributors who only want to `curl` it: Node built-ins stay external, snarkjs is inlined.
  await build({
    entryPoints: [root("contribute.mjs")],
    outfile: `${outdir}/contribute.mjs`,
    bundle: true,
    format: "esm",
    platform: "node",
    target: "node20",
    alias: { "web-worker": root("web/node-worker.mjs") },
    legalComments: "none",
    banner: { js: 'import { createRequire as __createRequire } from "node:module"; const require = __createRequire(import.meta.url);' },
    logLevel,
  });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await buildAssets();
