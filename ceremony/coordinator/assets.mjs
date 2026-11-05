import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { gzipSync } from "node:zlib";

const TYPES = { ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".mjs": "text/javascript; charset=utf-8", ".svg": "image/svg+xml" };

// name -> where it comes from. Sources live in web/, the browser and CLI bundles are built into web/dist/ by build.mjs.
const FILES = {
  "index.html": "index.html",
  "style.css": "style.css",
  "favicon.svg": "favicon.svg",
  "app.js": "dist/app.js",
  "worker.js": "dist/worker.js",
  "contribute.mjs": "dist/contribute.mjs",
};

/**
 * Loads the page and its bundles into memory once, with the sha256 of each (shown on the page so a visitor can compare
 * it with a build of this repository) and the SRI attribute for the two files the HTML references directly.
 */
export async function loadAssets(webDir) {
  const assets = new Map();
  const missing = [];
  for (const [name, source] of Object.entries(FILES)) {
    const body = await readFile(join(webDir, source)).catch(() => undefined);
    if (!body) {
      missing.push(name);
      continue;
    }
    const digest = createHash("sha256").update(body).digest();
    assets.set(name, { name, body, gzip: gzipSync(body), type: TYPES[name.slice(name.lastIndexOf("."))], sha256: digest.toString("hex"), integrity: `sha256-${digest.toString("base64")}` });
  }
  const index = assets.get("index.html");
  if (index && assets.has("app.js") && assets.has("style.css")) {
    const html = index.body.toString("utf8").replace("__APP_INTEGRITY__", assets.get("app.js").integrity).replace("__CSS_INTEGRITY__", assets.get("style.css").integrity);
    assets.set("index.html", { ...index, body: Buffer.from(html), gzip: gzipSync(html), sha256: createHash("sha256").update(html).digest("hex") });
  }
  return { assets, missing };
}
