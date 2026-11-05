import { createHash, randomBytes } from "node:crypto";
import { createReadStream, createWriteStream } from "node:fs";
import { mkdir, open, rename, rm } from "node:fs/promises";
import { dirname } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { nodeHashName } from "./config.mjs";

export async function hashFile(path, algorithm = "sha256") {
  const hash = createHash(nodeHashName(algorithm));
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest("hex");
}

/** The published JSON byte convention; digests of published JSON are over exactly this text. */
const jsonText = (value) => `${JSON.stringify(value, null, 2)}\n`;
export const jsonSha256 = (value) => createHash("sha256").update(jsonText(value)).digest("hex");

export async function writeJsonAtomic(path, value) {
  const tmp = `${path}.tmp-${randomBytes(6).toString("hex")}`;
  const handle = await open(tmp, "wx");
  try {
    await handle.writeFile(jsonText(value));
    await handle.sync();
  } finally { await handle.close(); }
  await rename(tmp, path);
  // Directory fsync is supported on the Linux deployment, but not Windows.
  if (process.platform !== "win32") {
    const directory = await open(dirname(path), "r");
    try { await directory.sync(); } finally { await directory.close(); }
  }
}

/** Honor the public archive's explicit rate-limit backoff, bounded to five attempts. */
export async function fetchWithRetry(url, { fetch: fetcher = fetch, sleep: delay = sleep, ...options } = {}) {
  for (let attempt = 0; ; attempt++) {
    const response = await fetcher(url, options);
    if (response.status !== 429 || attempt >= 4) return response;
    const retry = response.headers.get("retry-after");
    const ms = /^\d+$/.test(retry ?? "") ? Number(retry) * 1000 : Date.parse(retry) - Date.now();
    await response.body?.cancel();
    await delay(Math.min(600_000, Math.max(1000, Number.isFinite(ms) ? ms : 60_000)));
  }
}

/** Download atomically; an interrupted transfer never replaces a complete cached file. */
export async function downloadTo(url, dest, { fetch: fetcher = fetch, algorithm = "sha256", onProgress } = {}) {
  const response = await fetchWithRetry(url, { fetch: fetcher });
  if (!response.ok || !response.body) throw new Error(`GET ${url} failed: HTTP ${response.status}`);
  await mkdir(dirname(dest), { recursive: true });
  const tmp = `${dest}.tmp-${randomBytes(6).toString("hex")}`;
  const total = Number(response.headers.get("content-length")) || 0;
  const hash = createHash(nodeHashName(algorithm));
  let bytes = 0;
  const source = Readable.fromWeb(response.body);
  source.on("data", (chunk) => {
    hash.update(chunk);
    bytes += chunk.length;
    onProgress?.(bytes, total);
  });
  try {
    await pipeline(source, createWriteStream(tmp, { flags: "wx" }));
    await rename(tmp, dest);
  } catch (error) {
    await rm(tmp, { force: true });
    throw error;
  }
  return { hash: hash.digest("hex"), bytes };
}
