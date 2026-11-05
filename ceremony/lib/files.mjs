import { createHash, randomBytes } from "node:crypto";
import { createReadStream, createWriteStream } from "node:fs";
import { rename, rm, writeFile } from "node:fs/promises";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { nodeHashName } from "./config.mjs";

export async function hashFile(path, algorithm = "sha256") {
  const hash = createHash(nodeHashName(algorithm));
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest("hex");
}

export async function writeJsonAtomic(path, value) {
  const tmp = `${path}.tmp-${randomBytes(6).toString("hex")}`;
  await writeFile(tmp, `${JSON.stringify(value, null, 2)}\n`);
  await rename(tmp, path);
}

/** Streams `url` into `dest` and returns the hash of exactly the bytes written. Removes `dest` on any failure. */
export async function downloadTo(url, dest, { fetch: fetcher = fetch, algorithm = "sha256", onProgress } = {}) {
  const response = await fetcher(url);
  if (!response.ok || !response.body) throw new Error(`GET ${url} failed: HTTP ${response.status}`);
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
    await pipeline(source, createWriteStream(dest));
  } catch (error) {
    await rm(dest, { force: true });
    throw error;
  }
  return { hash: hash.digest("hex"), bytes };
}
