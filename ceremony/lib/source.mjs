import { mkdir, readFile, stat } from "node:fs/promises";
import { dirname, join } from "node:path";
import { downloadTo, fetchWithRetry, hashFile } from "./files.mjs";

// Where verify-ceremony reads the published ceremony from. Both kinds share the layout the coordinator serves under
// /files/ (ceremony.json, transcript.json, r1cs/, rounds/NNNN/, final/): a coordinator URL, or a directory holding a
// copy of the coordinator's data directory.

export class DirSource {
  constructor(dir) {
    this.dir = dir;
    this.label = dir;
  }

  async json(rel) {
    return JSON.parse(await readFile(join(this.dir, rel), "utf8"));
  }

  async exists(rel) {
    return stat(join(this.dir, rel)).then(() => true, () => false);
  }

  async file(rel) {
    return join(this.dir, rel);
  }
}

export class UrlSource {
  constructor(base, { cacheDir, fetch: fetcher = fetch, log = () => {} }) {
    this.base = base.endsWith("/") ? base : `${base}/`;
    this.label = base;
    this.cacheDir = cacheDir;
    this.fetch = fetcher;
    this.log = log;
  }

  #url(rel) {
    return new URL(`files/${rel}`, this.base).href;
  }

  async json(rel) {
    const response = await fetchWithRetry(this.#url(rel), { fetch: this.fetch });
    if (!response.ok) throw new Error(`GET ${this.#url(rel)}: HTTP ${response.status}`);
    return response.json();
  }

  /** Downloads into the cache (reusing a cached copy whose sha256 is `expectedSha256`) and returns the local path. */
  async file(rel, expectedSha256) {
    const path = join(this.cacheDir, new URL(this.base).host.replace(/[^\w.-]/g, "_"), rel);
    await mkdir(dirname(path), { recursive: true });
    if (expectedSha256 && (await stat(path).then(() => true, () => false)) && (await hashFile(path)) === expectedSha256) return path;
    this.log(`downloading ${rel}`);
    await downloadTo(this.#url(rel), path, { fetch: this.fetch });
    return path;
  }
}
