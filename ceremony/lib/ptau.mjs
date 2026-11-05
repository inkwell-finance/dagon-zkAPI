import { copyFile, mkdir, rename, rm, stat } from "node:fs/promises";
import { basename, join } from "node:path";
import { hashFile, downloadTo } from "./files.mjs";

export function ptauFileName(config) {
  return basename(new URL(config.ptau.url).pathname) || `ptau-${config.ptau.power}.ptau`;
}

/**
 * Returns the path of a Powers of Tau file whose hash equals the pin in ceremony.json. Reuses `dir`/<name> when it
 * already verifies, otherwise downloads it (url, then mirrors) and refuses anything that does not match the pin.
 * `localFile` lets an operator supply a file they downloaded themselves; it is verified, never trusted.
 */
export async function ensurePtau(config, { dir, localFile, fetch: fetcher = fetch, log = () => {} }) {
  const { hash, hashAlgorithm } = config.ptau;
  const target = join(dir, ptauFileName(config));
  await mkdir(dir, { recursive: true });

  for (const candidate of [localFile, target]) {
    if (!candidate) continue;
    const present = await stat(candidate).then(() => true, () => false);
    if (!present) continue;
    log(`hashing ${candidate} (${hashAlgorithm})`);
    const actual = await hashFile(candidate, hashAlgorithm);
    if (actual !== hash) throw new Error(`${candidate}: ${hashAlgorithm} ${actual} does not match the pinned ${hash}`);
    if (candidate !== target) await copyFile(candidate, target);
    return target;
  }

  const sources = [config.ptau.url, ...(config.ptau.mirrors ?? [])];
  const tmp = `${target}.download`;
  const failures = [];
  for (const url of sources) {
    log(`downloading ${url}`);
    let lastReport = 0;
    try {
      const result = await downloadTo(url, tmp, {
        fetch: fetcher,
        algorithm: hashAlgorithm,
        onProgress: (bytes, total) => {
          if (bytes - lastReport < 16 * 2 ** 20) return;
          lastReport = bytes;
          log(`  ${(bytes / 2 ** 20).toFixed(0)} MiB${total ? ` of ${(total / 2 ** 20).toFixed(0)}` : ""}`);
        },
      });
      if (result.hash !== hash) {
        await rm(tmp, { force: true });
        failures.push(`${url}: ${hashAlgorithm} ${result.hash} does not match the pinned ${hash}`);
        continue;
      }
      await rename(tmp, target);
      return target;
    } catch (error) {
      failures.push(`${url}: ${error.message}`);
    }
  }
  throw new Error(`no source delivered the pinned Powers of Tau file:\n  ${failures.join("\n  ")}`);
}
