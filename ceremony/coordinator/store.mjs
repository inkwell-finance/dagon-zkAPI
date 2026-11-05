import { randomBytes } from "node:crypto";
import { mkdir, open, readdir, readFile, rename, rm, stat, statfs } from "node:fs/promises";
import { join } from "node:path";
import { writeJsonAtomic } from "../lib/files.mjs";

// Everything lives under one data directory, laid out exactly as it is published (served under /files/ and consumed by
// verify-ceremony.mjs, so a copy of the directory is a complete public mirror):
//
//   ceremony.json            the configuration this ceremony was initialised with (immutable)
//   ptau/<file>.ptau         the verified Powers of Tau file (not served)
//   r1cs/<id>.r1cs           the circuits
//   rounds/NNNN/<id>.zkey    every accepted round; NNNN/entry.json is that round's transcript entry
//   transcript.json          derived from the entry.json files, rewritten after each promotion
//   final/                   written by `finalize`: <id>_final.zkey, <id>_verification_key.json, FINAL.md
//   closed.json              present once the ceremony stopped accepting contributions
//   staging/                 uploads in flight (not served)

export const roundName = (round) => String(round).padStart(4, "0");

export class Store {
  constructor(dir) {
    this.dir = dir;
  }

  path(...parts) {
    return join(this.dir, ...parts);
  }

  roundDir(round) {
    return this.path("rounds", roundName(round));
  }

  async rounds() {
    const names = await readdir(this.path("rounds")).catch((error) => { if (error.code === "ENOENT") return []; throw error; });
    const entries = [];
    for (const name of names.filter((n) => /^\d{4,}$/.test(n)).sort((a, b) => Number(a) - Number(b))) {
      entries.push(JSON.parse(await readFile(this.path("rounds", name, "entry.json"), "utf8")));
    }
    entries.forEach((entry, i) => {
      if (entry.round !== i) throw new Error(`rounds/ is not contiguous: expected round ${i}, found ${entry.round}`);
    });
    return entries;
  }

  async latest() {
    const rounds = await this.rounds();
    return rounds.length === 0 ? undefined : rounds[rounds.length - 1];
  }

  async isClosed() {
    return stat(this.path("closed.json")).then(() => true, (error) => { if (error.code === "ENOENT") return false; throw error; });
  }

  async cleanStaging() {
    await rm(this.path("staging"), { recursive: true, force: true });
    await mkdir(this.path("staging"), { recursive: true });
  }

  async requireSpace(bytes) {
    const fs = await statfs(this.dir);
    if (fs.bavail * fs.bsize < bytes + 1024 ** 3) throw new Error("insufficient disk space: preserve 1 GiB reserve plus staging/final copies");
  }

  async newStaging() {
    const dir = this.path("staging", randomBytes(8).toString("hex"));
    await mkdir(dir, { recursive: true });
    return dir;
  }

  /** Atomically publishes a staged round: entry.json goes in, then one directory rename is the commit point. */
  async promote(stagingDir, entry) {
    for (const name of await readdir(stagingDir)) {
      const handle = await open(join(stagingDir, name), "r+");
      try { await handle.sync(); } finally { await handle.close(); }
    }
    await writeJsonAtomic(join(stagingDir, "entry.json"), entry);
    await mkdir(this.path("rounds"), { recursive: true });
    await rename(stagingDir, this.roundDir(entry.round));
    try {
      if (process.platform !== "win32") {
        const parent = await open(this.path("rounds"), "r");
        try { await parent.sync(); } finally { await parent.close(); }
      }
      await this.writeTranscript();
    }
    catch (error) { error.committed = true; throw error; }
  }

  async discard(stagingDir) {
    await rm(stagingDir, { recursive: true, force: true });
  }

  async writeTranscript() {
    const config = JSON.parse(await readFile(this.path("ceremony.json"), "utf8"));
    const rounds = await this.rounds();
    const transcript = { version: 1, ceremony: { name: config.name, ptau: config.ptau, circuits: config.circuits.map((c) => c.id), beacon: config.beacon }, rounds };
    await writeJsonAtomic(this.path("transcript.json"), transcript);
    return transcript;
  }
}
