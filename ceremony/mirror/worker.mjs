// Cron Worker: mirrors the Dagon zkAPI ceremony coordinator's public /files/ tree into the R2 bucket served at
// https://ceremony-files.dagon.so. Holds no credentials: it writes through the BUCKET binding.
//
// Round files are immutable and listed with their sha256 in transcript.json. Each missing file is copied from the
// coordinator into R2 while it is hashed; a hash mismatch deletes the object again, so the mirror never serves a
// file that disagrees with the transcript. ceremony.json and transcript.json are written last, so a reader never
// sees a transcript that points at files the mirror does not have yet. Once they are written, files/ keys the
// transcript no longer lists (a restarted ceremony) are deleted. Readers verify everything independently anyway
// (verify-ceremony.mjs checks every hash and replays every contribution).
const SRC = "https://ceremony.dagon.so";

// Bodies without a usable content-length (the coordinator's edge gzips JSON with chunked transfer) are buffered in
// memory, so they are capped. Zkeys always arrive with a length and are streamed.
export const BUFFER_CAP = 8 * 1024 * 1024;

export const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");

const contentType = (key) => (key.endsWith(".json") ? "application/json" : key.endsWith(".md") ? "text/markdown" : "application/octet-stream");

export async function get(path) {
  const r = await fetch(`${SRC}/files/${path}`, { cf: { cacheTtl: 0 } });
  if (!r.ok || !r.body) throw new Error(`GET ${path} -> ${r.status}`);
  return r;
}

// Reads a body into one buffer, failing as soon as it exceeds `cap` bytes.
export async function readCapped(body, cap, key) {
  const chunks = [];
  let size = 0;
  const reader = body.getReader();
  for (let next = await reader.read(); !next.done; next = await reader.read()) {
    size += next.value.byteLength;
    if (size > cap) {
      await reader.cancel();
      throw new Error(`${key}: body exceeds ${cap} bytes`);
    }
    chunks.push(next.value);
  }
  const out = new Uint8Array(size);
  let at = 0;
  for (const chunk of chunks) {
    out.set(chunk, at);
    at += chunk.byteLength;
  }
  return out;
}

// True when R2 already holds exactly the transcript's bytes (size and the sha256 checksum R2 stored at put time).
export async function isCurrent(env, key, expect) {
  const head = await env.BUCKET.head(`files/${key}`);
  const sha256 = head?.checksums?.sha256;
  return Boolean(head && head.size === expect.bytes && sha256 && hex(sha256) === expect.sha256);
}

export async function mirrorFile(env, key, expect) {
  if (expect?.bytes && expect?.sha256 && (await isCurrent(env, key, expect))) return "present";
  const r = await get(key);
  const lengthHeader = r.headers.get("content-length");
  const length = lengthHeader === null ? NaN : Number(lengthHeader);
  // A content-encoded body is decoded by fetch, so its content-length (if any) is the compressed size.
  const streamable = !r.headers.get("content-encoding") && Number.isFinite(length) && length > 0;
  const fail = async (message) => {
    await env.BUCKET.delete(`files/${key}`);
    throw new Error(`${message}; removed from the mirror`);
  };

  if (!streamable) {
    const bytes = await readCapped(r.body, expect?.bytes ?? BUFFER_CAP, key);
    if (expect?.bytes && bytes.byteLength !== expect.bytes) return fail(`${key}: size ${bytes.byteLength} != transcript ${expect.bytes}`);
    const digest = hex(await crypto.subtle.digest("SHA-256", bytes));
    if (expect?.sha256 && digest !== expect.sha256) return fail(`${key}: sha256 ${digest} != transcript ${expect.sha256}`);
    await env.BUCKET.put(`files/${key}`, bytes, { httpMetadata: { contentType: contentType(key) }, sha256: digest });
    return "uploaded";
  }

  if (expect?.bytes && length !== expect.bytes) {
    await r.body.cancel();
    return fail(`${key}: size ${length} != transcript ${expect.bytes}`);
  }
  const [toBucket, toHash] = r.body.tee();
  const digest = new crypto.DigestStream("SHA-256");
  const hashed = toHash.pipeTo(digest).then(() => digest.digest);
  // With the transcript's sha256 in the options R2 itself rejects a mismatching body and stores the checksum that
  // isCurrent() compares on later runs.
  const put = env.BUCKET.put(`files/${key}`, toBucket.pipeThrough(new FixedLengthStream(length)), {
    httpMetadata: { contentType: contentType(key) },
    ...(expect?.sha256 ? { sha256: expect.sha256 } : {}),
  });
  const [stored, hash] = await Promise.allSettled([put, hashed]);
  if (hash.status === "rejected") return fail(`${key}: download failed: ${hash.reason?.message ?? hash.reason}`);
  const got = hex(hash.value);
  if (expect?.sha256 && got !== expect.sha256) return fail(`${key}: sha256 ${got} != transcript ${expect.sha256}`);
  if (stored.status === "rejected") return fail(`${key}: put failed: ${stored.reason?.message ?? stored.reason}`);
  return "uploaded";
}

// Every file the transcript references, relative to files/.
export function wantedFiles(transcript) {
  const wanted = transcript.ceremony.circuits.map((c) => ({ key: `r1cs/${c}.r1cs` }));
  for (const round of transcript.rounds) {
    const dir = `rounds/${String(round.round).padStart(4, "0")}`;
    for (const [id, info] of Object.entries(round.circuits ?? {})) wanted.push({ key: `${dir}/${id}.zkey`, sha256: info.sha256, bytes: info.bytes });
    wanted.push({ key: `${dir}/entry.json` });
  }
  if (transcript.final) {
    wanted.push({ key: "final/FINAL.md" });
    for (const c of transcript.ceremony.circuits) wanted.push({ key: `final/${c}_final.zkey` }, { key: `final/${c}_verification_key.json` });
  }
  return wanted;
}

// Deletes files/ objects that are neither in `keep` nor ceremony.json/transcript.json. Never touches keys outside files/.
export async function prune(env, keep) {
  const listed = new Set(["files/ceremony.json", "files/transcript.json", ...[...keep].map((k) => `files/${k}`)]);
  const stale = [];
  let cursor;
  do {
    const page = await env.BUCKET.list({ prefix: "files/", cursor });
    for (const o of page.objects) if (o.key.startsWith("files/") && !listed.has(o.key)) stale.push(o.key);
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor);
  for (const key of stale) await env.BUCKET.delete(key);
  return stale.length;
}

export async function sync(env) {
  const transcriptBytes = await (await get("transcript.json")).arrayBuffer();
  const configBytes = await (await get("ceremony.json")).arrayBuffer();
  const transcript = JSON.parse(new TextDecoder().decode(transcriptBytes));
  const wanted = wantedFiles(transcript);
  const counts = { uploaded: 0, present: 0 };
  for (const w of wanted) {
    // r1cs, entry and final files carry no size in the transcript; skip them once present (they never change).
    if (!w.bytes && (await env.BUCKET.head(`files/${w.key}`))) { counts.present++; continue; }
    counts[await mirrorFile(env, w.key, w)]++;
  }
  await env.BUCKET.put("files/ceremony.json", configBytes, { httpMetadata: { contentType: "application/json" } });
  await env.BUCKET.put("files/transcript.json", transcriptBytes, { httpMetadata: { contentType: "application/json" } });
  const removed = await prune(env, wanted.map((w) => w.key));
  console.log(JSON.stringify({ rounds: transcript.rounds.length, ...counts, removed }));
}

export default {
  async scheduled(_event, env, ctx) {
    ctx.waitUntil(sync(env));
  },
};
