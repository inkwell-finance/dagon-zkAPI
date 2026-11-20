// Cron Worker: mirrors the Dagon zkAPI ceremony coordinator's public /files/ tree into the R2 bucket served at
// https://ceremony-files.dagon.so. Holds no credentials: it writes through the BUCKET binding.
//
// Round and final zkeys are checked by R2 against transcript sha256 values before publication. Indexes are written
// last, then stale files/ keys are pruned. Closure and final artifacts are retained even when an older/open
// transcript is observed. Readers still verify independently (verify-ceremony.mjs).
const SRC = "https://ceremony.dagon.so";

// Only bodies without a length in either the transcript or response need buffering. Never buffer a whole zkey
// just because the edge compressed it or omitted content-length.
export const BUFFER_CAP = 8 * 1024 * 1024;

export const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");

const contentType = (key) => (key.endsWith(".json") ? "application/json" : key.endsWith(".md") ? "text/markdown" : "application/octet-stream");

export async function get(path, optional = false) {
  const r = await fetch(`${SRC}/files/${path}`, { cf: { cacheTtl: 0 } });
  if (!r.ok || !r.body) {
    await r.body?.cancel();
    if (optional && r.status === 404) return null;
    throw new Error(`GET ${path} -> ${r.status}`);
  }
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
  const r = await get(key, expect?.optional);
  if (!r) return "absent";
  const lengthHeader = r.headers.get("content-length");
  // An encoded response's content-length describes compressed bytes, not fetch's decoded body.
  const responseLength = !r.headers.get("content-encoding") && lengthHeader !== null ? Number(lengthHeader) : NaN;
  const length = expect?.bytes ?? responseLength;
  const streamable = Number.isSafeInteger(length) && length >= 0;
  const fail = async (message) => {
    await env.BUCKET.delete(`files/${key}`);
    throw new Error(`${message}; removed from the mirror`);
  };

  if (!streamable) {
    const bytes = await readCapped(r.body, BUFFER_CAP, key);
    if (expect?.bytes && bytes.byteLength !== expect.bytes) return fail(`${key}: size ${bytes.byteLength} != transcript ${expect.bytes}`);
    const digest = hex(await crypto.subtle.digest("SHA-256", bytes));
    if (expect?.sha256 && digest !== expect.sha256) return fail(`${key}: sha256 ${digest} != transcript ${expect.sha256}`);
    await env.BUCKET.put(`files/${key}`, bytes, { httpMetadata: { contentType: contentType(key) }, sha256: digest });
    return "uploaded";
  }

  if (expect?.bytes && Number.isFinite(responseLength) && responseLength !== expect.bytes) {
    await r.body.cancel();
    return fail(`${key}: size ${responseLength} != transcript ${expect.bytes}`);
  }
  // R2 verifies the supplied checksum and retains it for isCurrent(). Do not tee to a second hash consumer:
  // a faster hash branch can queue the entire body behind a slow upload, defeating streaming's memory bound.
  try {
    await env.BUCKET.put(`files/${key}`, r.body.pipeThrough(new FixedLengthStream(length)), {
      httpMetadata: { contentType: contentType(key) },
      ...(expect?.sha256 ? { sha256: expect.sha256 } : {}),
    });
  } catch (error) {
    return fail(`${key}: put failed: ${error.message ?? error}`);
  }
  return "uploaded";
}

// Public artifacts relative to files/. Closure is not recorded in the transcript; a final beacon round is.
export function wantedFiles(transcript) {
  const wanted = transcript.ceremony.circuits.map((c) => ({ key: `r1cs/${c}.r1cs` }));
  for (const round of transcript.rounds) {
    const dir = `rounds/${String(round.round).padStart(4, "0")}`;
    for (const [id, info] of Object.entries(round.circuits ?? {})) wanted.push({ key: `${dir}/${id}.zkey`, sha256: info.sha256, bytes: info.bytes });
    wanted.push({ key: `${dir}/entry.json` });
  }
  const last = transcript.rounds.at(-1);
  const finalized = last?.kind === "beacon";
  wanted.push({ key: "closed.json", optional: !finalized, refresh: true });
  if (finalized) {
    wanted.push({ key: "final/FINAL.md", refresh: true });
    for (const c of transcript.ceremony.circuits) {
      const info = last.circuits[c];
      wanted.push(
        { key: `final/${c}_final.zkey`, sha256: info.sha256, bytes: info.bytes },
        { key: `final/${c}_verification_key.json`, sha256: info.verificationKeySha256, refresh: true },
      );
    }
  }
  return wanted;
}

// Complete the listing before deleting anything: a failed page must not cause partial pruning.
// Never prune closure/final artifacts, or keys outside files/ (including round1/ and index.html).
export async function prune(env, keep) {
  const listed = new Set(["files/ceremony.json", "files/transcript.json", "files/closed.json", ...[...keep].map((k) => `files/${k}`)]);
  const stale = [];
  let cursor;
  do {
    const page = await env.BUCKET.list({ prefix: "files/", cursor });
    for (const o of page.objects) if (o.key.startsWith("files/") && !o.key.startsWith("files/final/") && !listed.has(o.key)) stale.push(o.key);
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor);
  for (const key of stale) await env.BUCKET.delete(key);
  return stale.length;
}

export async function sync(env) {
  const transcriptBytes = await readCapped((await get("transcript.json")).body, BUFFER_CAP, "transcript.json");
  const transcript = JSON.parse(new TextDecoder().decode(transcriptBytes));
  const configBytes = await readCapped((await get("ceremony.json")).body, BUFFER_CAP, "ceremony.json");
  const wanted = wantedFiles(transcript);
  const counts = { uploaded: 0, present: 0, absent: 0 };
  for (const w of wanted) {
    // r1cs and entry files are immutable; closure and final reports are refreshed after a restart.
    if (!w.bytes && !w.refresh && (await env.BUCKET.head(`files/${w.key}`))) { counts.present++; continue; }
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
