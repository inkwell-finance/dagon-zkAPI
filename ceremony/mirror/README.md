# Ceremony mirror

`dagon-ceremony-mirror` is a cron Worker (every 10 minutes) that copies the coordinator's public `/files/` tree from
https://ceremony.dagon.so into the R2 bucket `dagon-ceremony`, served at https://ceremony-files.dagon.so. It holds no
credentials and writes only through its `BUCKET` binding, only under `files/`.

Each run:

1. Fetches `transcript.json` and `ceremony.json`, each capped at 8 MiB before buffering.
2. Copies every file the transcript lists (r1cs, each round's zkeys and `entry.json`). A last round with
   `kind: "beacon"` also requires `final/FINAL.md`, final zkeys and verification-key JSON; there is no `transcript.final`.
   Round and final zkeys are skipped only when R2 already has the transcript's size and stored sha256; verification
   keys are skipped when R2 has their transcript sha256.
   The Worker supplies the expected sha256 on put, so R2 rejects mismatching bytes and stores the checksum.
   Zkeys stream through `FixedLengthStream` using their transcript size, even with gzip/chunked responses.
   Other bodies use a valid unencoded response length, or are buffered with an 8 MiB cap and hashed.
   A zkey or verification key whose bytes disagree with the transcript is deleted and the run fails. A failed put
   leaves the previous object in place, so a transient failure on a file without a transcript sha256 deletes nothing.
3. Probes `closed.json` every run, copying it before the indexes. Only a 404 while not finalized is optional;
   other errors abort the run. Finalization requires the checkpoint. Final reports are refreshed.
4. Writes `ceremony.json`, then `transcript.json`, after all required artifacts have been copied.
5. Lists all pages under `files/`, then deletes stale keys. A listing failure deletes nothing; a transcript fetch,
   body-read or parse failure never reaches listing. `files/closed.json` and **all** `files/final/` objects are never
   pruned, even when an open/older transcript is observed. Nothing outside `files/` is touched (`round1/`, `index.html`).
   Removing retained close/final artifacts after an intentional restart is an operator task. Objects uploaded after
   the run started are not pruned: an overlapping run (a slow run lasting past the next cron tick) may have seen a
   newer transcript.

Zkeys uploaded before checksums were stored have none, so the first run of this version downloads them once more.

## Worker resource limits

The [Workers limit](https://developers.cloudflare.com/workers/platform/limits/#memory) is 128 MB **per isolate**.
Buffering a 50 MiB zkey is unsafe: retaining chunks plus a contiguous copy already costs about 100 MiB, before
digest input copies, runtime overhead and concurrent invocations. This Worker instead streams transcript-sized
zkeys and avoids `tee()` (a fast hash consumer could otherwise queue the whole file behind a slow R2 upload).
Only bounded unknown-length bodies are hashed in the Worker; large zkey checksums are verified by R2.
The cap bounds body storage, not total isolate memory including parsed JSON.

For this 10-minute cron, the [documented CPU limits](https://developers.cloudflare.com/workers/platform/limits/#cpu-time)
are 10 ms on Workers Free, or 30 seconds by default on Workers Paid (configurable up to 5 minutes).
The 15-minute CPU allowance applies to intervals of at least one hour; 15 minutes of wall time is separate.
Use Workers Paid and monitor invocation CPU/memory metrics; local Node tests do not measure deployed Worker quotas.
`DigestStream` and buffered `subtle.digest` both perform SHA-256 work proportional to input size; buffering does not
make hashing roughly 108 MB cheaper. The large-body Worker hash pass is now removed entirely.

[R2 accepts](https://developers.cloudflare.com/r2/api/workers/workers-api-reference/#r2putoptions) `sha256` as a
32-byte ArrayBuffer or 64-character hexadecimal string, and `head().checksums.sha256` is an ArrayBuffer.
The Worker uses hexadecimal strings on put and converts the returned buffer to hex for comparisons.

## Test

```sh
cd ceremony && node --test mirror/
```

## Deploy

```sh
cd ceremony/mirror && npx wrangler deploy
```

or upload `worker.mjs` as an ES module through the Cloudflare API with the cron and `BUCKET` binding from
`wrangler.toml`.

## Pause

Set `crons = []` in `wrangler.toml` and deploy (or clear the Worker's cron triggers through the API). Restore
`["*/10 * * * *"]` to resume.
