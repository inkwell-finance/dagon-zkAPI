# Ceremony mirror

`dagon-ceremony-mirror` is a cron Worker (every 10 minutes) that copies the coordinator's public `/files/` tree from
https://ceremony.dagon.so into the R2 bucket `dagon-ceremony`, served at https://ceremony-files.dagon.so. It holds no
credentials and writes only through its `BUCKET` binding, only under `files/`.

Each run:

1. Fetches `transcript.json` and `ceremony.json`.
2. Copies every file the transcript lists (r1cs, each round's zkeys and `entry.json`, the `final/` files once finalized).
   A zkey is skipped only when R2 already has it with the transcript's size and sha256 (R2 stores the checksum because
   the Worker passes `sha256` on put). Files with a known length are streamed; bodies without a content-length or with
   a content-encoding (the coordinator's edge gzips JSON with chunked transfer) are buffered, capped at 8 MiB, hashed and
   put as a buffer. A zkey whose bytes disagree with the transcript is deleted and the run fails.
3. Writes `ceremony.json`, then `transcript.json`, so the published transcript never points at missing files.
4. Deletes `files/` keys the transcript no longer lists (a restarted ceremony). Keys outside `files/` are never touched.

Zkeys uploaded before checksums were stored have none, so the first run of this version downloads them once more.

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
