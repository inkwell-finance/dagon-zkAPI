# Dagon zkAPI trusted setup ceremony

Help secure Dagon zkAPI by contributing fresh randomness. No wallet or account is needed. Independently authenticate the software for the strongest contribution path.

## What this is, in plain words

Dagon's private payments rely on zero-knowledge proofs. To make them, three proof systems (the `request`, `withdrawal` and Solana `transition` circuits) each need a set of public *proving and verifying keys*. Those keys are generated from secret random numbers. **Whoever knows those secret numbers could forge proofs** (for example, create balances out of thin air) without anyone noticing. So the secrets must be destroyed.

This ceremony replaces single-party keys with a **multi-party trusted setup**. The guarantee requires at least one participant using honest software on a trusted device, whose contribution is included in the adopted keys and whose randomness remains unknown. The website and downloadable client are supplied by the coordinator: using them directly trusts that origin. A public beacon does not repair stolen randomness. Before claiming this guarantee, obtain an independently operated, audited contribution and verify its inclusion.

The ceremony uses the standard Groth16 tooling ([snarkjs](https://github.com/iden3/snarkjs), pinned to one exact version):

* **Phase 1** is the public Hermez *Perpetual Powers of Tau* (BN254), already run by hundreds of participants. We pin its published hash and refuse any other file.
* **Phase 2** is specific to our circuits and is the part you contribute to.
* The last step is the precommitted public beacon, applied after a separately recorded and independently published pre-beacon closure. This limits steering conditional on closure publication and the beacon assumptions.

## Contribute in 3 steps

### In your browser (easiest)

1. Open `https://ceremony.dagon.so`.
2. Optionally type a name to show in the public list, optionally type some random characters, and press **Contribute my randomness**. You are placed in a queue; the page shows your position.
3. Keep the tab open until it says **Done**. Copy the **attestation hash** and post it somewhere public (the page prefills a message and share links).

The page targets modern browsers with Web Workers, WebAssembly and `Promise.withResolvers`; it refuses missing built-ins. Build targets are not browser certification. Tests exercise the browser worker in Node, not every browser/device. No runtime CDN dependencies are used. Same-origin SRI detects accidental asset mismatches, not an origin that can replace HTML and hashes.

### From a terminal

Use Node.js 24 or newer (local execution uses Node 26; image uses Node 24). Obtain this repository/revision and `ceremony.json` through an independently authenticated channel, inspect the source and build with locked dependencies:

```sh
cd dagon-zkAPI/ceremony
npm ci
npm run build
cat web/dist/SHA256SUMS
node web/dist/contribute.mjs --server https://ceremony.dagon.so --ceremony ceremony.json --name "Alice"
```

The reproducible build emits `web/dist/SHA256SUMS` for `app.js`, `worker.js` and `contribute.mjs`. Release operators must publish those full digests with the reviewed repository revision **independently of the ceremony origin**. Rebuild that revision and compare before executing downloaded code. A digest downloaded alongside an executable from the same server provides no origin authentication.

The CLI requires `--ceremony FILE` and rejects a different server configuration. Options: `--name` (public, optional), `--receipt FILE` (public receipt). OS cryptographic randomness is always used. Command-line entropy was removed because shell history and process listings can retain it.

Reviewed bundle digests (locked build; independently authenticate this README/revision before relying on them):

```text
14fb3cb119a6139e3952be0d5f2fd60dc8467409aa6164b67bc91dacca1a093c  app.js
7ea726fecdc07ed0a5deb95d8b6e50ea4174ba7776b4b6cb9db25b2ac94a8d0f  worker.js
8d87e42f22d3b4b2a6732f4c7b6b56852b7645896e21d59b0e0ca7c75624e32b  contribute.mjs
```

Two independent output-directory builds reproduced these bytes locally. Compare the deployment's Node 24 build before publishing invitations; do not silently replace these pins if it differs.

The command prints your **attestation hash** and the contribution hash of each circuit, and writes a receipt file with no secrets in it. Post the attestation hash publicly.

### How long does it take?

Current round-zero key sizes are 35,970,228 / 41,807,844 / 49,791,336 bytes (request / withdrawal / transition): **127,569,408 bytes total**, downloaded and uploaded per contribution. Allow several minutes or more; no full-size browser/Railway latency guarantee is established. Earlier 25/40-second estimates did not describe this artifact set. Slots last 25 minutes; expired clients may rejoin. Uploads have a real 15-minute cancellation deadline, including stalled reads and EOF.

## Privacy and secret-memory lifetime

The reviewed honest client uploads public keys, name and hashes, not secret randomness or optional browser input. This is conditional on trusting the code/device: a compromised origin can serve different code. Never enter passwords, seed phrases or existing secrets.

The browser clears input/samples and terminates its worker after completion, failure or cancellation. Close the tab/process afterward. JavaScript garbage collection, OS swap and crash dumps prevent guaranteed zeroization. The CLI writes a public receipt only. Coordinator rate limiting uses salted short-lived address hashes; hosting-edge logs are outside this code's control.

## Check that your contribution is in the final keys

An independently obtained verifier and pinned inputs check the algebra and artifacts without trusting server assertions. Inclusion additionally requires independently retained receipts or checkpoints.

1. **Your hash is public.** The page's contributor list, `https://ceremony.dagon.so/files/transcript.json` and (after the end) `final/FINAL.md` list every contribution with its attestation hash. Yours must be there.
2. **Recompute your attestation** if you like: it is `sha256` of the text `dagon-zkapi-ceremony-v1`, a line `round:<your round>`, then one line `<circuit>:<contribution hash>` per circuit, in the order `request`, `withdrawal`, `transition`, each line ending in a newline. The contribution hashes are in your receipt and in the transcript.
3. **Re-verify everything** (downloads the 75 MB Powers of Tau file, plus the rounds):

   ```sh
   node verify-ceremony.mjs https://ceremony.dagon.so --ceremony ceremony.json --strict --checkpoint closed.json --receipt YOUR_ATTESTATION --manifest adoption.json
   ```

   Obtain `closed.json` independently **before the beacon exists**, not from the final mirror afterward. `--strict` requires finality, all historical rounds including init, online beacon authentication, pinned config and checkpoint. It requires final zkeys and exact published VK JSON matching derived keys, and can emit an adoption manifest. Default verification checks historical hashes/MPC prefixes and fully verifies only the last algebraic key; `--all-rounds` verifies every historical algebraic file. `--final-only` cannot combine with `--all-rounds`/`--strict`. `--offline` cannot produce a strict adoption manifest. A self-consistent transcript cannot prove omitted participants did not exist: use repeatable `--receipt HASH` checks. Cache creation is automatic; downloads honor bounded Retry-After backoff.

## Staying safe

* **Use a device you trust.** A laptop or phone you own, with an up-to-date browser or operating system. Not a shared or work machine you do not control.
* **Close other tabs and programs** while you contribute, and keep the page open and awake until it says Done.
* Optional browser text supplements system randomness; never paste existing secrets.
* At least one independently trusted contribution must be included and its randomness remain unknown. Neither SRI nor the public beacon establishes this.
* Audit/rebuild from an independently authenticated revision, verify digests before execution, retain your receipt and require it during final adoption.

---

# Coordinator guide

This section is for the people running the ceremony.

## Layout

```
ceremony.json            ptau pin (url, hash, power), circuits, the final beacon (chosen in advance)
circuits.json            sizes of the circuits, written by the Rust exporter
coordinator/             server (Hono), init and finalize commands, slot queue, upload receiver, verifier job
web/                     the contributor page (index.html, style.css, app.js, worker.js)
lib/                     code shared by server, CLI, page and verifier (contribution core, flow, zkey reader, beacon, ...)
contribute.mjs           CLI contributor
verify-ceremony.mjs      public verifier
build.mjs                bundles web/dist/{app.js,worker.js} and web/dist/contribute.mjs with the pinned snarkjs
test/                    node --test suites
Dockerfile, docker-entrypoint.sh   image for the coordinator (not deployed from here)
```

## How the Rust bridge fits

```
arkworks circuits --ceremony_export--> <id>.r1cs --coordinator init--> round 0000 --contributors--> --finalize--> <id>_final.zkey --ceremony_import--> arkworks keys
```

1. **Export the circuits** (see [`README-rust.md`](README-rust.md)); it is deterministic, so publish the hashes:

   ```sh
   cargo run --release --manifest-path protocol/rust/Cargo.toml -p zkapi-proof --example ceremony_export -- OUT_DIR
   sha256sum OUT_DIR/*.r1cs
   ```

   Put each `sha256` into the matching circuit's `r1csSha256` in `ceremony.json` and commit it. `init` refuses an r1cs that does not match, and `verify-ceremony` checks it again.
2. **Choose the beacon** (below), commit `ceremony.json`.
3. **Run the ceremony** (`init`, `serve`, contributors).
4. **Finalize**, publish `data/` (or at least `ceremony.json`, `closed.json`, `final/`, `transcript.json`, `rounds/`, `r1cs/`).
5. **Import** into arkworks keys, outside of `protocol/setup` first:

   ```sh
   cargo run --release --manifest-path protocol/rust/Cargo.toml -p zkapi-proof \
     --example ceremony_import -- data/final OUT_DIR adoption.json INDEPENDENTLY_ACCEPTED_MANIFEST_SHA256
   ```

   Generate `adoption.json` with strict verification and independently accept its SHA256. Import hashes the exact bytes it decodes, requires the r1cs it serializes from its own compiled circuits to equal the manifest's verified `r1csSha256`, checks contribution counts and records manifest/digest provenance. Do not obtain the expected digest from an untrusted neighboring file. Import is not a substitute for snarkjs verification.

## Initialise

Requirements: Node 24, `npm ci` (this directory). Everything lives in one data directory (`DATA_DIR`, default `./data`; on Railway a volume mounted at `/data`).

```sh
npm ci
node coordinator/cli.mjs init --config ceremony.json --r1cs-dir OUT_DIR --data data
```

`init` downloads the Powers of Tau file from `ptau.url` (power 16, about 75 MB), **verifies its blake2b-512 hash against the pin and refuses to continue on any mismatch** (use `--ptau FILE` to supply a file you downloaded yourself; it is verified the same way), checks every r1cs (BN254 field, `nPubOut = 0`, public input count equals `publicInputs`, fits the Powers of Tau, `r1csSha256` pin), runs `snarkjs zkey new` and a full verification for each circuit, and writes round `0000`. It refuses to run on a directory that already holds a ceremony.

The pinned Hermez hashes (blake2b-512) come from the snarkjs README table; both the power 16 and 17/18 files were downloaded and hashed during development and match. `ceremony.json` points at `https://circom.info/powersOfTau28_hez_final_16.ptau` (the Google Cloud and S3 locations used in older guides now answer 403); add `ptau.mirrors` if you have another host, the hash makes the source irrelevant.

On start-up `serve` repeats the checks that can be repeated cheaply: the Powers of Tau hash, the r1cs hashes against round 0, and the newest round against the transcript. **It refuses to start if any of them fails.**

The public verifier checks r1cs hashes against the transcript and any independent config pin before parsing the header. The header reader bounds section scans by the actual file length, rejects sections past EOF, and reads only the fixed 64-byte BN254 header; malformed declarations cannot drive unbounded scans or header allocations. History/type/prefix checks and the committed beacon exponent must pass before snarkjs runs, so untrusted keys cannot select an uncommitted, expensive beacon work factor.

## Run

```sh
node coordinator/server.mjs                 # or: npm start
```

| Variable | Default | Meaning |
|---|---|---|
| `DATA_DIR` | `./data` | the ceremony directory |
| `HOST`, `PORT` | `0.0.0.0`, `8788` | listen address |
| `TRUST_PROXY` | off | set `1` behind a proxy that appends the client address to `X-Forwarded-For` (Railway). Without it every client behind the proxy shares one rate-limit bucket |
| `SLOT_MINUTES` | `25` | how long one contributor holds the slot |
| `MAX_QUEUE` | `100` | people allowed to wait at once |
| `VERIFY_TIMEOUT_MINUTES` | `30` | kill a snarkjs verification after this long |
| `INIT_ON_EMPTY` | off | set `1` only for intentional first initialization; remove immediately afterward |

State on disk only needs the volume; the queue is in memory (a restart sends waiting contributors back to the end, their pages and the CLI rejoin on their own), so **run exactly one instance**. `/healthz` answers `{"ok":true,"round":N}`.

The server serves the page at `/`, the self-contained CLI at `/contribute.mjs`, and the public mirror at `/files/`. Build the bundles first (`npm run build`, done by the Dockerfile).

### API

All bodies are JSON unless stated; tickets travel in `Authorization: Bearer <ticket>`; errors are `{ "error": code, "message": text }`.

| | |
|---|---|
| `GET /healthz` | liveness |
| `GET /api/status` | round, contributors (name, time, attestation), queue length, per-circuit `sha256` and size of the latest round, `finalized`, `closed`, sha256 of the page files |
| `POST /api/queue` `{name?}` | join; returns `{ticket, state, ahead, etaSeconds, ...}` (429 when rate limited, 503 when the queue is full) |
| `GET /api/ticket` | `state`: `waiting` (with `ahead`, `etaSeconds`), `active` (`expiresInMs`, `uploading`), `verifying`, `done` (`result`: round, attestation, contribution hashes), `rejected` / `expired` (`error`). Waiting tickets that stop polling for 3 minutes are dropped |
| `DELETE /api/ticket` | leave the queue at once |
| `GET /api/round/<circuit>` | the latest zkey, only for the ticket whose turn it is (`X-Round`, `X-Sha256` headers) |
| `PUT /api/contribution` | the slot holder uploads one bundle with the new zkey of every circuit (`DZC1`, header JSON with name and attestation, then the zkeys); answers `202` and verifies in the background |
| `GET /files/<path>` | public mirror: `ceremony.json`, `transcript.json`, `closed.json`, `r1cs/<id>.r1cs`, `rounds/NNNN/<id>.zkey` and `entry.json`, `final/...` |

Slot model: one active contributor at a time, FIFO, 25 minutes by default. A turn nobody connects to within 2 minutes is skipped. A failed or malformed upload keeps the slot (a dropped connection does not cost a turn); a verification failure frees it. After losing an upload response, clients poll the same ticket: they wait for an in-flight receive, retrieve an admitted contribution's receipt, and retry only when the slot is active and no receive owns it. A hosting-edge 502/503/504 that lacks the coordinator's JSON error code counts as a lost response. Transient polling failures, including the first poll, share one bounded exponential backoff that rides out about 2.5 minutes offline; a finished ticket's receipt stays retrievable for 15 minutes. Body sizes are bounded by the previous round's size (a contribution adds well under 1 KB per circuit).

### What is verified for every upload

Validate hashes/sizes, exact previous MPC prefix plus one ordinary contribution, name/hash/attestation, then full snarkjs r1cs/ptau verification. Structural parsing bounds section-table scans and MPC allocation by previous history plus permitted growth before curve work. Cancellation invalidates ownership; verifier jobs are independently serialized. Cutoff/closure are rechecked before promotion. Staged data and metadata are synced before the round-directory rename; a derived transcript failure cannot revoke acceptance. Startup repairs the transcript and scavenges orphan staging.

### Transcript

`transcript.json` lists the ceremony configuration and every round: for contributions the name, time, attestation, and per circuit the contribution hash (blake2b-512, as `snarkjs zkey verify` prints it), sha256 and size of the zkey; round 0 also records the r1cs hashes and the circuit hash.

## How to pick the beacon

The final contribution must come from public randomness that nobody could know when the last contributor submitted. Write it into `ceremony.json` **before you announce the ceremony** and commit it, so nobody can pick it afterwards:

```json
"beacon": { "source": "drand", "chain": "52db9ba7…2e971", "round": 36212212, "applyAfter": "2027-02-01T00:00:00Z", "iterationsExp": 20 }
```

* `drand` (default chain: quicknet, one round every 3 seconds since 2023-08-23T15:09:27Z, so `round = (unix_time - 1692803367) / 3 + 1`; the example round is exactly 2027-02-01T00:00:00Z) or `{ "source": "bitcoin", "height": 950000, "applyAfter": "…" }`.
* Pick a time **after you intend to stop accepting contributions**, with a margin: pick it too early and the ceremony cannot close before the beacon exists; choose it after the last contribution so it was unpredictable at that moment.
* Quicknet responses must agree and each BLS signature is authenticated under the pinned quicknet key for the exact round. Its scheduled time must equal `applyAfter`; exponent is checked against the committed effective value. Bitcoin support trusts two HTTPS explorers and confirmations, not a locally validated proof-of-work chain; it is not the production beacon.
* Production pins `contributionsCloseAt = 2026-12-04T00:00:00Z`, quicknet round `34599412`, `applyAfter = 2026-12-07T00:00:00Z`, `iterationsExp = 20`. Admission/download/upload/promotion stop at the cutoff even without operator action. Independently publish the closed checkpoint before December 7: server timestamps alone cannot prove historical closure.

## Finalize

Stop/drain the server at cutoff. Before beacon availability record closure, independently publish `data/closed.json` (config hash, accepted tip and attestation), then wait for the beacon:

```sh
node coordinator/cli.mjs close --data data
# Independently publish closed.json now; wait until the committed beacon time.
node coordinator/cli.mjs finalize --data data
```

Finalization refuses missing/late closure and refuses before `applyAfter`. It authenticates/applies the beacon, verifies results and publishes artifacts. Rerun after a crash: an already committed beacon round repairs missing final artifacts without applying another beacon. Strictly verify before adoption.

## Railway single-instance procedure

1. Build the pinned Node 24 image with exported `r1cs/` files in its context; check config pins. Use **one replica**, one volume at `/data`, `DATA_DIR=/data`, and no overlapping writers. Enable `TRUST_PROXY=1` only after confirming actual Railway XFF semantics and preventing direct-origin header injection.
2. First initialization only: set `INIT_ON_EMPTY=1`, run `serve`, wait for round-zero health, retain config/initial hashes externally, **remove the flag** and redeploy normally. Empty replacement volumes then fail closed; never re-enable init to conceal volume loss. Initialization (ptau download, `zkey new` and full verification of three keys) runs before the server listens and takes many minutes: leave the healthcheck path unset or set `RAILWAY_HEALTHCHECK_TIMEOUT_SEC` above the observed duration. Set `RAILWAY_DEPLOYMENT_DRAINING_SECONDS` above one full verification if a redeploy should let an admitted contribution finish instead of losing it.
3. Reserve at least **4 GiB** container memory; startup checks detected cgroup/host capacity. This is not an OS hard limit. The latest local Windows/Node 26 strict verification of 12 full-size historical keys peaked at **1,955,127,296 bytes RSS** (about 1.82 GiB); repeated malformed inputs were also rejected. These are not isolated Node 24/Railway measurements or proof of a hard upper bound. Before invitations benchmark under the actual image/cgroup and monitor OOM/restarts. Timeout is not a native-memory limit.
4. Retention is about **128 GB per 1,000 rounds** before growth/staging/final copies/backups. Admission reserves 1 GiB plus three current rounds. Alert well before that threshold and budget independent backup storage.
5. Back up the stopped complete data directory (config, ptau, r1cs, rounds/entries, closed marker, final files) independently. Retain the highest accepted checkpoint and participant receipts outside Railway. Rehearse restore into a disposable directory: startup hash checks, full-history verification and external checkpoint/receipt comparisons must pass.
6. At `2026-12-04T00:00:00Z`, stop/drain the service; temporarily set the Railway start command to `docker-entrypoint.sh close` on the **same volume**, before December 7. Railway's start command replaces the image `ENTRYPOINT`, so a bare `close` is not a command and `node coordinator/cli.mjs close` would skip the privilege drop. This is a one-shot command, not a healthy web deployment: unset the healthcheck path (or raise its timeout) and disable restart-on-failure loops while performing it, capture output, independently publish `closed.json`, then clear the start command to restore `serve` for a read-only archive. Never close/finalize concurrently with a writer.
7. After `2026-12-07T00:00:00Z`, use start command `docker-entrypoint.sh finalize` on that volume with the same healthcheck precautions (it applies the beacon and fully verifies three keys), capture outputs, rerun if interrupted, clear the start command to restore `serve`, strictly verify and independently publish the adoption-manifest digest.
8. On volume loss, stop invitations/writes, restore with initialization disabled and reconcile external checkpoints/receipts. Publicly disclose unrecoverable accepted contributions; do not silently replace the ceremony identity.

These are required operator actions, not claims that Railway resource limits, XFF, backup/restore or one-shot commands were exercised here. Atomic renames/fsync cannot protect a lost volume.

## Tests

```sh
cd ceremony && npm ci && node --test
```

Tests cover the tiny cryptographic ceremony through the real CLI path, cancellation/cutoff/streamed limits, disk-failure commit semantics, authenticated historical quicknet fixtures, resumable final publication, strict history/inclusion/artifact checks, cache/retry behavior and the browser worker in Node.

---

# Artifacts to regenerate after finalize

After the ceremony the single-party keys are obsolete. **None of the following has been executed or changed as part of building this ceremony tooling**; this is the checklist for the follow-up change that adopts the ceremony keys. Write the import output to a scratch directory first, compare, then replace.

1. **`protocol/setup/v2/`** and **`protocol/setup/solana-transition-v1/`**: `request.{pk,vk}`, `withdrawal.{pk,vk}`, `transition.{pk,vk}` and both `manifest.json` files, from `ceremony_import`. Update both setup `README.md` files and any doc that says the setup is "single-party".
2. **SDK assets**: `sdk/assets/proofs/*` plus its manifest and the config hash pins, through `scripts/sync-sdk-assets.mjs` (then `npm run verify:assets`).
3. **Solana verifying keys**: `crates/dagon-zkapi-solana/src/verifying_keys.rs` via `npm run generate:solana-vk`, followed by an Anchor rebuild of the program (the program id and deployment are a separate decision).
4. **EVM verifier contracts**: `protocol/contracts` `Groth16ProofAdapter.sol` and `Bn254Poseidon.sol` (emitted by `ceremony_import` into `v2/`), plus the Forge fixtures that embed the verifying keys or proofs.
5. **`zkapi-clientd`**: `deployments/sepolia.json` and `deployments/mainnet.json`, and the `testdata` browser profiles that pin key hashes.
6. **Ledger crate**: it embeds `transition.pk`; rebuild it with the new file.
7. **Docs** that describe the setup as "single-party" or a single-party trusted setup (setup READMEs, the repository README, `docs/` and `docs-site/`): replace with a link to the ceremony transcript, the `FINAL.md` hashes and `verify-ceremony.mjs`.

Keys made by the ceremony carry the new headers (`…/snarkjs\0`) and are proven with the snarkjs-compatible QAP reduction (`CircomReduction`); see [`README-rust.md`](README-rust.md). Anything deployed against the old verifying keys (contracts, programs) must be redeployed or upgraded together with the new proving keys.
