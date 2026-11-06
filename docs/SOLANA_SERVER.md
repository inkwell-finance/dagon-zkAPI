# Dagon zkAPI server: Solana startup and SOL billing

Status: the bounded startup/SOL-billing package is accepted by Daybreak's
security review in `docs/CODEX_PI_REPLY.md`. **Not approval for production
deployment or funded use.** Browser/native Solana transport uses exact
decimal-string chain IDs and durable stage journals. Subsequent fresh SBF and
local-validator lifecycle evidence is recorded in `docs/PORTING_STATUS.md`;
that evidence does not establish compatibility with a selected live Pyth account.

## Configuration

Every shared parameter (protocol version, circuit ids, program id and
executable hash, vault policy, server timing, Pyth receiver/feed/policy) is
compiled in from `solana/profile/shared.json`. There are no flags or
environment variables for them. The operator supplies only the network identity
file, the RPC URL and secrets (see [the Solana profile](solana-profile.md)):

```sh
dagon-zkapi --proof-setup-dir protocol/setup/v2 serverd \
  --solana-identity solana/profile/mainnet-beta.identity.json \
  --solana-rpc-url "$SOLANA_RPC_URL" \
  --listen 0.0.0.0:3000 \
  --indexer-url http://indexer:3001 \
  --db-path /data/server.db \
  --oa-org-url "$OA_ORG_URL"
```

| Option | Environment | Purpose |
| --- | --- | --- |
| `--proof-setup-dir DIR` (global) | `ZKAPI_PROOF_SETUP_DIR` | Groth16 setup artifacts |
| `--solana-identity PATH` | `ZKAPI_SOLANA_IDENTITY` | Network identity file (required) |
| `--solana-rpc-url URL` | `SOLANA_RPC_URL` | Finalized-read RPC (required) |
| `--listen ADDR` | | HTTP listen address |
| `--indexer-url URL` | | Finalized tree indexer |
| `--root-poll-interval-ms N` | | Vault root poll interval |
| `--db-path P` | | SQLite transcript database |
| `--state-seed S` / `--clear-seed S` | `ZKAPI_STATE_SEED` / `ZKAPI_CLEAR_SEED` | Signing seeds |
| `--openrouter-api-base URL` | | OpenRouter API base |
| `--openrouter-management-key K` | `ZKAPI_OPENROUTER_MANAGEMENT_KEY` | Direct lease issuer |
| `--oa-org-url URL` | (`ZKAPI_OA_ORG_SHARED_SECRET`) | OA-org lease issuer |
| | `ZKAPI_TESTNET_PASSWORD` | Optional non-mainnet access gate ([testnet password](testnet-auth.md)) |

Configure exactly one lease issuer. Solana never silently uses the public
development seeds. Treat command-line secrets as visible in process listings;
prefer the environment. `ZKAPI_SOLANA_IDENTITY` and `SOLANA_RPC_URL` are also
read by `dagon-zkapi indexer`, `dagon-zkapi-indexerd` and
`dagon-zkapi-challenged` (whose keypair may come from
`ZKAPI_CHALLENGE_SOLANA_KEYPAIR`).

The identity file holds only the allowed per-network values: network label,
genesis hash, vault authority, vault state, treasury and Pyth price account.
Unknown keys (including any shared parameter) are rejected, and the vault state
must equal the PDA `["vault", authority]` of the compiled-in program id. All
identities are canonical nonzero base58-encoded 32-byte values. The network
label is informational; the authoritative network identity is the genesis hash,
checked against the RPC. The server derives its proof chain ID and deployment
binding from the genesis hash and vault state. A configured indexer URL is
passed to the ledger; startup does not trust an indexer root instead of the
vault.

## Fail-closed startup order

Before SQLite creation, workers, or listener binding:

1. Load the identity file and resolve it against the embedded profile.
2. Check the identity genesis hash against the RPC's genesis hash.
3. Construct `SolanaCreditLedger` using the RPC and resolved identity.
4. Call its finalized immutable-program gate: executable supported loader-v3
   program, canonical program-data account, permanently revoked upgrade
   authority, and an executable hash equal to the profile's
   `program.executable_sha256` (sha256 of the program-data bytes after the
   loader metadata with trailing zeros trimmed, the `solana-verify` convention).
5. Read its finalized vault runtime view, validating owner,
   discriminator/decoding, PDA/bump and deployment binding, and require the
   vault version, request charge cap, note TTL and challenge period to equal
   the profile.
6. Reject paused state or a mismatch in either public signing key derived from
   the configured seeds.
7. Read a fresh finalized Pyth quote from the identity's price account through
   the **same RPC**, with a separate genesis check. No tip, HTTP-price or
   initial-root fallback exists.
8. Use the finalized vault root to construct the processor with separate
   `Arc<dyn CreditLedger>` and `Arc<dyn BillingPriceSource>` objects.

The program must already be immutable. Do not revoke authority on a deployment
just to satisfy this check without completing Daybreak's deployment review.

## Pyth pins and quote validation

The production reader uses official `pyth-solana-receiver-sdk = 1.2.0` with
`anchor-lang = 0.32.1`. It uses the official account type's discriminator,
owner and serialization/deserialization APIs, not a hand-written account layout.
The SDK's broad transitive Solana range is resolved to `solana-program = 2.3.0`
in the committed workspace lock; use locked builds.

Policy (receiver, push oracle, feed, shard, age and confidence come from the
profile; the identity's price account must be the profile's push-oracle account):

- Receiver: `rec5EKMGg6MxZYaMdyBfgwp4d5rB9T1VQH5pJv5LtFJ`, verified against
  the official `PriceUpdateV2::owner()`.
- Feed: SOL/USD
  `0xef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d`.
- Price account: the push-oracle PDA `[push_shard_id (u16 LE), feed_id]`
  (`7UVimffxr9ow1uXYxsr4LHAcV58mLzhmwaeKvJ1pjLiE`, shard 0), declared in the
  identity file and checked against the profile; never supplied by the API caller.
- Maximum age: 30 seconds.
- Maximum confidence: 100 bps (1%).
- Full verification only; partial guardian verification is rejected.
- Non-executable data account, exact official allocated length, canonical official
  serialization with zero trailing allocation padding, and posted slot no later
  than the finalized response context.
- Positive price, nonfuture publication, nonexpired quote, allowed exponent
  `-18..=18`, and bounded confidence. No clamping or floating-point conversion.

The strict zero-padding rule deliberately rejects noncanonical allocation data.
Review this against the actual pinned receiver account before release: an account
with nonzero unused padding fails closed rather than being silently accepted.

### Mainnet freshness

Measured on mainnet-beta in November 2026: the only continuously updated
SOL/USD `PriceUpdateV2` account is the sponsored push-oracle shard 0
(`7UVimffxr9ow1uXYxsr4LHAcV58mLzhmwaeKvJ1pjLiE`). Pyth's sponsor refreshes it
about every 53–55 s, so at finalized commitment its age ranged 2–58 s and was
within the 30 s maximum age in only about half of the samples; every other
fully verified SOL/USD account was days stale. On its own, a server pinned to
it fails closed for roughly half of each cycle. The operator therefore runs
`dagon-zkapi-pyth-pusher`, which keeps the same account fresh at the profile's
`push_interval_seconds` (5 s). The 30 s maximum age is unchanged.

## Operator Pyth pusher

### Who may write the pinned account

The pinned account is a Pyth **push-oracle** price feed account: the PDA
`[shard_id (u16 LE), feed_id]` of `pythWSnswVUd12oZpeFP8e9CVaEqJg25g1Vtc2biRsT`,
owned by the receiver `rec5EKMGg6MxZYaMdyBfgwp4d5rB9T1VQH5pJv5LtFJ`, with the
PDA itself as its write authority. The push oracle's `update_price_feed` is
permissionless: any fee payer may call it, and the program signs for the PDA
when it CPIs into the receiver's `post_update`. The receiver writes only after

- the Wormhole core bridge (`HDwcJBJXjL9FpJ7UBsYBtaDjsBUhuLCUYoz3zr8SWWaQ`)
  has verified the VAA against the current guardian set
  (`VerifyEncodedVaaV1`, full verification, recorded as `Full` in the account);
- the price message's Merkle proof matches the VAA's signed root;
- the message carries the account's feed; and
- the push oracle has checked that the update is newer than the stored one
  (an older or equal update is a successful no-op).

So a third party, such as the operator, can push into the exact account the
server already pins; no operator-owned account, identity change or new trust
is needed. Pyth's sponsor keeps pushing the same account, so a pusher outage
falls back to the sponsored cadence rather than to no updates. A dedicated
shard would be just as permissionless and lose that fallback; an
operator-owned `post_update` account (write authority = operator key) would
make the operator key a single point of failure. Both were rejected. The
profile pins `push_shard_id` 0, and every binary, the SDK build and the
parity check require the identity's `pyth_price_account` to be exactly
`PDA(push_shard_id, feed_id)`, so the server reads the account the pusher
writes.

### Trust

The pusher holds no protocol authority. It cannot write a price the guardians
did not sign, cannot move the account backwards, and cannot change what the
server accepts: the server still reads the finalized account itself and
checks owner, canonical layout, full verification, feed, publish time, age and
confidence (above). A compromised Hermes cannot forge guardian signatures or
Merkle inclusion. It can withhold updates and induce failed paid write attempts;
the payment protections below bound that exposure. A compromised pusher process
can spend its own dedicated hot key, but its container mounts no server seeds,
vault authority, or other payer. Pyth's sponsor remains independent.

### What one push does

Every `push_interval_seconds` (5 s) the pusher reads the price account
(confirmed and finalized), fetches `GET /v2/updates/price/latest?ids[]=<feed>
&encoding=base64` from Hermes with `Authorization: Bearer <key>`, decodes the
PNAU accumulator update, and skips the push if the update is not newer than the
confirmed on-chain one. Otherwise it sends two legacy transactions, each
signed only by the payer:

1. `create_account_with_seed` (address `create_with_seed(payer,
   "dagon-pyth-vaa", wormhole)`, so no second signer), `init_encoded_vaa`,
   `write_encoded_vaa` (the whole VAA when it fits; larger VAAs get extra
   write packets);
2. `verify_encoded_vaa_v1`, the push oracle's `update_price_feed` (random
   receiver treasury id, as Pyth's SDK does), `close_encoded_vaa` (refunds the
   encoded VAA's rent).

Instruction bytes equal those of mainnet's own push transactions (a unit test
compares them byte for byte against a recorded one). An encoded VAA left by an
interrupted push is closed at the start of the next cycle
(`leftover_vaas_closed_total`).

Retries and backoff: every RPC and Hermes call is retried up to 4 times with
exponential backoff and jitter on transport errors, HTTP 429 and 5xx; a 401/403
from Hermes is not retried. Transactions are rebroadcast every 2 s until
confirmed or until the push deadline (3 intervals) passes. After failed cycles
the next cycle waits 5, 10, then at most 15 s (half the maximum age), jittered.

Payment safety: every packet (including orphan cleanup) is simulated before
broadcast. Its quoted total fee must be at most **50,000 lamports**, its net
simulated debit across payer plus encoded-VAA account must be at most that
amount, and its resulting payer balance must preserve `--min-balance-lamports`
(default **2 SOL**). Counting both accounts prevents rent recycling from hiding
receiver fees. The fixed CU price never follows a network fee spike upward.
Future or expired Hermes updates are not posted; response size is bounded
to 128 KiB and VAAs to 4 KiB.

Three failed cycles that paid for a transaction (one with a recorded on-chain
status, including a late landing after the cycle timed out) latch further
payments off (`payments_paused = 1`) until an operator investigates and
restarts the process. Before broadcasting, the pusher retains the signed
transaction's signature and blockhash, even if the RPC response is lost.
An unresolved transaction blocks all subsequent payments until its status is
confirmed/finalized, or the finalized block height has passed its blockhash's
`lastValidBlockHeight` and a subsequent historical status lookup still finds no transaction. A late
status counts toward the original failed cycle exactly once. Rejected or
expired unseen sends do not count, so congestion without paid failures cannot
latch payments off by itself. This also prevents a new payment's reserve
simulation from overlooking an outstanding transaction's debit.
Unpaid skips cannot clear this latch. Account observations continue so sponsor
updates still count toward health. A single reusable encoded-VAA account bounds
orphan rent; its next cleanup is simulated like every other payment. Inspect
and restart to reclaim it after a latched failure. Do not run multiple pushers
with the same payer, auto-restart a live paused process, or auto-refill it.
The reserve is checked against the chain balance; the failure latch and pending
signature are process-local. After stopping a process with an unresolved
transaction, wait for its confirmation or blockhash expiry before restarting.
RPC and the pinned on-chain programs remain
trusted: simulation is not an on-chain spending covenant, and a stolen hot key
can spend its entire balance outside this binary.
An attacker-prefunded empty system account at the predictable seed address is
recovered with the payer's seeded-transfer authority, rather than repeatedly
trying Wormhole close on an account Wormhole does not own.

Regression gate (built WSL-native checkout):
`ZKAPI_STATE_SEED=0x1 ZKAPI_CLEAR_SEED=0x2 node scripts/localnet/pusher-security.mjs /tmp/pusher-security-unique`.
It runs cloned real programs, rejects a corrupted guardian signature and a
mutated message under a valid signed root, checks the payment latch and reserve,
recovers prefunded/orphan accounts, and stops its validator.

The Hermes key stays in the environment and a Bearer header, never argv or
logs. Redirects are disabled (including HTTPS-to-HTTP redirects), URLs cannot
contain embedded credentials/query strings/fragments, and transport errors
omit URLs. Protect the environment file with mode 0600; Docker administrators
and same-privilege process inspection can still read environment secrets.

Freshness budget: measure actual finalization rather than assuming the legacy
32-slot (~13 s) delay. A read-only mainnet sample on 2026-11-06 saw finalized
block timestamps 0.9–1.9 s behind wall time, with no measurable
confirmed→finalized slot gap. This short sample is not a latency guarantee.

### Configuration

| Input | Source |
| --- | --- |
| Feed, shard, programs, cadence, maximum age | compiled-in profile |
| `--solana-identity` | identity file; its `pyth_price_account` must be the push-oracle account |
| `--solana-rpc-url` | RPC with `sendTransaction` and confirmed/finalized reads; its genesis must match the identity |
| `--payer-keypair` | Solana CLI keypair of the dedicated, funded fee payer (secret) |
| `PYTH_HERMES_API_KEY` | Hermes API key from Pyth Terminal; environment only (secret) |
| `--hermes-url` | default `https://hermes.pyth.network`; HTTPS required except on loopback |
| `--priority-fee-micro-lamports` | default 10,000 µlamports/CU |
| `--min-balance-lamports` | default 2 SOL; protected reserve checked before every payment, not merely an alarm |
| `--listen` | default `0.0.0.0:3002`: `/health`, `/metrics` |

The operator image ships the binary; `docker/aws/compose.yml` runs it as the
`pyth-pusher` service (`dagon-zkapi-run pyth-pusher`). The server does **not**
depend on its health; the server's own finalized-price checks fail closed when
needed, without blocking sponsor-backed startup. See `docker/aws/README.md`.

### Cost

Measured on the local parity stack against the cloned mainnet programs with a
3-signature mainnet VAA: the first packet uses 3,019 CU, the second
132,085–135,094 CU; the payer's balance fell by exactly the transaction fees
(the receiver's update fee is 0). With the shipped compute limits (20,000 and
120,000 + 30,000 per signature = 210,000) and the default 10,000 µlamports/CU:

| Per push | Lamports |
| --- | --- |
| 2 signatures × 5,000 | 10,000 |
| priority fee (230,000 CU × 0.01) | 2,300 |
| encoded-VAA rent (refunded in the same push) | 0 net |
| **total** | **12,300** |

Pyth publishes a newer SOL/USD price far more often than every 5 s, so nearly
every cycle pushes: 17,280 pushes a day, **about 0.21 SOL a day** (0.17 SOL
of it base fees), about $19 a day or $7,000 a year at $90/SOL. Raising the
priority fee to 50,000 µlamports/CU makes it 0.37 SOL a day. Fund the payer
for several weeks (for example 10 SOL provides 8 SOL spendable above the default
2 SOL reserve, about 37.6 days at 0.212544 SOL/day). Alert before reaching the
reserve. Hermes sees one request per cycle (17,280 a day); choose a Pyth plan
that covers it.

The cheapest cadence within the current profile's safety constraint
(`interval <= max_age / 3`) is **10 s**, recommended for the next profile build:
**0.106272 SOL/day**, half the 5 s cost. Observed native cold quote→lease time
was 3.660 s (warm 1.225 s). Budgeting 2 s for observed finalization, 2 s for
fetch/post, 10 s for scheduling and 3.660 s for proof/admission leaves about
12.3 s under the 30 s age. The shipped profile remains 5 s in this review.
Before rollout, confirm production Hermes, RPC and browser/cold-proof tails:
no real Hermes API key was available for this replay-based review. If the
legacy 13 s finalization delay returns, retain 5 s instead. Never relax the
30 s maximum age to mask a slow pusher.

### Metrics and alerting

`/health` returns 200 while the finalized price account is within the maximum
age and was observed within the last 3 intervals, else 503 (the compose
healthcheck). `/metrics` (Prometheus text) exposes, with prefix
`dagon_pyth_pusher_`: `onchain_age_seconds{commitment}` and
`onchain_publish_time_seconds{commitment}` (finalized is what the server reads),
`hermes_publish_time_seconds`, `pushes_total{result="landed"|"not_newer"}`,
`failures_total{stage="hermes_auth"|"hermes"|"rpc"|"transaction"}`,
`consecutive_failures`, `last_success_timestamp_seconds`,
`last_push_duration_seconds`, `leftover_vaas_closed_total`,
`lamports_spent_total` (observed payer-plus-rent equity decreases, including
failed cycles), `payer_balance_lamports`, `payer_balance_low`,
`payments_paused`, `push_interval_seconds` and `max_age_seconds`.

Alert on:

| Condition | Severity | Meaning |
| --- | --- | --- |
| `onchain_age_seconds{commitment="finalized"} > 25` for 1 min, or `/health` failing | page | quotes are about to fail closed |
| `consecutive_failures >= 6` (30 s) | page | pushes are not landing |
| `increase(failures_total{stage="hermes_auth"}[5m]) > 0` | page | the Hermes key is revoked, expired or over quota |
| `payments_paused == 1` or `payer_balance_low == 1` | page | investigate failures or refill above the protected reserve before restarting |
| `rate(pushes_total{result="landed"}[10m]) < 0.15` | warn | below the expected 0.2 pushes/s |
| `increase(leftover_vaas_closed_total[1h]) > 3` | warn | second packets are being dropped; raise the priority fee or change RPC |
| `rate(lamports_spent_total[1d])` | track | daily cost |

### Operator setup

1. Get a Hermes API key at Pyth Terminal; put it in
   `/etc/zkapi/pyth-pusher.env` as `PYTH_HERMES_API_KEY` (mode 0600).
2. Create a dedicated payer: `solana-keygen new --no-bip39-passphrase -o
   /etc/zkapi/pyth-pusher-keypair.json`, readable only by uid 10001. Fund it
   (for example 10 SOL).
3. Use an RPC that accepts `sendTransaction` (a paid endpoint for mainnet).
4. `docker compose -f docker/aws/compose.yml up -d pyth-pusher`, wait for it
   to turn healthy, then start the indexer and server.
5. Scrape `pyth-pusher:3002/metrics` and add the alerts above.

The local parity stack runs this binary as the only writer of the cloned
account, fed a recorded Hermes that serves real mainnet-signed updates (see
[the Solana profile](solana-profile.md#local-parity-stack)).

## Pricing and the stable HTTP/proof envelope

`GET /v2/billing/quote` remains unchanged as a route. The returned top-level
object is included under `billing_quote` in the exact payload authorized by the
existing request proof. The SOL variant identifies `native_sol`, source,
lamports, base units per SOL, ledger backend/network/vault, deployment binding,
price account/receiver/feed, raw integer price/confidence/exponent and timestamps.
Its chain ID is an exact **decimal string**, not a rounded JSON number.

One credit is one lamport, and one SOL is exactly 1,000,000,000 credits. Arithmetic
uses the conservative price `price - confidence`:

- Lamports -> provider micro-USD budget: **floor**.
- Settled provider micro-USD -> lamport charge: **ceil**.
- Unsafe bounds and checked-arithmetic overflow are errors, never saturation.

A request's proof bound (`solvency_bound`) must be at least the profile's
`request_charge_cap`, 11,000,000 lamports, so the smallest lease is the cap
converted at the quote's conservative price: about $1 at $90/SOL. The cap is
fixed in lamports and pinned in the vault at initialization, so the smallest
lease in USD moves with SOL (about $0.55 at $50/SOL, $2.20 at $200/SOL).

### Quote observation cache

The finalized SOL/USD price account can be updated while a client is
generating a request proof, so "only the latest update" would reject honest
requests. The oracle therefore remembers every quote
it has itself read from the finalized price account, in a bounded cache whose
entries expire at the quote's `expires_at`. Before first reservation the server
accepts a submitted quote only if it is still fresh **and** exactly matches a
cached observation; it rechecks freshness after I/O and again at synchronous
proof validation/reservation. Unobserved, expired or mismatched quotes cannot
issue access. A byte-identical already reserved request keeps its original
accepted quote. Settlement never refreshes/substitutes that quote. No
fixed/development-price implementation is included.

## Validation limits

Host tests exercise official serialized vault/Pyth fixtures against a mock
finalized RPC, including pre-database negative cases. They are not evidence of a
live Pyth deployment or a local-validator money lifecycle on their own. Daybreak
subsequently reports a fresh SBF build and local-validator lifecycle in
`docs/PORTING_STATUS.md`, separately from these startup tests. The former
Windows checkpoint replacement failures are fixed; the server library passed
94/94 at the package-review checkpoint. Production pins, setup decisions,
secrets and live Pyth compatibility remain external release requirements.
