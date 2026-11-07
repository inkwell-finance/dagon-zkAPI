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
- Maximum age: 90 seconds (the ceiling; see [Pyth sponsored feed](#pyth-sponsored-feed)).
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

## Pyth sponsored feed

### Source

The pinned account is the push-oracle price account of the SOL/USD feed on
shard 0, `7UVimffxr9ow1uXYxsr4LHAcV58mLzhmwaeKvJ1pjLiE` (the PDA
`[push_shard_id (u16 LE), feed_id]` of
`pythWSnswVUd12oZpeFP8e9CVaEqJg25g1Vtc2biRsT`, owned by the receiver). Pyth
sponsors this feed on Solana for free: it posts a new guardian-verified update
at least once a minute (heartbeat) and whenever the price moves by 0.5%
([Pyth sponsored feeds](https://docs.pyth.network/pro/sponsored-feeds)). Dagon
runs no price pusher and holds no Hermes key or price-posting payer; the server
only reads the account.

Every write goes through the push oracle's `update_price_feed`, which the
receiver applies only after the Wormhole core bridge
(`HDwcJBJXjL9FpJ7UBsYBtaDjsBUhuLCUYoz3zr8SWWaQ`) has verified the VAA against
the current guardian set (`VerifyEncodedVaaV1`, recorded as `Full`), the
message's Merkle proof matches the signed root, the message carries the
account's feed, and the update is newer than the stored one. The server trusts
no writer: it reads the finalized account itself and checks owner, canonical
layout, full verification, feed, publish time, age and confidence (above).

Measured on mainnet-beta on 2026-11-06 (finalized commitment). Earlier that
day the account was pushed about every 53–55 s and its age ranged 2–58 s; the
payer then was `4p16wya1Vw2u9w22oah4yXQgySb6eWKRRLMsEXCreish`, which pushes
many other feeds and is most likely the sponsor. In a later 15-minute window a third party
(`U91Qk9dq4MavGViv6pqWteUc8JaPcLXGAARQyQJvg8B`) pushed it every 10–30 s:
414 samples, all fully verified, age 2.3–30.9 s (median 8.4 s), and each new
update was readable at finalized commitment 2.3–5.4 s after its publish time.
The sponsor then had nothing to push, as its heartbeat never came due. Such
third-party pushes come and go and are not relied on: the bound below assumes
only the sponsor. Every other fully verified SOL/USD account was days stale.

### Maximum age: 90 s

`pyth.max_age_seconds` is 90, and 90 is also the ceiling the profile parser,
the server's quote validation and the SDK enforce
(`dagon_zkapi_profile::PYTH_MAX_AGE_CEILING_SECONDS`, mirrored by the SDK's
`PYTH_MAX_AGE_CEILING_SECONDS`; the single-profile parity rule is unchanged):

- **Why not less.** A healthy sponsor leaves the finalized account up to one
  heartbeat (60 s) plus the time to land and finalize the next update old. Any
  limit below that refuses quotes for part of every heartbeat although nothing
  is wrong: at the former 30 s, about half the time.
- **Why 90.** 60 s heartbeat plus 30 s for landing, finalization (legacy
  finality alone is about 13 s; measured publish→finalized 2–5 s) and RPC lag.
- **Why not more.** 90 s is an availability allowance, not a bound on price
  movement: a price can become economically stale before it expires. Older
  prices are refused to limit that exposure in time. Raising the ceiling is a
  source change to the profile crate and SDK requiring a new risk assessment.
  Pyth explicitly warns that sponsored updates can be delayed; neither the
  heartbeat nor the 0.5% trigger guarantees landing or finalization latency.

### Timing budget

| Window | Value | Relation to the 90 s maximum age |
| --- | --- | --- |
| Quote life | `expires_at = publish_time + 90` | a quote is usable from its read until then |
| Age at quote read, healthy sponsor | nominally 60 s heartbeat + publication/landing/finalization/RPC delay | 15–25 s remaining is an estimate under 15–5 s delay, not a minimum; a successful quote may be arbitrarily close to expiry |
| Client proof and submission | quote → lease 1.2 s warm, 3.7 s cold (previous native parity-stack measurements) | illustrative only; browser proof times are not measured here |
| Admission | every new request reads `getGenesisHash` then finalized `getAccountInfo`, each with a 15 s timeout; expiry and supersession recheck after I/O, Groth16 verification, recheck at reservation | unexpired, previously observed quotes remain usable only within the 1% conservative-price tolerance; otherwise retriable `409` and nothing is reserved |
| Request time | `request_time` within 300 s back, 30 s ahead | longer than 90 s; not binding |
| Lease TTL, settlement grace | 300 s and 5 s from issuance; settlement uses the accepted quote without a freshness check | independent of the price age |
| Challenge timing (`check_challenge_timing`) | TTL 300 + 2 × grace 5 + 2 × poll 2 + usage read 600 + raise lead 3,600 + margin 1,800 = 6,314 s ≤ 86,400 s | the price age is not a term; unchanged |
| Startup | one fresh finalized quote, checked again after RPC | fails if no valid unexpired quote is available, even with a healthy sponsor but slow RPC |

The 90 s policy accommodates the nominal sponsored cadence; it does not
guarantee every proof or RPC completes before expiry. The two sequential RPC
calls can consume nearly 30 s, apart from scheduling. The quote endpoint and
startup recheck expiry and supersession after I/O; admission rechecks after I/O
and proof verification. A device that misses expiry gets `409 native_quote_expired`
without a new reservation; the SDK confirms nonacceptance before releasing
the request. Browser proof latency and production RPC/finality tails must be
measured separately. The published mainnet samples above are observations,
not a worst-case bound.

### Pricing exposure

An older server-observed quote remains usable until `publish_time + 90` only
if it passes the shared profile's `pyth.max_supersession_bps = 100` policy.
For quoted conservative price `Q = price - confidence` and the newest observed
conservative price `Qnew`, reject when `Qnew < 0.99 * Q`. Exactly 1% lower,
unchanged and higher newer prices remain acceptable. The comparison uses exact
integer arithmetic, including differing price exponents. The tolerance comes
only from `solana/profile/shared.json`, with the same profile/parity rules as
the age limit; it is not a runtime override.

Every new admission performs a fresh finalized RPC read, even for a previously
observed quote. A failed read has no cached fallback. The quote endpoint,
startup and the final reservation check also enforce the newest-observed
policy. A lower observation arriving during proof verification therefore
causes `409 native_quote_superseded` before reservation; the SDK uses the
existing nonacceptance recovery flow before preparing another proof. Exact
retries of already reserved requests and settlement retain their frozen quote.

This bounds **selection/gaming disparity against the newest observed price**:
`Q/Qnew <= 1/0.99`, approximately 1.010101. At billed usage `U`, the value
shortfall measured at `Qnew` is at most `0.01 * U`, inside a 5% markup's
`U - U/1.05` margin before other costs. Both sides subtract actual confidence;
the 100 bps confidence limit is an uncertainty ceiling, not an additional
guaranteed 1% buffer. The sponsor's 0.5% trigger is an update policy, not a
market-movement bound.

After acceptance the price stays frozen through the 300 s lease TTL. That
inherent SOL market risk is borne by the operator: for later realizable price
`S`, billed-value shortfall is `U * max(0, 1 - S/Q)`, ignoring protective
integer rounding. `U` is bounded by `ZKAPI_MAX_LEASE_USD` (default $10, configurable)
per lease, not across all leases. Relative to the admission market price, the
additional TTL exposure scales with that budget times the adverse SOL move;
there is no guaranteed bound on the move itself. A sponsor stall is covered
only by the 90 s age limit; RPC failure refuses admission, but an RPC returning
a valid aged account can still lag the market. Neither the tolerance nor the
fee insures against these unobserved or post-acceptance moves.

### When the sponsor stalls: fail closed

From the moment the finalized price is 90 s old (`now >= publish_time + 90`):

- `GET /v2/billing/quote` answers `409 native_quote_expired`;
- a new lease request answers `409 native_quote_expired` before any nullifier
  is reserved or key minted, whether its quote was observed earlier or not;
- server startup fails (the compose restart policy retries it);
- there is no fallback: no other account, no Hermes read, no cached or
  extrapolated price.

Everything that needs no new price keeps working: `/health`, the tree,
deposits, withdrawal clearances and closes, settlement and retirement of
already issued leases (each with the quote it was accepted with), exact retries
of requests reserved before the stall, and the challenger. Quoting resumes by
itself with the sponsor's next update; no restart is needed.

The parity stack exercises this: the lifecycle gate's `localnet_pyth` test
stalls the replayed feed until the price is older than 90 s and requires the
server's quote, lease admission and startup to refuse it, then resumes, and the
gateway's `zkapi-full` e2e requires `409 native_quote_expired` from the running
server between its two leases.

### Monitoring and alerting

No paid service is needed. Probe the server's own quote endpoint, which reads
the pinned account through the server's RPC exactly as clients see it, from the
host every 15 s (cron or a systemd timer), through the gateway published on
`127.0.0.1:8080` by `docker/aws/compose.yml`:

```sh
# Prints the price age in seconds. Exits non-zero, naming the server's
# error_code (native_quote_expired for a stale price), when it refuses to quote;
# a connection failure leaves jq no input and also exits non-zero.
curl -sS --max-time 10 http://127.0.0.1:8080/v2/billing/quote \
  | jq -e 'if .publish_time then (now | floor) - .publish_time else error(.error_code // "no quote") end'
```

| Condition | Severity | Meaning |
| --- | --- | --- |
| the probe reports `native_quote_expired`, or the age exceeds 90 s | page | the sponsor has stalled: the server refuses every new quote and lease |
| the probe fails otherwise (connection, 5xx, another `error_code`) | page | server, gateway or RPC unavailable, not a price problem |
| the age exceeds 70 s on two consecutive probes | warn | the sponsor missed its 60 s heartbeat; quoting stops at 90 s |

To check the account independently of the server, read it from any RPC
(`getAccountInfo`, `encoding: base64`, `commitment: finalized`): the
134-byte `PriceUpdateV2` data has the verification level at byte 40 (1 =
`Full`) and `publish_time` as a little-endian `i64` at byte offset 93; its age
is now minus that value.

The local parity stack replays the sponsor's real mainnet updates instead of
running a writer of its own (see
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
