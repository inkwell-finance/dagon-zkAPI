# Dagon zkAPI server: Solana startup and SOL billing

Status: the bounded startup/SOL-billing package is accepted by Daybreak's
security review in `docs/CODEX_PI_REPLY.md`. **Not approval for production
deployment or funded use.** Browser/native Solana transport uses exact
decimal-string chain IDs and durable stage journals. Subsequent fresh SBF and
local-validator lifecycle evidence is recorded in `docs/PORTING_STATUS.md`;
that evidence does not establish compatibility with a selected live Pyth account.

## Selecting the backend

The server defaults to `--ledger solana`. There is no automatic ETH fallback.
Complete Solana startup requires:

```sh
dagon-zkapi --request-charge-cap 50000 serverd \
  --ledger solana \
  --solana-rpc-url "$SOLANA_RPC_URL" \
  --solana-program-id "$PROGRAM_ID" \
  --solana-vault-state "$VAULT_PDA" \
  --solana-genesis-hash "$GENESIS_HASH" \
  --solana-network mainnet-beta \
  --pyth-price-account "$SOL_USD_PRICE_ACCOUNT" \
  --state-seed "$STATE_SEED" \
  --clear-seed "$CLEAR_SEED" \
  --oa-org-url "$OA_ORG_URL"
```

OA org provisioning also requires `ZKAPI_OA_ORG_SHARED_SECRET`. Alternatively,
configure direct OpenRouter provisioning through
`ZKAPI_OPENROUTER_MANAGEMENT_KEY` (or the existing management-key flag); do not
configure both providers. Seeds may come from `ZKAPI_STATE_SEED` and
`ZKAPI_CLEAR_SEED`, but Solana does not silently use the public development seeds.
Treat command-line secrets as visible in process listings; prefer the existing
operator secret/environment workflow.

All Solana identities are canonical nonzero base58-encoded 32-byte values.
`--solana-network` is a human-readable label only. The authoritative network
identity is the pinned genesis hash, checked against the RPC. The server derives
its proof chain ID and deployment binding from the existing shared helpers.

Solana rejects independently supplied `--chain-id`, `--contract-address`, or
`--initial-root`, even when `--initial-root 0x0` is explicitly supplied. It also
rejects ETH oracle options. A configured indexer URL is passed consistently to
the selected ledger; startup does not trust an indexer root instead of the vault.

For EVM compatibility, select `--ledger evm` explicitly and provide the legacy
contract address plus Chainlink oracle RPC/feed flags. Existing ETH quote JSON,
gwei accounting, lease recovery and settlement semantics remain unchanged.

## Fail-closed startup order

Before SQLite creation, workers, or listener binding:

1. Validate backend configuration and reject mixed/incomplete options.
2. Construct `SolanaCreditLedger` using the pinned RPC/deployment.
3. Call its finalized immutable-program gate: executable supported loader-v3
   program, canonical program-data account, permanently revoked upgrade authority.
4. Read its finalized vault runtime view, validating genesis, owner,
   discriminator/decoding, PDA/bump, version and deployment binding.
5. Reject paused state or a mismatch in the request-charge cap or either public
   signing key derived from the configured seeds.
6. Read a fresh finalized Pyth quote through the **same RPC**, with a separate
   genesis check. No cached, tip, HTTP-price, EVM, or initial-root fallback exists.
7. Use the finalized vault root to construct the processor with separate
   `Arc<dyn CreditLedger>` and `Arc<dyn BillingPriceSource>` objects.

The program must already be immutable. Do not revoke authority on a deployment
just to satisfy this check without completing Daybreak's deployment review.

## Pyth pins and quote validation

The production reader uses official `pyth-solana-receiver-sdk = 1.2.0` with
`anchor-lang = 0.32.1`. It uses the official account type's discriminator,
owner and serialization/deserialization APIs, not a hand-written account layout.
The SDK's broad transitive Solana range is resolved to `solana-program = 2.3.0`
in the committed workspace lock; use locked builds.

Defaults/policy:

- Receiver: `rec5EKMGg6MxZYaMdyBfgwp4d5rB9T1VQH5pJv5LtFJ`, verified against
  the official `PriceUpdateV2::owner()`.
- Feed: SOL/USD
  `0xef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d`.
- Price account: explicitly configured, never supplied by the API caller.
- `--pyth-max-age-seconds`: default 30, allowed `1..=60`.
- `--pyth-max-confidence-bps`: default 100, allowed `1..=100` (at most 1%).
- Full verification only; partial guardian verification is rejected.
- Non-executable data account, exact official allocated length, canonical official
  serialization with zero trailing allocation padding, and posted slot no later
  than the finalized response context.
- Positive price, nonfuture publication, nonexpired quote, allowed exponent
  `-18..=18`, and bounded confidence. No clamping or floating-point conversion.

The strict zero-padding rule deliberately rejects noncanonical allocation data.
Review this against the actual pinned receiver account before release: an account
with nonzero unused padding fails closed rather than being silently accepted.

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

Before first reservation, the server compares a submitted quote with the pinned
finalized account and rechecks freshness after I/O and again at synchronous
proof validation/reservation. A superseded or expired unaccepted quote cannot
issue access. A byte-identical already reserved request keeps its original
accepted quote. Settlement never refreshes/substitutes that quote.

Existing ETH quote objects round-trip without a new wrapper, source tag, or field
renaming. ETH quotes cannot use the Pyth adapter and SOL quotes cannot use the
ETH adapter. No fixed/development-price implementation is included.

## Validation limits

Host tests exercise official serialized vault/Pyth fixtures against a mock
finalized RPC, including pre-database negative cases. They are not evidence of a
live Pyth deployment or a local-validator money lifecycle on their own. Daybreak
subsequently reports a fresh SBF build and local-validator lifecycle in
`docs/PORTING_STATUS.md`, separately from these startup tests. The former
Windows checkpoint replacement failures are fixed; the server library passed
94/94 at the package-review checkpoint. Production pins, setup decisions,
secrets and live Pyth compatibility remain external release requirements.
