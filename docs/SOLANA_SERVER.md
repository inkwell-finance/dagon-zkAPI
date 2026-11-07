# Dagon zkAPI server: Solana startup and USDC billing

Status: the earlier bounded startup/billing package was reviewed by Daybreak in
`docs/CODEX_PI_REPLY.md` against the former native-SOL design; the USDC
cutover described here has not been re-reviewed. **Not approval for production
deployment or funded use.** Browser/native Solana transport uses exact
decimal-string chain IDs and durable stage journals. Local-validator lifecycle
evidence is recorded in `docs/PORTING_STATUS.md`.

## Configuration

Every shared parameter (protocol version, circuit ids, program id and
executable hash, USDC asset pins, vault policy, server timing) is
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
genesis hash, vault authority, vault state and treasury token account.
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
   the profile, the pinned mint to be the profile's USDC mint, the vault token
   account to be the PDA `["vault-token", vault_state]` and the treasury token
   account to equal the identity's `treasury_token_account`.
6. Reject paused state or a mismatch in either public signing key derived from
   the configured seeds.
7. Use the finalized vault root to construct the processor with its
   `Arc<dyn CreditLedger>`. No tip or initial-root fallback exists, and no
   price source is read: billing needs no oracle.

The program must already be immutable. Do not revoke authority on a deployment
just to satisfy this check without completing Daybreak's deployment review.

## USDC billing and the stable HTTP/proof envelope

The vault holds Circle USDC (`EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v`,
6 decimals, classic SPL Token only; Token-2022 is rejected). One protocol
credit is one USDC base unit, one micro-USDC, and the server bills it as one
micro-USD. The conversion is the identity, so there is no price oracle, quote,
quote expiry or market exposure between admission and settlement:

- Lease spend limit (micro-USD) = the request's proof-bound `solvency_bound`,
  which must be in `1..=2^53 - 1` (browser-safe integers).
- Charge (base units) = metered provider spend in micro-USD, rounded **up** to
  a whole micro-USD, then capped at `solvency_bound`.
- Unsafe bounds are errors, never saturation.

A request's `solvency_bound` must be at least the profile's
`request_charge_cap`, 1,000,000 base units = $1, so the smallest lease is $1.
Startup requires the cap to fit browser-safe units.

The lease authorization payload proven by the request proof is exactly
`{"mode":"openrouter_ephemeral_lease","version":1}`; unknown fields are
rejected. Settlement payloads and receipts carry no price data. Prepared
ledger responses carry the chain ID as an exact **decimal string**, not a
rounded JSON number. The dashboard
summary reports `billing_asset: "usdc"`, `billing_unit: "micro_usdc"` and
`asset: {symbol: "USDC", decimals: 6, mint}`.
Dashboard event `charge_usd` and its running USD total represent the signed
USDC charge divided by 1,000,000, not the unrounded upstream cost. The latter
remains separately available as `usage.cost_usd`; it can differ after rounding
or the proof-bound cap. The billing parity host test invokes the actual SDK
with Node and compares server/SDK lease-limit IEEE-754 bits at rounding
boundaries; run `npm ci` before the Rust workspace test gate.

USDC carries issuer risk the protocol cannot remove: Circle's freeze authority
can freeze any USDC token account, including the vault token account itself,
which would block every deposit, payout and treasury withdrawal until it is
unfrozen. Users also need a little SOL for transaction fees and rent (operation
buffer, nullifier and pending-withdrawal records, and their USDC token account).

## Validation limits

Host tests exercise serialized vault fixtures against a mock finalized RPC,
including pre-database negative cases. They are not evidence of a
local-validator money lifecycle on their own; that is reported separately in
`docs/PORTING_STATUS.md`. Production pins, setup decisions and secrets remain
external release requirements.
