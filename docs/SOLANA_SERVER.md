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
| | `ZKAPI_RELAYER_KEY` | Optional [CCTP relay](#cctp-relay) key: keypair JSON file path or base58 64-byte keypair. Unset = relay off |
| | `ZKAPI_RELAYER_FEE_ACCOUNT` | Relay: USDC token account receiving relay fees (required with the key) |
| | `ZKAPI_RELAYER_SOL_USD` | Relay: SOL price in USD, decimal with ≤ 6 places (required with the key) |
| | `ZKAPI_RELAYER_MARGIN_BPS` | Relay: fee margin in basis points, 0–10000 (default 2000) |
| | `ZKAPI_RELAYER_MIN_SOL` | Relay: SOL floor below which it refuses work (default 0.05) |
| | `ZKAPI_RELAYER_RECEIVE_MIN_USDC` | Subsidized receive minimum source burn, decimal USDC (default 1) |
| | `ZKAPI_RELAYER_RECEIVE_DAILY_SOL` | Durable UTC-day SOL subsidy allowance (default 0.05; 0 disables subsidized receives) |
| | `ZKAPI_RELAYER_RECEIVE_PER_ADDRESS_DAILY` | Durable UTC-day preparation limit per source-chain sender and per ek (default 6) |
| | `ZKAPI_RELAYER_BURN_MIN_USDC` | Minimum net relayed CCTP exit after relay fee, decimal USDC (default 5) |
| | `ZKAPI_RELAYER_BURN_FLOAT_SOL` | Durable outstanding MessageSent rent backstop (default 0.5 SOL) |
| | `ZKAPI_RELAYER_LOSS_DAILY_SOL` | Durable daily lost network fees plus all outstanding reservations of credentialed and relay-only work (default 0.02 SOL) |
| | `ZKAPI_RELAYER_UNBACKED_LOSS_DAILY_SOL` | Separate durable daily loss budget of ek-co-signed work without a sponsorship credential (default 0.002 SOL) |
| | `ZKAPI_CCTP_IRIS_URL` | Relay: Circle Iris base URL (default `https://iris-api.circle.com`; plain `http` only to loopback) |

Configure exactly one lease issuer. Solana never silently uses the public
development seeds. Treat command-line secrets as visible in process listings;
prefer the environment. `ZKAPI_SOLANA_IDENTITY` and `SOLANA_RPC_URL` are also
read by `dagon-zkapi indexer`, `dagon-zkapi-indexerd` and
`dagon-zkapi-challenged` (whose keypair may come from
`ZKAPI_CHALLENGE_SOLANA_KEYPAIR`). The relay variables have no flags, so the
key never appears in process arguments; any `ZKAPI_RELAYER_*` or
`ZKAPI_CCTP_IRIS_URL` without `ZKAPI_RELAYER_KEY` is a startup error.

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

## CCTP relay

The optional relay (`/v2/relay/*`) lets a note's per-note emergency key (ek)
deposit CCTP-delivered USDC and burn exits back out without holding SOL. It is
off unless `ZKAPI_RELAYER_KEY` is set; then every route answers
`404 {"error":{"code":"relay_disabled",...}}` and nothing else changes. The
vault program is unchanged: ek owns each deposit buffer and is its depositor;
the relay atomically advances rent and receives the buffer rent back. For
close/escape the relay remains the vault owner paying nullifier/pending rent.

**Key and startup.** The relay key must be a dedicated low-balance wallet. After
the normal fail-closed startup, the relay refuses a key equal to the vault
authority, vault state, treasury token account or its owner, the program id or
`ZKAPI_CHALLENGE_SOLANA_KEYPAIR`'s key (the state and clearance keys are
Baby-JubJub, not ed25519), and a fee account that is the relayer or its own
USDC account or is not an unfrozen classic USDC account. Rent is read from the
cluster. Quotes above the SDK fee caps are logged. At startup the relay
creates (or reuses) its address lookup table holding every request-independent
exit and CCTP receive account. The relay keeps its state in the server
database (`relay_*` tables): in-flight relayer transactions, risk
reservations, sponsorship credentials, `MessageSent` accounts and the
lookup-table address. It keeps no debts or staged deposits. Submit tickets
are sealed with a key derived from the relay key: rotating the key invalidates
outstanding preparations (clients simply prepare again).
In production `ZKAPI_RELAYER_FEE_ACCOUNT` is the Zoneless relayer's USDC
account, which also keeps this key topped up with SOL.

**Fees.** `fee = ceil(cost_lamports × sol_usd_micros / 1e9 × (10000 +
margin_bps) / 10000)` USDC base units, with rent from the cluster and 5,000
lamports per signature (relay transactions set no compute-unit price). Every
charged fee is a `TransferChecked(ATA(ek) → fee account)` signed by the ek
**inside the same transaction** as the relayer's spend, so both land or
neither does; there is no debt and no later collection.

| Kind | Cost | Paid from |
| --- | --- | --- |
| deposit | NoteState rent + 2 signatures (buffer rent advanced/refunded atomically) | `ATA(ek)`, same transaction |
| receive | not charged (see below); relayer spend `used_nonce` rent + 1 signature | — |
| close | UsedNullifier rent + ATA rent if `ATA(ek)` is absent + 2 signatures | the close payout, same transaction |
| escape | 2 × UsedNullifier rent + 2 signatures + the relayer's finalize signature | prepaid `ATA(ek)` balance, same transaction |
| burn | 3 burn signatures + 1 reclaim signature; relay floats event rent for 5 days | `ATA(ek)`, same transaction |
| sweep | 2 signatures | `ATA(ek)`, same transaction |

At Solana rent (6,960 lamports per (128 + bytes)) and a 20% margin the
worst-case quotes are, at $88.89: deposit 177,761, close 368,560 with ATA
creation, escape 301,534; at $150: deposit 299,967, close 621,936, escape
508,832 base units. Burn/sweep caps are **0.05 USDC each**, independently
enforced by server and wallet. At 20% margin, burn quotes are **0.003600 USDC
at SOL $150**, **0.004320 at $180**, independent of hook length. Sweeps cost
**0.001800/0.002160 USDC** at those prices. MessageSent rent is not a user fee.
The server independently enforces these hard caps even if a caller supplies a
larger `max_fee`. The SOL price is an operator-maintained configuration, not
an oracle: refresh it as market conditions change. A stale low price can make
the relay run at a loss; a stale high price cannot exceed the wallet/server caps.

**Routes** (JSON; amounts are decimal strings of USDC base units, keys base58,
bytes hex with optional `0x`). Prepared ek-co-signed transactions (deposit,
burn, sweep, close, escape) are full wire bytes with **every signature slot
zeroed** plus an opaque `submit_token`; the relay reserves nothing for them.
The client checks the transaction, signs it with the ek and posts it to
`/v2/relay/submit`, which signs for the relay (and a burn's event account,
whose key only the relay can derive), reserves risk, broadcasts and returns
the complete transaction for the client to verify and confirm. The fallback
receive is complete when prepared (relayer-only) and the client broadcasts it.
Legacy transactions have `format: "solana-legacy-transaction-v1"`; v0
transactions have `format: "solana-v0-transaction-v1"` and `lookup_tables:
[{address, addresses}]` (the relayer-owned table; clients verify its on-chain
contents).

| Route | Body → response |
| --- | --- |
| `GET /v2/relay` | → `{relayer, fee_account, margin_bps, sol_usd_micros, usdc_mint, quotes:{deposit,receive,close,escape,burn,sweep}, iris_url, burn_minimum}` (worst-case quotes; `burn_minimum` is the smallest relayed burn after the relay fee, USDC base units) |
| `POST /v2/relay/deposits/prepare` | `{depositor, expected_note_id, commitment, amount, zero_path, max_fee, inbound?}` → `{fee, operation, note, operation_rent, note_rent, transaction, submit_token}` (rents: decimal lamports) |
| `POST /v2/relay/receives/prepare` | `{source_domain, transaction_hash, owner, max_fee}` → `{fee:"0", nonce, recipient_token_account, transaction}` (`transaction` is `null` if the nonce was already used) |
| `POST /v2/relay/exits/prepare` | `{kind:"mutual"\|"escape", destination_owner, public_inputs, proof, max_fee}` → `{fee, destination, transaction, submit_token}` |
| `POST /v2/relay/escapes/finalize` | `{note_id}` → `{signature, action:"finalize"\|"release"}` |
| `POST /v2/relay/burns/prepare` | `{owner, destination_domain, mint_recipient, destination_caller?, max_cctp_fee, min_finality_threshold, hook_data, max_fee, inbound?}` → `{fee, amount, message_sent_event_account, transaction, submit_token}` |
| `POST /v2/relay/sweeps/prepare` | `{owner, destination, max_fee, inbound?}` → `{fee, amount, transaction, submit_token}` |
| `POST /v2/relay/submit` | `{token, transaction}` (the prepared bytes with the ek's signature) → `{signature, transaction}` (complete and broadcast; idempotent) |

`inbound` is `{source_domain, message, attestation}`: the attested inbound CCTP
transfer that funded `ATA(owner)`, offered as a sponsorship credential (see
below). An unverifiable credential is ignored, never an error.

Transaction shapes, all with the relayer as fee payer:

- deposit (v0): `[SOL transfer relayer → ek (buffer + note rent),
  initialize_operation(owner = ek), write_operation(owner = ek),
  RequestHeapFrame(128 KiB), SetComputeUnitLimit(1.4M),
  execute_deposit(owner = depositor = ek), TransferChecked fee if > 0,
  SOL transfer ek → relayer (buffer rent)]`. All stages are in the same
  signed message; no staging is broadcast separately. `ATA(ek)` must hold
  `amount + fee`. ek cannot cancel a prefunded buffer to steal relay rent.
- burn (legacy): `[TransferChecked fee if > 0, deposit_for_burn(_with_hook)(owner
  = ek, event_rent_payer = relayer, burn account = ATA(ek), fresh event
  account)]`, `amount = balance − fee > max_cctp_fee`, hook ≤ 192 bytes,
  `min_finality_threshold` 1000 or 2000.
- sweep (legacy): `[TransferChecked fee if > 0, TransferChecked(rest →
  destination)]` to an existing unfrozen USDC account.
- mutual close (v0): `[RequestHeapFrame, SetComputeUnitLimit,
  CreateIdempotent(ATA(ek), payer = relayer), execute_close(owner = relayer,
  destination_token = ATA(ek)), TransferChecked fee]`, signed by relayer and
  ek. The `CreateIdempotent` is always present (a no-op when `ATA(ek)` exists,
  e.g. after a CCTP deposit; its rent is charged only when absent). An invalid
  proof fails simulation (nothing is returned or sent), and if
  broadcast anyway the ATA creation rolls back with it.
- escape (v0): `[RequestHeapFrame, SetComputeUnitLimit, execute_escape(owner =
  relayer, destination = ATA(ek)), TransferChecked fee]`: the fee is prepaid,
  so `ATA(ek)` must already exist and hold it (else `insufficient_funds`).
  `/escapes/finalize` is relayer-paid (the pending rent returns to the
  relayer) and only for escapes whose pending rent the relayer paid.
- receive (v0, relayer-signed only): `[SetComputeUnitLimit(400,000),
  receive_message(payer = caller = relayer, recipient = ATA(ek))]` (a Fast,
  unfinalized receive with the 312-byte hook exceeds the default 200k compute
  units; no compute-unit price) for a Circle-attested message whose hook is
  `cctp-forward` v0 with ATA creation for `owner` followed by a `DGNZK-IN`
  intent naming the same ek, minting to `ATA(ek)`. `ATA(ek)` must already exist
  (`insufficient_funds` otherwise): the relayer never creates it, because the
  ek could close it and take the rent. **Residual subsidy:** the relayer pays
  the never-closable `used_nonce` rent (953,520 lamports at the rent above)
  plus 5,000 signature lamports (958,520 total), subject to a minimum source
  burn of 1 USDC, a durable 0.05 SOL/day budget and durable 6/day limits for
  each source-chain sender and each emergency key by default.
  Reservations are atomic in SQLite, persist across restarts and include any
  receive-triggered ALT rent/signature cost. Each attested message (nonce) is
  reserved once: its `used_nonce` rent can be paid only once, and anyone can
  request a public message, so repeated preparations of the same message
  neither charge the budget again nor spend its sender's or ek's allowance,
  and they receive the same relayer-signed transaction while it has at least
  30 blocks of validity left (one outstanding receive per message).
  Reservations are not refunded after failed/abandoned preparation: issued
  signatures may still land. A backwards clock cannot reopen an earlier allowance.
  Budget exhaustion stops subsidized signing even if Zoneless refills the key;
  it does not stop paid relay operations, Circle forwarding or self-funded
  receives. Keep the database durable; deleting it resets the accounting.
  An ek-paid fee cannot be added: with the 312-byte D2 hook, measured
  v0 sizes against the 1,232-byte packet are 1,326 bytes for `[CreateIdempotent,
  receive_message, fee]`, 1,284 for `[receive_message, fee]`, 1,213 for
  `[CreateIdempotent, receive_message]` and 1,138 for `[receive_message]`; the
  shipped `[SetComputeUnitLimit, receive_message]` is 1,178 bytes.
  Attestations are authenticated against the destination MessageTransmitter's
  on-chain attesters before any lookup-table extension can spend SOL.

Before signing, every message passes a policy audit: the relayer must be the
fee payer and may otherwise appear only as a vault operation owner/payer/rent
payer, ATA-creation payer, CCTP event-rent payer, receive payer/caller,
reclaim payee or the authority/payer of its own lookup table, never as a token
authority, and never loaded from a lookup table. The atomic deposit builder
alone constructs the fixed rent advance/refund System transfers; its inner
ledger instructions pass the ordinary restrictive audit. Prepared
transactions are simulated unsigned before they are returned (without
signature verification), and with every signature at submit and before the
relayer's own transactions are sent.

Errors are `{"error":{"code","message"}}`: `relay_disabled` (404),
`invalid_request` (400, including a vault or CCTP simulation failure such as an
invalid proof, a forged or foreign submit token, or a submitted message that
differs from the prepared one; 409 while an attestation is still pending),
`insufficient_funds` and `relay_fee_above_cap` (409),
`relay_transaction_expired` (409: the prepared transaction's blockhash is no
longer valid; prepare again),
`rate_limited` (429; 6 authenticated submissions per ek per minute, 120
requests per kind per minute; unauthenticated requests never spend an ek quota),
`relayer_unavailable` (503: SOL below the floor, RPC or Iris unavailable) and
`cctp_paused` (503: Circle's
MessageTransmitter or TokenMinter `paused` flag is set).
Subsidy refusals are `receive_below_minimum` (409),
`receive_budget_exhausted` (429) and `receive_address_limited` (429). Submit
refusals are `relay_submission_pending`, `relay_backing_spent`,
`relay_loss_budget_exhausted`, `relay_failure_limited` and
`relay_burn_float_exhausted` (429). The in-memory per-key and per-kind limits
are only a backstop: fresh keys cost nothing, so the shipped gateway
(`docker/aws/nginx.conf`) also limits `/v2/relay/` to 30 requests per minute
per client IP (burst 10) and `GET /v2/relay` to 60 (burst 20), answering
`rate_limited` (429, `Retry-After: 60`); operators running another proxy must
enforce an equivalent per-IP limit.

**Bounded failure/float exposure.** Risk is reserved only for transactions the
relay itself signs and broadcasts: at `/v2/relay/submit` for ek-co-signed
work, at issuance for relay-only receives and the relay's own transactions.
A preparation that is never submitted holds no float and no loss budget, so
no number of unsubmitted preparations can exhaust either. A definitive
preflight rejection of a fresh submission releases its reservation. Submission
reservation, broadcast and rejection release are serialized, so no concurrent
duplicate can expose signed bytes before that release. Finalized success frees a
reservation. Once finalized height is past validity, a full-history
`Unknown` releases it without a loss or failure: the transaction never
executed. Only actual on-chain failures consume daily loss budget.

An ek-co-signed transaction can still fail on chain if its ek moves the funds
between the relay's simulation and execution. To keep that from cheaply
exhausting the budget with fresh keys:
- at most one unsettled submitted transaction per ek exists at a time (one
  conflicting ek transfer can fail only one relay transaction). Expiry alone
  does not unlock the ek: the previous result must be settled first, spending
  its credential on failure or proving non-execution before releasing it;
- every failure must be covered by a **sponsorship credential** with a
  lifetime allowance of one attributed failure: an attested, already minted
  zkAPI inbound CCTP transfer of any amount to `ATA(ek)` (`nonce:…`, offered
  as `inbound`), or a note the ek exits through the relay (`note:…`,
  recorded when a valid exit is prepared; it also covers that ek's later
  burn or sweep). A credential backs one ek only. Mint recognition requires
  the nonce PDA to be Circle-owned with the exact `UsedNonce` discriminator
  and `is_used = true`; a prefunded system account is not a mint. Each new failure therefore
  needs a new real, minted CCTP transfer (source gas plus forward fee or
  `used_nonce` rent) or a new note, costing far more than the ≤ 15,000
  lamports it can cost the relay. Deposit note-id contention (the vault's
  `StaleNoteId` at the deposit's own `execute_deposit`: another deposit
  landed first) is always recorded as a loss. Up to three such failures per
  ek or credential in a rolling 24 hours are forgiven: they spend no
  credential and count toward no ban. Further contention failures are normal
  attributed failures, spending the credential and counting toward the ban.
  The allowance is durable across restarts; changing credentials does not
  reset an ek's allowance;
- credentialed and relay-only work share `ZKAPI_RELAYER_LOSS_DAILY_SOL`
  (0.02 SOL: lost fees plus outstanding reservations, across restarts and
  day boundaries). Every CCTP deposit, refund, transit sweep, relayed exit
  and burn after a relayed exit (or of a CCTP-deposited note) is
  credentialed, including a first-time user's first deposit. Only
  uncredentialed ek-co-signed work (a burn or sweep after a self-funded exit
  of a non-CCTP note, a sweep of donations alone, or a credential the relay
  cannot verify, e.g. after a Circle attester rotation) draws on
  `ZKAPI_RELAYER_UNBACKED_LOSS_DAILY_SOL` (0.002 SOL), so exhausting it never
  blocks credentialed users; those users can always use their own SOL.

Three actual ek-co-signed failures in rolling 24 hours also block that ek or
source USDC account. Permissionless relay-only receive failures consume global
loss and receive budgets but never ban their innocent recipient. Receive
preparation limits still apply to the attested `domain:messageSender` and ek.
Network fees are 5,000 lamports per signature: 0.02 SOL allows at most 4,000
single-signature or 2,000 two-signature reservations, less any losses.

**CCTP exits under $5 are not relayed by default** (net burn after relay fee;
configurable via `ZKAPI_RELAYER_BURN_MIN_USDC`, published as `burn_minimum` by
`GET /v2/relay`). The wallet refuses a relayed CCTP exit whose worst-case
payout after relay fees is below it before the irreversible close/escape.
Users can exit on Solana, sweep, or burn with their own SOL instead. The relay
floats event rent for five days. The durable **0.5 SOL outstanding-rent
backstop** is reserved at submit, atomically with fee risk, only for burns the
relay broadcasts, and released only after finalized absence once the burn
blockhash is dead (unlanded or reclaimed). Holding it therefore needs landed
burns of at least $5 each (about 96 maximal-hook burns, ≈ $480 of capital
cycled plus fees, lock it for five days) or credential-backed failures.
Exhaustion refuses new relayed burns until rent returns; it does not block
Solana-side exits or self-paid burns. These are bounded residual costs and
availability limits, not zero-drain guarantees.

Every 15 s the relay reconciles its own in-flight transactions (each is
written to the database before broadcast, then dropped once confirmed, failed
or expired, and rebroadcast while still valid) and, 5 days after each burn it
funded landed, reclaims the `MessageSent` rent using the attested destination
message from Iris.

### Running the relay against a localnet

Start the local stack (`scripts/localnet/stack.mjs`, RPC on a free port such as
18899; burns and receives also need the CCTP clones and Iris simulator from
`scripts/localnet/cctp/`), then:

```sh
solana-keygen new --no-bip39-passphrase -o "$RUN/relayer.json"
solana airdrop 5 "$(solana-keygen pubkey "$RUN/relayer.json")" --url http://127.0.0.1:18899
ZKAPI_STATE_SEED=... ZKAPI_CLEAR_SEED=... \
ZKAPI_SOLANA_IDENTITY="$RUN/identity.json" SOLANA_RPC_URL=http://127.0.0.1:18899 \
ZKAPI_RELAYER_KEY="$RUN/relayer.json" \
ZKAPI_RELAYER_FEE_ACCOUNT=<usdcFaucetTokenAccount printed by stack.mjs> \
ZKAPI_RELAYER_SOL_USD=150 \
ZKAPI_CCTP_IRIS_URL=http://127.0.0.1:<iris-sim port> \
dagon-zkapi --proof-setup-dir protocol/setup/v2 serverd \
  --listen 127.0.0.1:13000 --db-path "$RUN/server.db" --oa-org-url "$OA_ORG_URL"
curl -s http://127.0.0.1:13000/v2/relay
```

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
