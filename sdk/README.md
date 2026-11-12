# Dagon zkAPI browser SDK

`@dagon/zkapi-browser-sdk` owns the browser wallet, local proof worker,
private-note journal, short-lived key issuance and settlement, deposit/withdrawal
recovery, and public payment history for Dagon zkAPI on Solana. It has no UI,
model-catalog, or chat-storage dependency. The host owns chat and payment UI.

Dagon runs zkAPI only on Solana: Circle USDC (classic SPL Token, 6 decimals)
in the Dagon vault program, signed through a Wallet Standard wallet. One USDC
base unit is one micro-USD of credit; there is no price oracle. For
Ethereum, use the upstream [ethereum/zkapi](https://github.com/ethereum/zkapi)
project.

Users also need a little SOL in the same wallet besides their USDC: every
transaction pays Solana network fees, and deposits, escapes and payout-account
creation pay account rent (the staged deposit operation and note accounts, the
escape's pending-withdrawal and nullifier accounts, and the wallet's USDC
associated token account when it does not exist yet). Rent of temporary
accounts returns to the wallet that paid it.

Install a reviewed immutable Git revision, or install its `npm pack` tarball.
No Rust compiler, setup ceremony, or npm publish step is needed to consume this
package. The public proving keys, the WASM wallet core and the shared Solana
profile are included and hashed in `sdk/assets/manifest.json`; these are public
artifacts, not wallet secrets.

```js
import { configureBrowserSdk } from '@dagon/zkapi-browser-sdk';
import client from '@dagon/zkapi-browser-sdk/client';

configureBrowserSdk({
  configUrl: '/zkapi/browser-config.json',
  workerUrl: '/zkapi/assets/zkapiWasmWorker.js',
  // Optional: the host may preserve its explicit opt-in privacy proxy policy.
  transport: (url, init, hints) => hostTransport.fetch(url, init, hints)
});

// Initialize only when private payments are enabled. Importing creates no
// proof worker, network request, wallet connection, or wallet popup.
await client.init();
client.setSolanaWallet(walletStandardWallet);
const unsubscribe = client.subscribe(snapshot => renderBalance(snapshot));
```

Configuration must precede the first initialization. `mode: 'auto'` and
`mode: 'daemon'` are unsupported. The host config URL supplies the pinned
cluster, vault, server signing keys, proof hashes, and approved deployment
manifest URLs; runtime URL overrides remain restricted to that allowlist.
Private protocol and public manifest/config requests omit account credentials,
including through an optional same-origin deployment rewrite. An injected
transport receives `credentials: 'omit'` and the `{ preferProxy: true }` hint
and must preserve that credential policy. Chat account cookies must never
accompany private proof or key issuance requests. Never include note secrets,
key values, proof bodies, or signed transactions in host logs.

This SDK requires `proof_setup.circuit_id: "zkapi-v2-concession-v1"` in the
deployment manifest and the same `trusted_deployment.circuit_id` in the host
config. Configuration mismatches are rejected before funding.

## Building a deployment's browser assets

Every shared parameter (program ID, circuit ID, request charge cap, note TTL,
and the USDC asset: mint, decimals, token program and associated token
program) comes from
`solana/profile/shared.json`, packaged as `sdk/assets/config/profile.json` by
`npm run sync:assets`. The network identity (cluster genesis hash, vault
authority and state, treasury USDC token account) comes from a
`dagon-zkapi.solana-identity.v1` file: a packaged one such as
`sdk/assets/config/mainnet-beta.identity.json`, or one written by
`dagon-zkapi-deploy identity` for a local validator. The operator's public
endpoints and signing keys are build inputs:

```json
{
  "schema": "dagon-zkapi.sdk-deployment.v1",
  "deployment_manifest_url": "https://zkapi.example/config.json",
  "protocol_server_url": "https://zkapi.example",
  "indexer_url": "https://zkapi.example",
  "rpc_url": "https://solana-rpc.example",
  "openrouter_inference_base": "https://gateway.example/v1",
  "oa_verifier_url": null,
  "state_signing_key": { "x": "0x…", "y": "0x…" },
  "clearance_signing_key": { "x": "0x…", "y": "0x…" }
}
```

The signing keys are the output of `dagon-zkapi signing-keys`. Set
`oa_verifier_url` only when the server mints keys through an OA organization;
the browser then requires OA verifier evidence for every key.

```sh
npm run build:sdk -- --identity mainnet-beta --deployment deployment.json \
  --out-dir dist/zkapi --public-path /zkapi/
```

or, from the host build:

```js
import { build } from 'esbuild';
import { buildBrowserSdkAssets } from '@dagon/zkapi-browser-sdk/build';

await buildBrowserSdkAssets({
  outDir: 'dist/zkapi',
  publicPath: '/zkapi/',
  identity: 'mainnet-beta', // or a parsed identity object
  deployment,               // the deployment inputs above
  deploymentApiProxyPath: '/zkapi-deployment/', // optional same-origin rewrite
  build
});
```

The identity is validated exactly like the operator binaries: every account is
required and the vault state must be the `["vault", authority]` PDA of the
profile's program. An undeployed identity (null accounts, as mainnet-beta is
until its vault exists) is refused. The build derives the v2 `chain_id` and
deployment binding from the genesis hash, program and vault, and the Wallet
Standard chain from the network label. It emits `browser-config.json`,
`assets/zkapiWasmWorker.js`, `wasm/zkapi_browser_bg.wasm`, `proofs/request.pk`,
`proofs/withdrawal.pk` and `sdk-assets.json`, after verifying every packaged
artifact hash. The host supplies its esbuild implementation, controls its
CSP/rewrites, and hashes these emitted assets in its deployment manifest. Proof
downloads are verified again inside the worker. No private credentials are
required to build.

`npm run build:sdk:fixture` builds from the checked-in localnet test identity
in `sdk/test/fixtures`; CI uses it to exercise the build path.
`npm run verify:assets` checks every packaged artifact hash and that the
packaged profile and identities are exact copies of `solana/profile`.

## Solana wallets and durable staged operations

Deployments pin `ledger_backend: "dagon.solana.groth16.v1"`, `billing_asset:
"usdc"`, `billing_unit: "micro_usdc"`, `base_units_per_asset: "1000000"`, an
exact decimal-string chain ID, the cluster genesis hash, the immutable program
ID, the vault-state PDA, the Circle USDC mint (`usdc_mint`), the classic SPL
Token program (`token_program`; Token-2022 is rejected everywhere), the
associated token program (`associated_token_program`) and a finalized RPC. On
initialization the SDK checks, through the pinned RPC, that the cluster genesis
matches, the vault is owned by the program and carries the pinned chain ID,
binding, USDC mint and `["vault-token", vault]` token account, and the program
has no upgrade authority. Its challenge period sizes the escape window
(`client.escapePeriodLabel()`).

The host supplies a Wallet Standard wallet (`client.setSolanaWallet(wallet,
account)`) with an account that can `solana:signTransaction` on the pinned
cluster. Prepared legacy messages must contain exactly one instruction for the
pinned program, optionally preceded by bounded Compute Budget heap-frame and
compute-unit limit instructions. Priority-fee instructions, other prefix
programs and duplicate budget settings are rejected. The pinned vault must be
account zero of the vault instruction, and the selected account must be the
exact fee payer. The one non-vault wallet transaction is the creation of the
wallet's own canonical USDC account (associated token program
`CreateIdempotent`), which must match that exact instruction. The transport
checks recent blockhash lifetime and packet
size, persists signed bytes and the deterministic signature before broadcast,
and then submits and finalizes each stage in order. Restart resumes from the
stored bytes without prompting the wallet to sign again.

Deposit, mutual close, escape initiation, escape finalization and parked-payout
release each have an independent durable journal. The runtime mutates private
wallet state only after the transaction is finalized and the program-owned
note/pending accounts match the expected operation. Never clear or synthesize a
journal from UI state. Calling the same `client.deposit()`, `client.withdraw()`,
`client.finalizeEscape()` or `client.releaseEscapePayout()` again resumes an
interrupted operation.

Close, escape, finalization and release transactions are constructed locally
from the pinned RPC's canonical vault/note/pending accounts and a recent
blockhash; they never call the operator's `/v2/ledger/*/prepare` endpoints.
Deposits use the staged operator preparation route. Before journaling and
again before signing or resuming, the SDK authorizes the complete
initialize/write/execute sequence: exactly three transactions, one canonical
operation PDA, one complete 344-byte payload (including the 256-byte Groth16
proof), its digest, and the locally planned note ID, amount and registration
commitment. Fragmented writes and oversized buffers are rejected before any
wallet signature to prevent operator-inflated SOL fees and rent. Extra vault
instructions and substituted staging accounts are rejected. The final `execute_deposit` must take the wallet as
operation owner and token authority, the wallet's canonical USDC account as
source, the vault's token account, the pinned USDC mint and the classic Token
program. Pinning the vault alone would not prevent an operator from replacing
the note commitment with its own. A deposit that landed is
installed from the finalized note account alone: confirmation never reads the
operator's indexer, so withholding the tree mirror cannot keep a landed deposit
from being exited. Requests still read and verify the mirror: a request proves
against the finalized vault root, and a mirror snapshot that does not yet hold
the note or that root (the indexer polls the vault, so it can trail a fresh
deposit) is retried with bounded backoff for about 12 seconds before the proof
worker runs, then fails with `indexer_root_lag`. A `stale_root` rejection of a
request proved at the finalized vault root, with a different server root, is
treated as server poll lag; the SDK resends the identical request for up to
10 seconds, including time spent checking the vault before each resend.
A request proved at an older root still fails at once, and the next attempt
re-proves. Cancellation reaches both the snapshot fetch and finalized-vault
RPC and stops backoff and worker dispatch. A vault whose pause flag is set
still loads: the program reopens exits after the bounded pause, and only new
deposits are refused while the flag stays set.

These waits are not a traffic-analysis defense: repeated requests are linkable
as attempts at the same lease (the request ID, nullifier and proof are unchanged),
and deterministic backoff reveals lag/retry timing. This extends the existing
identical-request transport retry behavior, not the linkability of separate
notes or successful leases. The SDK fetches the same full `/v1/tree/snapshot`
for every note and computes the path locally; neither the note ID nor a
note-specific path URL is sent to the indexer. Lag adds snapshot queries and
vault RPC reads, so observers can correlate their timing with deposits and lease
creation; use of a proxy does not eliminate that residual timing exposure.

Signing-key trust pins compare hexadecimal field values rather than their
padding or letter case; different key values are always rejected.

If the operator's deployment manifest is unavailable or no longer matches the
host's trusted pins, initialization uses those pins in **exit-only** mode
(`config.exit_only`). New deposits and requests remain disabled; existing
balances and recovery stay available. Reload once the operator recovers.

## Withdrawals and the concession rule

`client.withdraw(mode, onStatus, { destination, earlyConcession })` withdraws
the selected balance; `mode` is `mutual` (cooperative close with the server's
clearance) or `escape` (unilateral). The payout goes to `destination`, a
classic-Token USDC token account with any owner (never a vault account), or,
when omitted, to the connected wallet's canonical USDC associated token
account. The vault pays only a creditable account (initialized, unfrozen,
USDC): when the wallet's own account is missing the SDK first submits a
separate `CreateIdempotent` transaction for it (the wallet pays its rent); any
other missing or frozen payout account is refused before proving. The SDK
binds the payout account into the durable proof; an explicit different
destination on a later call is rejected, and omitting it when resuming keeps
the saved one.

An escape records its payout account. If that account cannot be credited when
`client.finalizeEscape()` lands, the note still closes and the payout is parked
in the vault (`phase: 'payout_parked'`). `client.releaseEscapePayout(recordId)`
recreates the wallet's own USDC account when that is the payout account and then
pays the parked amount to exactly that account; the pending record's rent
returns to the escaper.

A challenged escape never removes the note leaf: a defeated escape returns the
note to `active`, and a concession raise lowers the pending payout while it
stays `pending_withdrawal`. Exit rules in the wallet: the note is frozen once an
exit starts (no new requests); the client chooses a concession (fresh state:
`c = 0`; request in flight: wait until the settlement deadline plus margin or
`expiry - 12h`, then concede the recorded bound `b_k` or the smaller reported
charge); one bound is released per state, and re-proving an unfinished lease
reuses the recorded bound. The exit proof is leaf-bound and root-free with a
short `valid_until` TTL. `earlyConcession` (`'zero'` or `'bound'`) forces an
escape while the last request may still be settling; without it the SDK refuses
with `escape_wait` (and `escapeAt`) until the settlement window ends. A signed
successor state that fails the derived-anchor check (`next_anchor == H(d_anchor,
N)`) or the commitment recomputation is treated as withheld
(`successor_withheld`): the balance is frozen for requests and escaping concedes
at most that request's bound. With these rules the honest user is paid at least
`B_k - b_k` from the newest installed state without operator cooperation
(guarantee G1); see [the concession rule](../protocol/SPEC.md). Withdrawal
records expose `stateBalance`, `concededAtInit` and `conceded`.

Escape recovery is best-effort and bounded: an offline or refusing operator or
a malformed successor cannot prevent proving an escape. Failed recovery retains
the durable request journal and its bound; the same local settlement deadline,
concession choice and exit-proof freeze apply. Mutual close still requires a
valid operator clearance.

A released exit proof freezes its balance (no successor install, request or
cancel) until both this device's clock and the finalized block time read from
the host-pinned RPC are past `valid_until + 900 s`; the program checks
`valid_until` against block time, so a fast device clock alone never thaws the
balance. An unreadable RPC keeps it frozen; exits and finalization are never
blocked by the freeze. `client.cancelPreparedWithdrawal()` cancels an escape
that never finalized once its proof is dead; a mutual close, whose clearance
the server already reserved, is finished or escaped instead.

## Cross-chain USDC through CCTP (program-free)

The SDK can fund a note from an EVM chain and pay a note out to an EVM address
through Circle CCTP V2 without new on-chain code. Each note has its own
**emergency key** `ek`: an ed25519 key derived from the note secret
(HKDF-SHA256, info `dagon-zkapi/cctp-ek/v1`). Minted transit USDC sits in
`ATA(ek)`, controlled by that key. A relayer (`zkapi-serverd`, `/v2/relay/*`)
pays SOL and rent, collecting capped USDC fees atomically. A relayed escape
requires USDC prefunding of `ATA(ek)`; self-funded recovery requires SOL.
CCTP does not improve privacy: Circle and the relayer can link the EVM
address, note and destination. The SDK must run in a trusted wallet origin:
malicious same-origin JavaScript can read its secrets and change its checks.

```js
// EVM → private note. The plan is persisted and its backup is mandatory before the burn.
let result = await client.cctpDeposit({ sourceChain: 'base', amount: '25', finality: 'fast', evmProvider: window.ethereum });
if (result.status === 'backup_required') {
  await saveBackupFile(result.backup);               // secret, emergency key, intent, authorized CCTP fee
  await client.cctpAcknowledgeBackup(result.backup.operationId);
  result = await client.cctpDeposit({ evmProvider: window.ethereum });   // or pass onBackup to do both at once
}
// Private note → EVM address (mutual close, or escape and finalize later).
await client.cctpExit({ kind: 'mutual', destinationChain: 'arbitrum', recipient: '0x…', claim: 'forward' });
await client.cctpResumeExit(recordId, { waitForChallenge: true }); // after an escape's challenge window
// Emergency paths.
await client.cctpSweep({ to: solanaUsdcAccountOrWallet });      // ATA(ek) → any Solana USDC account
await client.cctpRefund({ force: false });                       // undeposited arrival → the EVM burner
await client.cctpEmergencyInfo();                                // where the funds are, which key holds them
```

**Backup scope and browser loss.** The mandatory initial backup recovers the
emergency key and a **never-used** note, not the current state of a note used
for private requests. Used notes additionally require the latest private state
(including balance blinding and signature) and any pending-request journal.
Losing those can prevent spending and escape; expiry can send the funds to
the treasury. Persistent browser storage is not an external backup.

In an empty wallet, `await client.cctpImportBackup(backup)` imports emergency
funds without initiating another EVM burn. Then use `cctpSweep` or `cctpRefund`.
For a note you have **never used**, pass
`{ restoreUnspentNote: true, noteId }`; omitting `noteId` scans the pinned vault
for a unique matching commitment. A reported used/reserved genesis nullifier
is refused, and existing wallet state is never overwritten. An unavailable
operator does not block recovery of a genuinely never-used note. Neither an
unavailable server nor its negative report proves non-use: this option is
your assertion that the note has never been used.
To resume an unminted inbound transfer, also supply its source `burnTxHash`;
the pre-burn backup cannot contain that future hash. Old backups lacking the
inbound finality still recover the emergency key but cannot resume the burn
tracking flow. Circle refusal/pause/blacklisting cannot be bypassed by a backup.

**Deposit** (`cctpDeposit`):
1. Reads the relayer (`GET /v2/relay`), connects the EVM wallet
   (`eth_requestAccounts`, `wallet_switchEthereumChain`) and checks the USDC
   balance.
2. Creates the note secret and stores the plan in IndexedDB. The plan holds an
   InboundIntent v1 (refund to the burner on the source domain after 72 h,
   priority relayer = the relay key) and the hook `cctp-forward` (ATA creation
   for `ek`) ‖ `"DGNZK-IN"` ‖ intent.
3. Stops in phase `backup_required` and returns `{ status: 'backup_required',
   backup }`. The backup also reports whether the browser granted persistent
   storage. The burn is requested only after the acknowledgement is persisted:
   either an `onBackup` handler resolves (anything but `false`), or the host
   calls `cctpAcknowledgeBackup()`.
4. Approves USDC only if the allowance is short, then calls
   `depositForBurnWithHook(amount, 5, ATA(ek), usdc, 0, maxFee, 1000|2000, hook)`.
   `maxFee` is Circle's Fast fee + the high forward fee with ATA creation +
   headroom, within the fee policy (see Fees). Sources where Circle offers no
   Fast route use Standard. The burn hash is stored as soon as the wallet
   returns it. If it was lost, resume with `{ burnTxHash }`.

**Arrival.** Iris's message is accepted only after every field is compared
with the plan: versions, domains, sender (the source TokenMessengerV2),
recipient (TokenMessengerMinterV2), destination caller 0, burn token (the
source USDC), mint recipient `ATA(ek)`, amount, message sender (the burner),
max fee, minimum and executed finality, and hook. Its attestation must also
verify against the **pinned attesters** (see Configuration). The transfer
counts as arrived only when its CCTP nonce is used on Solana and `ATA(ek)` holds
the attested net mint (amount − feeExecuted). Only that amount is deposited:
dust sent to the public `ATA(ek)` never stands in for the transfer and stays
sweepable.

**Fallback receive.** If Circle's forwarder is late (`receiveFallbackMs` after
attestation), the SDK asks `/v2/relay/receives/prepare`. That call only works
once `ATA(ek)` exists; otherwise the wallet keeps waiting for the forwarder.
The receive is free and signed by the relayer alone. The SDK reads its address
lookup table from the RPC (owner, active, contents) and requires exactly
`[SetComputeUnitLimit(≤ 1.4M), receive_message(payer = caller = relayer,
recipient ATA(ek))]` of the validated message with a pinned attestation. A
compute-unit price is refused. It then broadcasts it.
Subsidized fallback receives require a minimum source burn (default 1 USDC)
and obey durable SOL/day and source/ek quotas. Refusal does not prevent
Circle's forwarder or an independently funded receive; the wallet keeps
watching for that arrival. Arrival requires Circle-owned `UsedNonce` state
with the correct discriminator and `is_used = true`, not mere PDA existence.
Expired, unused inbound messages are re-attested through Iris, then checked
again against the original intent and pinned attesters.

**Relay submission.** Every ek-co-signed relay transaction (deposit, exit,
burn, sweep) is prepared **unsigned**: every signature slot, the relayer's
included, is zero, and the prepare returns an opaque `submit_token`. The SDK
validates the message exactly and checks its actual blockhash in the trusted
RPC's queue. An RPC head at least as new as that observation supplies a
conservative expiration bound (`expiryHeight`), independent of the relay's
unsigned `last_valid_height` metadata. It signs with `ek`, journals the
ek-signed bytes, token and bound, and POSTs `{ token, transaction }` to
`/v2/relay/submit`. Older signed journals get a fresh conservative bound
persisted before retrying; this can add one blockhash lifetime of waiting. The
relay signs (relayer and, for burns, the MessageSent event key), broadcasts and
returns the complete transaction. The SDK accepts it only if the message bytes
are identical, its `ek` signature is unchanged and every signature is valid
(`cctp_relay_tx_rejected` otherwise; nothing is broadcast). It then journals
the full bytes and confirms them as before. After a crash the same token and
bytes are re-submitted (idempotent). No submit error, including
`relay_transaction_expired`, authorizes replacement until the trusted RPC's
**finalized** block height passes the journaled RPC-derived `expiryHeight`. A premature
relay expiry claim returns `cctp_relay_pending`. After finalized expiry any
submit refusal (including 400 after key rotation or simulation failure) permits
recovery; the flow first checks chain state (note, burn event account history,
`ATA(ek)` balance) in case it landed. Within the lifetime other submit refusals
surface with their original code and retain the journal. Deposit, refund-burn and
transit-sweep prepares also send `inbound` (the attested inbound transfer:
`source_domain`, `message`, `attestation`) as the relay's sponsorship
credential when the plan has it; exits and their burns send none.

**Deposit transaction.** The SDK reads a fresh vault path and calls
`/v2/relay/deposits/prepare`. Before signing with `ek` it requires:
- the v0 transaction itself to contain initialization and the complete
  344-byte payload, with this note ID, commitment, amount and matching digest;
- the emergency key to own the buffer (so a relayer cannot cancel/recreate it);
- exactly [SOL rent advance relayer → ek, initialize, write, heap frame,
  compute-unit limit, execute with owner = depositor = ek, capped USDC fee,
  buffer-rent refund ek → relayer], with every account and privilege checked;
- rent amounts to match the pinned RPC and lookup-table contents to match chain;
- the fee to be at most the cap.

The ek-signed bytes are stored before submission (phase `signed`) and the
complete bytes before confirmation (phase `submitted`). A transaction that
expires or fails is rebuilt; one that lands is confirmed from the finalized
note account (`confirmSolanaDeposit`).

**Exit** (`cctpExit`):
1. Proves the close or escape with destination `ATA(ek)`. The CCTP fee ceiling
   of the later burn is fixed now and persisted (status `authorized`). Before
   proving, a relayed exit whose expected burn is below the relay's
   `burn_minimum` is refused (`cctp_exit_below_minimum`).
2. Asks `/v2/relay/exits/prepare` for a v0 transaction. The SDK checks it
   exactly, signs it with `ek` and submits it through the relay:
   - close: [heap, CU limit, `CreateIdempotent(ATA(ek))`, `execute_close(owner =
     relayer, destination ATA(ek))` of this proof, `TransferChecked(fee)`]. The
     fee is paid from the payout and must not exceed it.
   - escape: [heap, CU limit, `execute_escape(…)`, `TransferChecked(fee)`]. The
     fee is prepaid, so `ATA(ek)` must already hold at least the escape quote
     (`cctp_escape_fee_required` otherwise).
3. Records the withdrawal from the finalized note and pending accounts. An
   escape is finalized after its window through `/v2/relay/escapes/finalize`.
4. Asks `/v2/relay/burns/prepare` for a burn of the whole balance. The amount
   must be balance − fee, the instruction must equal the SDK's own
   `deposit_for_burn(_with_hook)` (owner `ek`, recipient, domain, the authorized
   max CCTP fee, finality, hook), and only the relayer and the fresh event
   keypair may co-sign. The SDK signs it and submits it through the relay; the
   event account, target and amount are journaled before submission.
5. Accepts Iris's attestation only if it matches the burn's on-chain
   `MessageSent` bytes, except the fields Iris fills (nonce, executed finality,
   fee executed, expiration block), and verifies against the pinned attesters.
   If the rent payer has already reclaimed `MessageSent`, the wallet instead
   reconstructs every source-controlled field from the validated finalized
   burn and trusted chain deployment; the pinned attestation is still required.

With `claim: 'forward'` Circle's Forwarding Service mints on the destination.
With `claim: 'self'`, call `client.cctpClaim({ recordId, evmProvider })`. Zero,
burn and CCTP/USDC contract addresses are refused as recipients.

**Fees.**
- **Relay fees.** Every relay call carries `max_fee` = the SDK cap for that
  transaction kind (`CCTP_FEE_CAPS`, USDC base units: deposit 400 000, receive
  0 (receives are free), close 750 000, escape 750 000, burn and sweep
  **50 000 each**). Burn fees cover three burn signatures plus one reclaim
  signature and margin, not rent.
  The relay floats MessageSent rent and reclaims it after five days. At SOL
  $150/$180 with 20% margin, burns cost 0.003600/0.004320 USDC and sweeps
  0.001800/0.002160 USDC, independent of the burn hook length.
  A higher fee is refused before signing; host overrides may only lower caps.
  **CCTP exits under $5 are not relayed by default** (net burn after the relay
  fee; operator-configurable, published as `burn_minimum`). A relayed
  `cctpExit` whose note plus emergency-account balance, less the worst-case
  exit and burn quotes, is below it fails with `cctp_exit_below_minimum`
  before any clearance or proof, so the payout is never stranded in ATA(ek).
  Exit on Solana, sweep, or burn with your own SOL.
  The durable 0.5 SOL outstanding-rent backstop refuses new sponsored burns
  until rent returns. Durable failed-fee and per-address limits also apply.
- **CCTP fees.** The CCTP `maxFee` a burn authorizes is capped by
  `CCTP_FEE_POLICY`, max(minimum, bps × amount):
  - inbound ≤ max(0.50 USDC, 0.5 %);
  - outbound with forwarding ≤ max(1.50 USDC, 0.5 %), which covers the
    Ethereum forward fee of about $0.7–1.2;
  - outbound self-claim ≤ max(0.10 USDC, 0.1 %).

  An Iris quote above the policy is refused (`cctp_fee_above_policy`), and
  headroom never lifts `maxFee` above it. A persisted ceiling (the intent's
  refund fee, an exit's fee fixed at proving) is never raised automatically.
  If Circle's quote rises above it, the burn stops with
  `cctp_fee_above_authorized`. The user re-authorizes within policy with
  `cctpRefund({ maxCctpFee })` or `cctpResumeExit(recordId, { maxCctpFee })`.

**No relayer.** If the relay is disabled or unreachable, flows fail with
`code: 'relay_unavailable'`. The error carries `emergencyKey`,
`emergencyAccount` and `balance` and says that the funds are safe in `ATA(ek)`.
Fund `ek` with about 0.005 SOL and pass `{ selfFunded: true }`: the same
transactions are then built with `ek` as fee payer. Deposits and exits use the
existing single-signer journaled paths with `ek` as the wallet; burns and
sweeps are built locally. A relay transaction whose complete bytes were
returned by `/v2/relay/submit` is still rebroadcast without the relayer; one
that was only ek-signed waits for the relayer until its blockhash expires, then
the self-funded path takes over.

**Resume and refunds.** Every phase is persisted, and calling the same method
again resumes it:
- the deposit plan is in `pending_deposit.cctp`;
- the exit plan is in the withdrawal record's `cctpExit`;
- the key seed never appears in snapshots.

`cctpCancelDeposit()` is allowed only before the burn was requested.
`cctpRefund()` is refused before the intent's `refund_after` unless
`{ force: true }`. Refunded, swept and canceled deposit plans are archived with
their secret, never deleted.

**Configuration.**
```js
configureBrowserSdk({ cctp: {
  irisUrl, relayUrl, attesters, attestationThreshold, feeRecipientTokenAccount,
  evmChains: { base: { chainId, domain, usdc, tokenMessenger, messageTransmitter } },
  feeCaps: { deposit: 400000n }, feePolicy: { inbound: { minimum: 500000n, bps: 50 } },
  receiveFallbackMs, pollIntervalMs, /* … */
} });
```
These options override `CCTP_DEFAULTS`, e.g. for a local iris-sim and anvil
fork:
- **Attesters.** Mainnet pins Circle's two attesters (`CIRCLE_ATTESTERS`,
  threshold 2). Other networks must configure `attesters`, e.g. the iris-sim
  test keys; without them no CCTP flow starts (`cctp_attesters_unconfigured`).
  A configured Iris URL cannot vouch for a message by itself.
  Rotation fails closed: old SDK pins reject new signatures until a reviewed
  SDK/configuration update. Never learn replacement pins from Iris itself.
  Already minted emergency-key funds remain sweepable without attestation.
- **Iris URL.** Without `irisUrl`, mainnet uses `iris-api.circle.com`, devnet
  and testnet use the sandbox, and localnet uses the relayer's `iris_url`.

## Deposits and inference

`client.deposit(amount, onStatus)` deposits an exact USDC amount (a decimal
string with up to six decimals) from the connected wallet's canonical USDC
account. Before preparing a new deposit the SDK checks that this account exists,
is not frozen and holds the amount, and that the wallet has some SOL for fees
and rent. A deposit plan with no Solana journal can still be replaced by a new
amount (`config.pending_deposit.replannable`); once a deposit has a Solana
journal it can only be resumed (`config.pending_deposit.phase ===
'submitting'`, `replannable === false`).

`client.formatBillingAmount(units)` returns decimal USDC and
`client.formatMoney(units)` the same amount in USD; `creditsPerUsd` is exactly
1,000,000.

For inference the prompt-free authorization payload is exactly
`{"mode":"openrouter_ephemeral_lease","version":1}`. A model tier of `$t`
proves a `solvency_bound` of `t × 1,000,000` USDC base units, and the issued
OpenRouter key must carry a `spending_limit_usd` of exactly
`solvency_bound / 1,000,000` as an f64, stepped one ulp down when that
quotient would round above the bound (the server's `micro_usd_to_usd`); any
other limit is rejected. A request that was
never accepted is re-sent byte-for-byte; nothing expires it.

A model adapter must select one of `CHAT_SPENDING_TIER_USD` (`1`, `2`, `3`,
`4.5`, `6`) without disclosing the user's exact balance. The SDK settles and
rekeys when a selected cap changes; only actual usage is charged.

The SDK uses IndexedDB, local/session storage, Web Locks, BroadcastChannel,
revision checks and signed receipt validation to manage wallet state. Hosting
the same SDK on a different origin does not transfer browser wallet data. The
runtime checks that active notes, pending deposits, leases and unfinished
recovery state match the selected deployment.

Run `npm test` in this checkout. Some tests compare the packaged assets with
`solana/profile` and the protocol's binding vectors, so they need the full
repository, not only an installed package. The tests use local fixtures and do
not connect a wallet or broadcast transactions.
