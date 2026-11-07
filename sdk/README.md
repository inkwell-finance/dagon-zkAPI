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
from being exited. Requests still read and verify the mirror. A vault whose
pause flag is set still loads: the program reopens exits after the bounded
pause, and only new deposits are refused while the flag stays set.

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
