# Dagon zkAPI browser SDK

`@dagon/zkapi-browser-sdk` owns the browser wallet, local proof worker,
private-note journal, short-lived key issuance and settlement, deposit/withdrawal
recovery, and public payment history for Dagon zkAPI on Solana. It has no UI,
model-catalog, or chat-storage dependency. The host owns chat and payment UI.

Dagon runs zkAPI only on Solana: native SOL in the Dagon vault program, priced
by the Pyth SOL/USD feed, signed through a Wallet Standard wallet. For Ethereum,
use the upstream [ethereum/zkapi](https://github.com/ethereum/zkapi) project.

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
Pyth receiver, push oracle, feed, shard, maximum age and confidence bound) comes from
`solana/profile/shared.json`, packaged as `sdk/assets/config/profile.json` by
`npm run sync:assets`. The network identity (cluster genesis hash, vault
authority and state, treasury, Pyth price account, which must be the
profile's push-oracle account) comes from a
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
"native_sol"`, `billing_unit: "lamports"`, an exact decimal-string chain ID, the
cluster genesis hash, the immutable program ID, the vault-state PDA, the Pyth
receiver/price/feed identities and a finalized RPC. On initialization the SDK
checks, through the pinned RPC, that the cluster genesis matches, the vault is
owned by the program and carries the pinned chain ID and binding, and the
program has no upgrade authority. Its challenge period sizes the escape window
(`client.escapePeriodLabel()`).

The host supplies a Wallet Standard wallet (`client.setSolanaWallet(wallet,
account)`) with an account that can `solana:signTransaction` on the pinned
cluster. Prepared legacy messages must contain exactly one instruction for the
pinned program, optionally preceded by bounded Compute Budget heap-frame and
compute-unit limit instructions. Priority-fee instructions, other prefix
programs and duplicate budget settings are rejected. The pinned vault must be
account zero of the vault instruction, and the selected account must be the
exact fee payer. The transport checks recent blockhash lifetime and packet
size, persists signed bytes and the deterministic signature before broadcast,
and then submits and finalizes each stage in order. Restart resumes from the
stored bytes without prompting the wallet to sign again.

Deposit, mutual close, escape initiation and escape finalization each have an
independent durable journal. The runtime mutates private wallet state only
after the transaction is finalized and the program-owned note/pending accounts
match the expected operation. Never clear or synthesize a journal from UI
state. Calling the same `client.deposit()`, `client.withdraw()` or
`client.finalizeEscape()` again resumes an interrupted operation.

Close, escape and finalization transactions are constructed locally from the
pinned RPC's canonical vault/note accounts and a recent blockhash; they never
call the operator's `/v2/ledger/*/prepare` endpoints. Deposits use the staged
operator preparation route. A deposit that landed is installed from the
finalized note account alone: confirmation never reads the operator's indexer,
so withholding the tree mirror cannot keep a landed deposit from being exited.
Requests still read and verify the mirror. A vault whose pause flag is set still
loads: the program reopens exits after the bounded pause, and only new deposits
are refused while the flag stays set.

If the operator's deployment manifest is unavailable or no longer matches the
host's trusted pins, initialization uses those pins in **exit-only** mode
(`config.exit_only`). New deposits and requests remain disabled; existing
balances and recovery stay available. Reload once the operator recovers.

## Withdrawals and the concession rule

`client.withdraw(mode, onStatus, { destination, earlyConcession })` withdraws
the selected balance; `mode` is `mutual` (cooperative close with the server's
clearance) or `escape` (unilateral). The payout goes to `destination`, a
canonical base58 Solana account other than the vault state, or to the connected
account when omitted. The SDK binds it into the durable proof; an explicit
different destination on a later call is rejected, and omitting it when
resuming keeps the saved one.

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

## Prices, deposits and inference

`await client.quoteDepositUsd("10")` reads the server's public
`/v2/billing/quote`, a Pyth SOL/USD update verified against the pinned receiver,
price account, feed, maximum age and confidence bound. It returns `{ amount,
depositLamports, solAmount, usdAmount, priceUpdatedAt, price, chainId,
contractAddress }`; amounts are exact decimal strings. USD converts at the
lower confidence bound, rounding lamports upward. Deposits accept up to nine
SOL decimal places.

`await client.prepareDepositQuote(solAmount, { from })` fixes a private note's
secret and vault slot for an exact amount before funding the `from` account.
It returns `{ operationId, commitment, amount, depositLamports, chainId,
contractAddress, payer }`, never note secrets, and never connects a wallet or
signs. The draft is not a pending deposit or payment-history entry; read-only
polling and reload cannot promote it. An explicit
`client.deposit(solAmount, onStatus, { preparedOperationId })` atomically
promotes that exact draft under the cross-tab wallet lock. Once a deposit has
a Solana journal it can only be resumed (`config.pending_deposit.phase ===
'submitting'`, `funding_quote_available === false`).

`client.formatBillingAmount(lamports)` returns decimal SOL;
`client.formatMoney(lamports)` uses the current verified quote, returning `—`
when none is fresh. Normal wallet refreshes attempt a public price refresh at
most once per minute; `refreshNativePrice({ signal })` refreshes it explicitly.
`creditsPerUsd` is only a display conversion and must not be used to construct
a payment or proof.

For inference the complete quote is bound into the prompt-free authorization
payload before its proof is generated. Fixed USD model tiers round upward to
whole lamports; the provider's USD limit rounds down to microdollars. The saved
request, issued key and settlement all retain that same quote. A quote that
expires or is superseded before acceptance is discarded only after the
read-only `POST /v2/openrouter/leases/{id}/expire` endpoint confirms that exact
saved request was never accepted under the server's issuance lock.

New admission always refreshes the finalized oracle account. Older observed
quotes remain acceptable only if the newest observed conservative price
(`price - confidence`) is no more than 1% lower than the submitted quote's
conservative price (`pyth.max_supersession_bps` in the shared profile).
Larger drops return retriable `409 native_quote_superseded` without reserving
the new request. This does not reprice accepted leases or remove SOL market
risk during their 300 s lifetime.

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
