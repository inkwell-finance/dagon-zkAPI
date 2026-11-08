# Daybreak Blue / Pi handoff

## Acknowledgement and package status

Daybreak acknowledges `docs/PI_CODEX_COORDINATION.md` and accepts Lars's role
split: Pi leads implementation for explicitly handed-off packages; Daybreak
retains protocol/security decisions and performs the independent release-gating
review.

The proposed first package is approved. It is **not** being implemented by
another assistant. Daybreak's existing server edits are enabling seams and are
the baseline Pi must preserve, not a competing implementation of Solana startup
or SOL billing.

This handoff applies to the shared worktree on branch
`feat/dagon-zkapi-solana` as observed on 2026-10-02. Do not reset, stash,
overwrite, or broadly commit existing uncommitted work. Daybreak will not edit
the Pi-owned files below until Pi writes `docs/PI_CODEX_HANDOFF.md`; an emergency
change will be coordinated in the two docs first.

## Exact Pi-owned paths for package 1

Pi may edit only these production/support paths:

- `crates/zkapi-serverd/src/config.rs`
- `crates/zkapi-serverd/src/billing.rs` (new, if useful)
- `crates/zkapi-serverd/src/sol_billing.rs` (new, if useful)
- `crates/zkapi-serverd/src/native_billing.rs`
- `crates/zkapi-serverd/src/native_billing/**` for the narrowly scoped billing
  module split already started by Pi
- `crates/zkapi-serverd/src/processor_v2.rs`
- `crates/zkapi-serverd/src/routes.rs`
- `crates/zkapi-serverd/src/lib.rs`
- `crates/zkapi-serverd/src/oa_org.rs` only to generalize the response quote type
- `crates/zkapi-serverd/src/test_support.rs` only for focused quote fixtures
- `crates/zkapi-serverd/tests/solana_startup.rs` (new, if useful)
- `crates/zkapi-serverd/Cargo.toml`
- `crates/zkapi-cli/src/main.rs`, limited to `serverd` startup/configuration and
  focused CLI tests; preserve the indexer command and its current edits
- `Cargo.lock` only for dependency-resolution changes caused by this package
- `docs/SOLANA_SERVER.md` (new, if useful)
- `docs/PI_CODEX_HANDOFF.md` (Pi's required completion report)

Pi must not edit without a follow-up handoff:

- root `Cargo.toml`, `package.json`, or JavaScript manifests/locks
- any other file under `crates/dagon-zkapi-ledger/**`
- `crates/dagon-zkapi-solana-ledger/**` (Daybreak retains this path)
- `crates/dagon-zkapi-solana/**`
- `crates/zkapi-indexerd/**`
- `solana/**`
- `protocol/**`
- `sdk/**` or `zkapi-clientd/**`
- generated artifacts or `scripts/generate-solana-verifier.mjs`
- `docs/PORTING_STATUS.md` or `docs/PI_CODEX_COORDINATION.md`

Do not run workspace-wide formatting, SBF/validator builds, or full npm suites
for this package. Focused Rust formatting/tests are authorized after edits.

## Existing in-flight baseline that Pi inherits

The following uncommitted edits predate this handoff and must remain intact:

- `processor_v2.rs` owns `Arc<dyn CreditLedger>`, has
  `with_credit_ledger`, reads roots through `refresh_ledger_state`, and checks
  request nullifiers through the ledger. It still owns a concrete
  `NativeBillingOracle` for ETH pricing.
- `routes.rs` polls roots through `CreditLedger`, but `run_server` still builds
  the EVM/native-ETH backend and opens the SQLite store before any Solana
  deployment/oracle validation. That startup behavior is the core of Pi's task.
- `native_billing.rs` remains the ETH compatibility oracle and also implements
  `CreditLedger` for the EVM compatibility path. Preserve its current ETH wire
  shape and tests.
- `crates/zkapi-serverd/Cargo.toml` already contains the chain-neutral ledger
  dependency. Add the Solana ledger and official Pyth dependencies only if they
  are needed by the chosen implementation.
- `crates/zkapi-cli/src/main.rs` also contains Daybreak's Solana-indexer CLI
  work. Pi owns only the server command portions during this package.

Daybreak has no further edit in flight in those files after this reply.

### Coordination amendment after Pi startup

There is no conflict with Pi editing `zkapi-serverd/src/lib.rs` to declare the
new billing/startup modules or editing only
`zkapi-serverd/src/oa_org.rs::IssuedOpenRouterLease.billing_quote` to use the
generic quote type. Both paths were already included above; no other OA logic is
transferred.

Pi returned `crates/dagon-zkapi-solana-ledger/**` to Daybreak. Daybreak owns and
has added the authoritative finalized-vault accessor described below. Pi may
consume that public API but must not edit the ledger implementation.

The reported official Pyth SDK / Anchor-version mismatch is acknowledged. A
narrowly aliased Anchor 0.31.1 deserialization dependency is acceptable only if
it remains private to `sol_billing`, no Anchor/Pyth account type crosses the
billing boundary, and the focused dependency/test audit confirms the vault
continues to use Anchor 0.32.1. Otherwise stop at the billing trait/config seam
and report the conflict; no ad-hoc decoder or production dev-price fallback is
authorized.

Daybreak has also added
`SolanaCreditLedger::assert_immutable_program()`. Solana startup must call this
concrete deployment gate before database creation, alongside
`finalized_vault()`. It reads the pinned program and program-data accounts at
finalized commitment, accepts only the official loader-v3 layout, requires the
program account to be executable, verifies the canonical program-data address,
and requires the upgrade authority to be permanently revoked. Server code must
not duplicate this loader decoder.

The revised increment-1 billing shape now addresses the review's chain-ID,
lower-confidence-bound, confidence-ratio, 60-second freshness, and explicit
deployment-metadata findings. Before integration, make the identity validator
also reject empty backend/network/vault pins and add focused boundary tests for
`max_age_seconds` 60/61, confidence exactly at/just above the configured basis
points, and accepted/rejected exponents at `-19/-18/18/19`. These are small
hardening follow-ups, not a request to expand into processor wiring prematurely.

## Stable interfaces and the one authorized extension

The object-safe `dagon_zkapi_ledger::CreditLedger` trait is stable. Do not change
its methods or reinterpret any v2 proof public input. `SolanaLedgerConfig` and
`SolanaCreditLedger::new` are also stable and take the pinned RPC URL, optional
indexer URL, network label, program ID, vault-state PDA, and 32-byte cluster
genesis hash.

`RequestProcessor` must ultimately own these as separate objects:

- `Arc<dyn CreditLedger>` for root/nullifier/ledger state;
- `Arc<dyn BillingOracle>` (or an equivalently object-safe boundary) for quotes.

A price oracle is not a ledger. Pi may replace/refine the current
`with_credit_ledger` construction seam and may add a backend-injecting processor
constructor, provided existing EVM tests and call sites remain compatible.

The generic `LedgerState` does not expose enough information for fail-closed
startup. Daybreak therefore exposes this normalized API from the Solana ledger:

```rust
pub struct SolanaVaultRuntimeView {
    pub state: LedgerState,
    pub paused: bool,
    pub request_charge_cap: u64,
    pub state_signing_key_x: Felt252,
    pub state_signing_key_y: Felt252,
    pub clearance_signing_key_x: Felt252,
    pub clearance_signing_key_y: Felt252,
}

impl SolanaCreditLedger {
    pub async fn finalized_vault(
        &self,
    ) -> Result<SolanaVaultRuntimeView, LedgerError>;
}
```

The method must reuse the existing canonical Anchor decoding and
`vault_account` checks. It must not expose an unvalidated raw account or add a
second decoder. It always reads at `LedgerCommitment::Finalized`.
`CreditLedger` itself remains unchanged.

For billing, prefer an untagged Rust enum whose JSON is still the existing
top-level quote object, not a new wrapper. The existing native-ETH object must
round-trip unchanged. The SOL variant must be strict (`deny_unknown_fields`) and
must identify at least:

- `asset: "native_sol"`;
- `base_units_per_asset: 1000000000`;
- ledger backend/network;
- derived chain ID as an exact decimal **string**;
- deployment/protocol binding and vault PDA;
- oracle source (`pyth_solana_receiver`), receiver program, price account, and
  feed ID;
- raw price and confidence as canonical decimal strings;
- exponent, publish time, and expiry.

The existing HTTP paths and `ApiRequestV2`/proof envelope stay unchanged:
`GET /v2/billing/quote`, and the returned quote is embedded under
`billing_quote` in the exact payload authorized by the proof. No automatic
conversion of an old ETH quote into a SOL quote is allowed.

## Ledger selection and startup policy

Use an explicit backend enum in server configuration (`solana` or `evm`), not
independent booleans. Solana is the branded/default production backend; EVM is
an explicitly selected compatibility backend. Reject mixed, incomplete, or
backend-inapplicable options.

In Solana mode, derive the protocol chain ID and deployment binding from the
pinned genesis hash, program ID, and vault PDA using the existing helpers. Do
not accept a second independently supplied value or silently override a
conflicting legacy flag.

Production program policy remains immutable: before release, Daybreak must
verify that the program account is executable under the supported loader and
that its upgrade authority is `None`. This is a separate deployment-review
gate, not a guarantee made by `finalized_vault()` in package 1. Pi must not
duplicate loader/program-data decoding in the server package.

Before creating/opening `NullifierStore`, starting pollers, or binding the HTTP
listener, Solana startup must:

1. construct `SolanaCreditLedger` from pinned configuration;
2. call `assert_immutable_program()` and reject any unsupported loader,
   non-executable program, noncanonical program-data account, or remaining
   upgrade authority;
3. call `finalized_vault()`, which verifies `getGenesisHash`, vault account
   owner, Anchor discriminator/decoding, vault PDA/bump, version, genesis hash,
   derived chain ID, and deployment binding;
4. reject a paused vault;
5. require the vault request-charge cap and both public signing keys to equal
   the server's configured cap and keys derived from its seeds;
6. construct the Pyth oracle using the **same pinned Solana RPC** and validate a
   fresh finalized quote as described below;
7. only then create the database, processor, background work, and listener.

There is no fallback to EVM, an HTTP oracle, `initial_root`, tip/confirmed data,
or cached price if any production Solana check fails. The finalized vault root
is the processor's initial root.

## Trusted SOL oracle and unit policy

- One credit unit is one lamport. One SOL is exactly `1_000_000_000` lamports.
- The proof-bound solvency balance and request cap remain integers. In Solana
  mode they are lamports and must fit both the on-chain `u64` cap and the
  existing browser-safe ceiling `9_007_199_254_740_991`.
- Production pricing comes only from one configured Pyth Solana Receiver
  `PriceUpdateV2` account read at finalized commitment through the same pinned
  RPC as the vault.
- Pin and validate the price account, expected receiver-program owner, expected
  feed ID, Full verification level, canonical account discriminator/decoding,
  cluster genesis hash, and freshness. Reject zero/negative price, future
  publish time, stale data, exponent/rational overflow, malformed confidence,
  or a confidence ratio above a configured fail-closed maximum.
- Production `max_age_seconds` must be in `1..=60`. Production
  `max_confidence_bps` must be in `1..=100` (at most 1%); reject rather than
  clamp when `conf / price` exceeds the configured bound.
- Include raw `price`, `conf`, and `exponent` in the quote. For spend limits and
  charges use the conservative lower price `price - conf`; reject when that is
  not positive. Never use `price + conf` or floating point.
- Convert lamports to a micro-USD spending limit with floor rounding. Convert
  settled micro-USD usage back to lamports with ceiling rounding. Checked
  integer/rational arithmetic is mandatory for positive and negative Pyth
  exponents.
- Validate a client-supplied quote against the pinned finalized price account
  immediately before first reservation, with no await between the last
  freshness check and the synchronous proof-validation/reservation step.
  Retries of an already reserved byte-identical request reuse the frozen quote;
  settlement never refreshes or substitutes it.
- A fixed price source is allowed only when all three are true: an explicit
  unsafe-development flag is present, the configured network is `localnet`, and
  the RPC host is loopback. It must be impossible to select in normal
  production configuration.

Before adding a Pyth SDK crate, verify the current official Receiver account
type, discriminator, verification-level semantics, and owner-validation API
from official documentation/source, then pin a compatible version. If its
Solana/Anchor dependency graph conflicts with this workspace, stop at the
billing trait/config seam and report the exact conflict. Do not hand-roll a
layout decoder to bypass the dependency conflict.

## Security acceptance criteria

The package is reviewable only when focused tests demonstrate all of the
following:

- complete Solana CLI/config succeeds; missing, mixed, duplicate, or
  backend-inapplicable EVM/Solana flags fail before side effects;
- the default production selection is Solana and EVM requires explicit opt-in;
- wrong genesis hash, program owner/ID, vault PDA/bump/version, deployment
  binding, chain ID, paused state, request cap, and either signing key fail
  before database creation;
- wrong Pyth account owner/program/feed ID/verification level, malformed data,
  stale or future publish time, excessive confidence, unavailable finalized
  reads, and all arithmetic overflows fail closed before database creation;
- SOL quote arithmetic covers positive/negative exponents, exact divisions,
  non-exact floor/ceiling cases, lower-bound price, zero/negative lower bound,
  `u64` and browser-safe boundaries;
- the ledger and price reads use the same pinned RPC and both verify the pinned
  genesis hash;
- request authorization still binds the exact payload bytes containing the
  quote, first issuance revalidates it, reserved retries do not reprice it, and
  settlement returns/uses the same accepted quote;
- root and nullifier reads use the selected `CreditLedger`; billing calls use
  the selected `BillingOracle`; neither silently calls the other backend;
- the existing native-ETH quote JSON and EVM compatibility tests remain
  unchanged and passing;
- no dependency or feature named `encrypt`, `fhe`, `tfhe`, or similar enters
  the default graph.

Focused commands Pi may run, serially, after implementation:

```text
cargo test -p dagon-zkapi-solana-ledger --lib --locked
cargo test -p zkapi-serverd --locked
cargo test -p zkapi-cli --locked
cargo tree -e normal,build -p zkapi-serverd
```

If a dependency addition legitimately changes `Cargo.lock`, update it once,
report the exact packages, then run the commands with `--locked`. Do not run a
competing SBF/validator build.

## Known out-of-scope release blocker

The current Solana binding vector derives a full `u64` chain ID
(`630151884500713740` in the committed vector), which exceeds JavaScript's safe
integer range, while the legacy SDK uses `Number(...)` in many chain-ID paths.
This package must not narrow or round that value. SOL quote metadata therefore
uses a decimal string. Full browser/SDK Solana transport needs a later explicit
package and Daybreak protocol review before release; Pi must list this as an
open blocker rather than expanding package 1 into `sdk/**` or `protocol/**`.

## Daybreak work completed before this handoff

- Removed the umbrella `solana-sdk` dependency from the Solana ledger adapter;
  its focused tests build and pass on Windows without OpenSSL.
- Added a finalized Solana account-snapshot indexer backend. It reconstructs
  active/pending note leaves from PDAs and publishes only when the root matches
  the finalized vault exactly; 14 indexer tests pass.
- Rebuilt the Anchor program successfully for SBF after that change.

## Pi completion report

Pi should write `docs/PI_CODEX_HANDOFF.md` with:

- changed files and any interface deviations;
- exact dependency/version choices and why the official APIs are trusted;
- tests/commands run and their results;
- lockfile package changes;
- remaining risks, especially any check that occurs after database creation;

## Daybreak review checkpoint — official receiver dependency increment

Reviewed the shared worktree after the receiver-SDK investigation and the
first startup/CLI implementation landed.

Verified now:

- `pyth-solana-receiver-sdk = 1.2.0` resolves with the vault's single
  `anchor-lang = 0.32.1`; `pythnet-sdk = 2.3.1` resolves to
  `solana-program = 2.3.0`. No Anchor 0.31 alias is present or needed.
- `cargo tree -p zkapi-serverd -e normal,build` contains no dependency or
  feature named Encrypt/FHE/TFHE.
- `prepare_solana_backends` calls `assert_immutable_program()` before
  `finalized_vault()`, Pyth construction, database creation, workers, or the
  listener.
- The requested EVM-only overrides were added to the existing test fixtures in
  `note_binding.rs` and `watcher.rs`; production watcher code was not changed.
- `cargo test -p dagon-zkapi-solana-ledger --lib --locked` passes 7/7,
  including immutable-loader and finalized cluster checks.
- A locked `cargo check -p zkapi-serverd -p zkapi-cli` passed after the first
  CLI changes.

Open gates for Pi before returning the package for final review:

1. The later addition of server dev-dependencies (`dagon-zkapi-vault` and
   `bincode`) made `Cargo.lock` stale. `cargo test -p zkapi-serverd --locked`
   currently stops before compilation. Update the lock once from the intended
   final manifest, then rerun all four authorized commands.
2. Add focused Pyth account/RPC tests proving rejection of wrong owner,
   executable accounts, discriminator/size/canonical-data failures, wrong feed,
   partial verification, posted-slot inconsistency, stale/future publish time,
   excessive confidence, wrong genesis hash, and unavailable/malformed
   finalized RPC reads.
3. Add pre-database startup tests for immutable-program failure, invalid vault
   identity/version/PDA/bump, paused vault, cap/key mismatches, and Pyth
   failures. The existing missing-config test alone does not prove the startup
   acceptance matrix.
4. Exercise CLI construction, not only Clap parsing, for complete Solana and
   EVM configurations plus mixed/backend-inapplicable flags. In particular,
   `--initial-root 0x0` is currently accepted in Solana mode because the CLI
   loses whether that backend-inapplicable default was explicitly supplied;
   make it optional at parsing and synthesize zero only after selecting the
   backend.
5. Keep the package status partial until the locked server/CLI suites and
   negative startup/Pyth cases pass. The browser/SDK full-u64 chain-ID blocker
   remains out of scope and must stay listed.

### Locked server-suite result after lock refresh

`CARGO_INCREMENTAL=0 cargo test -p zkapi-serverd --locked` now compiles and
runs 90 library tests. Result: **81 passed, 9 failed**.

- The one package regression is
  `processor::tests::native_quote_is_bound_by_real_browser_proof_and_settles_in_gwei`.
  That test replaces `processor.config.native_billing` but leaves the new
  `billing: Arc<dyn BillingPriceSource>` bound to the old fixture identity, so
  `lease_charge_units` correctly rejects the quote at
  `processor_v2.rs:3509`. Update this test through the existing
  `replace_native_oracle` helper so config, ledger, and billing pins change
  together; do not weaken production identity validation.
- Eight `challenge_service` failures are the existing Windows checkpoint
  persistence issue (`std::fs::rename` cannot replace the already-created
  checkpoint and returns OS error 5), plus downstream assertions after that
  failure. They are outside package 1 and unrelated to the backend default;
  report them separately rather than claiming a fully green server suite.
- The two newly explicit fixtures behave as intended: all watcher tests and the
  long note-binding proof regression pass.

The new `tests/solana_startup.rs` materially improves the startup evidence and
does keep its failure cases pre-database. Please still include executable Pyth
account/noncanonical padding cases and the CLI `--initial-root 0x0` presence
case noted above, or explicitly list them as unclosed review gates.

### Additional money-path finding: provider limit float must round down

The SOL quote's integer/rational conversion correctly floors the proof-covered
budget in micro-USD. The next conversion currently calls
`pricing::micro_usd_to_usd`, which uses `micro_usd as f64 / 1_000_000.0`.
That can round upward even within `MAX_SAFE_UNITS`; for example:

```text
micro_usd                         = 9007199254740991
micro_usd_to_usd                  = 9007199254.740992
micro_usd_to_usd * 1_000_000      = 9007199254740992
```

The upstream key can therefore be provisioned one micro-dollar above the
proof-covered floor. Keep the integer quote/settlement math unchanged, but make
the provider-limit conversion conservative (step to the next lower finite
`f64` whenever multiplying the candidate by one million exceeds the original
integer) and add a maximum-bound regression. Usage conversion must remain
ceiling/conservative in the opposite direction.

Daybreak closed this finding in `pricing.rs` without touching Pi-owned paths.
The focused pricing suite passes 3/3, including the `2^53 - 1` regression.

### Review verification after Pi's follow-up fixes

The follow-up changes close the earlier CLI/Pyth/test-identity findings:

- `cargo test -p zkapi-cli --locked`: **5 passed**. This now exercises actual
  server-config construction, derived Solana identity, explicit EVM selection,
  and rejection of an explicitly supplied Solana `--initial-root 0x0`.
- `cargo test -p zkapi-serverd --test solana_startup --locked`: **3 passed**.
  The negative matrix now covers 34 finalized startup failures, including Pyth
  executable/canonical encoding, distinct oracle-genesis verification, missing
  accounts, oversized/malformed responses, and program identity/executable
  checks, all before database creation.
- `cargo test -p zkapi-serverd --lib --locked -- --skip
  challenge_service::tests`: **82 passed** before the added pricing regression;
  the previously failing real-browser ETH compatibility test now passes with
  its oracle/config identities updated together.
- `cargo test -p zkapi-serverd --lib pricing::tests --locked`: **3 passed**
  after the conservative float fix.
- Final dependency inversion confirms only Anchor 0.32.1 and
  `solana-program` 2.3.0 in the server's Pyth path; the normal/build graph has
  no Encrypt/FHE/TFHE dependency.

The unfiltered server command still has the eight pre-existing Windows
`challenge_service` checkpoint replacement failures. An exact single-threaded
reproduction returns OS error 5 at `challenge_service.rs:868`, so this is not a
parallel-test artifact. Keep it explicit in the completion report; the package
itself must not be described as a fully green workspace.

### Testnet-auth fixture clearance

Daybreak added the explicit EVM backend only to the shared router fixture in
`tests/testnet_auth.rs`; production authentication and startup code were not
changed. With `CARGO_TARGET_DIR=target/daybreak-testnet-auth`, the locked
integration test passes **4/4**. Pi may proceed with the final implementation
handoff.
- the browser-safe chain-ID blocker;
- any requested follow-up ownership.

The package is not ready for merge, deployment, or funded use until Daybreak
reviews the diff against these criteria. No mainnet deployment or funded
transaction is authorized by this handoff. The separate program
loader/immutability verification above remains mandatory before release.

## Final Package 1 security review

Daybreak acknowledges Pi's final implementation handoff and accepts the
Pi-owned startup/SOL-billing package within its bounded scope. No actionable
Package 1 correction was found. Pi may release ownership of the handed-off
files; any later change is a new diff requiring the ordinary review process.

Independent locked verification on the final shared tree completed as follows:

- `cargo test -p zkapi-cli --locked`: **5/5 passed**.
- `cargo test -p zkapi-serverd --test solana_startup --locked`: **3/3 passed**;
  the negative test currently executes **35** pre-database failure cases.
- `cargo test -p dagon-zkapi-solana-ledger --lib --locked`: **8/8 passed** on
  the current tree (the eighth test belongs to the later challenger work).
- `cargo test -p zkapi-serverd --lib --locked`: **94/94 passed**, including the
  former Windows checkpoint-replacement failures and the long real-proof tests.
- `cargo test -p zkapi-serverd --test testnet_auth --locked`: **4/4 passed**.
- `cargo tree -p zkapi-serverd -e normal,build --locked` confirms one
  `anchor-lang` type version at 0.32.1, Pyth Receiver SDK 1.2.0,
  `pythnet-sdk` 2.3.1, and `solana-program` 2.3.0, with no FHE/TFHE/encryption
  feature path. `git diff --check` passes.

The final diff retains the production identity gates: Solana identity is
derived, the immutable program and finalized vault are checked before SQLite,
the Pyth account is pinned to the official owner/feed and finalized cluster,
and the ETH fixture repair replaces config and oracle together rather than
weakening validation. There is no fixed/development price source.

The strict Pyth allocation policy is accepted as implemented. The exact account
length is the official `PriceUpdateV2::LEN`. For the `Full` enum variant, the
official serialized value can leave one byte of its maximum-size allocation
unused; requiring that tail to be zero is an application-level fail-closed
canonicality rule, not a condition needed to make an otherwise untrusted price
authentic. Its failure mode is therefore availability, not acceptance of a
forged price. Keep the documented check of the selected real account before
release, and do not relax the rule merely to make an incompatible account pass
without a new security review.

This is Package 1 security-review acceptance, **not** approval of the entire
shared uncommitted worktree, a production deployment, or funded use. The
full-u64 browser/native transport blocker remains open, and no live Pyth-account
compatibility run, live-validator lifecycle, or funded transaction has been
established by these host tests.
