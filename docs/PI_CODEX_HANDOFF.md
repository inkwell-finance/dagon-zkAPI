# Pi implementation handoff — server startup / SOL billing package

Status: **Package 1 accepted by Daybreak's security review** in
`docs/CODEX_PI_REPLY.md`, section "Final Package 1 security review". Pi has
released the package's production-file ownership. This is not approval of the
entire shared worktree, production deployment, or funded use.

Post-handoff evidence below is reported by Daybreak in `docs/PORTING_STATUS.md`,
not independently rerun by Pi during this documentation reconciliation:

- The later challenger/checkpoint work fixed the eight Windows replacement
  failures; the server library passed 94/94 at that review checkpoint.
- `zkapi-challenged` defaults to Solana and uses canonical pending-escape
  discovery, prepared challenges, restricted signing and durable recovery.
- Subsequent wallet transport work preserves full-u64 chain IDs as decimal
  strings and includes durable staged-operation journals. The original transport
  blocker recorded in this handoff is no longer listed as open in port status.
- Port status records 323/323 SDK tests, 57 protocol tests, root workspace tests,
  a fresh SBF build, and a 406.86-second fresh local-validator money lifecycle.

Pi independently rechecked the later shared tree during reconciliation:

- Locked CLI tests: **5/5 passed**.
- Locked Solana startup tests: **3/3 passed**, including the 35 negative cases.
- `node scripts/sync-sdk-assets.mjs --check`: **passed**.
- `node scripts/generate-solana-verifier.mjs --check`: **passed**.
- `git diff --check`: **passed**.

The detailed command results below remain the historical evidence for Pi's
bounded startup/billing package; they do not claim review coverage of every
later change.

## Implemented

- Solana is the default server backend; EVM compatibility requires explicit
  selection. CLI parsing and a side-effect-free config-construction helper reject
  missing/mixed/backend-inapplicable inputs. Even explicit `--initial-root 0x0`
  is rejected in Solana mode; chain ID/binding are derived, not separately supplied.
- Solana CLI requires explicitly supplied signing seeds (flags or environment),
  not silent public development defaults.
- Server startup constructs `SolanaCreditLedger`, calls its finalized immutable
  program gate and authoritative finalized-vault view, rejects paused/cap/key
  mismatches, and authenticates a fresh finalized Pyth quote **before SQLite,
  background work, or listener binding**. No ETH/tip/indexer-root/cache/dev-price
  fallback exists. The finalized vault root initializes the processor.
- Processor now owns separate `Arc<dyn CreditLedger>` and
  `Arc<dyn BillingPriceSource>` objects. Backend-injecting construction preserves
  the explicit EVM compatibility constructor and existing lease state machine.
- Generic untagged `BillingQuote` preserves legacy ETH JSON verbatim. SOL quotes
  identify native SOL/lamports, backend/network/vault, deployment binding,
  pinned Pyth receiver/account/feed, raw integer price/confidence/exponent,
  publication/expiry/posted slot. SOL chain ID is an exact decimal **string**.
- Official Pyth account adapter checks cluster genesis, strict JSON-RPC identity,
  bounded response bodies, finalized account owner/executable/encoding,
  discriminator/allocated size/canonical official serialization and padding,
  Full verification, feed, posted slot, future/stale time, confidence and price.
- SOL arithmetic uses `price - confidence`, floor budgets and ceil charges,
  canonical positive i64 prices, checked rational arithmetic, exponent range
  [-18,18] and browser-safe bounds. Age is 1..=60 seconds and confidence is
  1..=100 bps. Settlement uses the accepted quote, not a refreshed price.
- First issuance validates submitted quotes against the finalized pinned source;
  freshness is rechecked after I/O and at synchronous proof/reservation. Existing
  byte-identical reserved retries and settlement retain the frozen quote.
- Existing real-proof ETH quote binding/settlement regression remains passing.

## Pi-changed files

- `crates/zkapi-serverd/src/config.rs`
- `crates/zkapi-serverd/src/native_billing.rs` (preserved the earlier ledger adapter)
- `crates/zkapi-serverd/src/native_billing/billing.rs` (new)
- `crates/zkapi-serverd/src/sol_billing.rs` (new)
- `crates/zkapi-serverd/src/processor_v2.rs`
- `crates/zkapi-serverd/src/routes.rs`
- `crates/zkapi-serverd/src/lib.rs` (new module declaration only)
- `crates/zkapi-serverd/src/oa_org.rs` (response quote type only)
- `crates/zkapi-serverd/tests/solana_startup.rs` (new)
- `crates/zkapi-serverd/Cargo.toml`
- `crates/zkapi-cli/src/main.rs` (server/config/tests; preserved indexer behavior)
- `Cargo.lock` (package dependency resolution, preserving the uncommitted port)
- `docs/SOLANA_SERVER.md` and this report

Focused formatting was limited to package-owned files, not the workspace.
No commits, reset, stash, artifact generation, funded transaction or deployment
were performed. The shared worktree still contains Daybreak's uncommitted port.

## Daybreak contributions during this handoff

Daybreak provided `finalized_vault()` and `assert_immutable_program()` and retained
ownership of their implementations. Daybreak also updated EVM-only fixtures in
`note_binding.rs`, `watcher.rs`, and `tests/testnet_auth.rs`; Pi did not edit those
out-of-scope files. Daybreak found/fixed conservative provider-limit f64 rounding
in `pricing.rs`, including the `2^53 - 1` regression. These should not be
attributed to Pi's implementation diff.

## Dependency choices and audit

New server production edges:

- `dagon-zkapi-solana-ledger` (existing local port crate)
- `pyth-solana-receiver-sdk = 1.2.0`
- `anchor-lang = 0.32.1`
- `solana-program = 2.3.0`
- `bs58 = 0.5.1`

New fixture/dev edges: local `dagon-zkapi-vault` with `no-entrypoint` and
`bincode = 1.3.3`.

Official SDK 1.2.0 depends on Anchor 0.32.1, matching the vault, and
`pythnet-sdk` 2.3.1. The SDK uses official `PriceUpdateV2::owner`,
`AccountDeserialize`/`AccountSerialize`, and `VerificationLevel` APIs privately
inside `sol_billing`; no Pyth/Anchor account type crosses the billing boundary.
No hand-written decoder or older-Anchor alias was used.

An isolated SDK 1.0.1 probe initially failed with Borsh 0.10/1.x trait mismatches
because pythnet's broad Anchor range selected Anchor 1.2.0. Published SDK 1.2.0
resolved that issue; its isolated check passed. The root lock initially selected
an unnecessary Solana 5.1.0 branch through pythnet's broad range, then was
constrained to the tested Solana 2.3.0 graph and refreshed for final dev edges.
Later commands use `--locked`.

Verified tree: one Anchor 0.32.1 in the server/Pyth/vault path, pyth receiver
1.2.0, pythnet 2.3.1, Solana program 2.3.0. No Encrypt/FHE/TFHE dependency or
feature in the normal/build graph. The SDK adds its ordinary number/math,
serialization and Solana-program transitive dependencies. The large whole-lock
Git diff includes Daybreak's already-uncommitted Solana port and must not all be
attributed to this package; exact resolved versions are in `Cargo.lock`.

Primary provenance:
https://github.com/pyth-network/pyth-crosschain/tree/main/target_chains/solana/pyth_solana_receiver_sdk
and official downloaded crates/normalized manifests for 1.0.1, 1.2.0 and 2.0.0.
Latest SDK 2.0.0 requires Anchor 1.0.2; it is not used here.

## Tests and commands

After shared-target artifact contention, Pi jobs used
`CARGO_TARGET_DIR=target/pi-server-build CARGO_INCREMENTAL=0` to avoid competing
with Daybreak's build artifacts. Commands were serialized.

- `cargo test -p zkapi-cli --locked`: **5/5 pass**, including actual complete
  Solana/EVM construction, derived identity, missing/mixed/duplicate flags and
  explicit Solana initial-root rejection.
- `cargo test -p zkapi-serverd --test solana_startup --locked`: **3/3 pass**;
  one test loops **35 pre-database negative cases**. Covers immutable-program
  executable/owner and unrevoked upgrade-authority checks, genesis (including an independently wrong Pyth RPC
  genesis after successful ledger checks), vault version/PDA/bump/binding/chain/
  paused/cap/keys, Pyth owner/executable/size/discriminator/padding/encoding/feed/
  partial verification/posted slot/stale/future/price/confidence/exponent, missing
  account, malformed RPC identity, unavailable reads and oversized response.
  Successful preflight and authenticated quotes are checked without opening DB.
- `cargo test -p dagon-zkapi-solana-ledger --lib --locked`: **7/7 pass**, including
  Daybreak's immutable-loader and normalized finalized metadata tests.
- `cargo test -p zkapi-serverd --lib --locked` filtered to the real-browser ETH
  quote-binding test: **1/1 pass**. Its config replacement now calls the existing
  oracle replacement helper; production identity checks were not weakened.
- `cargo test -p zkapi-serverd --locked -- --skip challenge_service::tests::`:
  **82/82 library tests pass**, including long real-proof watcher/note-binding
  tests; **3/3 new startup tests pass**. That run then identified the four
  testnet-auth fixtures inheriting the Solana default. Daybreak supplied their
  explicit EVM selection; a subsequent locked `--test testnet_auth` run is
  **4/4 pass**.
- After Daybreak's extra pricing regression, locked `--lib pricing::tests`:
  **3/3 pass**. The library count therefore increases by one; do not confuse
  the earlier 82 count with a later full-suite result.
- `cargo tree -e normal,build -p zkapi-serverd --locked`: inspected; no FHE path.
- `git diff --check`: passes.

An unfiltered Pi server sweep hit a 180-second timeout while long proof and known
Windows checkpoint tests were still running. Daybreak separately completed the
unfiltered suite, reproducing the eight upstream challenge-service OS error 5
checkpoint-rename failures. Those were not modified or hidden by this package;
at handoff time the workspace was therefore not fully green. The post-handoff
update at the top records their later resolution.

## Current review/release gates

- Daybreak accepted the bounded Package 1 diff. Later changes require their own
  review; this acceptance does not cover the entire shared release candidate.
- Windows checkpoint persistence and full-u64 wallet transport were resolved in
  subsequent work, as recorded in `docs/PORTING_STATUS.md`.
- Pi's Package 1 tests used mock vault/Pyth accounts. Daybreak subsequently
  reports a fresh SBF/validator lifecycle; it does not prove compatibility with
  a selected live Pyth account or authorize production deployment.
- A real deployment still requires explicit acceptance/replacement of the two
  single-party Groth16 setups, operator secrets and finalized deployment/oracle
  pins. No mainnet deployment or real-money transaction is authorized here.
- Strict unused Pyth allocation padding must be checked against the selected
  real account before release; nonzero unused padding currently fails closed.
- Existing provider/proof-setup construction failures can still occur after DB
  opening; all Solana deployment and oracle checks above occur before it. This
  does not claim transactional rollback of every unrelated startup failure.
- The current wire shape has explicit production-only Pyth pins; there is no
  fixed/dev oracle implementation. No dev-price exception can activate silently.

Next action: coordinate a new bounded implementation task if Daybreak identifies
one. Package 1 is closed; do not infer continuing ownership of its production
files from this historical report. External production decisions remain with the
operator.
