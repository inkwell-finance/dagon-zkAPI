# Solana vault -> serverd -> vcii lease (end-to-end scenario)

`scripts/solana-vcii-lease.mjs` is the Solana counterpart of `scripts/v2-vcii-lease.mjs`: deposit native SOL into the
Solana vault, prove, have `dagon-zkapi serverd --ledger solana` mint an OpenRouter-style lease through vcii's management API
(`POST /zk/v1/keys`), pay for an MCP `tools/call` with the `vcii_zk_` key, let serverd settle the note with vcii's measured
usage, and confirm the key is refused afterwards.

## What is real and what is mocked

Real: `solana-test-validator` (Agave 3.1.11, loopback), the actual `dagon-zkapi-vault` SBF program made immutable with
`solana program set-upgrade-authority --final`, `Initialize`, a native-SOL deposit (Solana Merkle-transition Groth16 proof
verified on chain), the finalized-account indexer (`dagon-zkapi-indexerd --ledger solana`), request Groth16 proofs, serverd's
full Solana startup (immutable-program gate, genesis pin, finalized vault read, finalized Pyth read), vcii lease
provisioning/usage/settlement, the wallet accepting the server-signed settlement.

Mocked: the Pyth SOL/USD account. `solana/dev/mock-pyth-writer` is a ~20-line program loaded at the Pyth receiver program ID
(`rec5EKMG...`) that copies instruction data into an account it owns. The harness fills the pre-created account at
`7UVimffx...` (Pyth's SOL/USD shard-0 address) with an official-SDK-serialized `PriceUpdateV2` (Full verification, the real
SOL/USD feed ID, correct length and zero padding) at `$150.00 +/- $0.01` (random walk of +/-20 bps), refreshed every 400 ms (random walk, see below) with the current
time and a finalized `posted_slot`. No Wormhole/guardian verification and no real market price. A static clone of the real
account cannot work because serverd allows at most 60 s of price age.

## Running it

Needs Linux with Node 24, Rust, and Agave (`solana-test-validator`, `solana`, `cargo-build-sbf`), and a vcii dev server whose
`ZK_MANAGEMENT_KEY_SHA256` matches `VCII_ZK_MANAGEMENT_KEY` (`ZK_USD_PER_CREDIT=1.5`, `ZK_MAX_LEASE_USD>=2`). The recipe used
under Podman (`localhost/zk3-e2e` plus Agave v3.1.11 from the anza release tarball, `--network host` on a mirrored-network
WSL machine so `127.0.0.1:8813` reaches the Windows dev server):

```sh
# 1. SBF programs (the vault and the mock oracle writer)
(cd solana && cargo-build-sbf --manifest-path programs/dagon-zkapi-vault/Cargo.toml --sbf-out-dir /target/sbf)
(cd solana/dev/mock-pyth-writer && cargo-build-sbf --sbf-out-dir /target/sbf)
# 2. host binaries (the wallet helper is the crate crates/zkapi-solana-wallet; its `dev` feature adds the validator-only
#    commands this harness uses, a release build has none of them)
cargo build --locked --release --target-dir /target/sol-host -p zkapi-cli --bin dagon-zkapi \
  -p zkapi-indexerd --bin dagon-zkapi-indexerd -p zkapi-solana-wallet --features zkapi-solana-wallet/dev
# 3. scenario: the Rust helper plays the client (default), or zkapi-clientd does everything (see below)
VCII_ZK_BASE=http://127.0.0.1:8813/zk VCII_ZK_MANAGEMENT_KEY=... node scripts/solana-vcii-lease.mjs \
  --bin-dir /target/sol-host/release --sbf-dir /target/sbf --key-dir /scratch/keys --output-dir /scratch/runs
```

The container must run with `--security-opt seccomp=unconfined --ulimit memlock=-1:-1`: Agave 3.x asserts `io_uring` support
when creating its accounts directories and the default Podman seccomp profile blocks it.

`--key-dir` holds three throwaway keypair files (payer, deployer, mock-Pyth updater); only public keys are printed.

## Things worth knowing (found while building this)

- **Immutability gate vs `solana-test-validator`.** `--upgradeable-program <id> <so> none` does not produce an immutable
  program: the program-data account stores `Some(11111111111111111111111111111111)`, so serverd's startup gate correctly
  refuses it ("still has an upgrade authority"). The harness deploys with a real authority and revokes it with
  `set-upgrade-authority --final`.
- **`Initialize` compute budget.** One of four fresh validators ran `Initialize` out of the default 200,000 units (genesis hash
  influences the work). Clients should request the 1.4M units / 128 KiB heap the ledger's own transactions use; the helper does.
- **u64 chain IDs.** The derived Solana chain ID usually exceeds 2^53 and the Rust public-input structs serialize it as a JSON
  number. A JS client that `JSON.parse`s and re-sends the request rounds it and serverd answers `protocol_mismatch`. The
  browser SDK's WASM layer stringifies it; the Node helper does the same.
- **Quote supersession and `native_quote_stale`.** The quote is bound into the proof (it is part of the signed payload), so
  a ~13 s proof is always made against a quote that is no longer the latest finalized Pyth publication. serverd used to
  answer such a lease with a non-retriable `409 native_quote_superseded`, which a feed publishing every few hundred ms
  would trigger on essentially every lease. It now verifies the proof against the QUOTED price (unchanged) and then compares
  the latest finalized publication: the lease is accepted if the quote is one this server itself read from the finalized
  feed (an invented price inside the tolerance is refused), is within the price-age limit (`--pyth-max-age-seconds`, at
  most 60 s), and the latest lower-bound price (price minus confidence, what billing converts with) has not fallen more than
  `--native-quote-tolerance-bps` (default 50) below the quoted lower bound. A price rise only favours the server. Anything
  else is `409 native_quote_stale`, `retriable: true`, nothing reserved: re-quote and prove again. The browser SDK does this
  (up to 4 attempts); the harness does it explicitly. The exposure per lease is bounded by the tolerance because the USD
  budget and the settlement conversion stay a deterministic function of the proof-bound quote (the client and the recovery
  paths re-derive them). zkapi-clientd now does the same for Solana (see "zkapi-clientd as the client" below); its native-ETH
  retry list is unchanged.
  The harness now refreshes the mock feed continuously (`--refresh-ms`, default 400) as a bounded random walk (+/-20 bps),
  and `--scenario jump` drops the price 2% mid-proof to exercise the stale -> re-quote -> re-prove path.
- The finalized indexer lags the chain by roughly 15 s (about 32 slots); the harness polls instead of sleeping.

## Applying the quote-tolerance change onto the Solana-port work in progress

The serverd/CLI/SDK part of the fix edits files that are still uncommitted in the Solana port, so it is not committed as
source here. `patches/native-quote-tolerance.patch` is a unified diff (paths relative to the repo root, `-p1`) of only that
change against the working tree it was made on. Apply it on top of the port:

```sh
git apply --check patches/native-quote-tolerance.patch && git apply patches/native-quote-tolerance.patch
```

It touches `crates/zkapi-serverd/src/{sol_billing,error,routes,processor_v2}.rs`, `crates/zkapi-serverd/tests/solana_startup.rs`,
`crates/zkapi-cli/src/main.rs`, `sdk/services/browserWalletRuntime.js`, `sdk/test/browser-wallet-lease-retry.test.mjs` and
`docs/SOLANA_SERVER.md` (new flag `--native-quote-tolerance-bps`, new `PythBillingConfig::quote_tolerance_bps` field, new error
`NativeQuoteStale`/`native_quote_stale`). Tests: `cargo test -p zkapi-serverd -p zkapi-cli` and
`node --test sdk/test/browser-wallet-lease-retry.test.mjs`.

## Applying the SDK native-SOL schema fix

`sdk/services/zkapiNativeSol.mjs` (owner WIP, uncommitted) validated quotes against a schema serverd never emitted
(`source: 'pyth_receiver'`, `published_at`, `price_account`), so it rejected every real quote, and `sameSolanaQuote`
compared the same wrong keys, which made the lease/receipt quote-equality check vacuous. `patches/sdk-native-sol-schema.patch`
fixes it to serverd's `SolanaBillingQuote` (`pyth_solana_receiver`, `publish_time`, `feed_account`, exact key set, numeric
Felt252 comparison because serverd strips leading zeros) and adds `sdk/test/helpers/serverd-solana-quote.json` plus tests in
`sdk/test/native-sol.test.mjs` that also read the Rust struct to catch future drift.

Order matters: apply it AFTER `patches/native-quote-tolerance.patch` (it was generated against a tree that already has that
patch; the two touch disjoint SDK files, so either order applies cleanly, but the baseline assumed is tolerance-applied):

```sh
git apply patches/native-quote-tolerance.patch
git apply --check patches/sdk-native-sol-schema.patch && git apply patches/sdk-native-sol-schema.patch
node --test sdk/test/native-sol.test.mjs
```

Two more patches follow the same rule (they edit files that are still uncommitted in the port; apply them after the one above,
in this order; `git apply --check` first):

- `patches/solana-wallet-workspace.patch`: `Cargo.toml` (adds `crates/zkapi-solana-wallet` to the workspace) and `Cargo.lock`
  (its package entry), so `cargo build --locked -p zkapi-solana-wallet` works. The `Cargo.toml` hunk has mixed CRLF/LF context,
  which the patch preserves; apply it with `git -c core.autocrlf=false apply` (plain `git apply` works too on a checkout that
  has the same endings).
- `patches/serverd-live-lease-usage.patch`: `GET /v2/openrouter/leases/{id}` now also answers `observed_usage_usd`, the issuer's
  live reading of a still-active direct OpenRouter key (`processor_v2.rs`: `openrouter_lease_status_live`, `routes.rs`; the
  response field is in `protocol/rust/crates/zkapi-types/src/wire.rs`, which is clean and committed directly). Until now the
  endpoint only reported `usage_usd` after retirement, so a client could not see usage while a key was open. It is advisory:
  settlement still reads the final usage at retirement, and a failed issuer read just omits the field. Test:
  `cargo test -p zkapi-serverd --lib active_lease_status`.

The harness, the wallet helper crate and this document are committed directly.

## zkapi-clientd as the client (`--client clientd`)

`zkapi-clientd` (the Go client daemon) has a native-SOL profile that follows the browser SDK's lease flow
(`sdk/services/browserWalletRuntime.js`): quote -> prove -> lease -> settle, with the SDK's bounded `native_quote_stale` retry.
It is a separate network next to `mainnet`/`sepolia`: `network: "solana"` plus a pinned deployment in `config.json`
(`zkapi.solana`: serverd and indexer origins, cluster label, program ID, vault state PDA, genesis hash, derived chain ID and
protocol binding, the vault's state/clearance signing keys, the vault's per-request cap as the minimum lease, the Pyth feed
identities and bounds, the lease provider base). It never starts the Ethereum `zkapi-walletd` companion.

Division of labour: Go owns durable state and the network protocol; every proof, note transition and Solana transaction is
built and signed by the same Rust code as the SDK (`zkapi_browser::prepare_request_with_prover` / `complete_response` /
`confirm_deposit` / `prepare_withdrawal`, and `SolanaCreditLedger` for the vault transactions), reached through the wallet helper
`crates/zkapi-solana-wallet` (binary `zkapi-solana-wallet`; stdin/stdout JSON, one process per operation, empty environment, no
stderr kept; details and release notes in its `README.md`). The helper started as the `solana_acceptance_wallet` example of
`zkapi-serverd`; it moved into its own crate, and the test-only commands (keygen, airdrop, vault initialization, the mock Pyth
writer) live behind its `dev` feature.

```sh
zkapi-clientd solana init --deployment deployment.json --prover ./zkapi-solana-wallet --prover-sha256 <digest> \
    --proof-setup-dir protocol/setup/v2 [--rpc-url URL] [--settle-idle-seconds 900]   # verifies the chain, then saves the profile
zkapi-clientd solana verify                                       # re-run the on-chain verification any time
zkapi-clientd solana deposit --keypair ~/.config/solana/id.json --sol 1 --confirm
zkapi-clientd serve                                               # loopback management API; settles leases, recovers funding
zkapi-clientd lease export --usd 2 --confirm                      # key on stdout, once
zkapi-clientd lease status                                        # open lease timing, usage and idle deadline, never the key
zkapi-clientd lease settle --confirm                              # close the key now and install the signed receipt
zkapi-clientd solana withdraw --to <address> --all --confirm      # close the note, pay its whole balance to <address>
zkapi-clientd solana status                                       # offline: balance, pending deposit/withdrawal/lease
zkapi-clientd solana import-wallet --file wallet-export.json      # alternative to deposit: adopt a note made elsewhere
```

### Packaging and pinning the helper

`cargo build --locked --release -p zkapi-solana-wallet` (or `scripts/build-solana-wallet.sh [--verify]`, a Containerfile build
with a digest-pinned toolchain, remapped paths and stripped symbols; `--verify` builds twice from scratch and requires identical
bytes) produces `zkapi-solana-wallet`, versioned by its crate version (`--version`) and by a command-protocol number
(`PROTOCOL`, now 1). The profile pins the binary's SHA-256 (`prover_sha256`; required whenever `prover_binary` is set, so `solana
init` without `--prover-sha256` stops and prints the digest of the file to compare with the release notes). Before every run
clientd resolves the binary to one absolute path, hashes and executes that same file, and refuses a different one (`solana_prover_hash_mismatch`); its first command is `handshake`, and it
refuses a helper that is not `zkapi-solana-wallet`, speaks another protocol (`solana_prover_protocol_mismatch`) or is a `dev`
build outside a `localnet` profile (`solana_prover_dev_build`). The helper's error text is never shown (it can echo protocol
values); only a closed set of codes (`stale_root`, `blockhash_expired`, ...) reaches the client. The hash is checked at spawn,
not on an open file descriptor, so it guards against a swapped or upgraded binary, not against an attacker who can rewrite the
binary and the profile in the same instant (they could change the pin too).

### On-chain verification (`rpc_url`)

`rpc_url` (HTTPS or numeric-loopback HTTP, no credentials or query; the pinned RPC) is part of the profile.
`zkapi-clientd solana init`, `solana verify`, `serve` at startup, and every deposit and withdrawal read the chain through it at
finalized commitment and refuse on any difference (`ChainMismatchError`, "on-chain verification failed: ...; refusing to use this
deployment"). This mirrors the browser SDK's `assertSolanaVault` and adds the vault's keys and cap:

- `getGenesisHash` equals the pinned genesis hash (again after the reads: the RPC cannot change cluster mid-check);
- the vault state account exists, is owned by the pinned program, is not executable, has the vault program's canonical layout
  (343 bytes, Anchor discriminator), version 1, is not paused, carries the pinned genesis hash, chain ID and protocol binding,
  the pinned state and clearance signing keys, and a per-request cap equal to `min_lease_lamports`;
- the program account is an executable loader-v3 (upgradeable loader) program and its program-data account has no upgrade
  authority (`Some(..)` is "can still be upgraded"): the code can never change. On a local validator the harness finalizes the
  authority with `set-upgrade-authority --final`; `solana-test-validator --upgradeable-program ... none` is not enough (see above).

The PDA derivation of the vault address is not recomputed (the SDK does not either: the binding already commits to program,
vault and genesis). `zkapi-solana-wallet` independently checks the RPC's genesis hash when it connects. The helper's RPC calls
are direct (not through `relay_url`): the funding transactions are public anyway, but the RPC provider sees the client's address.

### Funding: deposit and withdrawal

`solana deposit` and `solana withdraw` run in the CLI process while no daemon holds `daemon.lock`; with `serve` running they ask
the daemon (`/admin/solana/deposit`, `/admin/solana/withdraw`, behind the same API key and management token as `lease export`),
because the daemon owns the wallet file in memory. Both journal everything in the wallet file (0600, atomic replace + fsync), so
a crash at any point is recovered from the chain, by running the same command again or by `serve` (which resolves unfinished
funding at start and in the background, without needing the keypair unless a transaction still has to be signed):

| step | durable before it happens | after a crash |
| --- | --- | --- |
| deposit: generate note secret and commitment | the secret, commitment, amount and payer, **before anything touches the chain** | the same secret is reused, never a second one |
| deposit: prepare the staged operation (transition proof, buffer + execute transactions) | the unsigned operation and the expected note ID | re-signed deterministically |
| deposit: sign | the exact signed bytes | re-sent as they are (idempotent: a transaction that landed is skipped, never signed or sent twice) |
| deposit: land and finalize | - | the finalized note account decides: ours (commitment and amount match) -> install the note from the chain's expiry; someone else's, a failed or expired transaction -> the operation is cancelled (a durable cancellation journal retains the buffer ID and exact signed bytes until finalized or explicitly absent; malformed RPC responses are errors) and a fresh one is prepared for the same secret |
| withdrawal: intent | the destination, note, withdrawal nullifier, amount, fee payer, **before clearance is requested**; from here the note is frozen: leases refuse it (`withdrawal_pending`), so a note is never spent twice | |
| withdrawal: server clearance | the signed clearance (`POST /v2/withdraw/clearance`; idempotent for the nullifier) | reused |
| withdrawal: close proof, staged close transaction, signature | the proof, the operation, the signed bytes | a stale tree root re-proves from a fresh indexer snapshot; an expired blockhash discards proof and operation (the clearance stays) |
| withdrawal: land | - | the used-nullifier account on chain decides; then the note account must be gone, and the note state is cleared |

Both operations check the chain first (above), the funding keypair's balance (amount plus 0.05 SOL of fees and refundable rent;
withdrawal: 0.05 SOL), and refuse a deposit while a lease, deposit or withdrawal is unfinished. The vault closes a note as a
whole, so there are no partial withdrawals: `--all`, or `--sol N` with N equal to the whole balance, otherwise a clear refusal
(withdraw everything and deposit the remainder again). The destination receives the note's remaining balance plus the rent of
the closed note account (0.00154512 SOL), so even a fresh address can receive a small note. The transaction fee payer of a
withdrawal is the funding keypair (`--keypair`, remembered from the deposit). `sign_operation` in the helper refuses to sign anything but the pinned vault's own instructions, paid by that keypair.
The exported lease path and funding share one wallet slot, so a withdrawal waits for an open lease to settle (`lease settle` ends
it at once). Only the mutual close (server clearance) exists; escape withdrawals and `claim-expired` are not implemented.

### Settlement timing

A lease settles when its `settle_after` passes, on `lease settle --confirm`, and now also early, by the daemon:

- **limit used up**: the key's usage has reached its spending limit (`spending_limit_usd`), so it can buy nothing more;
- **idle**: no new usage for `settle_idle_seconds` (profile field, default 900 = 15 minutes; `0` disables idle settlement;
  `solana init --settle-idle-seconds`). Idle time counts from the last time the usage grew as the daemon observed it (from
  issuance for a key that is never used); a key in active use keeps pushing the deadline out, so it is not settled under its
  user. The idle clock is stored in the wallet file, so a restart keeps it. Older wallet files without an activity timestamp start a full conservative idle period at the first valid poll. Regressing or oversized readings and unknown lease states cannot authorize early retirement. `lease status` shows `lease_usage_usd` and `idle_settle_at`.

The daemon polls serverd's lease status (`observed_usage_usd`, see `patches/serverd-live-lease-usage.patch`) about every
`min(30s, idle/4)`. If the reading is missing or invalid, or serverd is unreachable, nothing is settled early: the lease stays
open until `settle_after`. Caveat: the issuer's usage can lag the real calls, so keep the idle period well above that lag (the
15-minute default does); an exported key that is never used is settled after one idle period, and is then refused.

Lease flow in `ExportLease` (`zkapi-clientd/internal/zkapi/solana_wallet.go`):

1. Recover first. A journal left by a crash or an unknown outcome is resolved (lease status, nullifier lookup, the
   `/expire` handshake) before anything new is proved. A wallet with an unresolved request answers `lease_pending`.
2. Check serverd's attestation against the pinned chain ID, binding and signing keys; read and validate the quote (field-by-field
   against the pins, 60 s age bound, confidence bound); convert the cap to lamports (ceil on the price minus confidence);
   refuse below the vault minimum or above the balance.
3. Prove, then write the journal (the full prepared request, secret-bearing) to the wallet file with fsync + rename BEFORE the
   POST. The exported key is never written anywhere.
4. On `409 native_quote_stale` with `retriable: true`: ask `POST .../expire` (serverd answers under its issuance lock whether
   the request was never accepted; while the quote could still be accepted it answers `lease_pending` and the client waits for
   the quote to expire). Only a confirmed `superseded_unaccepted`/`expired_unaccepted` clears the journal and starts a new
   round with a fresh quote, a fresh request ID and a fresh proof; at most 4 rounds (`native_quote_stale` afterwards). The same
   proof is never sent twice. Any other failure (timeout, 5xx) keeps the journal: the outcome is unknown and recovery decides.
5. Verify the 201 lease against what was proved (quote, spending limit in micro-USD, provider base, `key_source` must be
   `openrouter`); record its expiry/settle times durably; only then return the key. A lease failing the checks is retired at once.
6. Settlement: at `settle_after` (or `lease settle`) retire through `POST /v2/openrouter/leases/{id}` (retrying only
   `lease_settlement_pending`-style refusals), fetch `/v2/requests/{id}`, require the settled payload's quote to equal the proved
   quote, let the helper verify and apply the signed transition, then replace the note and clear journal and lease in one atomic
   write. A restarted daemon never retires a key whose settle time has not come (it may be in use); it retires an open key that
   was lost before it was handed out.

The wallet file is `<config-dir>/zkapi/solana/<vault-state>/wallet.json` (0600). It stores private note state, funding and request recovery records,
lease timing, and a public funding history.

`--client clientd --clientd-bin PATH` makes zkapi-clientd the whole client; the harness only creates the vault (with the dev
helper) and runs the validator, serverd and the mock oracle:

1. `solana init` with the wrong program ID pinned (refused: "the pinned vault ... is owned by ..., not the pinned program"; no
   profile is saved) and with a wrong helper SHA-256 (refused, `solana_prover_hash_mismatch`); then the real `solana init`
   (on-chain verification passes) and `solana verify`;
2. Stage the first transaction of a disposable operation, cancel its real buffer, confirm it is absent and its rent has returned (only transaction fees remain spent). Then `solana deposit --keypair payer.json --sol 1 --confirm`, SIGKILLed as soon as the signed transactions are journaled (the note
   must not exist yet), then the same command again: it resumes from the journal and the chain and installs the note;
3. `serve`, `lease export --usd 3 --confirm`, a paid MCP call with the printed key, a daemon SIGKILL and restart (the lease and
   its idle clock survive), half an idle period of silence (still open: the key is in use), a second call that uses the limit
   up, and clientd settles it by itself (`Settling the open Solana lease early: its spending limit is used up`); the note balance
   equals the deposit minus the exact ceil-converted vcii usage and the key is refused;
4. `lease export --usd 2 --confirm`, one call, then nothing: clientd settles it after the idle period (`--idle-seconds`, default
   40 in the harness) with no `lease settle`;
5. `solana withdraw --to <fresh address> --all --confirm` while the daemon runs (so it goes through the management API); the
   destination's finalized balance must equal the note's remaining balance plus the closed note account's rent to the lamport, and
   a further lease is refused.

A loopback proxy between clientd and serverd records every lease POST (status, request ID, proof hash; a proof must never
repeat); with `--scenario jump` it holds the first POST until the finalized feed shows the 2% drop, so serverd answers 409
`native_quote_stale` and clientd must re-quote and re-prove (`[409, 201]`). Build clientd statically for the Linux container:
`CGO_ENABLED=0 go build -o zkapi-clientd ./cmd/zkapi-clientd` (in `zkapi-clientd/`), then
`node scripts/solana-vcii-lease.mjs ... --client clientd --clientd-bin /path/zkapi-clientd [--idle-seconds 40]`. Go unit tests:
`podman run --rm -v <worktree>:/src -w /src/zkapi-clientd golang:1.25 go test ./...` (a CRLF checkout breaks two embedded-manifest
hash tests; run in a copy normalised with `sed -i 's/\r$//'`). The new tests cover the chain verification (every mismatch
against a mock RPC), the helper pin/handshake, deposit and withdrawal journaling and crash recovery against a simulated vault, the
admin API, and early settlement (exhausted, idle, active use, unreadable usage, restart, background loop); the helper has its own
`cargo test -p zkapi-solana-wallet`.

Open decisions: partial withdrawals (the protocol closes a note whole), the helper's RPC traffic bypassing `relay_url`, whether
`serve` should auto-create an empty wallet instead of requiring a deposit or import first, and whether the idle default
(15 minutes) suits issuers whose usage reporting lags more than that.

SDK compatibility: the original quote-field mismatch is fixed by `patches/sdk-native-sol-schema.patch` (apply order above).
The SDK and clientd now validate serverd's actual `pyth_solana_receiver`, `publish_time` and `feed_account` schema;
the eight native-SOL SDK tests include a guard against Rust schema drift.


## Continuation review and release verification (2026-10-06)

The independent read-only review rated the funding, helper, chain verification and early settlement work at 89% security and
91% completeness after fixes. Its findings added regressions for executing the same helper file that was hashed, preserving
legacy leases through upgrade, refusing unknown/regressing/oversized live usage, cancellation recovery across RPC or storage
failure, rejecting malformed RPC replies without mistaking them for absent buffers, and keeping provisional transaction
failures from resetting funding. A local mock RPC exercises processed/confirmed failure changing to finalized success;
post-cancellation checks retain the original note/nullifier if the operation succeeded. Rejected helpers are cancelled before
waiting for process exit; resumed withdrawals reuse the recorded fee payer.

Validation: full clientd `go vet ./...` and `go test -race ./... -count=1` in the Go 1.25 Podman image, 16 release-helper tests,
15 development-helper tests, the serverd live-usage test, and all eight native-SOL SDK tests passed. The WIP patches apply to
the saved baseline and reproduce the current Cargo and serverd files byte-for-byte. Two independent container builds with the
pinned Rust image produced identical release binaries:

```
zkapi-solana-wallet 0.1.0 (protocol 1)
sha256 8bd38f8a2cc89dab431d1856e7d62e851aceac27dc5cf73f59948b1b58305bad
```

This digest identifies the current Solana-port source snapshot, not every future build of this branch. Rebuild and republish
the digest after changing the port or helper. The binary is a Linux executable; version verification occurs inside the build
container, and the script writes a sibling `.sha256` file for operator pinning.

Remaining scope limits: the acceptance oracle is mocked and the validator is local; partial/escape withdrawals and Solana OA
key attestation are absent. A binary writable by an attacker can still change between hashing and execution. Signing inspection
restricts the target to the pinned vault but does not independently bind every instruction argument or compute-budget fee to
the journal's intent. Production operators must protect the helper/profile files and publish trusted deployment pins.


Final binaries passed both local-validator scenarios after the finality safeguards:

- **Steady:** one successful lease issuance; exhausted and idle leases settled automatically. Withdrawal returned
  969964948 lamports plus 1545120 lamports of closed-account rent (971510068 at the destination).
- **2% price jump:** the first proof received `409 native_quote_stale`; a fresh proof succeeded with `201`.
  Withdrawal returned 969367281 lamports plus rent (970912401 at the destination).

Both runs refused wrong program/helper pins, finalized a real staged-buffer cancellation with rent refunded (10000 lamports
of transaction fees), recovered a deposit after SIGKILL, preserved a working key through daemon restart and ongoing usage,
refused retired keys, and ended with no private note balance. These are local-validator transactions with a mocked oracle;
no live-chain funds were spent. Final staged secret scan passed.
