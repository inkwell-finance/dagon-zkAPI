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
# 2. host binaries
cargo build --locked --release --target-dir /target/sol-host -p zkapi-cli --bin dagon-zkapi \
  -p zkapi-indexerd --bin dagon-zkapi-indexerd -p zkapi-serverd --example solana_acceptance_wallet
# 3. scenario
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

The harness, wallet example (`discard_request` command) and this document are committed directly.

## zkapi-clientd as the client (`--client clientd`)

`zkapi-clientd` (the Go client daemon) has a native-SOL profile that follows the browser SDK's lease flow
(`sdk/services/browserWalletRuntime.js`): quote -> prove -> lease -> settle, with the SDK's bounded `native_quote_stale` retry.
It is a separate network next to `mainnet`/`sepolia`: `network: "solana"` plus a pinned deployment in `config.json`
(`zkapi.solana`: serverd and indexer origins, cluster label, program ID, vault state PDA, genesis hash, derived chain ID and
protocol binding, the vault's state/clearance signing keys, the vault's per-request cap as the minimum lease, the Pyth feed
identities and bounds, the lease provider base). It never starts the Ethereum `zkapi-walletd` companion.

Division of labour: Go owns durable state and the network protocol; every proof and note transition is computed by the same
Rust code as the SDK (`zkapi_browser::prepare_request_with_prover` / `complete_response`), reached through the wallet helper
`crates/zkapi-serverd/examples/solana_acceptance_wallet` (stdin/stdout JSON, one process per operation, empty environment, no
stderr kept). The helper gained `derive_deployment`, `load_wallet`, `export_wallet` and returns the pending-request journal from
`prepare_request`. Pass `--prover` and `--proof-setup-dir` (the directory holding `request.pk`) to `zkapi-clientd solana init`.

```sh
zkapi-clientd solana init --deployment deployment.json --prover ./solana_acceptance_wallet --proof-setup-dir protocol/setup/v2
zkapi-clientd solana import-wallet --file wallet-export.json   # the helper's export_wallet reply: {config, state}
zkapi-clientd serve                                            # loopback management API, settles the lease when due
zkapi-clientd lease export --usd 2 --confirm                   # key on stdout, once
zkapi-clientd lease status                                     # open lease timing, never the key
zkapi-clientd lease settle --confirm                           # close the key now and install the signed receipt
zkapi-clientd solana status                                    # offline: balance and pending flag
```

Deposits are not part of this client yet: the note comes from `export_wallet` of a helper/SDK wallet that made the deposit.

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

The wallet file is `<config-dir>/zkapi/solana/<vault-state>/wallet.json` (0600): note secret, journal, lease timing.

`--client clientd --clientd-bin PATH` replaces the Rust helper as the client in this scenario. The helper still deposits and
hands the note over; then clientd obtains the lease itself (`lease export --usd 2 --confirm`), a paid MCP call uses the printed
key, the daemon is SIGKILLed and restarted mid-lease, `lease settle --confirm` closes it, the note balance must equal the deposit
minus the exact ceil-converted vcii usage, and the key must be refused afterwards. A loopback proxy between clientd and serverd
records every lease POST (status, request ID, proof hash; a proof must never repeat); with `--scenario jump` it holds the first
POST until the finalized feed shows the 2% drop, so serverd answers 409 `native_quote_stale` and clientd must re-quote and
re-prove (`[409, 201]`). Build clientd statically for the Linux container:
`CGO_ENABLED=0 go build -o zkapi-clientd ./cmd/zkapi-clientd` (in `zkapi-clientd/`), then
`node scripts/solana-vcii-lease.mjs ... --client clientd --clientd-bin /path/zkapi-clientd`. Go unit tests:
`podman run --rm -v <worktree>:/src -w /src/zkapi-clientd golang:1.25 go test ./...` (a CRLF checkout breaks two embedded-manifest
hash tests; run in a copy normalised with `sed -i 's/$//'`).

Known SDK mismatch (not touched here): `sdk/services/zkapiNativeSol.mjs` validates a quote with `source: "pyth_receiver"`,
`published_at` and `price_account`, while serverd's quote carries `source: "pyth_solana_receiver"`, `publish_time` and
`feed_account` (the clientd port follows serverd's actual JSON).
