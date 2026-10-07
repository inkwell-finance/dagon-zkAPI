# zkapi-solana-wallet

The native-SOL wallet helper that `zkapi-clientd` drives. It holds every proof and note transition (the same pure
`zkapi-browser` code the browser SDK runs) and builds, checks and signs the Solana vault transactions. `zkapi-clientd` owns the
durable state and the network protocol; nothing cryptographic is reimplemented in Go.

```sh
zkapi-solana-wallet --version      # zkapi-solana-wallet 0.1.0 (protocol 1)
zkapi-solana-wallet SETUP_DIR      # JSON commands on stdin, one JSON reply per line on stdout
```

`SETUP_DIR` holds `request.pk` and `withdrawal.pk` (`protocol/setup/v2`). One process serves one operation: clientd starts it,
sends commands, closes stdin. Secret-bearing commands travel over stdin/stdout; clientd discards helper stderr and error text, and its helper
environment is empty apart from `PATH`.

## Versioning and the handshake

- **Package version** (`Cargo.toml`, semver) identifies a release; `--version` prints it.
- **Protocol version** (`PROTOCOL` in `src/driver.rs`, currently `1`) is the command protocol. It changes whenever a command or
  reply changes incompatibly. The first command a client sends is `handshake`:
  `{"name":"zkapi-solana-wallet","version":"0.1.0","protocol":1,"circuit_id":"...","ledger_backend":"...","dev":false}`.
  `zkapi-clientd` refuses a helper whose name or protocol differs from what it was built against, and a helper that reports
  `"dev": true` unless the profile is a `localnet` test cluster.
- **Pinned digest.** The profile (`zkapi.solana.prover_sha256`) pins the helper's SHA-256. clientd hashes the binary before every
  run using the same absolute path it executes, and never starts one that differs, so a swapped or upgraded binary needs an explicit new pin
  (`zkapi-clientd solana init ... --prover-sha256 <digest>`), which `solana init` prints for an unpinned helper.

Failures carry a `code` only for a closed set of conditions clients act on (`stale_root`, `stale_note_id`, `blockhash_expired`,
`transaction_failed`, `wrong_cluster`); all other error text stays inside this process's reply and is dropped by clientd.

## Commands (release build)

| command | purpose |
| --- | --- |
| `handshake`, `derive_deployment`, `wallet_config` | identity, chain ID/protocol binding and wallet configuration derived from the public pins |
| `load_wallet`, `export_wallet`, `status` | load / read back the wallet (config, note state, pending-request journal) |
| `prepare_request`, `complete_response`, `tree_path` | lease request proofs and the signed settlement transition |
| `withdrawal_nullifier`, `withdraw_prove` | mutual-close proof (needs the server's clearance signature) |
| `connect` | pin the RPC, indexer and vault identity for the commands below (HTTPS or numeric-loopback HTTP only) |
| `keypair_pubkey`, `deposit_params`, `deposit_prepare`, `deposit_confirm` | native-SOL deposit |
| `withdraw_prepare`, `cancel_prepare` | close transactions, closing an abandoned staged buffer |
| `sign_operation`, `submit_signed`, `signed_status` | sign with the local keypair file, re-sendable idempotent submission, chain progress |
| `note_status`, `nullifier_status` | finalized note / used-nullifier reads |

`sign_operation` refuses any transaction that is not paid and signed only by the keypair, or that calls anything other than the
pinned vault program (and compute-budget requests) on the pinned vault. Signing is deterministic. clientd journals the exact signed bytes before submission and reuses them after a crash;
expired operations are rebuilt only after chain recovery. Cancellation keeps the abandoned buffer identity and its signed
cleanup transaction durable until finalized or explicitly confirmed absent. Malformed RPC replies never count as absence.

## Development builds

`--features dev` adds commands for a disposable local validator only: `keygen`, `airdrop`, `vault_init`, `attach_indexer`,
`deposit` (a helper-side deposit), `vault_snapshot`, `wallet_snapshot_tree`, `balance`, `pyth_account_file`, `pyth_update`
(a mock Pyth account writer: no Wormhole verification), `public_keys`, `init`, `discard_request`. `scripts/solana-vcii-lease.mjs`
uses them. A dev build says so in `--version` and in its handshake; a release build does not contain them.

## Building

```sh
cargo build --locked --release -p zkapi-solana-wallet                       # release binary: target/release/zkapi-solana-wallet
cargo build --locked --release -p zkapi-solana-wallet --features dev        # local-validator test build
cargo test --release -p zkapi-solana-wallet
scripts/build-solana-wallet.sh [--verify]                                   # reproducible container build -> dist/
```

`scripts/build-solana-wallet.sh` builds from `crates/zkapi-solana-wallet/Containerfile`: a toolchain image pinned by digest,
`--locked`, path remapping, stripped symbols, a fixed `SOURCE_DATE_EPOCH`. With `--verify` it builds twice with no layer cache and
fails unless both binaries are byte-identical. Publish the printed SHA-256 with the release; operators compare it before pinning.

Release checklist: bump `version` (and `PROTOCOL` if a command changed incompatibly), `cargo test`, run
`scripts/build-solana-wallet.sh --verify`, publish the binary and its digest, and update the pin in each deployment's
`zkapi-clientd solana init` instructions.
