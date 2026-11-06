# Dagon zkAPI

Dagon zkAPI is a Solana-first private payment layer for AI and other APIs. A
browser wallet deposits native SOL, proves authorization with Groth16, pays only
for completed usage, and withdraws the remaining balance without linking API
requests to the on-chain deposit.

This repository ports the upstream Ethereum zkAPI protocol to Solana while
preserving its request and proof model. Solana is the production-default ledger;
the former EVM implementation remains available only as an explicit compatibility
backend.

The implementation release gates, including a fresh SBF build and complete
local-validator money lifecycle, are recorded in
[the port status](docs/PORTING_STATUS.md). This repository is not itself a live
deployment: do not treat checked-in program IDs, example identities, test
fixtures, development setup keys, or generated artifacts as production pins.

## Security and architecture

- Groth16 over BN254 remains the trusted authorization path.
- The Anchor vault settles native SOL and verifies request/withdrawal proofs with
  Solana BN254 syscalls.
- A chain-neutral `CreditLedger` boundary isolates the request/server protocol
  from ledger transport.
- The browser uses exact decimal strings for Solana-derived `u64` chain IDs and a
  durable, signed-transaction journal for multi-stage wallet operations.
- Server startup verifies the pinned cluster, immutable program deployment,
  vault-state PDA, finalized vault metadata, and Pyth SOL/USD source before
  opening durable state.
- Encrypt/FHE is intentionally absent from the default dependency graph and the
  trusted money path. A future experimental ledger may implement `CreditLedger`
  without changing the request API or vault semantics.

The selected authorization circuit is `zkapi-v2-concession-v1`. The
Solana-only root transition uses the separate
`dagon-zkapi-solana-transition-v1` circuit. Both checked-in setups are
single-party ceremonies and must be replaced or accepted explicitly for a real
deployment. See [note-bound commitments](docs/note-bound-commitments.md),
[transition setup provenance](protocol/setup/solana-transition-v1/README.md),
and [Solana server invariants](docs/SOLANA_SERVER.md).

## Build and test

Prerequisites include Node 24+, Rust, Solana CLI and Anchor 0.32.1. From the
repository root:

```sh
npm ci
npm test
npm run verify:assets
npm run verify:solana-vk
cargo test --locked --workspace
cargo test --locked --manifest-path protocol/rust/Cargo.toml --workspace
anchor build --manifest-path solana/Anchor.toml
```

The final local-validator lifecycle is a release gate and is not implied by the
unit suites above. Current verified coverage and known environment constraints
are recorded in [docs/PORTING_STATUS.md](docs/PORTING_STATUS.md).

## Browser SDK

The package identity is `@dagon/zkapi-browser-sdk`. Its public modules include
the runtime/store/client APIs plus Solana ledger identity, native-SOL billing,
Wallet Standard transport, and the crash-safe operation journal.

```js
import { BrowserWalletRuntime } from '@dagon/zkapi-browser-sdk/runtime';
import { SolanaOperationJournal } from '@dagon/zkapi-browser-sdk/solana-journal';
```

Applications must pin the server URL, RPC cluster identity, immutable program,
vault-state PDA, genesis hash, Pyth source, setup hashes and Wallet Standard
account. See [SDK integration](sdk/README.md) and the native-SOL tests under
`sdk/test/`.

## Operator services

The shipped executable names are Dagon-branded:

- `dagon-zkapi serverd` runs proof authorization, lease settlement and prepared
  Solana ledger operations.
- `dagon-zkapi indexer` or `dagon-zkapi-indexerd` reconstructs finalized Merkle
  snapshots.
- `dagon-zkapi-challenged` monitors and challenges stale escape withdrawals.
- `dagon-zkapi signing-keys` derives the state and clearance public keys.
- `dagon-zkapi setup --output-dir NEW_DIRECTORY` creates a fresh Groth16 setup;
  it is not needed to connect to an existing deployment.

All three ledger-facing services default to Solana. Select `--ledger evm` (or
`--ledger ethereum` for the indexer) only for the compatibility backend.

For containers, copy the public and secret examples in `docker/aws/`, replace
every placeholder, keep secret files mode `0600`, and run the
`dagon-zkapi-run` entrypoint through `docker/aws/compose.yml`. The default
deployment example is Solana; `deployment.evm.env.example` is explicitly legacy.

## Source layout

| Directory | Purpose |
| --- | --- |
| `solana/` | Anchor native-SOL vault and generated Groth16 verifier constants |
| `crates/dagon-zkapi-ledger/` | Generic `CreditLedger` contract and shared operation types |
| `crates/dagon-zkapi-solana-ledger/` | Solana RPC, account validation and operation preparation adapter |
| `crates/zkapi-serverd/` | Protocol server and Solana-default challenge service |
| `crates/zkapi-indexerd/` | Privacy-safe finalized Solana/EVM tree indexer |
| `sdk/` | Browser SDK, Wallet Standard transport, durable journals and tests |
| `protocol/rust/` | Shared v2 types, circuits, proof code and browser WASM |
| `protocol/setup/v2/` | Selected proof setup and immutable artifact manifest |
| `protocol/contracts/` | Legacy EVM compatibility vault and verifier |
| `docker/aws/` | Solana-default operator image and explicit EVM compatibility config |

The original upstream protocol provenance remains documented in
[protocol/VENDORED.md](protocol/VENDORED.md).
