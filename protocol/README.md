# zkAPI protocol

Anonymous prepaid API usage with native SOL settlement on Solana, BN254 Groth16
proofs, and Baby-JubJub Schnorr signatures. A request consumes one private state
and returns a fresh server-signed state. The Solana vault program settles the
remaining balance when the note closes.

This is Dagon's Solana deployment of the upstream
[ethereum/zkapi](https://github.com/ethereum/zkapi) protocol (provenance in
[VENDORED.md](VENDORED.md)). The EVM vault and Solidity verifier live upstream.

The current circuit binds signed balances to the private membership leaf.
Its circuit ID is `zkapi-v2-concession-v1`. Read the
[setup compatibility and trust assumptions](setup/v2/README.md) before using its keys.

## Implementation

```text
setup/v2/                    Request/withdrawal Groth16 keys and manifest
setup/solana-transition-v1/  Solana Merkle-transition Groth16 keys and manifest
test-vectors/                Solana binding vectors and the real-proof vault fixture
rust/crates/
  zkapi-types   Canonical BN254 field encoding, v2 statements, Solana bindings
  zkapi-core    BN254 Poseidon, note/nullifier helpers, and Merkle trees
  zkapi-proof   Groth16 circuits, proving, verification, and the snarkjs bridge
  zkapi-browser Storage- and transport-independent WASM wallet core
  zkapi-client  Native wallet, note persistence, and request recovery
```

The Anchor vault program is in [`../solana`](../solana). The runtime server,
challenge service, indexer, and operator CLI live in the
[parent workspace](../crates). The browser integration is in the
[parent SDK](../sdk).

See [PROTOCOL.md](PROTOCOL.md) for the protocol model,
[SPEC.md](SPEC.md) for the active implementation interfaces, and
[the implementation book](docs/src/intro.md) for a source map.

## Build and test

From this directory:

```bash
cargo test --release --manifest-path rust/Cargo.toml --workspace --locked
```

The proof system requires the circuit-specific Groth16 setup. The committed
artifacts use a single-party setup with no multi-party ceremony. Its trust
assumptions and compatibility requirements are described in the setup README.

## License

MIT OR Apache-2.0
