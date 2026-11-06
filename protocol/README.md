# zkAPI protocol

Anonymous prepaid API usage with native ETH settlement, BN254 Groth16 proofs,
and Baby-JubJub Schnorr signatures. A request consumes one private state and
returns a fresh server-signed state. The vault settles the remaining balance
when the note closes.

The current circuit binds signed balances to the private membership leaf.
Its circuit ID is `zkapi-v2-concession-v1`. Read the
[setup compatibility and trust assumptions](setup/v2/README.md) before using its keys.

## Implementation

```text
contracts/      Solidity vault, BN254 Poseidon, and Groth16 verifier
setup/v2/       Circuit-specific Groth16 keys and manifest
rust/crates/
  zkapi-types   Canonical BN254 field encoding and v2 wire statements
  zkapi-core    BN254 Poseidon, note/nullifier helpers, and Merkle trees
  zkapi-proof   Groth16 circuits, proving, verification, and curve operations
  zkapi-browser Storage- and transport-independent WASM wallet core
  zkapi-client  Native wallet, note persistence, and request recovery
```

The runtime server, challenge service, indexer, and operator CLI live in the
[parent workspace](../crates). The browser integration is in the
[parent SDK](../sdk).

See [PROTOCOL.md](PROTOCOL.md) for the protocol model,
[SPEC.md](SPEC.md) for the active implementation interfaces, and
[the implementation book](docs/src/intro.md) for a source map.

## Build and test

From this directory:

```bash
cargo test --release --manifest-path rust/Cargo.toml --workspace --locked
cd contracts
forge test
```

The proof system requires the circuit-specific Groth16 setup. The committed
artifacts use a single-party setup with no multi-party ceremony. Its trust
assumptions and compatibility requirements are described in the setup README.

## License

MIT OR Apache-2.0
