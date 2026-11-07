# Introduction

This book maps the active zkAPI v2 implementation, as deployed by Dagon on
Solana, to its source. The [protocol model](../../PROTOCOL.md) describes
sequential anonymous spending; the [implementation specification](../../SPEC.md)
describes exact interfaces.

The current implementation uses BN254 Groth16 proofs, BN254 Poseidon hashing,
and Baby-JubJub Schnorr signatures and note-bound balance commitments. The
Anchor vault program settles Circle USDC in base units (micro-USDC). These are classical
elliptic-curve primitives. Review the [setup trust assumptions and
compatibility](../../setup/v2/README.md) before deploying. The protocol descends
from upstream [ethereum/zkapi](https://github.com/ethereum/zkapi), where its EVM
vault is maintained.

```text
setup/        Matching circuit-specific Groth16 keys (v2 and Solana transition)
rust/         Proof circuits, native/browser wallets, types, and Merkle helpers
../solana/    Anchor vault program and deployment profile
../crates/    Runtime server, challenge service, indexer, and operator CLI
../sdk/       Browser SDK and proof assets
```
