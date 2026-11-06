# Protocol source provenance

`protocol/` is tracked directly by this repository. A normal clone includes the
Rust workspace, the selected proof setup, and test vectors; no submodule
initialization or separate protocol checkout is needed. Make protocol changes
here and commit them with the application changes that use them. The Rust
workspace under `rust/` remains separate from the root workspace.

The protocol was imported from the upstream zkAPI project
([ethereum/zkapi](https://github.com/ethereum/zkapi)) at this pinned revision,
preserving files and executable modes except for the removed `.gitmodules`
files:

| Directory relative to `protocol/` | Source repository | Imported commit |
| --- | --- | --- |
| `.` | <https://github.com/mingyech/zkapi> | `8b2d4e3da921f956e1eb6b93afbf722a877c060c` |

Dagon runs zkAPI only on Solana. The upstream EVM components (the Foundry
project with the Solidity vault, Groth16 adapter and BN254 Poseidon library,
its forge-std and OpenZeppelin dependencies, and the generated Solidity setup
sources) are not part of this repository; Ethereum deployments use upstream
ethereum/zkapi. The Solana vault program lives in [`../solana`](../solana).

The import itself did not regenerate proving or verifying keys; the current
keys and their provenance are described in [setup/v2/README.md](setup/v2/README.md).
