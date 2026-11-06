# Protocol Map

| Behavior | Implementation |
| --- | --- |
| Registration, active leaf, note-bound nullifiers, derived anchors | [v2.rs](../../rust/crates/zkapi-core/src/v2.rs) |
| Active-note tree and sibling paths | [merkle.rs](../../rust/crates/zkapi-core/src/merkle.rs) |
| Request and withdrawal constraints | [groth16.rs](../../rust/crates/zkapi-proof/src/groth16.rs) |
| Native proving, verification, and signing | [compact.rs](../../rust/crates/zkapi-proof/src/compact.rs) |
| Public statements and field ordering | [inputs.rs](../../rust/crates/zkapi-types/src/inputs.rs) |
| Native wallet and recovery | [wallet.rs](../../rust/crates/zkapi-client/src/wallet.rs) |
| Browser wallet | [zkapi-browser](../../rust/crates/zkapi-browser/src/lib.rs) |
| Native ETH deposits and close-out | [ZkApiVault.sol](../../contracts/src/ZkApiVault.sol) |
| EVM verification | [Groth16ProofAdapter.sol](../../contracts/src/adapters/Groth16ProofAdapter.sol) |
| HTTP processing and durable transcripts | [Root server](../../../crates/zkapi-serverd) |
| Contract event indexing | [Root indexer](../../../crates/zkapi-indexerd) |

Registration commits to the user's secret. The active leaf also commits to the
note ID, deposit and expiry. Both circuits include that private leaf in the
balance commitment, so a signed state remains bound to its original note.
