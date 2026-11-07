# Protocol Map

| Behavior | Implementation |
| --- | --- |
| Registration, active leaf, note-bound nullifiers, derived anchors | [v2.rs](../../rust/crates/zkapi-core/src/v2.rs) |
| Active-note tree and sibling paths | [merkle.rs](../../rust/crates/zkapi-core/src/merkle.rs) |
| Request, withdrawal and Merkle-transition constraints | [groth16.rs](../../rust/crates/zkapi-proof/src/groth16.rs) |
| Native proving, verification, and signing | [compact.rs](../../rust/crates/zkapi-proof/src/compact.rs) |
| Public statements and field ordering | [inputs.rs](../../rust/crates/zkapi-types/src/inputs.rs) |
| Solana chain, deployment and destination bindings | [solana.rs](../../rust/crates/zkapi-types/src/solana.rs) |
| Native wallet and recovery | [wallet.rs](../../rust/crates/zkapi-client/src/wallet.rs) |
| Browser wallet | [zkapi-browser](../../rust/crates/zkapi-browser/src/lib.rs) |
| USDC deposits and close-out | [dagon-zkapi-vault](../../../solana/programs/dagon-zkapi-vault/src/lib.rs) |
| On-chain Groth16 verification | [dagon-zkapi-solana](../../../crates/dagon-zkapi-solana/src/lib.rs) |
| HTTP processing and durable transcripts | [Root server](../../../crates/zkapi-serverd) |
| Vault event indexing | [Root indexer](../../../crates/zkapi-indexerd) |

Registration commits to the user's secret. The active leaf also commits to the
note ID, deposit and expiry. Both circuits include that private leaf in the
balance commitment, so a signed state remains bound to its original note.
