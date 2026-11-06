# Groth16 Proofs

[groth16.rs](../../rust/crates/zkapi-proof/src/groth16.rs) defines request and
withdrawal circuits and the Solana Merkle-transition circuit.
[compact.rs](../../rust/crates/zkapi-proof/src/compact.rs)
provides their native proving and verification interface, canonical proof
serialization, Baby-JubJub operations, and setup export.
[ceremony.rs](../../rust/crates/zkapi-proof/src/ceremony.rs) exports the
circuits as snarkjs `.r1cs` files and imports the ceremony's final zkeys.

The request circuit has 12 public field elements. It proves membership,
secret knowledge, a valid genesis or signed state, sufficient balance, expiry,
rerandomization, and a request-context-bound nullifier authorization. The
withdrawal circuit has 16 public field elements and proves the leaf-bound final
state (no Merkle path or root), the concession split `B = final + c`, the
note-bound nullifier chain, the successor nullifier, destination/balance
binding, and clearance when requested.

Both circuits use `E(B,r,L) = B*G + r*H + L*J`. Reusing a signed state with a
different membership leaf fails the signature/balance relation. The exact
public input order is in [inputs.rs](../../rust/crates/zkapi-types/src/inputs.rs).

Keys use circuit ID `zkapi-v2-concession-v1`. The Solana vault embeds the
matching verifying keys (`npm run generate:solana-vk`). The browser wallet
consumes the same proving-key bytes. See [setup compatibility](../../setup/v2/README.md):
the committed keys use a single-party setup with no multi-party ceremony.
Proving keys, signed states, and the verifier must use this exact circuit.
