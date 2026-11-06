# Rust Libraries and Services

The protocol workspace contains five crates:

- [zkapi-types](../../rust/crates/zkapi-types): canonical BN254 field encoding,
  v2 public statements, Solana deployment bindings, HTTP messages, and Schnorr
  signatures.
- [zkapi-core](../../rust/crates/zkapi-core): BN254 Poseidon, registration,
  note/nullifier/state helpers, and Merkle trees.
- [zkapi-proof](../../rust/crates/zkapi-proof): Groth16 circuits, commitments,
  signing, setup serialization, proving, verification, and the snarkjs
  ceremony bridge.
- [zkapi-client](../../rust/crates/zkapi-client): native wallet state,
  prepared-request journal, response validation, withdrawal proofs, and recovery.
- [zkapi-browser](../../rust/crates/zkapi-browser): wallet core for the browser,
  with storage and transport supplied by its caller.

The [root workspace](../../../crates) owns the runtime server and challenge
service, vault event indexer, and operator CLI; the Anchor vault program is in
[`solana/`](../../../solana). It imports the protocol
libraries directly. The browser [SDK](../../../sdk) supplies the web-facing
transport, storage integration, and proof assets.
