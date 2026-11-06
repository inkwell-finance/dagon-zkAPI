# Solana Merkle-transition Groth16 setup

Circuit ID: `dagon-zkapi-solana-transition-v1`.

This is an auxiliary Solana-only circuit. It proves that one canonical zkAPI
note leaf changes between zero and its committed value under the existing
32-level Poseidon tree. It does not authorize an API request or a payout. The
`zkapi-v2-concession-v1` request and withdrawal circuits remain the
only authorization proofs.

The ten public inputs are `protocol_version`, `chain_id`, `protocol_binding`,
`old_root`, `new_root`, `note_id`, `commitment`, `amount`, `expiry`, and
`inserting`. The 32 Merkle siblings are private witness data. The Solana vault
constructs the public statement from authoritative vault/note state and accepts
a root update only after verifying this proof through the BN254 syscalls.

These keys were generated with OS randomness by one process:

```sh
cargo run --release --manifest-path protocol/rust/Cargo.toml \
  -p zkapi-proof --example solana_transition_setup -- \
  protocol/setup/solana-transition-v1
```

No multi-party ceremony has been conducted. The generated proving key is
embedded by the Solana `CreditLedger` adapter, and the matching verifying key is
compiled into the SBF program by `scripts/generate-solana-verifier.mjs`.
Production operators must either explicitly accept this single-party trust
assumption or replace the setup and regenerate every dependent artifact before
deployment. File hashes establish artifact identity; they do not prove that
setup secrets were discarded.

SHA-256 identities for this checked-in setup:

- `transition.pk`: `8ad263ae68ff433b9ca39d4633a10bf63912df7c43c512ea348e8b0474005a7b`
- `transition.vk`: `e2ed190f660638b9c94b72569bcc6072fe210200c62eb43b7c6d39c695210259`
- `manifest.json`: `0d832295f71398e32803f4b1bea918e3ba18e0ad40b6737f64d3affe2228cbab`

Encrypt/FHE is not used by this circuit, prover, verifier, vault, or default
dependency graph. A future experimental ledger remains outside this setup and
must implement the generic `CreditLedger` boundary without changing request or
vault semantics.
