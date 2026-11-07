# Note-bound commitments

A signed balance commitment binds to the same note used by the Merkle-membership
proof:

```text
L = Poseidon(leaf_domain, note_id, registration(secret), deposit, expiry)
C = balance * G + blinding * H + L * J
```

Both request and withdrawal circuits compute `L` from the exact private values
(the request circuit also proves Merkle membership; the withdrawal circuit is
root-free and binds `L` through the public note fields). They use that same `L` to open the signed
commitment. `J` is independently derived with Keccak try-and-increment from
`zkapi.v2.note-binding.generator.v1`, choosing even y and clearing the cofactor.
No known scalar relation to `G` or `H` is introduced. The full canonical BN254
field representation of `L` is multiplied by J, naturally reducing modulo the
Baby-JubJub subgroup order, in both native code and the circuit.

The server updates an anonymous commitment by subtracting `charge * G` and
adding `blind_delta * H`. The note component survives that update without
revealing the note leaf. A fresh uniformly random blinding masks the leaf in
public commitments. Changing the note while retaining the signature requires
breaking the commitment binding/signature or finding an appropriate hash
collision; balancing the deposit amounts alone cannot do it.

This construction relies on the discrete-log binding assumption for the
independent third generator, alongside the Poseidon, Schnorr and Groth16
assumptions. Groth16/BN254 and Baby-JubJub are not post-quantum.

## Compatibility and setup

The circuit identifier is `zkapi-v2-concession-v1`. Proving and verifying key
files carry that header; loaders reject files without the expected circuit header
before decoding. Public deployment manifests must advertise
`proof_setup.circuit_id`, and clients must
pin the matching key hashes and vault state. The header guards against
accidental mismatches; it does not establish setup provenance or replace
independently pinned key hashes.

The checked-in `protocol/setup/v2` directory contains a single-party Groth16
setup. The matching Solana verifier constants and SDK WASM/proving keys must
travel together. Artifact hashes identify setup files but do not establish that setup
secrets were destroyed. See [setup provenance](../protocol/setup/v2/README.md)
for the trust assumptions.

The vault has an immutable verifier and signing keys. Its circuit, proof
artifacts, denomination, and client pins must match exactly. Wallet state and
recovery journals are bound to that configuration. See
[the Solana server](SOLANA_SERVER.md) for asset and billing configuration.

## Challenge and settlement requirements

Operate `dagon-zkapi-challenged` alongside the server and indexer, with durable retries
and a dedicated challenge payer keypair. Defeat and raise preserve the historical request
root and need no Merkle path; there is no restore step. The concession rule
(G1/G2/G3), challenger policy and bounded pause are in
[service operation](challenge-service.md).

Direct OpenRouter retirement persists disable, grace, usage capture and
revocation stages and does not sign before confirmed deletion. Its aggregate
usage API supplies no authoritative final receipt: the configured grace must
cover in-flight calls and accounting delay. OA-org finalized receipts provide
a separate settlement path.
