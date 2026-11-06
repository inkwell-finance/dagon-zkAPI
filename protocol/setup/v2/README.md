# Concession-exit Groth16 development setup

Circuit ID: `zkapi-v2-concession-v1`.

These are single-party Groth16 keys generated with OS randomness by
`cargo run --release -p zkapi-proof --example setup -- NEW_OUTPUT_DIRECTORY`.
The `v2` directory name denotes the wire schema. Proving/verifying files carry
the `zkapi-v2-concession-v1` circuit header.
The matching generated Solidity verifier is committed alongside them.

Requests retain 12 public inputs and prove note-bound nullifiers, a derived
anchor chain, anchor-1 genesis, and balance no greater than the deposit.
Withdrawals have 16 inputs: registration and packed `(note_id, deposit, expiry)`
replace Merkle membership; the exit binds its successor nullifier, concession,
expiry deadline, and destination. The signed balance equals payout plus
concession without overflow. Clearance forces zero concession and successor.
The separate Solana transition circuit and its setup are unchanged.

Regenerate fixtures with `solidity_fixture` and `vault_challenge_fixture`.
The latter emits `req0/req1/req2`, `esc0/esc1/esc1_conceded/esc2`, and `close2`
for one derived state chain. `public_fields` contains the circuit's scalar
array; `inputs_abi` expands withdrawal note fields into the Solidity tuple.
Old keys, proofs, random anchors, and withdrawal-tag statements are incompatible.

No multi-party setup ceremony has been conducted. Matching hashes establish
artifact identity, not the absence of retained setup secrets. Independently
review the circuit, third Pedersen generator, setup provenance and trust
assumptions before deployment.
The vault's immutable verifier, client proving keys, and pinned hashes must
match this setup. Use the matching circuit for all signed states and keep wallet
data bound to its configured vault and signing keys.
