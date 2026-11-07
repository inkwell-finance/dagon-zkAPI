# zkAPI v2 implementation specification

This document describes the active implementation, deployed by Dagon on
Solana. The protocol model is in [PROTOCOL.md](PROTOCOL.md). Source definitions
linked below fix the exact field order, encodings, and constraints. The
circuits descend unchanged in structure from upstream
[ethereum/zkapi](https://github.com/ethereum/zkapi); its EVM vault and Solidity
verifier are maintained upstream and are not part of this repository.

## Cryptographic parameters

- Proof system: circuit-specific Groth16 on BN254.
- Circuit revision: `zkapi-v2-concession-v1`.
- Circuit field: BN254 scalar field, modulus
  `0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001`.
- Hash: domain-separated Poseidon, exponent 5, rate 2, capacity 1,
  8 full rounds and 57 partial rounds.
- Balance commitment: `E(B, r, L) = B*G + r*H + L*J` on Baby-JubJub,
  where `L` is the private active-note leaf.
- Server authentication: separate Baby-JubJub Schnorr keys for state and
  clearance signatures, pinned by the deployment.
- Active-note tree: depth 32, zero leaf 0, note ID as the leaf index.

[Native hash functions](rust/crates/zkapi-core/src/v2.rs) and
[circuit constraints](rust/crates/zkapi-proof/src/groth16.rs) use the
`zkapi.v2.*` domain labels. The independent note-binding generator is derived
under `zkapi.v2.note-binding.generator.v1`. Native helpers, circuits, setup
manifest, and the verifying keys embedded in the Solana vault must agree. This
is a classical elliptic-curve proof and signature system.

## Notes and state

A registration commitment is `C = H_reg(secret, 0)`. The active leaf is
`L = H_leaf(note_id, C, deposit_amount, expiry)`. The user keeps the secret,
private balance and blinding, current anchor, previous anchor, and server
signature locally. Genesis has balance equal to the deposit and anchor 1. The
request nullifier is note-bound: `N = H(d_null, secret, note_id, anchor)`. The
next anchor is derived, `anchor' = H(d_anchor, N)`, so the successor nullifier
`N+ = H(d_null, secret, note_id, anchor')` is computable from `N` alone. A later
spend proves a valid signature on the deployment-bound commitment and anchor and
that the anchor equals the derived successor of the previous nullifier.

Binding `L` into both request and withdrawal commitments prevents a signed
state from being moved to a different membership note. Rerandomization changes
only the blinding term. The server subtracts the bounded usage charge and adds
a fresh blinding delta before signing the next state.

## Proof statements

The public statement structs and exact verifier order are defined by
[inputs.rs](rust/crates/zkapi-types/src/inputs.rs); the Solana vault's
`RequestInputs` and `WithdrawalInputs` mirror them field for field.

The statements are chain-neutral. On Solana the three deployment-specific
fields carry domain-separated Keccak bindings defined in
[solana.rs](rust/crates/zkapi-types/src/solana.rs) and recomputed by the
program:

- `chain_id = solana_chain_id(genesis_hash)` (the cluster's full genesis hash);
- `contract_address = solana_deployment_binding(program_id, vault_state,
  genesis_hash)`, the deployment binding;
- `destination = solana_destination_binding(destination_account)`, the 20-byte
  binding of the 32-byte payout account.

The request statement contains these 12 field elements:

1. protocol version
2. chain ID
3. deployment binding (`contract_address`)
4. active root
5. state signing key x
6. state signing key y
7. request time
8. solvency bound
9. request nullifier
10. authorization tag
11. anonymous commitment x
12. anonymous commitment y

The request proof establishes note membership, secret knowledge, genesis or
valid signed state, balance solvency, expiry at least the request time, correct
rerandomization, and the nullifier/authorization tag. The authorization tag
binds the nullifier to a private context derived from the exact client request
ID and payload hash. Runtime validation binds the public deployment, keys,
root, time, and charge bound to the configured service.

The withdrawal statement contains these 16 field elements:

1. protocol version
2. chain ID
3. deployment binding (`contract_address`)
4. registration commitment
5. state signing key x
6. state signing key y
7. clearance signing key x
8. clearance signing key y
9. packed note fields `note_id * 2^192 + deposit_amount * 2^64 + expiry_ts`
10. final balance
11. destination binding
12. withdrawal nullifier
13. has-clearance flag
14. next nullifier (`N+`; zero for mutual close)
15. conceded amount
16. valid-until timestamp

The withdrawal proof carries no Merkle path, active root or withdrawal tag.
It recomputes the registration and the leaf from the range-checked note fields,
binds the signed state commitment to that leaf, proves `state_balance =
final + conceded` without wrap and `state_balance <= deposit`, and proves the
note-bound nullifier chain. Mutual close additionally proves the clearance
signature and requires `next_nullifier = 0` and `conceded = 0`. Escape reveals
`N+ = successor_nullifier(secret, note_id, N)`. The vault checks the
deployment, pinned keys, `valid_until`, note status and note fields against the
stored note, nullifier states and amounts before settlement.

## Wire format and persistence

[wire.rs](rust/crates/zkapi-types/src/wire.rs) defines the active HTTP schemas.
`Groth16ProofWire` carries backend `groth16_bn254` and a base64-encoded 256-byte
proof: eight big-endian 32-byte BN254 coordinates (not compressed Arkworks
bytes). Public inputs are part of the enclosing
request and are verified directly. The Solana vault verifies the same 256-byte
proof encoding with Solana's BN254 syscalls (`groth16-solana`).

The internal `Felt252` name is retained for compatibility, but values are BN254
scalar-field elements. JSON fields use canonical `0x` hexadecimal strings and
reject values at or above the field modulus. Preserve the existing v2 JSON
shapes; numeric handling at browser boundaries is defined by the SDK.

The native wallet journals prepared requests before transport. The runtime
server persists nullifier reservations and finalized transcripts to make
request retries idempotent and to preserve evidence for escape challenges.
The browser wallet receives storage and transport from its caller.

## Solana settlement

The [Anchor vault program](../solana/programs/dagon-zkapi-vault/src/lib.rs)
accounts in USDC base units (micro-USDC) of Circle USDC
(`EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v`, 6 decimals, classic SPL
Token; Token-2022 is rejected). The server bills one base unit per metered
micro-USD, so no price oracle exists. Every shared deployment parameter
(program id, USDC asset, vault version, request charge cap of 1,000,000 base
units, note TTL, challenge period, pause bounds) comes from
`solana/profile/shared.json`; only the network identity (genesis hash, vault
authority and state, treasury token account) differs between clusters.

`initialize` creates the vault-state PDA `["vault", authority]` and its USDC
token account, the PDA `["vault-token", vault_state]` with the vault state as
token authority, derives `chain_id` and the deployment binding from the
configured genesis hash, starts from the empty Poseidon root, and pins the
mint, the treasury token account and the state and clearance signing keys. A
deposit is staged in an operation buffer (`initialize_operation`,
`write_operation`) and executed by `execute_deposit`, which transfers exactly
the amount from a USDC source account whose token authority (`depositor`) may
be any signer, including a CPI PDA. It must have positive amount within
`2^53 - 1` base units and the expiry `now + note_ttl` rounded up to a whole
day. Because SBF cannot afford a
Poseidon tree update, the deposit carries a Groth16 proof of the auxiliary
Merkle-transition statement (`dagon-zkapi-solana-transition-v1`, 10 public
inputs: protocol version, chain ID, deployment binding, old root, new root,
note ID, registration, amount, expiry, inserting flag), which authenticates
the new root for inserting the note leaf.

Every mutation reasserts solvency:
`vault_token.amount >= total_credits + treasury_accrued + deferred_payouts`.
Tokens donated to the vault token account are permanent surplus.

Treasury shares are pulled, not pushed: mutual close, finalize and
`execute_claim_expired` add the operator share (or the swept deposit) to
`treasury_accrued`, and the permissionless `withdraw_treasury` sends the
accrued total to the pinned treasury token account (`TreasuryWithdrawn`). A
treasury that cannot receive USDC therefore cannot block any user payout.

The withdrawal destination bound by the proof is the payout USDC token account
(any owner). Clients default it to the wallet's canonical associated token
account and create that account first (caller pays rent); the program never
derives one.

Mutual close (`execute_close`) pays the user's final balance to the chosen
destination token account (failing if it cannot be credited; zero skips the
transfer) and accrues the spent amount for the treasury, consumes the
withdrawal nullifier, and marks the note `Closed`; the leaf stays in the tree
until `retire_closed_leaf` (permissionless, `Closed`-only, with a removal
transition proof) removes it. Exits never remove a leaf and never take a
Merkle path or root, so a root-changing deposit cannot front-run them.

Escape initiation (`execute_escape`) proves the exit statement for a
leaf-bound state, consumes the state's nullifier `N` and its derived successor
nullifier `N+` (each a `["nullifier", vault, N]` PDA), records a
`["pending", vault, note_id]` withdrawal and starts the challenge period. The
pending withdrawal pays `final = state_balance - conceded` to the destination,
where the proof reveals the concession `c` and requires `final + c <= D`.
`valid_until` bounds how long a prepared exit proof can be submitted. The
destination must be a creditable USDC token account (initialized, not frozen,
not the vault token account) at initiation.

Challenge (the leaf stays in the tree; there is no second phase and no restore):

- Defeat (`execute_challenge(note_id, request)`): a valid request proof whose
  request nullifier equals the pending `N+` proves the user spent past the
  escaped state. The note returns to `Active`, `N` becomes `Challenged`, `N+` is
  released, and `EscapeWithdrawalDefeated` is emitted. Defeat is
  root-independent and does not write the vault account.
- Raise (`raise_escape_concession(note_id, request, amount)`): a request proof
  at the escaped nullifier `N` (the request that spent the escaped state)
  raises the concession to `c' = min(amount, sb, state_balance)`, where `sb` is
  the request's solvency bound; `c' > c` is required (`ConcessionNotRaised`).
  The payout becomes `state_balance - c'` (`EscapeConcessionRaised`). The
  deadline does not change and a later defeat is still possible.
- Finalize (`finalize_escape(note_id)`) is permissionless after the deadline;
  it closes the note, accrues the remainder of the deposit for the treasury and
  pays the pending final balance to the destination. If the destination cannot
  be credited then (closed, frozen, reassigned), the payout is parked in
  `deferred_payouts` and the pending record kept; the permissionless
  `release_escape_payout(note_id)` pays it, retryable forever and only to that
  bound account. A closed non-associated keypair account can be re-created
  only by its keypair holder; an account frozen by the USDC freeze authority
  stays parked until unfrozen. Pending rent goes only to the escaper; if the
  escaper's address became executable, `refund_pending_rent(note_id)` returns
  it later.

After a defeat the note sets `claimable_after` so an expiry sweep cannot occur
before the user can exit again.

Nullifier states: `0` unused or released, `1` consumed, `2` challenged. An
escape whose `N+` is `Challenged` is rejected as superseded; a consumed `N` or
`N+` is rejected as replayed.

Bounded pause: the authority can pause deposits and exits for at most
`MAX_PAUSE_DURATION` (7 days). The pause lapses by itself, and a new pause needs
`PAUSE_COOLDOWN` (1 day) after the previous one ended. Challenge, raise and
finalize are never blocked. `execute_claim_expired` is rejected while the vault
is effectively paused, and each note's claimable time is extended by the paused
time accumulated since its deposit. Expired notes are claimed for the treasury
only through `execute_claim_expired` after that time.

**Concession rule and guarantees.** An exit from state `S_k` releases a single
bound `b_k` per state: the client never proves more than one request bound
against the same state. The exit proves a concession `c`: in-flight value the
operator may be owed. An honest client picks `c = 0` when no request is in
flight and otherwise waits for settlement (or `expiry - 12h`) and concedes
`b_k` or the reported charge. The guarantees are:

- G1 (honest user): from the newest installed state `S_k`, the user is paid at
  least `B_k - b_k` without operator cooperation, including when the operator
  withholds the successor state, a depositor front-runs the exit, or the vault
  is paused.
- G2 (honest operator): total paid on a note is at most
  `D - sum(owed(served requests))`. A user who spent `S_{k+1}` cannot be paid
  from `S_k`: the request at `N+` defeats the escape, or the request at `N`
  raises the concession to the owed amount.
- G3 (privacy): requests stay unlinkable; new linkage appears only at exit, for
  the exiting note, for its last request.

A request proof proves authorization, not delivery. The server therefore signs
the successor state only after the request nullifier is confirmed unused
on-chain (settle-then-sign) and stores request evidence append-only so the
challenger can defeat or raise a stale escape.

## Source ownership

- [zkapi-core](rust/crates/zkapi-core): native hashing and Merkle helpers.
- [zkapi-proof](rust/crates/zkapi-proof): circuits, proving and verification,
  signing, commitments, and setup serialization.
- [zkapi-browser](rust/crates/zkapi-browser): browser wallet core.
- [zkapi-client](rust/crates/zkapi-client): native wallet and persistence.
- [Solana vault program](../solana/programs/dagon-zkapi-vault).
- [Root runtime crates](../crates): server, challenge service, indexer, and CLI.
- [SDK](../sdk): browser integration and public proof assets.

## Setup compatibility and verification

The wire version is v2 and the circuit ID is `zkapi-v2-concession-v1`.
Keys carry that circuit header. Setup files, the verifying keys embedded in the
Solana vault (`npm run generate:solana-vk`, checked by
`npm run verify:solana-vk`), WASM, and SDK asset hashes must remain paired. See
[the setup README](setup/v2/README.md) for setup provenance, compatibility
requirements, and trust assumptions; the snarkjs ceremony bridge is documented
in [`ceremony/`](../ceremony).

Run protocol Rust tests with
`cargo test --release --manifest-path rust/Cargo.toml --workspace --locked`. The
parent workspace tests the Solana program, HTTP and settlement integration;
the local Solana validator stack runs the mainnet configuration end to end.
Regenerating setup keys is a separate change that requires regenerating all
dependent artifacts and redeploying the vault with its matching verifying keys.
