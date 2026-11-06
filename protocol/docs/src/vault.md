# Solana Vault Program

The [Anchor vault program](../../../solana/programs/dagon-zkapi-vault/src/lib.rs)
(`dagon-zkapi-vault`) accepts native SOL deposits in lamports, maintains the
depth-32 active-note tree root, and pins the server's state and clearance
signing keys and the treasury. Amounts are bounded by `2^53 - 1` lamports. Its
shared parameters (program id, vault version, request charge cap, note TTL,
challenge period, pause bounds) come from `solana/profile/shared.json`; only the
network identity differs between clusters. The EVM vault of upstream
[ethereum/zkapi](https://github.com/ethereum/zkapi) is not part of this
repository.

`initialize` creates the vault-state PDA `["vault", authority]` and derives the
statement fields `chain_id = solana_chain_id(genesis_hash)` and
`contract_address = solana_deployment_binding(program_id, vault_state,
genesis_hash)` ([solana.rs](../../rust/crates/zkapi-types/src/solana.rs)).
Request and withdrawal proofs are verified on chain with Solana's BN254
syscalls against verifying keys embedded from `setup/v2`
([dagon-zkapi-solana](../../../crates/dagon-zkapi-solana)). SBF cannot afford a
Poseidon tree update, so `execute_deposit` and `retire_closed_leaf` carry a
proof of the auxiliary Merkle-transition circuit
(`dagon-zkapi-solana-transition-v1`, keys in `setup/solana-transition-v1`) that
authenticates the new root. Deposits are staged in an operation buffer
(`initialize_operation`, `write_operation`, `cancel_operation`) because the
payload exceeds one transaction.

Mutual close (`execute_close`) pays the final balance to the destination,
accrues the spent balance for the treasury, consumes the withdrawal nullifier
and marks the note `Closed`; the leaf stays until the permissionless
`retire_closed_leaf`. Exits (`execute_close`, `execute_escape`) are leaf-bound
and root-free: they take no Merkle path, never remove a leaf, and check
`valid_until` and the note fields against the stored note. The 20-byte
destination statement field must equal
`solana_destination_binding(destination_account)`. Escape consumes the state
nullifier and its derived successor `N+` (nullifier PDAs
`["nullifier", vault, N]`) and records a `["pending", vault, note_id]` account.
A challenge never removes or restores a leaf: `execute_challenge` defeats the
escape with a valid request proof at `N+` (`EscapeWithdrawalDefeated`; `N`
becomes challenged, `N+` is released), `raise_escape_concession` raises the
concession up to the request's solvency bound (`EscapeConcessionRaised`), and
`finalize_escape` is permissionless after the deadline. The escape destination
is checked to be creditable at initiation, so the payout cannot be blocked;
operator revenue accrues in `treasury_accrued` and is flushed by the
permissionless `withdraw_treasury`. Nullifier states are `0` unused/released,
`1` consumed, `2` challenged. The authority pause is bounded by
`MAX_PAUSE_DURATION` (7 days) with a `PAUSE_COOLDOWN` (1 day);
`execute_claim_expired` needs no path, is rejected while paused, and paused
time extends each note's claimable time. The concession rule gives the honest
user at least `B_k - b_k` without operator cooperation (G1) and bounds payouts
by `D` minus owed charges (G2).
