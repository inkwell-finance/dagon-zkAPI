# Solidity Contracts

[ZkApiVault](../../contracts/src/ZkApiVault.sol) accepts native ETH deposits in
whole gwei, maintains the depth-32 active-note tree, and pins the server's state
and clearance signing keys. Amounts are bounded by `2^53 - 1` gwei.

[NoteLeafLib](../../contracts/src/libraries/NoteLeafLib.sol) and
[MerkleUpdateLib](../../contracts/src/libraries/MerkleUpdateLib.sol) use the
[BN254 Poseidon implementation](../../contracts/src/libraries/Bn254Poseidon.sol)
shared with the circuit parameters.

[Groth16ProofAdapter](../../contracts/src/adapters/Groth16ProofAdapter.sol)
verifies the request and withdrawal statements directly. Public deployment
fields and pinned signing keys are checked by the vault before settlement.

Mutual close pays the final balance to the destination and the spent balance
to the treasury, consumes the request nullifier and marks the note `Closed`;
the leaf stays until the permissionless `retireClosedLeaf(noteId, siblings)`.
Exits (`mutualClose`, `initiateEscapeWithdrawal`) are leaf-bound and root-free:
they take no Merkle path, never remove a leaf, and check `validUntil` and the
note fields against the stored note. Escape consumes the state nullifier and its
derived successor `N+`. A challenge never removes or restores a leaf:
`challengeEscapeWithdrawal` defeats the escape with a valid request proof at
`N+` (`EscapeWithdrawalDefeated`; `N` becomes challenged, `N+` is released),
`raiseEscapeConcession` raises the concession up to the request's solvency bound
(`EscapeConcessionRaised`), and `finalizeEscapeWithdrawal` is permissionless
after the deadline; it pushes the payout with `ESCAPE_PAYOUT_GAS` and credits a
destination that refuses it (`EscapePayoutDeferred`, `claimEscapePayout`), so
the note always closes and the operator share always accrues. Nullifier states
are `0` unused/released, `1` consumed, `2` challenged (`nullifierState`). The
owner pause is bounded by
`MAX_PAUSE_DURATION` (7 days) with a `PAUSE_COOLDOWN` (1 day); `claimExpired`
needs no path, reverts while paused, and paused time extends each note's
`claimableAt`. The concession rule gives the honest user at least `B_k - b_k`
without operator cooperation (G1) and bounds payouts by `D` minus owed charges
(G2). [Types.sol](../../contracts/src/libraries/Types.sol) defines the current
note state and proof statements.
