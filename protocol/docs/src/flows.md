# End-to-End Flows

## Request

1. The wallet proves membership and a note-bound state, sufficient balance,
   rerandomization, the note-bound nullifier and anchor chain, and
   authorization for the exact request context.
2. The server verifies deployment, signing keys, time, root, bound, and proof.
3. A durable nullifier reservation prevents competing spends.
4. Provider execution or a short-lived OpenRouter lease determines usage.
5. The server applies the bounded charge, derives the next anchor
   `H(d_anchor, N)` and a fresh blinding delta, writes append-only request
   evidence, and signs the next state with Schnorr only after the request
   nullifier is confirmed unused on-chain (settle-then-sign).
6. The wallet verifies the returned transition and installs its next state.
   Prepared-request journals support retries and recovery.

## Mutual close

The client asks for clearance on the current withdrawal nullifier. The server
reserves it and returns a clearance signature. The client proves the final
balance and clearance, and the vault pays USDC to the user's
destination, accrues the operator share for the treasury, and marks the note
`Closed`.

## Escape and challenge

The client freezes the note, picks a concession `c` (0 when nothing is in
flight), and proves a leaf-bound, root-free withdrawal (16 public inputs,
`valid_until` short TTL) without clearance. Initiation consumes the state
nullifier and its derived successor `N+` and starts the challenge period; the
leaf stays in the tree. A stale state's `N+` is the request nullifier of the
spent successor. The challenge service submits the archived request proof as a
defeat (pending payout deleted, note `Active`, `N+` released), or raises the
concession up to the request's solvency bound when the evidence shows a larger
owed charge. Neither depends on the root, so a deposit cannot front-run them.

After the deadline anyone can finalize the pending withdrawal to its bound
destination. If an active note expires without close-out, its deposit can be
claimed for the treasury, but not while the vault is paused, and paused time
extends the claim time.
