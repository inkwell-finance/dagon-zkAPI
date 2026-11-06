# Operating the v2 escape challenge service

`dagon-zkapi-challenged` reads the active server's SQLite transcript/lease database,
matches consumed request evidence to pending escape withdrawals, reconstructs
the archived Groth16 request proof, and submits a root-independent defeat or a
concession raise (no Merkle path needed) on the Solana vault.

Build it separately from the API server:

```sh
cargo build --release -p zkapi-serverd --bin dagon-zkapi-challenged
```

## Running

```sh
RUST_LOG=info target/release/dagon-zkapi-challenged \
  --solana-identity solana/profile/mainnet-beta.identity.json \
  --solana-rpc-url "$SOLANA_RPC_URL" \
  --solana-keypair /run/secrets/dagon-challenge-keypair.json \
  --db-path /var/lib/dagon-zkapi/server.db \
  --checkpoint /var/lib/dagon-zkapi/solana-challenges.json \
  --proof-setup-dir /var/lib/dagon-zkapi/setup/v2
```

The program id, challenge period and raise lead come from the compiled-in
profile; the identity file supplies the genesis hash and vault (see
[the Solana profile](solana-profile.md)). Optional `--poll-interval-ms N` sets
the poll cadence. The keypair must be a dedicated funded Solana challenge payer;
do not reuse the vault authority or expose the key file to the API process. At
startup the daemon verifies the identity genesis hash against the RPC, the
canonical vault identity, and an executable loader-v3 program with permanently
revoked upgrade authority before it accepts work. It needs no indexer.

Pending withdrawals are discovered as a finalized, canonical PDA set through
`CreditLedger::pending_escapes`, read in pages of at most 100 PDAs per RPC
response. A System-owned, data-less account at a pending PDA (anyone can fund
an address) is not program state and is ignored. Defeat and raise need no Merkle
path, so no indexer is involved. Deadline gating uses the finalized snapshot's Solana block time, not
the operator host clock. The daemon passes the unchanged historical request
statement and proof to `CreditLedger::prepare_challenge` (defeat) or
`prepare_raise_concession` (raise); the Solana backend
returns one direct transaction (the evidence fits one packet, so there is no
staged initialize/write step).

The signer accepts only canonical legacy messages whose sole required signer is
the configured payer. The checkpoint stores every signed wire transaction and
its deterministic signature before submission. On restart, the daemon checks
that signature through `CreditLedger::transaction_status`: an RPC response lost
after acceptance therefore resumes the exact operation instead of creating a
duplicate. Transactions advance in order after confirmation. The obligation is
retired only when the pending PDA disappears from a finalized snapshot.

If an unknown signed transaction has passed its last valid block height, the
daemon discards that plan and rebuilds a single fresh signed transaction.

## Evidence and recovery invariants

The server, prover, verifier, vault and daemon must use the same deployment and
`zkapi-v2-concession-v1` circuit setup. A finalized transcript or an active
issued lease supplies challenge evidence. Mere provisioning is insufficient: a
key must have been durably activated or usage finalized. Evidence reconstruction
is read-only; it never signs a balance or changes usage accounting.

The checkpoint is tied to the exact deployment and payer and is atomically
replaced after syncing. Both Windows and Unix use replace-existing semantics;
repeated writes cannot fail merely because the previous checkpoint exists.
Malformed, foreign, duplicate-note, wrong-signer and wrong-proof records fail
closed.

Watch `ledger escape challenge requires retry`, `Solana challenge poll failed`,
and especially `MISSED ledger escape challenge deadline`. The daemon does not
configure monitoring, keypair funding, priority fees, redundant infrastructure,
or external signer availability. RPC, indexer, signing and restart latency must
fit inside the vault's challenge period.

## Challenge rule, challenger policy and guarantees

The leaf never leaves the tree on exit, so a challenge needs no Merkle path, no
root and no second step. There is no restore transaction and no `Challenged`
note status. For a pending escape the challenger reads the pending record
(`nullifier` N, `next_nullifier` N+, `state_balance`, `conceded` c, deadline)
and the server's append-only `request_evidence` table at N and N+:

| Evidence | Action |
| --- | --- |
| A request proof with request nullifier N+ verifies | Defeat (`execute_challenge`) |
| No defeat; the request at N has a final owed amount (settled charge, or the solvency bound `sb` when it may have been delivered and is unsettled by deadline minus a lead time) greater than c | Raise to `min(amount, sb, state_balance)` (`raise_escape_concession`) with the request proof at N; must exceed c (`ConcessionNotRaised` otherwise) |
| Otherwise | Nothing |

A defeat supersedes an unconfirmed raise. `ledger_challenge_service.rs`
implements this policy. A raise may only increase the concession.

- Defeat: the vault verifies the request proof's deployment binding and that its
  request nullifier equals the pending N+. It does not check the root. The
  pending payout is deleted, N becomes challenged (state `2`), N+ is released,
  the note is `Active` again, and `claimableAfter` is set to
  `max(expiry, now + ...)` so an expiry sweep cannot race the user's next exit.
- Raise: payout becomes `state_balance - amount`.
- Finalize: `finalize_escape` is permissionless after the deadline and is never
  blocked by pause.

Nullifier states are `0` unused/released, `1` consumed, `2` challenged. The
ledger trait reports `Unused|Used` (released is unused; consumed and
challenged are used). An escape whose N+ is challenged reverts
`SupersededState`; a consumed N or N+ reverts `ReplayedNullifier`.

Closed leaves are retired with `retire_closed_leaf`: permissionless,
`Closed`-only, so an operator can remove a leaf whose challenger missed a
defeat. Expired notes are claimed with `execute_claim_expired`, which needs no
siblings, fails while the vault is effectively paused, and respects the note's
claimable-at time.

### Guarantees

Let S_k be the newest state the client installed and b_k the single bound it
released at S_k (0 if none).

- G1 (honest user): without operator cooperation the user is paid at least
  B_k - b_k. A request proof shows authorization, not delivery of the successor
  state; an operator who withholds the successor cannot challenge S_k away,
  because the client concedes at most b_k and the defeat evidence at N+ does not
  exist for a successor the user never received.
- G2 (honest operator): total paid on a note is at most D minus the owed amount
  of served requests. A user who spent S_{k+1} is defeated or conceded up to the
  owed amount at N+.
- G3 (privacy): requests stay unlinkable; linkage appears only at exit, only for
  the exiting note and its last request.

### Server obligations

The server derives the next anchor as `next_anchor(N) = H(d_anchor, N)`. It
refuses 0, 1, or any anchor that differs from the circuit-mirror recomputation.
Settle-then-sign: the charge is persisted at settlement, and the successor is
signed only when the vault reports N unused. Otherwise the request is
`exit_deferred`; after the challenge period plus 3600 s without a defeat
releasing N it becomes the terminal `exited_unsigned` (never signed, replay
refused). A background sweep re-checks deferred requests. The append-only
`request_evidence` table (exact public inputs and proof) is written in the same
SQLite transaction as the nullifier reservation, and triggers abort any UPDATE
or DELETE. Recovery returns a status only once N is on-chain.

The challenge period (86400 s) and raise lead (3600 s) come from the
compiled-in profile. Startup reads `VaultState.challenge_period` and refuses to
run unless it equals the profile. It also refuses unless lease TTL + settlement
grace (counted twice for directly managed OpenRouter keys, which drain again
after they are disabled) + two settlement polls + 600 s usage latency + raise
lead + 1800 s margin is at most the challenge period.
`--adversary withhold|random-anchor|born-spent|overcharge`
exists only with the cargo feature `adversary` and is refused in release builds.

### Challenger details

`dagon-zkapi-challenged` uses the profile's raise lead (3600 s). The raise
target is `min(Omega, sb, B)` where Omega is the settled charge, or `sb` when
access may have been delivered and is still unsettled at
`deadline - raise lead`, and 0 when access was provably never issued; an honest
fresh escape is never touched. A defeat replaces an unconfirmed raise with a
new defeat plan; a raise never replaces a defeat. The daemon uses
`prepare_challenge` and `prepare_raise_concession`. Checkpoint version is 2; old
checkpoints are rejected. The indexer decodes the initiated, defeated, raised,
finalized, mutual-close, `ExpiredClaimed`, `ClosedLeafRetired`, `VaultPaused`
and `VaultUnpaused` events; only `ClosedLeafRetired` removes a leaf, and the
snapshot has no `original_leaves`.

### Bounded pause

The vault pause is bounded: the maximum pause is 7 days and the pause cooldown
is 1 day (profile `max_pause_seconds`, `pause_cooldown_seconds`). Exits and deposits are blocked only while the pause is in effect;
defeat, raise and finalize are never blocked. The challenger must keep running
through a pause. The claimable-at time is extended by accumulated paused time, so an
indefinite pause cannot turn into an expiry sweep.

Completion for the daemon is "the escape is no longer pending at finalized".
The defeat and raise are direct transactions (no staged
operation account), so the challenger creates no operation accounts and
nothing can be orphaned. Live note and pending-escape scans ignore
System-owned, data-less accounts at program PDAs, because anyone can fund a PDA
address.
