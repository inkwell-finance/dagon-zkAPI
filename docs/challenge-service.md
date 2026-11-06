# Operating the v2 escape challenge service

`dagon-zkapi-challenged` reads the active server's SQLite transcript/lease database,
matches consumed request evidence to pending escape withdrawals, reconstructs
the archived Groth16 request proof, and submits a root-independent defeat or a
concession raise (no Merkle path needed). Solana is the production default. The EVM daemon is
retained only as an explicitly selected compatibility backend.

Build it separately from the API server:

```sh
cargo build --release -p zkapi-serverd --bin dagon-zkapi-challenged
```

## Solana Groth16 ledger (default)

```sh
RUST_LOG=info target/release/dagon-zkapi-challenged \
  --ledger solana \
  --solana-rpc-url "$SOLANA_RPC_URL" \
  --solana-program-id "$PROGRAM_ID" \
  --solana-vault-state "$VAULT_PDA" \
  --solana-genesis-hash "$GENESIS_HASH" \
  --solana-network mainnet-beta \
  --solana-keypair /run/secrets/dagon-challenge-keypair.json \
  --db-path /var/lib/dagon-zkapi/server.db \
  --checkpoint /var/lib/dagon-zkapi/solana-challenges.json \
  --proof-setup-dir /var/lib/dagon-zkapi/setup/v2
```

Every identity is explicit. The keypair must be a dedicated funded Solana
challenge payer; do not reuse the vault authority or expose the key file to
the API process. At startup the daemon verifies the pinned genesis hash,
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

## EVM compatibility mode

Select EVM explicitly; Solana and EVM options cannot be mixed:

```sh
RUST_LOG=info target/release/dagon-zkapi-challenged \
  --ledger evm \
  --rpc-url "$OPERATOR_SIGNER_RPC_URL" \
  --sender "$DEDICATED_CHALLENGE_ACCOUNT" \
  --chain-id "$CHAIN_ID" \
  --contract-address "$VAULT_ADDRESS" \
  --from-block "$VAULT_DEPLOYMENT_BLOCK" \
  --db-path /var/lib/dagon-zkapi/server.db \
  --checkpoint /var/lib/dagon-zkapi/evm-challenges.json \
  --proof-setup-dir /var/lib/dagon-zkapi/setup/v2 \
  --confirmations 2
```

The EVM RPC must implement `eth_sendTransaction` with an operator-controlled,
dedicated, funded sender. A public read-only RPC is insufficient. The daemon
locks its checkpoint so two processes cannot share one sender/deployment. Its
event cursor, reorg handling, nonce reservations and exact ABI simulation remain
unchanged. The EVM daemon takes no indexer (`--indexer-url` and
`ZKAPI_CHALLENGE_INDEXER_URL` are removed): defeat and raise need no Merkle path.

For the legacy AWS EVM deployment, [the bounded signer sidecar](../docker/aws/signer/README.md)
provides that signer RPC on a private container network. It is not a Solana
signer and must not be used for the default backend.

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

EVM operators should additionally watch `escape challenge requires retry` and
`MISSED escape challenge deadline`. The nonce lane never waits on a gap. A
reservation that was never broadcast, or that the node dropped, and that its
note no longer needs (the escape resolved, expired, no longer needs a raise, or
its call now fails simulation) is released as a spare. The next defeat or raise
takes the lowest spare, and any note holding a higher nonce moves its call down
to it; the superseded transaction stays tracked and reverts harmlessly if it
mines. A released transaction still in flight is tracked, never waited on.

A reservation without a known hash is not necessarily unused: an ambiguous
`eth_sendTransaction` failure may have been accepted. Every EVM send therefore
carries an explicit `gasPrice`, persisted with the reservation (and with a
released spare) before broadcast. A send to a nonce that the sender's
`pending` count shows occupied, or that already had an attempt, bids at least
1.25x the highest recorded attempt (or the known transaction) plus 1, never
less than `eth_gasPrice`. Bids are capped at `--max-gas-price-wei`
(`ZKAPI_CHALLENGE_MAX_GAS_PRICE_WEI`, default 10 gwei), which must equal the
signer's cap: the signer refuses any price above it, so a bump that would
exceed the cap is sent at the cap and retried each poll until the occupying
transaction mines or is dropped. Any failure before broadcast (simulation, gas
estimation, nonce or fee reads) releases an unsent reservation as a spare.

## Challenge rule, challenger policy and guarantees

The leaf never leaves the tree on exit, so a challenge needs no Merkle path, no
root and no second step. There is no restore transaction and no `Challenged`
note status. For a pending escape the challenger reads the pending record
(`nullifier` N, `next_nullifier` N+, `state_balance`, `conceded` c, deadline)
and the server's append-only `request_evidence` table at N and N+:

| Evidence | Action |
| --- | --- |
| A request proof with request nullifier N+ verifies | Defeat (`challengeEscapeWithdrawal` / `execute_challenge`) |
| No defeat; the request at N has a final owed amount (settled charge, or the solvency bound `sb` when it may have been delivered and is unsettled by deadline minus a lead time) greater than c | Raise to `min(amount, sb, state_balance)` (`raiseEscapeConcession` / `raise_escape_concession`) with the request proof at N; must exceed c (`ConcessionNotRaised` otherwise) |
| Otherwise | Nothing |

A defeat supersedes an unmined raise. Both ledger daemons
(`challenge_service.rs` for EVM, `ledger_challenge_service.rs` for Solana)
implement this policy. A raise may only increase the concession.

- Defeat: the vault verifies the request proof's deployment binding and that its
  request nullifier equals the pending N+. It does not check the root. The
  pending payout is deleted, N becomes challenged (state `2`), N+ is released,
  the note is `Active` again, and `claimableAfter` is set to
  `max(expiry, now + ...)` so an expiry sweep cannot race the user's next exit.
  EVM event: `EscapeWithdrawalDefeated(noteId, nullifier, nextNullifier)`.
- Raise: payout becomes `state_balance - amount`. EVM event:
  `EscapeConcessionRaised(noteId, nullifier, conceded, finalBalance)`.
- Finalize: `finalizeEscapeWithdrawal(noteId)` (EVM) / `finalize_escape`
  (Solana) is permissionless after the deadline and is never blocked by pause.

Nullifier states: EVM `usedNullifiers(n)` is true for any non-zero state, and
`nullifierState(n)` returns `0` unused/released, `1` consumed, `2` challenged.
The ledger trait reports `Unused|Used` (released is unused; consumed and
challenged are used). An escape whose N+ is challenged reverts
`SupersededState`; a consumed N or N+ reverts `ReplayedNullifier`.

Closed leaves are retired with `retireClosedLeaf(noteId, siblings)` (EVM) /
`retire_closed_leaf` (Solana): permissionless, `Closed`-only, so an operator can
remove a leaf whose challenger missed a defeat. EVM has no `Retired` status, so a
second `retireClosedLeaf` reverts `StaleRoot`. Expired notes are claimed with
`claimExpired(noteId)` / `execute_claim_expired`, which need no siblings, revert
while the vault is effectively paused, and respect `claimableAt` (EVM view
`claimableAt(uint32)`; `claimExpired` needs `now >= claimableAt`).

EVM timing: defeat and raise are allowed while `now <= deadline`; finalize needs
`now > deadline`. Escape and close need `now <= validUntil` (`ExitProofExpired`)
and `now < claimableAt` (`NoteExpired`). `mutualClose` rejects a challenged N
with `ReplayedNullifier`.

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

Server flags: `--challenge-period-seconds` (default 86400) and
`--raise-lead-seconds` (default 3600). Startup reads the vault's challenge period
(EVM `challengePeriod()`, Solana `VaultState.challenge_period`) and refuses to
run unless the flag equals it. It also refuses unless lease TTL + settlement
grace (counted twice for directly managed OpenRouter keys, which drain again
after they are disabled) + two settlement polls + 600 s usage latency + raise
lead + 1800 s margin is at most the challenge period.
`--adversary withhold|random-anchor|born-spent|overcharge`
exists only with the cargo feature `adversary` and is refused in release builds.

### Challenger details

`dagon-zkapi-challenged` takes `--raise-lead-seconds` (default 3600). The raise
target is `min(Omega, sb, B)` where Omega is the settled charge, or `sb` when
access may have been delivered and is still unsettled at
`deadline - raise lead`, and 0 when access was provably never issued; an honest
fresh escape is never touched. A defeat replaces an unmined raise (EVM: same
nonce, gas price at least 1.25x the previous plus 1; ledger: a new defeat plan);
a raise never replaces a defeat. The EVM daemon reads
`EscapeWithdrawalInitiated(uint32 indexed,uint256,uint256,uint128,uint128,address,uint64)`
and `pendingWithdrawals(uint32)` (8 words). The Solana path uses
`prepare_challenge` and `prepare_raise_concession`. Checkpoint version is 2; old
checkpoints are rejected. The indexer decodes the initiated, defeated, raised,
finalized, mutual-close, `ExpiredClaimed`, `ClosedLeafRetired`, `VaultPaused`
and `VaultUnpaused` events; only `ClosedLeafRetired` removes a leaf, and the
snapshot has no `original_leaves`.

### Bounded pause

The vault pause is bounded: `MAX_PAUSE_DURATION` is 7 days and `PAUSE_COOLDOWN`
is 1 day. Exits and deposits are blocked only while the pause is in effect;
defeat, raise and finalize are never blocked. The challenger must keep running
through a pause. `claimableAt` is extended by accumulated paused time, so an
indefinite pause cannot turn into an expiry sweep.

Completion for the daemon is "the escape is no longer pending at finalized", on
both ledgers. The Solana defeat and raise are direct transactions (no staged
operation account), so the challenger creates no operation accounts and
nothing can be orphaned. Live note and pending-escape scans ignore
System-owned, data-less accounts at program PDAs, because anyone can fund a PDA
address.
