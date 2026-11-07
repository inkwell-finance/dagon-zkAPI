# Solana Vault Program

The [Anchor vault program](../../../solana/programs/dagon-zkapi-vault/src/lib.rs)
(`dagon-zkapi-vault`, program id `8cYsHTNTvS5DwNqFaJ3LDZo8ed1k53cdgWQVZqEN45BX`,
immutable) accepts Circle USDC deposits, maintains the depth-32 active-note
tree root, and pins the server's state and clearance signing keys, the USDC
mint and the treasury token account. Its shared parameters (program id, USDC
asset, vault version, request charge cap, note TTL, challenge period, pause
bounds) come from `solana/profile/shared.json`; only the network identity
differs between clusters. The EVM vault of upstream
[ethereum/zkapi](https://github.com/ethereum/zkapi) is not part of this
repository.

## Asset and accounts

- Mint: USDC `EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v`, 6 decimals,
  classic SPL Token program only. Token-2022 accounts and mints are rejected
  everywhere. One credit is one base unit (one micro-USDC); amounts are bounded
  by `2^53 - 1`. The request charge cap is 1,000,000 base units ($1).
- Vault token account: the PDA `["vault-token", vault_state]`, a classic token
  account whose token authority is the vault-state PDA, created by
  `initialize`.
- Treasury: one pinned classic USDC token account of any owner (identity
  `treasury_token_account`), which must be creditable at initialization.
- Deposits: the operation owner signs and pays rent; the token authority of the
  source account (`depositor`) may be any signer, including a program PDA
  signing through CPI (for example a CCTP forwarder), and may equal the owner.
  The vault checks that it received exactly the deposit amount.
- Payout destination: the proof-bound withdrawal destination is the payout
  *token account* address, any classic USDC account with any owner (wallet,
  associated token account, PDA-owned account). The program never derives an
  associated token account; clients default to the wallet's canonical one and
  create it first (Associated Token Account `CreateIdempotent`, caller pays
  rent).
- Solvency is reasserted after every mutation:
  `vault_token.amount >= total_credits + treasury_accrued + deferred_payouts`.
  Tokens sent to the vault token account outside a deposit are a permanent
  surplus; nothing sweeps them.
- Users need a little SOL besides USDC for transaction fees and rent (operation
  buffer, note, nullifier and pending records, and any token account they
  create).
- USDC's issuer can freeze any USDC token account. A frozen vault token account
  blocks every deposit and payout until unfrozen; this risk is inherent to USDC
  and outside the protocol.

## Instructions

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

Mutual close (`execute_close`) pays the final balance to the destination token
account (the transaction fails if it cannot be credited; a zero final balance
skips the transfer), accrues the spent balance for the treasury, consumes the
withdrawal nullifier and marks the note `Closed`; the leaf stays until the
permissionless `retire_closed_leaf`. Exits (`execute_close`, `execute_escape`)
are leaf-bound and root-free: they take no Merkle path, never remove a leaf,
and check `valid_until` and the note fields against the stored note. The
20-byte destination statement field must equal
`solana_destination_binding(destination_token_account)`. Escape requires the
destination to be creditable at initiation (initialized, not frozen, USDC mint,
not the vault token account), consumes the state nullifier and its derived
successor `N+` (nullifier PDAs `["nullifier", vault, N]`) and records a
`["pending", vault, note_id]` account whose rent payer is the escaper.
A challenge never removes or restores a leaf: `execute_challenge` defeats the
escape with a valid request proof at `N+` (`EscapeWithdrawalDefeated`; `N`
becomes challenged, `N+` is released), `raise_escape_concession` raises the
concession up to the request's solvency bound (`EscapeConcessionRaised`), and
`finalize_escape` is permissionless after the deadline.

## Parked escape payouts

`finalize_escape` always closes the note and accrues the operator share. If the
destination can no longer be credited (closed, frozen, reassigned), the user's
final balance is parked: it moves to `deferred_payouts`, the pending record
stays with `payout_deferred = true` in `EscapeWithdrawalFinalized`, and
`release_escape_payout(note_id)` pays it later. Release is permissionless,
retryable forever with no expiry or sweep, and pays only the proof-bound
destination account (`EscapePayoutReleased`). Consequences:

- A closed associated token account can be re-created by anyone with
  `CreateIdempotent`, after which anyone can release.
- A closed non-ATA keypair account can only be re-created by the holder of that
  keypair; until then the payout stays parked.
- A destination frozen by USDC's freeze authority keeps the payout parked
  until it is unfrozen.

The pending record's rent is refunded only to the escaper (`rent_payer`), never
to the caller or the destination. If the escaper's address has become
executable when finalize or release runs, the rent stays parked and the
permissionless `refund_pending_rent(note_id)` returns it to the escaper once it
can receive lamports again.

## Treasury, nullifiers and pause

Operator revenue accrues in `treasury_accrued` and is flushed by the
permissionless `withdraw_treasury` to the pinned treasury token account; a
treasury that cannot receive USDC fails only that transaction, never a user
exit. Nullifier states are `0` unused/released, `1` consumed, `2` challenged.
The authority pause is bounded by `MAX_PAUSE_DURATION` (7 days) with a
`PAUSE_COOLDOWN` (1 day); `execute_claim_expired` needs no path, is rejected
while paused, accrues the whole deposit for the treasury, and paused time
extends each note's claimable time. The concession rule gives the honest user
at least `B_k - b_k` without operator cooperation (G1) and bounds payouts by
`D` minus owed charges (G2).
