# Dagon zkAPI protocol API

The browser SDK sends prompt-free proof authorizations to the Dagon server.
Inference runs directly against the issued provider key.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/health` | Process and deployment summary |
| GET | `/v1/attestation` | Public signing keys and protocol pins |
| GET | `/v2/auth` | Validate the configured testnet shared password without side effects |
| POST | `/v2/openrouter/leases` | Verify proof and reserve a bounded runtime key |
| GET | `/v2/openrouter/leases/{client_request_id}` | Non-secret lease status |
| POST | `/v2/openrouter/leases/{client_request_id}` | Retire and settle the exact lease |
| POST | `/v2/withdraw/clearance` | Mutual-close Schnorr clearance |
| POST | `/v2/ledger/deposits/prepare` | Prepare ordered Solana USDC deposit messages |
| POST | `/v2/ledger/withdrawals/prepare` | Prepare ordered Solana mutual-close messages |
| POST | `/v2/ledger/escapes/prepare` | Prepare ordered Solana escape messages |
| POST | `/v2/ledger/escapes/finalize/prepare` | Prepare Solana escape finalization |
| POST | `/v2/ledger/escapes/release/prepare` | Prepare release of a parked escape payout (`{payer, note_id}`) |
| POST | `/v2/ledger/escapes/rent-refund/prepare` | Prepare refund of parked escape rent to the escaper (`{payer, note_id}`) |
| POST | `/v2/ledger/usdc-accounts/prepare` | Prepare idempotent creation of `owner`'s canonical USDC token account, rent paid by `payer` (`{payer, owner}`) |
| GET | `/v2/relay` | Optional CCTP relay: relayer, fee account, margin, SOL price, worst-case quotes, relayed burn minimum |
| POST | `/v2/relay/deposits/prepare` | Atomic ek-owned deposit with rent advance/refund; unsigned v0 transaction + `submit_token`, no standalone staging |
| POST | `/v2/relay/receives/prepare` | Fallback CCTP receive of a zkAPI inbound burn into an existing `ATA(ek)`: relayer-signed v0 transaction, client broadcasts |
| POST | `/v2/relay/exits/prepare` | Mutual close or escape with the relayer as vault owner and the ek's fee in the same v0 transaction; unsigned + `submit_token` |
| POST | `/v2/relay/escapes/finalize` | Finalize or release a relayed escape |
| POST | `/v2/relay/burns/prepare` | CCTP burn of `ATA(owner)`; unsigned + `submit_token` (the relay holds the event key) |
| POST | `/v2/relay/sweeps/prepare` | Sweep of `ATA(owner)` to an existing USDC account; unsigned + `submit_token` |
| POST | `/v2/relay/submit` | Ek-signed prepared transaction + token: the relay signs, reserves risk, broadcasts and returns it complete |
| GET | `/v2/requests/{client_request_id}` | Recover signed settlement |
| GET | `/v2/nullifiers/{nullifier}` | Recover by nullifier |

When public `/health` reports `testnet_password_required: true`, all `/v2/*`
routes require `X-ZKAPI-Testnet-Password`. Missing or incorrect passwords return
HTTP 401 with `error_code: "testnet_password_required"` before request parsing.
See [testnet shared password](testnet-auth.md) for the complete access,
transport and credential-lifecycle contract. `mainnet-beta` refuses the gate.

A lease uses `ApiRequestV2`: client request ID, canonical prompt-free payload,
payload hash, public inputs and `{backend: "groth16_bn254", proof: "base64..."}`.
The authorization payload is exactly
`{"mode":"openrouter_ephemeral_lease","version":1}`. The server recomputes
payload/request binding and verifies the proof. Proof bytes contain eight
canonical 32-byte coordinates (256 bytes total). Public inputs, proof
coordinates and circuit ID are unchanged.

The runtime key is returned once. Retry/recovery must preserve the exact saved
request, journal and proof. Credits are USDC base units (micro-USDC) billed as
micro-USD with no price conversion: the proof-bound `solvency_bound` (at least
the $1 `request_charge_cap`) is the provider spend limit in micro-USD, and
settlement charges actual provider usage rounded up to whole micro-USD, capped
at that bound, then verifies/installs a signed next balance. An unavailable
receipt must not be treated as zero usage.

Withdrawal and escape prepare bodies take `destination` = the payout USDC token
account (any owner; clients default to the wallet's canonical associated token
account and create it first with `/v2/ledger/usdc-accounts/prepare`). Deposits
draw from the payer's canonical USDC token account.

The `/v2/relay/*` routes exist only when the operator configures a relay key
(otherwise `404 {"error":{"code":"relay_disabled"}}`); see
[the server's relay section](SOLANA_SERVER.md#cctp-relay) for fees, the receive subsidy,
the exact transaction shapes and the error codes.

OA-org issuance includes verifier-backed station/org evidence checked by the
browser's independently pinned verifier. Directly managed keys use durable
disable, grace, usage capture and confirmed deletion before settlement. The
provider's aggregate usage delay remains an operator assumption for direct mode.

The indexer provides `/v1/tree/root`, `/v1/tree/snapshot`,
`/v1/tree/notes/{note_id}/path`, `/v1/tree/notes/{note_id}/zero-path`, and
`/v1/tree/next-note-id`; see its route source for the
full endpoint set. Solana wallet operations use server-prepared messages that
the browser independently validates, journals, signs through Wallet Standard,
submits and verifies at finalized commitment.

Request evidence and signing follow settle-then-sign: the server derives the next
anchor `H(d_anchor, N)`, writes the request to an append-only evidence table in
the reservation transaction, and signs the successor state only after the
request nullifier is confirmed unused on the ledger. A request whose nullifier an
escape already consumed is deferred (exit-deferred, then ExitedUnsigned after the
challenge period plus margin) and signed later only if a defeat released the
nullifier. Recovery by request or nullifier returns a status only once the
nullifier is on the ledger. The restore route is removed: exits never remove a
leaf, so challenges need no restoration. Escape requests carry the 16-input
withdrawal statement (note-bound nullifier, successor nullifier, concession,
`valid_until`); the vault pause is bounded to 7 days.
