# Dagon zkAPI protocol API

The browser SDK sends prompt-free proof authorizations to the Dagon server.
Inference runs directly against the issued provider key.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/health` | Process and deployment summary |
| GET | `/v1/attestation` | Public signing keys and protocol pins |
| GET | `/v2/auth` | Validate the configured Sepolia shared password without side effects |
| GET | `/v2/billing/quote` | Pinned finalized native-SOL/Pyth billing quote (or explicit EVM compatibility quote) |
| POST | `/v2/openrouter/leases` | Verify proof and reserve a bounded runtime key |
| GET | `/v2/openrouter/leases/{client_request_id}` | Non-secret lease status |
| POST | `/v2/openrouter/leases/{client_request_id}` | Retire and settle the exact lease |
| POST | `/v2/openrouter/leases/{client_request_id}/expire` | Authoritative recovery of an expired or superseded unaccepted request |
| POST | `/v2/withdraw/clearance` | Mutual-close Schnorr clearance |
| POST | `/v2/ledger/deposits/prepare` | Prepare ordered Solana deposit messages |
| POST | `/v2/ledger/withdrawals/prepare` | Prepare ordered Solana mutual-close messages |
| POST | `/v2/ledger/escapes/prepare` | Prepare ordered Solana escape messages |
| POST | `/v2/ledger/escapes/finalize/prepare` | Prepare Solana escape finalization |
| GET | `/v2/requests/{client_request_id}` | Recover signed settlement |
| GET | `/v2/nullifiers/{nullifier}` | Recover by nullifier |

When public `/health` reports `testnet_password_required: true`, all `/v2/*`
routes require `X-ZKAPI-Testnet-Password`. Missing or incorrect passwords return
HTTP 401 with `error_code: "testnet_password_required"` before request parsing.
See [Sepolia shared password](testnet-auth.md) for the complete access,
transport and credential-lifecycle contract. Mainnet is unaffected.

A lease uses `ApiRequestV2`: client request ID, canonical prompt-free payload,
payload hash, public inputs and `{backend: "groth16_bn254", proof: "base64..."}`.
The authorization payload includes mode/version and its frozen `billing_quote`.
The server recomputes payload/request binding, validates the native quote and
verifies the proof. Proof bytes contain eight canonical 32-byte coordinates
(256 bytes total). Public inputs, proof coordinates and circuit ID are unchanged.

The runtime key is returned once. Retry/recovery must preserve the exact saved
request and journal, including quote and proof. A native lamport solvency bound is
converted to the provider's USD budget using the frozen quote. Settlement uses
actual provider usage converted back to lamports, then verifies/installs a signed
next balance. An unavailable receipt must not be treated as zero usage.

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
