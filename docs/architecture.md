# Architecture

```text
Host app -> browser SDK -> zkAPI server (proof-backed lease authorization)
                   |                  -> OA org/station or direct key management
                   |-> inference provider (prompts/responses)
                   |-> Solana USDC vault (Wallet Standard transactions)
                   |-> indexer (finalized Merkle root and paths)

Challenger -> durable server transcripts -> Solana vault (defeat / raise)
```

The browser keeps note secrets, blindings, signing evidence and recovery journals.
It creates Groth16 proofs locally with the packaged WASM and matching keys.
The server verifies each exact authorization, reserves its nullifier, issues a
bounded key and persists settlement before returning a new signed balance.

Notes and signed balances are integer USDC base units (micro-USDC), and the
server bills one base unit per metered micro-USD, so no price oracle or quote
is involved. Exact retries preserve the original proof. See
[the Solana server](SOLANA_SERVER.md) for startup gates and billing rules.

Every shared parameter is compiled into the binaries from
`solana/profile/shared.json`; each deployment differs only by its network
identity file. See [the Solana profile](solana-profile.md).

The indexer mirrors deposits, closes and escape transitions from finalized
vault state. The challenger submits a root-independent defeat with the
historical request proof (the payout is cancelled, the note stays `Active`, the
leaf never left the tree) or raises the concession up to the request's solvency
bound; anyone finalizes after the deadline. Retries use durable
deployment-bound checkpoints. See [challenge operation](challenge-service.md).

Only the v2 Groth16/Baby-JubJub proof path and the classic-SPL USDC payment
path exist. The operator CLI supplies server/indexer/setup/signing-key commands and
`dagon-zkapi-deploy` supplies identity, vault initialization and parity
tooling; the host application integrates the browser SDK directly.
