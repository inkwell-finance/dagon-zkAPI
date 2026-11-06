# Legacy EVM compatibility architecture

This page documents the retained native-ETH backend. Dagon zkAPI defaults to
the Solana architecture described in [SOLANA_SERVER.md](SOLANA_SERVER.md).

```text
Host app -> browser SDK -> zkAPI server (proof-backed lease authorization)
                   |                  -> OA org/station or direct key management
                   |-> inference provider (prompts/responses)
                   |-> Ethereum native ETH vault
                   |-> indexer (current Merkle root and paths)

Challenger -> durable server transcripts + indexer -> restricted signer -> vault
```

The browser keeps note secrets, blindings, signing evidence and recovery journals.
It creates Groth16 proofs locally with the packaged WASM and matching keys.
The server verifies each exact authorization, reserves its nullifier, issues a
bounded key and persists settlement before returning a new signed balance.

The authorization includes a pinned finalized ETH/USD quote. Notes and signed
balances are integer gwei; provider costs are micro-USD converted using that
saved quote. Exact retries preserve the original proof and quote. See
[native billing](native-eth-billing.md) for rounding and recovery rules.

The indexer mirrors deposits, closes and escape transitions. The challenger
submits a root-independent defeat with the historical request proof (the payout
is cancelled, the note stays `Active`, the leaf never left the tree) or raises
the concession up to the request's solvency bound; anyone finalizes after the
deadline. Retries use durable deployment-bound
checkpoints. See [challenge operation](challenge-service.md).

Only the v2 Groth16/Baby-JubJub proof path and native ETH payment path are active.
The operator CLI supplies server/indexer/setup/signing-key commands; the host
application integrates the browser SDK directly. The separate [zkapi-clientd](../zkapi-clientd/README.md) frontend provides a local
OpenAI-compatible API backed by private native ETH balances. It packages a
pinned Rust wallet/prover with reviewed patches, separately from
this operator workspace. It has no ticket mode or token wallet.
