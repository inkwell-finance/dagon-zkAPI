# Deployment-bound challenge signer

This internal JSON-RPC sidecar supplies `eth_sendTransaction` to
`dagon-zkapi-challenged --ledger evm`. It signs only two canonical vault calls:
`challengeEscapeWithdrawal(noteId, inputs, proof)` (the root-independent defeat
of a stale escape, with request evidence at its successor nullifier) and
`raiseEscapeConcession(noteId, inputs, proof, amount)` (a positive concession
raise, capped on-chain by the evidence's solvency bound). Exits, finalization,
`claimExpired`, `retireClosedLeaf` and `pause` are never signed. A caller
`gasPrice` is only a floor (the daemon's fee bump for a nonce that may already
hold a transaction, such as a defeat replacing an unmined raise) and is still
bounded by `ZKAPI_CHALLENGE_MAX_GAS_PRICE_WEI`; give the challenge daemon the
same value so its bumps stay within the cap. The signer signs
for one configured vault and explicitly configured chain (Mainnet 1 or
Sepolia 11155111), from its dedicated key, with
zero ETH value. It decodes the complete ABI, checks the proof's deployment,
simulates the call again, and checks current gas and fee bounds before signing
with ethers. It does not expose generic signing or raw-transaction forwarding.
It never signs a generic call; there is no restore transaction, because exits
never remove a leaf.

The read-only RPC allowlist includes `eth_gasPrice`: the daemon reads the
upstream fee through this same sidecar before persisting and submitting each
nonce reservation. Forwarding the quote does not relax signing fee caps.

Required environment, supplied only to this container:

```text
ZKAPI_CHALLENGE_PRIVATE_KEY=<dedicated funded key for this deployment>
ZKAPI_CHALLENGE_RPC_URL=https://<upstream RPC for the selected chain>
ZKAPI_CHALLENGE_CHAIN_ID=11155111
ZKAPI_CHALLENGE_VAULT=0x<fresh vault>
```

`ZKAPI_CHALLENGE_CHAIN_ID` is required; only canonical `1` and `11155111` are
accepted. There is no default or fallback. Use a fresh exclusive sender for
each network and deployment. Daemon chain/vault, signer chain/vault, decoded
proof and upstream chain must all agree.

Bind options are `ZKAPI_CHALLENGE_LISTEN_HOST` (default `127.0.0.1`) and
`ZKAPI_CHALLENGE_PORT` (default `8547`). Compose sets the host to `0.0.0.0`
on its private backend network and publishes no signer port. Never proxy this
service to the public internet. `GET /health` checks the upstream chain and
returns only public sender/vault metadata. Use its sender as the challenge
daemon's `--sender`; point that daemon's RPC URL at `http://signer:8547`.

The default `ZKAPI_CHALLENGE_MAX_GAS` is 12,000,000 (hard ceiling 16,777,216).
`ZKAPI_CHALLENGE_MAX_GAS_PRICE_WEI` defaults to 10,000,000,000 (10 gwei; hard
ceiling 100 gwei). The same caps apply on both networks. Before Mainnet funding,
choose explicit caps and a bounded dedicated account balance; maximum authorized
fee is gas limit multiplied by gas price. Calls exceeding a bound remain in the daemon's durable retry
queue. Transactions are legacy EIP-155 transactions with the current upstream
gas price; the signer does not autonomously increase fees or replace a pending
transaction. Monitor the dedicated sender's gas balance, stuck transactions,
and daemon retry/deadline logs.

The challenge daemon owns nonce reservation and its durable checkpoint. This
sidecar requires the explicit nonce and never allocates another on ambiguous
send failures. Run only one challenge daemon for the deployment and never use
its dedicated sender for other transactions. No signer state is written to
disk; the container can use a read-only filesystem. Keep the private key out of
the server/indexer/challenger environments and deployment manifests.

Run `npm ci --ignore-scripts && npm test` here. Tests use a public fixture key
and mock RPC responses, decode actual ethers signatures, and cover mismatched
deployment bindings, forbidden methods, failed simulation, fee/gas bounds,
durable nonce retries, and sanitized HTTP errors. No test broadcasts a chain
transaction.
