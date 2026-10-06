# Solana vault -> serverd -> vcii lease (end-to-end scenario)

`scripts/solana-vcii-lease.mjs` is the Solana counterpart of `scripts/v2-vcii-lease.mjs`: deposit native SOL into the
Solana vault, prove, have `dagon-zkapi serverd --ledger solana` mint an OpenRouter-style lease through vcii's management API
(`POST /zk/v1/keys`), pay for an MCP `tools/call` with the `vcii_zk_` key, let serverd settle the note with vcii's measured
usage, and confirm the key is refused afterwards.

## What is real and what is mocked

Real: `solana-test-validator` (Agave 3.1.11, loopback), the actual `dagon-zkapi-vault` SBF program made immutable with
`solana program set-upgrade-authority --final`, `Initialize`, a native-SOL deposit (Solana Merkle-transition Groth16 proof
verified on chain), the finalized-account indexer (`dagon-zkapi-indexerd --ledger solana`), request Groth16 proofs, serverd's
full Solana startup (immutable-program gate, genesis pin, finalized vault read, finalized Pyth read), vcii lease
provisioning/usage/settlement, the wallet accepting the server-signed settlement.

Mocked: the Pyth SOL/USD account. `solana/dev/mock-pyth-writer` is a ~20-line program loaded at the Pyth receiver program ID
(`rec5EKMG...`) that copies instruction data into an account it owns. The harness fills the pre-created account at
`7UVimffx...` (Pyth's SOL/USD shard-0 address) with an official-SDK-serialized `PriceUpdateV2` (Full verification, the real
SOL/USD feed ID, correct length and zero padding) at a fixed `$150.00 +/- $0.01`, refreshed every 3 s with the current
time and a finalized `posted_slot`. No Wormhole/guardian verification and no real market price. A static clone of the real
account cannot work because serverd allows at most 60 s of price age.

## Running it

Needs Linux with Node 24, Rust, and Agave (`solana-test-validator`, `solana`, `cargo-build-sbf`), and a vcii dev server whose
`ZK_MANAGEMENT_KEY_SHA256` matches `VCII_ZK_MANAGEMENT_KEY` (`ZK_USD_PER_CREDIT=1.5`, `ZK_MAX_LEASE_USD>=2`). The recipe used
under Podman (`localhost/zk3-e2e` plus Agave v3.1.11 from the anza release tarball, `--network host` on a mirrored-network
WSL machine so `127.0.0.1:8813` reaches the Windows dev server):

```sh
# 1. SBF programs (the vault and the mock oracle writer)
(cd solana && cargo-build-sbf --manifest-path programs/dagon-zkapi-vault/Cargo.toml --sbf-out-dir /target/sbf)
(cd solana/dev/mock-pyth-writer && cargo-build-sbf --sbf-out-dir /target/sbf)
# 2. host binaries
cargo build --locked --release --target-dir /target/sol-host -p zkapi-cli --bin dagon-zkapi \
  -p zkapi-indexerd --bin dagon-zkapi-indexerd -p zkapi-serverd --example solana_acceptance_wallet
# 3. scenario
VCII_ZK_BASE=http://127.0.0.1:8813/zk VCII_ZK_MANAGEMENT_KEY=... node scripts/solana-vcii-lease.mjs \
  --bin-dir /target/sol-host/release --sbf-dir /target/sbf --key-dir /scratch/keys --output-dir /scratch/runs
```

The container must run with `--security-opt seccomp=unconfined --ulimit memlock=-1:-1`: Agave 3.x asserts `io_uring` support
when creating its accounts directories and the default Podman seccomp profile blocks it.

`--key-dir` holds three throwaway keypair files (payer, deployer, mock-Pyth updater); only public keys are printed.

## Things worth knowing (found while building this)

- **Immutability gate vs `solana-test-validator`.** `--upgradeable-program <id> <so> none` does not produce an immutable
  program: the program-data account stores `Some(11111111111111111111111111111111)`, so serverd's startup gate correctly
  refuses it ("still has an upgrade authority"). The harness deploys with a real authority and revokes it with
  `set-upgrade-authority --final`.
- **`Initialize` compute budget.** One of four fresh validators ran `Initialize` out of the default 200,000 units (genesis hash
  influences the work). Clients should request the 1.4M units / 128 KiB heap the ledger's own transactions use; the helper does.
- **u64 chain IDs.** The derived Solana chain ID usually exceeds 2^53 and the Rust public-input structs serialize it as a JSON
  number. A JS client that `JSON.parse`s and re-sends the request rounds it and serverd answers `protocol_mismatch`. The
  browser SDK's WASM layer stringifies it; the Node helper does the same.
- **Quote supersession.** serverd rejects a lease (`409 native_quote_superseded`) if a newer finalized Pyth publication exists
  between the quote fetch and the lease POST; proving took ~13 s here. The harness serializes and pauses its price refresher
  across quote -> prove -> lease. A real feed updating faster than a client can prove would make lease issuance racy, so
  clients should treat that error as retryable with a fresh quote.
- The finalized indexer lags the chain by roughly 15 s (about 32 slots); the harness polls instead of sleeping.
