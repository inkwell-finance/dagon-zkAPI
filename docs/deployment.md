# Legacy EVM compatibility deployment

Dagon zkAPI production commands default to Solana. This page applies only when
`--ledger evm` is selected explicitly; use [SOLANA_SERVER.md](SOLANA_SERVER.md)
and the Solana-default `docker/aws/deployment.env.example` otherwise.

The source supports native ETH vaults and the concession-exit Groth16 circuit
`zkapi-v2-concession-v1`. The current selected setup remains a single-party
experimental setup; publishing code does not establish an independent audit or
setup ceremony. See [setup provenance](../protocol/setup/v2/README.md).

Configure the exact circuit artifacts, contract and signing-key pins, oracle
feed, and denomination for the vault. Preserve persistent operator state and
keep wallet journals bound to their configuration.

## Build services

```sh
cargo build --release --workspace
```

`dagon-zkapi serverd --ledger evm` requires `--native-billing-rpc-url` and
`--native-price-feed-address` (or corresponding `ZKAPI_NATIVE_*` variables), plus
an OA org/service credential or direct OpenRouter management credential.
Supply chain ID, vault, gwei request cap, matching signing seeds, database path,
indexer URL and the exact proof directory. Run `dagon-zkapi serverd --help` for flags.
Native prices come from the pinned finalized oracle round; a generic RPC/chain
or USD token configuration is not interchangeable with these pins.

For a private Sepolia test, configure `ZKAPI_TESTNET_PASSWORD` only in the
Sepolia server's secret environment. The built-in gate requires that password
for every service API call while leaving health and protocol metadata public.
See [Sepolia shared password](testnet-auth.md) for client behavior, proxy header
forwarding, validation and rotation. Never put this value in the public SDK
manifest or configure it on Mainnet.

## Contracts

`demo/contracts/script/Deploy.s.sol` deploys the real Groth16 adapter and a
native-only vault. It reads `PRIVATE_KEY`, `TREASURY`, `OUTPUT_PATH`, state and
clearance public-key coordinates, optional `CHAIN_ID`, `REQUEST_CHARGE_CAP`
and `CHALLENGE_PERIOD_SECONDS`. The deployment output is constructor metadata;
prepare the public SDK manifest with circuit/key hashes and oracle/deployment
pins separately. The vault accepts native ETH.

Use a fresh directory when intentionally generating a new Groth16 setup.
Keep challenger coverage and persistent server/indexer state available whenever
the vault holds funds. The owner pause is bounded (`MAX_PAUSE_DURATION` 7 days,
`PAUSE_COOLDOWN` 1 day) and the challenger must keep running during it.

## Runtime

The [Docker guide](../docker/aws/README.md) configures API, indexer, gateway,
challenger and a restricted private signer. The challenger needs a funded
exclusive account and must fit RPC/indexer/retry delays inside the challenge
window; see [challenge operation](challenge-service.md).

The host application packages the SDK assets for the selected network. Review
its trusted config against finalized on-chain deployment state, the public
manifest and the selected proof hashes before enabling funding.
