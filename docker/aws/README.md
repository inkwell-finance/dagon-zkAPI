# Dagon zkAPI operator deployment

The operator image runs the Dagon server, finalized tree indexer and optional
escape challenger. Solana is the default ledger. Set `LEDGER_BACKEND=evm` only
for the legacy EVM compatibility deployment.

This is release-candidate packaging, not a populated production deployment.
The fresh SBF build and full funded local-validator lifecycle have passed, but
operators must still review the exact immutable deployment and live Pyth
accounts they pin. Unit/startup tests cannot substitute for those
deployment-specific checks.

## Files

Create the host directories and copy the examples:

```sh
sudo install -d -m 0700 /etc/zkapi
sudo install -d -m 0700 -o 10001 -g 10001 /var/lib/zkapi
sudo install -m 0644 docker/aws/deployment.env.example /etc/zkapi/deployment.env
sudo install -m 0600 docker/aws/indexer.env.example /etc/zkapi/indexer.env
sudo install -m 0600 docker/aws/server.env.example /etc/zkapi/server.env
sudo install -m 0600 docker/aws/challenge.env.example /etc/zkapi/challenge.env
```

Replace every placeholder. Never commit the populated files.

| File | Contents |
| --- | --- |
| `deployment.env` | Public immutable Solana identity, request policy and Pyth pins |
| `indexer.env` | Finalized-read RPC used by the indexer |
| `server.env` | Distinct signing seeds and exactly one lease-issuer credential |
| `challenge.env` | Challenger finalized RPC and read-only keypair path |
| `challenge-keypair.json` | Dedicated rent/transaction payer; mode `0600` |
| `config.json` | Public browser deployment manifest served by the gateway |

The compose file mounts `/etc/zkapi` read-only at `/run/dagon-zkapi` for the
challenger and persists only `/data`. The keypair must not be the vault treasury,
upgrade authority or any user wallet.

## Start Solana services

Build and start the indexer/server:

```sh
docker compose -f docker/aws/compose.yml build
docker compose -f docker/aws/compose.yml up -d indexer server gateway
```

After the server is healthy, enable the challenger profile:

```sh
docker compose -f docker/aws/compose.yml --profile challenge up -d challenger
```

The image entrypoint is `dagon-zkapi-run`. It rejects missing deployment pins,
mixed Solana/EVM settings, the public development signing seeds and a circuit
other than `zkapi-v2-concession-v1`. A legacy `zkapi-v2-note-bound-v1`
environment is refused: concession-exit keys need a fresh vault or program.

Server startup additionally fails closed unless the RPC genesis matches, the
program is executable and permanently immutable, the vault PDA/config/signing
keys match, the vault is unpaused, and the pinned finalized Pyth quote satisfies
the configured age/confidence policy.

## Explicit EVM compatibility

Copy `deployment.evm.env.example` to `deployment.env`, set
`LEDGER_BACKEND=evm`, and provide the former Chainlink/native-ETH settings. The
restricted signer sidecar is retained only under the `evm-compat` profile:

```sh
docker compose -f docker/aws/compose.yml --profile evm-compat up -d signer
```

Then start the EVM challenger with both profiles enabled:

```sh
docker compose -f docker/aws/compose.yml --profile challenge --profile evm-compat up -d signer challenger
```

The EVM challenger uses `ZKAPI_CHALLENGE_RPC_URL` and
`ZKAPI_CHALLENGE_SENDER` in its secret environment. Do not run the signer
sidecar for a Solana deployment.

## Operations

- Do not publish server, indexer, signer or challenger ports. Only the gateway
  should be reachable by clients.
- Preserve `/var/lib/zkapi`; it contains the transcript database, finalized
  indexer state and challenge checkpoint.
- Back up populated public deployment metadata together with its exact program,
  vault, setup and SDK artifact hashes.
- Rotate provider credentials independently of signing seeds. Changing signing
  seeds requires a new vault identity and client configuration.
- Monitor `/health`, finalized RPC availability, quote freshness, settlement
  retries and challenger progress. Stop funded operation on any identity drift.
