# Dagon zkAPI operator deployment

The operator image runs the Dagon server, finalized tree indexer and optional
escape challenger against the Solana vault, and ships `dagon-zkapi-deploy`.
Every shared protocol parameter (program id and executable hash, circuit, vault
policy, server timing, Pyth programs, feed, shard and policy) is compiled into
the binaries from `solana/profile/shared.json`; operators supply only the
network identity file, a finalized RPC URL and secrets. See
`docs/solana-profile.md`.

The SOL/USD price comes from Pyth's free sponsored push feed (shard 0 of the
push oracle). The operator posts no prices and needs no Hermes API key or fee
payer for them. See `docs/SOLANA_SERVER.md`, "Pyth sponsored feed".

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
| `deployment.env` | Finalized Solana RPC URL, optional identity override and OA-org URL |
| `indexer.env` | Optional dedicated indexer RPC (`SOLANA_RPC_URL`) |
| `server.env` | Distinct signing seeds and exactly one lease-issuer credential |
| `challenge.env` | Challenger keypair path and optional dedicated RPC |
| `challenge-keypair.json` | Dedicated rent/transaction payer; mode `0600` |
| `config.json` | Public browser deployment manifest served by the gateway |

The challenger mounts `/etc/zkapi` read-only. Bind-mount any public identity
separately (below). The challenger keypair must be dedicated to it: not the
vault treasury, vault authority or any user wallet.

## Network identity

The image contains `solana/profile/mainnet-beta.identity.json` at
`/srv/zkapi/solana/profile/mainnet-beta.identity.json`, and the launcher uses
it unless `ZKAPI_SOLANA_IDENTITY` names another file. The identity file holds
only the allowed per-network values (genesis hash, vault authority, vault state,
treasury, Pyth price account, which must be the profile's push-oracle
account). To run against a different deployment, produce a
file with `dagon-zkapi-deploy identity ...`, bind-mount it read-only into the
indexer, server and challenger (for example at
`/run/dagon-zkapi-identity/identity.json`) and set `ZKAPI_SOLANA_IDENTITY` in
`deployment.env`. Unknown keys and shared parameters are rejected.

## Start Solana services

Build and start the indexer and server:

```sh
docker compose -f docker/aws/compose.yml build
docker compose -f docker/aws/compose.yml up -d indexer server gateway
```

The server refuses to start unless the sponsored Pyth account holds a fully
verified finalized price younger than the profile's 90 s maximum age. Pyth's
sponsor refreshes it at least once a minute, so this holds unless the sponsor
has stalled; the `unless-stopped` restart policy then retries startup until
the feed recovers.

After the server is healthy, enable the challenger profile:

```sh
docker compose -f docker/aws/compose.yml --profile challenge up -d challenger
```

The image entrypoint is `dagon-zkapi-run`. It rejects an unreadable identity
file, a missing RPC URL or seed, and the public development signing seeds.

Server startup additionally fails closed unless the RPC genesis matches the
identity, the program is executable and permanently immutable with an on-chain
executable hash equal to the profile's `executable_sha256`, the vault PDA,
version, request charge cap, note TTL, challenge period and signing keys match
the profile and seeds, the vault is unpaused, and the identity's finalized Pyth
price account satisfies the profile's receiver/feed/age/confidence policy.

## Operations

- Do not publish server, indexer or challenger ports. Only the gateway
  should be reachable by clients.
- Preserve `/var/lib/zkapi`; it contains the transcript database, finalized
  indexer state and challenge checkpoint.
- Back up populated public deployment metadata together with its exact program,
  vault, setup and SDK artifact hashes.
- Rotate provider credentials independently of signing seeds. Changing signing
  seeds requires a new vault identity and client configuration.
- Monitor `/health`, finalized RPC availability, quote freshness, settlement
  retries and challenger progress. Stop funded operation on any identity drift.
- Alert on the age of the sponsored Pyth price (page above 90 s, when the
  server refuses every new quote and lease): probe `/v2/billing/quote` through
  the gateway as described in `docs/SOLANA_SERVER.md` ("Monitoring and
  alerting"). No paid service is needed.
