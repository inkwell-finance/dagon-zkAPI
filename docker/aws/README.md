# Dagon zkAPI operator deployment

The operator image runs the Dagon server, finalized tree indexer, Pyth price
pusher and optional escape challenger against the Solana vault, and ships
`dagon-zkapi-deploy`. Every shared protocol parameter (program id and
executable hash, circuit, vault policy, server timing, Pyth programs, feed,
shard, policy and push cadence) is compiled into the binaries from
`solana/profile/shared.json`; operators supply only the network identity file,
a finalized RPC URL and secrets. See `docs/solana-profile.md`.

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
sudo install -m 0600 docker/aws/pyth-pusher.env.example /etc/zkapi/pyth-pusher.env
```

Replace every placeholder. Never commit the populated files.

| File | Contents |
| --- | --- |
| `deployment.env` | Finalized Solana RPC URL, optional identity override and OA-org URL |
| `indexer.env` | Optional dedicated indexer RPC (`SOLANA_RPC_URL`) |
| `server.env` | Distinct signing seeds and exactly one lease-issuer credential |
| `challenge.env` | Challenger keypair path and optional dedicated RPC |
| `challenge-keypair.json` | Dedicated rent/transaction payer; mode `0600` |
| `pyth-pusher.env` | Hermes API key, pusher keypair path, optional RPC/Hermes URL, priority fee and balance alarm |
| `pyth-pusher-keypair.json` | Dedicated, funded Pyth push fee payer; mode `0600` |
| `config.json` | Public browser deployment manifest served by the gateway |

The challenger mounts `/etc/zkapi` read-only; the Pyth pusher mounts **only**
`pyth-pusher-keypair.json`, never the directory containing server signing seeds
or other payers. Bind-mount any public identity separately (below). Each
keypair must be dedicated to its daemon: not the vault treasury, vault
authority, the other daemon's keypair or any user wallet. Create the pusher payer with
`solana-keygen new --no-bip39-passphrase -o /etc/zkapi/pyth-pusher-keypair.json`,
make it readable by uid 10001 only, and fund it (see
`docs/SOLANA_SERVER.md`, "Operator Pyth pusher", for the daily cost).

## Network identity

The image contains `solana/profile/mainnet-beta.identity.json` at
`/srv/zkapi/solana/profile/mainnet-beta.identity.json`, and the launcher uses
it unless `ZKAPI_SOLANA_IDENTITY` names another file. The identity file holds
only the allowed per-network values (genesis hash, vault authority, vault state,
treasury, Pyth price account, which must be the profile's push-oracle
account). To run against a different deployment, produce a
file with `dagon-zkapi-deploy identity ...`, bind-mount it read-only into the
indexer, server, challenger and Pyth pusher (for example at
`/run/dagon-zkapi-identity/identity.json`) and set `ZKAPI_SOLANA_IDENTITY` in
`deployment.env`. Unknown keys and shared parameters are rejected.

## Start Solana services

Build and start the Pyth pusher, indexer and server:

```sh
docker compose -f docker/aws/compose.yml build
docker compose -f docker/aws/compose.yml up -d pyth-pusher indexer server gateway
```

The server does not depend on pusher health: it independently requires a fresh,
fully verified finalized price at startup and for each quote. A broken pusher
must not block startup while Pyth's sponsor provides a valid price. Monitor
pusher health separately; sponsor-only service has intermittent fresh windows.

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
- Scrape the pusher's `/metrics` (port 3002, inside the backend network) and
  alert as described in `docs/SOLANA_SERVER.md` ("Operator Pyth pusher"):
  finalized price age, consecutive failures, Hermes authentication failures and
  the payer balance.
