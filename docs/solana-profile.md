# Solana profile, network identity and local parity

Dagon zkAPI has one configuration: the mainnet configuration. Every shared
parameter lives in `solana/profile/shared.json` and is compiled into every
binary (`crates/dagon-zkapi-profile`, `SharedProfile::embedded()`). A deployment
is selected only by a **network identity file**. A local validator therefore
runs exactly the mainnet configuration, except for the values listed under
[allowed differences](#allowed-differences), on a pinned validator whose
feature activation equals mainnet's for every feature that release knows (see
[runtime feature parity](#runtime-feature-parity)).

## Shared profile

`solana/profile/shared.json` (schema `dagon-zkapi.solana-profile.v1`):

| Section | Values |
| --- | --- |
| `protocol` | `protocol_version` 2, `circuit_id` `zkapi-v2-concession-v1`, `transition_circuit_id` `dagon-zkapi-solana-transition-v1` |
| `program` | `program_id` `7NdY5ZVP2He8gSiDHZbkfmNfSgKWV2tkZmZgty2C1d8H`, upgradeable loader, `upgrade_authority: null`, `executable_sha256` |
| `vault` | `version` 1, `request_charge_cap` 11000000, `note_ttl_seconds` 2592000, `challenge_period_seconds` 86400, `max_pause_seconds` 604800, `pause_cooldown_seconds` 86400 |
| `server` | `lease_ttl_seconds` 300, `settlement_grace_seconds` 5, `settlement_poll_seconds` 2, `raise_lead_seconds` 3600 |
| `pyth` | `receiver_program` `rec5EKMGg6MxZYaMdyBfgwp4d5rB9T1VQH5pJv5LtFJ`, `push_oracle_program` `pythWSnswVUd12oZpeFP8e9CVaEqJg25g1Vtc2biRsT`, `wormhole_program` `HDwcJBJXjL9FpJ7UBsYBtaDjsBUhuLCUYoz3zr8SWWaQ`, SOL/USD `feed_id`, `push_shard_id` 0, `max_age_seconds` 30, `max_confidence_bps` 100, `push_interval_seconds` 5 |

`request_charge_cap` is the smallest lease: the server signs no request whose
proof bound is below it, so every lease is funded with at least 11,000,000
lamports (0.011 SOL, about $1 at $90/SOL). The cap is fixed in lamports and
pinned in the vault at initialization, so the smallest lease in USD moves with
the SOL price (about $0.55 at $50/SOL, $2.20 at $200/SOL); changing it needs a
new vault.

`push_shard_id` and `feed_id` determine the one SOL/USD account every
deployment pins: the push-oracle PDA `[push_shard_id (u16 LE), feed_id]`,
`7UVimffxr9ow1uXYxsr4LHAcV58mLzhmwaeKvJ1pjLiE` for shard 0.
`push_interval_seconds` is the cadence of the operator Pyth pusher
(`dagon-zkapi-pyth-pusher`, see [the Solana server](SOLANA_SERVER.md#operator-pyth-pusher));
the profile requires it to be at most a third of `max_age_seconds`.

There are no flags or environment variables for any of these. Changing one is a
source change that produces new binaries.

`executable_sha256` is the `solana-verify` executable hash: sha256 of the
program bytes with trailing zeros trimmed. It is computed the same way for the
verifiable `.so` and for the on-chain program-data bytes after the loader
metadata. The server refuses to start unless the deployed program matches it,
and `init-vault` refuses to initialize against any other program.

## Network identity

An identity file (schema `dagon-zkapi.solana-identity.v1`) holds only the
per-network values:

```json
{
  "schema": "dagon-zkapi.solana-identity.v1",
  "network": "mainnet-beta",
  "genesis_hash": "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d",
  "vault_authority": "<base58>",
  "vault_state": "<base58>",
  "treasury": "<base58>",
  "pyth_price_account": "7UVimffxr9ow1uXYxsr4LHAcV58mLzhmwaeKvJ1pjLiE"
}
```

- `solana/profile/mainnet-beta.identity.json` is the mainnet identity. Its
  vault fields stay `null` until the mainnet vault is deployed; binaries refuse
  to run against an identity with unset fields.
- Local identity files are generated at runtime with the same schema and
  `network: "localnet"`.
- Unknown keys are rejected, so a shared parameter cannot be overridden from an
  identity file. `vault_state` must equal the PDA `["vault", vault_authority]`
  of the compiled-in program id, `pyth_price_account` must equal the profile's
  push-oracle account, and `genesis_hash` must equal the RPC's.

Binaries take the identity with `--solana-identity PATH` (server env
`ZKAPI_SOLANA_IDENTITY`) and an RPC URL; see
[the Solana server](SOLANA_SERVER.md) and
[challenge operation](challenge-service.md).

## Allowed differences

The effective profile of a deployment may differ from the mainnet reference
only in:

- `network`, `rpc_url`
- `genesis_hash` (and the derived `chain_id` and `deployment_binding`)
- `vault_authority`, `vault_state`, `treasury`
- `pyth_price_account` (declared per network, but every binary, the SDK build
  and the parity check require it to be the profile's push-oracle account)
- `state_signing_key`, `clearance_signing_key`

Anything else, including the program id (embedded in the byte-identical binary;
the local validator loads the program at the declared id), is a parity
violation.

The deploy tool validates each effective-profile document before comparing it:
all observation sections are required, identity values cannot hide nested
parameters, and both the shared profile and observed program/vault must match
the compiled profile. Two empty documents or two deployments with the same
non-profile challenge period cannot pass parity. A deployed mainnet reference
is subject to these same pins; equality with mainnet alone is insufficient.

## Deploy tool

`dagon-zkapi-deploy` (crate `crates/dagon-zkapi-deploy`) uses the same
compiled-in profile for mainnet and local deployments:

```sh
# Write an identity file (reads genesis from the RPC, derives the vault PDA).
dagon-zkapi-deploy identity --network NAME --solana-rpc-url URL \
  --vault-authority PUBKEY --treasury PUBKEY --pyth-price-account PUBKEY --out PATH

# Initialize the vault with every vault argument from the profile. Signing
# seeds come from ZKAPI_STATE_SEED / ZKAPI_CLEAR_SEED. Refuses unless the
# program is immutable and its executable hash equals the profile.
dagon-zkapi-deploy init-vault --solana-identity PATH --solana-rpc-url URL \
  --authority-keypair PATH

# Effective profile as observed on chain.
dagon-zkapi-deploy observe --solana-identity PATH --solana-rpc-url URL

# Expected effective profile (mainnet reference).
dagon-zkapi-deploy expected --solana-identity PATH [--mainnet-rpc-url URL]

# Exit nonzero on any parity violation.
dagon-zkapi-deploy diff LOCAL.json REFERENCE.json
```

## Verifiable program build

```sh
bash scripts/build-verifiable-program.sh --check
```

Builds the SBF program reproducibly with `cargo build-sbf -- --locked` at a
fixed `/build` root and a clean target inside the digest-pinned image
`solanafoundation/solana-verifiable-build@sha256:4687aba06e83923eb01b550451335fcf452c9feb9c70f309ba75a8e683a482c2`
(Agave 3.1.11), writes `target/deploy/dagon_zkapi_vault.so`, prints its
executable hash and, with `--check`, fails unless it equals
`program.executable_sha256`. It needs Docker and Node 24 on the host, but no
host SBF toolchain. `--pin` rebuilds and rewrites the pinned hash in one
command (a deliberate profile change); because the profile is compiled in,
rebuild every operator binary afterwards.

## Local parity stack

`scripts/localnet/` runs the full end-to-end gate on a local validator:

- `solana-test-validator` preloads the canonical loader-v3 Program and
  ProgramData accounts for the declared program id (`--account`: slot 0,
  upgrade authority `None`, the exact verifiable bytes, rent-exempt), the same
  state as a deploy followed by `set-upgrade-authority --final`;
- the validator is a pinned, isolated Agave 4.4.1 release with mainnet's
  feature set cloned (`--clone-feature-set`); the parity check requires equal
  activation for every feature 4.4.1 knows;
- the real mainnet Pyth receiver, push-oracle and Wormhole programs and
  accounts (including the identity's SOL/USD price account) are cloned. The
  price account is then written only by the operator pusher binary
  (`dagon-zkapi-pyth-pusher`, built like the other operator binaries): a local
  recorded Hermes (`scripts/localnet/pyth-replay.mjs`) serves the real
  guardian-signed SOL/USD updates carried by mainnet's own push-oracle
  transactions, re-encoded exactly as Hermes serves them and behind the same
  Bearer API-key check, and the pusher posts each through the cloned Wormhole
  guardian set (full verification) and push oracle. Mainnet records new
  updates only about once a minute, so a fresh finalized window is not
  available at every moment locally;
- a localnet identity is written, the vault is initialized with
  `dagon-zkapi-deploy init-vault`, and the stack is diffed against the mainnet
  reference before any test runs.

```sh
ZKAPI_STATE_SEED=... ZKAPI_CLEAR_SEED=... \
  node scripts/localnet/stack.mjs --run-dir PATH [--bin-dir PATH]
```

`--bin-dir` (default `target/release`) must hold `dagon-zkapi-deploy` and
`dagon-zkapi-pyth-pusher`.

Under a Node version-manager shim such as Volta, launch the real Node process with `"$(node -p process.execPath)" scripts/localnet/stack.mjs ...` so signals sent to the background PID reach Node rather than the shim.

The stack needs Node 24, `npm ci`, and the pinned validator, installed once
with:

```sh
bash scripts/localnet/install-validator.sh
```

The installer (x86_64 Linux, including WSL) downloads the official Agave
v4.4.1 `solana-release-x86_64-unknown-linux-gnu.tar.bz2`, verifies its sha256
`5b0f0fc7e4eedace05f6455de00aa1f2f3d1642068f1e8d50760ba49112c3941`, and unpacks
it into `${XDG_DATA_HOME:-~/.local/share}/dagon-zkapi/agave-v4.4.1/`. It does
not run `agave-install`, change the active release or touch `PATH`. The
launcher uses `.../agave-v4.4.1/solana-release/bin/solana-test-validator`
unless `DAGON_SOLANA_TEST_VALIDATOR` names another binary.

`MAINNET_RPC_URL` optionally selects the mainnet RPC used for cloning, recording
updates and the reference (a public endpoint by default; a live RPC is
required). The stack logs the pusher to `RUN_DIR/pyth-pusher.log`. The JS API
for end-to-end tests is
`startLocalStack({ root, runDir, binDir, log })` from
`scripts/localnet/stack.mjs`, returning `{ rpcUrl, identityPath, identity,
authorityKeypairPath, payerKeypairPath, treasury, pusherMetricsUrl,
awaitFreshQuote, stop() }` after `init-vault`, a passing parity check and one
fresh-quote wait.

`awaitFreshQuote({ minRemainingSeconds = 5, timeoutMs = 180000 } = {})` waits
until the finalized price account holds a quote newer than the cloned one
(so one the pusher posted) with at least `minRemainingSeconds` of its maximum
age left, and returns that account's
`publishTime`, age and `postedSlot` (not a server billing quote). It only
waits; it never changes the maximum age, the clock or the quote. Call it before
starting the server and before each quote → prove → lease cycle.

Check a running stack (or any deployment) against the mainnet reference:

```sh
node scripts/check-solana-parity.mjs --solana-identity PATH --solana-rpc-url URL \
  [--bin-dir PATH] [--mainnet-rpc-url URL]
```

### Runtime feature parity

The runtime is pinned to Agave 4.4.1. `crates/dagon-zkapi-deploy/src/agave-4.4.1-features.json`
pins the 290 feature IDs that Agave 4.4.1 knows (its `FEATURE_NAMES`) plus a
reviewed list of 59 retired IDs. Retired features are still active on mainnet
but have been removed from (hardwired into) the 4.4.1 source, so the release no
longer reads them.

`dagon-zkapi-deploy observe` and `expected` report, at the finalized context
slot:

- the activation state of every one of the 290 known IDs (252 are active on
  both mainnet and a correct local stack at the time of writing);
- `retired_in_software`, the full explicit list of the 59 retired IDs;
- mainnet's `getVersion` and the pinned software version.

`diff` (hence `check-solana-parity.mjs`) fails unless the local validator is
4.4.1 and the activation state of every known ID is equal. It also fails closed
on any active mainnet feature ID that is neither known nor listed as retired.
No feature accounts are added or normalized just to make the lists match.
Feature activation is not an allowed difference.

When mainnet activates a feature unknown to the pinned release, the gate fails
until the pinned Agave release and the feature list are updated.

The validator is Agave 4.4.1 because the earlier Agave 3.1.11 validator could
not reach parity: with mainnet's feature set cloned it activated 222 feature
IDs against mainnet's 311, and all 89 missing features were absent from
`agave-feature-set` 3.1.11.

## Test-only override

Exactly one file may deviate from the profile:
`solana/profile/localnet-test-overrides.json`. It sets only
`challenge_period_seconds` (40) with a stated reason, so the local-validator
lifecycle test can exercise challenge deadlines in real time. Only that test
reads it; no binary does. The server's startup gate rejects a vault whose
challenge period differs from the profile (and the shortened timing), so a
vault initialized with the override can never be served.
