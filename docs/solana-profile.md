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
| `program` | `program_id` `8cYsHTNTvS5DwNqFaJ3LDZo8ed1k53cdgWQVZqEN45BX`, upgradeable loader, `upgrade_authority: null`, `executable_sha256` |
| `asset` | `symbol` `USDC`, `mint` `EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v` (Circle USDC), `decimals` 6, `token_program` `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA` (classic SPL Token), `associated_token_program` `ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL` |
| `vault` | `version` 1, `request_charge_cap` 1000000, `note_ttl_seconds` 2592000, `challenge_period_seconds` 86400, `max_pause_seconds` 604800, `pause_cooldown_seconds` 86400 |
| `server` | `lease_ttl_seconds` 300, `settlement_grace_seconds` 5, `settlement_poll_seconds` 2, `raise_lead_seconds` 3600 |

The vault holds only Circle USDC under the classic SPL Token program;
Token-2022 is rejected everywhere. The profile accepts exactly the `asset`
values above. One USDC base unit is one micro-USDC, which the protocol bills
as one micro-USD, so note amounts, solvency bounds, charges, payouts and caps
are all USDC base units and need no price oracle.

`request_charge_cap` is the smallest lease: the server signs no request whose
proof bound is below it, so every lease is funded with at least 1,000,000 base
units, exactly $1.00 of USDC at 6 decimals. It is pinned in the vault at
initialization; changing it needs a new vault.

The profile crate also derives the token accounts every component uses:
`vault_token_address(program, vault_state)` is the vault's USDC account, PDA
`["vault-token", vault_state]` of the program (created by `initialize`, token
authority = the vault state), and `usdc_associated_token_address(owner)` is
`owner`'s canonical USDC ATA, PDA `[owner, token_program, mint]` of the ATA
program.

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
  "treasury_token_account": "<base58>"
}
```

- `solana/profile/mainnet-beta.identity.json` is the mainnet identity. Its
  vault fields stay `null` until the mainnet vault is deployed; binaries refuse
  to run against an identity with unset fields.
- Local identity files are generated at runtime with the same schema and
  `network: "localnet"`.
- Unknown keys are rejected, so a shared parameter cannot be overridden from an
  identity file. `vault_state` must equal the PDA `["vault", vault_authority]`
  of the compiled-in program id, and `genesis_hash` must equal the RPC's.
- `treasury_token_account` is the classic-Token USDC account (any owner, for
  example the canonical ATA of an operator wallet) that receives treasury
  withdrawals. `initialize` requires it to be an initialized, unfrozen USDC
  account and pins it in the vault; it can be neither the vault nor the
  vault's token account.

Binaries take the identity with `--solana-identity PATH` (server env
`ZKAPI_SOLANA_IDENTITY`) and an RPC URL; see
[the Solana server](SOLANA_SERVER.md) and
[challenge operation](challenge-service.md).

## Allowed differences

The effective profile of a deployment may differ from the mainnet reference
only in:

- `network`, `rpc_url`
- `genesis_hash` (and the derived `chain_id` and `deployment_binding`)
- `vault_authority`, `vault_state`, `treasury_token_account`
- `state_signing_key`, `clearance_signing_key`

Anything else, including the program id (embedded in the byte-identical binary;
the local validator loads the program at the declared id), is a parity
violation.

The deploy tool validates each effective-profile document before comparing it:
all observation sections are required, identity values cannot hide nested
parameters, and both the shared profile and observed program/vault must match
the compiled profile. Two empty documents or two deployments with the same
non-profile challenge period cannot pass parity.

Besides the program and the vault parameters, `observe` and `expected` report
the USDC facts both networks must share:

- the vault's pinned `mint`; its token account is the canonical
  `["vault-token", vault_state]` PDA, a classic-Token USDC account whose token
  authority is the vault, initialized (not frozen), not native, with no
  delegate or close authority; the pinned treasury token account is an
  initialized classic-Token USDC account (its owner and every balance are
  per-deployment and not compared);
- the USDC mint account: owner (classic Token), decimals, `is_initialized`,
  `mint_authority` and `freeze_authority`. Supply legitimately differs (the
  local mint is a clone) and is not reported;
- the loader, executable hash (and, for an upgradeable program, the upgrade
  authority) of the classic Token program and of the ATA program, read from
  each chain, so the local validator must run mainnet's exact executables.

The undeployed mainnet reference reports the vault token facts as the
profile requires them; the mint and both token programs are always read live
from mainnet. A deployed mainnet reference
is subject to these same pins; equality with mainnet alone is insufficient.

## Deploy tool

`dagon-zkapi-deploy` (crate `crates/dagon-zkapi-deploy`) uses the same
compiled-in profile for mainnet and local deployments:

```sh
# Write an identity file (reads genesis from the RPC, derives the vault PDA).
dagon-zkapi-deploy identity --network NAME --solana-rpc-url URL \
  --vault-authority PUBKEY --treasury-token-account PUBKEY --out PATH

# Initialize the vault with every vault argument from the profile. Signing
# seeds come from ZKAPI_STATE_SEED / ZKAPI_CLEAR_SEED. Refuses unless the
# program is immutable and its executable hash equals the profile. The
# transaction passes the treasury token account, the USDC mint, the vault
# token PDA (created here) and the classic Token program.
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
- the real mainnet USDC mint is cloned (`--clone`, byte-identical to mainnet
  at clone time), and the classic Token and ATA programs are cloned from
  mainnet with the flag their mainnet loader needs, so the local executables
  are mainnet's rather than the validator's bundled copies (parity compares
  their executable hashes);
- two USDC token accounts are preloaded as `--account` fixtures: a faucet
  (the canonical ATA of a stack keypair holding 1,000,000 USDC) and one
  frozen account (state 2, the canonical ATA of another stack keypair) for
  adversarial tests. Their balances and states are fabricated local state:
  only the mint they name is mainnet's, and the cloned mint's supply does not
  include the faucet balance;
- the test-only PDA signer (`solana/test-programs/pda-signer`, a CPI relay
  that signs with its `["forwarder"]` PDA, standing in for a CCTP forwarder)
  is loaded at the fixed id `FrGKWj9gdt9d7VcjWN6zucZxYgYqyRDeGXdCWeQybr3u` with
  `--bpf-program`. It is never part of a deployment or the verifiable build.
  The stack builds it with `scripts/localnet/build-test-programs.sh` when
  `target/deploy-test/dagon_zkapi_test_pda_signer.so` is missing (needs
  `cargo build-sbf`);
- a treasury owner keypair is generated and its canonical USDC ATA is created
  through the cloned ATA program (`CreateIdempotent`);
- a localnet identity is written, the vault is initialized with
  `dagon-zkapi-deploy init-vault`, and the stack is diffed against the mainnet
  reference before any test runs.

```sh
ZKAPI_STATE_SEED=... ZKAPI_CLEAR_SEED=... \
  node scripts/localnet/stack.mjs --run-dir PATH [--bin-dir PATH] [--rpc-port PORT] \
  [--clock-offset-seconds N | --clock-before-utc-midnight N]
```

`--bin-dir` (default `target/release`) must hold `dagon-zkapi-deploy`.

The clock options are test-only, like the token-account fixtures. With a
nonzero offset the stack compiles `scripts/localnet/clock-offset.c` with
`gcc -shared -fPIC -O2 -o RUN_DIR/clock-offset.so` and launches the validator
with `LD_PRELOAD` of that shim and `DAGON_CLOCK_OFFSET_SECONDS`. The shim adds
the offset to the validator's `CLOCK_REALTIME` (monotonic clocks are
untouched), so its vote timestamps and the Clock sysvar run that many seconds
ahead of wall time, consistently from genesis. `--warp-slot` does not move the
clock and libfaketime crashes Agave, hence the shim. `--clock-before-utc-midnight N`
sets the offset so that, when the CLI starts, the chain clock reads `N`
seconds before a UTC midnight (the next one, or the one after if the next is
closer than `N`); the chain clock then advances in real time, so choose `N`
larger than the stack's startup time. The expired-claim lifecycle test uses it
to cross a note's UTC-day expiry bucket within minutes. The default offset 0
loads no shim. Parity is unaffected: it compares no timestamps, and the
offset never reaches a deployment.

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

`MAINNET_RPC_URL` optionally selects the mainnet RPC used for cloning and the
reference (a public endpoint by default; a live RPC is required). The CLI
prints `{ rpcUrl, identityPath, identity, authorityKeypairPath,
payerKeypairPath, treasuryTokenAccount, usdcFaucetKeypairPath,
usdcFaucetTokenAccount, frozenUsdcOwnerKeypairPath, frozenUsdcTokenAccount,
pdaSignerProgramId, clockOffsetSeconds }` as JSON once ready. The JS API for
end-to-end tests is `startLocalStack({ root, runDir, binDir, log, rpcPort,
clockOffsetSeconds })` (with `clockOffsetBeforeUtcMidnight(N)` exported to
compute an offset) from
`scripts/localnet/stack.mjs`, returning the same fields plus `stop()` after
`init-vault` and a passing parity check. The authority, payer, faucet and
frozen-account owners each hold 50 SOL for fees and rent.

The vault lifecycle test runs against a stack:

```sh
DAGON_SOLANA_RPC_URL=<rpcUrl> \
  DAGON_USDC_FAUCET_KEYPAIR=<usdcFaucetKeypairPath> \
  DAGON_USDC_FROZEN_ACCOUNT=<frozenUsdcTokenAccount> \
  DAGON_USDC_FROZEN_OWNER_KEYPAIR=<frozenUsdcOwnerKeypairPath> \
  DAGON_TEST_PDA_SIGNER_PROGRAM=<pdaSignerProgramId> \
  cargo test --release -p dagon-zkapi-solana-ledger --test localnet -- --ignored
```

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
`solana/profile/localnet-test-overrides.json`, with a stated reason. It sets
only:

- `challenge_period_seconds` (40), so the main local-validator lifecycle test
  can exercise challenge deadlines in real time;
- `note_ttl_seconds` (1), read only by the ignored expired-claim lifecycle
  test on a stack started with a clock offset
  (`--clock-before-utc-midnight`), so a note's UTC-day expiry bucket passes
  within minutes.

Only those ignored tests read it; no binary does. The server's startup gate
rejects a vault whose challenge period or note TTL differs from the profile
(and the shortened timing), so a vault initialized with an override can never
be served.
