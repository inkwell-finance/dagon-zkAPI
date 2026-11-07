# Dagon zkAPI Solana port status

Checkpoint windows: foundation `01a0fd37-6b49-7b83-8223-1689b6770a4c`;
challenger `01a0fde4-a300-7b71-9eae-526e28362ada`.

## Objective

Ship zkAPI on Solana as **Dagon zkAPI** (`dagon-zkAPI`) using Groth16 first.
Encrypt/FHE stays outside the trusted money path. Expose a generic
`CreditLedger` boundary so an experimental FHE implementation can be added
later without changing the host application's request API or the vault's
protocol semantics.

## Repository and baseline

- Working repository: `H:\dagon-zkAPI`
- Branch: `feat/dagon-zkapi-solana`
- Upstream remote: `https://github.com/ethereum/zkapi.git` (named `upstream`)
- The existing `H:\dagon` worktree is intentionally untouched; it has unrelated
  uncommitted Dagon/FHE work and is used only as a brand reference.
- `npm ci` succeeds.
- Protocol Rust workspace baseline: 49 tests pass on Windows.
- The original root Rust baseline had eight Windows challenge-checkpoint
  replacement failures. The shared atomic checkpoint writer now uses native
  replace-existing semantics; the complete server library suite passes 94/94
  on Windows.
- WSL has Rust 1.97.1, Solana CLI 3.1.11 and Anchor 0.32.1.

## Decisions

1. Fork upstream rather than rewrite the browser prover, circuits, server state
   machine, or lease settlement.
2. Replace only the upstream chain boundary: vault program, RPC/indexer,
   challenger transaction writer, wallet transaction builders, and billing
   asset adapter.
3. Keep circuit revision `zkapi-v2-note-bound-v1` and its 12/14 public fields.
4. Bind a Solana deployment by hashing the program ID + vault-state PDA +
   cluster identity into the existing `contract_address` field.
5. Bind a 32-byte Solana withdrawal recipient by hashing it to a 160-bit value
   stored in the existing destination public input. The vault recomputes this
   binding from the actual writable recipient account. This preserves the
   existing circuit/setup while retaining 160-bit collision resistance.
6. The production `CreditLedger` implementation will be the Solana Groth16
   ledger. No Encrypt dependency is permitted in the default feature graph.
7. Solana Merkle updates use the isolated
   `dagon-zkapi-solana-transition-v1` Groth16 circuit. The vault derives its ten
   public inputs from authoritative state; the server supplies only the proof.
   This avoids trusted root signers and keeps the stable request/withdrawal
   statements unchanged.

## Relevant upstream facts

- Request statement: 12 BN254 scalar-field public inputs.
- Withdrawal statement: 16 public inputs (registration, packed note fields,
  final balance, destination binding, withdrawal nullifier, has-clearance,
  next nullifier, conceded amount, `valid_until`; no Merkle path, root or
  withdrawal tag), including a 20-byte destination field inherited from
  upstream. This field is reinterpreted as the Solana destination binding.
- Proof wire encoding is 256 bytes of big-endian BN254 coordinates and matches
  the input expected by `groth16-solana` after negating proof A.
- `groth16-solana` 0.2.0 is available and uses Solana BN254 syscalls.
- The vault maintains the current root and per-note records. Deposits and
  `retire_closed_leaf` (permissionless, `Closed`-only) change the root; the
  Solana ledger derives a 32-sibling path from a whole-tree snapshot and proves
  each insert/remove transition off chain. Exits never touch the root:
  `execute_escape` and `execute_close` take no transition proof, and
  `execute_claim_expired` takes none and honours `claimable_after` and the
  bounded pause. `execute_challenge` is a defeat (request nullifier equals the
  pending successor nullifier; the note stays `ACTIVE`). Nullifier accounts
  carry `status` 0 released, 1 consumed, 2 challenged and are never closed.
  `set_paused` is bounded: `MAX_PAUSE_DURATION` 7 days, `PAUSE_COOLDOWN` 1 day,
  and paused time extends `claimable_after`. Request evidence does not prove
  delivery of a successor state; the concession rule gives the honest user at
  least `B_k - b_k` (G1) regardless.
- Challenge discovery remains finalized. Non-finalized ledger snapshots are
  reconstructed from canonical note PDAs and checked against the vault root,
  rather than waiting for the finalized indexer.
  An RPC preflight rejection (`-32002`) carrying a real simulation error
  discards the stale challenge plan so the next poll rebuilds it immediately;
  `AlreadyProcessed`, `BlockhashNotFound` and transport failures retain the
  original signed transaction for ambiguous-submission recovery.
- Live note scans and finalized pending-escape discovery use sequential
  `getMultipleAccounts` pages of at most 100 canonical PDAs, each retaining the
  1 MiB RPC response cap. They do not allocate from `next_note_id` up front.
  This avoids a fixed whole-scan response ceiling that could hide all escapes
  after enough deposits. Anyone can fund a PDA address with a System transfer;
  such a System-owned, data-less account is not program state, so the scans
  (and nullifier status) treat it as absent instead of failing. Total scan work
  still grows with allocated note IDs (including closed slots), and dense live
  snapshots grow with the tree size; operators must provision scan
  latency/memory for their ledger and challenge window. Pagination bounds
  individual RPC memory, not total ledger size.

## Implemented foundations

- The object-safe asynchronous `CreditLedger` boundary covers state, paths,
  nullifiers, deposits, close/escape/challenge/finalize/expiry operations,
  signed submission, and transaction status. The Solana backend implements the
  full boundary and is the only backend.
- Solana cluster/deployment/destination binding helpers and deterministic test
  vectors are shared by the host and program without changing the v2 proof
  statements.
- Committed Groth16 verifying-key constants are generated from the existing
  setup and real request/withdrawal fixtures pass through the Solana verifier.
- The Anchor vault implements native-SOL settlement, staged transaction
  payloads, request/withdrawal/transition Groth16 verification, nullifiers,
  mutual close, escape/challenge/finalize, expiry claims, and
  abandoned-operation cleanup. Poseidon Merkle hashing is kept out of the SBF
  trusted path because even a leaf hash exceeded the program compute ceiling.
- The Solana ledger builds every vault operation and the finalized snapshot
  indexer reconstructs state only when its root matches the vault.
- Server startup verifies the immutable deployment, finalized
  vault metadata and pinned finalized Pyth source before opening SQLite. SOL
  quote arithmetic and settlement stay behind separate ledger/price boundaries.
- The challenge daemon discovers canonical finalized
  pending PDAs through `CreditLedger`, derives paths from privacy-safe whole-tree
  snapshots, signs prepared staged operations with a restricted keypair, and
  durably recovers deterministic transaction signatures across lost responses
  and restarts.
- Challenges are concession exits. The leaf stays in the tree on exit, so there
  is no restore. The challenger submits a defeat
  (`execute_challenge`, root-independent, request nullifier equal to the pending
  successor nullifier) or a concession raise
  (`raise_escape_concession(note_id, payload, amount)`, capped by the request's
  solvency bound); finalization is permissionless. The challenger creates no
  operation accounts, so there is no rent to orphan or reclaim.
  Live note and pending scans ignore System-owned, data-less accounts at
  program PDAs, since anyone can fund a PDA address.

## Solana-only cutover

Solana is the only ledger: the inherited upstream chain backend, its billing
adapter, signer sidecar and local client have been removed (see the README for
the upstream pointer). Every shared parameter is compiled in from
`solana/profile/shared.json`, and deployments differ only by network identity
(see [the Solana profile](solana-profile.md)).

Release gates are now:

1. Verifiable program build: `bash scripts/build-verifiable-program.sh --check`
   rebuilds the SBF program in the pinned Docker image and requires its
   executable hash to equal `program.executable_sha256` in the profile.
2. Local-validator parity stack: the validator preloads that verifiable program
   at the declared program id as canonical loader-v3 accounts with upgrade
   authority `None` (the state after a final authority revocation), clones the
   mainnet Pyth receiver/oracle accounts, keeps the price account fresh only
   by replaying the real guardian-signed updates of Pyth's sponsored feed as
   they land on mainnet (its ~60 s cadence), initializes the vault with
   `dagon-zkapi-deploy init-vault`, and must pass
   `scripts/check-solana-parity.mjs` against the mainnet reference before the
   full end-to-end lifecycle runs (the vault lifecycle plus the sponsored-feed
   freshness test, which stalls the replay past the 90 s maximum age and
   requires quoting to fail closed). The validator is the pinned, isolated Agave
   4.4.1 release (`scripts/localnet/install-validator.sh`) with mainnet's
   feature set cloned. The parity check requires equal activation for every
   feature ID 4.4.1 knows, lists the reviewed retired (hardwired) mainnet IDs
   explicitly, and fails closed on any unclassified active ID (see
   [runtime feature parity](solana-profile.md#runtime-feature-parity)).

### Cutover gate evidence (2026-11-06)

- Verifiable build: executable hash
  `a61192ae477628c499f35069d39be91f2964f5c39df08d22f65b657f4cb67115`, pinned
  in the profile; two independent Docker build paths produced it.
- Parity stack on the pinned validator: local `getVersion` 4.4.1, mainnet
  4.4.0, both reporting feature set 2681577653. The 252 known active feature IDs
  matched on both sides (0 missing, 0 extra), with the 59 retired IDs listed
  explicitly. `check-solana-parity.mjs` reported
  `Solana parity PASS (only explicit network identity may differ)`.
- Billing against the replayed mainnet price account: the server returned HTTP
  200 for two `/v2/billing/quote` requests 5.5 s apart (publish time
  1793966005, ages 10 s and 15 s). Later replayed updates arrived at ages 6 s
  and 8 s.
- Lifecycle:
  `cargo test --release -p dagon-zkapi-solana-ledger --test localnet -- --ignored --nocapture`
  passed 1/1 in 105.51 s.
- `dagon-zkapi-deploy init-vault` needs an explicit 1.4M compute-unit limit
  (the same as the lifecycle test). The default 200k limit was exhausted in
  one run, and the CLI now sets the higher limit.

## Earlier release-gate evidence (2026-10-02)

- Solana browser/native wallet transport is complete. It preserves derived
  `u64` chain IDs as canonical decimal strings, validates the exact signer,
  program, vault, message and packet size, journals signed bytes before
  broadcast, resumes ordered staged operations, and keeps background escape
  finalization in a separate durable journal.
- Native-SOL/Pyth billing validates the full deployment and conservative
  confidence-adjusted quote with integer arithmetic. Server startup verifies
  the finalized cluster, vault PDA, immutable loader-v3 program and Pyth source
  before opening durable state.
- The ignored local-validator gate passed against a fresh Agave 3.1.11
  validator and freshly built SBF program in 406.86 seconds. It proved two real
  deposits, a signed non-genesis mutual close and exact lamport payout, an
  escape sharing a nullifier with a historical request proof, a successful
  on-chain challenge, a second signed escape with a new
  anchor/nullifier, enforced deadline, final payout, liability cleanup, and a
  matching finalized account-snapshot index after every load-bearing state.
  (That gate predates the concession exit: it exercised the former
  one-step challenge-with-restoration, and defeat / raise / retire need
  their own gate run.)
- `npm test`: 323/323 passed, including native-SOL quote, transport and durable
  runtime-journal coverage.
- `cargo test --locked --manifest-path protocol/rust/Cargo.toml --workspace`:
  all 57 protocol tests passed, including generated transition proof setup and
  mutation of every public input.
- `cargo test --locked --workspace`: all root tests passed; the explicit
  validator test was skipped there by design and passed separately as described
  above.
- `anchor build` under WSL completed a fresh release SBF build and host tests.
- `git diff --check` passed. Manifest, lockfile and executable-source searches
  found no Encrypt/FHE dependency or code path.
- `npm run verify:assets` and `npm run verify:solana-vk` are deterministic
  release gates for the packaged WASM/proving assets and all three generated
  Solana verifying keys.

The repository is an implementation release candidate, not a deployed
production service. A real deployment still requires an explicit decision to
accept or replace both single-party Groth16 setups, operator-managed secrets,
immutable program deployment, finalized program/vault/oracle pins, and normal
infrastructure rollout. Those external deployment choices do not change the
request API, vault protocol, or `CreditLedger` boundary.

## Security hardening completed during server handoff

- `SolanaCreditLedger::finalized_vault()` now exposes normalized finalized root,
  slot, paused state, request cap, and signing-key metadata only after the
  existing cluster, owner, PDA, version, chain-ID, and deployment checks. Its
  focused ledger tests pass.
- `SolanaCreditLedger::assert_immutable_program()` now verifies the finalized
  program and program-data accounts through Anchor's official loader-v3 types,
  requires an executable canonical deployment, and rejects any remaining
  upgrade authority. The decoder remains inside the Solana ledger adapter.
- Vault initialization now rejects a zero genesis identity, a treasury equal to
  the vault PDA, and reuse of the same state/clearance signing key. This prevents
  a self-treasury configuration from permanently failing operator payouts.
- The vault now has an owner-authorized `cancel_operation` instruction, and the
  Solana ledger can prepare it, so stale/incomplete staged-operation rent is
  recoverable without changing the generic `CreditLedger` contract.
- The focused Solana-ledger library suite now passes 8/8 with canonical pending
  escape PDA discovery. The server library passes 94/94, including durable
  accepted-but-response-lost Solana recovery and the formerly failing Windows
  checkpoint tests.

## Challenger package verification

- `cargo test -p zkapi-serverd --tests --locked`: server library **94/94**,
  Solana startup **3/3**, testnet auth **4/4**, challenger binary builds.
- `cargo test -p dagon-zkapi-solana-ledger --lib --locked`: **8/8**.
- `cargo test -p zkapi-cli -p zkapi-indexerd -p dagon-zkapi-ledger --locked`:
  CLI **5/5**, indexer **14/14**, generic ledger **2/2**.
- `git diff --check`: passes. No new dependency family was introduced for the
  challenger; its signer uses the already-resolved Solana 2.x split crates.
- The browser/native Solana transport and exact decimal-string chain-ID journal
  described in the release-gate section are complete and covered by the 323
  passing SDK tests.
