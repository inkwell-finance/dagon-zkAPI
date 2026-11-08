# Pi / Daybreak Blue coordination

## Status

Lars requested cooperation between the existing Daybreak Blue Codex session and
this Pi assistant. This is a proposed split, awaiting Daybreak's acknowledgement;
it does not override the implementation plan already in progress.

- Daybreak session: `01a0fd37-6b45-7523-9ce6-bfaa7b8fd99d`
- Pi session: `01a0fd7d-9f64-74af-b29c-986d95945b35`
- Shared repo: `H:/dagon-zkAPI`, branch `feat/dagon-zkapi-solana`
- Pi model reported by its harness: `gpt-6.1-sol`

## Proposed ownership

### Daybreak Blue / Codex: security and protocol lead

Lars explicitly prefers Daybreak to handle security and Pi to handle
implementation. Daybreak owns protocol/security decisions and independent review:
account/PDA constraints, nullifier lifecycle, proof/deployment/recipient binding,
escape/challenge behavior, solvency/rent, staged operation integrity, RPC
finality, and privacy-sensitive indexer behavior. Daybreak reviews Pi's changes
before they are considered ready. Existing in-flight implementation is not
reassigned until Daybreak acknowledges a concrete handoff.

### Pi: implementation lead for explicitly handed-off components

Proposed first work package: wire Solana ledger selection into normal server
startup and introduce SOL billing/quote configuration, retaining Ethereum
compatibility and the unchanged HTTP/proof protocol. Likely paths are server
configuration, startup routes, processor construction, billing adapter, and
focused tests. Daybreak should confirm exact file ownership and the oracle
source/unit policy before Pi edits these shared components; this is a proposal,
not an exclusive claim on files Daybreak is currently editing.

Subsequent implementation packages can cover indexer/challenger integration and
wallet/CLI transport, each with explicit ownership and security review.

Until acknowledgement, Pi may create/edit only this coordination document and
perform read-only reconnaissance. Pi will not alter production code, manifests,
lockfiles, generated artifacts, or Daybreak's `docs/PORTING_STATUS.md` until the
handoff identifies its permitted paths. Daybreak can suggest a different bounded
implementation task if startup/billing is already underway.

This is the user's preferred role split, not a claim of measured model capability
differences. Security review is a release gate, not proof that the port is safe.

## Coordination rules

- Shared uncommitted work must not be reset, stashed, broadly committed, or
  overwritten by the other assistant.
- Avoid workspace-wide formatting, artifact regeneration, and simultaneous
  Cargo/SBF/validator jobs. Coordinate expensive or mutating test commands.
- Review findings must identify code locations, expected semantics, confidence,
  and a reproduction/test proposal; distinguish confirmed failures from risks.
- Daybreak can respond in a separate `docs/CODEX_PI_REPLY.md` to avoid concurrent
  edits to this file. A reply should confirm ownership and any changed APIs or
  test work already delegated.
- Any implementation/test ownership transfer requires an explicit handoff with
  file paths. New worktrees do not automatically contain the uncommitted port.
- No mainnet deployment or funded transaction is authorized by this split.

## Initial checks already performed by Pi

These observations predate acknowledgement and may change as work continues:

- `cargo test -p dagon-zkapi-ledger -p dagon-zkapi-solana --locked`: 6 tests pass,
  including real request and withdrawal proof fixtures on the host verifier.
- `npm run verify:solana-vk`: passes.
- `npm test`: 307/309 pass on Windows/Node 25.8.2. Failures:
  `browser-only.test.mjs` (`localStorage.removeItem is not a function`) and
  `sdk-integration.test.mjs` (integrity mismatch for `wasm/zkapi_browser.js`).
  These have not been reproduced on a clean upstream checkout or a supported
  Node/npm pairing; do not yet label them port regressions.
- Adding `dagon-zkapi-solana-ledger` to the Rust test command blocked compilation
  on missing Windows OpenSSL. No Solana ledger test result was obtained.
- Existing `.so` artifact observed; Pi has not rerun SBF build or validator tests.
- Server root refresh/nullifier checks use `CreditLedger`, but the startup path
  observed still constructs `NativeBillingOracle` and quote logic remains ETH.

## First implementation handoff requested

Confirm the startup/SOL-billing package (or nominate an alternative), including:
owned paths, current in-flight edits, stable ledger interfaces, trusted price
source and unit policy, required tests, and security acceptance criteria. Pi will
then implement that package and publish a concise changed-files/test-results
handoff for Daybreak's review.
