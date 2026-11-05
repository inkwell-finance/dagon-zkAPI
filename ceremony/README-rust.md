# Rust side of the snarkjs ceremony

The ceremony itself runs with snarkjs. Rust only converts at the two ends:

```
arkworks circuits --ceremony_export--> <id>.r1cs --snarkjs ceremony--> <id>_final.zkey --ceremony_import--> arkworks keys
```

Circuit ids: `request`, `withdrawal`, `transition` (Solana Merkle transition).

## Sizes (`circuits.json`)

| id         | constraints | instance vars (incl. const 1) | witness vars | ptau power |
|------------|------------:|------------------------------:|-------------:|-----------:|
| request    | 30 821      | 13                            | 30 530       | 15         |
| withdrawal | 35 969      | 15                            | 35 524       | 16         |
| transition | 31 810      | 11                            | 31 834       | 15         |

`snarkjs zkey new` needs `ptau power >= ceil(log2(constraints + instanceVariables))`
(it appends one `input * 0 = 0` constraint per public wire including the constant
and takes the next power of two; see `zkey_new.js`, `cirPower`). The withdrawal circuit
therefore needs a **power-16** Perpetual Powers of Tau file, which covers all three.
Checked against snarkjs 0.7.6: `zkey new` of `withdrawal` with a power-15 ptau fails
("circuit too big"), `request` with power 15 works. Regenerate with
`cargo run --release -p zkapi-proof --example ceremony_export -- OUT_DIR`
(writes `circuits.json` next to the `.r1cs` files).

## Export (before the ceremony)

```sh
cargo run --release --manifest-path protocol/rust/Cargo.toml -p zkapi-proof \
  --example ceremony_export -- OUT_DIR
```

Writes `OUT_DIR/{request,withdrawal,transition}.r1cs` (snarkjs binary r1cs:
prime = BN254 scalar field, wires `1`, public inputs, private wires, `nPubOut = 0`)
and `OUT_DIR/circuits.json`. The constraint system comes from the same
witness-independent template circuits `compact::setup` uses, after the same
`finalize()` LC inlining, and the output is deterministic (publish its hashes).
Verify with `snarkjs r1cs info`.

## Import (after the ceremony)

```sh
cargo run --release --manifest-path protocol/rust/Cargo.toml -p zkapi-proof \
  --example ceremony_import -- ZKEY_DIR OUT_DIR
```

`ZKEY_DIR` holds `{request,withdrawal,transition}_final.zkey`. Writes
`OUT_DIR/v2/{request,withdrawal}.{pk,vk}`, `manifest.json`, `Bn254Poseidon.sol`,
`Groth16ProofAdapter.sol` and `OUT_DIR/solana-transition-v1/transition.{pk,vk}`,
`manifest.json`, through the same writers as `compact::setup`. It refuses
non-empty output directories and never targets `protocol/setup`.
Checks per circuit: wire/public/domain dimensions against the arkworks circuit,
every point on-curve and every G2 point in the prime-order subgroup,
`e(beta_1,g2) = e(g1,beta_2)`, `e(delta_1,g2) = e(g1,delta_2)`, `gamma_2 = g2`,
and a random-linear-combination pairing check that the `B1` and `B2` queries agree.
It does **not** replace `snarkjs zkey verify` against the r1cs and ptau.

## Key kind

Files written by the import carry the headers `zkapi-v2-note-bound-v1/snarkjs\0`
and `dagon-zkapi-solana-transition-v1/snarkjs\0`; the single-party keys keep their
old headers and keep working. The loaders in `compact.rs` accept both and remember
the kind; `RequestProver`/`WithdrawalProver`/`SolanaTransitionProver` prove with
`CircomReduction` (snarkjs' `H` query over the doubled domain, vendored in
`circom_reduction.rs`, wasm-clean) for the new kind and the default arkworks
reduction for the legacy kind. Verifiers are identical for both (same pairing
equation, same vk bytes layout, same manifest/Solidity/Solana verifier inputs).
`snarkjs_zkey.rs` is the `.zkey` reader (Montgomery-encoded points, Groth16 sections
only; the `Coefs` section is not needed because arkworks re-derives the matrices).

## Tests

```sh
cargo test --release --manifest-path protocol/rust/Cargo.toml -p zkapi-proof
```

includes a real snarkjs zkey fixture (`crates/zkapi-proof/tests/fixtures/product.r1cs`
= exporter output for a 6-constraint circuit, `product_final.zkey` = snarkjs 0.7.6,
two contributions plus a beacon, throwaway ptau) that is read, proved against with
`CircomReduction` and verified, and the exporter output is compared byte for byte
to the committed `.r1cs`.

## Dry run (full-size circuits, throwaway ptau)

```sh
# 1. export
cargo run --release --manifest-path protocol/rust/Cargo.toml -p zkapi-proof \
  --example ceremony_export -- /tmp/cer/r1cs
# 2. local ptau (power 16), NOT for production; use the Hermez Perpetual Powers of Tau file there
npx snarkjs powersoftau new bn128 16 p0.ptau
npx snarkjs powersoftau contribute p0.ptau p1.ptau --name=dry -e="entropy"
npx snarkjs powersoftau prepare phase2 p1.ptau pot16.ptau          # ~15-25 min
# 3. per circuit c in request withdrawal transition
npx snarkjs zkey new r1cs/$c.r1cs pot16.ptau zk/${c}_0000.zkey
npx snarkjs zkey contribute zk/${c}_0000.zkey zk/${c}_0001.zkey --name=alice -e="..."
npx snarkjs zkey contribute zk/${c}_0001.zkey zk/${c}_0002.zkey --name=bob -e="..."
npx snarkjs zkey beacon zk/${c}_0002.zkey zk/${c}_final.zkey <64-hex> 10 -n="Final Beacon"
npx snarkjs zkey verify r1cs/$c.r1cs pot16.ptau zk/${c}_final.zkey
# 4. import into a scratch directory outside the repository
cargo run --release --manifest-path protocol/rust/Cargo.toml -p zkapi-proof \
  --example ceremony_import -- zk /tmp/cer/imported
# 5. prove and verify request, withdrawal and transition with the new key kind
ZKAPI_CEREMONY_IMPORT_DIR=/tmp/cer/imported cargo test --release \
  --manifest-path protocol/rust/Cargo.toml -p zkapi-proof --lib -- --ignored imported_ceremony_keys
```

Solana verifier path (nothing is written into the repository): build a scratch tree
`S/` with `S/protocol/setup/v2` and `S/protocol/setup/solana-transition-v1` copied from the
import output, run `vault_challenge_fixture /tmp/cer/imported/v2 >
S/protocol/contracts/test/fixtures/vault-challenge.json` (real request and withdrawal proofs
from the imported keys), copy `scripts/generate-solana-verifier.mjs` to `S/scripts/` (it
resolves its paths relative to its own location, so it reads and writes only inside `S/`;
create `S/crates/dagon-zkapi-solana/src/` first), run it plus `--check`, copy
`crates/dagon-zkapi-solana/src/lib.rs` there with a standalone `Cargo.toml` (same
dependencies, path dependencies on `protocol/rust/crates/*`) and `cargo test --release`: the
unmodified `dagon-zkapi-solana` tests then verify proofs of the imported keys through
`groth16_solana::Groth16Verifier` against the freshly generated `verifying_keys.rs`.

To compare against snarkjs directly, `snarkjs zkey export verificationkey` output equals the
imported `manifest.json` verifying keys (decimal vs `0x` hex, same coordinate order) and
`snarkjs groth16 verify` accepts the arkworks proofs (public signals = the 32-byte
big-endian inputs of the fixture).
