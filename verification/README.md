# Circuit verification: no hidden prover freedom in the pinned zkAPI circuits

This directory reproduces the under-constraint verification of the three Groth16 circuits pinned in
[`ceremony/ceremony.json`](../ceremony/ceremony.json): `request`, `withdrawal` and `transition`.
It is written for auditors and ceremony participants. One command reruns all of it:

```sh
verification/rebuild.sh      # ends with "VERIFICATION: PASS" or "VERIFICATION: FAIL"
```

Nothing here changes the circuits or the ceremony pins. The scripts read the r1cs files that the
repo's own exporter produces and refuse to continue unless their sha256 equals `r1csSha256` in
`ceremony.json`.

## What is proven

For each pinned r1cs, **every wire is uniquely determined by the public inputs and the prover-chosen
free witnesses** (secret, note fields, balance, Merkle siblings, anchors, blinding and
rerandomization scalars, signature `R` and `s`). In other words, the r1cs computes exactly the
arkworks gadget functions, and a prover has no freedom beyond the private inputs the spec gives it,
apart from the four benign cases listed under [Known residuals](#known-residuals-c1c4-all-info).

| circuit | wires | constraints | Picus slices SAFE | lemmas used |
|---|---|---|---|---|
| transition | 31,845 | 31,810 | 140 / 140 | none (pure Picus result) |
| withdrawal | 21,604 | 22,222 | 311 / 311 | L-EC, L-bits, L-neq |
| request | 31,391 | 31,670 | 331 / 331 | L-EC, L-bits, L-neq |

Wire accounting (`tools/compose.py`; 0 wires unproven in every circuit):

| circuit | public | free | Picus-SAFE | L-bits | L-neq |
|---|---|---|---|---|---|
| transition | 11 | 32 | 31,802 | 0 | 0 |
| withdrawal | 17 | 760 | 19,762 | 1,016 | 49 |
| request | 13 | 1,143 | 29,702 | 508 | 25 |

**What is not claimed.** Uniqueness holds *given* the free witnesses. Binding the free witnesses to the
public inputs is cryptographic (Poseidon, EdDSA/Schnorr under the server key, Pedersen binding) and
outside what an under-constraint check can show. Whether the relation matches SPEC/PROTOCOL is also out
of scope here; the earlier circuit audits covered that.

## Method

1. **Export and pin check.** `protocol/rust/crates/zkapi-proof/examples/ceremony_export.rs` writes the
   three r1cs files; their sha256 must equal `ceremony.json`.
2. **Wire map (`mapper/`).** `picus-mapper` is a verbatim copy of the three `generate_constraints`
   bodies from `groth16.rs`, with only `sec()`/`free()` marker calls added (they read counters and
   never touch the constraint system). It exports through the repo's own
   `zkapi_proof::ceremony::r1cs_bytes` and aborts unless the bytes hash to the pins. Because the copy
   is byte-identical, every wire and constraint index maps to an exact source section and the set of
   free witnesses is known exactly (`<id>.marks.json`).
3. **Forged-witness harness (`mapper/src/bin/forge.rs`).** Builds concrete witnesses on the pinned
   constraint system to confirm each residual below and to test the in-field gadget at its boundaries
   (15 checks).
4. **Relabel and slice (`tools/`).** The pinned headers declare every witness a private input, so
   Picus would be vacuous on them as-is (`prepare.py` writes the relabelled whole-circuit copy).
   `chunk.py` cuts each circuit into slices of contiguous witness wires: slice inputs are the public
   wires, free wires, lemma wires and wires proven by earlier slices; slice targets are its own wires.
   Each constraint belongs to the slice of its highest-index wire. `chunk.py` asserts the constraint
   partition is exact and every wire is covered. Normalisation rewrites booleanity constraints to the
   identical `w*(w-1)=0` and *adds* implied copies of bit-sum constraints (the originals are kept).
5. **Picus** (`veridise/picus@sha256:3e78b3b6e3adb064e713553debdf83424bad538a84d95afbafc95e2c9dfe7f5c`,
   cvc5 1.0.8 with finite fields) runs `--strong --solver cvc5 --timeout 5000` on every slice.
6. **Composition (`tools/compose.py`).** Every wire must be public, free, lemma-backed, or a target of a
   SAFE slice. By induction over slice order every wire is then unique. Dropping constraints owned by
   later slices only enlarges a slice's solution set, so a SAFE slice stays sound.
7. **Lean lemmas (`lean/`).** The three facts Picus cannot prove are proved in Lean 4 with Mathlib.
8. **Linkage (`lean/link/link.py`).** Ties each Lean theorem to the exact constraints of the pinned
   r1cs that the slices took a lemma for; `negative_controls.py` shows the linkage rejects perturbed
   constraints.

## The three lemmas

All are kernel-checked: no `sorry`, no extra `axiom`, no `native_decide`, no `implemented_by`. Each
of the 15 theorems depends only on `[propext, Classical.choice, Quot.sound]` (`lean/Axioms.lean`).
`lean/PicusLemmas/Field.lean` also proves that the BN254 scalar modulus `p` is prime (Pratt
certificate) and that the curve's `d = 168696/168700` is a non-square.

- **L-EC: twisted-Edwards completeness** (`Edwards.lean`: `add_gadget`, `dbl_gadget`,
  `add_denoms_ne_zero`, `add_onCurve`, `onCurve_of_gadget`, `onCurve_neg`, `onCurve_select`). For
  on-curve inputs the arkworks 0.5 add and double gadgets (ark-ed-on-bn254, `a = 1`) never divide by
  zero, their outputs are unique and on the curve. The slices encode this by adding `D·inv = 1` and
  the implied `inv·N = t` for each division. `link.py` regenerates every add/double gadget
  (3,804 gadgets, 7,608 denominator constraints) and checks the on-curve premise for all 6,837 input
  points, using rule lemmas proved in Lean.
- **L-bits: canonical 254-bit decomposition** (`InField.lean`: `toBitsLe_canonical`). A Lean generator
  reproduces arkworks' `AllocatedFp::to_bits_le` constraint emission, including
  `enforce_in_field_le`; any satisfying assignment sets the bit wires to the bits of the canonical
  representative `< p`. `link.py` checks that all 6 sites (640 constraints each) equal the generator's
  output exactly.
- **L-neq: the `is_neq` multiplier** (`IsNeq.lean`: `isNeq_ne`, `isNeq_unique`, `isNeq_m_of_ne`,
  `isNeq_m_free`). In `(x−y)·m = ne`, `(x−y)·(1−ne) = 0`, the output `ne` is unique, and `m` is free
  exactly when `x = y`. `link.py` checks that each of the 74 helper wires occurs in exactly this pair
  and nowhere else.

## Trusted parts

- **Python linkage and slicing scripts.** `link.py` (r1cs parser, linear-combination normalisation,
  the mirror of arkworks `FpVar` constant folding, input identification and on-curve provenance
  rules), `chunk.py`, `compose.py` and `r1cs.py` are ordinary code, not proofs. The negative controls
  show the linkage discriminates; the `const`/`boolsel` on-curve checks are Python arithmetic.
- **Slice-decomposition soundness.** The induction over slices is a paper argument (step 6 above)
  backed by `compose.py`'s accounting, not a Lean proof.
- **Picus and cvc5.** A SAFE verdict is trusted to be sound. The verdict is read from the exact log
  line (see `tools/picus_verdict.sh`).
- **Lean export.** `lean-export.json` comes from Lean's evaluator (`#eval`) running the same
  `toBitsLe` definition; the kernel does not check that the output matches it. Its sha256 is pinned
  in `rebuild.sh`.
- **The mapper copy** is trusted only as far as its sha256 equality with the pins, which makes the
  wire-to-source map exact.

## Known residuals (C1–C4, all Info)

Picus and the forged-witness harness found these non-unique wires. None changes a public input or a
semantically meaningful private value (balance, deposit, note id, expiry, secret, nullifier, anchor,
registration, leaf, commitment, root, destination).

| # | wires | meaning | severity |
|---|---|---|---|
| C1 | `is_neq` multiplier `m` (request 25, withdrawal 49) | inverse helper of an equality test, free only when the compared values are equal; occurs in one constraint, `ne` is unique (L-neq) | Info / false positive |
| C2 | genesis `prev_anchor`; state signature `R`, `s` on genesis; clearance signature when `has_clearance = 0` | the anchor chain and signature checks are disabled by design in those cases | Info, intended |
| C3 | signature `R` pre-cofactor point | arkworks allocates `R/8` and constrains `8·ge`; `ge + T` for a small-order `T` gives the same `R` | Info, intended |
| C4 | 251-bit scalars (`s`, blinding, rerandomization) not reduced below the subgroup order ℓ | `k` and `k+ℓ` give the same point; only the point is used | Info, intended |

A whole-circuit (undecomposed) Picus `--strong` run was attempted with 26 GB: transition and request
were OOM-killed and withdrawal returned UNKNOWN (cvc5 per-query timeout). The decomposed result is
the evidence. That UNKNOWN is what exposed a classifier bug: the old `run_picus.sh` matched the
substring "properly constrained", which also occurs in Picus's UNKNOWN line, and labelled it SAFE.
It now matches whole verdict lines only, and `tools/test_picus_verdict.sh` (run by `rebuild.sh`)
checks this, including the old classifier as a regression case. No slice verdict was affected: every
slice log contains the exact SAFE line.

## Reproducing

### Requirements

Linux x86_64 with 8 cores and 30 GB RAM was used (Ubuntu 24.04). Network access is needed for the
Docker image, crates and the Mathlib cache.

| tool | version used |
|---|---|
| Rust (stable, via rustup) | 1.99.1 |
| Python | 3.12 (stdlib only) |
| Docker | 29.x; the Picus image is pulled by digest |
| elan / Lean | elan 4.2.4; `leanprover/lean4:v4.24.0` from `lean/lean-toolchain` |
| Mathlib | `f897ebcf72cd16f89ab4577d0c826cd14afaafc7` (pinned in `lean/lake-manifest.json`; oleans via `lake exe cache get`) |
| coreutils, git, awk | any recent |

Minimal setup on a fresh Ubuntu 24.04 machine:

```sh
sudo apt-get install -y build-essential pkg-config libssl-dev git curl python3 docker.io
sudo usermod -aG docker "$USER"   # then log in again
curl https://sh.rustup.rs -sSf | sh -s -- -y
curl -sSfL https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh | sh -s -- -y --default-toolchain none
```

### Running

```sh
verification/rebuild.sh
```

About 9 minutes on 8 cores with warm caches (Picus 5 minutes, Lean 2 minutes; the recorded clean run is
`results/rebuild-summary.txt`). Generated files go to `verification/work/`
(override with `VERIF_WORK`); per-step logs are in `work/logs/`. Options: `PICUS_PARALLEL` (default
6 containers), `PICUS_MEMORY` (default `3g` each), `PICUS_WALL` (default 900 s per slice).

The steps and their pass conditions:

| step | passes when |
|---|---|
| verdict classifier self-test | every fixture is classified correctly |
| export r1cs | all three sha256 equal `ceremony.json` |
| instrumented mapper | its exported bytes hash to the pins (it aborts otherwise) |
| forged-witness harness | 15/15 checks PASS |
| relabel and slice | `chunk.py`'s partition and coverage assertions hold |
| Picus | all 782 slices SAFE |
| composition | 0 wires unproven; accounting equals `results/compose-summary.json` |
| Lean | clean build; no forbidden constructs; 15 theorems with only the three standard axioms; export sha256 matches |
| linkage | `link.py` prints `ALL LINKED` |
| negative controls | every perturbation rejected |

Ecne (a second, propagation-based checker) was also run on the same slices during the audit and
confirmed 763 of 782; its 19 non-proofs were exactly the inverse and in-field slices, which Picus
proved. It is not part of `rebuild.sh` because it needs Julia 1.7.3 with a 2022 package manifest.

### Layout

| path | contents |
|---|---|
| `rebuild.sh` | the end-to-end run |
| `mapper/` | instrumented exporter (`picus-mapper`) and forged-witness harness (`forge`) |
| `tools/r1cs.py` | r1cs reader/writer and marks; defines the work-directory paths |
| `tools/prepare.py`, `isneq.py`, `chunk.py`, `compose.py` | relabel, `is_neq` detection, slicing, composition |
| `tools/run_picus.sh`, `picus_verdict.sh`, `test_picus_verdict.sh` | Picus driver, verdict classifier, its self-test |
| `tools/cex.py` | maps a Picus counterexample back to pinned wires (debugging aid) |
| `lean/` | Lean project: `PicusLemmas/*.lean`, `Axioms.lean`, `Export.lean`, toolchain and manifest pins |
| `lean/link/` | `link.py`, `negative_controls.py` |
| `results/` | recorded outputs: `compose-summary.json`, `forge.txt`, `link-output.txt`, `rebuild-summary.txt` |
