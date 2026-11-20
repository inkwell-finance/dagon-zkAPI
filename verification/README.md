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

For each pinned r1cs, **every non-residual wire is uniquely determined by the public inputs and the
declared prover-chosen free witnesses** (secret, request context, note fields, balance, Merkle
siblings, anchors, canonical blinding/rerandomization/signature scalars, signature `R` cofactor
preimages and signing-key cofactor preimages `Q`). The exception is the isolated equality-test
multiplier described in C1. Free means *chosen as an input to this uniqueness analysis*, not
unconstrained: these values must still satisfy every original circuit constraint.

Thus this check establishes absence of additional internal witness freedom, not equivalence of the
accepted relation to the protocol specification or uniqueness of the free witnesses themselves.
See [Known residuals](#known-residuals) for the intentional conditional freedoms and cofactor aliases.

| circuit | wires | constraints | Picus slices SAFE | lemmas used |
|---|---|---|---|---|
| transition | 31,845 | 31,810 | 140 / 140 | none (pure Picus result) |
| withdrawal | 22,408 | 23,537 | 316 / 316 | L-EC, L-bits, L-neq |
| request | 32,168 | 32,862 | 334 / 334 | L-EC, L-bits, L-neq |

Circuit pins (`r1csSha256` in `ceremony/ceremony.json`, circuit ID `zkapi-v2-hardening-v1`):

| circuit | r1cs sha256 |
|---|---|
| request | `595545d3ef56eb2bbbbefdb8943aa85ba45d2c79340f94bf75de6ea05452945d` |
| withdrawal | `ad31498f2330687325faec694b11a221194c7790909a092a59964e6382163c4d` |
| transition | `a9cd49c195bd2d6e80664672f0994542baa12aa661e8e93bd9563f3bed8ad1c1` |

Wire accounting (`tools/compose.py`; 0 wires unproven in every circuit):

| circuit | public | free | Picus-SAFE | L-bits | L-neq |
|---|---|---|---|---|---|
| transition | 11 | 32 | 31,802 | 0 | 0 |
| withdrawal | 17 | 764 | 20,507 | 1,016 | 104 |
| request | 13 | 1,145 | 30,424 | 508 | 78 |

**What is not claimed.** Uniqueness holds *given* the free witnesses. Binding the free witnesses to the
public inputs is cryptographic (Poseidon, EdDSA/Schnorr under the server key, Pedersen binding) and
outside what an under-constraint check can show. Whether the relation matches SPEC/PROTOCOL is also out
of scope here; the earlier circuit audits covered that.

## Method

1. **Export and pin check.** `protocol/rust/crates/zkapi-proof/examples/ceremony_export.rs` writes the
   three r1cs files; their sha256 must equal `ceremony.json`.
2. **Wire map (`mapper/`).** `picus-mapper` contains verbatim copies of the three
   `generate_constraints` bodies and their constraint-emitting helper gadgets from hardened
   `groth16.rs`, with only `sec()`/`free()` marker calls added (they read counters and never touch the
   constraint system). `tools/check_mapper.py` compares the bodies after removing these markers.
   It exports through the repo's own `zkapi_proof::ceremony::r1cs_bytes` and aborts unless the bytes
   hash to the pins. Every wire and constraint index therefore maps to the exact source section.
   The first two coordinates of each signing-key `Q` and signature-`R` preimage allocation are
   free; their curve-equation helpers and cofactor doublings are not. Each scalar's first 251
   Boolean wires are free; the new `r−1` comparator's derived wires are not.
3. **Forged-witness harness (`mapper/src/bin/forge.rs`).** Builds concrete witnesses on the pinned
   constraint system to confirm each residual below and to test the in-field gadget at its boundaries
   (18 checks).
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
   SAFE slice. By induction over slice order every non-C1 wire is then unique. C1 multipliers
   are isolated by L-neq, not asserted unique at equality. Dropping constraints owned by later
   slices only enlarges a slice's solution set, so a SAFE slice stays sound.
7. **Lean lemmas (`lean/`).** The three facts Picus cannot prove are proved in Lean 4 with Mathlib.
8. **Linkage (`lean/link/link.py`).** Ties each Lean theorem to the exact constraints of the pinned
   r1cs that the slices took a lemma for; `negative_controls.py` shows the linkage rejects perturbed
   constraints, including extra multiplier occurrences in both hardened L-neq families (signing-key
   nonidentity and scalar bounds), and a corrupted signing-key `Q` on-curve premise.

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
  (3,816 gadgets, 7,632 denominator constraints) and checks the on-curve premise for all 6,852 input
  points, using rule lemmas proved in Lean.
- **L-bits: canonical 254-bit decomposition** (`InField.lean`: `toBitsLe_canonical`). A Lean generator
  reproduces arkworks' `AllocatedFp::to_bits_le` constraint emission, including
  `enforce_in_field_le`; any satisfying assignment sets the bit wires to the bits of the canonical
  representative `< p`. `link.py` checks that all 6 sites (640 constraints each) equal the generator's
  output exactly.
- **L-neq: the `is_neq` multiplier** (`IsNeq.lean`: `isNeq_ne`, `isNeq_unique`, `isNeq_m_of_ne`,
  `isNeq_m_free`). In `(x−y)·m = ne`, `(x−y)·(1−ne) = 0`, the output `ne` is unique, and `m` is free
  exactly when `x = y`. `link.py` checks that each of the 182 helper wires occurs in exactly this pair
  and nowhere else (the multiplier itself occurs only in the first constraint).

### Hardened constraint families

No new Lean theorem or axiom was needed. The existing composition covers all 790 slices:

| added family | uniqueness evidence |
|---|---|
| signing-key `Q` allocation and cofactor clearing | two declared free coordinates per key; L-EC links the on-curve allocation and all add/double operations |
| signing-key nonidentity | Picus proves the test result; L-neq isolates two equality-test multipliers per key |
| scalar `r−1` bound | the 251 input bits remain free; Picus proves derived comparator wires, with 17 isolated L-neq multipliers per allocation |
| deployment version, u64 chain ID and nonzero binding | Picus, including the unique chain-ID decomposition and nonzero inverses |
| destination 160-bit limit | existing L-bits decomposition plus the added high-bit equalities; Picus handles remaining helpers |

L-neq now covers request 78 / withdrawal 104 wires, versus 25 / 49 previously:
the six scalar bounds add 102 helpers and the three signing keys add six. L-EC adds 12 gadgets.
There were no non-SAFE slices in the hardened run after extending these existing classifications.
The initial rebuild failed only the old wire-accounting snapshot and a negative-control assumption:
perturbing `identity + Q` can match an add with a shifted input, but the full linkage rejects that
input's on-curve premise. The controls retain the original variable-add perturbation and also
check this shifted-input rejection; no solver verdict or circuit constraint was weakened.


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

## Known residuals

The following are evaluated against the hardened circuit ID `zkapi-v2-hardening-v1`
(transition remains unchanged). None of the remaining residuals changes a public input or a
semantically meaningful private value such as balance, secret, nullifier, commitment or destination.

| # | wires / scope | hardened status | severity |
|---|---|---|---|
| C1 | isolated `is_neq` multiplier `m`, including the signing-key nonidentity test and scalar-bound helpers | Still free when the compared values coincide; occurs in one constraint only. L-neq proves the Boolean result unique and the multiplier unique when the values differ. | Info / benign internal freedom |
| C2 | genesis `prev_anchor` and state signature; clearance signature when `has_clearance = 0` | Still intentionally disabled checks. Scalars are now canonical even when the signature equation is disabled; signing keys are always subgroup-checked and nonidentity. | Info / intended |
| C3 | signature `R` cofactor preimage and **new signing-key `Q` cofactor preimage** | Still possible to replace a preimage by its sum with an 8-torsion point. `8·(Q+T) = 8·Q` leaves the public key unchanged. The full-request harness demonstrates the new `Q` alias; this is representation freedom, not a signing-key bypass. | Info / intended |
| C4 | formerly unbounded 251-bit scalar representations | **Resolved.** All six scalar-allocation sites enforce `bits ≤ r−1`, including disabled signatures. The identical mapper allocator accepts 0 and r−1 and rejects r. | Historical representation malleability; no remaining residual |

No separate subgroup-membership theorem is claimed: the formal composition establishes uniqueness
of the cofactor-clearing computation given `Q`, using L-EC. The cryptographic interpretation of that
computation and signing-key validation remain part of the circuit specification review.

In the earlier, pre-hardening audit, a whole-circuit (undecomposed) Picus `--strong` run with
26 GB OOM-killed transition and request; withdrawal returned UNKNOWN (cvc5 per-query timeout).
The hardened evidence here is the decomposed rerun, not a whole-circuit solver result.
That earlier UNKNOWN exposed a classifier bug: the old `run_picus.sh` matched the
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

The hardened runs use `ssh dagon-build`, a clean `git archive` export and `dagon-busy <name> -- …`, with
`PICUS_PARALLEL=4` on its 8 vCPUs. `results/rebuild-summary.txt`, `forge.txt` and `link-output.txt` come from
one unmodified full run of `rebuild.sh` on commit `0e1117a` (2026-11-19): all 11 steps PASS, including the
Picus run (step 07: 790/790 SAFE; wall sums 415 s, 233 s and 364 s) and all 8 linkage negative controls
rejected, ending in `VERIFICATION: PASS`. `compose-summary.json` from that run is identical apart from key order.

Generated files go to `verification/work/`
(override with `VERIF_WORK`); per-step logs are in `work/logs/`. Options: `PICUS_PARALLEL` (default
6 containers), `PICUS_MEMORY` (default `3g` each), `PICUS_WALL` (default 900 s per slice).

The steps and their pass conditions:

| step | passes when |
|---|---|
| verdict classifier self-test | every fixture is classified correctly |
| export r1cs | all three sha256 equal `ceremony.json` |
| instrumented mapper | source bodies are verbatim and exported bytes hash to the pins |
| forged-witness harness | 18/18 checks PASS |
| relabel and slice | `chunk.py`'s partition and coverage assertions hold |
| Picus | all 790 slices SAFE |
| composition | 0 wires unproven; accounting equals `results/compose-summary.json` |
| Lean | clean build; no forbidden constructs; 15 theorems with only the three standard axioms; export sha256 matches |
| linkage | `link.py` prints `ALL LINKED` |
| negative controls | every perturbation rejected |

Ecne (a second, propagation-based checker) confirmed 763 of 782 slices in the **pre-hardening**
audit; its 19 non-proofs were inverse and in-field slices that Picus proved. It has not been rerun
on the hardened slices and is not evidence for them. It is not part of `rebuild.sh` because it
needs Julia 1.7.3 with a 2022 package manifest.

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
