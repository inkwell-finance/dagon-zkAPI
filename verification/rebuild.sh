#!/usr/bin/env bash
# Reproduce the circuit verification end to end (see verification/README.md).
#
#   verification/rebuild.sh
#
# Steps: self-test -> export r1cs + check ceremony pins -> instrumented mapper (byte-identical, wire map)
# + forged-witness harness -> relabel + slice -> Picus on every slice (Docker image pinned by digest)
# -> composition check -> Lean build + axioms -> r1cs linkage + negative controls -> PASS/FAIL summary.
#
# Environment (all optional):
#   VERIF_WORK       work directory for every generated file (default: verification/work)
#   PICUS_PARALLEL   Picus containers in parallel (default 6)
#   PICUS_MEMORY     memory cap per container (default 3g)
#   PICUS_WALL       wall limit per slice in seconds (default 900)
#   SKIP_PICUS=1     skip the Picus run (the summary then reports FAIL for it)
set -uo pipefail

VERIF=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$VERIF/.." && pwd)
export VERIF_WORK=${VERIF_WORK:-$VERIF/work}
mkdir -p "$VERIF_WORK"
WORK=$(cd "$VERIF_WORK" && pwd)
export VERIF_WORK=$WORK
R1CS=$WORK/r1cs
OUT=$WORK/out
RUNS=$WORK/runs
LOGS=$WORK/logs
PICUS_IMAGE=veridise/picus@sha256:3e78b3b6e3adb064e713553debdf83424bad538a84d95afbafc95e2c9dfe7f5c
PICUS_OPTS="--strong --solver cvc5 --timeout 5000"
PAR=${PICUS_PARALLEL:-6}
MEM=${PICUS_MEMORY:-3g}
WALL=${PICUS_WALL:-900}
LEAN_EXPORT_SHA=7b846f032126fe9097c57e1ed4c702de39206cd7056b0c3fb0d515991bc9a667
MATHLIB_REV=f897ebcf72cd16f89ab4577d0c826cd14afaafc7
export PATH="$HOME/.cargo/bin:$HOME/.elan/bin:$PATH"

rm -rf "$OUT" "$RUNS" "$LOGS"
mkdir -p "$R1CS" "$OUT" "$RUNS" "$LOGS"

NAMES=(); STATUS=()
EXPECTED_STEPS=11
step() {  # NAME COMMAND...: run, log to $LOGS/<n>.log, record PASS/FAIL
  local name=$1; shift
  local n=$(( ${#NAMES[@]} + 1 ))
  local log
  log=$LOGS/$(printf '%02d' "$n")-$(echo "$name" | tr -c 'a-zA-Z0-9\n' '-' | tr -s '-' | tr 'A-Z' 'a-z').log
  printf '\n===== [%02d] %s\n' "$n" "$name"
  local t0=$SECONDS
  # each step runs in a subshell, so `set -e` / `cd` inside a step stay local to it
  ( "$@" ) 2>&1 | tee "$log"
  local rc=${PIPESTATUS[0]}
  local st=PASS; [ $rc -eq 0 ] || st=FAIL
  NAMES+=("$name"); STATUS+=("$st")
  printf -- '----- [%02d] %s: %s (%ds)\n' "$n" "$name" "$st" $((SECONDS - t0))
  return $rc
}

versions() {
  echo "repo: $(git -C "$REPO" rev-parse HEAD 2>/dev/null || echo 'not a git checkout')"
  rustc --version && cargo --version
  python3 --version
  docker --version
  elan --version
  lean --version 2>/dev/null || true
  echo "cpus: $(nproc), memory: $(free -g | awk '/Mem:/{print $2}') GiB"
}

export_r1cs() {
  (cd "$REPO" && cargo run --locked --release --manifest-path protocol/rust/Cargo.toml \
     -p zkapi-proof --example ceremony_export -- "$R1CS") || return 1
  python3 - "$REPO/ceremony/ceremony.json" "$R1CS" <<'EOF'
import hashlib, json, sys
pins = {c['id']: c['r1csSha256'] for c in json.load(open(sys.argv[1]))['circuits']}
ok = True
for cid, pin in pins.items():
    sha = hashlib.sha256(open(f'{sys.argv[2]}/{cid}.r1cs', 'rb').read()).hexdigest()
    print(f'{cid:10} {sha} ceremony.json {"MATCH" if sha == pin else "MISMATCH " + pin}')
    ok &= sha == pin
sys.exit(0 if ok and len(pins) == 3 else 1)
EOF
}

mapper() {
  # picus-mapper re-synthesises the circuits with section/free-witness marks, exports them through
  # zkapi_proof::ceremony::r1cs_bytes and refuses to continue unless the bytes hash to the pins.
  (cd "$VERIF/mapper" && CARGO_TARGET_DIR="$WORK/target" cargo build --release --locked) || return 1
  "$WORK/target/release/picus-mapper" "$OUT"
}

forge() { "$WORK/target/release/forge"; }

slices() {
  set -e
  python3 "$VERIF/tools/prepare.py"
  python3 "$VERIF/tools/isneq.py"
  python3 "$VERIF/tools/chunk.py" transition 400 v5 --ec --assume="$OUT/assume-isneq.json"
  python3 "$VERIF/tools/chunk.py" withdrawal 400 v6 --ec --implied --assume="$OUT/assume-isneq.json"
  python3 "$VERIF/tools/chunk.py" request 400 v6 --ec --implied --assume="$OUT/assume-isneq.json"
}

picus() {
  if ! docker image inspect "$PICUS_IMAGE" >/dev/null 2>&1; then docker pull "$PICUS_IMAGE" || return 1; fi
  docker image inspect "$PICUS_IMAGE" --format 'image {{index .RepoDigests 0}}'
  # Containers run as the image's picususer; logs are written next to each slice.
  chmod -R a+rwX "$OUT/slices" "$RUNS"
  local lists=$RUNS/lists
  mkdir -p "$lists"
  (cd "$WORK" && ls out/slices/transition-v5/*.r1cs out/slices/withdrawal-v6/*.r1cs out/slices/request-v6/*.r1cs) \
    | awk -v p="$PAR" -v d="$lists" '{print > (d "/part-" (NR % p))}'
  local names=()
  for part in "$lists"/part-*; do
    local name=verif-picus-$$-${part##*-}
    docker rm -f "$name" >/dev/null 2>&1
    docker run -d --name "$name" --memory="$MEM" --memory-swap="$MEM" \
      -v "$WORK:/work" -v "$VERIF/tools:/tools:ro" "$PICUS_IMAGE" \
      bash -c "cd /work && bash /tools/run_picus.sh /work/runs/results-slices-${part##*-}.jsonl $WALL '$PICUS_OPTS' \$(cat runs/lists/${part##*/})" >/dev/null || return 1
    names+=("$name")
  done
  local total
  total=$(cat "$lists"/part-* | wc -l)
  while :; do
    local running=0
    for n in "${names[@]}"; do [ "$(docker inspect -f '{{.State.Running}}' "$n")" = true ] && running=$((running + 1)); done
    local done_n
    done_n=$(cat "$RUNS"/results-slices-*.jsonl 2>/dev/null | wc -l)
    echo "picus: $done_n/$total slices done, $running containers running"
    [ $running -eq 0 ] && break
    sleep 30
  done
  for n in "${names[@]}"; do docker rm "$n" >/dev/null; done
  python3 - "$RUNS" "$total" <<'EOF'
import collections, glob, json, sys
rows = [json.loads(l) for f in glob.glob(f'{sys.argv[1]}/results-slices-*.jsonl') for l in open(f)]
by = collections.defaultdict(collections.Counter)
wall = collections.defaultdict(list)
for r in rows:
    c = r['file'].split('/')[-2]
    by[c][r['result']] += 1
    wall[c].append(r['wall_s'])
for c in sorted(by):
    print(f'{c:15} {dict(by[c])}  wall sum {sum(wall[c]):.0f}s max {max(wall[c]):.1f}s')
bad = [r for r in rows if r['result'] != 'SAFE']
for r in bad:
    print('NOT SAFE:', r['result'], r['file'])
print(f'{len(rows)} slices, {len(rows) - len(bad)} SAFE')
sys.exit(0 if rows and not bad and len(rows) == int(sys.argv[2]) else 1)
EOF
}

compose() {
  python3 "$VERIF/tools/compose.py" "$RUNS" || return 1
  python3 - "$RUNS/compose-summary.json" "$VERIF/results/compose-summary.json" <<'EOF'
import json, sys
got, want = json.load(open(sys.argv[1])), json.load(open(sys.argv[2]))
unproven = {c: v.get('UNPROVEN', 0) for c, v in got.items()}
print('unproven wires:', unproven)
print('wire accounting equals results/compose-summary.json:', got == want)
sys.exit(0 if got == want and not any(unproven.values()) else 1)
EOF
}

lean_build() {
  set -e
  cd "$VERIF/lean"
  echo "== toolchain: $(cat lean-toolchain)"; command lean --version
  grep -q "$MATHLIB_REV" lake-manifest.json
  lake exe cache get > /dev/null
  echo "== mathlib $(git -C .lake/packages/mathlib rev-parse HEAD)"
  test "$(git -C .lake/packages/mathlib rev-parse HEAD)" = "$MATHLIB_REV"
  rm -rf .lake/build/lib/lean/PicusLemmas* .lake/build/ir/PicusLemmas*
  echo "== clean build"
  if ! lake build > "$OUT/lake-build.log" 2>&1; then tail -40 "$OUT/lake-build.log"; return 1; fi
  grep -vE "^✔|^⣿" "$OUT/lake-build.log" | tail -3
  echo "== sorry/axiom scan"
  if grep -nE "\bsorry\b|^\s*axiom |native_decide|implemented_by|extern" PicusLemmas/*.lean PicusLemmas.lean; then
    echo "forbidden construct found"; return 1
  fi
  echo none
  echo "== #print axioms"
  lake env lean Axioms.lean | tee "$OUT/axioms.txt"
  local n_ok n_all
  n_all=$(grep -c "depends on axioms" "$OUT/axioms.txt")
  n_ok=$(grep -cx "'Picus\.[A-Za-z_]*' depends on axioms: \[propext, Classical.choice, Quot.sound\]" "$OUT/axioms.txt")
  echo "theorems: $n_all, with only [propext, Classical.choice, Quot.sound]: $n_ok"
  [ "$n_all" -eq 15 ] && [ "$n_ok" -eq 15 ]
  echo "== export"
  lake env lean Export.lean
  mv lean-export.json "$OUT/lean-export.json"
  local sha
  sha=$(sha256sum "$OUT/lean-export.json" | cut -d' ' -f1)
  echo "lean-export.json sha256 $sha (expected $LEAN_EXPORT_SHA)"
  [ "$sha" = "$LEAN_EXPORT_SHA" ]
}

link_check() { python3 "$VERIF/lean/link/link.py"; }
negative_controls() { python3 "$VERIF/lean/link/negative_controls.py"; }

echo "verification rebuild: repo $REPO, work dir $WORK"
step "Tool versions" versions
step "Picus verdict classifier self-test" bash "$VERIF/tools/test_picus_verdict.sh"
step "Export r1cs and check ceremony.json pins" export_r1cs
step "Instrumented mapper (byte-identical to the pins)" mapper
step "Forged-witness harness" forge
step "Relabel and slice" slices
if [ "${SKIP_PICUS:-0}" = 1 ]; then NAMES+=("Picus slices"); STATUS+=("SKIPPED"); echo "Picus skipped"
else step "Picus slices ($PICUS_OPTS)" picus; fi
step "Composition check (every wire accounted for)" compose
step "Lean lemmas: build and axioms" lean_build
step "Linkage of the Lean lemmas to the pinned r1cs" link_check
step "Linkage negative controls" negative_controls

echo
echo "===== SUMMARY"
fail=0
[ ${#NAMES[@]} -eq $EXPECTED_STEPS ] || { echo "ran ${#NAMES[@]} of $EXPECTED_STEPS steps"; fail=1; }
for i in "${!NAMES[@]}"; do
  printf '%-8s %s\n' "${STATUS[$i]}" "${NAMES[$i]}"
  [ "${STATUS[$i]}" = PASS ] || fail=1
done
echo "logs: $LOGS"
if [ $fail -eq 0 ]; then echo "VERIFICATION: PASS"; else echo "VERIFICATION: FAIL"; fi
exit $fail
