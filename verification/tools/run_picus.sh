#!/usr/bin/env bash
# usage (inside the Picus container): run_picus.sh RESULTS.jsonl WALL_LIMIT_S "PICUS OPTS" FILE...
# Appends one JSON line per file: result, exit code, wall seconds, log path.
# result: SAFE | UNSAFE | UNKNOWN | CONFLICT | TIMEOUT | KILLED_OOM | ERROR (see picus_verdict.sh).
set -u
. "$(dirname "$0")/picus_verdict.sh"
results=$1; limit=$2; opts=$3; shift 3
for f in "$@"; do
  log="${f%.r1cs}.$(echo "$opts" | tr -c 'a-z0-9' '_' ).log"
  start=$(date +%s.%N)
  timeout --kill-after=30 "$limit" /Picus/run-picus $opts "$f" > "$log" 2>&1
  code=$?
  end=$(date +%s.%N)
  wall=$(awk -v a="$start" -v b="$end" 'BEGIN{printf "%.1f", b-a}')
  res=$(picus_verdict "$log")
  if [ "$res" = NONE ]; then
    if [ $code -eq 124 ] || awk -v w="$wall" -v l="$limit" 'BEGIN{exit !(w+0 >= l+0)}'; then res=TIMEOUT
    elif [ $code -eq 137 ]; then res=KILLED_OOM
    else res=ERROR; fi
  fi
  printf '{"file":"%s","opts":"%s","result":"%s","exit":%d,"wall_s":%s,"log":"%s"}\n' \
    "$f" "$opts" "$res" "$code" "$wall" "$log" >> "$results"
  echo "$res $wall $f"
done
