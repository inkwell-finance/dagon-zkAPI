# Classify a Picus log by its verdict line. Sourced by run_picus.sh and test_picus_verdict.sh.
#
# Picus (picus.rkt, image 3e78b3b6…) prints exactly one of these lines:
#   The circuit is properly constrained
#   The circuit is underconstrained
#   Cannot determine whether the circuit is properly constrained
# Only whole, exact lines count. A substring match is wrong: the UNKNOWN line contains
# "properly constrained", and an earlier classifier recorded it as SAFE.
#
# usage: picus_verdict LOG   -> prints SAFE | UNSAFE | UNKNOWN | NONE
# Two different verdict lines in one log print CONFLICT.
picus_verdict() {
  local log=$1 v=()
  grep -qxF 'The circuit is properly constrained' "$log" && v+=(SAFE)
  grep -qxF 'The circuit is underconstrained' "$log" && v+=(UNSAFE)
  grep -qxF 'Cannot determine whether the circuit is properly constrained' "$log" && v+=(UNKNOWN)
  case ${#v[@]} in
    0) echo NONE ;;
    1) echo "${v[0]}" ;;
    *) echo CONFLICT ;;
  esac
}
