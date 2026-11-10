#!/usr/bin/env bash
# Self-test for picus_verdict.sh. Exit 0 iff every case classifies as expected.
# The UNKNOWN case is the regression: the old substring classifier labelled it SAFE.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
. "$here/picus_verdict.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0

expect() {  # NAME EXPECTED LOG-CONTENT
  printf '%b' "$3" > "$tmp/log"
  local got
  got=$(picus_verdict "$tmp/log")
  if [ "$got" = "$2" ]; then echo "ok   $1 -> $got"; else echo "FAIL $1 -> $got (expected $2)"; fail=1; fi
}

expect safe      SAFE     '# parsing...\nThe circuit is properly constrained\n'
expect unsafe    UNSAFE   'The circuit is underconstrained\nCounter-example:\n  inputs:\n'
expect unknown   UNKNOWN  'Cannot determine whether the circuit is properly constrained\n'
expect empty     NONE     ''
expect oom       NONE     'Killed\n'
expect prefixed  NONE     'note: The circuit is properly constrained\n'
expect suffixed  NONE     'The circuit is properly constrained?\n'
expect conflict  CONFLICT 'The circuit is properly constrained\nThe circuit is underconstrained\n'

# The classifier that run_picus.sh used before the fix, kept here to show the test catches it.
old_verdict() { if grep -q "properly constrained" "$1"; then echo SAFE; elif grep -q "underconstrained" "$1"; then echo UNSAFE; else echo NONE; fi; }
printf 'Cannot determine whether the circuit is properly constrained\n' > "$tmp/log"
if [ "$(old_verdict "$tmp/log")" = SAFE ] && [ "$(picus_verdict "$tmp/log")" = UNKNOWN ]; then
  echo "ok   regression: old classifier says SAFE on the UNKNOWN line, the fixed one says UNKNOWN"
else
  echo "FAIL regression check"; fail=1
fi

[ $fail -eq 0 ] && echo "picus_verdict self-test: PASS" || echo "picus_verdict self-test: FAIL"
exit $fail
