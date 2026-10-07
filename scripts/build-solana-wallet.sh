#!/usr/bin/env bash
# Build zkapi-solana-wallet reproducibly inside the pinned toolchain container and print its SHA-256.
#   scripts/build-solana-wallet.sh [--verify] [--out DIR] [--engine podman|docker]
# --verify builds twice with no layer cache and fails unless both binaries are byte-identical.
# The digest printed here is what operators pin with `zkapi-clientd solana init --prover-sha256`.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENGINE="${ENGINE:-}"
OUT="$ROOT/dist"
VERIFY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --verify) VERIFY=1 ;;
    --out) OUT="$2"; shift ;;
    --engine) ENGINE="$2"; shift ;;
    *) echo "usage: $0 [--verify] [--out DIR] [--engine podman|docker]" >&2; exit 2 ;;
  esac
  shift
done
if [ -z "$ENGINE" ]; then
  if command -v podman >/dev/null 2>&1; then ENGINE=podman; elif command -v docker >/dev/null 2>&1; then ENGINE=docker; else
    echo "needs podman or docker" >&2; exit 1
  fi
fi

build() { # build <destination directory> [extra build flags...]
  local dest="$1"; shift
  local image="zkapi-solana-wallet-build:$$-$RANDOM"
  "$ENGINE" build "$@" -f "$ROOT/crates/zkapi-solana-wallet/Containerfile" --target build -t "$image" "$ROOT" >&2
  local container
  container="$("$ENGINE" create "$image")"
  mkdir -p "$dest"
  "$ENGINE" cp "$container:/out/zkapi-solana-wallet" "$dest/zkapi-solana-wallet" >&2
  "$ENGINE" rm "$container" >/dev/null
  "$ENGINE" rmi "$image" >/dev/null 2>&1 || true
  sha256sum "$dest/zkapi-solana-wallet" | cut -d' ' -f1
}

mkdir -p "$OUT"
if [ "$VERIFY" = 1 ]; then first="$(build "$OUT" --no-cache)"; else first="$(build "$OUT")"; fi
if [ "$VERIFY" = 1 ]; then
  scratch="$(mktemp -d)"
  trap 'rm -rf "$scratch"' EXIT
  second="$(build "$scratch" --no-cache)"
  if [ "$first" != "$second" ]; then
    echo "NOT reproducible: $first != $second" >&2
    exit 1
  fi
  echo "reproducible: two clean builds produced identical bytes" >&2
fi
printf '%s  %s\n' "$first" "zkapi-solana-wallet" > "$OUT/zkapi-solana-wallet.sha256"
echo "$first  $OUT/zkapi-solana-wallet"
# The build prints --version inside Linux; the exported binary may be copied onto a Windows host.
