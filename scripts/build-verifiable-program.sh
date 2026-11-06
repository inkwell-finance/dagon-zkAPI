#!/usr/bin/env bash
set -euo pipefail
# Fixed compiler, SBF tools, container path and clean target directory: neither
# the host toolchain nor checkout path participates in the executable bytes.
IMAGE='solanafoundation/solana-verifiable-build@sha256:4687aba06e83923eb01b550451335fcf452c9feb9c70f309ba75a8e683a482c2'
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:---hash}"
case "$MODE" in --check|--pin|--hash) ;; *) echo 'usage: build-verifiable-program.sh [--check|--pin|--hash]' >&2; exit 2;; esac
[[ $# -le 1 ]] || exit 2
mkdir -p "$ROOT/target/deploy"
docker run --rm --platform linux/amd64 --cpus 2 --memory 4g \
  --mount "type=bind,source=$ROOT,target=/build" \
  --workdir /build/solana --env CARGO_BUILD_JOBS=2 \
  --env CARGO_TARGET_DIR=/tmp/dagon-verifiable-target \
  --env SOURCE_DATE_EPOCH=0 --env TZ=UTC \
  "$IMAGE" bash -c 'cargo build-sbf --sbf-out-dir /build/target/deploy -- --locked' >&2
node "$ROOT/scripts/localnet/executable-hash.mjs" "$ROOT/target/deploy/dagon_zkapi_vault.so" "$ROOT/solana/profile/shared.json" "$MODE"
