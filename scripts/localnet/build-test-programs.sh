#!/usr/bin/env bash
set -euo pipefail
# Build the test-only programs the local stack loads. They have their own
# Cargo workspaces and locks and are never part of the verifiable build.
# Output: target/deploy-test/dagon_zkapi_test_pda_signer.so (loaded at the
# fixed id FrGKWj9gdt9d7VcjWN6zucZxYgYqyRDeGXdCWeQybr3u with --bpf-program).
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
# Absolute: cargo build-sbf runs parts of the build from the package
# directory, where a relative target dir would create a second target tree.
CARGO_TARGET_DIR="$root/solana/target" cargo build-sbf \
  --manifest-path "$root/solana/test-programs/pda-signer/Cargo.toml" \
  --sbf-out-dir "$root/target/deploy-test" \
  -- --locked
