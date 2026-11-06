#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

for executable in node npm cargo forge anvil; do
    if ! command -v "$executable" >/dev/null 2>&1; then
        echo "Required executable is missing: $executable" >&2
        exit 1
    fi
done
node -e 'if (Number(process.versions.node.split(".")[0]) < 24) { console.error("Node 24 or newer is required"); process.exit(1); }'
node --test scripts/v2-acceptance.test.mjs

# Respect explicit toolchain settings. Prefer the installed standalone tools on
# macOS; SDK 15.4 also works with hosts whose newer SDK needs a newer linker.
if [[ "$(uname -s)" == Darwin ]]; then
    if [[ -z "${DEVELOPER_DIR:-}" && -d /Library/Developer/CommandLineTools ]]; then
        export DEVELOPER_DIR=/Library/Developer/CommandLineTools
    fi
    if [[ -z "${SDKROOT:-}" && -d /Library/Developer/CommandLineTools/SDKs/MacOSX15.4.sdk ]]; then
        export SDKROOT=/Library/Developer/CommandLineTools/SDKs/MacOSX15.4.sdk
    fi
fi

npm ci --prefix docker/aws/signer --ignore-scripts --no-audit --no-fund
cargo build --locked --release --target-dir target \
    -p zkapi-cli --bin dagon-zkapi \
    -p zkapi-serverd --bin dagon-zkapi-challenged --example v2_acceptance_wallet \
    -p zkapi-indexerd --bin dagon-zkapi-indexerd
# The withheld-successor scenario needs a server that settles requests but
# never signs their successors. That test mode exists only with the
# `adversary` feature and is refused in release builds, so build it in debug.
cargo build --locked --target-dir target/adversary \
    -p zkapi-cli --bin dagon-zkapi --features adversary
(cd protocol/contracts && forge build)
exec node scripts/v2-acceptance.mjs --bin-dir target/release \
    --adversary-bin target/adversary/debug/dagon-zkapi "$@"
