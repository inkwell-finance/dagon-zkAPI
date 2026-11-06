#!/usr/bin/env bash
set -euo pipefail
# Official release asset digest published by GitHub's release API:
# https://api.github.com/repos/anza-xyz/agave/releases/tags/v4.4.1
# Deliberately does not run agave-install or modify the global active_release.
version=v4.4.1
sha256=5b0f0fc7e4eedace05f6455de00aa1f2f3d1642068f1e8d50760ba49112c3941
[[ "$(uname -s)-$(uname -m)" == Linux-x86_64 ]] || { echo 'Pinned local validator requires x86_64 Linux (including WSL)' >&2; exit 1; }
destination="${XDG_DATA_HOME:-$HOME/.local/share}/dagon-zkapi/agave-$version"
mkdir -p "$destination"
archive="$destination/solana-release-x86_64-unknown-linux-gnu.tar.bz2"
if [[ ! -f "$archive" ]]; then
  trap 'rm -f "$archive.partial"' EXIT
  curl --fail --location --silent --show-error "https://github.com/anza-xyz/agave/releases/download/$version/solana-release-x86_64-unknown-linux-gnu.tar.bz2" --output "$archive.partial"
  printf '%s  %s\n' "$sha256" "$archive.partial" | sha256sum --check
  mv "$archive.partial" "$archive"
fi
printf '%s  %s\n' "$sha256" "$archive" | sha256sum --check
tar -xjf "$archive" -C "$destination"
"$destination/solana-release/bin/solana-test-validator" --version
printf 'Validator installed: %s/solana-release/bin/solana-test-validator\n' "$destination"
