#!/bin/sh
# Railway mounts the volume root-owned. Take ownership of it, then run everything as an unprivileged user so a bug in the
# coordinator cannot touch anything outside /data. `init` and `finalize` are the one-off operator commands; with no
# arguments the server starts. Railway has no one-off containers, so `serve` on an empty volume first runs `init` with
# the circuits baked into the image at /app/r1cs (init checks each against its sha256 pin in ceremony.json).
set -eu
mkdir -p "${DATA_DIR:-/data}"
chown -R node:node "${DATA_DIR:-/data}"
case "${1:-serve}" in
  init | finalize) exec setpriv --reuid=node --regid=node --init-groups node coordinator/cli.mjs "$@" ;;
  serve)
    if [ ! -d "${DATA_DIR:-/data}/rounds/0000" ] && [ -d /app/r1cs ]; then
      setpriv --reuid=node --regid=node --init-groups node coordinator/cli.mjs init --r1cs-dir /app/r1cs
    fi
    exec setpriv --reuid=node --regid=node --init-groups node coordinator/server.mjs ;;
  *) echo "usage: docker-entrypoint.sh [serve | init --r1cs-dir DIR | finalize]" >&2; exit 2 ;;
esac
