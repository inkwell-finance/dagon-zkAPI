#!/bin/sh
# Railway mounts the volume root-owned. Take ownership of it, then run everything as an unprivileged user so a bug in the
# coordinator cannot touch anything outside /data. Initialization is an explicit, one-time opt-in.
set -eu
mkdir -p "${DATA_DIR:-/data}"
chown -R node:node "${DATA_DIR:-/data}"
case "${1:-serve}" in
  init | close | finalize) exec setpriv --reuid=node --regid=node --init-groups node coordinator/cli.mjs "$@" ;;
  serve)
    if [ ! -d "${DATA_DIR:-/data}/rounds/0000" ]; then
      if [ "${INIT_ON_EMPTY:-0}" != "1" ]; then
        echo "Empty ceremony volume: restore backup, or explicitly set INIT_ON_EMPTY=1 for the first initialization." >&2
        exit 1
      fi
      setpriv --reuid=node --regid=node --init-groups node coordinator/cli.mjs init --r1cs-dir /app/r1cs
    fi
    exec setpriv --reuid=node --regid=node --init-groups node coordinator/server.mjs ;;
  *) echo "usage: docker-entrypoint.sh [serve | init --r1cs-dir DIR | close | finalize]" >&2; exit 2 ;;
esac
