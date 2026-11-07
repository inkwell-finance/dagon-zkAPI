#!/bin/sh
# Launch a Dagon zkAPI daemon from the deployment identity file, a finalized
# Solana RPC endpoint and secrets. Every shared protocol parameter (program id,
# circuit, vault policy, server timing, Pyth programs/feed/shard/policy) is
# compiled into the binaries from solana/profile/shared.json; none is
# configurable here. Keep private seeds, keypair paths and provider credentials
# in the process environment.
set -eu

# Match the artifacts installed by docker/Dockerfile; allow an explicit override.
ZKAPI_PROOF_SETUP_DIR=${ZKAPI_PROOF_SETUP_DIR:-/srv/zkapi/protocol/setup/v2}
ZKAPI_SOLANA_IDENTITY=${ZKAPI_SOLANA_IDENTITY:-/srv/zkapi/solana/profile/mainnet-beta.identity.json}

require() {
    for name in "$@"; do
        if ! value=$(printenv "$name") || [ -z "$value" ]; then
            echo "Missing required environment variable: $name" >&2
            exit 1
        fi
    done
}

if [ ! -r "$ZKAPI_SOLANA_IDENTITY" ]; then
    echo "Solana identity file is not readable: $ZKAPI_SOLANA_IDENTITY" >&2
    exit 1
fi

case "${1:-}" in
    server)
        require SOLANA_RPC_URL ZKAPI_STATE_SEED ZKAPI_CLEAR_SEED
        case "$ZKAPI_STATE_SEED:$ZKAPI_CLEAR_SEED" in
            0x1:*|*:0x2)
                echo "Refusing the development signing seeds" >&2
                exit 1
                ;;
        esac
        set -- dagon-zkapi --proof-setup-dir "$ZKAPI_PROOF_SETUP_DIR" \
            serverd --solana-identity "$ZKAPI_SOLANA_IDENTITY" \
            --solana-rpc-url "$SOLANA_RPC_URL" \
            --listen 0.0.0.0:3000 --indexer-url http://indexer:3001 \
            --db-path /data/server.db
        if [ -n "${OA_ORG_URL:-}" ]; then
            set -- "$@" --oa-org-url "$OA_ORG_URL"
        fi
        exec "$@"
        ;;
    indexer)
        require SOLANA_RPC_URL
        exec dagon-zkapi-indexerd --solana-identity "$ZKAPI_SOLANA_IDENTITY" \
            --rpc-url "$SOLANA_RPC_URL" --listen 0.0.0.0:3001
        ;;
    challenger)
        require SOLANA_RPC_URL ZKAPI_CHALLENGE_SOLANA_KEYPAIR
        exec dagon-zkapi-challenged --solana-identity "$ZKAPI_SOLANA_IDENTITY" \
            --solana-rpc-url "$SOLANA_RPC_URL" \
            --solana-keypair "$ZKAPI_CHALLENGE_SOLANA_KEYPAIR" \
            --db-path /data/server.db --checkpoint /data/challenges.json \
            --proof-setup-dir "$ZKAPI_PROOF_SETUP_DIR"
        ;;
    *)
        echo "Usage: dagon-zkapi-run server|indexer|challenger" >&2
        exit 2
        ;;
esac
