#!/bin/sh
# Keep private seeds and provider credentials in the process environment.
set -eu

# Match the artifacts installed by docker/Dockerfile; allow an explicit override.
ZKAPI_PROOF_SETUP_DIR=${ZKAPI_PROOF_SETUP_DIR:-/srv/zkapi/protocol/setup/v2}
LEDGER_BACKEND=${LEDGER_BACKEND:-solana}

require() {
    for name in "$@"; do
        if ! value=$(printenv "$name") || [ -z "$value" ]; then
            echo "Missing required environment variable: $name" >&2
            exit 1
        fi
    done
}

require CIRCUIT_ID
if [ "$CIRCUIT_ID" != zkapi-v2-concession-v1 ]; then
    echo "Dagon zkAPI requires the zkapi-v2-concession-v1 circuit and a fresh vault" >&2
    exit 1
fi

case "$LEDGER_BACKEND" in
    solana)
        require SOLANA_PROGRAM_ID SOLANA_VAULT_STATE SOLANA_GENESIS_HASH
        ;;
    evm)
        require CHAIN_ID VAULT_ADDRESS DEPLOY_BLOCK
        ;;
    *)
        echo "LEDGER_BACKEND must be solana or evm" >&2
        exit 1
        ;;
esac

case "${1:-}" in
    server)
        require ZKAPI_STATE_SEED ZKAPI_CLEAR_SEED REQUEST_CHARGE_CAP
        case "$ZKAPI_STATE_SEED:$ZKAPI_CLEAR_SEED" in
            0x1:*|*:0x2)
                echo "Refusing the development signing seeds" >&2
                exit 1
                ;;
        esac
        if [ "$LEDGER_BACKEND" = solana ]; then
            require SOLANA_RPC_URL PYTH_PRICE_ACCOUNT
            set -- dagon-zkapi --protocol-version 2 \
                --request-charge-cap "$REQUEST_CHARGE_CAP" \
                --proof-setup-dir "$ZKAPI_PROOF_SETUP_DIR" \
                serverd --ledger solana --listen 0.0.0.0:3000 \
                --indexer-url http://indexer:3001 \
                --solana-rpc-url "$SOLANA_RPC_URL" \
                --solana-program-id "$SOLANA_PROGRAM_ID" \
                --solana-vault-state "$SOLANA_VAULT_STATE" \
                --solana-genesis-hash "$SOLANA_GENESIS_HASH" \
                --solana-network "${SOLANA_NETWORK:-mainnet-beta}" \
                --pyth-price-account "$PYTH_PRICE_ACCOUNT" \
                --pyth-max-age-seconds "${PYTH_MAX_AGE_SECONDS:-30}" \
                --pyth-max-confidence-bps "${PYTH_MAX_CONFIDENCE_BPS:-100}" \
                --openrouter-lease-ttl-seconds "${LEASE_TTL_SECONDS:-300}" \
                --openrouter-settlement-grace-seconds "${SETTLEMENT_GRACE_SECONDS:-5}" \
                --openrouter-settlement-poll-seconds "${SETTLEMENT_POLL_SECONDS:-2}" \
                --db-path /data/server.db
            if [ -n "${PYTH_RECEIVER_PROGRAM:-}" ]; then
                set -- "$@" --pyth-receiver-program "$PYTH_RECEIVER_PROGRAM"
            fi
            if [ -n "${PYTH_FEED_ID:-}" ]; then
                set -- "$@" --pyth-feed-id "$PYTH_FEED_ID"
            fi
        else
            require ZKAPI_NATIVE_BILLING_RPC_URL ZKAPI_NATIVE_PRICE_FEED_ADDRESS
            set -- dagon-zkapi --protocol-version 2 --chain-id "$CHAIN_ID" \
                --contract-address "$VAULT_ADDRESS" \
                --request-charge-cap "$REQUEST_CHARGE_CAP" \
                --proof-setup-dir "$ZKAPI_PROOF_SETUP_DIR" \
                serverd --ledger evm --listen 0.0.0.0:3000 \
                --indexer-url http://indexer:3001 \
                --native-billing-rpc-url "$ZKAPI_NATIVE_BILLING_RPC_URL" \
                --native-price-feed-address "$ZKAPI_NATIVE_PRICE_FEED_ADDRESS" \
                --native-price-feed-decimals "${ZKAPI_NATIVE_PRICE_FEED_DECIMALS:-8}" \
                --native-price-max-age-seconds "${ZKAPI_NATIVE_PRICE_MAX_AGE_SECONDS:-4500}" \
                --openrouter-lease-ttl-seconds "${LEASE_TTL_SECONDS:-300}" \
                --openrouter-settlement-grace-seconds "${SETTLEMENT_GRACE_SECONDS:-5}" \
                --openrouter-settlement-poll-seconds "${SETTLEMENT_POLL_SECONDS:-2}" \
                --db-path /data/server.db
        fi
        if [ -n "${OA_ORG_URL:-}" ]; then
            set -- "$@" --oa-org-url "$OA_ORG_URL"
        fi
        exec "$@"
        ;;
    indexer)
        require RPC_URL
        if [ "$LEDGER_BACKEND" = solana ]; then
            exec dagon-zkapi-indexerd --listen 0.0.0.0:3001 --ledger solana \
                --rpc-url "$RPC_URL" --program-id "$SOLANA_PROGRAM_ID" \
                --vault-state "$SOLANA_VAULT_STATE"
        fi
        exec dagon-zkapi-indexerd --listen 0.0.0.0:3001 --ledger ethereum \
            --rpc-url "$RPC_URL" --contract-address "$VAULT_ADDRESS" \
            --from-block "$DEPLOY_BLOCK" --cursor-path /data/indexer.cursor
        ;;
    challenger)
        if [ "$LEDGER_BACKEND" = solana ]; then
            require ZKAPI_CHALLENGE_SOLANA_RPC_URL ZKAPI_CHALLENGE_SOLANA_KEYPAIR
            exec dagon-zkapi-challenged --ledger solana \
                --solana-rpc-url "$ZKAPI_CHALLENGE_SOLANA_RPC_URL" \
                --solana-program-id "$SOLANA_PROGRAM_ID" \
                --solana-vault-state "$SOLANA_VAULT_STATE" \
                --solana-genesis-hash "$SOLANA_GENESIS_HASH" \
                --solana-network "${SOLANA_NETWORK:-mainnet-beta}" \
                --solana-keypair "$ZKAPI_CHALLENGE_SOLANA_KEYPAIR" \
                --db-path /data/server.db --checkpoint /data/challenges.json \
                --proof-setup-dir "$ZKAPI_PROOF_SETUP_DIR"
        fi
        require ZKAPI_CHALLENGE_RPC_URL ZKAPI_CHALLENGE_SENDER
        exec dagon-zkapi-challenged --ledger evm \
            --rpc-url "$ZKAPI_CHALLENGE_RPC_URL" \
            --sender "$ZKAPI_CHALLENGE_SENDER" --chain-id "$CHAIN_ID" \
            --contract-address "$VAULT_ADDRESS" --from-block "$DEPLOY_BLOCK" \
            --confirmations "${CHALLENGE_CONFIRMATIONS:-2}" \
            --db-path /data/server.db --checkpoint /data/challenges.json \
            --proof-setup-dir "$ZKAPI_PROOF_SETUP_DIR"
        ;;
    *)
        echo "Usage: dagon-zkapi-run server|indexer|challenger" >&2
        exit 2
        ;;
esac
