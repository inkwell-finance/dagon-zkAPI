import { base58Encode } from '../../services/zkapiSolanaTransport.mjs';

const account = byte => base58Encode(new Uint8Array(32).fill(byte));

export const nativeFunding = (changes = {}) => ({
    ledger_backend: 'dagon.solana.groth16.v1',
    billing_asset: 'native_sol',
    billing_unit: 'lamports',
    base_units_per_asset: '1000000000',
    chain_id: '265940889672238678',
    contract_address: `0x${'11'.repeat(32)}`,
    network: 'localnet',
    program_id: account(1),
    vault_state: account(2),
    genesis_hash: account(7),
    wallet_standard_chain: 'solana:localnet',
    pyth_receiver_program: account(3),
    pyth_price_account: account(4),
    pyth_feed_id: `0x${'ef'.repeat(32)}`,
    pyth_max_age_seconds: 30,
    pyth_max_confidence_bps: 100,
    rpc_url: 'https://rpc.example',
    protocol_server_url: 'https://protocol.example',
    ...changes
});

// A quote exactly as the server's `BillingQuote` serializes it (same fields,
// order and JSON types). $1,000/SOL with no confidence haircut keeps
// ledger-size fixtures exact: $1 = 1,000,000 lamports.
export const nativeQuote = (funding = nativeFunding()) => {
    const published = Math.floor(Date.now() / 1000) - 5;
    return {
        asset: 'native_sol', source: 'pyth_solana_receiver', credit_unit: 'lamports',
        base_units_per_asset: Number(funding.base_units_per_asset), chain_id: funding.chain_id,
        deployment_binding: funding.contract_address, backend: funding.ledger_backend,
        network: funding.network, vault: funding.vault_state, feed_id: funding.pyth_feed_id,
        feed_account: funding.pyth_price_account, receiver_program: funding.pyth_receiver_program,
        price: '100000000000', exponent: -8, confidence: '0',
        publish_time: published, expires_at: published + funding.pyth_max_age_seconds, posted_slot: 42
    };
};
