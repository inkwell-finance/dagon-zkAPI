import { base58Decode, base58Encode } from '../../services/zkapiSolanaTransport.mjs';
import { ASSOCIATED_TOKEN_PROGRAM_ID, TOKEN_PROGRAM_ID, USDC_MINT, vaultTokenAddress }
    from '../../services/zkapiUsdc.mjs';

const account = byte => base58Encode(new Uint8Array(32).fill(byte));

export const usdcFunding = (changes = {}) => ({
    ledger_backend: 'dagon.solana.groth16.v1',
    billing_asset: 'usdc',
    billing_unit: 'micro_usdc',
    base_units_per_asset: '1000000',
    chain_id: '265940889672238678',
    contract_address: `0x${'11'.repeat(32)}`,
    network: 'localnet',
    program_id: account(1),
    vault_state: account(2),
    genesis_hash: account(7),
    wallet_standard_chain: 'solana:localnet',
    usdc_mint: USDC_MINT,
    token_program: TOKEN_PROGRAM_ID,
    associated_token_program: ASSOCIATED_TOKEN_PROGRAM_ID,
    rpc_url: 'https://rpc.example',
    protocol_server_url: 'https://protocol.example',
    ...changes
});

const feltBytes = value => {
    let remaining = BigInt(value);
    const bytes = new Uint8Array(32);
    for (let index = 31; index >= 0; index -= 1) {
        bytes[index] = Number(remaining & 0xffn);
        remaining >>= 8n;
    }
    return bytes;
};

const writeU64 = (bytes, offset, value) => new DataView(bytes.buffer, bytes.byteOffset)
    .setBigUint64(offset, BigInt(value), true);
const writeU32 = (bytes, offset, value) => new DataView(bytes.buffer, bytes.byteOffset)
    .setUint32(offset, value, true);

/** A canonical 448-byte `VaultState` of `funding`'s deployment. */
export function vaultAccountData(funding, {
    paused = false, nextNoteId = 0, signingKeys = ['0x1', '0x2', '0x3', '0x4'],
    mint = funding.usdc_mint, vaultToken = vaultTokenAddress(funding.program_id, funding.vault_state)
} = {}) {
    const bytes = new Uint8Array(448);
    bytes.set([228, 196, 82, 165, 98, 210, 235, 152]);
    bytes[8] = 1;
    bytes[10] = paused ? 1 : 0;
    bytes.set(base58Decode(mint, 32), 75);
    bytes.set(base58Decode(vaultToken, 32), 107);
    bytes.set(base58Decode(funding.genesis_hash, 32), 140);
    writeU64(bytes, 172, funding.chain_id);
    bytes.set(feltBytes(funding.contract_address), 180);
    writeU32(bytes, 244, nextNoteId);
    signingKeys.forEach((key, index) => bytes.set(feltBytes(key), 280 + index * 32));
    return bytes;
}

/** A canonical 110-byte `NoteState`. */
export function noteAccountData(funding, {
    noteId = 7, status = 1, commitment = `0x${'11'.repeat(32)}`, amount = 1_000_000n, expiry = 1_900_000_000n
} = {}) {
    const bytes = new Uint8Array(110);
    bytes.set([148, 41, 201, 122, 175, 58, 113, 83]);
    bytes.set(base58Decode(funding.vault_state, 32), 8);
    writeU32(bytes, 40, noteId);
    bytes.set(feltBytes(commitment), 44);
    writeU64(bytes, 76, amount);
    writeU64(bytes, 84, expiry);
    bytes[92] = status;
    return bytes;
}

/** A canonical 206-byte `PendingWithdrawal`; stage 0 open, 1 payout parked, 2 rent parked. */
export function pendingAccountData(funding, {
    noteId = 7, stateBalance = 800_000n, conceded = 50_000n, destination, rentPayer, stage = 0,
    deadline = 1_900_000_100n
} = {}) {
    const bytes = new Uint8Array(206);
    bytes.set([61, 103, 179, 177, 148, 199, 63, 171]);
    bytes.set(base58Decode(funding.vault_state, 32), 8);
    writeU32(bytes, 40, noteId);
    writeU64(bytes, 108, stateBalance);
    writeU64(bytes, 116, conceded);
    writeU64(bytes, 124, BigInt(stateBalance) - BigInt(conceded));
    bytes.set(base58Decode(destination, 32), 132);
    writeU64(bytes, 164, deadline);
    bytes.set(base58Decode(rentPayer, 32), 173);
    bytes[205] = stage;
    return bytes;
}

/** A 165-byte classic SPL Token account; state 1 initialized, 2 frozen. */
export function tokenAccountData({ mint = USDC_MINT, owner, amount = 0n, state = 1 }) {
    const bytes = new Uint8Array(165);
    bytes.set(base58Decode(mint, 32), 0);
    bytes.set(base58Decode(owner, 32), 32);
    writeU64(bytes, 64, amount);
    bytes[108] = state;
    return bytes;
}

/** A base64 `getAccountInfo`/`getMultipleAccounts` entry. */
export const rpcAccount = (owner, data, executable = false) => ({
    owner, executable, data: [Buffer.from(data).toString('base64'), 'base64']
});
