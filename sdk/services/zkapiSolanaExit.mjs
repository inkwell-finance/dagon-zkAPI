import { PublicKey, Transaction, TransactionInstruction, ComputeBudgetProgram, SystemProgram } from '@solana/web3.js';
import { decodeSolanaNoteState, decodeSolanaPendingWithdrawal, decodeSolanaVaultState,
    solanaRpc, validateSolanaFunding } from './zkapiNativeSol.mjs';
import { sameChainId } from './zkapiLedgerIdentity.mjs';
import { sameFelt } from './zkapiActiveRoot.mjs';

const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const utf8 = value => new TextEncoder().encode(value);
function integer(value, size) {
    if (typeof value === 'number' && !Number.isSafeInteger(value)) throw new Error('Unsafe Solana exit integer.');
    let n = BigInt(value);
    if (n < 0n || n >= 1n << BigInt(size * 8)) throw new Error('Solana exit integer is out of range.');
    return Uint8Array.from({ length: size }, () => { const b = Number(n & 255n); n >>= 8n; return b; });
}
function felt(value) {
    if (typeof value !== 'string' || !/^0x[0-9a-f]+$/i.test(value) || BigInt(value) >= FIELD) {
        throw new Error('Invalid Solana exit field.');
    }
    return integer(value, 32).reverse();
}
function concat(...values) {
    const output = new Uint8Array(values.reduce((length, value) => length + value.length, 0));
    let offset = 0;
    for (const value of values) { output.set(value, offset); offset += value.length; }
    return output;
}
async function discriminator(name) {
    return new Uint8Array(await crypto.subtle.digest('SHA-256', utf8(`global:${name}`))).slice(0, 8);
}
function decodeBase64(value) {
    return Uint8Array.from(atob(value), character => character.charCodeAt(0));
}
function withdrawalBytes(p) {
    const destination = Array.isArray(p.destination) ? p.destination
        : typeof p.destination === 'string' && /^0x[0-9a-f]{40}$/i.test(p.destination)
            ? p.destination.slice(2).match(/../g).map(value => parseInt(value, 16)) : [];
    if (destination.length !== 20 || destination.some(b => !Number.isInteger(b) || b < 0 || b > 255)
        || typeof p.has_clearance !== 'boolean') throw new Error('Invalid Solana exit destination or mode.');
    return concat(integer(p.protocol_version, 2), integer(p.chain_id, 8),
        ...['contract_address', 'registration', 'state_signing_key_x', 'state_signing_key_y',
            'clearance_signing_key_x', 'clearance_signing_key_y'].map(key => felt(p[key])),
        integer(p.note_id, 4), integer(p.deposit_amount, 16), integer(p.expiry_ts, 8),
        integer(p.final_balance, 16), Uint8Array.from(destination), felt(p.withdrawal_nullifier),
        Uint8Array.of(Number(p.has_clearance)), felt(p.next_nullifier), integer(p.conceded, 16), integer(p.valid_until, 8));
}

/** Build root-free exits using only the user's pinned Solana RPC, never the operator's prepare routes. */
export async function prepareLocalSolanaExit(funding, kind, body, { signal = AbortSignal.timeout(20_000) } = {}) {
    validateSolanaFunding(funding);
    if (!['escape', 'mutual', 'finalize'].includes(kind)) throw new Error('Invalid local Solana exit kind.');
    const program = new PublicKey(funding.program_id);
    const vault = new PublicKey(funding.vault_state);
    const payer = new PublicKey(body.payer);
    const p = body.public_inputs;
    const noteId = kind === 'finalize' ? body.note_id : p?.note_id;
    const noteSeed = integer(noteId, 4);
    const pda = (name, seed) => PublicKey.findProgramAddressSync([utf8(name), vault.toBytes(), seed], program)[0];
    const note = pda('note', noteSeed);
    const pending = pda('pending', noteSeed);
    if (await solanaRpc(funding, 'getGenesisHash', [], signal) !== funding.genesis_hash) {
        throw new Error('Solana exit RPC belongs to another cluster.');
    }
    const addresses = [vault, note, ...(kind === 'finalize' ? [pending] : [])];
    const response = await solanaRpc(funding, 'getMultipleAccounts', [addresses.map(key => key.toBase58()),
        { encoding: 'base64', commitment: 'confirmed' }], signal);
    if (!Array.isArray(response.value) || response.value.length !== addresses.length) throw new Error('Incomplete Solana exit accounts.');
    const data = response.value.map(account => {
        if (account?.owner !== funding.program_id || account.executable !== false
            || !Array.isArray(account.data) || account.data[1] !== 'base64') throw new Error('Invalid Solana exit account owner or data.');
        return decodeBase64(account.data[0]);
    });
    const vaultState = decodeSolanaVaultState(data[0]);
    const noteState = decodeSolanaNoteState(data[1]);
    if (!sameChainId(vaultState.chainId, funding.chain_id) || !sameFelt(vaultState.protocolBinding, funding.contract_address)
        || vaultState.genesisHash !== funding.genesis_hash || noteState.vault !== funding.vault_state
        || noteState.noteId !== Number(noteId)) throw new Error('Solana exit accounts belong to another deployment or note.');
    const meta = (pubkey, isWritable = true, isSigner = false) => ({ pubkey, isWritable, isSigner });
    let instruction;
    if (kind === 'finalize') {
        const state = decodeSolanaPendingWithdrawal(data[2]);
        if (noteState.status !== 'pending_withdrawal' || state.vault !== funding.vault_state || state.noteId !== Number(noteId)) {
            throw new Error('Solana escape is not pending for this note.');
        }
        instruction = new TransactionInstruction({ programId: program,
            keys: [meta(vault), meta(note), meta(pending), meta(payer, true, true), meta(new PublicKey(state.destination))],
            data: concat(await discriminator('finalize_escape'), noteSeed) });
    } else {
        const close = kind === 'mutual';
        if (p.protocol_version !== 2 || !sameChainId(p.chain_id, funding.chain_id)
            || !sameFelt(p.contract_address, funding.contract_address) || p.has_clearance !== close
            || noteState.status !== 'active' || !sameFelt(p.registration, noteState.commitment)
            || BigInt(p.deposit_amount) !== BigInt(noteState.amount) || BigInt(p.expiry_ts) !== BigInt(noteState.expiry)
            || BigInt(p.final_balance) + BigInt(p.conceded) > BigInt(noteState.amount)
            || (close ? BigInt(p.next_nullifier) !== 0n || BigInt(p.conceded) !== 0n
                : BigInt(p.next_nullifier) === 0n || sameFelt(p.next_nullifier, p.withdrawal_nullifier))) {
            throw new Error('Solana withdrawal does not match its note, mode, or deployment.');
        }
        for (const [wire, stored] of [['state_signing_key_x', 'stateSigningKeyX'], ['state_signing_key_y', 'stateSigningKeyY'],
            ['clearance_signing_key_x', 'clearanceSigningKeyX'], ['clearance_signing_key_y', 'clearanceSigningKeyY']]) {
            if (!sameFelt(p[wire], vaultState[stored])) throw new Error('Solana exit signing key mismatch.');
        }
        if (body.proof?.backend !== 'groth16_bn254') throw new Error('Invalid Solana exit proof backend.');
        const proof = decodeBase64(body.proof.proof);
        if (proof.length !== 256) throw new Error('Invalid Solana exit proof size.');
        const destination = new PublicKey(body.destination);
        const used = pda('nullifier', felt(p.withdrawal_nullifier));
        const keys = close
            ? [meta(vault), meta(note), meta(used), meta(payer, true, true), meta(destination), meta(SystemProgram.programId, false)]
            : [meta(vault), meta(note), meta(pending), meta(used), meta(pda('nullifier', felt(p.next_nullifier))),
                meta(payer, true, true), meta(destination), meta(SystemProgram.programId, false)];
        instruction = new TransactionInstruction({ programId: program, keys,
            data: concat(await discriminator(close ? 'execute_close' : 'execute_escape'), noteSeed, destination.toBytes(),
                withdrawalBytes(p), integer(proof.length, 4), proof) });
    }
    const latest = await solanaRpc(funding, 'getLatestBlockhash', [{ commitment: 'confirmed' }], signal);
    const { blockhash, lastValidBlockHeight } = latest.value || {};
    if (!Number.isSafeInteger(lastValidBlockHeight) || lastValidBlockHeight <= 0) throw new Error('Invalid Solana exit block height.');
    const transaction = new Transaction({ feePayer: payer, recentBlockhash: blockhash });
    if (kind !== 'finalize') transaction.add(ComputeBudgetProgram.requestHeapFrame({ bytes: 128 * 1024 }),
        ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }));
    transaction.add(instruction);
    const bytes = transaction.serializeMessage();
    if (bytes.length + 65 > 1_232) throw new Error('Solana exit exceeds one packet.');
    return { transactions: [{ format: 'solana-legacy-message-v1', bytes: Array.from(bytes),
        required_signers: [Array.from(payer.toBytes())], last_valid_height: lastValidBlockHeight }] };
}
