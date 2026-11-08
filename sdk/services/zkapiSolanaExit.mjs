import { PublicKey, Transaction, TransactionInstruction, ComputeBudgetProgram, SystemProgram } from '@solana/web3.js';
import { assertVaultUsdcAccounts, createUsdcAccountIdempotentInstruction, decodeSolanaNoteState,
    decodeSolanaPendingWithdrawal, decodeSolanaVaultState, readUsdcTokenAccount, solanaRpc,
    validateSolanaFunding, vaultTokenAddress } from './zkapiUsdc.mjs';
import { sameChainId } from './zkapiLedgerIdentity.mjs';
import { sameFelt } from './zkapiActiveRoot.mjs';

const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const EXIT_KINDS = ['escape', 'mutual', 'finalize', 'release'];
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

async function latestBlockhash(funding, signal) {
    const latest = await solanaRpc(funding, 'getLatestBlockhash', [{ commitment: 'confirmed' }], signal);
    const { blockhash, lastValidBlockHeight } = latest.value || {};
    if (!Number.isSafeInteger(lastValidBlockHeight) || lastValidBlockHeight <= 0) {
        throw new Error('Invalid Solana block height.');
    }
    return { blockhash, lastValidBlockHeight };
}

function singleSignerOperation(transaction, payer, lastValidBlockHeight) {
    const bytes = transaction.serializeMessage();
    if (bytes.length + 65 > 1_232) throw new Error('Solana transaction exceeds one packet.');
    return { transactions: [{ format: 'solana-legacy-message-v1', bytes: Array.from(bytes),
        required_signers: [Array.from(payer.toBytes())], last_valid_height: lastValidBlockHeight }] };
}

async function assertSameCluster(funding, signal) {
    if (await solanaRpc(funding, 'getGenesisHash', [], signal) !== funding.genesis_hash) {
        throw new Error('Solana RPC belongs to another cluster.');
    }
}

/**
 * The payout account must be creditable when an exit lands: an escape
 * requires it, and a mutual close with a positive final balance fails
 * otherwise. Fail before the wallet prompt with an actionable error.
 */
async function assertCreditableDestination(funding, destination, signal) {
    const tokenAccount = await readUsdcTokenAccount(funding, destination, { signal });
    if (!tokenAccount?.creditable) {
        const error = new Error(tokenAccount
            ? 'The USDC payout account is frozen, uninitialized or holds another token.'
            : 'The USDC payout account does not exist yet. Create it before withdrawing.');
        error.code = 'usdc_destination_not_creditable';
        throw error;
    }
    return tokenAccount;
}

/**
 * The vault's `execute_close` (mutual) or `execute_escape` instruction for
 * `{ payer, destination, public_inputs, proof }`, built from the deployment
 * pins alone (no RPC): `payer` is the vault operation owner. Also used to
 * check a relayer-prepared exit byte for byte.
 */
export async function solanaExitInstruction(funding, kind, body) {
    if (!['mutual', 'escape'].includes(kind)) throw new Error('Invalid Solana exit kind.');
    const program = new PublicKey(funding.program_id);
    const vault = new PublicKey(funding.vault_state);
    const p = body.public_inputs;
    const close = kind === 'mutual';
    if (p?.has_clearance !== close
        || (close ? BigInt(p.next_nullifier) !== 0n || BigInt(p.conceded) !== 0n
            : BigInt(p.next_nullifier) === 0n || sameFelt(p.next_nullifier, p.withdrawal_nullifier))) {
        throw new Error('Solana withdrawal does not match its note, mode, or deployment.');
    }
    if (body.proof?.backend !== 'groth16_bn254') throw new Error('Invalid Solana exit proof backend.');
    const proof = decodeBase64(body.proof.proof);
    if (proof.length !== 256) throw new Error('Invalid Solana exit proof size.');
    const vaultToken = new PublicKey(vaultTokenAddress(funding.program_id, funding.vault_state));
    const destination = new PublicKey(body.destination);
    if (destination.equals(vaultToken)) throw new Error('The vault token account cannot receive a withdrawal.');
    const noteSeed = integer(p.note_id, 4);
    const pda = (name, seed) => PublicKey.findProgramAddressSync([utf8(name), vault.toBytes(), seed], program)[0];
    const meta = (pubkey, isWritable = true, isSigner = false) => ({ pubkey, isWritable, isSigner });
    const payer = new PublicKey(body.payer);
    const used = pda('nullifier', felt(p.withdrawal_nullifier));
    const keys = close
        ? [meta(vault), meta(pda('note', noteSeed)), meta(used), meta(payer, true, true), meta(destination), meta(vaultToken),
            meta(new PublicKey(funding.usdc_mint), false), meta(new PublicKey(funding.token_program), false),
            meta(SystemProgram.programId, false)]
        : [meta(vault), meta(pda('note', noteSeed)), meta(pda('pending', noteSeed)), meta(used),
            meta(pda('nullifier', felt(p.next_nullifier))), meta(payer, true, true), meta(destination, false),
            meta(SystemProgram.programId, false)];
    return new TransactionInstruction({ programId: program, keys,
        data: concat(await discriminator(close ? 'execute_close' : 'execute_escape'), noteSeed,
            withdrawalBytes(p), integer(proof.length, 4), proof) });
}

/**
 * Build root-free exits using only the user's pinned Solana RPC, never the
 * operator's prepare routes. `mutual`/`escape` take `{ payer, destination,
 * public_inputs, proof }` where `destination` is the proof-bound USDC payout
 * token account; `finalize` and `release` take `{ payer, note_id }` and pay the
 * pending record's saved destination and rent payer.
 */
export async function prepareLocalSolanaExit(funding, kind, body, { signal = AbortSignal.timeout(20_000) } = {}) {
    validateSolanaFunding(funding);
    if (!EXIT_KINDS.includes(kind)) throw new Error('Invalid local Solana exit kind.');
    const program = new PublicKey(funding.program_id);
    const vault = new PublicKey(funding.vault_state);
    const payer = new PublicKey(body.payer);
    const p = body.public_inputs;
    const pendingKind = kind === 'finalize' || kind === 'release';
    const noteId = pendingKind ? body.note_id : p?.note_id;
    const noteSeed = integer(noteId, 4);
    const pda = (name, seed) => PublicKey.findProgramAddressSync([utf8(name), vault.toBytes(), seed], program)[0];
    const note = pda('note', noteSeed);
    const pending = pda('pending', noteSeed);
    await assertSameCluster(funding, signal);
    const addresses = [vault, note, ...(pendingKind ? [pending] : [])];
    const response = await solanaRpc(funding, 'getMultipleAccounts', [addresses.map(key => key.toBase58()),
        { encoding: 'base64', commitment: 'confirmed' }], signal);
    if (!Array.isArray(response.value) || response.value.length !== addresses.length) throw new Error('Incomplete Solana exit accounts.');
    const data = response.value.map(account => {
        if (account?.owner !== funding.program_id || account.executable !== false
            || !Array.isArray(account.data) || account.data[1] !== 'base64') throw new Error('Invalid Solana exit account owner or data.');
        return decodeBase64(account.data[0]);
    });
    const vaultState = assertVaultUsdcAccounts(decodeSolanaVaultState(data[0]), funding);
    const noteState = decodeSolanaNoteState(data[1]);
    if (!sameChainId(vaultState.chainId, funding.chain_id) || !sameFelt(vaultState.protocolBinding, funding.contract_address)
        || vaultState.genesisHash !== funding.genesis_hash || noteState.vault !== funding.vault_state
        || noteState.noteId !== Number(noteId)) throw new Error('Solana exit accounts belong to another deployment or note.');
    const meta = (pubkey, isWritable = true, isSigner = false) => ({ pubkey, isWritable, isSigner });
    const vaultToken = new PublicKey(vaultState.vaultToken);
    const mint = new PublicKey(vaultState.mint);
    const tokenProgram = new PublicKey(funding.token_program);
    let instruction;
    if (pendingKind) {
        const state = decodeSolanaPendingWithdrawal(data[2]);
        if (state.vault !== funding.vault_state || state.noteId !== Number(noteId)) {
            throw new Error('The Solana pending withdrawal belongs to another note.');
        }
        if (kind === 'finalize' && (noteState.status !== 'pending_withdrawal' || state.stage !== 'open')) {
            throw new Error('Solana escape is not pending for this note.');
        }
        if (kind === 'release' && (!['closed', 'retired'].includes(noteState.status) || state.stage !== 'payout_parked')) {
            throw new Error('This Solana escape has no parked payout to release.');
        }
        // The program pays only the saved destination and refunds the
        // pending rent only to the saved escaper, who must be writable.
        instruction = new TransactionInstruction({ programId: program,
            keys: [meta(vault), meta(note, kind === 'finalize'), meta(pending), meta(payer, false, true),
                meta(new PublicKey(state.rentPayer)), meta(new PublicKey(state.destination)),
                meta(vaultToken), meta(mint, false), meta(tokenProgram, false)],
            data: concat(await discriminator(kind === 'finalize' ? 'finalize_escape' : 'release_escape_payout'), noteSeed) });
    } else {
        if (p.protocol_version !== 2 || !sameChainId(p.chain_id, funding.chain_id)
            || !sameFelt(p.contract_address, funding.contract_address)
            || noteState.status !== 'active' || !sameFelt(p.registration, noteState.commitment)
            || BigInt(p.deposit_amount) !== BigInt(noteState.amount) || BigInt(p.expiry_ts) !== BigInt(noteState.expiry)
            || BigInt(p.final_balance) + BigInt(p.conceded) > BigInt(noteState.amount)) {
            throw new Error('Solana withdrawal does not match its note, mode, or deployment.');
        }
        for (const [wire, stored] of [['state_signing_key_x', 'stateSigningKeyX'], ['state_signing_key_y', 'stateSigningKeyY'],
            ['clearance_signing_key_x', 'clearanceSigningKeyX'], ['clearance_signing_key_y', 'clearanceSigningKeyY']]) {
            if (!sameFelt(p[wire], vaultState[stored])) throw new Error('Solana exit signing key mismatch.');
        }
        instruction = await solanaExitInstruction(funding, kind, body);
        if (kind === 'escape' || BigInt(p.final_balance) > 0n) {
            await assertCreditableDestination(funding, body.destination, signal);
        }
    }
    const { blockhash, lastValidBlockHeight } = await latestBlockhash(funding, signal);
    const transaction = new Transaction({ feePayer: payer, recentBlockhash: blockhash });
    if (!pendingKind) transaction.add(ComputeBudgetProgram.requestHeapFrame({ bytes: 128 * 1024 }),
        ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }));
    transaction.add(instruction);
    return singleSignerOperation(transaction, payer, lastValidBlockHeight);
}

/**
 * Build the wallet's own canonical USDC account (`CreateIdempotent`, rent paid
 * by the wallet) as a standalone transaction that precedes a payout to it.
 */
export async function prepareLocalUsdcAccountCreation(funding, { payer }, { signal = AbortSignal.timeout(20_000) } = {}) {
    validateSolanaFunding(funding);
    const wallet = new PublicKey(payer);
    await assertSameCluster(funding, signal);
    const { blockhash, lastValidBlockHeight } = await latestBlockhash(funding, signal);
    const transaction = new Transaction({ feePayer: wallet, recentBlockhash: blockhash });
    transaction.add(createUsdcAccountIdempotentInstruction({ payer, owner: payer }));
    return singleSignerOperation(transaction, wallet, lastValidBlockHeight);
}
