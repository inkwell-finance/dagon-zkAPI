// Test-only Solana transaction helpers for the CCTP harness: v0
// transactions over a CCTP address lookup table (a receive_message with an
// inbound hook does not fit a legacy transaction), and polling confirmation
// (no websocket subscriptions, so stopped validators leave no reconnect loop).
import { AddressLookupTableProgram, PublicKey, SystemProgram, TransactionMessage, VersionedTransaction } from '@solana/web3.js';
import { setTimeout as delay } from 'node:timers/promises';
import { cctpAccounts, remoteTokenMessenger, tokenPair } from '../../../sdk/services/zkapiCctp.mjs';
import { ASSOCIATED_TOKEN_PROGRAM_ID } from '../../../sdk/services/zkapiUsdc.mjs';
import { CCTP_REMOTE_USDC } from './validator.mjs';

export async function confirmSignature(connection, signature, { timeoutMs = 60_000 } = {}) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        const { value: [status] } = await connection.getSignatureStatuses([signature]);
        if (status?.err) throw new Error(`transaction ${signature} failed: ${JSON.stringify(status.err)}`);
        if (status && (status.confirmationStatus === 'confirmed' || status.confirmationStatus === 'finalized')) return signature;
        await delay(200);
    }
    throw new Error(`transaction ${signature} was not confirmed`);
}

async function versioned(connection, instructions, signers, lookupTables) {
    const { blockhash } = await connection.getLatestBlockhash('confirmed');
    const message = new TransactionMessage({ payerKey: signers[0].publicKey, recentBlockhash: blockhash, instructions }).compileToV0Message(lookupTables);
    const transaction = new VersionedTransaction(message);
    transaction.sign(signers);
    return transaction;
}

/** Sends a v0 transaction (fee payer = signers[0]) and waits for confirmation. */
export async function sendV0(connection, instructions, signers, lookupTables = []) {
    const transaction = await versioned(connection, instructions, signers, lookupTables);
    const signature = await connection.sendRawTransaction(transaction.serialize(), { preflightCommitment: 'confirmed' });
    return confirmSignature(connection, signature);
}

/** Simulates a v0 transaction; returns `{err, logs}` (logs joined). */
export async function simulateV0(connection, instructions, signers, lookupTables = []) {
    const transaction = await versioned(connection, instructions, signers, lookupTables);
    const { value } = await connection.simulateTransaction(transaction, { sigVerify: false, commitment: 'confirmed' });
    return { err: value.err, logs: (value.logs ?? []).join('\n') };
}

/** An address lookup table holding every fixed CCTP account (plus `extra`), owned by `payer`. */
export async function createCctpLookupTable(connection, payer, { feeRecipientTokenAccount, extra = [] } = {}) {
    const accounts = cctpAccounts();
    const addresses = [accounts.messageTransmitterProgram, accounts.tokenMessengerMinterProgram, accounts.messageTransmitter,
        accounts.messageTransmitterAuthority, accounts.messageTransmitterEventAuthority, accounts.tokenMessenger, accounts.tokenMinter,
        accounts.senderAuthority, accounts.tokenMessengerEventAuthority, accounts.localToken, accounts.custody,
        new PublicKey(feeRecipientTokenAccount ?? accounts.feeRecipientTokenAccount), accounts.mint, accounts.tokenProgram, SystemProgram.programId,
        new PublicKey(ASSOCIATED_TOKEN_PROGRAM_ID),
        ...Object.entries(CCTP_REMOTE_USDC).flatMap(([domain, usdc]) => [remoteTokenMessenger(Number(domain)), tokenPair(Number(domain), usdc)]),
        ...extra.map(key => new PublicKey(key))];
    // The recent slot must be in the executing bank's SlotHashes, which holds only its ancestors: on a single
    // local validator processed == confirmed == finalized == the bank's own slot, so take the parent.
    let table;
    for (let attempt = 0; ; attempt++) {
        const [create, address] = AddressLookupTableProgram.createLookupTable({ authority: payer.publicKey, payer: payer.publicKey,
            recentSlot: Math.max(0, await connection.getSlot('confirmed') - 1) });
        const extend = AddressLookupTableProgram.extendLookupTable({ lookupTable: address, authority: payer.publicKey, payer: payer.publicKey, addresses });
        try { await sendV0(connection, [create, extend], [payer]); table = address; break; } catch (error) {
            if (attempt >= 10 || !/not a recent slot/.test(String(error.message) + JSON.stringify(error.transactionLogs ?? []))) throw error;
            await delay(500);
        }
    }
    const extendedAt = await connection.getSlot('confirmed');
    while (await connection.getSlot('confirmed') <= extendedAt) await delay(200);
    const { value } = await connection.getAddressLookupTable(table, { commitment: 'confirmed' });
    if (!value || value.state.addresses.length !== addresses.length) throw new Error('CCTP lookup table was not extended');
    return value;
}
