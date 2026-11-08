// Test-only stand-in for Circle's Forwarding Service: polls iris-sim for
// attested messages whose hook starts with `cctp-forward` (and
// destinationCaller = 0) and broadcasts the destination mint. Solana:
// CreateIdempotent ATA(declared owner) when requested, then receive_message
// (the fee is already in feeExecuted). EVM: receiveMessage on the anvil fork.
// pause() simulates a Forwarding Service outage: messages attested meanwhile
// are queued and forwarded on resume() unless a fallback receiver (or the
// user) already consumed their nonce on the destination.
import { Connection, PublicKey } from '@solana/web3.js';
import { setTimeout as delay } from 'node:timers/promises';
import { EVM_CCTP, SOLANA_DOMAIN, decodeHook, decodeMessageV2, evmReceiveMessageCalldata, receiveMessageInstruction, usedNonce }
    from '../../../sdk/services/zkapiCctp.mjs';
import { createUsdcAccountIdempotentInstruction, usdcAssociatedTokenAddress } from '../../../sdk/services/zkapiUsdc.mjs';
import { ethRpc } from './anvil.mjs';
import { createCctpLookupTable, sendV0 } from './solana-tx.mjs';

// MessageTransmitterV2.usedNonces(bytes32)
const USED_NONCES_SELECTOR = 'feb61724';

/**
 * `payer` (Keypair) pays Solana fees/rent; `evm` = {domain: {rpcUrl, from}}
 * where `from` is an unlocked/impersonated account on that RPC.
 * `feeRecipientTokenAccount` = the CCTP fee recipient ATA; `lookupTable` = an
 * AddressLookupTableAccount from createCctpLookupTable (created on demand if absent).
 */
export function startForwardingSim({ irisUrl, solanaRpcUrl, payer, evm = {}, feeRecipientTokenAccount, lookupTable = null, pollMs = 300, log = () => {} }) {
    const connection = solanaRpcUrl ? new Connection(solanaRpcUrl, 'confirmed') : null;
    let since = 0; let paused = false; let stopped = false;
    const handled = new Set();
    const pending = new Map();
    const results = [];
    let idle = Promise.resolve();

    async function report(nonce, forwardState, forwardTxHash) {
        await fetch(`${irisUrl}/sim/forward`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ nonce, forwardState, forwardTxHash }) });
    }

    async function forwardToSolana(entry, message, hook) {
        const mintRecipient = new PublicKey(message.body.mintRecipient);
        const instructions = [];
        if (hook.forward.createAta) {
            // Circle validates mintRecipient == ATA(owner, USDC) before creating it.
            const owner = hook.forward.ataOwner.toBase58();
            if (usdcAssociatedTokenAddress(owner) !== mintRecipient.toBase58()) throw new Error('mintRecipient is not the ATA of the declared owner');
            instructions.push(createUsdcAccountIdempotentInstruction({ payer: payer.publicKey.toBase58(), owner }));
        }
        instructions.push(receiveMessageInstruction({ payer: payer.publicKey, message: entry.message, attestation: entry.attestation,
            ...(feeRecipientTokenAccount ? { feeRecipientTokenAccount } : {}) }));
        lookupTable ??= await createCctpLookupTable(connection, payer, { feeRecipientTokenAccount });
        return sendV0(connection, instructions, [payer], [lookupTable]);
    }

    async function forwardToEvm(entry, message) {
        const target = evm[message.destinationDomain];
        if (!target) throw new Error(`forwarding-sim has no EVM RPC for domain ${message.destinationDomain}`);
        const to = target.messageTransmitter ?? Object.values(EVM_CCTP).find(chain => chain.domain === message.destinationDomain).messageTransmitter;
        const hash = await ethRpc(target.rpcUrl, 'eth_sendTransaction', [{ from: target.from, to, data: evmReceiveMessageCalldata(entry.message, entry.attestation) }]);
        for (let i = 0; i < 240; i++) {
            const receipt = await ethRpc(target.rpcUrl, 'eth_getTransactionReceipt', [hash]);
            if (receipt) { if (receipt.status !== '0x1') throw new Error(`receiveMessage ${hash} reverted`); return hash; }
            await delay(250);
        }
        throw new Error(`receiveMessage ${hash} not mined`);
    }

    /** Whether the destination already consumed the nonce (e.g. a fallback receiver while forwarding was down). */
    async function nonceUsed(message) {
        if (message.destinationDomain === SOLANA_DOMAIN) return (await connection.getAccountInfo(usedNonce(message.nonce), 'confirmed')) !== null;
        const target = evm[message.destinationDomain];
        if (!target) return false;
        const to = target.messageTransmitter ?? Object.values(EVM_CCTP).find(chain => chain.domain === message.destinationDomain).messageTransmitter;
        const data = `0x${USED_NONCES_SELECTOR}${Buffer.from(message.nonce).toString('hex')}`;
        return BigInt(await ethRpc(target.rpcUrl, 'eth_call', [{ to, data }, 'latest'])) !== 0n;
    }

    async function handle(entry) {
        if (handled.has(entry.eventNonce)) return;
        if (entry.status !== 'complete' || entry.forwardState !== 'PENDING') { handled.add(entry.eventNonce); return; }
        if (paused) {
            // Forwarding outage: keep the latest attestation (a reattest replaces it) and deliver it on resume().
            pending.set(entry.eventNonce, entry);
            return;
        }
        handled.add(entry.eventNonce);
        pending.delete(entry.eventNonce);
        const message = decodeMessageV2(entry.message);
        const hook = decodeHook(message.body.hookData);
        try {
            if (await nonceUsed(message)) {
                // Someone else (fallback receiver, self-claim) minted it meanwhile; nothing left to forward.
                results.push({ nonce: entry.eventNonce, destinationDomain: message.destinationDomain, skipped: 'nonce already used' });
                log(`forwarding-sim skipped nonce ${entry.eventNonce}: already received`);
                return;
            }
            const txHash = message.destinationDomain === SOLANA_DOMAIN ? await forwardToSolana(entry, message, hook) : await forwardToEvm(entry, message);
            results.push({ nonce: entry.eventNonce, destinationDomain: message.destinationDomain, txHash });
            await report(entry.eventNonce, 'COMPLETE', txHash);
            log(`forwarding-sim minted nonce ${entry.eventNonce} on domain ${message.destinationDomain}: ${txHash}`);
        } catch (error) {
            results.push({ nonce: entry.eventNonce, destinationDomain: message.destinationDomain, error: String(error.message ?? error) });
            await report(entry.eventNonce, 'FAILED');
            log(`forwarding-sim failed nonce ${entry.eventNonce}: ${error.message ?? error}`);
        }
    }

    async function poll() {
        if (!paused) for (const entry of [...pending.values()]) await handle(entry);
        const response = await fetch(`${irisUrl}/sim/messages?since=${since}`);
        const body = await response.json();
        for (const entry of body.messages) {
            await handle(entry);
            since = Math.max(since, entry.sequence);
        }
    }

    const loop = (async () => {
        while (!stopped) {
            idle = poll().catch(error => log(`forwarding-sim poll error: ${error.message ?? error}`));
            await idle;
            await delay(pollMs);
        }
    })();

    return {
        /** Forwarding outage: work attested meanwhile is queued, not dropped. */
        pause() { paused = true; },
        /** Ends the outage; queued messages are forwarded unless their nonce was already received. */
        resume() { paused = false; },
        /** Nonces queued during the current/last outage. */
        pending: () => [...pending.keys()],
        results,
        /** Waits until a forward for `nonce` (0x-hex) completed, failed or was skipped as already received. */
        async waitFor(nonce, timeoutMs = 60_000) {
            const deadline = Date.now() + timeoutMs;
            while (Date.now() < deadline) {
                const result = results.find(entry => entry.nonce === nonce);
                if (result) return result;
                await delay(100);
            }
            throw new Error(`forwarding-sim did not process ${nonce}`);
        },
        async stop() { stopped = true; await loop; }
    };
}
