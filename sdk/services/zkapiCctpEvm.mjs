// EIP-1193 side of the program-free CCTP flows: the user's own EVM wallet
// approves and burns USDC on the source chain (inbound) and, for a
// self-claimed outbound transfer, submits Circle's attested message to the
// destination MessageTransmitterV2. No EVM library: calldata comes from
// zkapiCctp.mjs and every provider answer is checked before it is trusted.
import { keccak_256 } from '@noble/hashes/sha3';
import { evmReceiveMessageCalldata } from './zkapiCctp.mjs';

const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const TX_HASH = /^0x[0-9a-fA-F]{64}$/;
const ZERO_ADDRESS = `0x${'0'.repeat(40)}`;
// Addresses that accept a mint but that nobody controls: a transfer there is lost.
const DEAD_ADDRESSES = new Set([
    ZERO_ADDRESS,
    '0x000000000000000000000000000000000000dead',
    '0xdead000000000000000042069420694206942069',
    '0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead',
    `0x${'f'.repeat(40)}`,
    '0x0000000000000000000000000000000000000001'
]);

const utf8 = value => new TextEncoder().encode(value);

function hex(bytes) {
    return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}

const selector = signature => hex(keccak_256(utf8(signature)).slice(0, 4));
const BALANCE_OF = selector('balanceOf(address)');
const ALLOWANCE = selector('allowance(address,address)');

function addressWord(address) {
    return evmAddress(address, 'address').slice(2).padStart(64, '0');
}

/** A checksummed or lower-case 20-byte EVM address, returned lower-case. */
export function evmAddress(value, label = 'EVM address') {
    if (typeof value !== 'string' || !ADDRESS.test(value)) {
        throw new TypeError(`${label} must be a 0x-prefixed 20-byte EVM address.`);
    }
    return value.toLowerCase();
}

/**
 * Refuse destinations a transfer can never be recovered from: the zero
 * address, well-known burn/"dead" addresses and the CCTP/USDC contracts of the
 * destination chain itself.
 */
export function assertEvmRecipient(value, chain = null) {
    const address = evmAddress(value, 'EVM recipient');
    const contracts = chain ? [chain.usdc, chain.tokenMessenger, chain.messageTransmitter]
        .filter(Boolean).map(entry => String(entry).toLowerCase()) : [];
    if (DEAD_ADDRESSES.has(address) || contracts.includes(address)) {
        const error = new Error('This EVM recipient cannot receive USDC: it is a zero, burn or contract address.');
        error.code = 'cctp_recipient_rejected';
        throw error;
    }
    return address;
}

function providerRequest(provider, method, params = []) {
    if (!provider || typeof provider.request !== 'function') {
        throw new TypeError('An EIP-1193 provider with request() is required.');
    }
    return provider.request({ method, params });
}

function quantity(value, label) {
    if (typeof value !== 'string' || !/^0x[0-9a-fA-F]+$/.test(value)) {
        throw new Error(`The EVM wallet returned an invalid ${label}.`);
    }
    return BigInt(value);
}

function hexQuantity(value) {
    return `0x${BigInt(value).toString(16)}`;
}

/** eth_requestAccounts: the account that will sign (and be refunded). */
export async function requestEvmAccount(provider) {
    const accounts = await providerRequest(provider, 'eth_requestAccounts');
    if (!Array.isArray(accounts) || accounts.length === 0) {
        throw new Error('The EVM wallet did not return an account.');
    }
    return evmAddress(accounts[0], 'EVM wallet account');
}

/** Switch the wallet to `chainId` and verify that it actually switched. */
export async function ensureEvmChain(provider, chainId) {
    const wanted = BigInt(chainId);
    if (quantity(await providerRequest(provider, 'eth_chainId'), 'chain ID') === wanted) return;
    try {
        await providerRequest(provider, 'wallet_switchEthereumChain', [{ chainId: hexQuantity(wanted) }]);
    } catch (cause) {
        const error = new Error(cause?.code === 4902
            ? `Add EVM chain ${wanted} to your wallet, then try again.`
            : `The EVM wallet did not switch to chain ${wanted}.`);
        error.code = 'evm_chain_switch_failed';
        error.cause = cause;
        throw error;
    }
    if (quantity(await providerRequest(provider, 'eth_chainId'), 'chain ID') !== wanted) {
        const error = new Error(`The EVM wallet is not on chain ${wanted}.`);
        error.code = 'evm_chain_switch_failed';
        throw error;
    }
}

async function callUint(provider, to, data) {
    const result = await providerRequest(provider, 'eth_call', [{ to: evmAddress(to, 'token'), data }, 'latest']);
    if (typeof result !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(result)) {
        throw new Error('The EVM RPC returned a malformed uint256.');
    }
    return BigInt(result);
}

export function readErc20Balance(provider, token, owner) {
    return callUint(provider, token, `0x${BALANCE_OF}${addressWord(owner)}`);
}

export function readErc20Allowance(provider, token, owner, spender) {
    return callUint(provider, token, `0x${ALLOWANCE}${addressWord(owner)}${addressWord(spender)}`);
}

/** eth_sendTransaction; returns the transaction hash. */
export async function sendEvmTransaction(provider, { from, to, data }) {
    const hash = await providerRequest(provider, 'eth_sendTransaction', [{
        from: evmAddress(from, 'sender'), to: evmAddress(to, 'contract'), data, value: '0x0'
    }]);
    if (typeof hash !== 'string' || !TX_HASH.test(hash)) {
        throw new Error('The EVM wallet returned an invalid transaction hash.');
    }
    return hash.toLowerCase();
}

function sleep(milliseconds, signal) {
    return new Promise((resolve, reject) => {
        const timer = setTimeout(resolve, milliseconds);
        signal?.addEventListener('abort', () => {
            clearTimeout(timer);
            reject(signal.reason || new DOMException('The operation was aborted.', 'AbortError'));
        }, { once: true });
    });
}

/** Poll eth_getTransactionReceipt until mined; a reverted transaction throws. */
export async function waitForEvmReceipt(provider, hash, {
    timeoutMs = 15 * 60_000, pollIntervalMs = 2_000, signal = null, now = Date.now
} = {}) {
    const deadline = now() + timeoutMs;
    while (true) {
        const receipt = await providerRequest(provider, 'eth_getTransactionReceipt', [hash]);
        if (receipt) {
            if (String(receipt.transactionHash || hash).toLowerCase() !== hash.toLowerCase()) {
                throw new Error('The EVM RPC returned a receipt for a different transaction.');
            }
            if (quantity(receipt.status, 'receipt status') !== 1n) {
                const error = new Error('The EVM transaction reverted.');
                error.code = 'evm_transaction_reverted';
                error.transactionHash = hash;
                throw error;
            }
            return receipt;
        }
        if (now() > deadline) {
            const error = new Error('The EVM transaction was not mined in time. It may still confirm; resume later.');
            error.code = 'evm_receipt_timeout';
            error.transactionHash = hash;
            throw error;
        }
        await sleep(pollIntervalMs, signal);
    }
}

/**
 * Approve (only when the allowance is short) and burn. `onBurnRequested` is
 * awaited before the burn prompt and `onBurnHash` before anything else, so
 * the caller can make both durable.
 */
export async function burnUsdcOnEvm({
    provider,
    chain,
    from,
    amount,
    approveCalldata,
    burnCalldata,
    onApproveHash = async () => {},
    onBurnRequested = async () => {},
    onBurnHash = async () => {},
    receiptOptions = {}
}) {
    const allowance = await readErc20Allowance(provider, chain.usdc, from, chain.tokenMessenger);
    if (allowance < BigInt(amount)) {
        const approveHash = await sendEvmTransaction(provider, { from, to: chain.usdc, data: approveCalldata });
        await onApproveHash(approveHash);
        await waitForEvmReceipt(provider, approveHash, receiptOptions);
    }
    await onBurnRequested();
    const burnHash = await sendEvmTransaction(provider, { from, to: chain.tokenMessenger, data: burnCalldata });
    await onBurnHash(burnHash);
    const receipt = await waitForEvmReceipt(provider, burnHash, receiptOptions);
    return { transactionHash: burnHash, receipt };
}

/** Self-claim an attested outbound transfer on its EVM destination. */
export async function claimCctpOnEvm({ provider, chain, message, attestation, receiptOptions = {} }) {
    const from = await requestEvmAccount(provider);
    await ensureEvmChain(provider, chain.chainId);
    const hash = await sendEvmTransaction(provider, {
        from, to: chain.messageTransmitter, data: evmReceiveMessageCalldata(message, attestation)
    });
    await waitForEvmReceipt(provider, hash, receiptOptions);
    return { transactionHash: hash, from };
}

export { DEAD_ADDRESSES, ZERO_ADDRESS };
