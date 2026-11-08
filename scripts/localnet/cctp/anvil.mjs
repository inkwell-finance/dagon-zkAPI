// Test-only: an anvil fork of an EVM CCTP chain (Base mainnet by default)
// with real Circle bytecode/state. Impersonation funds a test user with
// USDC (masterMinter -> configureMinter -> mint), enables the local test
// attesters on MessageTransmitterV2 (attesterManager -> enableAttester),
// and denylists/blacklists addresses. `provider` is an EIP-1193 shim.
import { spawn } from 'node:child_process';
import { open } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { setTimeout as delay } from 'node:timers/promises';
import { randomBytes } from 'node:crypto';
import { keccak_256 } from '@noble/hashes/sha3';
import { EVM_CCTP, evmBytes32 } from '../../../sdk/services/zkapiCctp.mjs';

const selector = signature => Buffer.from(keccak_256(new TextEncoder().encode(signature))).subarray(0, 4).toString('hex');
const word = value => BigInt(value).toString(16).padStart(64, '0');
const addressWord = address => Buffer.from(evmBytes32(address)).toString('hex');
const addressFrom = result => `0x${result.slice(-40)}`;
const ETH = '0x3635c9adc5dea00000'; // 1000 ETH for gas on impersonated accounts.

export async function ethRpc(url, method, params = []) {
    const response = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }), signal: AbortSignal.timeout(120_000) });
    const body = await response.json();
    if (body.error) {
        const error = new Error(`${method}: ${body.error.message}${body.error.data ? ` ${JSON.stringify(body.error.data)}` : ''}`);
        error.rpc = body.error;
        throw error;
    }
    return body.result;
}

/** Minimal EIP-1193 provider over an RPC with locally "connected" (impersonated/unlocked) accounts. */
export function eip1193Provider(rpcUrl, { accounts = [], chainId } = {}) {
    return {
        async request({ method, params = [] }) {
            if (method === 'eth_requestAccounts' || method === 'eth_accounts') return accounts;
            if (method === 'wallet_switchEthereumChain') {
                const current = chainId ?? await ethRpc(rpcUrl, 'eth_chainId');
                if (BigInt(params[0]?.chainId) !== BigInt(current)) throw Object.assign(new Error('Unrecognized chain ID.'), { code: 4902 });
                return null;
            }
            return ethRpc(rpcUrl, method, params);
        },
        on() {}, removeListener() {}
    };
}

/**
 * Starts anvil forking `forkUrl` and returns helpers bound to `chain`
 * (an EVM_CCTP entry). Ports: `port` only.
 */
export async function startAnvilFork({ forkUrl = process.env.BASE_RPC_URL ?? 'https://mainnet.base.org', chain = EVM_CCTP.base, port = 18545,
    anvilPath = process.env.ANVIL ?? join(homedir(), '.foundry/bin/anvil'), forkBlockNumber, logPath, log = () => {} }) {
    const rpcUrl = `http://127.0.0.1:${port}`;
    // Default anvil auto-mines one block per transaction.
    const args = ['--fork-url', forkUrl, '--port', String(port), '--host', '127.0.0.1', '--silent'];
    if (forkBlockNumber !== undefined) args.push('--fork-block-number', String(forkBlockNumber));
    const logFile = logPath ? await open(logPath, 'a') : null;
    const child = spawn(anvilPath, args, { stdio: ['ignore', logFile?.fd ?? 'ignore', logFile?.fd ?? 'ignore'] });
    let failed; let stopped = false;
    child.on('error', error => { failed = error; });
    child.on('exit', code => { if (!stopped) failed = new Error(`anvil exited ${code}`); });
    const kill = () => { stopped = true; if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); };
    process.on('exit', kill);
    async function stop() {
        stopped = true;
        if (child.exitCode === null && child.signalCode === null) {
            const exited = new Promise(done => child.once('exit', done));
            child.kill('SIGTERM');
            await exited;
        }
        await logFile?.close();
        process.removeListener('exit', kill);
    }
    try {
        let chainId;
        for (let i = 0; i < 240 && chainId === undefined; i++) {
            if (failed) throw failed;
            try { chainId = await ethRpc(rpcUrl, 'eth_chainId'); } catch { await delay(500); }
        }
        if (chainId === undefined) throw new Error('anvil readiness deadline exceeded');
        if (BigInt(chainId) !== BigInt(chain.chainId)) throw new Error(`anvil fork chain id ${BigInt(chainId)} is not ${chain.chainId}`);
        log(`anvil fork of chain ${chain.chainId} at ${rpcUrl}`);

        const call = async (to, data) => ethRpc(rpcUrl, 'eth_call', [{ to, data }, 'latest']);
        async function impersonate(address) {
            await ethRpc(rpcUrl, 'anvil_impersonateAccount', [address]);
            await ethRpc(rpcUrl, 'anvil_setBalance', [address, ETH]);
            return address;
        }
        /** eth_sendTransaction from an unlocked/impersonated account; resolves to the successful receipt. */
        async function send({ from, to, data, value = '0x0', gas }) {
            const hash = await ethRpc(rpcUrl, 'eth_sendTransaction', [{ from, to, data, value, ...(gas ? { gas } : {}) }]);
            for (let i = 0; i < 240; i++) {
                const receipt = await ethRpc(rpcUrl, 'eth_getTransactionReceipt', [hash]);
                if (receipt) {
                    if (receipt.status !== '0x1') throw new Error(`EVM transaction ${hash} reverted`);
                    return receipt;
                }
                await delay(250);
            }
            throw new Error(`EVM transaction ${hash} was not mined`);
        }
        const roleHolder = async (contract, signature) => addressFrom(await call(contract, `0x${selector(signature)}`));

        /** A fresh impersonated EVM account with gas money, usable via `provider`. */
        async function newUser() {
            return impersonate(`0x${randomBytes(20).toString('hex')}`);
        }
        /** Mints `amount` USDC base units to `to` as a minter configured by the impersonated masterMinter. */
        async function mintUsdc(to, amount) {
            const masterMinter = await impersonate(await roleHolder(chain.usdc, 'masterMinter()'));
            const minter = await newUser();
            await send({ from: masterMinter, to: chain.usdc, data: `0x${selector('configureMinter(address,uint256)')}${addressWord(minter)}${word(amount)}` });
            await send({ from: minter, to: chain.usdc, data: `0x${selector('mint(address,uint256)')}${addressWord(to)}${word(amount)}` });
        }
        async function usdcBalance(owner) {
            return BigInt(await call(chain.usdc, `0x${selector('balanceOf(address)')}${addressWord(owner)}`));
        }
        /** enableAttester(address) for each local test attester, as the impersonated attesterManager. */
        async function enableAttesters(addresses) {
            const manager = await impersonate(await roleHolder(chain.messageTransmitter, 'attesterManager()'));
            for (const address of addresses) {
                const enabled = BigInt(await call(chain.messageTransmitter, `0x${selector('isEnabledAttester(address)')}${addressWord(address)}`));
                if (!enabled) await send({ from: manager, to: chain.messageTransmitter, data: `0x${selector('enableAttester(address)')}${addressWord(address)}` });
            }
            return BigInt(await call(chain.messageTransmitter, `0x${selector('signatureThreshold()')}`));
        }
        /** TokenMessengerV2.denylist(address) as the impersonated denylister (blocks depositForBurn* by msg.sender/tx.origin). */
        async function denylist(address) {
            const denylister = await impersonate(await roleHolder(chain.tokenMessenger, 'denylister()'));
            await send({ from: denylister, to: chain.tokenMessenger, data: `0x${selector('denylist(address)')}${addressWord(address)}` });
        }
        /** USDC blacklist(address) as the impersonated blacklister (blocks mints/transfers to it). */
        async function blacklistUsdc(address) {
            const blacklister = await impersonate(await roleHolder(chain.usdc, 'blacklister()'));
            await send({ from: blacklister, to: chain.usdc, data: `0x${selector('blacklist(address)')}${addressWord(address)}` });
        }
        async function nonceUsed(nonce) {
            return BigInt(await call(chain.messageTransmitter, `0x${selector('usedNonces(bytes32)')}${Buffer.from(nonce).toString('hex')}`)) !== 0n;
        }
        return {
            rpcUrl, chain, chainId: Number(BigInt(chainId)), stop, call, send, impersonate, newUser, mintUsdc, usdcBalance, enableAttesters, denylist,
            blacklistUsdc, nonceUsed, provider: accounts => eip1193Provider(rpcUrl, { accounts, chainId })
        };
    } catch (error) { await stop(); throw error; }
}
