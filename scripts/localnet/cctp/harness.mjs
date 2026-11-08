// Test-only CCTP harness CLI: CCTP localnet (or attach to a stack started
// with `stack.mjs --cctp`), Base anvil fork, iris-sim and forwarding-sim.
// Prints one JSON line with the endpoints and runs until SIGINT/SIGTERM.
//
//   node scripts/localnet/cctp/harness.mjs --run-dir /tmp/cctp-run [--rpc-port 18899]
//       [--variant normal|mt-paused|minter-paused] [--denylist KEY,KEY] [--anvil-port 18545]
//       [--no-anvil] [--iris-port 18333] [--no-forwarder]
//   node scripts/localnet/cctp/harness.mjs --attach-solana http://127.0.0.1:18899 --attesters RUN/cctp-attesters.json --payer RUN/payer.json ...
import { mkdir, readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { Keypair } from '@solana/web3.js';
import { EVM_CCTP } from '../../../sdk/services/zkapiCctp.mjs';
import { readTestAttesters, startCctpLocalnet } from './validator.mjs';
import { startIrisSim } from './iris-sim.mjs';
import { startForwardingSim } from './forwarding-sim.mjs';
import { startAnvilFork } from './anvil.mjs';

const { values } = parseArgs({ options: {
    'run-dir': { type: 'string' }, 'rpc-port': { type: 'string', default: '18899' }, variant: { type: 'string', default: 'normal' },
    denylist: { type: 'string', default: '' }, 'anvil-port': { type: 'string', default: '18545' }, 'no-anvil': { type: 'boolean', default: false },
    'fork-url': { type: 'string' }, 'iris-port': { type: 'string', default: '18333' }, 'no-forwarder': { type: 'boolean', default: false },
    'attach-solana': { type: 'string' }, attesters: { type: 'string' }, payer: { type: 'string' }
} });

const stops = [];
let shuttingDown = false;
async function shutdown(code) {
    if (shuttingDown) return;
    shuttingDown = true;
    console.error('cctp harness: shutting down');
    // Bound shutdown; the validator/anvil exit hooks kill any remaining child.
    setTimeout(() => process.exit(code), 15_000).unref();
    for (const stop of stops.reverse()) { try { await stop(); } catch (error) { console.error(error); } }
    process.exit(code);
}
for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP']) process.on(signal, () => void shutdown(0));

try {
    const log = message => console.error(message);
    let solana;
    if (values['attach-solana']) {
        if (!values.attesters || !values.payer) throw new Error('--attach-solana needs --attesters and --payer');
        const payer = Keypair.fromSecretKey(Uint8Array.from(JSON.parse(await readFile(values.payer, 'utf8'))));
        solana = { rpcUrl: values['attach-solana'], payer, payerKeypairPath: resolve(values.payer), cctp: { attestersPath: resolve(values.attesters) } };
    } else {
        if (!values['run-dir']) throw new Error('--run-dir is required (a new directory)');
        await mkdir(values['run-dir'], { recursive: true });
        solana = await startCctpLocalnet({ runDir: join(values['run-dir'], 'solana'), rpcPort: Number(values['rpc-port']), log,
            cctp: { variant: values.variant, denylist: values.denylist ? values.denylist.split(',') : [] } });
        stops.push(solana.stop);
    }
    const { attesters, threshold } = await readTestAttesters(solana.cctp.attestersPath);
    let anvil = null; let evmForwarder = null;
    if (!values['no-anvil']) {
        anvil = await startAnvilFork({ port: Number(values['anvil-port']), forkUrl: values['fork-url'] ?? process.env.BASE_RPC_URL ?? 'https://mainnet.base.org',
            logPath: values['run-dir'] ? join(values['run-dir'], 'anvil.log') : undefined, log });
        stops.push(anvil.stop);
        await anvil.enableAttesters(attesters.map(attester => attester.address));
        evmForwarder = await anvil.newUser();
    }
    const base = EVM_CCTP.base.domain;
    const iris = await startIrisSim({ port: Number(values['iris-port']), attesters, threshold, solanaRpcUrl: solana.rpcUrl,
        evmRpcUrls: anvil ? { [base]: anvil.rpcUrl } : {}, log });
    stops.push(iris.close);
    if (!values['no-forwarder']) {
        const forwarder = startForwardingSim({ irisUrl: iris.url, solanaRpcUrl: solana.rpcUrl, payer: solana.payer,
            feeRecipientTokenAccount: solana.cctp.feeRecipientTokenAccount,
            evm: anvil ? { [base]: { rpcUrl: anvil.rpcUrl, from: evmForwarder } } : {}, log });
        stops.push(forwarder.stop);
    }
    // `attesters` (ascending EVM addresses of the local test keys) + `attesterThreshold` are the pin a wallet/relay
    // configures to verify iris-sim attestations; iris-sim /v2/publicKeys serves the same keys.
    console.log(JSON.stringify({ solanaRpcUrl: solana.rpcUrl, payerKeypairPath: solana.payerKeypairPath, attestersPath: solana.cctp.attestersPath,
        attesters: attesters.map(attester => attester.address), attesterThreshold: threshold, cctp: solana.cctp, irisUrl: iris.url,
        anvilRpcUrl: anvil?.rpcUrl ?? null, evmChainId: anvil?.chainId ?? null, forwarding: !values['no-forwarder'] }));
} catch (error) {
    console.error(error);
    await shutdown(1);
}
