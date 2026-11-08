// Test-only: Circle CCTP V2 on a local validator with real mainnet bytecode
// and state. Only MessageTransmitter.enabled_attesters is replaced (same
// vector length, threshold unchanged) by fresh local secp256k1 keys so
// iris-sim can attest; variants pause MT or TokenMinter, and denylist
// entries are preloaded DenylistedAccount PDAs. Layouts: local://cctp-facts.md.
import { mkdir, readFile, writeFile, open } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { resolve, join, dirname } from 'node:path';
import { homedir } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { spawn } from 'node:child_process';
import { parseArgs } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';
import { Connection, Keypair, PublicKey } from '@solana/web3.js';
import { keccak_256 } from '@noble/hashes/sha3';
import { secp256k1 } from '@noble/curves/secp256k1';
import { EVM_CCTP, MESSAGE_TRANSMITTER_V2, TOKEN_MESSENGER_MINTER_V2, cctpAccounts, denylistAccount, remoteTokenMessenger, tokenPair }
    from '../../../sdk/services/zkapiCctp.mjs';
import { ASSOCIATED_TOKEN_PROGRAM_ID, TOKEN_PROGRAM_ID, USDC_MINT } from '../../../sdk/services/zkapiUsdc.mjs';
import { confirmSignature } from './solana-tx.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const PROGRAMS_PATH = join(here, 'programs.json');
const UPGRADEABLE_LOADER = 'BPFLoaderUpgradeab1e11111111111111111111111';
const BPF_LOADER_2 = 'BPFLoader2111111111111111111111111111111111';
export const CCTP_VARIANTS = Object.freeze(['normal', 'mt-paused', 'minter-paused']);
/** Source domains whose RemoteTokenMessenger and TokenPair are cloned, with their remote USDC. */
export const CCTP_REMOTE_USDC = Object.freeze({ 0: EVM_CCTP.ethereum.usdc, 2: EVM_CCTP.optimism.usdc, 3: EVM_CCTP.arbitrum.usdc, 6: EVM_CCTP.base.usdc });
const MT_DISCRIMINATOR = Buffer.from([71, 40, 180, 142, 19, 203, 35, 252]);
const TOKEN_MESSENGER_DISCRIMINATOR = Buffer.from([162, 4, 242, 52, 147, 243, 221, 96]);
const TOKEN_MINTER_DISCRIMINATOR = Buffer.from([122, 133, 84, 63, 57, 159, 171, 206]);
const DENYLISTED_DISCRIMINATOR = Buffer.from([186, 58, 212, 239, 102, 131, 157, 146]);
// MessageTransmitter: paused u8 @136, signature_threshold u32 @145, enabled_attesters len u32 @149, entries @153.
const MT_PAUSED = 136; const MT_THRESHOLD = 145; const MT_ATTESTERS = 149;
const TOKEN_MINTER_PAUSED = 72;
const TOKEN_MESSENGER_FEE_RECIPIENT = 109;
const rentExempt = bytes => (bytes + 128) * 3480 * 2;

export async function rpc(url, method, params) {
    const response = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }), signal: AbortSignal.timeout(30_000) });
    if (!response.ok) throw new Error(`${method}: HTTP ${response.status}`);
    const body = await response.json();
    if (body.error) throw new Error(`${method}: ${JSON.stringify(body.error)}`);
    return body.result;
}

async function accountInfo(url, address) {
    const value = (await rpc(url, 'getAccountInfo', [address.toString(), { encoding: 'base64', commitment: 'confirmed' }])).value;
    if (!value) throw new Error(`account ${address} is absent on ${url}`);
    return { ...value, data: Buffer.from(value.data[0], 'base64') };
}

async function writeAccountFixture(runDir, address, { lamports, data, owner }) {
    const path = join(runDir, `${address.toBase58()}.json`);
    await writeFile(path, JSON.stringify({ pubkey: address.toBase58(), account: {
        lamports, data: [data.toString('base64'), 'base64'], owner: owner.toString(), executable: false, rentEpoch: 0 } }));
    return ['--account', address.toBase58(), path];
}

/** EVM address (0x, lowercase) of a secp256k1 private key. */
export function attesterAddress(privateKey) {
    const point = secp256k1.getPublicKey(Buffer.from(privateKey.replace(/^0x/, ''), 'hex'), false);
    return `0x${Buffer.from(keccak_256(point.subarray(1))).subarray(12).toString('hex')}`;
}

/** `count` fresh local attester keys, ascending by address (CCTP's required signature order). */
export function generateTestAttesters(count) {
    return Array.from({ length: count }, () => {
        const privateKey = `0x${Buffer.from(secp256k1.utils.randomPrivateKey()).toString('hex')}`;
        return { privateKey, address: attesterAddress(privateKey) };
    }).sort((a, b) => (a.address < b.address ? -1 : 1));
}

function executableHash(programData) {
    let end = programData.length;
    while (end > 45 && programData[end - 1] === 0) end--;
    return createHash('sha256').update(programData.subarray(45, end)).digest('hex');
}

async function loadPins() {
    return JSON.parse(await readFile(PROGRAMS_PATH, 'utf8'));
}

/** Compares the CCTP executables at `rpcUrl` with the pins in programs.json. */
export async function verifyCctpPrograms(rpcUrl) {
    const pins = await loadPins();
    for (const pin of pins.programs) {
        const program = await accountInfo(rpcUrl, pin.program_id);
        if (!program.executable || program.owner !== UPGRADEABLE_LOADER) throw new Error(`${pin.name} at ${rpcUrl} is not an upgradeable program`);
        const programData = await accountInfo(rpcUrl, pin.programdata);
        const hash = executableHash(programData.data);
        if (hash !== pin.executable_sha256) {
            throw new Error(`${pin.name} executable hash ${hash} differs from pinned ${pin.executable_sha256}; Circle upgraded it? Review, then re-pin: node scripts/localnet/cctp/validator.mjs --pin`);
        }
    }
    return pins.programs.map(pin => ({ name: pin.name, executable_sha256: pin.executable_sha256 }));
}

/** Rewrites programs.json from mainnet's current CCTP executables. */
export async function pinCctpPrograms(mainnetUrl) {
    const pins = await loadPins();
    for (const pin of pins.programs) pin.executable_sha256 = executableHash((await accountInfo(mainnetUrl, pin.programdata)).data);
    await writeFile(PROGRAMS_PATH, `${JSON.stringify(pins, null, 2)}\n`);
    return pins;
}

/** Clone flags for programs, whichever loader mainnet uses (as stack.mjs does for Token/ATA). */
async function programClones(mainnetUrl, programs) {
    const flags = [];
    for (const address of programs) {
        const account = (await rpc(mainnetUrl, 'getAccountInfo', [address, { encoding: 'base64', dataSlice: { offset: 0, length: 0 } }])).value;
        if (!account?.executable) throw new Error(`mainnet program ${address} is absent or not executable`);
        if (account.owner === UPGRADEABLE_LOADER) flags.push('--clone-upgradeable-program', address);
        else if (account.owner === BPF_LOADER_2) flags.push('--clone', address);
        else throw new Error(`mainnet program ${address} has unsupported loader ${account.owner}`);
    }
    return flags;
}

function normalizeOptions({ variant = 'normal', denylist = [], domains = Object.keys(CCTP_REMOTE_USDC).map(Number) } = {}) {
    if (!CCTP_VARIANTS.includes(variant)) throw new Error(`CCTP variant must be one of ${CCTP_VARIANTS.join(', ')}`);
    for (const domain of domains) if (!CCTP_REMOTE_USDC[domain]) throw new Error(`no remote USDC known for CCTP domain ${domain}`);
    return { variant, denylist: denylist.map(key => new PublicKey(key)), domains };
}

/**
 * solana-test-validator flags adding CCTP V2 (requires `--url mainnet`).
 * Writes the attester keys to `runDir/cctp-attesters.json` (0600).
 */
export async function cctpValidatorFixtures({ runDir, mainnetUrl, cctp = {} }) {
    const { variant, denylist, domains } = normalizeOptions(cctp);
    const accounts = cctpAccounts(USDC_MINT);
    const flags = [...await programClones(mainnetUrl, [MESSAGE_TRANSMITTER_V2, TOKEN_MESSENGER_MINTER_V2])];

    const mt = await accountInfo(mainnetUrl, accounts.messageTransmitter);
    if (mt.owner !== MESSAGE_TRANSMITTER_V2 || !mt.data.subarray(0, 8).equals(MT_DISCRIMINATOR)) throw new Error('mainnet MessageTransmitter state has an unexpected owner or discriminator');
    const attesterCount = mt.data.readUInt32LE(MT_ATTESTERS);
    const threshold = mt.data.readUInt32LE(MT_THRESHOLD);
    if (mt.data.length !== MT_ATTESTERS + 4 + 32 * attesterCount + 8 || threshold === 0 || threshold > attesterCount) throw new Error('mainnet MessageTransmitter layout changed; update the CCTP harness');
    const attesters = generateTestAttesters(attesterCount);
    const mtData = Buffer.from(mt.data);
    attesters.forEach(({ address }, index) => {
        const entry = MT_ATTESTERS + 4 + 32 * index;
        mtData.fill(0, entry, entry + 12);
        Buffer.from(address.slice(2), 'hex').copy(mtData, entry + 12);
    });
    if (variant === 'mt-paused') mtData[MT_PAUSED] = 1;
    flags.push(...await writeAccountFixture(runDir, accounts.messageTransmitter, { lamports: mt.lamports, data: mtData, owner: mt.owner }));

    const tokenMinter = await accountInfo(mainnetUrl, accounts.tokenMinter);
    if (!tokenMinter.data.subarray(0, 8).equals(TOKEN_MINTER_DISCRIMINATOR)) throw new Error('mainnet TokenMinter has an unexpected discriminator');
    if (variant === 'minter-paused') {
        const data = Buffer.from(tokenMinter.data);
        data[TOKEN_MINTER_PAUSED] = 1;
        flags.push(...await writeAccountFixture(runDir, accounts.tokenMinter, { lamports: tokenMinter.lamports, data, owner: tokenMinter.owner }));
    } else {
        flags.push('--clone', accounts.tokenMinter.toBase58());
    }

    const tokenMessenger = await accountInfo(mainnetUrl, accounts.tokenMessenger);
    if (!tokenMessenger.data.subarray(0, 8).equals(TOKEN_MESSENGER_DISCRIMINATOR)) throw new Error('mainnet TokenMessenger has an unexpected discriminator');
    const feeRecipient = new PublicKey(tokenMessenger.data.subarray(TOKEN_MESSENGER_FEE_RECIPIENT, TOKEN_MESSENGER_FEE_RECIPIENT + 32));
    const feeRecipientTokenAccount = PublicKey.findProgramAddressSync([feeRecipient.toBytes(), new PublicKey(TOKEN_PROGRAM_ID).toBytes(), accounts.mint.toBytes()],
        new PublicKey(ASSOCIATED_TOKEN_PROGRAM_ID))[0];
    for (const address of [accounts.tokenMessenger, accounts.localToken, accounts.custody, feeRecipientTokenAccount,
        ...domains.flatMap(domain => [remoteTokenMessenger(domain), tokenPair(domain, CCTP_REMOTE_USDC[domain])])]) {
        flags.push('--clone', address.toBase58());
    }
    for (const owner of denylist) {
        const data = Buffer.concat([DENYLISTED_DISCRIMINATOR, owner.toBuffer()]);
        flags.push(...await writeAccountFixture(runDir, denylistAccount(owner), { lamports: rentExempt(data.length), data, owner: TOKEN_MESSENGER_MINTER_V2 }));
    }

    const attestersPath = join(runDir, 'cctp-attesters.json');
    await writeFile(attestersPath, JSON.stringify({ threshold, attesters }, null, 2), { mode: 0o600 });
    return {
        flags,
        info: { variant, denylist: denylist.map(key => key.toBase58()), domains, threshold, attestersPath,
            attesters: attesters.map(attester => attester.address), feeRecipientTokenAccount: feeRecipientTokenAccount.toBase58() }
    };
}

/** Reads `cctp-attesters.json` written by cctpValidatorFixtures. */
export async function readTestAttesters(path) {
    const { threshold, attesters } = JSON.parse(await readFile(path, 'utf8'));
    return { threshold, attesters };
}

/**
 * A standalone test validator with mainnet USDC, Token, ATA and CCTP V2 (no
 * vault). Used by the CCTP golden test and harness.mjs; the full zkAPI
 * stack takes the same fixtures via startLocalStack({ cctp }).
 */
export async function startCctpLocalnet({ runDir, rpcPort = 18899, mainnetUrl = process.env.MAINNET_RPC_URL ?? 'https://api.mainnet-beta.solana.com',
    cctp = {}, log = console.log, signal, validatorPath = process.env.DAGON_SOLANA_TEST_VALIDATOR
        ?? join(process.env.XDG_DATA_HOME ?? join(homedir(), '.local/share'), 'dagon-zkapi/agave-v4.4.1/solana-release/bin/solana-test-validator') }) {
    if (!runDir) throw new Error('runDir is required (must be a new directory)');
    runDir = resolve(runDir);
    await mkdir(runDir, { recursive: true });
    await (await open(join(runDir, 'cctp.lock'), 'wx')).close();
    const rpcUrl = `http://127.0.0.1:${rpcPort}`;
    const payer = Keypair.generate();
    const payerKeypairPath = join(runDir, 'payer.json');
    await writeFile(payerKeypairPath, JSON.stringify([...payer.secretKey]), { mode: 0o600 });
    const fixtures = await cctpValidatorFixtures({ runDir, mainnetUrl, cctp });
    const args = ['--ledger', join(runDir, 'ledger'), '--rpc-port', String(rpcPort), '--faucet-port', String(rpcPort + 101), '--gossip-port', String(rpcPort + 102),
        '--dynamic-port-range', `${rpcPort + 110}-${rpcPort + 140}`, '--bind-address', '127.0.0.1', '--url', mainnetUrl, '--clone-feature-set',
        '--limit-ledger-size', '50000000',
        '--clone', USDC_MINT, ...await programClones(mainnetUrl, [TOKEN_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID]),
        ...fixtures.flags, '--log'];
    const validatorLog = await open(join(runDir, 'validator.log'), 'a');
    let failed; let stopped = false; let stopTask;
    const validator = spawn(validatorPath, args, { cwd: runDir, stdio: ['ignore', validatorLog.fd, validatorLog.fd] });
    const running = () => validator.exitCode === null && validator.signalCode === null;
    const kill = () => { stopped = true; if (running()) validator.kill('SIGKILL'); };
    process.on('exit', kill);
    validator.on('error', error => { failed = error; });
    validator.on('exit', code => { if (!stopped) failed = new Error(`validator exited ${code}; see ${join(runDir, 'validator.log')}`); });
    function stop() {
        stopTask ??= (async () => {
            stopped = true;
            if (running()) {
                const exited = new Promise(done => validator.once('exit', done));
                validator.kill('SIGTERM');
                const timer = setTimeout(() => validator.kill('SIGKILL'), 5000);
                await exited; clearTimeout(timer);
            }
            await validatorLog.close();
            process.removeListener('exit', kill);
        })();
        return stopTask;
    }
    try {
        let ready = false;
        for (let i = 0; i < 240 && !ready; i++) {
            if (failed) throw failed;
            signal?.throwIfAborted();
            try { await rpc(rpcUrl, 'getHealth', []); ready = true; } catch { await delay(500); }
        }
        if (!ready) throw new Error('local validator readiness deadline exceeded');
        const programs = await verifyCctpPrograms(rpcUrl);
        const connection = new Connection(rpcUrl, 'confirmed');
        await confirmSignature(connection, await connection.requestAirdrop(payer.publicKey, 100_000_000_000));
        log(`CCTP localnet ready at ${rpcUrl} (${fixtures.info.variant})`);
        return { rpcUrl, payer, payerKeypairPath, cctp: { ...fixtures.info, programs }, stop };
    } catch (error) { await stop(); throw error; }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
    const { values } = parseArgs({ options: { pin: { type: 'boolean' } } });
    const mainnetUrl = process.env.MAINNET_RPC_URL ?? 'https://api.mainnet-beta.solana.com';
    if (!values.pin) throw new Error('usage: node scripts/localnet/cctp/validator.mjs --pin   (start the harness with harness.mjs)');
    const pins = await pinCctpPrograms(mainnetUrl);
    console.log(JSON.stringify(pins.programs, null, 2));
}
