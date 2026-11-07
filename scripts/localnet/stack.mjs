import { mkdir, readFile, writeFile, open, access } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { homedir } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { spawn, execFile } from 'node:child_process';
import { promisify, parseArgs } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';
import { Connection, Keypair, PublicKey, SystemProgram, Transaction, TransactionInstruction, sendAndConfirmTransaction } from '@solana/web3.js';
import { checkParity } from '../check-solana-parity.mjs';
const exec = promisify(execFile);
const defaultRoot = resolve(fileURLToPath(new URL('../..', import.meta.url)));

/** Fixed local id of the test-only PDA signer (`solana/test-programs/pda-signer`). */
export const PDA_SIGNER_PROGRAM_ID = 'FrGKWj9gdt9d7VcjWN6zucZxYgYqyRDeGXdCWeQybr3u';
const PDA_SIGNER_SO = 'target/deploy-test/dagon_zkapi_test_pda_signer.so';
const BPF_LOADER_2 = 'BPFLoader2111111111111111111111111111111111';
// Faucet balance: 1,000,000 USDC in base units (fabricated local state).
const FAUCET_BALANCE = 1_000_000_000_000n;

// Agave genesis Rent::default(): 3480 lamports/byte-year, exemption
// threshold 2, and 128 bytes of account-storage overhead.
const rentExempt = bytes => (bytes + 128) * 3480 * 2;

async function rpc(url, method, params) {
  const response = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }), signal: AbortSignal.timeout(30_000) });
  if (!response.ok) throw new Error(`${method}: HTTP ${response.status}`);
  const body = await response.json();
  if (body.error) throw new Error(`${method}: ${JSON.stringify(body.error)}`);
  return body.result;
}

async function writeAccountFixture(runDir, address, { lamports, data, owner, executable = false }) {
  const path = join(runDir, `${address.toBase58()}.json`);
  await writeFile(path, JSON.stringify({ pubkey: address.toBase58(), account: {
    lamports, data: [data.toString('base64'), 'base64'], owner: owner.toBase58(), executable, rentEpoch: 0,
  } }));
  return ['--account', address.toBase58(), path];
}

async function immutableProgramAccounts(root, runDir, profile) {
  // Agave 3.1.11's --upgradeable-program ... none is NOT Option::None:
  // validator/src/bin/solana-test-validator.rs maps it to Pubkey::default(),
  // and test-validator/src/lib.rs serializes Some(default). Preload the real
  // deploy + set-upgrade-authority --final end state instead; all deployment
  // and parity gates still require actual None, the declared ID and exact hash.
  const program = new PublicKey(profile.program.program_id);
  const loader = new PublicKey(profile.program.loader);
  const programData = PublicKey.findProgramAddressSync([program.toBuffer()], loader)[0];
  const programBytes = Buffer.alloc(36);
  programBytes.writeUInt32LE(2);
  programData.toBuffer().copy(programBytes, 4);
  const executable = await readFile(join(root, 'target/deploy/dagon_zkapi_vault.so'));
  const dataBytes = Buffer.alloc(45 + executable.length);
  dataBytes.writeUInt32LE(3); // ProgramData { slot: 0, upgrade_authority: None }.
  executable.copy(dataBytes, 45);
  const flags = [];
  for (const [address, data, executableAccount] of [[program, programBytes, true], [programData, dataBytes, false]]) {
    flags.push(...await writeAccountFixture(runDir, address, { lamports: rentExempt(data.length), data, owner: loader, executable: executableAccount }));
  }
  return flags;
}

export function usdcAssociatedTokenAddress(profile, owner) {
  const { token_program: token, mint, associated_token_program: ata } = profile.asset;
  return PublicKey.findProgramAddressSync([owner.toBuffer(), new PublicKey(token).toBuffer(), new PublicKey(mint).toBuffer()], new PublicKey(ata))[0];
}

/**
 * A classic-Token USDC account fixture at `owner`'s canonical ATA. Its balance
 * and state are fabricated local state; only the mint it names is mainnet's.
 */
async function usdcTokenAccountFixture(runDir, profile, owner, { amount, state }) {
  const address = usdcAssociatedTokenAddress(profile, owner);
  const data = Buffer.alloc(165);
  new PublicKey(profile.asset.mint).toBuffer().copy(data, 0);
  owner.toBuffer().copy(data, 32);
  data.writeBigUInt64LE(amount, 64);
  data[108] = state; // 1 = initialized, 2 = frozen; no delegate, not native, no close authority.
  return { address, flags: await writeAccountFixture(runDir, address, { lamports: rentExempt(165), data, owner: new PublicKey(profile.asset.token_program) }) };
}

/**
 * Clone flags that make the local Token and ATA programs mainnet's exact
 * executables, whichever loader mainnet currently uses for each (the parity
 * check then compares their executable hashes).
 */
async function mainnetProgramClones(mainnetUrl, programs) {
  const flags = [];
  for (const address of programs) {
    const account = (await rpc(mainnetUrl, 'getAccountInfo', [address, { encoding: 'base64', dataSlice: { offset: 0, length: 0 } }])).value;
    if (!account?.executable) throw new Error(`mainnet program ${address} is absent or not executable`);
    if (account.owner === 'BPFLoaderUpgradeab1e11111111111111111111111') flags.push('--clone-upgradeable-program', address);
    else if (account.owner === BPF_LOADER_2) flags.push('--clone', address);
    else throw new Error(`mainnet program ${address} has unsupported loader ${account.owner}`);
  }
  return flags;
}

async function writeKeypair(path, keypair) {
  await writeFile(path, JSON.stringify([...keypair.secretKey]), { mode: 0o600 });
  return path;
}

async function ensurePdaSigner(root, log) {
  const path = join(root, PDA_SIGNER_SO);
  try { await access(path); } catch {
    log(`building ${PDA_SIGNER_SO}`);
    await exec('bash', [join(root, 'scripts/localnet/build-test-programs.sh')], { cwd: root, maxBuffer: 64 * 1024 * 1024 });
  }
  return path;
}

/**
 * Seconds to add to the validator's wall clock so that, at `now`, it reads
 * `secondsBefore` seconds before a UTC midnight: the next one, or the one
 * after when the next is less than `secondsBefore` away (the shim only moves
 * the clock forward). The chain clock then advances in real time from there.
 */
export function clockOffsetBeforeUtcMidnight(secondsBefore, now = Date.now()) {
  if (!Number.isInteger(secondsBefore) || secondsBefore < 0 || secondsBefore >= 86_400) throw new Error('seconds before UTC midnight must be an integer in 0..86399');
  const nowSeconds = Math.floor(now / 1000);
  const midnight = (Math.floor(nowSeconds / 86_400) + 1) * 86_400;
  const offset = midnight - secondsBefore - nowSeconds;
  return offset >= 0 ? offset : offset + 86_400;
}

/**
 * Test-only: build the LD_PRELOAD shim (`clock-offset.c`) that shifts the
 * validator's CLOCK_REALTIME, and so its Clock sysvar from genesis on, by
 * `clockOffsetSeconds`. Never used by a deployment; parity is unaffected.
 */
async function clockOffsetEnv(root, runDir, clockOffsetSeconds) {
  if (!Number.isSafeInteger(clockOffsetSeconds) || clockOffsetSeconds < 0) throw new Error('clockOffsetSeconds must be a nonnegative integer');
  if (clockOffsetSeconds === 0) return process.env;
  const shim = join(runDir, 'clock-offset.so');
  await exec('gcc', ['-shared', '-fPIC', '-O2', '-o', shim, join(root, 'scripts/localnet/clock-offset.c')]);
  return { ...process.env, LD_PRELOAD: shim, DAGON_CLOCK_OFFSET_SECONDS: String(clockOffsetSeconds) };
}

export async function startLocalStack({ root = defaultRoot, runDir, binDir = join(root, 'target/release'), log = console.log, rpcPort = 8899, clockOffsetSeconds = 0, signal }) {
  if (!runDir) throw new Error('runDir is required (must be a new directory)');
  if (!process.env.ZKAPI_STATE_SEED || !process.env.ZKAPI_CLEAR_SEED) throw new Error('set ZKAPI_STATE_SEED and ZKAPI_CLEAR_SEED; use the same seeds for serverd');
  root = resolve(root); runDir = resolve(runDir); binDir = resolve(binDir);
  await mkdir(runDir, { recursive: true });
  const lock = await open(join(runDir, 'stack.lock'), 'wx');
  await lock.close();
  const profile = JSON.parse(await readFile(join(root, 'solana/profile/shared.json'), 'utf8'));
  const binary = join(binDir, 'dagon-zkapi-deploy');
  const mainnetUrl = process.env.MAINNET_RPC_URL ?? 'https://api.mainnet-beta.solana.com';
  const rpcUrl = `http://127.0.0.1:${rpcPort}`;
  const authority = Keypair.generate(); const payer = Keypair.generate(); const treasuryOwner = Keypair.generate();
  const faucet = Keypair.generate(); const frozenOwner = Keypair.generate();
  const authorityKeypairPath = await writeKeypair(join(runDir, 'authority.json'), authority);
  const payerKeypairPath = await writeKeypair(join(runDir, 'payer.json'), payer);
  const usdcFaucetKeypairPath = await writeKeypair(join(runDir, 'usdc-faucet.json'), faucet);
  const frozenUsdcOwnerKeypairPath = await writeKeypair(join(runDir, 'frozen-usdc-owner.json'), frozenOwner);
  const identityPath = join(runDir, 'localnet.identity.json');
  const abort = new AbortController();
  let validator; let stopTask; let stopped = false; let failed;
  const validatorLog = await open(join(runDir, 'validator.log'), 'a');
  const running = child => child?.exitCode === null && child.signalCode === null;
  // exit cannot await stop(). Kill synchronously on fatal errors/forced CLI
  // exit too, so an interrupted cleanup cannot leave the validator behind.
  function terminateValidator() {
    stopped = true;
    abort.abort();
    if (running(validator)) validator.kill('SIGKILL');
  }
  function stop() {
    if (stopTask) return stopTask;
    stopped = true;
    abort.abort();
    stopTask = (async () => {
      if (running(validator)) {
        const exited = new Promise(done => validator.once('exit', done));
        validator.kill('SIGTERM');
        const kill = setTimeout(() => validator.kill('SIGKILL'), 5000);
        await exited; clearTimeout(kill);
      }
      await validatorLog.close();
    })().finally(() => {
      signal?.removeEventListener('abort', onAbort);
      process.removeListener('exit', terminateValidator);
      process.removeListener('uncaughtExceptionMonitor', terminateValidator);
    });
    return stopTask;
  }
  function onAbort() { void stop().catch(error => { failed = error; }); }
  process.on('exit', terminateValidator);
  process.on('uncaughtExceptionMonitor', terminateValidator);
  signal?.addEventListener('abort', onAbort, { once: true });
  try {
    signal?.throwIfAborted();
    await exec(process.execPath, [join(root, 'scripts/localnet/executable-hash.mjs'), join(root, 'target/deploy/dagon_zkapi_vault.so'), join(root, 'solana/profile/shared.json'), '--check']);
    const pdaSignerPath = await ensurePdaSigner(root, log);
    const faucetAccount = await usdcTokenAccountFixture(runDir, profile, faucet.publicKey, { amount: FAUCET_BALANCE, state: 1 });
    const frozenAccount = await usdcTokenAccountFixture(runDir, profile, frozenOwner.publicKey, { amount: 0n, state: 2 });
    const args = ['--ledger', join(runDir, 'ledger'), '--rpc-port', String(rpcPort), '--faucet-port', String(rpcPort + 101), '--gossip-port', String(rpcPort + 102), '--bind-address', '127.0.0.1', '--url', mainnetUrl,
      '--clone-feature-set',
      ...await immutableProgramAccounts(root, runDir, profile),
      // The real mainnet USDC mint, byte-identical at clone time.
      '--clone', profile.asset.mint,
      ...await mainnetProgramClones(mainnetUrl, [profile.asset.token_program, profile.asset.associated_token_program]),
      ...faucetAccount.flags, ...frozenAccount.flags,
      '--bpf-program', PDA_SIGNER_PROGRAM_ID, pdaSignerPath,
      '--log'];
    const validatorPath = process.env.DAGON_SOLANA_TEST_VALIDATOR ?? join(process.env.XDG_DATA_HOME ?? join(homedir(), '.local/share'), 'dagon-zkapi/agave-v4.4.1/solana-release/bin/solana-test-validator');
    const validatorEnv = await clockOffsetEnv(root, runDir, clockOffsetSeconds);
    abort.signal.throwIfAborted();
    validator = spawn(validatorPath, args, { cwd: runDir, env: validatorEnv, stdio: ['ignore', validatorLog.fd, validatorLog.fd] });
    validator.on('error', e => { failed = e; });
    validator.on('exit', (code, signal) => { if (!stopped) { failed = new Error(`validator exited ${code ?? signal}; see ${join(runDir, 'validator.log')}`); abort.abort(); } });
    let ready = false;
    for (let i = 0; i < 180; i++) {
      if (failed) throw failed;
      try { await rpc(rpcUrl, 'getHealth', []); ready = true; break; } catch { await delay(500, undefined, { signal: abort.signal }); }
    }
    if (!ready) throw new Error('local validator readiness deadline exceeded');
    const connection = new Connection(rpcUrl, 'confirmed');
    // Fee/rent SOL for every local signer; the faucet and frozen-account
    // owners sign their own USDC transfers and account creations in tests.
    for (const key of [authority.publicKey, payer.publicKey, faucet.publicKey, frozenOwner.publicKey]) {
      const signature = await connection.requestAirdrop(key, 50_000_000_000);
      await connection.confirmTransaction(signature, 'finalized');
    }
    // The treasury's canonical USDC ATA, created through the cloned ATA
    // program (CreateIdempotent) as any operator would on mainnet.
    const treasuryTokenAccount = usdcAssociatedTokenAddress(profile, treasuryOwner.publicKey);
    const createTreasury = new TransactionInstruction({ programId: new PublicKey(profile.asset.associated_token_program), data: Buffer.from([1]), keys: [
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },
      { pubkey: treasuryTokenAccount, isSigner: false, isWritable: true },
      { pubkey: treasuryOwner.publicKey, isSigner: false, isWritable: false },
      { pubkey: new PublicKey(profile.asset.mint), isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      { pubkey: new PublicKey(profile.asset.token_program), isSigner: false, isWritable: false },
    ] });
    await sendAndConfirmTransaction(connection, new Transaction().add(createTreasury), [payer], { commitment: 'finalized' });
    await exec(binary, ['identity', '--network', 'localnet', '--solana-rpc-url', rpcUrl, '--vault-authority', authority.publicKey.toBase58(), '--treasury-token-account', treasuryTokenAccount.toBase58(), '--out', identityPath]);
    const initialized = await exec(binary, ['init-vault', '--solana-identity', identityPath, '--solana-rpc-url', rpcUrl, '--authority-keypair', authorityKeypairPath]);
    log(initialized.stdout.trim());
    await checkParity({ identityPath, rpcUrl, binDir, mainnetRpcUrl: mainnetUrl, log });
    if (failed) throw failed;
    const identity = JSON.parse(await readFile(identityPath, 'utf8'));
    return { rpcUrl, identityPath, identity, authorityKeypairPath, payerKeypairPath, treasuryTokenAccount: treasuryTokenAccount.toBase58(),
      usdcFaucetKeypairPath, usdcFaucetTokenAccount: faucetAccount.address.toBase58(),
      frozenUsdcOwnerKeypairPath, frozenUsdcTokenAccount: frozenAccount.address.toBase58(),
      pdaSignerProgramId: PDA_SIGNER_PROGRAM_ID, clockOffsetSeconds, stop };
  } catch (error) { await stop(); throw error; }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const { values } = parseArgs({ options: { 'run-dir': { type: 'string' }, 'bin-dir': { type: 'string' }, 'rpc-port': { type: 'string' },
    'clock-offset-seconds': { type: 'string' }, 'clock-before-utc-midnight': { type: 'string' } } });
  const controller = new AbortController();
  let stack; let shuttingDown = false;
  function shutdown() {
    if (shuttingDown) return;
    shuttingDown = true;
    // web3.js may still be awaiting a subscription/RPC after cancellation.
    // Bound CLI shutdown; the synchronous exit hook kills any remaining child.
    setTimeout(() => process.exit(0), 8000);
    controller.abort();
    if (stack) void stack.stop().then(() => process.exit(0), error => { console.error(error); process.exit(1); });
  }
  // Install before startup, including when bash launched us asynchronously
  // with SIGINT inherited as SIG_IGN. Keep handlers for repeated signals.
  for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP']) process.on(signal, shutdown);
  try {
    if (values['clock-offset-seconds'] !== undefined && values['clock-before-utc-midnight'] !== undefined) throw new Error('use --clock-offset-seconds or --clock-before-utc-midnight, not both');
    const integer = (name, text) => { if (!/^\d+$/.test(text)) throw new Error(`--${name} must be a nonnegative integer`); return Number(text); };
    const clockOffsetSeconds = values['clock-before-utc-midnight'] !== undefined
      ? clockOffsetBeforeUtcMidnight(integer('clock-before-utc-midnight', values['clock-before-utc-midnight']))
      : values['clock-offset-seconds'] !== undefined ? integer('clock-offset-seconds', values['clock-offset-seconds']) : 0;
    stack = await startLocalStack({ runDir: values['run-dir'], binDir: values['bin-dir'], rpcPort: values['rpc-port'] ? Number(values['rpc-port']) : undefined, clockOffsetSeconds, signal: controller.signal });
    if (shuttingDown) { await stack.stop(); process.exit(0); }
    const { stop: _stop, ...fields } = stack;
    console.log(JSON.stringify(fields));
  } catch (error) {
    if (!shuttingDown) console.error(error);
    process.exit(shuttingDown ? 0 : 1);
  }
}
