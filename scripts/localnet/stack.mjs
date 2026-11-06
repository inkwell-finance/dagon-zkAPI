import { mkdir, readFile, writeFile, open } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { homedir } from 'node:os';
import { createServer } from 'node:net';
import { randomBytes } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { spawn, execFile } from 'node:child_process';
import { promisify, parseArgs } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';
import { Connection, Keypair, PublicKey, SystemProgram, Transaction, sendAndConfirmTransaction } from '@solana/web3.js';
import { checkParity } from '../check-solana-parity.mjs';
import { latestPlan, startHermesReplay, priceFreshness, rpc, RECEIVER, PUSH, WORMHOLE } from './pyth-replay.mjs';
const exec = promisify(execFile);
const defaultRoot = resolve(fileURLToPath(new URL('../..', import.meta.url)));

async function freePort() {
  const server = createServer();
  await new Promise((done, fail) => { server.once('error', fail); server.listen(0, '127.0.0.1', done); });
  const { port } = server.address();
  await new Promise(done => server.close(done));
  return port;
}

// The receiver pays its update fee into treasury PDA `["treasury", [id]]`;
// the pusher picks the id at random per push, like Pyth's SDK. Mainnet has all
// 256 funded. Local funding only (lamports, no data): rent-exempt balances.
async function fundReceiverTreasuries(connection, payer) {
  const receiver = new PublicKey(RECEIVER);
  const treasuries = Array.from({ length: 256 }, (_, id) => PublicKey.findProgramAddressSync([Buffer.from('treasury'), Buffer.from([id])], receiver)[0]);
  const lamports = await connection.getMinimumBalanceForRentExemption(0);
  for (let i = 0; i < treasuries.length; i += 20) {
    const tx = new Transaction().add(...treasuries.slice(i, i + 20).map(toPubkey => SystemProgram.transfer({ fromPubkey: payer.publicKey, toPubkey, lamports })));
    await sendAndConfirmTransaction(connection, tx, [payer], { commitment: 'confirmed' });
  }
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
    const path = join(runDir, `${address.toBase58()}.json`);
    // Agave 3.1.11 genesis Rent::default(): 3480 lamports/byte-year,
    // exemption threshold 2, and 128 bytes of account-storage overhead.
    await writeFile(path, JSON.stringify({ pubkey: address.toBase58(), account: {
      lamports: (data.length + 128) * 3480 * 2, data: [data.toString('base64'), 'base64'],
      owner: loader.toBase58(), executable: executableAccount, rentEpoch: 0,
    } }));
    flags.push('--account', address.toBase58(), path);
  }
  return flags;
}

export async function startLocalStack({ root = defaultRoot, runDir, binDir = join(root, 'target/release'), log = console.log, rpcPort = 8899, signal }) {
  if (!runDir) throw new Error('runDir is required (must be a new directory)');
  if (!process.env.ZKAPI_STATE_SEED || !process.env.ZKAPI_CLEAR_SEED) throw new Error('set ZKAPI_STATE_SEED and ZKAPI_CLEAR_SEED; use the same seeds for serverd');
  root = resolve(root); runDir = resolve(runDir); binDir = resolve(binDir);
  await mkdir(runDir, { recursive: true });
  const lock = await open(join(runDir, 'stack.lock'), 'wx');
  await lock.close();
  const profile = JSON.parse(await readFile(join(root, 'solana/profile/shared.json'), 'utf8'));
  const mainnetIdentity = JSON.parse(await readFile(join(root, 'solana/profile/mainnet-beta.identity.json'), 'utf8'));
  const priceAccount = new PublicKey(mainnetIdentity.pyth_price_account).toBase58();
  const binary = join(binDir, 'dagon-zkapi-deploy');
  const mainnetUrl = process.env.MAINNET_RPC_URL ?? 'https://api.mainnet-beta.solana.com';
  const rpcUrl = `http://127.0.0.1:${rpcPort}`;
  const authority = Keypair.generate(); const payer = Keypair.generate(); const pusherPayer = Keypair.generate(); const treasury = Keypair.generate().publicKey.toBase58();
  const authorityKeypairPath = join(runDir, 'authority.json'); const payerKeypairPath = join(runDir, 'payer.json'); const identityPath = join(runDir, 'localnet.identity.json');
  const pusherKeypairPath = join(runDir, 'pyth-pusher-payer.json');
  await writeFile(authorityKeypairPath, JSON.stringify([...authority.secretKey]), { mode: 0o600 });
  await writeFile(payerKeypairPath, JSON.stringify([...payer.secretKey]), { mode: 0o600 });
  await writeFile(pusherKeypairPath, JSON.stringify([...pusherPayer.secretKey]), { mode: 0o600 });
  // The recorded Hermes demands a Bearer key exactly like Hermes; the pusher
  // reads it from PYTH_HERMES_API_KEY as in production.
  const hermesApiKey = randomBytes(24).toString('hex');
  const abort = new AbortController();
  let validator; let pusher; let hermes; let stopTask; let stopped = false; let failed; let clonedPublishTime;
  const validatorLog = await open(join(runDir, 'validator.log'), 'a');
  const pusherLog = await open(join(runDir, 'pyth-pusher.log'), 'a');
  const running = child => child?.exitCode === null && child.signalCode === null;
  // exit cannot await stop(). Kill synchronously on fatal errors/forced CLI
  // exit too, so an interrupted cleanup cannot leave a child behind.
  function terminateValidator() {
    stopped = true;
    abort.abort();
    for (const child of [pusher, validator]) if (running(child)) child.kill('SIGKILL');
  }
  async function terminate(child) {
    if (!running(child)) return;
    const exited = new Promise(done => child.once('exit', done));
    child.kill('SIGTERM');
    const kill = setTimeout(() => child.kill('SIGKILL'), 5000);
    await exited; clearTimeout(kill);
  }
  function stop() {
    if (stopTask) return stopTask;
    stopped = true;
    abort.abort();
    stopTask = (async () => {
      await terminate(pusher);
      await terminate(validator);
      await hermes?.stop();
      await pusherLog.close();
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
  // Timing only: never extend max_age or manufacture an oracle quote. Call
  // before server startup and before quote -> prove -> lease work. The return
  // value describes the finalized account; obtain the billing quote from serverd.
  // Only an update newer than the cloned account counts: the local account has
  // no writer but the operator pusher, so freshness always relies on it.
  async function awaitFreshQuote({ minRemainingSeconds = 5, timeoutMs = 180_000 } = {}) {
    if (!Number.isFinite(minRemainingSeconds) || minRemainingSeconds < 0 || minRemainingSeconds >= profile.pyth.max_age_seconds) throw new Error('invalid fresh-window duration');
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (failed) throw failed;
      if (stopped) throw new Error('local stack is stopped');
      const quote = await priceFreshness(rpcUrl, priceAccount);
      if (quote.finalized && quote.publishTime > clonedPublishTime && quote.age >= 0 && quote.age < profile.pyth.max_age_seconds - minRemainingSeconds) return quote;
      await delay(500, undefined, { signal: abort.signal });
    }
    throw new Error('the Pyth pusher did not produce the requested fresh finalized window');
  }
  try {
    signal?.throwIfAborted();
    await exec(process.execPath, [join(root, 'scripts/localnet/executable-hash.mjs'), join(root, 'target/deploy/dagon_zkapi_vault.so'), join(root, 'solana/profile/shared.json'), '--check']);
    let plan;
    const seen = new Set();
    const discoveryDeadline = Date.now() + 180_000;
    while (!plan && Date.now() < discoveryDeadline) { plan = await latestPlan(mainnetUrl, priceAccount, seen, abort.signal); if (!plan) await delay(2000); }
    if (!plan) throw new Error('no self-contained, fully verified mainnet SOL/USD update found');
    hermes = await startHermesReplay({ mainnetUrl, priceAccount, apiKey: hermesApiKey, initialPlan: plan, log, signal: abort.signal });
    const bridge = PublicKey.findProgramAddressSync([Buffer.from('Bridge')], new PublicKey(WORMHOLE))[0].toBase58();
    const args = ['--ledger', join(runDir, 'ledger'), '--rpc-port', String(rpcPort), '--faucet-port', String(rpcPort + 101), '--gossip-port', String(rpcPort + 102), '--bind-address', '127.0.0.1', '--url', mainnetUrl,
      '--clone-feature-set',
      ...await immutableProgramAccounts(root, runDir, profile),
      '--clone-upgradeable-program', RECEIVER, '--clone-upgradeable-program', PUSH, '--clone-upgradeable-program', WORMHOLE,
      ...[plan.config, plan.guardian, bridge, priceAccount].flatMap(a => ['--clone', a]), '--log'];
    const validatorPath = process.env.DAGON_SOLANA_TEST_VALIDATOR ?? join(process.env.XDG_DATA_HOME ?? join(homedir(), '.local/share'), 'dagon-zkapi/agave-v4.4.1/solana-release/bin/solana-test-validator');
    abort.signal.throwIfAborted();
    validator = spawn(validatorPath, args, { cwd: runDir, stdio: ['ignore', validatorLog.fd, validatorLog.fd] });
    validator.on('error', e => { failed = e; });
    validator.on('exit', (code, signal) => { if (!stopped) { failed = new Error(`validator exited ${code ?? signal}; see ${join(runDir, 'validator.log')}`); abort.abort(); } });
    let ready = false;
    for (let i = 0; i < 180; i++) {
      if (failed) throw failed;
      try { await rpc(rpcUrl, 'getHealth', []); ready = true; break; } catch { await delay(500); }
    }
    if (!ready) throw new Error('local validator readiness deadline exceeded');
    clonedPublishTime = (await priceFreshness(rpcUrl, priceAccount)).publishTime;
    const connection = new Connection(rpcUrl, 'confirmed');
    for (const key of [authority.publicKey, payer.publicKey, pusherPayer.publicKey]) {
      const signature = await connection.requestAirdrop(key, 50_000_000_000);
      await connection.confirmTransaction(signature, 'finalized');
    }
    await fundReceiverTreasuries(connection, payer);
    await exec(binary, ['identity', '--network', 'localnet', '--solana-rpc-url', rpcUrl, '--vault-authority', authority.publicKey.toBase58(), '--treasury', treasury, '--pyth-price-account', priceAccount, '--out', identityPath]);
    // The operator pusher binary, exactly as deployed: Hermes (recorded) ->
    // Wormhole guardian verification -> push oracle -> the pinned account.
    const pusherMetricsUrl = `http://127.0.0.1:${await freePort()}`;
    pusher = spawn(join(binDir, 'dagon-zkapi-pyth-pusher'), ['--solana-identity', identityPath, '--solana-rpc-url', rpcUrl,
      '--payer-keypair', pusherKeypairPath, '--hermes-url', hermes.url, '--listen', new URL(pusherMetricsUrl).host],
    { cwd: runDir, env: { ...process.env, PYTH_HERMES_API_KEY: hermesApiKey, RUST_LOG: process.env.RUST_LOG ?? 'info' }, stdio: ['ignore', pusherLog.fd, pusherLog.fd] });
    pusher.on('error', e => { failed = e; });
    pusher.on('exit', (code, signal) => {
      if (!stopped) { failed = new Error(`Pyth pusher exited ${code ?? signal}; see ${join(runDir, 'pyth-pusher.log')}`); log(failed.message); terminateValidator(); }
    });
    const initialized = await exec(binary, ['init-vault', '--solana-identity', identityPath, '--solana-rpc-url', rpcUrl, '--authority-keypair', authorityKeypairPath]);
    log(initialized.stdout.trim());
    await checkParity({ identityPath, rpcUrl, binDir, mainnetRpcUrl: mainnetUrl, log });
    // Initialization and parity can take a finalization window. Only return
    // after a pushed update is finalized after that work, never a stale clone.
    await awaitFreshQuote();
    if (failed) throw failed;
    const identity = JSON.parse(await readFile(identityPath, 'utf8'));
    return { rpcUrl, identityPath, identity, authorityKeypairPath, payerKeypairPath, treasury, pusherMetricsUrl, awaitFreshQuote, stop };
  } catch (error) { await stop(); throw error; }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const { values } = parseArgs({ options: { 'run-dir': { type: 'string' }, 'bin-dir': { type: 'string' }, 'rpc-port': { type: 'string' } } });
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
    stack = await startLocalStack({ runDir: values['run-dir'], binDir: values['bin-dir'], rpcPort: values['rpc-port'] ? Number(values['rpc-port']) : undefined, signal: controller.signal });
    if (shuttingDown) { await stack.stop(); process.exit(0); }
    console.log(JSON.stringify({ rpcUrl: stack.rpcUrl, identityPath: stack.identityPath, authorityKeypairPath: stack.authorityKeypairPath, payerKeypairPath: stack.payerKeypairPath, treasury: stack.treasury, pusherMetricsUrl: stack.pusherMetricsUrl }));
  } catch (error) {
    if (!shuttingDown) console.error(error);
    process.exit(shuttingDown ? 0 : 1);
  }
}
