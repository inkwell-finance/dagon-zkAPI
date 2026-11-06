// Real-program regressions for malicious Hermes, bounded paid failures and orphan recovery.
// Run after building: node scripts/localnet/pusher-security.mjs <new-run-directory>
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile, writeFile, mkdir, rm } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { resolve, join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { Connection, Keypair, PublicKey } from '@solana/web3.js';
import { startLocalStack } from './stack.mjs';
import { WORMHOLE } from './pyth-replay.mjs';

const root = resolve(new URL('../..', import.meta.url).pathname);
const runDir = process.argv[2] && resolve(process.argv[2]);
if (!runDir) throw new Error('usage: pusher-security.mjs <new-run-directory>');
await mkdir(runDir, { recursive: true });
const fixture = JSON.parse(await readFile(join(root, 'crates/dagon-zkapi-pyth-pusher/tests/fixtures/mainnet-sol-usd-update.json'), 'utf8'));
const payer = Keypair.generate();
const payerPath = join(runDir, 'adversarial-payer.json');
await writeFile(payerPath, JSON.stringify([...payer.secretKey]), { mode: 0o600 });
let authFailure = false;
let corruptSignature = true;
let child;
let log = '';
const server = createServer((request, response) => {
  if (authFailure) { response.writeHead(401); response.end('{}'); return; }
  assert.equal(request.headers.authorization, 'Bearer regression-secret');
  const binary = Buffer.from(fixture.hermes_response.binary.data[0], 'base64');
  // Corrupt a guardian signature; advertise a fresh message to force the
  // untrusted parser past the not-newer check. No guardian signed these bytes.
  if (corruptSignature) binary[17] ^= 1;
  const vaaLength = binary.readUInt16BE(8);
  const messageOffset = 10 + vaaLength + 1 + 2;
  binary.writeBigInt64BE(BigInt(Math.floor(Date.now() / 1000)), messageOffset + 53);
  response.setHeader('content-type', 'application/json');
  response.end(JSON.stringify({ binary: { encoding: 'base64', data: [binary.toString('base64')] } }));
});
await new Promise(done => server.listen(0, '127.0.0.1', done));
const hermesUrl = `http://127.0.0.1:${server.address().port}`;
async function waitFor(label, fn, timeout = 120_000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const result = await fn();
    if (result) return result;
    if (child && child.exitCode !== null) throw new Error(`pusher exited: ${log}`);
    await delay(250);
  }
  throw new Error(`${label} timed out: ${log}`);
}
async function stopPusher() {
  if (!child || child.exitCode !== null) return;
  const exited = once(child, 'exit');
  child.kill('SIGTERM');
  const timer = setTimeout(() => child.kill('SIGKILL'), 5000);
  await exited;
  clearTimeout(timer);
  child = undefined;
}
let stack;
try {
  stack = await startLocalStack({ root, runDir: join(runDir, 'stack'), rpcPort: 19999 });
  const connection = new Connection(stack.rpcUrl, 'confirmed');
  await connection.confirmTransaction(await connection.requestAirdrop(payer.publicKey, 3_000_000_000), 'finalized');
  const encoded = await PublicKey.createWithSeed(payer.publicKey, 'dagon-pyth-vaa', new PublicKey(WORMHOLE));
  // An attacker needs no signer to pre-fund the predictable seed address.
  await connection.confirmTransaction(await connection.requestAirdrop(encoded, 1_000_000), 'finalized');
  async function launch() {
    child = spawn(join(root, 'target/release/dagon-zkapi-pyth-pusher'), [
      '--solana-identity', stack.identityPath, '--solana-rpc-url', stack.rpcUrl,
      '--payer-keypair', payerPath, '--hermes-url', hermesUrl, '--listen', '127.0.0.1:0',
    ], { env: { ...process.env, PYTH_HERMES_API_KEY: 'regression-secret', RUST_LOG: 'info' }, stdio: ['ignore', 'pipe', 'pipe'] });
    log = '';
    child.stdout.on('data', data => { log += data.toString(); });
    child.stderr.on('data', data => { log += data.toString(); });
    return waitFor('metrics listener', async () => {
      const clean = log.replace(/\x1b\[[0-9;]*m/g, '');
      const port = clean.match(/listen=127\.0\.0\.1:(\d+)/)?.[1];
      return port && `http://127.0.0.1:${port}/metrics`;
    });
  }
  const metricsUrl = await launch();
  const metrics = () => fetch(metricsUrl).then(r => r.text());
  await waitFor('paid-failure circuit breaker', async () => (await metrics()).includes('dagon_pyth_pusher_payments_paused 1'));
  // Packet 2 has two compute-budget instructions followed by VerifyEncodedVaaV1.
  // Different signature corruptions may yield recovery or guardian-key errors;
  // the invariant is rejection by verification, before UpdatePriceFeed.
  assert.match(log, /payment simulation failed: \{"InstructionError":\[2,\{"Custom":(?:7800|10224)\}\]\}/,
    'the real Wormhole verifier rejects the corrupted signature before posting');
  assert.ok(await connection.getAccountInfo(encoded), 'the last interrupted write leaves one reclaimable VAA');
  assert.match(await metrics(), /dagon_pyth_pusher_leftover_vaas_closed_total [3-9]/,
    'a prefunded system account and subsequent orphan VAAs are reclaimed');
  const balance = await connection.getBalance(payer.publicKey);
  assert.ok(balance >= 2_000_000_000, 'the reserve survives the attack');
  const signatures = await connection.getSignaturesForAddress(payer.publicKey, { limit: 100 });
  assert.ok(signatures.every(s => !s.err), 'failed verification is simulated, never paid');
  const pausedMetrics = await metrics();
  assert.match(pausedMetrics, /dagon_pyth_pusher_pushes_total\{result="landed"\} 0/);
  await delay(17_000);
  assert.equal(await connection.getBalance(payer.publicKey), balance, 'no spending after the latch');
  await writeFile(join(runDir, 'malicious-pusher.log'), log);
  await stopPusher();
  // A deliberate operator restart with Hermes unavailable must reclaim the
  // leftover first, not leak another rent account or require fresh Hermes data.
  authFailure = true;
  await launch();
  await waitFor('orphan refund', async () => !(await connection.getAccountInfo(encoded)));
  const recovered = await connection.getBalance(payer.publicKey);
  assert.ok(recovered > balance, 'orphan rent returns to its payer');
  await waitFor('authentication failure', async () => log.includes('hermes_auth'));
  assert.ok(!log.includes('regression-secret'), 'the API key is not logged');
  await stopPusher();
  // Keep the original guardian-signed VAA, corrupt only the price message.
  // Verification must now pass instruction 2; Merkle checking must fail in
  // UpdatePriceFeed (instruction 3), proving the earlier failure was not an
  // expired/missing guardian set or broken fixture.
  authFailure = false;
  corruptSignature = false;
  await launch();
  await waitFor('Merkle rejection after valid guardian verification', async () =>
    /payment simulation failed: \{"InstructionError":\[3,\{"Custom":\d+\}\]\}/.test(log));
  await writeFile(join(runDir, 'merkle-rejection.log'), log);
  await stopPusher();
  authFailure = true;
  await launch();
  await waitFor('second orphan refund', async () => !(await connection.getAccountInfo(encoded)));
  const allSignatures = await connection.getSignaturesForAddress(payer.publicKey, { limit: 100 });
  assert.ok(allSignatures.every(s => !s.err), 'neither invalid verification nor invalid Merkle proof is broadcast');
  const result = { passed: true, corrupted_guardian_rejected: true, payments_latched: true,
    failed_onchain_transactions: allSignatures.filter(s => s.err).length,
    prefunded_seed_recovered: true,
    valid_guardians_but_mutated_message_rejected: true,
    balance_before_recovery: balance, balance_after_recovery: recovered, paused_metrics: pausedMetrics };
  await writeFile(join(runDir, 'result.json'), JSON.stringify(result, null, 2));
  console.log(JSON.stringify(result));
} finally {
  await stopPusher();
  server.closeAllConnections();
  await new Promise(done => server.close(done));
  await stack?.stop();
  await rm(join(runDir, 'stack', 'ledger'), { recursive: true, force: true });
}
