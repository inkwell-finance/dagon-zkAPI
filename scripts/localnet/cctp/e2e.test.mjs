// Opt-in CCTP end-to-end test (Linux/WSL) of the REAL SDK flows
// (BrowserWalletRuntime + WASM proof worker + ZkapiCctpWallet, under Node via
// node-wallet.mjs) against the full local stack (e2e-stack.mjs: verified
// vault, Circle CCTP V2 with local attesters, Base anvil fork, iris-sim,
// forwarding-sim, indexer, zkapi-serverd with the relay).
//
//   DAGON_CCTP_E2E=1 node --test --test-concurrency=1 scripts/localnet/cctp/e2e.test.mjs
//
// Needs a release build (dagon-zkapi, dagon-zkapi-indexerd, dagon-zkapi-deploy in
// target/release or DAGON_E2E_BIN_DIR), the verifiable vault build in
// target/deploy, the PDA signer, the pinned validator, anvil, and live
// mainnet Solana + Base RPCs (MAINNET_RPC_URL, BASE_RPC_URL). Ports: Solana
// 18899 (+101, +102), anvil 18545. DAGON_CCTP_KEEP=1 keeps the run directory.
//
// Threats exercised (see the result table in local docs): malicious relayer
// (tampering proxy: signed commitment, fee, recipient, extra instruction,
// forged /v2/relay/submit response), relay risk reserved only on submit
// (unsubmitted prepares hold nothing), malicious operator (vault paused,
// relay down), third party (EVM denylist on the source), Circle failure
// (MT/TokenMinter paused, denylisted ek, forwarding service down).
import assert from 'node:assert/strict';
import test from 'node:test';
import http from 'node:http';
import { mkdtemp, rm } from 'node:fs/promises';
import { DatabaseSync } from 'node:sqlite';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { Keypair, PublicKey, Transaction } from '@solana/web3.js';
import { EVM_CCTP, decodeMessageV2, deriveEmergencyKey, usedNonce } from '../../../sdk/services/zkapiCctp.mjs';
import { decodeSolanaVaultState, usdcAssociatedTokenAddress, USDC_MINT } from '../../../sdk/services/zkapiUsdc.mjs';
import { CCTP_FEE_CAPS, decodeTransaction, readFinalizedNoteState, signTransactionWith, transferCheckedInstruction,
    verifyRelaySubmission } from '../../../sdk/services/zkapiCctpWallet.mjs';
import { installNodeBrowser, presetNextDeposit } from './node-wallet.mjs';
import { RELAYER_SOL_USD, sendLegacy, startCctpE2eStack, toWeb3, waitFor } from './e2e-stack.mjs';
import { confirmSignature } from './solana-tx.mjs';

const RUN = process.env.DAGON_CCTP_E2E === '1';
const SKIP = !RUN && 'set DAGON_CCTP_E2E=1 (Linux/WSL; needs the release build, solana-test-validator, anvil, mainnet Solana + Base RPC)';
const ROOT = resolve(fileURLToPath(new URL('../../..', import.meta.url)));
const BIN_DIR = process.env.DAGON_E2E_BIN_DIR ?? join(ROOT, 'target/release');
const RPC_PORT = Number(process.env.CCTP_RPC_PORT ?? 18899);
const ANVIL_PORT = Number(process.env.CCTP_ANVIL_PORT ?? 18545);
const base = EVM_CCTP.base;
const DEPOSIT = 10_000_000n; // Leaves at least the $5 relay burn minimum after fees.
const SOL_USD_MICROS = BigInt(Math.round(Number(RELAYER_SOL_USD) * 1e6));

// Every stack is stopped in its test's after hook. Report anything still
// holding the event loop, then end the file's process so a leaked handle
// cannot hang the runner after the results are in.
test.after(() => {
    if (!RUN) return;
    console.error(`e2e: active resources at exit: ${JSON.stringify(process.getActiveResourcesInfo())}`);
    setTimeout(() => process.exit(), 10_000).unref();
});

function codeOf(error) {
    return `${error?.code ?? ''} ${error?.message ?? error}`;
}

/** Relay HTTP proxy in front of serverd that may rewrite requests and responses (a malicious relayer). */
async function tamperingProxy(target, { onRequest = (_path, body) => body, onResponse = (_path, body) => body } = {}) {
    const server = http.createServer(async (request, response) => {
        let raw = '';
        for await (const chunk of request) raw += chunk;
        const path = new URL(request.url, 'http://x').pathname;
        const body = raw ? onRequest(path, JSON.parse(raw)) : undefined;
        const upstream = await fetch(`${target}${request.url}`, { method: request.method,
            headers: { 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
        let payload = await upstream.json().catch(() => null);
        if (upstream.ok && payload) payload = await onResponse(path, payload, body);
        response.writeHead(upstream.status, { 'content-type': 'application/json' }).end(JSON.stringify(payload));
    });
    await new Promise(done => server.listen(0, '127.0.0.1', done));
    return { url: `http://127.0.0.1:${server.address().port}`, close: () => new Promise(done => server.close(done)) };
}

/**
 * The relay's risk reservations in serverd's database (read-only snapshot):
 * outstanding ek/relay transactions (`relay_issued`), MessageSent event
 * accounts and their rent float, and `owner`'s outstanding signatures.
 */
function relayRisk(runDir, owner = '') {
    const db = new DatabaseSync(join(runDir, 'server.db'), { readOnly: true, timeout: 5_000 });
    try {
        const count = sql => Number(db.prepare(`SELECT COUNT(*) AS n FROM ${sql}`).get().n);
        return {
            issued: count('relay_issued WHERE lost_at IS NULL'),
            events: count('relay_event_accounts'),
            float: count('relay_burn_float'),
            owned: db.prepare('SELECT signature FROM relay_issued WHERE lost_at IS NULL AND owner = ? ORDER BY signature')
                .all(owner).map(row => row.signature),
            eventAddresses: db.prepare('SELECT address FROM relay_event_accounts').all().map(row => row.address),
            floatAddresses: db.prepare('SELECT address FROM relay_burn_float').all().map(row => row.address)
        };
    } finally {
        db.close();
    }
}

const riskCounts = ({ issued, events, float }) => ({ issued, events, float });

/** One full stack plus the helpers every scenario uses. */
async function stackContext(t, { cctp, runDir, browser }) {
    const log = message => t.diagnostic(String(message));
    const env = await startCctpE2eStack({ root: ROOT, runDir, binDir: BIN_DIR, rpcPort: RPC_PORT, anvilPort: ANVIL_PORT, cctp, log });
    const { connection, stack, anvil, iris, payer, faucet } = env;
    await browser.setDeployment({ identity: stack.identity, deployment: { ...env.deployment, openrouter_inference_base: 'http://127.0.0.1:9/api/v1' } });
    const relayInfo = (await env.json(`${env.serverUrl}/v2/relay`)).body;
    const quotes = Object.fromEntries(Object.entries(relayInfo.quotes).map(([kind, value]) => [kind, BigInt(value)]));
    const balance = async address => {
        const info = await connection.getAccountInfo(new PublicKey(address), 'confirmed');
        return info ? Buffer.from(info.data).readBigUInt64LE(64) : 0n;
    };
    const lamports = async key => BigInt(await connection.getBalance(new PublicKey(key), 'confirmed'));
    const vault = async () => decodeSolanaVaultState((await connection.getAccountInfo(new PublicKey(stack.identity.vault_state), 'finalized')).data);
    /** The vault's on-chain solvency invariant. */
    const solvent = async () => {
        const state = await vault();
        const held = await balance(state.vaultToken);
        const owed = BigInt(state.totalCredits) + BigInt(state.treasuryAccrued) + BigInt(state.deferredPayouts);
        assert.ok(held >= owed, `vault solvent: ${held} >= ${owed}`);
        return { ...state, held };
    };
    /** A new browser profile with the CCTP wallet configured for the local Iris/anvil and the pinned test attesters. */
    const newWallet = async (options = {}) => browser.newWallet({ options: { irisUrl: iris.url, attesters: stack.cctp.attesters,
        attestationThreshold: stack.cctp.threshold, pollIntervalMs: 500, receiveFallbackMs: 120_000, arrivalTimeoutMs: 180_000,
        attestationTimeoutMs: 180_000, exitTimeoutMs: 180_000, evmReceipt: { pollIntervalMs: 250 }, ...options } });
    /** A funded Base user (impersonated on the fork) and its EIP-1193 provider. */
    const baseUser = async (amount = DEPOSIT) => {
        const address = await anvil.newUser();
        await anvil.mintUsdc(address, amount);
        return { address, provider: anvil.provider([address]) };
    };
    /** A fresh Solana owner with an (empty) USDC ATA. */
    const solanaAccount = async () => {
        const owner = Keypair.generate();
        const { createUsdcAccountIdempotentInstruction } = await import('../../../sdk/services/zkapiUsdc.mjs');
        await sendLegacy(connection, [toWeb3(createUsdcAccountIdempotentInstruction({ payer: payer.publicKey.toBase58(), owner: owner.publicKey.toBase58() }))], [payer]);
        return { owner, ata: usdcAssociatedTokenAddress(owner.publicKey.toBase58()) };
    };
    /** Faucet USDC straight into ATA(owner) (funds that arrived before a failure). */
    const fundAta = async (owner, amount) => {
        const { createUsdcAccountIdempotentInstruction } = await import('../../../sdk/services/zkapiUsdc.mjs');
        await sendLegacy(connection, [toWeb3(createUsdcAccountIdempotentInstruction({ payer: payer.publicKey.toBase58(), owner })),
            toWeb3(transferCheckedInstruction({ source: stack.usdcFaucetTokenAccount, mint: USDC_MINT,
                destination: usdcAssociatedTokenAddress(owner), authority: faucet.publicKey.toBase58(), amount }))], [payer, faucet]);
    };
    /** The SDK's planning phase (secret, ek, intent) with the mandatory backup acknowledged; nothing burned yet. */
    const planned = async (wallet, user, { finality = 'fast', amount = DEPOSIT } = {}) => {
        const plan = await wallet.planDeposit({ sourceChain: 'base', amount, finality, evmProvider: user.provider });
        assert.equal(plan.cctp.phase, 'backup_required', 'no burn before the backup');
        await assert.rejects(wallet.burnOnEvm(plan, { evmProvider: user.provider, onStatus: () => {} }), /backup/i);
        return wallet.acknowledgeBackup(plan.operationId);
    };
    /** Plan + EVM burn + arrival in ATA(ek), through the SDK's own deposit phases (stops before the vault deposit). */
    const arrive = async (wallet, user, options = {}, beforeBurn = async () => {}) => {
        let plan = await planned(wallet, user, options);
        await beforeBurn(plan);
        plan = await wallet.burnOnEvm(plan, { evmProvider: user.provider, onStatus: () => {} });
        return wallet.waitForArrival(plan, { onStatus: () => {} });
    };
    /** Relayer economics of one step: the USDC it was paid covers the SOL it spent, at the configured price and margin. */
    const relayerCovered = (label, feeUsdc, lamportsSpent) => {
        const costUsdc = (lamportsSpent * SOL_USD_MICROS + 999_999_999n) / 1_000_000_000n;
        assert.ok(feeUsdc >= costUsdc, `${label}: relayer fee ${feeUsdc} covers its SOL cost ${costUsdc} (${lamportsSpent} lamports)`);
        log(`${label}: fee ${feeUsdc} USDC base units, relayer spent ${lamportsSpent} lamports = ${costUsdc}; margin ${feeUsdc - costUsdc}`);
    };
    return { ...env, log, quotes, relayInfo, balance, lamports, vault, solvent, newWallet, baseUser, solanaAccount, fundAta, planned, arrive, relayerCovered };
}

test('CCTP e2e: deposits, exits and failure paths on the normal stack', { skip: SKIP, timeout: 120 * 60_000 }, async t => {
    const runDir = await mkdtemp(join(tmpdir(), 'dagon-cctp-e2e-'));
    const browser = await installNodeBrowser({ root: ROOT });
    // The denylisted ek must be known before the validator starts: a real WASM note secret, used by the scenario below.
    const deniedDeposit = await browser.generateDeposit();
    const deniedEk = deriveEmergencyKey(BigInt(deniedDeposit.secret)).publicKey.toBase58();
    const ctx = await stackContext(t, { runDir, browser, cctp: { variant: 'normal', denylist: [deniedEk] } });
    t.after(async () => {
        await ctx.stop();
        if (process.env.DAGON_CCTP_KEEP !== '1') await rm(runDir, { recursive: true, force: true });
    });
    const { anvil, connection, feeAccount, quotes, relayer } = ctx;
    for (const kind of ['deposit', 'burn', 'sweep', 'close', 'escape']) {
        assert.ok(quotes[kind] > 0n && quotes[kind] <= CCTP_FEE_CAPS[kind], `${kind} quote ${quotes[kind]} fits the SDK cap`);
    }
    assert.equal(quotes.receive, 0n, 'a fallback receive is free');
    await ctx.solvent();

    await t.test('unsubmitted relay preparations reserve nothing; only submit reserves', async () => {
        const post = (route, body) => ctx.json(`${ctx.serverUrl}${route}`, { method: 'POST',
            headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
        // Finalized relay transactions are released by maintenance (15 s): start from a settled store.
        await waitFor('earlier relay reservations settled', async () => relayRisk(runDir).issued === 0, 180_000);
        const ek = Keypair.generate();
        const owner = ek.publicKey.toBase58();
        const funded = 7_000_000n; // Above the $5 relay burn minimum after the relay fee.
        await ctx.fundAta(owner, funded);
        const ekAta = usdcAssociatedTokenAddress(owner);
        const target = await ctx.solanaAccount();
        const burnBody = { owner, destination_domain: base.domain,
            mint_recipient: `000000000000000000000000${randomBytes(20).toString('hex')}`, destination_caller: '',
            max_cctp_fee: '1000000', min_finality_threshold: 2000, hook_data: '', max_fee: String(CCTP_FEE_CAPS.burn) };
        const sweepBody = { owner, destination: target.ata, max_fee: String(CCTP_FEE_CAPS.sweep) };
        const prepare = async (route, body) => {
            const response = await post(route, body);
            assert.equal(response.status, 200, `${route}: ${JSON.stringify(response.body)}`);
            assert.equal(typeof response.body.submit_token, 'string');
            return response.body;
        };

        const before = relayRisk(runDir, owner);
        assert.deepEqual(before.owned, []);
        const relayerBefore = await ctx.lamports(relayer.publicKey);
        const burns = [];
        const sweeps = [];
        // Within the relay's 6-per-owner-per-minute prepare limit (one sweep prepare is left for the cleanup).
        for (let index = 0; index < 5; index += 1) burns.push(await prepare('/v2/relay/burns/prepare', burnBody));
        for (let index = 0; index < 4; index += 1) sweeps.push(await prepare('/v2/relay/sweeps/prepare', sweepBody));
        for (const prepared of [...burns, ...sweeps]) {
            assert.ok(decodeTransaction(prepared.transaction.bytes).signatures.every(signature => signature.every(byte => byte === 0)),
                'a prepare is unsigned (relayer and event slots included): nothing broadcastable leaves before submit');
        }
        const afterPrepares = relayRisk(runDir, owner);
        assert.deepEqual(riskCounts(afterPrepares), riskCounts(before),
            'unsubmitted prepares reserve no loss budget, event account or burn float');
        assert.deepEqual(afterPrepares.owned, []);
        for (const burn of burns) {
            assert.ok(!afterPrepares.eventAddresses.includes(burn.message_sent_event_account), 'no event account recorded at prepare');
            assert.ok(!afterPrepares.floatAddresses.includes(burn.message_sent_event_account), 'no float held at prepare');
        }
        assert.equal(await ctx.lamports(relayer.publicKey), relayerBefore, 'prepares spend no relayer SOL');
        assert.equal(await ctx.balance(ekAta), funded);

        // Top up so every prepared burn still simulates after the first one lands: the second
        // submission below is refused by the one-pending-submission rule, not by missing funds.
        await ctx.fundAta(owner, funded);
        const sign = prepared => Array.from(signTransactionWith(Uint8Array.from(prepared.transaction.bytes), [ek]).bytes);
        const submit = (prepared, transaction) => post('/v2/relay/submit', { token: prepared.submit_token, transaction });
        const complete = (prepared, response, sent, label) => {
            assert.equal(response.status, 200, `${label} submit: ${JSON.stringify(response.body)}`);
            return verifyRelaySubmission(response.body, { sent, ek: owner, format: prepared.transaction.format,
                lastValidHeight: prepared.transaction.last_valid_height, lookupTables: prepared.transaction.lookup_tables || [], label });
        };
        const sent = sign(burns[0]);
        const first = complete(burns[0], await submit(burns[0], sent), sent, 'burn');
        assert.equal(decodeTransaction(first.bytes).signatures.length, 3, 'relayer, ek and MessageSent event signatures');
        const submitted = relayRisk(runDir, owner);
        assert.deepEqual(riskCounts(submitted), { issued: before.issued + 1, events: before.events + 1, float: before.float + 1 },
            'the submitted burn reserved exactly one issuance, one event account and its float');
        assert.deepEqual(submitted.owned, [first.signature]);
        assert.ok(submitted.eventAddresses.includes(burns[0].message_sent_event_account));
        assert.ok(submitted.floatAddresses.includes(burns[0].message_sent_event_account));

        // Another prepare of the same ek while the first is executable (not yet finalized): refused, nothing reserved.
        const second = await submit(burns[1], sign(burns[1]));
        assert.equal(second.status, 429, JSON.stringify(second.body));
        assert.equal(second.body?.error?.code, 'relay_submission_pending');
        assert.deepEqual(riskCounts(relayRisk(runDir, owner)), riskCounts(submitted), 'a refused submission reserves nothing');

        // Cleanup: the burn finalizes; a fresh sweep moves the rest to a fresh account (the gate settles the burn first).
        await waitFor('relay-submitted burn finalized', async () => {
            const { value: [status] } = await connection.getSignatureStatuses([first.signature], { searchTransactionHistory: true });
            if (status?.err) throw new Error(`burn failed: ${JSON.stringify(status.err)}`);
            return status?.confirmationStatus === 'finalized';
        }, 120_000);
        assert.equal(await ctx.balance(ekAta), funded, 'the burn moved exactly its prepared amount and fee');
        const again = await submit(burns[0], sent);
        assert.equal(again.status, 200, `idempotent resubmission of a landed transaction: ${JSON.stringify(again.body)}`);
        assert.equal(again.body.signature, first.signature);
        assert.deepEqual(again.body.transaction.bytes, Array.from(first.bytes), 'the same complete transaction');
        const sweep = await prepare('/v2/relay/sweeps/prepare', sweepBody);
        const sweepSent = sign(sweep);
        const swept = complete(sweep, await submit(sweep, sweepSent), sweepSent, 'sweep');
        await confirmSignature(connection, swept.signature);
        await waitFor('the finalized burn released (submission gate or maintenance)', async () => {
            const owned = relayRisk(runDir, owner).owned;
            return !owned.includes(first.signature) && owned.every(signature => signature === swept.signature);
        }, 60_000);
        assert.equal(await ctx.balance(ekAta), 0n);
        assert.equal(await ctx.balance(target.ata), BigInt(sweep.amount));
    });

    await t.test('Fast deposit from Base -> note credited -> mutual close via relay -> Fast burn -> forwarded to Base', async () => {
        const user = await ctx.baseUser();
        const { runtime, wallet } = await ctx.newWallet();
        const vaultBefore = await ctx.solvent();
        const feesBefore = await ctx.balance(feeAccount);
        const relayerBefore = await ctx.lamports(relayer.publicKey);
        await wallet.deposit({ sourceChain: 'base', amount: DEPOSIT, finality: 'fast', evmProvider: user.provider, onBackup: async () => {} });
        assert.equal(await anvil.usdcBalance(user.address), 0n, 'the whole amount was burned on Base');
        const state = runtime.runtime.state;
        const noteId = Number(state.note_id);
        const chain = await readFinalizedNoteState(runtime.config.funding, noteId);
        assert.equal(chain.note.status, 'active');
        assert.equal(BigInt(chain.note.commitment), BigInt(state.current_commitment ?? chain.note.commitment));
        assert.equal(BigInt(chain.note.amount), BigInt(state.deposit_amount));
        const depositFee = await ctx.balance(feeAccount) - feesBefore;
        // ATA(ek) received burn − feeExecuted (Fast 1.3 bp + forward fee with ATA setup); the note is that minus the relay fee.
        const feeExecuted = DEPOSIT * 13n / 100_000n + 246_000n;
        assert.equal(BigInt(chain.note.amount) + depositFee, DEPOSIT - feeExecuted, 'note + relay fee = arrived net amount');
        assert.equal(depositFee, quotes.deposit, 'deposit fee = quote (no debt)');
        ctx.relayerCovered('deposit', depositFee, relayerBefore - await ctx.lamports(relayer.publicKey));
        const vaultAfter = await ctx.solvent();
        assert.equal(vaultAfter.held - vaultBefore.held, BigInt(chain.note.amount));
        assert.equal(BigInt(vaultAfter.totalCredits) - BigInt(vaultBefore.totalCredits), BigInt(chain.note.amount));

        const recipient = `0x${randomBytes(20).toString('hex')}`;
        const feesBeforeExit = await ctx.balance(feeAccount);
        const relayerBeforeExit = await ctx.lamports(relayer.publicKey);
        const exit = await wallet.exit({ kind: 'mutual', destinationChain: 'base', recipient, finality: 'fast', claim: 'forward' });
        assert.equal(exit.status, 'attested');
        assert.equal((await readFinalizedNoteState(runtime.config.funding, noteId)).note.status, 'closed');
        const message = decodeMessageV2(exit.message);
        assert.equal(message.destinationDomain, base.domain);
        const credited = await waitFor('forwarded mint on Base', async () => {
            const value = await anvil.usdcBalance(recipient);
            return value > 0n && value;
        }, 120_000);
        assert.equal(credited, message.body.amount - message.body.feeExecuted, 'Base recipient gets burn − Circle fee');
        assert.ok(message.body.feeExecuted <= message.body.maxFee);
        const exitFees = await ctx.balance(feeAccount) - feesBeforeExit;
        assert.equal(message.body.amount + exitFees, BigInt(chain.note.amount), 'the whole closed balance left ATA(ek): burn + relay fees');
        assert.ok(exitFees <= quotes.close + quotes.burn, `exit fees ${exitFees} <= close + burn quotes`);
        // Event rent is a bounded relay float, not a user fee.
        const eventRent = BigInt(await ctx.connection.getMinimumBalanceForRentExemption(
            428 + message.body.hookData.length));
        ctx.relayerCovered('close+burn', exitFees, relayerBeforeExit - await ctx.lamports(relayer.publicKey) - eventRent);
        await ctx.solvent();
    });

    await t.test('Standard deposit -> escape via relay -> pending challenge window; finalize refused before the deadline', async () => {
        const user = await ctx.baseUser();
        const { runtime, wallet } = await ctx.newWallet();
        await wallet.deposit({ sourceChain: 'base', amount: DEPOSIT, finality: 'standard', evmProvider: user.provider, onBackup: async () => {} });
        const noteId = Number(runtime.runtime.state.note_id);
        const note = (await readFinalizedNoteState(runtime.config.funding, noteId)).note;
        // Standard: no Fast fee, only the forward fee with ATA setup.
        assert.equal(BigInt(note.amount) + quotes.deposit, DEPOSIT - 246_000n);
        // A relayed escape is paid from ATA(ek) in the escape transaction: the user prefunds the quote.
        const ek = deriveEmergencyKey(BigInt(runtime.runtime.state.secret_s)).publicKey.toBase58();
        await ctx.fundAta(ek, quotes.escape);
        const feesBefore = await ctx.balance(feeAccount);
        const result = await wallet.exit({ kind: 'escape', destinationChain: 'base', recipient: user.address, finality: 'standard' });
        assert.equal(result.status, 'pending_withdrawal');
        const state = await readFinalizedNoteState(runtime.config.funding, noteId);
        assert.equal(state.note.status, 'pending_withdrawal');
        assert.equal(state.pending.stage, 'open');
        assert.ok(Number(result.challengeDeadline) * 1000 > Date.now(), 'deadline is in the future');
        assert.equal(result.emergencyKey, ek);
        const escapeFee = await ctx.balance(feeAccount) - feesBefore;
        assert.ok(escapeFee > 0n && escapeFee <= quotes.escape, `escape fee ${escapeFee}`);
        assert.equal(await ctx.balance(usdcAssociatedTokenAddress(ek)), quotes.escape - escapeFee,
            'only the escape fee left the prefund; nothing is paid out before finalization');
        const early = await ctx.json(`${ctx.serverUrl}/v2/relay/escapes/finalize`, { method: 'POST', headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ note_id: noteId }) });
        assert.notEqual(early.status, 200, `relay refuses to finalize before the challenge deadline: ${JSON.stringify(early.body)}`);
        const resumed = await wallet.resumeExit(result.recordId);
        assert.equal(resumed.status, 'pending_withdrawal', 'the SDK keeps the escape pending until the deadline');
        await ctx.solvent();
    });

    await t.test('EVM denylist on the source: depositForBurn reverts and the USDC stays with the burner', async () => {
        const user = await ctx.baseUser();
        await anvil.denylist(user.address);
        const { wallet } = await ctx.newWallet();
        await assert.rejects(wallet.deposit({ sourceChain: 'base', amount: DEPOSIT, evmProvider: user.provider, onBackup: async () => {} }));
        assert.equal(await anvil.usdcBalance(user.address), DEPOSIT, 'funds stay on Base');
        const plan = await wallet.currentDeposit();
        assert.ok(plan, 'the plan (and its secret) is kept');
        assert.equal(await ctx.balance(plan.cctp.ata), 0n);
    });

    await t.test('forwarding service down -> free relay fallback receive -> deposit credited', async () => {
        ctx.forwarder.pause();
        try {
            const user = await ctx.baseUser();
            const { runtime, wallet } = await ctx.newWallet({ receiveFallbackMs: 2_000 });
            // The relay never creates ATA(ek) (its rent could not be collected): the user (or anyone) creates it.
            const plan = await ctx.arrive(wallet, user, {}, async planned => ctx.fundAta(planned.cctp.ekPublicKey, 0n));
            assert.equal(plan.cctp.phase, 'arrived');
            const feesBefore = await ctx.balance(feeAccount);
            await wallet.deposit({ onBackup: async () => {} });
            const note = (await readFinalizedNoteState(runtime.config.funding, Number(runtime.runtime.state.note_id))).note;
            const fees = await ctx.balance(feeAccount) - feesBefore;
            assert.equal(BigInt(note.amount) + fees, DEPOSIT - (DEPOSIT * 13n / 100_000n + 246_000n));
            assert.equal(fees, quotes.deposit, 'the fallback receive was free; only the deposit fee');
        } finally {
            ctx.forwarder.resume();
        }
        await ctx.solvent();
    });

    await t.test('operator pauses the vault: wallet refuses, funds wait in ATA(ek); after unpause the deposit lands', async () => {
        const user = await ctx.baseUser();
        const { runtime, wallet } = await ctx.newWallet();
        const plan = await ctx.arrive(wallet, user);
        const arrived = await ctx.balance(plan.cctp.ata);
        assert.ok(arrived > 0n);
        const setPaused = async paused => {
            const { createHash } = await import('node:crypto');
            const data = Buffer.concat([createHash('sha256').update('global:set_paused').digest().subarray(0, 8), Buffer.from([paused ? 1 : 0])]);
            const { TransactionInstruction } = await import('@solana/web3.js');
            await sendLegacy(connection, [new TransactionInstruction({ programId: new PublicKey(runtime.config.funding.program_id), data,
                keys: [{ pubkey: new PublicKey(ctx.stack.identity.vault_state), isSigner: false, isWritable: true },
                    { pubkey: ctx.authority.publicKey, isSigner: true, isWritable: false }] })], [ctx.payer, ctx.authority]);
            await waitFor('finalized pause flag', async () => (await ctx.vault()).paused === paused, 60_000);
        };
        await setPaused(true);
        try {
            await assert.rejects(wallet.deposit({ onBackup: async () => {} }), error => /paused|closed|deposits/i.test(codeOf(error)));
            assert.equal(await ctx.balance(plan.cctp.ata), arrived, 'funds still in ATA(ek)');
        } finally {
            await setPaused(false);
        }
        await wallet.deposit({ onBackup: async () => {} });
        assert.equal((await readFinalizedNoteState(runtime.config.funding, Number(runtime.runtime.state.note_id))).note.status, 'active');
        await ctx.solvent();
    });

    await t.test('tampering relay proxy substitutes the signed payload commitment: wallet refuses; honest relay deposits', async () => {
        const user = await ctx.baseUser();
        const proxy = await tamperingProxy(ctx.serverUrl, { onRequest: (path, body) => (path === '/v2/relay/deposits/prepare'
            ? { ...body, commitment: `0x0${randomBytes(31).toString('hex')}` } : body) });
        try {
            const { runtime, wallet } = await ctx.newWallet({ relayUrl: proxy.url });
            const plan = await ctx.arrive(wallet, user);
            const arrived = await ctx.balance(plan.cctp.ata);
            await assert.rejects(wallet.deposit({ onBackup: async () => {} }), error => { ctx.log(`refused: ${codeOf(error)}`); return true; });
            assert.equal(await ctx.balance(plan.cctp.ata), arrived, 'funds still in ATA(ek)');
            assert.equal(runtime.runtime.state, null);
            wallet.overrides = { ...wallet.overrides, relayUrl: null };
            await wallet.deposit({ onBackup: async () => {} });
            assert.equal((await readFinalizedNoteState(runtime.config.funding, Number(runtime.runtime.state.note_id))).note.status, 'active');
        } finally {
            await proxy.close();
        }
    });

    await t.test('deposit buffer is ek-owned and created only inside the signed atomic transaction', async () => {
        const user = await ctx.baseUser();
        let prepared;
        const proxy = await tamperingProxy(ctx.serverUrl, { onResponse: (path, response) => {
            if (path === '/v2/relay/deposits/prepare') prepared = response;
            return response;
        } });
        try {
            const { runtime, wallet } = await ctx.newWallet({ relayUrl: proxy.url });
            const plan = await ctx.arrive(wallet, user);
            const backup = await wallet.depositBackup();
            const key = deriveEmergencyKey(BigInt(plan.secret));
            await wallet.prepareRelayDeposit(plan, { publicKey: key.publicKey.toBase58(), keypair: key.keypair },
                { onStatus: () => {} });
            assert.equal(await connection.getAccountInfo(new PublicKey(prepared.operation)), null,
                'preparing a deposit spends no buffer rent and exposes no mutable staged account');
            assert.deepEqual(relayRisk(runDir, key.publicKey.toBase58()).owned, [],
                'the journaled ek-signed deposit is not submitted yet: the relay reserved nothing for it');
            const tables = prepared.transaction.lookup_tables;
            const decoded = decodeTransaction(prepared.transaction.bytes, tables);
            assert.ok(decoded.signatures.every(signature => signature.every(byte => byte === 0)),
                'the relay prepared the deposit unsigned (its own fee-payer slot included)');
            const init = decoded.instructions[1];
            assert.equal(init.accounts[2].pubkey, key.publicKey.toBase58(), 'ek owns the buffer');
            const forged = toWeb3({ programId: init.programId, data: init.data,
                keys: init.accounts.map((account, index) => ({
                    pubkey: index === 2 ? relayer.publicKey.toBase58() : account.pubkey,
                    isSigner: index === 2, isWritable: index === 1 || index === 2
                })) });
            await assert.rejects(sendLegacy(connection, [forged], [relayer]),
                'relayer cannot initialize the ek-derived operation PDA');
            await wallet.deposit();
            assert.equal((await readFinalizedNoteState(runtime.config.funding, Number(runtime.runtime.state.note_id))).note.status, 'active');
            assert.equal(await connection.getAccountInfo(new PublicKey(prepared.operation)), null,
                'the buffer is consumed in the same transaction');
            const noteId = Number(runtime.runtime.state.note_id);
            const recovered = await ctx.newWallet(); // Empty browser storage; only the file survives.
            assert.equal((await recovered.wallet.importBackup(backup, { restoreUnspentNote: true, noteId })).status,
                'unspent_note_restored');
            const exit = await recovered.wallet.exit({ kind: 'mutual', destinationChain: 'base',
                recipient: user.address, finality: 'fast', claim: 'forward' });
            assert.equal(exit.status, 'attested', 'the restored never-used note can actually close and burn');
            await waitFor('recovered note forwarded to Base', async () => (await anvil.usdcBalance(user.address)) > 0n, 120_000);
        } finally {
            await proxy.close();
        }
    });

    await t.test('refund: refused before refund_after; tampered burns refused; after refund_after the ek burns back to the Base burner', async () => {
        const user = await ctx.baseUser();
        const { wallet } = await ctx.newWallet({ refundDelaySeconds: 45 });
        const plan = await ctx.arrive(wallet, user);
        const arrived = await ctx.balance(plan.cctp.ata);
        await assert.rejects(wallet.refund(), error => /refund/i.test(codeOf(error)));
        assert.equal(await ctx.balance(plan.cctp.ata), arrived);
        const attacker = `0x${'ee'.repeat(20)}`;
        const tampers = {
            'higher fee': (path, payload) => (path === '/v2/relay/burns/prepare' ? { ...payload, fee: String(BigInt(payload.fee) + 1_000n) } : payload),
            'different recipient': null,
            'extra instruction': (path, payload, request) => {
                if (path !== '/v2/relay/burns/prepare') return payload;
                const transaction = Transaction.from(Buffer.from(payload.transaction.bytes));
                transaction.add(toWeb3(transferCheckedInstruction({ source: usdcAssociatedTokenAddress(request.owner), mint: USDC_MINT,
                    destination: usdcAssociatedTokenAddress(Keypair.generate().publicKey.toBase58()), authority: request.owner, amount: 1n })));
                return { ...payload, transaction: { ...payload.transaction,
                    bytes: [...transaction.serialize({ requireAllSignatures: false, verifySignatures: false })] } };
            }
        };
        for (const [label, onResponse] of Object.entries(tampers)) {
            const proxy = await tamperingProxy(ctx.serverUrl, onResponse ? { onResponse } : {
                onRequest: (path, body) => (path === '/v2/relay/burns/prepare' ? { ...body, mint_recipient: `000000000000000000000000${attacker.slice(2)}` } : body) });
            try {
                wallet.overrides = { ...wallet.overrides, relayUrl: proxy.url };
                await assert.rejects(wallet.refund({ force: true }), error => { ctx.log(`${label}: ${codeOf(error)}`); return true; });
                assert.equal(await ctx.balance(plan.cctp.ata), arrived, `${label}: ek signed nothing`);
            } finally {
                await proxy.close();
            }
        }
        wallet.overrides = { ...wallet.overrides, relayUrl: null };
        await delay(Math.max(0, plan.cctp.refundAfter * 1000 - Date.now() + 1_000));
        const before = await anvil.usdcBalance(user.address);
        const feesBefore = await ctx.balance(feeAccount);
        const refunded = await wallet.refund();
        const message = decodeMessageV2(refunded.attestation.message);
        const credited = await waitFor('refund minted on Base', async () => {
            const value = await anvil.usdcBalance(user.address);
            return value > before && value;
        }, 120_000);
        assert.equal(credited - before, message.body.amount - message.body.feeExecuted);
        const fee = await ctx.balance(feeAccount) - feesBefore;
        assert.equal(message.body.amount + fee, arrived);
        assert.ok(fee <= quotes.burn);
        assert.equal(await ctx.balance(plan.cctp.ata), 0n);
        assert.equal(await wallet.currentDeposit(), null, 'the refunded plan is archived');
    });

    await t.test('emergency-key sweep via the relay; a forged /v2/relay/submit response is refused, the journaled sweep resumes', async () => {
        const user = await ctx.baseUser();
        const { wallet } = await ctx.newWallet();
        const plan = await ctx.arrive(wallet, user);
        const arrived = await ctx.balance(plan.cctp.ata);
        const target = await ctx.solanaAccount();
        // A malicious relay forges the relayer signature of the complete transaction it returns. The
        // honest serverd behind it has already broadcast the genuine one.
        let genuine = null;
        const proxy = await tamperingProxy(ctx.serverUrl, { onResponse: (path, payload) => {
            if (path !== '/v2/relay/submit') return payload;
            genuine = payload.signature;
            const bytes = [...payload.transaction.bytes];
            bytes[1] ^= 0xff; // Signature slot 0 (the relayer's), after the 1-byte signature count.
            return { ...payload, transaction: { ...payload.transaction, bytes } };
        } });
        try {
            wallet.overrides = { ...wallet.overrides, relayUrl: proxy.url };
            await assert.rejects(wallet.sweep({ to: target.owner.publicKey.toBase58() }), error => {
                ctx.log(`forged submit response: ${codeOf(error)}`);
                return error.code === 'cctp_relay_tx_rejected';
            });
        } finally {
            await proxy.close();
        }
        wallet.overrides = { ...wallet.overrides, relayUrl: null };
        assert.ok(genuine, 'the sweep reached /v2/relay/submit');
        assert.equal((await wallet.currentDeposit()).cctp.sweep?.signature, null,
            'the wallet kept only its own ek-signed record, not the forged transaction');
        // Landed first, so the resubmission below takes the relay's idempotent "already on chain" path.
        await confirmSignature(connection, genuine);
        const swept = await wallet.sweep();
        assert.equal(swept.signature, genuine, 'the same token and bytes resubmitted: the same transaction');
        const received = await ctx.balance(target.ata);
        assert.equal(BigInt(swept.amount), received);
        assert.ok(arrived - received <= quotes.sweep, 'sweep fee within the quote');
        assert.equal(await ctx.balance(plan.cctp.ata), 0n);
    });

    await t.test('CCTP exits below $5 are not relayed; the emergency funds remain sweepable', async () => {
        const user = await ctx.baseUser(5_000_000n);
        const { wallet } = await ctx.newWallet();
        const plan = await ctx.arrive(wallet, user, { amount: 5_000_000n });
        const before = await ctx.balance(plan.cctp.ata);
        await assert.rejects(wallet.refund({ force: true }), error => error.code === 'burn_below_minimum'
            && error.message.includes('5 USDC'));
        assert.equal(await ctx.balance(plan.cctp.ata), before);
        const target = await ctx.solanaAccount();
        await wallet.sweep({ to: target.ata });
        assert.equal(await ctx.balance(plan.cctp.ata), 0n);
        assert.equal(await ctx.balance(target.ata), before - quotes.sweep);
    });

    await t.test('no relayer: funds wait in ATA(ek); relay disabled -> self-funded ek deposit; server down -> self-funded sweep', async () => {
        const user = await ctx.baseUser(2n * DEPOSIT);
        const { runtime, wallet } = await ctx.newWallet();
        const plan = await ctx.arrive(wallet, user);
        const arrived = await ctx.balance(plan.cctp.ata);
        await ctx.startServer({ relay: false });
        try {
            const unavailable = await wallet.deposit({ onBackup: async () => {} }).then(() => null, error => error);
            assert.ok(unavailable, 'a relayed deposit cannot proceed');
            assert.equal(unavailable.code, 'relay_unavailable', codeOf(unavailable));
            assert.equal(unavailable.emergencyAccount, plan.cctp.ata);
            assert.equal(await ctx.balance(plan.cctp.ata), arrived);
            await confirmSignature(connection, await connection.requestAirdrop(new PublicKey(plan.cctp.ekPublicKey), 50_000_000));
            await wallet.deposit({ selfFunded: true, onBackup: async () => {} }).catch(error => {
                ctx.log(`self-funded deposit: ${codeOf(error)} ${JSON.stringify(error.data ?? null)}`);
                throw error;
            });
            const note = (await readFinalizedNoteState(runtime.config.funding, Number(runtime.runtime.state.note_id))).note;
            assert.equal(BigInt(note.amount), arrived, 'self-funded: the whole arrival, no relay fee');
        } finally {
            await ctx.startServer();
        }
        // Server entirely down: a second arrival is swept by the ek itself.
        const second = await ctx.newWallet();
        const plan2 = await ctx.arrive(second.wallet, user);
        await ctx.stopServer();
        try {
            await confirmSignature(connection, await connection.requestAirdrop(new PublicKey(plan2.cctp.ekPublicKey), 50_000_000));
            const target = await ctx.solanaAccount();
            const arrived2 = await ctx.balance(plan2.cctp.ata);
            await second.wallet.sweep({ to: target.ata, selfFunded: true });
            assert.equal(await ctx.balance(target.ata), arrived2);
        } finally {
            await ctx.startServer();
        }
        await ctx.solvent();
    });

    await t.test('denylisted ek: the refund burn is rejected; the ek sweeps to a Solana account', async () => {
        const user = await ctx.baseUser();
        const { runtime, wallet } = await ctx.newWallet();
        presetNextDeposit(runtime, deniedDeposit);
        const plan = await ctx.arrive(wallet, user);
        assert.equal(plan.cctp.ekPublicKey, deniedEk);
        const arrived = await ctx.balance(plan.cctp.ata);
        await assert.rejects(wallet.refund({ force: true }), error => { ctx.log(`denylisted burn: ${codeOf(error)}`); return true; });
        assert.equal(await ctx.balance(plan.cctp.ata), arrived);
        const target = await ctx.solanaAccount();
        await wallet.sweep({ to: target.ata });
        assert.ok(await ctx.balance(target.ata) >= arrived - quotes.sweep);
        assert.equal(await ctx.balance(plan.cctp.ata), 0n);
    });
});

for (const variant of ['mt-paused', 'minter-paused']) {
    test(`CCTP e2e variant ${variant}: receive and burn rejected, funds safe, sweep works`, { skip: SKIP, timeout: 40 * 60_000 }, async t => {
        const runDir = await mkdtemp(join(tmpdir(), `dagon-cctp-e2e-${variant}-`));
        const browser = await installNodeBrowser({ root: ROOT });
        const ctx = await stackContext(t, { runDir, browser, cctp: { variant, denylist: [] } });
        t.after(async () => {
            await ctx.stop();
            if (process.env.DAGON_CCTP_KEEP !== '1') await rm(runDir, { recursive: true, force: true });
        });
        const user = await ctx.baseUser();
        const { wallet } = await ctx.newWallet({ receiveFallbackMs: 2_000, arrivalTimeoutMs: 30_000 });
        let plan = await ctx.planned(wallet, user);
        plan = await wallet.burnOnEvm(plan, { evmProvider: user.provider, onStatus: () => {} });
        await assert.rejects(wallet.waitForArrival(plan, { onStatus: () => {} }), error => {
            ctx.log(`arrival: ${codeOf(error)}`);
            return /cctp_paused|cctp_arrival_pending/.test(codeOf(error));
        });
        plan = await wallet.currentDeposit();
        assert.equal(await ctx.balance(plan.cctp.ata), 0n, 'nothing minted while paused');
        assert.ok(plan.cctp.attested?.nonce, 'the burn was attested');
        assert.equal(await ctx.connection.getAccountInfo(usedNonce(Buffer.from(plan.cctp.attested.nonce, 'hex')), 'confirmed'), null,
            'the attested message is still receivable after Circle unpauses');
        // Funds that reached ATA(ek) before the pause: the burn is refused, the sweep works.
        await ctx.fundAta(plan.cctp.ekPublicKey, DEPOSIT);
        await assert.rejects(wallet.refund({ force: true }), error => { ctx.log(`burn: ${codeOf(error)}`); return true; });
        assert.equal(await ctx.balance(plan.cctp.ata), DEPOSIT);
        const target = await ctx.solanaAccount();
        await wallet.sweep({ to: target.ata });
        assert.ok(await ctx.balance(target.ata) >= DEPOSIT - ctx.quotes.sweep);
        await ctx.solvent();
    });
}
