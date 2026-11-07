import assert from 'node:assert/strict';
import test from 'node:test';

import { BrowserWalletRuntime } from '../services/browserWalletRuntime.js';
import { base58Encode, inspectPreparedSolanaMessage, unsignedSolanaTransaction } from '../services/zkapiSolanaTransport.mjs';
import { recordSolanaSignedStage } from '../services/zkapiSolanaJournal.mjs';
import { TOKEN_PROGRAM_ID, USDC_MINT, vaultTokenAddress } from '../services/zkapiUsdc.mjs';
import { PublicKey, Message } from '@solana/web3.js';
import { noteAccountData, pendingAccountData, rpcAccount, tokenAccountData, usdcFunding, vaultAccountData }
    from './helpers/usdc-fixtures.mjs';

const PROGRAM = new Uint8Array(32).fill(1);
const VAULT = new Uint8Array(32).fill(2);
const PAYER = new Uint8Array(32).fill(3);

function shortVec(value) {
    const result = [];
    do {
        let byte = value & 0x7f;
        value >>>= 7;
        if (value) byte |= 0x80;
        result.push(byte);
    } while (value);
    return result;
}

function message(data = [7]) {
    const accounts = [PAYER, PROGRAM, VAULT];
    return Uint8Array.from([
        1, 0, 2,
        ...shortVec(accounts.length), ...accounts.flatMap(value => [...value]),
        ...new Uint8Array(32).fill(4),
        1,
        1,
        2, 2, 0,
        ...shortVec(data.length), ...data
    ]);
}

function operation() {
    return { transactions: [{
        format: 'solana-legacy-message-v1',
        bytes: [...message()],
        required_signers: [[...PAYER]],
        last_valid_height: 500
    }] };
}

function runtime() {
    const value = new BrowserWalletRuntime();
    value.initPromise = Promise.resolve(value);
    value.manifest = { deployment_id: 'dagon-test', billing_asset: 'usdc' };
    value.config = { funding: usdcFunding({
        chain_id: '18446744073709551615',
        program_id: base58Encode(PROGRAM),
        vault_state: base58Encode(VAULT),
        genesis_hash: base58Encode(new Uint8Array(32).fill(4)),
        protocol_server_url: 'https://operator.invalid',
        rpc_url: 'https://rpc.example.test'
    }) };
    value.runtime = {
        deploymentId: 'dagon-test',
        pendingDeposit: { operationId: 'deposit-1', amount: 10, next_note_id: 0 }
    };
    value.reload = async () => value.runtime;
    value.commit = async next => {
        value.runtime = next;
        return next;
    };
    return value;
}

test('browser runtime persists signed/submitted/finalized Solana stages in its durable plan', async () => {
    const value = runtime();
    let journal = await value.beginSolanaOperationJournal(
        'deposit', base58Encode(PAYER), operation()
    );
    assert.equal(value.runtime.pendingDeposit.solanaJournal, journal);

    const signed = unsignedSolanaTransaction(message());
    signed.fill(9, 1, 65);
    const signature = base58Encode(signed.slice(1, 65));
    journal = await value.rememberSolanaStageSigned('deposit', 'deposit-1', {
        index: 0,
        format: 'solana-legacy-transaction-v1',
        signature,
        signedTransaction: signed
    });
    assert.equal(journal.stages[0].phase, 'signed');
    journal = await value.rememberSolanaStageSubmitted('deposit', 'deposit-1', {
        index: 0,
        signature
    });
    assert.equal(journal.stages[0].phase, 'submitted');
    journal = await value.rememberSolanaStageFinalized('deposit', 'deposit-1', {
        index: 0,
        signature,
        confirmation: { slot: '9007199254740993' }
    });
    assert.equal(journal.stages[0].phase, 'finalized');
    const resumed = await value.resumeSolanaOperation('deposit');
    assert.equal(resumed.completed, true);
    assert.equal(resumed.startIndex, 1);
});

test('browser runtime refuses to replace a journaled prepared operation', async () => {
    const value = runtime();
    await value.beginSolanaOperationJournal('deposit', base58Encode(PAYER), operation());
    const changed = operation();
    changed.transactions[0].bytes[changed.transactions[0].bytes.length - 1] ^= 1;
    await assert.rejects(
        value.beginSolanaOperationJournal('deposit', base58Encode(PAYER), changed),
        /different Solana transaction plan/
    );
});

test('background escape finalization keeps a separate ordered Solana journal', async () => {
    const value = runtime();
    let record = {
        recordId: 'escape-7',
        revision: 1,
        mode: 'escape',
        phase: 'pending',
        noteId: 7
    };
    value.currentWithdrawal = async () => structuredClone(record);
    value.updateWithdrawal = async (_recordId, changes, options = {}) => {
        assert.equal(options.expectedRevision, record.revision);
        record = { ...record, ...changes, revision: record.revision + 1 };
        return structuredClone(record);
    };
    let journal = await value.beginSolanaFinalizationJournal(
        record.recordId,
        base58Encode(PAYER),
        operation()
    );
    assert.equal(record.phase, 'finalizing');
    assert.equal(journal.kind, 'finalize');
    assert.notEqual(record.solanaFinalizeOperationId, 'deposit-1');

    const signed = unsignedSolanaTransaction(message());
    signed.fill(5, 1, 65);
    const signature = base58Encode(signed.slice(1, 65));
    journal = await value.updateSolanaFinalizationJournal(
        record.recordId,
        record.solanaFinalizeOperationId,
        current => recordSolanaSignedStage(current, {
            index: 0,
            format: 'solana-legacy-transaction-v1',
            signature,
            signedTransaction: signed
        })
    );
    assert.equal(journal.stages[0].phase, 'signed');
    assert.equal(record.solanaFinalizationJournal.stages[0].signature, signature);
});

test('a parked escape payout is released under its own journal on the same record slot', async () => {
    const value = runtime();
    let record = { recordId: 'escape-8', revision: 1, mode: 'escape', phase: 'pending', noteId: 8 };
    value.currentWithdrawal = async () => structuredClone(record);
    value.updateWithdrawal = async (_recordId, changes) => {
        record = { ...record, ...changes, revision: record.revision + 1 };
        return structuredClone(record);
    };
    await assert.rejects(value.beginSolanaFinalizationJournal(record.recordId, base58Encode(PAYER), operation(), 'release'),
        /no parked Solana escape payout/);
    record.phase = 'payout_parked';
    await assert.rejects(value.beginSolanaFinalizationJournal(record.recordId, base58Encode(PAYER), operation()),
        /no pending Solana escape to finalize/);
    const journal = await value.beginSolanaFinalizationJournal(record.recordId, base58Encode(PAYER), operation(), 'release');
    assert.equal(journal.kind, 'release');
    assert.equal(record.phase, 'releasing');
    await assert.rejects(value.submitSolanaFinalization(record.recordId, {
        account: { address: base58Encode(PAYER), publicKey: PAYER }
    }), /different Solana escape operation/);
});

test('USDC exits are built locally from pinned RPC accounts without any operator prepare route', async t => {
    const value = runtime();
    const funding = value.config.funding;
    const publicInputs = {
        protocol_version: 2, chain_id: funding.chain_id, contract_address: funding.contract_address,
        state_signing_key_x: '0x1', state_signing_key_y: '0x2',
        clearance_signing_key_x: '0x3', clearance_signing_key_y: '0x4',
        note_id: 7, registration: `0x${'11'.repeat(32)}`, deposit_amount: '1000000',
        expiry_ts: '1900000000', final_balance: '750000', conceded: '50000',
        destination: new Array(20).fill(0), withdrawal_nullifier: '0x22', next_nullifier: '0x23',
        valid_until: '1900000600', has_clearance: false
    };
    // A payout token account and an escaper distinct from the payer, so
    // their writability is observable.
    const DESTINATION = new Uint8Array(32).fill(9);
    const RENT_PAYER = new Uint8Array(32).fill(10);
    const plan = { mode: 'escape', destination: base58Encode(DESTINATION), public_inputs: publicInputs,
        proof: { backend: 'groth16_bn254', proof: Buffer.alloc(256).toString('base64') } };
    const vault = vaultAccountData(funding);
    let note = noteAccountData(funding, { noteId: 7 });
    let pending = pendingAccountData(funding, { destination: base58Encode(DESTINATION),
        rentPayer: base58Encode(RENT_PAYER) });
    let destinationAccount = tokenAccountData({ owner: base58Encode(new Uint8Array(32).fill(11)) });
    // [address, writable, signer] of the program instruction, in account order.
    const metas = bytes => {
        const message = Message.from(Uint8Array.from(bytes));
        return message.instructions.at(-1).accounts.map(index => [message.accountKeys[index].toBase58(),
            message.isAccountWritable(index), message.isAccountSigner(index)]);
    };
    const pda = (...seeds) => PublicKey.findProgramAddressSync(
        [Buffer.from(seeds[0]), VAULT, ...seeds.slice(1)], new PublicKey(PROGRAM))[0].toBase58();
    const feltSeed = byte => Uint8Array.from({ length: 32 }, (_, index) => (index === 31 ? byte : 0));
    const key = bytes => new PublicKey(bytes).toBase58();
    const SYSTEM = '11111111111111111111111111111111';
    const VAULT_TOKEN = vaultTokenAddress(funding.program_id, funding.vault_state);
    const noteSeed = Buffer.from([7, 0, 0, 0]);
    const expectedMetas = {
        // The escape only records its payout account; finalize credits it.
        escape: [[key(VAULT), true, false], [pda('note', noteSeed), true, false],
            [pda('pending', noteSeed), true, false], [pda('nullifier', feltSeed(0x22)), true, false],
            [pda('nullifier', feltSeed(0x23)), true, false], [key(PAYER), true, true],
            [key(DESTINATION), false, false], [SYSTEM, false, false]],
        mutual: [[key(VAULT), true, false], [pda('note', noteSeed), true, false],
            [pda('nullifier', feltSeed(0x22)), true, false], [key(PAYER), true, true],
            [key(DESTINATION), true, false], [VAULT_TOKEN, true, false], [USDC_MINT, false, false],
            [TOKEN_PROGRAM_ID, false, false], [SYSTEM, false, false]],
        // No SystemProgram payout: the vault token account pays the saved
        // destination and the pending rent goes back to the escaper.
        finalize: [[key(VAULT), true, false], [pda('note', noteSeed), true, false],
            [pda('pending', noteSeed), true, false], [key(PAYER), true, true], [key(RENT_PAYER), true, false],
            [key(DESTINATION), true, false], [VAULT_TOKEN, true, false], [USDC_MINT, false, false],
            [TOKEN_PROGRAM_ID, false, false]],
        release: [[key(VAULT), true, false], [pda('note', noteSeed), false, false],
            [pda('pending', noteSeed), true, false], [key(PAYER), true, true], [key(RENT_PAYER), true, false],
            [key(DESTINATION), true, false], [VAULT_TOKEN, true, false], [USDC_MINT, false, false],
            [TOKEN_PROGRAM_ID, false, false]]
    };
    let genesis = funding.genesis_hash;
    const calls = [];
    value.remoteJson = async () => assert.fail('no operator endpoint may authorize an exit');
    t.mock.method(globalThis, 'fetch', async (url, init) => {
        assert.equal(url, funding.rpc_url);
        const { method, params } = JSON.parse(init.body);
        calls.push(method);
        let result;
        if (method === 'getGenesisHash') result = genesis;
        else if (method === 'getMultipleAccounts') {
            const expected = PublicKey.findProgramAddressSync(
                [Buffer.from('note'), VAULT, Buffer.from([7, 0, 0, 0])], new PublicKey(PROGRAM))[0];
            assert.equal(params[0][1], expected.toBase58());
            result = { value: [vault, note, ...(params[0].length === 3 ? [pending] : [])]
                .map(data => rpcAccount(funding.program_id, data)) };
        } else if (method === 'getAccountInfo') {
            assert.equal(params[0], key(DESTINATION));
            result = { context: { slot: 1 },
                value: destinationAccount && rpcAccount(TOKEN_PROGRAM_ID, destinationAccount) };
        } else {
            assert.equal(method, 'getLatestBlockhash');
            result = { value: { blockhash: funding.genesis_hash, lastValidBlockHeight: 500 } };
        }
        return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result }));
    });
    for (const mode of ['escape', 'mutual']) {
        plan.mode = mode;
        publicInputs.has_clearance = mode === 'mutual';
        publicInputs.next_nullifier = mode === 'mutual' ? '0x0' : '0x23';
        publicInputs.conceded = mode === 'mutual' ? '0' : '50000';
        const prepared = await value.prepareSolanaWithdrawalOperation(base58Encode(PAYER), plan);
        assert.equal(prepared.transactions.length, 1);
        assert.ok(unsignedSolanaTransaction(prepared.transactions[0].bytes).length <= 1232);
        const message = Message.from(Uint8Array.from(prepared.transactions[0].bytes));
        assert.equal(message.instructions.length, 3, 'compute budget prefix plus one proof verification');
        assert.deepEqual(metas(prepared.transactions[0].bytes), expectedMetas[mode], `${mode} account metas`);
        // WithdrawalPayload has no leading destination pubkey:
        // discriminator | note_id | WithdrawalInputs | proof length | proof.
        const data = inspectPreparedSolanaMessage(prepared.transactions[0].bytes).instructionData;
        assert.equal(data.length, 8 + 4 + (2 + 8 + 32 * 6 + 4 + 16 + 8 + 16 + 20 + 32 + 1 + 32 + 16 + 8) + 4 + 256);
        assert.deepEqual([...data.slice(8, 12)], [7, 0, 0, 0]);
        assert.deepEqual([...data.slice(12, 14)], [2, 0], 'WithdrawalInputs start right after note_id');
    }
    // A payout account that cannot be credited fails before any wallet prompt.
    destinationAccount = tokenAccountData({ owner: base58Encode(new Uint8Array(32).fill(11)), state: 2 });
    await assert.rejects(value.prepareSolanaWithdrawalOperation(base58Encode(PAYER), plan),
        error => error.code === 'usdc_destination_not_creditable');
    destinationAccount = null;
    await assert.rejects(value.prepareSolanaWithdrawalOperation(base58Encode(PAYER), plan), /does not exist yet/);
    // A zero-balance mutual close transfers nothing, so its payout account is not read.
    publicInputs.final_balance = '0';
    const reads = calls.filter(method => method === 'getAccountInfo').length;
    await value.prepareSolanaWithdrawalOperation(base58Encode(PAYER), plan);
    assert.equal(calls.filter(method => method === 'getAccountInfo').length, reads);
    await assert.rejects(value.prepareSolanaWithdrawalOperation(base58Encode(PAYER),
        { ...plan, destination: VAULT_TOKEN }), /vault token account cannot receive/);

    note = noteAccountData(funding, { noteId: 7, status: 2 });
    const finalized = await value.prepareSolanaFinalizeEscapeOperation(base58Encode(PAYER), 7);
    assert.equal(Message.from(Uint8Array.from(finalized.transactions[0].bytes)).instructions.length, 1);
    assert.deepEqual(metas(finalized.transactions[0].bytes), expectedMetas.finalize, 'finalize account metas');
    await assert.rejects(value.prepareSolanaReleaseEscapePayoutOperation(base58Encode(PAYER), 7),
        /no parked payout to release/);

    // Finalization parked the payout: the note is closed (or later retired)
    // and the pending record waits at stage 1 for a release.
    pending = pendingAccountData(funding, { destination: base58Encode(DESTINATION),
        rentPayer: base58Encode(RENT_PAYER), stage: 1 });
    for (const status of [4, 5]) {
        note = noteAccountData(funding, { noteId: 7, status });
        const released = await value.prepareSolanaReleaseEscapePayoutOperation(base58Encode(PAYER), 7);
        assert.equal(Message.from(Uint8Array.from(released.transactions[0].bytes)).instructions.length, 1);
        assert.deepEqual(metas(released.transactions[0].bytes), expectedMetas.release, 'release account metas');
    }
    await assert.rejects(value.prepareSolanaFinalizeEscapeOperation(base58Encode(PAYER), 7), /not pending/);
    genesis = base58Encode(new Uint8Array(32).fill(8));
    await assert.rejects(value.prepareSolanaFinalizeEscapeOperation(base58Encode(PAYER), 7), /another cluster/);
    assert.equal(value.prepareSolanaRestoreChallengedOperation, undefined);
    await assert.rejects(value.prepareSolanaLedgerOperation('restore', {}), /Invalid local Solana exit kind/);
    assert.ok(calls.length >= 9);
});

// Threat: an operator that prepared a deposit withholds its tree mirror after
// every stage finalized (or a vault owner keeps the pause flag set). The note
// must still be installed from finalized chain state alone so it can exit.
test('a finalized Solana deposit is installed without the operator indexer, even while paused', async t => {
    await installFinalizedDeposit(t, { planCommitment: `0x${'11'.repeat(32)}` });
});

// Threat: the wallet WASM encodes felts without leading zeros (about a third of
// random registration commitments), while the note account is decoded padded.
// A string comparison stranded such a landed deposit until the treasury could
// claim it at expiry; the comparison must be by field value.
test('a landed deposit whose local commitment has a leading zero is still installed', async t => {
    const noteCommitment = `0x0f${'11'.repeat(31)}`;
    await installFinalizedDeposit(t, { planCommitment: `0xf${'11'.repeat(31)}`, noteCommitment });
    await assert.rejects(installFinalizedDeposit(t, { planCommitment: `0xe${'11'.repeat(31)}`, noteCommitment }),
        /does not match this browser’s deposit/);
});

async function installFinalizedDeposit(t, { planCommitment, noteCommitment = planCommitment }) {
    const value = runtime();
    const funding = value.config.funding;
    funding.indexer_url = 'https://indexer.invalid';
    value.runtime.pendingDeposit.commitment = planCommitment;
    await value.beginSolanaOperationJournal('deposit', base58Encode(PAYER), operation());
    const signed = unsignedSolanaTransaction(message());
    signed.fill(9, 1, 65);
    const signature = base58Encode(signed.slice(1, 65));
    await value.rememberSolanaStageSigned('deposit', 'deposit-1', {
        index: 0, format: 'solana-legacy-transaction-v1', signature, signedTransaction: signed
    });
    await value.rememberSolanaStageSubmitted('deposit', 'deposit-1', { index: 0, signature });
    await value.rememberSolanaStageFinalized('deposit', 'deposit-1', {
        index: 0, signature, confirmation: { slot: '10' }
    });
    // Paused, and never unpaused.
    const vault = Buffer.from(vaultAccountData(funding, { paused: true, nextNoteId: 1 }));
    const note = Buffer.from(noteAccountData(funding, { noteId: 0, amount: 10n, commitment: noteCommitment }));
    const loader = 'BPFLoaderUpgradeab1e11111111111111111111111';
    const programData = base58Encode(new Uint8Array(32).fill(12));
    const accounts = new Map([
        [funding.vault_state, { owner: funding.program_id, executable: false, data: vault }],
        [funding.program_id, { owner: loader, executable: true, data: Buffer.from([2, 0, 0, 0, ...new Uint8Array(32).fill(12)]) }],
        [programData, { owner: loader, executable: false, data: Buffer.from([3, 0, 0, 0, ...new Array(9).fill(0)]) }]
    ]);
    const encode = account => account && { owner: account.owner, executable: account.executable,
        data: [account.data.toString('base64'), 'base64'] };
    t.mock.restoreAll();
    t.mock.method(globalThis, 'fetch', async (url, init) => {
        assert.equal(url, funding.rpc_url, 'only the pinned RPC is read');
        const { method, params } = JSON.parse(init.body);
        let result;
        if (method === 'getGenesisHash') result = funding.genesis_hash;
        else if (method === 'getAccountInfo') result = { context: { slot: 11 }, value: encode(accounts.get(params[0])) };
        else {
            assert.equal(method, 'getMultipleAccounts');
            result = { context: { slot: 11 }, value: params[0].map(address => address === funding.vault_state
                ? encode({ owner: funding.program_id, executable: false, data: note }) : null) };
        }
        return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result }));
    });
    value.remoteJson = async () => assert.fail('no operator endpoint may gate deposit installation');
    value.treePath = async () => assert.fail('deposit installation never reads the operator indexer');
    let confirmed = null;
    value.confirmDeposit = async args => { confirmed = args; return { status: 'confirmed' }; };
    assert.deepEqual(await value.confirmSolanaDeposit(), { status: 'confirmed' });
    assert.equal(confirmed.note_id, 0);
    assert.equal(confirmed.amount, 10);
    assert.equal(confirmed.expiry_ts, 1900000000);
}
