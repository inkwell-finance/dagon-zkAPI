import assert from 'node:assert/strict';
import test from 'node:test';

import { BrowserWalletRuntime } from '../services/browserWalletRuntime.js';
import { base58Encode, unsignedSolanaTransaction } from '../services/zkapiSolanaTransport.mjs';
import { recordSolanaSignedStage } from '../services/zkapiSolanaJournal.mjs';
import { PublicKey, Message } from '@solana/web3.js';

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
    value.manifest = { deployment_id: 'dagon-test', billing_asset: 'native_sol' };
    value.config = { funding: {
        ledger_backend: 'dagon.solana.groth16.v1',
        billing_asset: 'native_sol',
        billing_unit: 'lamports',
        base_units_per_asset: '1000000000',
        chain_id: '18446744073709551615',
        contract_address: `0x${'11'.repeat(32)}`,
        program_id: base58Encode(PROGRAM),
        vault_state: base58Encode(VAULT)
    } };
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

test('native exits are built locally from pinned RPC accounts without any operator prepare route', async t => {
    const value = runtime();
    const funding = value.config.funding;
    Object.assign(funding, {
        network: 'localnet', protocol_server_url: 'https://operator.invalid',
        rpc_url: 'https://rpc.example.test', genesis_hash: base58Encode(new Uint8Array(32).fill(4)),
        wallet_standard_chain: 'solana:localnet', pyth_receiver_program: funding.program_id,
        pyth_price_account: funding.vault_state, pyth_feed_id: `0x${'01'.repeat(32)}`,
        pyth_max_age_seconds: 30, pyth_max_confidence_bps: 100
    });
    const publicInputs = {
        protocol_version: 2, chain_id: funding.chain_id, contract_address: funding.contract_address,
        state_signing_key_x: '0x1', state_signing_key_y: '0x2',
        clearance_signing_key_x: '0x3', clearance_signing_key_y: '0x4',
        note_id: 7, registration: `0x${'11'.repeat(32)}`, deposit_amount: '1000000',
        expiry_ts: '1900000000', final_balance: '750000', conceded: '50000',
        destination: new Array(20).fill(0), withdrawal_nullifier: '0x22', next_nullifier: '0x23',
        valid_until: '1900000600', has_clearance: false
    };
    // A destination distinct from the payer, so its writability is observable.
    const DESTINATION = new Uint8Array(32).fill(9);
    const plan = { mode: 'escape', destination: base58Encode(DESTINATION), public_inputs: publicInputs,
        proof: { backend: 'groth16_bn254', proof: Buffer.alloc(256).toString('base64') } };
    const vault = Buffer.alloc(375);
    vault.set([228, 196, 82, 165, 98, 210, 235, 152]);
    vault[8] = 1;
    vault.fill(4, 75, 107);
    vault.writeBigUInt64LE(BigInt(funding.chain_id), 107);
    vault.fill(0x11, 115, 147);
    for (const [offset, n] of [[246, 1], [278, 2], [310, 3], [342, 4]]) vault[offset] = n;
    const note = Buffer.alloc(110);
    note.set([148, 41, 201, 122, 175, 58, 113, 83]);
    note.set(VAULT, 8);
    note.writeUInt32LE(7, 40);
    note.fill(0x11, 44, 76);
    note.writeBigUInt64LE(1000000n, 76);
    note.writeBigUInt64LE(1900000000n, 84);
    note[92] = 1;
    const pending = Buffer.alloc(173);
    pending.set([61, 103, 179, 177, 148, 199, 63, 171]);
    pending.set(VAULT, 8);
    pending.writeUInt32LE(7, 40);
    pending.writeBigUInt64LE(800000n, 108);
    pending.writeBigUInt64LE(50000n, 116);
    pending.writeBigUInt64LE(750000n, 124);
    pending.set(DESTINATION, 132);
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
    const noteSeed = Buffer.from([7, 0, 0, 0]);
    const expectedMetas = {
        // Finalize must credit the escape destination, so it must be writable.
        escape: [[key(VAULT), true, false], [pda('note', noteSeed), true, false],
            [pda('pending', noteSeed), true, false], [pda('nullifier', feltSeed(0x22)), true, false],
            [pda('nullifier', feltSeed(0x23)), true, false], [key(PAYER), true, true],
            [key(DESTINATION), true, false], [SYSTEM, false, false]],
        mutual: [[key(VAULT), true, false], [pda('note', noteSeed), true, false],
            [pda('nullifier', feltSeed(0x22)), true, false], [key(PAYER), true, true],
            [key(DESTINATION), true, false], [SYSTEM, false, false]],
        finalize: [[key(VAULT), true, false], [pda('note', noteSeed), true, false],
            [pda('pending', noteSeed), true, false], [key(PAYER), true, true], [key(DESTINATION), true, false]]
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
            result = { value: [vault, note, ...(params[0].length === 3 ? [pending] : [])].map(data => ({
                owner: funding.program_id, executable: false, data: [data.toString('base64'), 'base64']
            })) };
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
    }
    note[92] = 2;
    const finalized = await value.prepareSolanaFinalizeEscapeOperation(base58Encode(PAYER), 7);
    assert.equal(Message.from(Uint8Array.from(finalized.transactions[0].bytes)).instructions.length, 1);
    assert.deepEqual(metas(finalized.transactions[0].bytes), expectedMetas.finalize, 'finalize account metas');
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
    const value = runtime();
    const funding = value.config.funding;
    Object.assign(funding, {
        network: 'localnet', protocol_server_url: 'https://operator.invalid',
        indexer_url: 'https://indexer.invalid',
        rpc_url: 'https://rpc.example.test', genesis_hash: base58Encode(new Uint8Array(32).fill(4)),
        wallet_standard_chain: 'solana:localnet', pyth_receiver_program: funding.program_id,
        pyth_price_account: funding.vault_state, pyth_feed_id: `0x${'01'.repeat(32)}`,
        pyth_max_age_seconds: 30, pyth_max_confidence_bps: 100
    });
    value.runtime.pendingDeposit.commitment = `0x${'11'.repeat(32)}`;
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
    const vault = Buffer.alloc(375);
    vault.set([228, 196, 82, 165, 98, 210, 235, 152]);
    vault[8] = 1;
    vault[10] = 1; // paused, and never unpaused
    vault.fill(4, 75, 107);
    vault.writeBigUInt64LE(BigInt(funding.chain_id), 107);
    vault.fill(0x11, 115, 147);
    vault.writeUInt32LE(1, 179); // next_note_id
    const note = Buffer.alloc(110);
    note.set([148, 41, 201, 122, 175, 58, 113, 83]);
    note.set(VAULT, 8);
    note.fill(0x11, 44, 76);
    note.writeBigUInt64LE(10n, 76);
    note.writeBigUInt64LE(1900000000n, 84);
    note[92] = 1;
    const loader = 'BPFLoaderUpgradeab1e11111111111111111111111';
    const programData = base58Encode(new Uint8Array(32).fill(12));
    const accounts = new Map([
        [funding.vault_state, { owner: funding.program_id, executable: false, data: vault }],
        [funding.program_id, { owner: loader, executable: true, data: Buffer.from([2, 0, 0, 0, ...new Uint8Array(32).fill(12)]) }],
        [programData, { owner: loader, executable: false, data: Buffer.from([3, 0, 0, 0, ...new Array(9).fill(0)]) }]
    ]);
    const encode = account => account && { owner: account.owner, executable: account.executable,
        data: [account.data.toString('base64'), 'base64'] };
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
});
