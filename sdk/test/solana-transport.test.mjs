import assert from 'node:assert/strict';
import test from 'node:test';

import { canonicalChainId, chainIdBigInt, sameChainId, U64_MAX }
    from '../services/zkapiLedgerIdentity.mjs';
import { base58Decode, base58Encode, inspectPreparedSolanaMessage, submitPreparedSolanaOperation,
    unsignedSolanaTransaction, validatePreparedSolanaOperation } from '../services/zkapiSolanaTransport.mjs';
import {
    assertSolanaOperationJournal,
    createSolanaOperationJournal,
    recordSolanaFinalizedStage,
    recordSolanaSignedStage,
    recordSolanaSubmittedStage,
    resumeSolanaOperationJournal
} from '../services/zkapiSolanaJournal.mjs';

const PROGRAM = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
const VAULT = Uint8Array.from({ length: 32 }, (_, index) => 100 + index);
const PAYER = Uint8Array.from({ length: 32 }, (_, index) => 200 + index);

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

function message(data = [9, 8, 7]) {
    const accounts = [PAYER, PROGRAM, VAULT];
    return Uint8Array.from([
        1, 0, 2,
        ...shortVec(accounts.length), ...accounts.flatMap(value => [...value]),
        ...new Uint8Array(32).fill(44),
        1,
        1,
        2, 2, 0,
        ...shortVec(data.length), ...data
    ]);
}

function prepared(data, height = 500) {
    return { format: 'solana-legacy-message-v1', bytes: [...message(data)],
        required_signers: [[...PAYER]], last_valid_height: height };
}

function signed(unsigned, fill) {
    const result = new Uint8Array(unsigned);
    result.fill(fill, 1, 65);
    return result;
}

test('full u64 chain identities remain canonical decimal strings', () => {
    assert.equal(chainIdBigInt(U64_MAX.toString()), U64_MAX);
    assert.equal(canonicalChainId(U64_MAX), '18446744073709551615');
    assert.equal(canonicalChainId(1), '1');
    assert.equal(sameChainId('265940889672238678', '265940889672238678'), true);
    assert.equal(sameChainId('1', 2), false);
    for (const invalid of [Number.MAX_SAFE_INTEGER + 1, '-1', '01', '1.0', U64_MAX + 1n]) {
        assert.throws(() => canonicalChainId(invalid));
    }
});

test('prepared legacy messages are inspected and wrapped without mutation', () => {
    assert.deepEqual(base58Decode(base58Encode(PROGRAM), 32), PROGRAM);
    const original = message();
    const inspected = inspectPreparedSolanaMessage(original);
    assert.deepEqual(inspected.payer, PAYER);
    assert.deepEqual(inspected.program, PROGRAM);
    const transaction = unsignedSolanaTransaction(original);
    assert.equal(transaction.length, original.length + 65);
    assert.equal(transaction[0], 1);
    assert.ok(transaction.slice(1, 65).every(value => value === 0));
    assert.deepEqual(transaction.slice(65), original);
});

test('real ledger heap and CU prefixes pass while extra programs and fees fail closed', () => {
    const budgetProgram = base58Decode('ComputeBudget111111111111111111111111111111', 32);
    const u32 = value => [...new Uint8Array(Uint32Array.of(value).buffer)];
    const heap = [3, 0, 5, 1, ...u32(131_072)];
    const units = [3, 0, 5, 2, ...u32(1_400_000)];
    const build = (prefixes, { budget = budgetProgram, vaultIndices = [2, 0] } = {}) => ({
        transactions: [{ ...prepared([9]), bytes: [
            1, 0, 3, 4, ...PAYER, ...PROGRAM, ...VAULT, ...budget,
            ...new Uint8Array(32).fill(44),
            prefixes.length + 1, ...prefixes.flat(),
            1, vaultIndices.length, ...vaultIndices, 1, 9
        ] }]
    });
    const validate = operation => validatePreparedSolanaOperation({
        operation, payer: PAYER, programId: PROGRAM, vaultState: VAULT
    });
    const operation = build([heap, units]);
    assert.equal(validate(operation).length, 1);
    const inspected = inspectPreparedSolanaMessage(operation.transactions[0].bytes);
    assert.deepEqual(inspected.program, PROGRAM);
    assert.deepEqual(inspected.vaultAccounts, [VAULT, PAYER]);
    assert.equal(unsignedSolanaTransaction(operation.transactions[0].bytes).length,
        operation.transactions[0].bytes.length + 65);
    for (const invalid of [
        build([heap, units], { budget: new Uint8Array(32).fill(88) }),
        build([heap, heap]),
        build([[3, 0, 9, 3, ...new Uint8Array(8).fill(255)]]),
        build([[3, 0, 5, 2, ...u32(1_400_001)]]),
        build([[3, 0, 5, 1, ...u32(131_073)]]),
        build([heap], { vaultIndices: [0] }),
        build([heap], { vaultIndices: [0, 2] }),
        build([heap], { vaultIndices: [0, 9] })
    ]) assert.throws(() => validate(invalid));
});

// Escape, close, defeat, raise, retire, finalize and claim are each ONE
// direct transaction: the ledger's heap+CU prefix, then the vault
// instruction. The vault pin is on the vault instruction's FIRST account,
// not on the message key order, and it holds for the read-only vault that
// root-free disputes (defeat/raise) use.
test('single-transaction exits and disputes keep the budget prefix and the vault-first pin', () => {
    const budgetProgram = base58Decode('ComputeBudget111111111111111111111111111111', 32);
    const u32 = value => [...new Uint8Array(Uint32Array.of(value).buffer)];
    const heap = [7, 0, 5, 1, ...u32(131_072)];
    const units = [7, 0, 5, 2, ...u32(1_400_000)];
    const key = fill => new Uint8Array(32).fill(fill);
    // Writable non-signers first, then the read-only vault, programs last.
    const keys = [PAYER, key(11), key(12), key(13), key(14), VAULT, PROGRAM, budgetProgram];
    const vaultInstruction = (indices, dataLength) => [
        6, indices.length, ...indices, ...shortVec(dataLength), ...new Uint8Array(dataLength).fill(3)
    ];
    const build = (indices, dataLength = 663) => ({
        transactions: [{ ...prepared([9]), bytes: [
            1, 0, 3, keys.length, ...keys.flatMap(value => [...value]),
            ...new Uint8Array(32).fill(44),
            3, ...heap, ...units, ...vaultInstruction(indices, dataLength)
        ] }]
    });
    const validate = operation => validatePreparedSolanaOperation({
        operation, payer: PAYER, programId: PROGRAM, vaultState: VAULT
    });
    // Defeat: vault, note, pending, N, N+, payer (escape-sized payload).
    const defeat = build([5, 1, 2, 3, 4, 0]);
    assert.equal(validate(defeat).length, 1);
    const inspected = inspectPreparedSolanaMessage(defeat.transactions[0].bytes);
    assert.deepEqual(inspected.vaultAccounts[0], VAULT);
    assert.deepEqual(inspected.program, PROGRAM);
    assert.ok(defeat.transactions[0].bytes.length + 65 <= 1_232);
    // Raise: vault, note, pending, payer.
    assert.equal(validate(build([5, 1, 2, 0], 361)).length, 1);
    for (const invalid of [
        // The vault is present but not the vault instruction's first account.
        build([1, 5, 2, 3, 4, 0]),
        // The vault appears only as a trailing remaining account.
        build([1, 2, 3, 4, 0, 5]),
        // A message that no longer fits one packet is refused before signing.
        build([5, 1, 2, 3, 4, 0], 900)
    ]) assert.throws(() => validate(invalid));
});

test('ordered transport journals signed bytes before broadcast and can resume', async () => {
    const operation = { transactions: [prepared([1], 501), prepared([2], 502)] };
    const events = [];
    const saved = [];
    let signCalls = 0;
    const account = { publicKey: PAYER, features: ['solana:signTransaction'], chains: ['solana:devnet'] };
    const wallet = { features: { 'solana:signTransaction': { signTransaction: async (...inputs) => {
        signCalls += 1;
        return inputs.map((input, offset) => ({ signedTransaction: signed(input.transaction, 10 + signCalls + offset) }));
    } } } };
    const first = await submitPreparedSolanaOperation({ wallet, account, chain: 'solana:devnet', operation,
        programId: PROGRAM, vaultState: VAULT,
        onSigned: async event => { events.push(`journal:${event.index}`); saved[event.index] = event.signedTransaction; },
        onSubmitted: async event => { events.push(`submitted:${event.index}`); },
        sendSignedTransaction: async event => { events.push(`send:${event.index}`); return event.signature; },
        confirmTransaction: async event => { events.push(`confirm:${event.index}`); return { slot: String(50 + event.index) }; },
        onConfirmed: async event => { events.push(`finalized:${event.index}`); }
    });
    assert.equal(signCalls, 2);
    assert.deepEqual(events, [
        'journal:0', 'send:0', 'submitted:0', 'confirm:0', 'finalized:0',
        'journal:1', 'send:1', 'submitted:1', 'confirm:1', 'finalized:1'
    ]);
    assert.equal(first.length, 2);
    assert.equal(first[0].signature, base58Encode(saved[0].slice(1, 65)));
    assert.equal(first[1].confirmation.slot, '51');

    events.length = 0;
    await submitPreparedSolanaOperation({ wallet, account, chain: 'solana:devnet', operation,
        programId: PROGRAM, vaultState: VAULT, signedTransactions: saved, startIndex: 1,
        onSigned: async () => assert.fail('resume must not reopen the wallet'),
        sendSignedTransaction: async event => { events.push(`send:${event.index}`); return event.signature; },
        confirmTransaction: async event => { events.push(`confirm:${event.index}`); }
    });
    assert.equal(signCalls, 2);
    assert.deepEqual(events, ['send:1', 'confirm:1']);
});

test('durable stage journal resumes exact signed bytes and advances only in order', () => {
    const operation = { transactions: [prepared([1], 501), prepared([2], 502)] };
    let journal = createSolanaOperationJournal({
        kind: 'deposit',
        operationId: 'deposit-1',
        deploymentId: 'dagon-localnet',
        backend: 'dagon.solana.groth16.v1',
        chainId: U64_MAX.toString(),
        protocolBinding: `0x${'11'.repeat(32)}`,
        programId: base58Encode(PROGRAM),
        vault: base58Encode(VAULT),
        payer: base58Encode(PAYER),
        operation,
        now: 10
    });
    assert.equal(resumeSolanaOperationJournal(journal).startIndex, 0);
    assert.throws(() => recordSolanaSubmittedStage(journal, { index: 0, signature: 'bad' }));

    const signed0 = signed(unsignedSolanaTransaction(message([1])), 7);
    const signature0 = base58Encode(signed0.slice(1, 65));
    journal = recordSolanaSignedStage(journal, {
        index: 0,
        format: 'solana-legacy-transaction-v1',
        signature: signature0,
        signedTransaction: signed0
    }, 11);
    assert.deepEqual(resumeSolanaOperationJournal(journal).signedTransactions[0], signed0);
    assert.throws(() => recordSolanaSignedStage(journal, {
        index: 1,
        format: 'solana-legacy-transaction-v1',
        signature: signature0,
        signedTransaction: signed0
    }), /previous stage finalizes/);
    journal = recordSolanaSubmittedStage(journal, { index: 0, signature: signature0 }, 12);
    journal = recordSolanaFinalizedStage(journal, {
        index: 0,
        signature: signature0,
        confirmation: { slot: '9007199254740992' }
    }, 13);
    assert.equal(resumeSolanaOperationJournal(journal).startIndex, 1);

    const signed1 = signed(unsignedSolanaTransaction(message([2])), 8);
    const signature1 = base58Encode(signed1.slice(1, 65));
    journal = recordSolanaSignedStage(journal, {
        index: 1,
        format: 'solana-legacy-transaction-v1',
        signature: signature1,
        signedTransaction: signed1
    }, 14);
    journal = recordSolanaSubmittedStage(journal, { index: 1, signature: signature1 }, 15);
    journal = recordSolanaFinalizedStage(journal, {
        index: 1,
        signature: signature1,
        confirmation: { slot: '9007199254740993' }
    }, 16);
    const resumed = resumeSolanaOperationJournal(journal);
    assert.equal(resumed.completed, true);
    assert.equal(resumed.startIndex, 2);
    assert.equal(assertSolanaOperationJournal(journal), journal);

    const tampered = structuredClone(journal);
    tampered.stages[0].signedTransaction[tampered.stages[0].signedTransaction.length - 1] ^= 1;
    assert.throws(() => assertSolanaOperationJournal(tampered), /does not match/);
});

test('transport rejects signer, program, vault, and wallet message substitution', async () => {
    const account = { publicKey: PAYER, features: ['solana:signTransaction'], chains: ['solana:devnet'] };
    const operation = { transactions: [prepared([1])] };
    const invoke = async (patch = {}) => submitPreparedSolanaOperation({
        account, chain: 'solana:devnet', operation, programId: PROGRAM, vaultState: VAULT,
        wallet: { features: { 'solana:signTransaction': { signTransaction: async ({ transaction }) => [{
            signedTransaction: patch.mutate ? signed(Uint8Array.from([...transaction.slice(0, -1), 99]), 5)
                : signed(transaction, 5)
        }] } } },
        sendSignedTransaction: async event => event.signature,
        confirmTransaction: async () => {},
        ...patch
    });
    await assert.rejects(invoke({ programId: new Uint8Array(32).fill(9) }), /different program/);
    await assert.rejects(invoke({ vaultState: new Uint8Array(32).fill(9) }), /pinned vault/);
    await assert.rejects(invoke({ account: { ...account, publicKey: new Uint8Array(32).fill(9) } }), /different wallet/);
    await assert.rejects(invoke({ mutate: true }), /changed the prepared/);
});
