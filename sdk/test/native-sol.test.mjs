import assert from 'node:assert/strict';
import test from 'node:test';

import { configureBrowserSdk } from '../configure.js';
import { base58Encode } from '../services/zkapiSolanaTransport.mjs';
import { assertSolanaDepositsOpen, assertSolanaVault, confirmFinalizedSolanaTransaction, decodeSolanaNoteState,
    decodeSolanaPendingWithdrawal, decodeSolanaVaultState, readFinalizedSolanaOperationState,
    readFinalizedSolanaTime, sendSignedSolanaTransaction, solanaUnitsForUsd, solanaUsdMicros, UPGRADEABLE_LOADER,
    validateSolanaFunding, validateSolanaQuote }
    from '../services/zkapiNativeSol.mjs';

let rpcHandler = null;
configureBrowserSdk({ transport: async (url, init) => rpcHandler(url, init) });

const key = fill => base58Encode(new Uint8Array(32).fill(fill));
const now = 1_900_000_010;
const funding = {
    ledger_backend: 'dagon.solana.groth16.v1',
    billing_asset: 'native_sol',
    billing_unit: 'lamports',
    base_units_per_asset: '1000000000',
    chain_id: '18446744073709551615',
    contract_address: `0x${'11'.repeat(32)}`,
    network: 'localnet',
    program_id: key(1),
    vault_state: key(2),
    genesis_hash: key(3),
    wallet_standard_chain: 'solana:devnet',
    pyth_receiver_program: key(4),
    pyth_price_account: key(5),
    pyth_feed_id: `0x${'06'.repeat(32)}`,
    pyth_max_age_seconds: 30,
    pyth_max_confidence_bps: 100,
    rpc_url: 'https://rpc.example.test',
    protocol_server_url: 'https://api.example.test'
};
const quote = {
    asset: 'native_sol', source: 'pyth_receiver', credit_unit: 'lamports',
    base_units_per_asset: 1_000_000_000, chain_id: funding.chain_id,
    deployment_binding: funding.contract_address, backend: funding.ledger_backend,
    network: funding.network, vault: funding.vault_state,
    receiver_program: funding.pyth_receiver_program, price_account: funding.pyth_price_account,
    feed_id: funding.pyth_feed_id, price: '15000000000', confidence: '150000000',
    exponent: -8, published_at: now - 10, expires_at: now + 20, posted_slot: '123456789'
};

test('native SOL pins and quotes retain full-u64 identity and conservative Pyth arithmetic', () => {
    assert.equal(validateSolanaFunding(funding), funding);
    assert.equal(validateSolanaQuote(quote, funding, { now }), quote);
    assert.equal(solanaUsdMicros(1_000_000_000n, quote), 148_500_000n);
    assert.equal(solanaUnitsForUsd('148.5', quote), 1_000_000_000n);
    assert.equal(solanaUnitsForUsd('1', quote), 6_734_007n);
});

test('native SOL quote validation fails closed on deployment, confidence, time, and chain changes', () => {
    const invalid = [
        { chain_id: '18446744073709551614' },
        { deployment_binding: `0x${'12'.repeat(32)}` },
        { confidence: quote.price },
        { published_at: now + 1, expires_at: now + 31 },
        { expires_at: now + 21 },
        { exponent: -19 },
        { vault: key(9) }
    ];
    for (const patch of invalid) {
        assert.throws(() => validateSolanaQuote({ ...quote, ...patch }, funding, { now }));
    }
    assert.throws(() => validateSolanaFunding({ ...funding, chain_id: Number.MAX_SAFE_INTEGER + 1 }));
    assert.throws(() => validateSolanaFunding({ ...funding, rpc_url: 'https://rpc.example.test/?key=secret' }));
});

function rpcResponse(result) {
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result }), {
        status: 200,
        headers: { 'content-type': 'application/json' }
    });
}

function writeU32(bytes, offset, value) {
    new DataView(bytes.buffer).setUint32(offset, value, true);
}

function writeU64(bytes, offset, value) {
    let remaining = BigInt(value);
    for (let index = 0; index < 8; index += 1) {
        bytes[offset + index] = Number(remaining & 0xffn);
        remaining >>= 8n;
    }
}

function vaultData() {
    const bytes = new Uint8Array(375);
    bytes.set([228, 196, 82, 165, 98, 210, 235, 152]);
    bytes[8] = 1;
    bytes[9] = 254;
    bytes[10] = 0;
    bytes.set(new Uint8Array(32).fill(9), 11);
    bytes.set(new Uint8Array(32).fill(10), 43);
    bytes.set(new Uint8Array(32).fill(3), 75);
    writeU64(bytes, 107, BigInt(funding.chain_id));
    bytes.set(new Uint8Array(32).fill(0x11), 115);
    bytes.set(new Uint8Array(32).fill(0x12), 147);
    writeU32(bytes, 179, 17);
    writeU64(bytes, 183, 86_400n);
    writeU64(bytes, 191, 60n);
    writeU64(bytes, 199, 50_000n);
    writeU64(bytes, 207, 1_000_000n);
    bytes.set(new Uint8Array(32).fill(0x13), 215);
    bytes.set(new Uint8Array(32).fill(0x14), 247);
    bytes.set(new Uint8Array(32).fill(0x15), 279);
    bytes.set(new Uint8Array(32).fill(0x16), 311);
    writeU64(bytes, 343, 1_900_000_000n);
    writeU64(bytes, 351, 1_899_000_000n);
    writeU64(bytes, 359, 3_600n);
    writeU64(bytes, 367, 650_000n);
    return bytes;
}

function noteData(noteId = 17, status = 1) {
    const bytes = new Uint8Array(110);
    bytes.set([148, 41, 201, 122, 175, 58, 113, 83]);
    bytes.set(new Uint8Array(32).fill(2), 8);
    writeU32(bytes, 40, noteId);
    bytes.set(new Uint8Array(32).fill(0x21), 44);
    writeU64(bytes, 76, 123_456n);
    writeU64(bytes, 84, 1_900_086_400n);
    bytes[92] = status;
    bytes[93] = 7;
    writeU64(bytes, 94, 1_900_172_800n);
    writeU64(bytes, 102, 3_600n);
    return bytes;
}

function pendingData(noteId = 17) {
    const bytes = new Uint8Array(173);
    bytes.set([61, 103, 179, 177, 148, 199, 63, 171]);
    bytes.set(new Uint8Array(32).fill(2), 8);
    writeU32(bytes, 40, noteId);
    bytes.set(new Uint8Array(32).fill(0x31), 44);
    bytes.set(new Uint8Array(32).fill(0x32), 76);
    writeU64(bytes, 108, 123_000n);
    writeU64(bytes, 116, 3_000n);
    writeU64(bytes, 124, 120_000n);
    bytes.set(new Uint8Array(32).fill(0x33), 132);
    writeU64(bytes, 164, 1_900_000_100n);
    bytes[172] = 8;
    return bytes;
}

function shortVec(value) {
    return [value];
}

function preparedOperation(accounts) {
    const message = Uint8Array.from([
        1, 0, 2,
        ...shortVec(accounts.length), ...accounts.flatMap(value => [...value]),
        ...new Uint8Array(32).fill(4),
        1,
        1,
        4, 2, 0, 3, 4,
        1, 7
    ]);
    return { transactions: [{
        format: 'solana-legacy-message-v1', bytes: [...message],
        required_signers: [[...accounts[0]]], last_valid_height: 500
    }] };
}

test('leaf-bound Solana note statuses decode; the removed challenged status 3 is rejected', () => {
    const expected = { 1: 'active', 2: 'pending_withdrawal', 4: 'closed', 5: 'retired' };
    for (const [status, name] of Object.entries(expected)) {
        const decoded = decodeSolanaNoteState(noteData(17, Number(status)));
        assert.equal(decoded.status, name);
        assert.equal(decoded.noteId, 17);
        assert.equal(decoded.amount, '123456');
    }
    for (const invalid of [0, 3, 6, 255]) {
        assert.throws(() => decodeSolanaNoteState(noteData(17, invalid)), /invalid status/);
    }
});

test('native SOL account decoders preserve u64 values and canonical identities', () => {
    const vault = decodeSolanaVaultState(vaultData());
    assert.equal(vault.chainId, funding.chain_id);
    assert.equal(vault.protocolBinding, funding.contract_address);
    assert.equal(vault.nextNoteId, 17);
    assert.equal(vault.totalCredits, '1000000');
    assert.equal(vault.pausedAt, '1900000000');
    assert.equal(vault.lastPauseEnd, '1899000000');
    assert.equal(vault.totalPausedDuration, '3600');
    assert.equal(vault.treasuryAccrued, '650000');
    const note = decodeSolanaNoteState(noteData());
    assert.equal(note.vault, funding.vault_state);
    assert.equal(note.noteId, 17);
    assert.equal(note.amount, '123456');
    assert.equal(note.status, 'active');
    assert.equal(note.claimableAfter, '1900172800');
    assert.equal(note.pausedOffset, '3600');
    const pending = decodeSolanaPendingWithdrawal(pendingData());
    assert.equal(pending.noteId, 17);
    assert.equal(pending.nullifier, `0x${'31'.repeat(32)}`);
    assert.equal(pending.nextNullifier, `0x${'32'.repeat(32)}`);
    assert.equal(pending.stateBalance, '123000');
    assert.equal(pending.conceded, '3000');
    assert.equal(pending.finalBalance, '120000');
    assert.equal(pending.destination, base58Encode(new Uint8Array(32).fill(0x33)));
    assert.equal(pending.deadline, '1900000100');
    assert.equal(pending.bump, 8);
    assert.equal('activeRoot' in pending, false);
    assert.throws(() => decodeSolanaVaultState(vaultData().slice(0, -1)));
    assert.throws(() => decodeSolanaNoteState(noteData().slice(0, 94)), /invalid canonical/);
    assert.throws(() => decodeSolanaPendingWithdrawal(pendingData().slice(0, 157)), /invalid canonical/);
    // A raise keeps finalBalance + conceded == stateBalance; anything else is forged.
    const inconsistent = pendingData();
    writeU64(inconsistent, 116, 2_999n);
    assert.throws(() => decodeSolanaPendingWithdrawal(inconsistent), /inconsistent concession/);
});

test('finalized operation-state reader accepts only matching program-owned note accounts', async () => {
    const payer = new Uint8Array(32).fill(6);
    const program = new Uint8Array(32).fill(1);
    const vault = new Uint8Array(32).fill(2);
    const noteAddress = new Uint8Array(32).fill(7);
    const pendingAddress = new Uint8Array(32).fill(8);
    const accounts = [payer, program, vault, noteAddress, pendingAddress];
    let noteStatus = 2;
    rpcHandler = async (_url, init) => {
        const request = JSON.parse(init.body);
        assert.equal(request.method, 'getMultipleAccounts');
        return rpcResponse({ context: { slot: 900719 }, value: [
            null,
            null,
            null,
            { owner: funding.program_id, executable: false,
                data: [Buffer.from(noteData(17, noteStatus)).toString('base64'), 'base64'] },
            { owner: funding.program_id, executable: false,
                data: [Buffer.from(pendingData()).toString('base64'), 'base64'] }
        ] });
    };
    const state = await readFinalizedSolanaOperationState(
        funding,
        preparedOperation(accounts),
        { noteId: 17 }
    );
    assert.equal(state.slot, '900719');
    assert.equal(state.note.address, base58Encode(noteAddress));
    assert.equal(state.note.status, 'pending_withdrawal');
    assert.equal(state.pending.address, base58Encode(pendingAddress));
    assert.equal(state.pending.nextNullifier, `0x${'32'.repeat(32)}`);
    assert.equal(state.pending.stateBalance, '123000');
    // A mutual close keeps the note account (and its leaf) as `closed`.
    noteStatus = 4;
    const closed = await readFinalizedSolanaOperationState(
        funding,
        preparedOperation(accounts),
        { noteId: 17 }
    );
    assert.equal(closed.note.status, 'closed');
});

test('native SOL RPC adapter submits exact bytes and waits for finalized status', async () => {
    const signature = base58Encode(new Uint8Array(64).fill(7));
    const calls = [];
    const results = [
        signature,
        { context: { slot: 10 }, value: [null] },
        499,
        { context: { slot: 12 }, value: [{ slot: 501, confirmations: null,
            confirmationStatus: 'finalized', err: null }] }
    ];
    rpcHandler = async (_url, init) => {
        const request = JSON.parse(init.body);
        calls.push(request);
        return rpcResponse(results.shift());
    };
    assert.equal(await sendSignedSolanaTransaction(funding, {
        bytes: new Uint8Array([1, 2, 3]), signature
    }), signature);
    const confirmation = await confirmFinalizedSolanaTransaction(funding, {
        signature, lastValidHeight: 500
    }, { pollIntervalMs: 0, signal: AbortSignal.timeout(1_000) });
    assert.deepEqual(confirmation, {
        signature, slot: '501', confirmationStatus: 'finalized'
    });
    assert.deepEqual(calls.map(call => call.method), [
        'sendTransaction', 'getSignatureStatuses', 'getBlockHeight', 'getSignatureStatuses'
    ]);
    assert.equal(calls[0].params[1].skipPreflight, false);
    assert.equal(calls[0].params[1].preflightCommitment, 'confirmed');
    assert.equal(calls[1].params[1].searchTransactionHistory, true);
});

test('native SOL RPC adapter fails closed after an unknown signature expires', async () => {
    const signature = base58Encode(new Uint8Array(64).fill(9));
    const results = [
        { context: { slot: 10 }, value: [null] },
        501
    ];
    rpcHandler = async () => rpcResponse(results.shift());
    await assert.rejects(confirmFinalizedSolanaTransaction(funding, {
        signature, lastValidHeight: 500
    }, { pollIntervalMs: 0, signal: AbortSignal.timeout(1_000) }), error => (
        error.code === 'solana_blockhash_expired'
        && error.lastValidHeight === 500
        && error.observedHeight === 501
    ));
});

// Threat: a malicious vault owner sets the pause flag and never clears it. The
// program reopens exits after MAX_PAUSE_DURATION and lets claim_expired sweep
// at expiry + the capped pause, so a wallet that refused to load a flagged
// vault would hand the owner every note. Only new deposits refuse the flag.
test('a paused Solana vault still loads for exits and refuses only new deposits', async () => {
    const programData = key(12);
    const accounts = new Map([
        [funding.vault_state, { owner: funding.program_id, executable: false, data: vaultData() }],
        [funding.program_id, { owner: UPGRADEABLE_LOADER, executable: true,
            data: Uint8Array.from([2, 0, 0, 0, ...new Uint8Array(32).fill(12)]) }],
        [programData, { owner: UPGRADEABLE_LOADER, executable: false, data: Uint8Array.from([3, 0, 0, 0, ...new Array(9).fill(0)]) }]
    ]);
    accounts.get(funding.vault_state).data[10] = 1;
    rpcHandler = async (_url, init) => {
        const { method, params } = JSON.parse(init.body);
        if (method === 'getGenesisHash') return rpcResponse(funding.genesis_hash);
        assert.equal(method, 'getAccountInfo');
        const value = accounts.get(params[0]);
        return rpcResponse({ context: { slot: 1 }, value: { ...value,
            data: [Buffer.from(value.data).toString('base64'), 'base64'] } });
    };
    const state = await assertSolanaVault(funding);
    assert.equal(state.paused, true);
    assert.throws(() => assertSolanaDepositsOpen(state), /paused/);
    accounts.get(funding.vault_state).data[10] = 0;
    assert.equal(assertSolanaDepositsOpen(await assertSolanaVault(funding)).paused, false);
});

test('the exit freeze reads finalized block time from the pinned cluster only', async () => {
    const calls = [];
    let genesis = funding.genesis_hash;
    let blockTime = now;
    rpcHandler = async (url, init) => {
        assert.equal(url, funding.rpc_url);
        const { method, params } = JSON.parse(init.body);
        calls.push([method, params]);
        if (method === 'getGenesisHash') return rpcResponse(genesis);
        if (method === 'getSlot') return rpcResponse(4242);
        assert.equal(method, 'getBlockTime');
        return rpcResponse(blockTime);
    };
    assert.equal(await readFinalizedSolanaTime(funding), now);
    assert.deepEqual(calls, [['getGenesisHash', []], ['getSlot', [{ commitment: 'finalized' }]], ['getBlockTime', [4242]]]);
    blockTime = -1;
    await assert.rejects(readFinalizedSolanaTime(funding), /invalid block time/);
    genesis = key(9);
    await assert.rejects(readFinalizedSolanaTime(funding), /wrong cluster/);
});
