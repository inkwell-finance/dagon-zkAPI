import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { keccak_256 } from '@noble/hashes/sha3';
import { AddressLookupTableAccount, ComputeBudgetProgram, Message, PublicKey, SystemProgram, Transaction,
    TransactionInstruction, TransactionMessage } from '@solana/web3.js';

import { configureBrowserSdk } from '../configure.js';
import { base58Decode, base58Encode, inspectPreparedSolanaMessage } from '../services/zkapiSolanaTransport.mjs';
import { ASSOCIATED_TOKEN_PROGRAM_ID, assertSolanaDepositsOpen, assertSolanaVault, confirmFinalizedSolanaTransaction,
    createUsdcAccountIdempotentInstruction, decodeSolanaNoteState, decodeSolanaPendingWithdrawal,
    decodeSolanaVaultState, decodeUsdcTokenAccount, leaseLimitUsd, readFinalizedSolanaOperationState,
    readFinalizedSolanaTime, readUsdcTokenAccount, sendSignedSolanaTransaction, TOKEN_2022_PROGRAM_ID,
    TOKEN_PROGRAM_ID, UPGRADEABLE_LOADER, USDC_MINT, usdcAssociatedTokenAddress, usdcBaseUnits,
    validatePreparedSolanaDeposit, validateSolanaFunding, vaultTokenAddress } from '../services/zkapiUsdc.mjs';
import { prepareLocalUsdcAccountCreation } from '../services/zkapiSolanaExit.mjs';
import { CHAT_SPENDING_TIER_USD } from '../services/zkapiRequestCompat.mjs';
import { rpcAccount, tokenAccountData, usdcFunding, vaultAccountData } from './helpers/usdc-fixtures.mjs';

let rpcHandler = null;
configureBrowserSdk({ transport: async (url, init) => rpcHandler(url, init) });

const key = fill => base58Encode(new Uint8Array(32).fill(fill));
const now = 1_900_000_010;
const funding = usdcFunding({
    chain_id: '18446744073709551615',
    genesis_hash: key(3),
    wallet_standard_chain: 'solana:devnet',
    rpc_url: 'https://rpc.example.test',
    protocol_server_url: 'https://api.example.test'
});
const PAYER = key(6);

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

test('a USDC deployment pins Circle USDC, classic SPL Token, micro-USDC billing and no oracle', () => {
    assert.equal(validateSolanaFunding(funding), funding);
    for (const [changes, error] of [
        [{ billing_asset: 'erc20' }, /Unsupported Solana billing/],
        [{ billing_unit: 'micro_usd' }, /invalid protocol or billing/],
        [{ base_units_per_asset: '1000000000' }, /invalid protocol or billing/],
        [{ usdc_mint: key(9) }, /Circle USDC under the classic SPL Token/],
        [{ token_program: TOKEN_2022_PROGRAM_ID }, /classic SPL Token/],
        [{ associated_token_program: SystemProgram.programId.toBase58() }, /classic SPL Token/],
        [{ rpc_url: 'http://rpc.example.test' }, /trusted HTTPS or loopback RPC/]
    ]) {
        assert.throws(() => validateSolanaFunding({ ...funding, ...changes }), error);
    }
});

test('a lease limit is solvency_bound / 1e6 USD, never rounded above the bound (server micro_usd_to_usd)', () => {
    for (const tier of CHAT_SPENDING_TIER_USD) {
        const bound = usdcBaseUnits(String(tier));
        assert.equal(bound, BigInt(Math.round(tier * 1_000_000)));
        assert.equal(leaseLimitUsd(bound), tier);
    }
    assert.equal(leaseLimitUsd(1), 0.000001);
    // 123 / 1e6 rounds up in f64: the server steps it one ulp down.
    assert.ok((123 / 1e6) * 1e6 > 123);
    assert.ok(leaseLimitUsd(123) < 123 / 1e6);
    for (const bound of [1, 123, 246, 253, 1_234_567, 4_500_000, Number.MAX_SAFE_INTEGER]) {
        const limit = leaseLimitUsd(bound);
        assert.ok(limit * 1e6 <= bound, `${bound} rounds down`);
        const exact = bound / 1e6;
        assert.ok(limit === exact || (exact * 1e6 > bound && limit < exact), `${bound} steps at most one ulp`);
    }
    assert.throws(() => leaseLimitUsd(0), /outside the lease range/);
    assert.throws(() => leaseLimitUsd(2n ** 53n), /outside the lease range/);
    assert.throws(() => usdcBaseUnits('1.0000001'), /no more than 6 decimal places/);
    assert.throws(() => usdcBaseUnits('0'), /positive USDC amount/);
});

function vaultData() {
    const bytes = new Uint8Array(448);
    bytes.set([228, 196, 82, 165, 98, 210, 235, 152]);
    bytes[8] = 1;
    bytes[9] = 254;
    bytes[10] = 0;
    bytes.set(new Uint8Array(32).fill(9), 11);
    bytes.set(new Uint8Array(32).fill(10), 43);
    bytes.set(base58Decode(USDC_MINT, 32), 75);
    bytes.set(new Uint8Array(32).fill(0x0c), 107);
    bytes[139] = 253;
    bytes.set(new Uint8Array(32).fill(3), 140);
    writeU64(bytes, 172, BigInt(funding.chain_id));
    bytes.set(new Uint8Array(32).fill(0x11), 180);
    bytes.set(new Uint8Array(32).fill(0x12), 212);
    writeU32(bytes, 244, 17);
    writeU64(bytes, 248, 86_400n);
    writeU64(bytes, 256, 60n);
    writeU64(bytes, 264, 1_000_000n);
    writeU64(bytes, 272, 9_000_000n);
    bytes.set(new Uint8Array(32).fill(0x13), 280);
    bytes.set(new Uint8Array(32).fill(0x14), 312);
    bytes.set(new Uint8Array(32).fill(0x15), 344);
    bytes.set(new Uint8Array(32).fill(0x16), 376);
    writeU64(bytes, 408, 1_900_000_000n);
    writeU64(bytes, 416, 1_899_000_000n);
    writeU64(bytes, 424, 3_600n);
    writeU64(bytes, 432, 650_000n);
    writeU64(bytes, 440, 120_000n);
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

function pendingData(noteId = 17, stage = 0) {
    const bytes = new Uint8Array(206);
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
    bytes.set(new Uint8Array(32).fill(0x34), 173);
    bytes[205] = stage;
    return bytes;
}

function preparedOperation(accounts) {
    const message = Uint8Array.from([
        1, 0, 2,
        accounts.length, ...accounts.flatMap(value => [...value]),
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

test('the 448-byte VaultState and 206-byte PendingWithdrawal decode at their USDC offsets', () => {
    const vault = decodeSolanaVaultState(vaultData());
    assert.equal(vault.authority, key(9));
    assert.equal(vault.treasuryToken, key(10));
    assert.equal(vault.mint, USDC_MINT);
    assert.equal(vault.vaultToken, key(0x0c));
    assert.equal(vault.vaultTokenBump, 253);
    assert.equal(vault.genesisHash, key(3));
    assert.equal(vault.chainId, funding.chain_id);
    assert.equal(vault.protocolBinding, funding.contract_address);
    assert.equal(vault.root, `0x${'12'.repeat(32)}`);
    assert.equal(vault.nextNoteId, 17);
    assert.equal(vault.noteTtl, '86400');
    assert.equal(vault.challengePeriod, '60');
    assert.equal(vault.requestChargeCap, '1000000');
    assert.equal(vault.totalCredits, '9000000');
    assert.equal(vault.stateSigningKeyX, `0x${'13'.repeat(32)}`);
    assert.equal(vault.clearanceSigningKeyY, `0x${'16'.repeat(32)}`);
    assert.equal(vault.pausedAt, '1900000000');
    assert.equal(vault.lastPauseEnd, '1899000000');
    assert.equal(vault.totalPausedDuration, '3600');
    assert.equal(vault.treasuryAccrued, '650000');
    assert.equal(vault.deferredPayouts, '120000');
    const pending = decodeSolanaPendingWithdrawal(pendingData());
    assert.equal(pending.noteId, 17);
    assert.equal(pending.nullifier, `0x${'31'.repeat(32)}`);
    assert.equal(pending.nextNullifier, `0x${'32'.repeat(32)}`);
    assert.equal(pending.stateBalance, '123000');
    assert.equal(pending.conceded, '3000');
    assert.equal(pending.finalBalance, '120000');
    assert.equal(pending.destination, key(0x33));
    assert.equal(pending.deadline, '1900000100');
    assert.equal(pending.bump, 8);
    assert.equal(pending.rentPayer, key(0x34));
    assert.equal(pending.stage, 'open');
    assert.equal(decodeSolanaPendingWithdrawal(pendingData(17, 1)).stage, 'payout_parked');
    assert.equal(decodeSolanaPendingWithdrawal(pendingData(17, 2)).stage, 'rent_parked');
    assert.throws(() => decodeSolanaPendingWithdrawal(pendingData(17, 3)), /invalid stage/);
    // The pre-USDC sizes (375 and 173 bytes) are no longer canonical.
    assert.throws(() => decodeSolanaVaultState(vaultData().slice(0, 375)), /invalid canonical/);
    assert.throws(() => decodeSolanaVaultState(vaultData().slice(0, -1)), /invalid canonical/);
    assert.throws(() => decodeSolanaNoteState(noteData().slice(0, 94)), /invalid canonical/);
    assert.throws(() => decodeSolanaPendingWithdrawal(pendingData().slice(0, 173)), /invalid canonical/);
    // A raise keeps finalBalance + conceded == stateBalance; anything else is forged.
    const inconsistent = pendingData();
    writeU64(inconsistent, 116, 2_999n);
    assert.throws(() => decodeSolanaPendingWithdrawal(inconsistent), /inconsistent concession/);
});

// An independent PDA derivation: sha256(seeds || bump || program || marker),
// the first candidate (from bump 255 down) off the ed25519 curve.
function derivePda(seeds, programId) {
    for (let bump = 255; bump >= 0; bump -= 1) {
        const hash = createHash('sha256');
        for (const seed of seeds) hash.update(seed);
        hash.update(Uint8Array.of(bump)).update(base58Decode(programId, 32)).update('ProgramDerivedAddress');
        const candidate = hash.digest();
        if (!PublicKey.isOnCurve(candidate)) return base58Encode(candidate);
    }
    throw new Error('no PDA');
}

test('the canonical USDC account is the ATA PDA [owner, Token program, USDC mint]', () => {
    for (const owner of [PAYER, key(0x55), funding.vault_state]) {
        assert.equal(usdcAssociatedTokenAddress(owner), derivePda([base58Decode(owner, 32),
            base58Decode(TOKEN_PROGRAM_ID, 32), base58Decode(USDC_MINT, 32)], ASSOCIATED_TOKEN_PROGRAM_ID));
    }
    assert.notEqual(usdcAssociatedTokenAddress(PAYER), usdcAssociatedTokenAddress(key(0x55)));
    assert.equal(vaultTokenAddress(funding.program_id, funding.vault_state),
        derivePda([Buffer.from('vault-token'), base58Decode(funding.vault_state, 32)], funding.program_id));
});

test('CreateIdempotent for the wallet USDC account is hand-rolled to the ATA program layout', async () => {
    const instruction = createUsdcAccountIdempotentInstruction({ payer: PAYER, owner: key(0x55) });
    assert.equal(instruction.programId.toBase58(), ASSOCIATED_TOKEN_PROGRAM_ID);
    assert.deepEqual([...instruction.data], [1]);
    assert.deepEqual(instruction.keys.map(meta => [meta.pubkey.toBase58(), meta.isSigner, meta.isWritable]), [
        [PAYER, true, true],
        [usdcAssociatedTokenAddress(key(0x55)), false, true],
        [key(0x55), false, false],
        [USDC_MINT, false, false],
        [SystemProgram.programId.toBase58(), false, false],
        [TOKEN_PROGRAM_ID, false, false]
    ]);

    const calls = [];
    rpcHandler = async (url, init) => {
        assert.equal(url, funding.rpc_url);
        const { method } = JSON.parse(init.body);
        calls.push(method);
        if (method === 'getGenesisHash') return rpcResponse(funding.genesis_hash);
        assert.equal(method, 'getLatestBlockhash');
        return rpcResponse({ value: { blockhash: key(8), lastValidBlockHeight: 900 } });
    };
    const operation = await prepareLocalUsdcAccountCreation(funding, { payer: PAYER });
    assert.deepEqual(calls, ['getGenesisHash', 'getLatestBlockhash']);
    assert.equal(operation.transactions.length, 1);
    const [prepared] = operation.transactions;
    assert.equal(prepared.last_valid_height, 900);
    assert.deepEqual(prepared.required_signers, [[...base58Decode(PAYER, 32)]]);
    const message = Message.from(Uint8Array.from(prepared.bytes));
    assert.equal(message.instructions.length, 1, 'no compute budget or other instruction');
    const inspected = inspectPreparedSolanaMessage(prepared.bytes);
    assert.equal(base58Encode(inspected.program), ASSOCIATED_TOKEN_PROGRAM_ID);
    assert.deepEqual([...inspected.instructionData], [1]);
    // The wallet is payer and owner of its own account.
    assert.deepEqual(inspected.instructionAccounts.map(meta => base58Encode(meta.pubkey)), [
        PAYER, usdcAssociatedTokenAddress(PAYER), PAYER, USDC_MINT,
        SystemProgram.programId.toBase58(), TOKEN_PROGRAM_ID
    ]);
    assert.equal(inspected.instructionAccounts[1].isWritable, true);
    assert.equal(inspected.instructionAccounts[3].isWritable, false);
});

const discriminator = name => createHash('sha256').update(`global:${name}`).digest().subarray(0, 8);
const depositIntent = { expected_note_id: 3, amount: '25000000', commitment: `0x${'11'.repeat(32)}` };

function depositOperation({ tokenProgram = TOKEN_PROGRAM_ID, mint = USDC_MINT,
    source = usdcAssociatedTokenAddress(PAYER), vaultToken = vaultTokenAddress(funding.program_id, funding.vault_state),
    intent = depositIntent, chunkSize = 344, proofBytes = 256 } = {}) {
    const payer = new PublicKey(PAYER);
    const program = new PublicKey(funding.program_id);
    const operationId = Buffer.alloc(32, 0x41);
    const operation = PublicKey.findProgramAddressSync([Buffer.from('operation'),
        new PublicKey(funding.vault_state).toBuffer(), payer.toBuffer(), operationId], program)[0];
    const noteId = Buffer.alloc(4);
    noteId.writeUInt32LE(intent.expected_note_id);
    const note = PublicKey.findProgramAddressSync([Buffer.from('note'),
        new PublicKey(funding.vault_state).toBuffer(), noteId], program)[0];
    // The transition proof is opaque here; the program verifies it. All
    // amount/commitment authorization happens before any proof reaches chain.
    const payload = Buffer.alloc(88 + proofBytes);
    payload.writeUInt32LE(intent.expected_note_id, 0);
    Buffer.from(intent.commitment.slice(2).padStart(64, '0'), 'hex').copy(payload, 4);
    payload.writeBigUInt64LE(BigInt(intent.amount), 36);
    payload.writeBigUInt64LE(1_900_086_400n, 44);
    payload.writeUInt32LE(proofBytes, 84);
    const init = Buffer.alloc(83);
    discriminator('initialize_operation').copy(init);
    operationId.copy(init, 8);
    init[40] = 1;
    init.writeUInt16LE(payload.length, 41);
    Buffer.from(keccak_256(payload)).copy(init, 43);
    init.writeBigUInt64LE(2000n, 75);
    const meta = (pubkey, isWritable, isSigner = false) => ({ pubkey: new PublicKey(pubkey), isWritable, isSigner });
    const prepared = (keys, data) => {
        const transaction = new Transaction({ feePayer: payer, recentBlockhash: key(8) })
            .add(new TransactionInstruction({ programId: program, keys, data }));
        return { format: 'solana-legacy-message-v1', bytes: [...transaction.serializeMessage()],
            required_signers: [[...payer.toBytes()]], last_valid_height: 500 };
    };
    const transactions = [prepared([meta(funding.vault_state, false), meta(operation, true),
        meta(PAYER, true, true), meta(SystemProgram.programId, false)], init)];
    for (let offset = 0; offset < payload.length; offset += chunkSize) {
        const chunk = payload.subarray(offset, offset + chunkSize);
        const data = Buffer.alloc(14 + chunk.length);
        discriminator('write_operation').copy(data);
        data.writeUInt16LE(offset, 8);
        data.writeUInt32LE(chunk.length, 10);
        chunk.copy(data, 14);
        transactions.push(prepared([meta(funding.vault_state, false), meta(operation, true), meta(PAYER, false, true)], data));
    }
    transactions.push(prepared([meta(funding.vault_state, true), meta(operation, true), meta(note, true),
        meta(PAYER, true, true), meta(PAYER, false, true), meta(source, true), meta(vaultToken, true),
        meta(mint, false), meta(tokenProgram, false), meta(SystemProgram.programId, false)],
    Buffer.concat([discriminator('execute_deposit'), noteId])));
    return { transactions };
}

const authorizeDeposit = (operation, payer = PAYER) =>
    validatePreparedSolanaDeposit(operation, { funding, payer, deposit: depositIntent });

test('a prepared deposit must move USDC from the wallet ATA into the vault under classic SPL Token', () => {
    const operation = depositOperation();
    assert.equal(authorizeDeposit(operation), operation);
    // Rust Felt252 JSON omits leading zeroes; compare the value, not its text.
    const shortIntent = { ...depositIntent, commitment: '0x123' };
    const shortOperation = depositOperation({ intent: shortIntent });
    assert.equal(validatePreparedSolanaDeposit(shortOperation, {
        funding, payer: PAYER, deposit: shortIntent
    }), shortOperation);
    for (const [options, error] of [
        [{ tokenProgram: TOKEN_2022_PROGRAM_ID }, /Token-2022/],
        [{ tokenProgram: key(0x43) }, /unknown token program/],
        [{ mint: key(0x44) }, /token other than Circle USDC/],
        [{ source: usdcAssociatedTokenAddress(key(0x45)) }, /from this wallet into the pinned vault/],
        [{ vaultToken: key(0x46) }, /from this wallet into the pinned vault/]
    ]) assert.throws(() => authorizeDeposit(depositOperation(options)), error);
    assert.throws(() => authorizeDeposit(operation, key(0x47)), /from this wallet into the pinned vault/);
});

test('an operator cannot replace the deposit commitment, amount, note ID or staging sequence', () => {
    for (const intent of [
        { ...depositIntent, commitment: `0x${'22'.repeat(32)}` },
        { ...depositIntent, amount: '25000001' },
        { ...depositIntent, amount: '1' },
        { ...depositIntent, expected_note_id: 4 }
    ]) assert.throws(() => authorizeDeposit(depositOperation({ intent })), /local note, amount and commitment/);
    const extraDeposit = depositOperation();
    extraDeposit.transactions.splice(1, 0, extraDeposit.transactions.at(-1));
    assert.throws(() => authorizeDeposit(extraDeposit), /exactly three transactions/);
    const repeatedWrite = depositOperation();
    repeatedWrite.transactions.splice(2, 0, repeatedWrite.transactions[1]);
    assert.throws(() => authorizeDeposit(repeatedWrite), /exactly three transactions/);
    const missingWrite = depositOperation();
    missingWrite.transactions.splice(1, 1);
    assert.throws(() => authorizeDeposit(missingWrite), /exactly three transactions/);
    const wrongBuffer = depositOperation();
    const parsed = inspectPreparedSolanaMessage(wrongBuffer.transactions[1].bytes);
    const message = Message.from(Uint8Array.from(wrongBuffer.transactions[1].bytes));
    const bufferIndex = message.accountKeys.findIndex(k => k.toBase58() === base58Encode(parsed.instructionAccounts[1].pubkey));
    message.accountKeys[bufferIndex] = new PublicKey(key(0x61));
    wrongBuffer.transactions[1].bytes = [...message.serialize()];
    assert.throws(() => authorizeDeposit(wrongBuffer), /substituted staging accounts/);
    const wrongDigest = depositOperation();
    const initMessage = Message.from(Uint8Array.from(wrongDigest.transactions[0].bytes));
    const initData = base58Decode(initMessage.instructions[0].data);
    initData[43] ^= 1;
    initMessage.instructions[0].data = base58Encode(initData);
    wrongDigest.transactions[0].bytes = [...initMessage.serialize()];
    assert.throws(() => authorizeDeposit(wrongDigest), /local note, amount and commitment/);
    assert.throws(() => validatePreparedSolanaDeposit(depositOperation(), { funding, payer: PAYER }), /local deposit intent/);
});

test('an operator cannot inflate deposit fees with fragmented writes or buffer rent with an oversized proof', () => {
    assert.equal(authorizeDeposit(depositOperation()).transactions.length, 3);
    // Both plans have the right local intent, contiguous writes and digest.
    // The old validator accepted 346 wallet-paid stages for a 344-byte payload.
    for (const chunkSize of [1, 200]) {
        assert.throws(() => authorizeDeposit(depositOperation({ chunkSize })), /exactly three transactions/);
    }
    // This still fits one legacy write message, but rents a larger operation
    // buffer and can never pass the deployed verifier's 256-byte proof check.
    assert.throws(() => authorizeDeposit(depositOperation({ proofBytes: 512, chunkSize: 600 })),
        /canonical 344-byte payload/);
});

// Threat: an operator keeps every authorized byte but reshapes a stage: an
// address lookup table (v0) hiding a substituted account, a priority fee
// charged to the wallet, or an extra instruction (here a Token approve to the
// operator) ahead of the vault instruction in any stage.
test('deposit stages are single-signer legacy messages with only bounded heap/CU prefixes', () => {
    const stage = (operation, index, rebuild) => {
        const message = Message.from(Uint8Array.from(operation.transactions[index].bytes));
        const instructions = message.instructions.map(compiled => new TransactionInstruction({
            programId: message.accountKeys[compiled.programIdIndex],
            keys: compiled.accounts.map(account => ({ pubkey: message.accountKeys[account],
                isSigner: message.isAccountSigner(account), isWritable: message.isAccountWritable(account) })),
            data: Buffer.from(base58Decode(compiled.data))
        }));
        operation.transactions[index].bytes = rebuild(instructions);
        return operation;
    };
    const payer = new PublicKey(PAYER);
    const legacy = instructions => [...new Transaction({ feePayer: payer, recentBlockhash: key(8) })
        .add(...instructions).serializeMessage()];
    for (const index of [0, 1, 2]) {
        assert.equal(authorizeDeposit(stage(depositOperation(), index, legacy)).transactions.length, 3);
        const budget = [ComputeBudgetProgram.requestHeapFrame({ bytes: 128 * 1024 }),
            ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 })];
        authorizeDeposit(stage(depositOperation(), index, instructions => legacy([...budget, ...instructions])));
        assert.throws(() => authorizeDeposit(stage(depositOperation(), index, instructions => legacy([
            ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 1_000_000 }), ...instructions]))),
        /compute budget is not authorized/);
        const approve = new TransactionInstruction({ programId: new PublicKey(TOKEN_PROGRAM_ID),
            keys: [{ pubkey: new PublicKey(usdcAssociatedTokenAddress(PAYER)), isSigner: false, isWritable: true },
                { pubkey: new PublicKey(key(0x62)), isSigner: false, isWritable: false },
                { pubkey: payer, isSigner: true, isWritable: false }],
            data: Buffer.from([4, ...new Uint8Array(8).fill(0xff)]) });
        assert.throws(() => authorizeDeposit(stage(depositOperation(), index,
            instructions => legacy([approve, ...instructions]))), /compute budget is not authorized/);
        assert.throws(() => authorizeDeposit(stage(depositOperation(), index,
            instructions => legacy([...instructions, approve]))));
        const table = new AddressLookupTableAccount({ key: new PublicKey(key(0x63)), state: {
            deactivationSlot: BigInt('18446744073709551615'), lastExtendedSlot: 0, lastExtendedSlotStartIndex: 0,
            addresses: lookupAddresses(depositOperation(), index) } });
        assert.throws(() => authorizeDeposit(stage(depositOperation(), index, instructions => [
            ...new TransactionMessage({ payerKey: payer, recentBlockhash: key(8), instructions })
                .compileToV0Message([table]).serialize()])), /exactly one signature/);
    }
});

function lookupAddresses(operation, index) {
    const message = Message.from(Uint8Array.from(operation.transactions[index].bytes));
    return message.accountKeys.filter((_, position) => !message.isAccountSigner(position)
        && position !== message.instructions.at(-1).programIdIndex);
}

test('USDC token accounts decode; Token-2022 and foreign owners are refused', async () => {
    const owner = key(0x55);
    const address = usdcAssociatedTokenAddress(owner);
    const decoded = decodeUsdcTokenAccount(tokenAccountData({ owner, amount: 5_000_000n }));
    assert.deepEqual({ ...decoded }, { mint: USDC_MINT, owner, amount: '5000000', state: 1, frozen: false,
        creditable: true });
    assert.equal(decodeUsdcTokenAccount(tokenAccountData({ owner, state: 2 })).creditable, false);
    assert.equal(decodeUsdcTokenAccount(tokenAccountData({ owner, mint: key(9) })).creditable, false);
    let entry = null;
    rpcHandler = async (_url, init) => {
        const { method, params } = JSON.parse(init.body);
        assert.equal(method, 'getAccountInfo');
        assert.equal(params[0], address);
        return rpcResponse({ context: { slot: 1 }, value: entry });
    };
    assert.equal(await readUsdcTokenAccount(funding, address), null);
    entry = rpcAccount(TOKEN_PROGRAM_ID, tokenAccountData({ owner, amount: 7n }));
    assert.equal((await readUsdcTokenAccount(funding, address)).amount, '7');
    entry = rpcAccount(TOKEN_2022_PROGRAM_ID, tokenAccountData({ owner }));
    await assert.rejects(readUsdcTokenAccount(funding, address), /Token-2022/);
    entry = rpcAccount(SystemProgram.programId.toBase58(), tokenAccountData({ owner }));
    await assert.rejects(readUsdcTokenAccount(funding, address), /not a classic SPL Token account/);
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
    assert.equal(state.pending.stage, 'open');
    // A mutual close keeps the note account (and its leaf) as `closed`.
    noteStatus = 4;
    const closed = await readFinalizedSolanaOperationState(
        funding,
        preparedOperation(accounts),
        { noteId: 17 }
    );
    assert.equal(closed.note.status, 'closed');
});

test('the Solana RPC adapter submits exact bytes and waits for finalized status', async () => {
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

test('the Solana RPC adapter fails closed after an unknown signature expires', async () => {
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
        [funding.vault_state, { owner: funding.program_id, executable: false,
            data: vaultAccountData(funding, { paused: true }) }],
        [funding.program_id, { owner: UPGRADEABLE_LOADER, executable: true,
            data: Uint8Array.from([2, 0, 0, 0, ...new Uint8Array(32).fill(12)]) }],
        [programData, { owner: UPGRADEABLE_LOADER, executable: false, data: Uint8Array.from([3, 0, 0, 0, ...new Array(9).fill(0)]) }]
    ]);
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
    accounts.get(funding.vault_state).data = vaultAccountData(funding);
    assert.equal(assertSolanaDepositsOpen(await assertSolanaVault(funding)).paused, false);
});

test('the pinned vault must hold Circle USDC in its canonical vault token account', async () => {
    let vault = vaultAccountData(funding, { mint: key(9) });
    rpcHandler = async (_url, init) => {
        const { method } = JSON.parse(init.body);
        if (method === 'getGenesisHash') return rpcResponse(funding.genesis_hash);
        return rpcResponse({ context: { slot: 1 }, value: rpcAccount(funding.program_id, vault) });
    };
    await assert.rejects(assertSolanaVault(funding), /does not hold Circle USDC/);
    vault = vaultAccountData(funding, { vaultToken: usdcAssociatedTokenAddress(funding.vault_state) });
    await assert.rejects(assertSolanaVault(funding), /does not hold Circle USDC/);
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
