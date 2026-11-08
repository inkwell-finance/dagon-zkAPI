import assert from 'node:assert/strict';
import test from 'node:test';
import { ed25519 } from '@noble/curves/ed25519';
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';
import { sha256 } from '@noble/hashes/sha256';
import { AddressLookupTableAccount, ComputeBudgetProgram, Keypair, PublicKey, Transaction, TransactionInstruction,
    TransactionMessage, VersionedTransaction, SystemProgram } from '@solana/web3.js';

import { BrowserWalletRuntime } from '../services/browserWalletRuntime.js';
import { EVM_CCTP, MESSAGE_TRANSMITTER_V2, TOKEN_MESSENGER_MINTER_V2, decodeMessageV2, depositForBurnInstruction,
    deriveEmergencyKey, encodeForwardHook, encodeMessageV2, evmBytes32, receiveMessageInstruction, usedNonce }
    from '../services/zkapiCctp.mjs';
import { assertEvmRecipient, burnUsdcOnEvm } from '../services/zkapiCctpEvm.mjs';
import {
    CCTP_FEE_CAPS, ZkapiCctpWallet, assertInboundMessage, assertOutboundMessage, assertRefundAllowed,
    cctpFeePolicyCap, cctpMaxFee, cctpNotePda, decodeTransaction, executeDepositInstruction, feltBytes, fromHex,
    readLookupTables, relayFeeCap, resolveCctpOptions, signTransactionWith, transferCheckedInstruction, validateRelayBurnTransaction,
    validateRelayDepositTransaction, validateRelayExitTransaction, validateRelayReceiveTransaction,
    validateRelaySweepTransaction, verifyCctpAttestation, verifyRelaySubmission
} from '../services/zkapiCctpWallet.mjs';
import { solanaExitInstruction } from '../services/zkapiSolanaExit.mjs';
import { base58Decode, base58Encode } from '../services/zkapiSolanaTransport.mjs';
import { TOKEN_PROGRAM_ID, UPGRADEABLE_LOADER, USDC_MINT, createUsdcAccountIdempotentInstruction,
    usdcAssociatedTokenAddress } from '../services/zkapiUsdc.mjs';
import { noteAccountData, rpcAccount, tokenAccountData, usdcFunding, vaultAccountData } from './helpers/usdc-fixtures.mjs';

const funding = usdcFunding();
const SECRET = `0x${'05'.repeat(31)}07`;
const COMMITMENT = `0x${'0a'.repeat(32)}`;
const ek = deriveEmergencyKey(BigInt(SECRET));
const EK = ek.publicKey.toBase58();
const ATA = usdcAssociatedTokenAddress(EK);
const relayer = Keypair.fromSeed(new Uint8Array(32).fill(41));
const RELAYER = relayer.publicKey.toBase58();
const FEE_ACCOUNT = base58Encode(new Uint8Array(32).fill(42));
const BLOCKHASH = base58Encode(new Uint8Array(32).fill(43));
const ALT_KEY = base58Encode(new Uint8Array(32).fill(80));
const LOOKUP_TABLE_PROGRAM = 'AddressLookupTab1e1111111111111111111111111';
const BURNER = '0x1111111111111111111111111111111111111111';
const RECIPIENT = '0x2222222222222222222222222222222222222222';
const NOTE_ID = 7;
const OPERATION_ID = new Uint8Array(32).fill(44);
const OPERATION = PublicKey.findProgramAddressSync([new TextEncoder().encode('operation'),
    base58Decode(funding.vault_state, 32), ek.publicKey.toBytes(), OPERATION_ID],
new PublicKey(funding.program_id))[0].toBase58();
const NOTE = cctpNotePda(funding, NOTE_ID);
const ZERO32 = new Uint8Array(32);
const NONCE = new Uint8Array(32).fill(5);
const hex = bytes => Buffer.from(bytes).toString('hex');

// Two local attester keys, pinned in ascending address order (as MessageTransmitterV2 requires).
const attesterAddress = key => `0x${hex(keccak_256(secp256k1.getPublicKey(key, false).slice(1)).slice(12))}`;
const ATTESTER_KEYS = [new Uint8Array(32).fill(0x11), new Uint8Array(32).fill(0x22)]
    .sort((left, right) => (BigInt(attesterAddress(left)) < BigInt(attesterAddress(right)) ? -1 : 1));
const ATTESTERS = ATTESTER_KEYS.map(attesterAddress);
const PINNED = { attesters: ATTESTERS, threshold: 2 };
function attest(message, keys = ATTESTER_KEYS) {
    const digest = keccak_256(message);
    return `0x${keys.map(key => {
        const signature = secp256k1.sign(digest, key);
        return hex(signature.toCompactRawBytes()) + (27 + signature.recovery).toString(16);
    }).join('')}`;
}

const web3 = plain => plain instanceof TransactionInstruction ? plain : new TransactionInstruction({
    programId: new PublicKey(plain.programId),
    keys: plain.keys.map(key => ({ pubkey: new PublicKey(key.pubkey), isSigner: key.isSigner, isWritable: key.isWritable })),
    data: Buffer.from(plain.data)
});

/** A relayer-prepared legacy transaction: unsigned like every ek-co-signed prepare (`signers` signs it). */
function relayTransaction(instructions, { feePayer = relayer, signers = [] } = {}) {
    const transaction = new Transaction({ feePayer: feePayer.publicKey, blockhash: BLOCKHASH, lastValidBlockHeight: 500 });
    transaction.add(...instructions.map(web3));
    if (signers.length) transaction.partialSign(...signers);
    return Uint8Array.from(transaction.serialize({ requireAllSignatures: false, verifySignatures: false }));
}

/**
 * A relayer-built v0 transaction using lookup table ALT_KEY with `addresses`,
 * relayer-signed by default (a fallback receive); ek-co-signed prepares pass `signers: []`.
 */
function relayV0Transaction(instructions, addresses, { feePayer = relayer, signers = [relayer] } = {}) {
    const table = new AddressLookupTableAccount({ key: new PublicKey(ALT_KEY), state: {
        deactivationSlot: (1n << 64n) - 1n, lastExtendedSlot: 0, lastExtendedSlotStartIndex: 0,
        authority: relayer.publicKey, addresses: addresses.map(address => new PublicKey(address)) } });
    const message = new TransactionMessage({ payerKey: feePayer.publicKey, recentBlockhash: BLOCKHASH,
        instructions: instructions.map(web3) }).compileToV0Message([table]);
    const transaction = new VersionedTransaction(message);
    if (signers.length) transaction.sign(signers);
    return transaction.serialize();
}
const unsignedV0 = (instructions, addresses) => relayV0Transaction(instructions, addresses, { signers: [] });

/** The on-chain bytes of an address lookup table holding `addresses`. */
function lookupTableData(addresses, { deactivated = false } = {}) {
    const data = new Uint8Array(56 + 32 * addresses.length);
    const view = new DataView(data.buffer);
    view.setUint32(0, 1, true);
    view.setBigUint64(4, deactivated ? 5n : (1n << 64n) - 1n, true);
    data[21] = 1;
    data.set(relayer.publicKey.toBytes(), 22);
    addresses.forEach((address, index) => data.set(base58Decode(address, 32), 56 + index * 32));
    return data;
}

const feeTransfer = (amount, { authority = EK, destination = FEE_ACCOUNT } = {}) => transferCheckedInstruction({
    source: usdcAssociatedTokenAddress(authority), mint: USDC_MINT, destination, authority, amount });

const OPERATION_RENT = (128 + 498) * 6960;
const NOTE_RENT = (128 + 110) * 6960;
function depositInstructions({ fee = 100_000n, noteId = NOTE_ID, commitment = COMMITMENT,
    amount = 9_400_000n, owner = EK } = {}) {
    const payload = stagedPayload({ noteId, commitment, amount });
    const init = Buffer.alloc(83);
    Buffer.from(sha256(new TextEncoder().encode('global:initialize_operation')).slice(0, 8)).copy(init);
    init.set(OPERATION_ID, 8); init[40] = 1; init.writeUInt16LE(344, 41);
    init.set(keccak_256(payload), 43); init.writeBigUInt64LE(99n, 75);
    const write = Buffer.alloc(358);
    write.set(sha256(new TextEncoder().encode('global:write_operation')).slice(0, 8));
    write.writeUInt32LE(344, 10); write.set(payload, 14);
    const key = (pubkey, isSigner = false, isWritable = false) => ({ pubkey, isSigner, isWritable });
    return [
        SystemProgram.transfer({ fromPubkey: relayer.publicKey, toPubkey: ek.publicKey, lamports: OPERATION_RENT + NOTE_RENT }),
        { programId: funding.program_id, keys: [key(funding.vault_state), key(OPERATION, false, true),
            key(owner, true, true), key(SystemProgram.programId.toBase58())], data: init },
        { programId: funding.program_id, keys: [key(funding.vault_state), key(OPERATION, false, true), key(owner, true)], data: write },
        ComputeBudgetProgram.requestHeapFrame({ bytes: 131_072 }),
        ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
        executeDepositInstruction({ funding, operation: OPERATION, note: NOTE, owner, depositor: EK, noteId }),
        ...(fee > 0n ? [feeTransfer(fee)] : []),
        SystemProgram.transfer({ fromPubkey: ek.publicKey, toPubkey: relayer.publicKey, lamports: OPERATION_RENT })
    ];
}
const DEPOSIT_TABLE = [funding.vault_state, funding.usdc_mint, FEE_ACCOUNT];
const depositTx = (instructions = depositInstructions(), options) => relayV0Transaction(instructions, DEPOSIT_TABLE,
    { signers: [], ...options });
const depositExpectation = (changes = {}) => ({ funding, relayer: RELAYER, ek: EK, feeAccount: FEE_ACCOUNT,
    operation: OPERATION, note: NOTE, noteId: NOTE_ID, commitment: COMMITMENT, amount: 9_400_000n,
    operationRent: String(OPERATION_RENT), noteRent: String(NOTE_RENT),
    lookupTables: [{ address: ALT_KEY, addresses: DEPOSIT_TABLE }],
    fee: '100000', maxFee: CCTP_FEE_CAPS.deposit, ...changes });

function stagedPayload({ noteId = NOTE_ID, commitment = COMMITMENT, amount = 9_400_000n } = {}) {
    const payload = new Uint8Array(344);
    const view = new DataView(payload.buffer);
    view.setUint32(0, noteId, true);
    payload.set(feltBytes(commitment), 4);
    view.setBigUint64(36, BigInt(amount), true);
    view.setBigUint64(44, 1_900_000_000n, true);
    view.setUint32(84, 256, true);
    return payload;
}


const burnTarget = (changes = {}) => ({ destinationDomain: 6, mintRecipient: evmBytes32(RECIPIENT), destinationCaller: ZERO32,
    maxCctpFee: 300_000n, minFinalityThreshold: 1000, hookData: encodeForwardHook({ createAtaOwner: null }), ...changes });

function burnInstructions({ event, fee = 40_000n, amount, target = burnTarget(), owner = EK } = {}) {
    return [
        ...(fee > 0n ? [feeTransfer(fee)] : []),
        depositForBurnInstruction({ owner, eventRentPayer: RELAYER, burnTokenAccount: usdcAssociatedTokenAddress(owner),
            messageSentEventData: event.publicKey, amount, destinationDomain: target.destinationDomain,
            mintRecipient: target.mintRecipient, destinationCaller: target.destinationCaller, maxFee: target.maxCctpFee,
            minFinalityThreshold: target.minFinalityThreshold, hookData: target.hookData })
    ];
}

/** An inbound Base → Solana message as Iris attests it for a plan (`changes` override any field). */
function inboundMessage(plan, { header = {}, body = {} } = {}) {
    return encodeMessageV2({ version: 1, sourceDomain: 6, destinationDomain: 5, nonce: NONCE,
        sender: evmBytes32(EVM_CCTP.base.tokenMessenger), recipient: new PublicKey(TOKEN_MESSENGER_MINTER_V2).toBytes(),
        destinationCaller: ZERO32, minFinalityThreshold: plan.minFinalityThreshold, finalityThresholdExecuted: 1000,
        ...header,
        body: { version: 1, burnToken: evmBytes32(EVM_CCTP.base.usdc), mintRecipient: base58Decode(ATA, 32),
            amount: BigInt(plan.burnAmount), messageSender: evmBytes32(BURNER), maxFee: BigInt(plan.maxFee),
            feeExecuted: 300_000n, expirationBlock: 9_000_000n, hookData: fromHex(plan.hook), ...body } });
}

/** The MessageSent message of an outbound burn (`filled` adds the fields Iris fills). */
function outboundMessage({ target, amount, filled = false }) {
    return encodeMessageV2({ version: 1, sourceDomain: 5, destinationDomain: target.destinationDomain,
        nonce: filled ? NONCE : ZERO32, sender: new PublicKey(TOKEN_MESSENGER_MINTER_V2).toBytes(),
        recipient: evmBytes32(EVM_CCTP.base.tokenMessenger), destinationCaller: target.destinationCaller,
        minFinalityThreshold: target.minFinalityThreshold, finalityThresholdExecuted: filled ? target.minFinalityThreshold : 0,
        body: { version: 1, burnToken: base58Decode(USDC_MINT, 32), mintRecipient: target.mintRecipient, amount,
            messageSender: base58Decode(EK, 32), maxFee: target.maxCctpFee, feeExecuted: filled ? 5_000n : 0n,
            expirationBlock: filled ? 77n : 0n, hookData: target.hookData } });
}

function messageSentData(message) {
    const data = new Uint8Array(52 + message.length);
    data.set([131, 100, 133, 56, 166, 225, 151, 60]);
    data.set(relayer.publicKey.toBytes(), 8);
    new DataView(data.buffer).setUint32(48, message.length, true);
    data.set(message, 52);
    return data;
}

const PUBLIC_INPUTS = { protocol_version: 2, chain_id: funding.chain_id, contract_address: funding.contract_address,
    registration: COMMITMENT, state_signing_key_x: '0x1', state_signing_key_y: '0x2', clearance_signing_key_x: '0x3',
    clearance_signing_key_y: '0x4', note_id: 3, deposit_amount: '5000000', expiry_ts: '1900000000',
    final_balance: '5000000', destination: `0x${'ab'.repeat(20)}`, withdrawal_nullifier: '0x99', has_clearance: true,
    next_nullifier: '0x0', conceded: '0', valid_until: '1900000000' };
const PROOF = { backend: 'groth16_bn254', proof: Buffer.alloc(256, 7).toString('base64') };

async function exitInstructions({ fee = 250_000n, destination = ATA, publicInputs = PUBLIC_INPUTS } = {}) {
    return [
        ComputeBudgetProgram.requestHeapFrame({ bytes: 131_072 }),
        ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
        createUsdcAccountIdempotentInstruction({ payer: RELAYER, owner: EK }),
        await solanaExitInstruction(funding, 'mutual', { payer: RELAYER, destination, public_inputs: publicInputs,
            proof: PROOF }),
        ...(fee > 0n ? [feeTransfer(fee)] : [])
    ];
}
/** What a relayer may put in a lookup table: every account that is never a signer nor an invoked program. */
function tableOf(instructions) {
    const all = instructions.map(web3);
    const excluded = new Set([...all.map(ix => ix.programId.toBase58()),
        ...all.flatMap(ix => ix.keys.filter(key => key.isSigner).map(key => key.pubkey.toBase58()))]);
    return [...new Set(all.flatMap(ix => ix.keys.map(key => key.pubkey.toBase58())))].filter(key => !excluded.has(key));
}
const EXIT_TABLE = tableOf(await exitInstructions());

/** The relay's free, relayer-signed fallback receive: exactly [CU limit, receive_message → ATA(ek)]. */
function receiveInstructions({ message, attestation, recipient = ATA, units = 400_000 }) {
    return [ComputeBudgetProgram.setComputeUnitLimit({ units }),
        receiveMessageInstruction({ payer: RELAYER, caller: RELAYER, message, attestation: fromHex(attestation),
            recipientTokenAccount: recipient, mint: USDC_MINT })];
}
const receiveTableOf = instructions => [...new Set(instructions[1].keys
    .filter(key => !key.isSigner).map(key => key.pubkey.toBase58()))]
    .filter(address => ![MESSAGE_TRANSMITTER_V2].includes(address));

const rejects = (fn, code) => assert.throws(fn, error => error.code === code, `expected ${code}`);
const rejectsAsync = (promise, code) => assert.rejects(promise, error => error.code === code, `expected ${code}`);

test('atomic deposit signs the payload and ek ownership within the packet limit', () => {
    const bytes = depositTx();
    assert.ok(bytes.length <= 1232);
    validateRelayDepositTransaction(bytes, depositExpectation());
    const signed = signTransactionWith(bytes, [ek.keypair]);
    const ekSigned = decodeTransaction(signed.bytes, depositExpectation().lookupTables);
    assert.deepEqual(ekSigned.signatures[0], new Uint8Array(64), 'the relayer signs only on submit');
    assert.ok(ed25519.verify(ekSigned.signatures[1], ekSigned.message, base58Decode(EK, 32)));
    const decoded = decodeTransaction(signTransactionWith(signed.bytes, [relayer]).bytes, depositExpectation().lookupTables);
    decoded.signatures.forEach((signature, index) => assert.ok(
        ed25519.verify(signature, decoded.message, base58Decode(decoded.staticKeys[index], 32))));
    assert.deepEqual(decoded.message, decodeTransaction(bytes, depositExpectation().lookupTables).message);
});

test('atomic deposit refuses substituted commitment, owner, amount, rent, instructions and signatures', () => {
    for (const changes of [
        { commitment: `0x${'0b'.repeat(32)}` }, { amount: 9_400_001n }, { noteId: 8 }, { owner: RELAYER }
    ]) rejects(() => validateRelayDepositTransaction(depositTx(depositInstructions(changes)), depositExpectation()),
        'cctp_relay_tx_rejected');
    const extra = [...depositInstructions(), feeTransfer(1n)];
    rejects(() => validateRelayDepositTransaction(depositTx(extra), depositExpectation()), 'cctp_relay_tx_rejected');
    const priced = depositInstructions();
    priced[3] = ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 1_000_000 });
    rejects(() => validateRelayDepositTransaction(depositTx(priced), depositExpectation()), 'cctp_relay_tx_rejected');
    const rentTheft = depositInstructions();
    rentTheft[rentTheft.length - 1] = SystemProgram.transfer({ fromPubkey: ek.publicKey,
        toPubkey: relayer.publicKey, lamports: OPERATION_RENT + 1 });
    rejects(() => validateRelayDepositTransaction(depositTx(rentTheft), depositExpectation()), 'cctp_relay_tx_rejected');
    const cap = CCTP_FEE_CAPS.deposit + 1n;
    rejects(() => validateRelayDepositTransaction(depositTx(depositInstructions({ fee: cap })),
        depositExpectation({ fee: String(cap) })), 'relay_fee_above_cap');
    // Prepared transactions carry no signature at all: a relayer-presigned one is refused.
    rejects(() => validateRelayDepositTransaction(depositTx(depositInstructions(), { signers: [relayer] }),
        depositExpectation()), 'cctp_relay_tx_rejected');
    const forged = depositTx(); forged.fill(9, 1, 65);
    rejects(() => validateRelayDepositTransaction(forged, depositExpectation()), 'cctp_relay_tx_rejected');
    // The old read-then-execute shape is never accepted, even if an RPC had
    // reported an honest buffer before its owner cancelled and replaced it.
    rejects(() => validateRelayDepositTransaction(depositTx(depositInstructions().slice(3, -1)),
        depositExpectation()), 'cctp_relay_tx_rejected');
});

test('relayer burns must burn exactly the remaining balance to the chosen recipient and domain', () => {
    const event = Keypair.fromSeed(new Uint8Array(32).fill(60));
    const balance = 5_000_000n;
    const expectation = (changes = {}) => ({ funding, relayer: RELAYER, ek: EK, feeAccount: FEE_ACCOUNT,
        eventAccount: event.publicKey.toBase58(), fee: '40000', maxFee: relayFeeCap('burn'), amount: '4960000',
        balance, target: burnTarget(), ...changes });
    const honest = relayTransaction(burnInstructions({ event, amount: 4_960_000n }));
    validateRelayBurnTransaction(honest, expectation());
    const signed = signTransactionWith(honest, [ek.keypair]);
    assert.equal(Transaction.from(signed.bytes).verifySignatures(false), true);
    assert.equal(Transaction.from(signed.bytes).verifySignatures(true), false, 'relayer and event sign only on submit');
    const full = signTransactionWith(signed.bytes, [relayer, event]);
    assert.equal(Transaction.from(full.bytes).verifySignatures(true), true);
    rejects(() => validateRelayBurnTransaction(relayTransaction(burnInstructions({ event, amount: 4_960_000n }),
        { signers: [relayer, event] }), expectation()), 'cctp_relay_tx_rejected');
    rejects(() => validateRelayBurnTransaction(relayTransaction(burnInstructions({ event, amount: 4_960_000n,
        target: burnTarget({ mintRecipient: evmBytes32('0x3333333333333333333333333333333333333333') }) })),
    expectation()), 'cctp_relay_tx_rejected');
    rejects(() => validateRelayBurnTransaction(relayTransaction(burnInstructions({ event, amount: 4_960_000n,
        target: burnTarget({ destinationDomain: 3 }) })), expectation()), 'cctp_relay_tx_rejected');
    rejects(() => validateRelayBurnTransaction(relayTransaction(burnInstructions({ event, amount: 4_960_000n,
        target: burnTarget({ maxCctpFee: 4_000_000n }) })), expectation()), 'cctp_relay_tx_rejected');
    rejects(() => validateRelayBurnTransaction(relayTransaction([
        ...burnInstructions({ event, amount: 4_960_000n }), feeTransfer(1n, { destination: usdcAssociatedTokenAddress(RELAYER) })
    ]), expectation()), 'cctp_relay_tx_rejected');
    rejects(() => validateRelayBurnTransaction(honest, expectation({ amount: '4900000' })), 'cctp_relay_tx_rejected');
    rejects(() => validateRelayBurnTransaction(honest, expectation({ fee: '50001', amount: '4949999' })), 'relay_fee_above_cap');
    const extra = Keypair.fromSeed(new Uint8Array(32).fill(61));
    const extraSigner = burnInstructions({ event, amount: 4_960_000n });
    extraSigner.push(new TransactionInstruction({ programId: new PublicKey(TOKEN_PROGRAM_ID),
        keys: [{ pubkey: extra.publicKey, isSigner: true, isWritable: false }], data: Buffer.from([]) }));
    rejects(() => validateRelayBurnTransaction(relayTransaction(extraSigner), expectation()), 'cctp_relay_tx_rejected');
    rejects(() => validateRelayBurnTransaction(honest, expectation({ eventAccount: RELAYER })), 'cctp_relay_tx_rejected');
});

test('relayer sweeps move the whole balance to the chosen account only', () => {
    const destination = usdcAssociatedTokenAddress(base58Encode(new Uint8Array(32).fill(70)));
    const instructions = (to = destination) => [feeTransfer(40_000n),
        transferCheckedInstruction({ source: ATA, mint: USDC_MINT, destination: to, authority: EK, amount: 960_000n })];
    const expectation = { funding, relayer: RELAYER, ek: EK, feeAccount: FEE_ACCOUNT, destination, fee: '40000',
        maxFee: CCTP_FEE_CAPS.sweep, amount: '960000', balance: 1_000_000n };
    validateRelaySweepTransaction(relayTransaction(instructions()), expectation);
    rejects(() => validateRelaySweepTransaction(relayTransaction(instructions(FEE_ACCOUNT)), expectation), 'cctp_relay_tx_rejected');
    rejects(() => validateRelaySweepTransaction(relayTransaction(instructions()), { ...expectation, amount: '900000' }),
        'cctp_relay_tx_rejected');
});

test('a submit response is accepted only with the signed message, the unchanged ek signature and valid relay signatures', () => {
    const destination = usdcAssociatedTokenAddress(base58Encode(new Uint8Array(32).fill(70)));
    const sweep = (to = destination) => relayTransaction([feeTransfer(40_000n),
        transferCheckedInstruction({ source: ATA, mint: USDC_MINT, destination: to, authority: EK, amount: 960_000n })]);
    const ekSigned = signTransactionWith(sweep(), [ek.keypair]).bytes;
    const full = signTransactionWith(ekSigned, [relayer]).bytes;
    const context = { sent: ekSigned, ek: EK, format: 'solana-legacy-transaction-v1', lastValidHeight: 500, label: 'sweep' };
    const response = (bytes, changes = {}) => ({ signature: base58Encode(bytes.slice(1, 65)),
        transaction: { format: context.format, bytes: [...bytes], last_valid_height: 500 }, ...changes });
    const accepted = verifyRelaySubmission(response(full), context);
    assert.deepEqual({ ...accepted, bytes: [...accepted.bytes] },
        { bytes: [...full], signature: base58Encode(full.slice(1, 65)), lastValidHeight: 500 });
    // A different (fully and validly signed) message.
    const other = signTransactionWith(signTransactionWith(sweep(FEE_ACCOUNT), [ek.keypair]).bytes, [relayer]).bytes;
    rejects(() => verifyRelaySubmission(response(other), context), 'cctp_relay_tx_rejected');
    // The ek signature replaced (here by ek's signature of another message).
    const swapped = Uint8Array.from(full); swapped.set(other.slice(65, 129), 65);
    rejects(() => verifyRelaySubmission(response(swapped), context), 'cctp_relay_tx_rejected');
    // A missing or invalid relayer signature.
    rejects(() => verifyRelaySubmission(response(ekSigned), context), 'cctp_relay_tx_rejected');
    const stranger = Keypair.fromSeed(new Uint8Array(32).fill(71));
    const forged = Uint8Array.from(full);
    forged.set(ed25519.sign(decodeTransaction(full).message, stranger.secretKey.slice(0, 32)), 1);
    rejects(() => verifyRelaySubmission(response(forged), context), 'cctp_relay_tx_rejected');
    // Another lifetime, format or reported signature.
    rejects(() => verifyRelaySubmission(response(full, { transaction: { ...response(full).transaction,
        last_valid_height: 501 } }), context), 'cctp_relay_tx_rejected');
    rejects(() => verifyRelaySubmission(response(full, { transaction: { ...response(full).transaction,
        format: 'solana-v0-transaction-v1' } }), context), 'cctp_relay_tx_rejected');
    rejects(() => verifyRelaySubmission(response(full, { signature: base58Encode(full.slice(65, 129)) }), context),
        'cctp_relay_tx_rejected');
    // A burn needs the MessageSent event account's signature too.
    const event = Keypair.fromSeed(new Uint8Array(32).fill(60));
    const burnSigned = signTransactionWith(relayTransaction(burnInstructions({ event, amount: 4_960_000n })), [ek.keypair]).bytes;
    const burnContext = { ...context, sent: burnSigned, label: 'burn' };
    rejects(() => verifyRelaySubmission(response(signTransactionWith(burnSigned, [relayer]).bytes), burnContext),
        'cctp_relay_tx_rejected');
    verifyRelaySubmission(response(signTransactionWith(burnSigned, [relayer, event]).bytes), burnContext);
});

test('attestations verify only for the pinned attesters, in order, with exactly the threshold of low-s signatures', () => {
    const message = `0x${hex(new Uint8Array(200).fill(1))}`;
    assert.equal(verifyCctpAttestation(message, attest(fromHex(message)), PINNED), true);
    const stranger = new Uint8Array(32).fill(0x33);
    rejects(() => verifyCctpAttestation(message, attest(fromHex(message), [ATTESTER_KEYS[0], stranger]), PINNED),
        'cctp_attestation_invalid');
    rejects(() => verifyCctpAttestation(message, attest(fromHex(message), [...ATTESTER_KEYS].reverse()), PINNED),
        'cctp_attestation_invalid');
    rejects(() => verifyCctpAttestation(message, attest(fromHex(message), [ATTESTER_KEYS[0]]), PINNED),
        'cctp_attestation_invalid');
    rejects(() => verifyCctpAttestation(`0x${hex(new Uint8Array(200).fill(2))}`, attest(fromHex(message)), PINNED),
        'cctp_attestation_invalid');
    // The same signatures in high-s form (s' = n - s, flipped v) are malleated and refused.
    const malleated = fromHex(attest(fromHex(message)));
    const s = BigInt(`0x${hex(malleated.slice(32, 64))}`);
    malleated.set(fromHex((secp256k1.CURVE.n - s).toString(16).padStart(64, '0')), 32);
    malleated[64] = malleated[64] === 27 ? 28 : 27;
    rejects(() => verifyCctpAttestation(message, `0x${hex(malleated)}`, PINNED), 'cctp_attestation_invalid');
    rejects(() => verifyCctpAttestation(message, attest(fromHex(message)), { attesters: [], threshold: 2 }),
        'cctp_attestation_invalid');
});

test('every planned field of an inbound message is compared', () => {
    const plan = { sourceDomain: 6, minFinalityThreshold: 1000, burnAmount: '10000000', maxFee: '334202',
        hook: hex(new Uint8Array(40).fill(9)) };
    const expected = { sourceDomain: 6, tokenMessenger: EVM_CCTP.base.tokenMessenger, usdc: EVM_CCTP.base.usdc, ata: ATA,
        amount: plan.burnAmount, burner: BURNER, maxFee: plan.maxFee, minFinalityThreshold: 1000, hook: plan.hook };
    assertInboundMessage(decodeMessageV2(inboundMessage(plan)), expected);
    for (const changes of [
        { body: { messageSender: evmBytes32(RECIPIENT) } },
        { body: { maxFee: 9_000_000n } },
        { body: { burnToken: evmBytes32(RECIPIENT) } },
        { body: { hookData: new Uint8Array(40).fill(8) } },
        { body: { feeExecuted: 9_000_000n } },
        { body: { version: 2 } },
        { header: { destinationCaller: evmBytes32(RECIPIENT) } },
        { header: { sender: evmBytes32(RECIPIENT) } },
        { header: { recipient: new Uint8Array(32).fill(4) } },
        { header: { minFinalityThreshold: 2000 } },
        { header: { finalityThresholdExecuted: 500 } },
        { header: { sourceDomain: 3 } }
    ]) {
        rejects(() => assertInboundMessage(decodeMessageV2(inboundMessage(plan, changes)), expected), 'cctp_message_mismatch');
    }
});

test('an outbound attestation must match the on-chain MessageSent bytes except the fields Iris fills', () => {
    const target = burnTarget({ maxCctpFee: 333_390n });
    const burn = { amount: '4710000', target: { destinationDomain: 6, mintRecipient: hex(target.mintRecipient),
        destinationCaller: hex(ZERO32), maxCctpFee: '333390', minFinalityThreshold: 1000, hookData: hex(target.hookData) } };
    const event = outboundMessage({ target, amount: 4_710_000n });
    assertOutboundMessage(outboundMessage({ target, amount: 4_710_000n, filled: true }), event, burn);
    // Another attested message with the same amount and recipient but a different caller or hook.
    rejects(() => assertOutboundMessage(outboundMessage({ target: { ...target, destinationCaller: evmBytes32(BURNER) },
        amount: 4_710_000n, filled: true }), event, burn), 'cctp_message_mismatch');
    rejects(() => assertOutboundMessage(outboundMessage({ target: { ...target, hookData: new Uint8Array(0) },
        amount: 4_710_000n, filled: true }), event, burn), 'cctp_message_mismatch');
    rejects(() => assertOutboundMessage(outboundMessage({ target, amount: 4_700_000n, filled: true }), event, burn),
        'cctp_message_mismatch');
});

test('a fallback receive must receive exactly the validated message into ATA(ek) through a verified lookup table', async t => {
    const plan = { minFinalityThreshold: 1000, burnAmount: '10000000', maxFee: '334202', hook: hex(new Uint8Array(40).fill(9)) };
    const message = inboundMessage(plan);
    const attestation = attest(message);
    const instructions = receiveInstructions({ message, attestation });
    const addresses = receiveTableOf(instructions);
    const tables = [{ address: ALT_KEY, addresses }];
    const expectation = (changes = {}) => ({ funding, relayer: RELAYER, ek: EK, fee: '0', message: `0x${hex(message)}`,
        lookupTables: tables, ...PINNED, ...changes });
    const honest = relayV0Transaction(instructions, addresses);
    const decoded = validateRelayReceiveTransaction(honest, expectation());
    assert.equal(decoded.version, 0);
    assert.equal(decoded.signatures.length, 1, 'only the relayer signs; ek signs nothing');
    assert.ok(decoded.lookups.length === 1 && decoded.accountKeys.length > decoded.staticKeys.length, 'accounts come from the table');
    // Extra instructions (an ek-authorized drain needs ek's signature; a relayer-only extra changes the list).
    const drain = feeTransfer(1n, { destination: usdcAssociatedTokenAddress(RELAYER) });
    rejects(() => validateRelayReceiveTransaction(relayV0Transaction([...instructions, drain], addresses), expectation()),
        'cctp_relay_tx_rejected');
    rejects(() => validateRelayReceiveTransaction(relayV0Transaction([
        createUsdcAccountIdempotentInstruction({ payer: RELAYER, owner: RELAYER }), ...instructions], addresses), expectation()),
    'cctp_relay_tx_rejected');
    // The compute budget may only set a bounded limit: no priority price, no missing or oversized limit.
    rejects(() => validateRelayReceiveTransaction(relayV0Transaction([
        ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 1 }), instructions[1]], addresses), expectation()),
    'cctp_relay_tx_rejected');
    rejects(() => validateRelayReceiveTransaction(relayV0Transaction([instructions[1]], addresses), expectation()),
        'cctp_relay_tx_rejected');
    rejects(() => validateRelayReceiveTransaction(relayV0Transaction(receiveInstructions({ message, attestation,
        units: 1_400_001 }), addresses), expectation()), 'cctp_relay_tx_rejected');
    // A different (also validly attested) message, the right one into another account, or unknown attesters.
    const other = inboundMessage(plan, { body: { amount: 1_000_000n } });
    rejects(() => validateRelayReceiveTransaction(relayV0Transaction(receiveInstructions({ message: other,
        attestation: attest(other) }), addresses), expectation()), 'cctp_relay_tx_rejected');
    const swapped = web3(receiveInstructions({ message, attestation })[1]);
    swapped.keys[15] = { ...swapped.keys[15], pubkey: new PublicKey(usdcAssociatedTokenAddress(RELAYER)) };
    rejects(() => validateRelayReceiveTransaction(relayV0Transaction([instructions[0], swapped], addresses), expectation()),
        'cctp_relay_tx_rejected');
    rejects(() => validateRelayReceiveTransaction(relayV0Transaction(receiveInstructions({ message, attestation:
        attest(message, [new Uint8Array(32).fill(0x44), new Uint8Array(32).fill(0x55)]) }), addresses), expectation()),
    'cctp_attestation_invalid');
    // Receives are free; any fee is refused.
    rejects(() => validateRelayReceiveTransaction(honest, expectation({ fee: '1' })), 'relay_fee_above_cap');
    // A different fee payer, or a missing relayer signature.
    const other2 = Keypair.fromSeed(new Uint8Array(32).fill(51));
    rejects(() => validateRelayReceiveTransaction(relayV0Transaction(instructions, addresses, { feePayer: other2,
        signers: [other2] }), expectation()), 'cctp_relay_tx_rejected');
    rejects(() => validateRelayReceiveTransaction(relayV0Transaction(instructions, addresses, { signers: [] }), expectation()),
        'cctp_relay_tx_rejected');
    // The lookup table must exist on chain, be active and agree with what the relayer reported.
    const rpc = new Map([[ALT_KEY, rpcAccount(LOOKUP_TABLE_PROGRAM, lookupTableData(addresses))]]);
    t.mock.method(globalThis, 'fetch', async (_url, init) => {
        const { params } = JSON.parse(init.body);
        return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: { value: rpc.get(params[0]) || null } }));
    });
    assert.deepEqual((await readLookupTables(funding, tables))[0].addresses, addresses);
    await rejectsAsync(readLookupTables(funding, [{ address: ALT_KEY, addresses: [...addresses].reverse() }]),
        'cctp_relay_tx_rejected');
    rpc.set(ALT_KEY, rpcAccount(LOOKUP_TABLE_PROGRAM, lookupTableData(addresses, { deactivated: true })));
    await rejectsAsync(readLookupTables(funding, tables), 'cctp_relay_tx_rejected');
    rpc.set(ALT_KEY, rpcAccount(TOKEN_PROGRAM_ID, lookupTableData(addresses)));
    await rejectsAsync(readLookupTables(funding, tables), 'cctp_relay_tx_rejected');
});

test('a relayed close must pay exactly this proof into ATA(ek) and only a capped fee to the relayer', async () => {
    const tables = [{ address: ALT_KEY, addresses: EXIT_TABLE }];
    const expectation = (changes = {}) => ({ funding, kind: 'mutual', relayer: RELAYER, ek: EK, feeAccount: FEE_ACCOUNT,
        fee: 250_000n, maxFee: CCTP_FEE_CAPS.close, publicInputs: PUBLIC_INPUTS, proof: PROOF, lookupTables: tables,
        ...changes });
    const honest = unsignedV0(await exitInstructions(), EXIT_TABLE);
    await validateRelayExitTransaction(honest, expectation());
    signTransactionWith(honest, [ek.keypair]);
    await rejectsAsync(validateRelayExitTransaction(relayV0Transaction(await exitInstructions(), EXIT_TABLE), expectation()),
        'cctp_relay_tx_rejected');
    await rejectsAsync(validateRelayExitTransaction(unsignedV0(await exitInstructions({
        destination: usdcAssociatedTokenAddress(RELAYER) }), EXIT_TABLE), expectation()), 'cctp_relay_tx_rejected');
    await rejectsAsync(validateRelayExitTransaction(unsignedV0([...await exitInstructions(),
        feeTransfer(1n, { destination: usdcAssociatedTokenAddress(RELAYER) })], EXIT_TABLE), expectation()), 'cctp_relay_tx_rejected');
    await rejectsAsync(validateRelayExitTransaction(unsignedV0(await exitInstructions({
        publicInputs: { ...PUBLIC_INPUTS, final_balance: '4000000' } }), EXIT_TABLE), expectation()), 'cctp_relay_tx_rejected');
    await rejectsAsync(validateRelayExitTransaction(honest, expectation({ fee: CCTP_FEE_CAPS.close + 1n })), 'relay_fee_above_cap');
    await rejectsAsync(validateRelayExitTransaction(honest, expectation({
        publicInputs: { ...PUBLIC_INPUTS, final_balance: '200000' } })), 'relay_fee_above_cap');
});

test('fee caps, CCTP fee policy, refund timing and recipients follow the contract', () => {
    assert.equal(relayFeeCap('receive'), 0n, 'a fallback receive is free');
    assert.equal(relayFeeCap('deposit'), 400_000n);
    assert.equal(relayFeeCap('close'), 750_000n);
    assert.equal(relayFeeCap('burn'), 50_000n);
    assert.equal(relayFeeCap('sweep'), 50_000n);
    assert.equal(cctpFeePolicyCap('inbound', 10_000_000n), 500_000n);
    assert.equal(cctpFeePolicyCap('inbound', 1_000_000_000n), 5_000_000n);
    assert.equal(cctpFeePolicyCap('outboundForward', 10_000_000n), 1_500_000n);
    assert.equal(cctpFeePolicyCap('outboundSelf', 10_000_000n), 100_000n);
    const fees = [{ finalityThreshold: 1000, minimumFee: 1.3, forwardFee: { low: 245_139, med: 246_092, high: 266_062 } },
        { finalityThreshold: 2000, minimumFee: 0, forwardFee: { low: 245_139, med: 246_092, high: 266_062 } }];
    const fast = cctpMaxFee({ fees, amount: 10_000_000n, finality: 'fast', policyCap: 500_000n });
    assert.deepEqual([fast.minFinalityThreshold, fast.protocolFee, fast.forwardFee, fast.baseFee, fast.maxFee],
        [1000, 1_300n, 266_062n, 267_362n, 267_362n + 66_840n]);
    // Headroom never lifts maxFee above the policy; a quote above the policy is refused.
    assert.equal(cctpMaxFee({ fees, amount: 10_000_000n, policyCap: 300_000n }).maxFee, 300_000n);
    const forged = [{ finalityThreshold: 1000, minimumFee: 1, forwardFee: { high: 9_000_000 } }];
    rejects(() => cctpMaxFee({ fees: forged, amount: 10_000_000n, policyCap: 500_000n }), 'cctp_fee_above_policy');
    assert.throws(() => cctpMaxFee({ fees, amount: 10_000_000n }), /policy cap is required/);
    assert.equal(cctpMaxFee({ fees: [fees[1]], amount: 10_000_000n, finality: 'fast', policyCap: 500_000n })
        .minFinalityThreshold, 2000);
    const intent = { refundAfter: 2_000_000_000n };
    rejects(() => assertRefundAllowed(intent, { now: 1_999_999_999 }), 'cctp_refund_too_early');
    assert.equal(assertRefundAllowed(intent, { now: 1_999_999_999, force: true }), true);
    for (const dead of ['0x0000000000000000000000000000000000000000', '0x000000000000000000000000000000000000dEaD',
        EVM_CCTP.base.usdc, EVM_CCTP.base.tokenMessenger]) {
        rejects(() => assertEvmRecipient(dead, EVM_CCTP.base), 'cctp_recipient_rejected');
    }
    assert.equal(assertEvmRecipient(RECIPIENT, EVM_CCTP.base), RECIPIENT);
});

test('the EVM burn approves only a short allowance and persists before and after the burn prompt', async () => {
    const calls = [];
    const events = [];
    const provider = { request: async ({ method, params }) => {
        calls.push(method);
        if (method === 'eth_call') return `0x${(params[0].data.startsWith('0xdd62ed3e') ? 0n : 10n ** 12n).toString(16).padStart(64, '0')}`;
        if (method === 'eth_sendTransaction') return `0x${String(calls.length).padStart(64, '0')}`;
        if (method === 'eth_getTransactionReceipt') return { status: '0x1', transactionHash: params[0] };
        throw new Error(method);
    } };
    await burnUsdcOnEvm({ provider, chain: EVM_CCTP.base, from: BURNER, amount: 5n, approveCalldata: '0x01', burnCalldata: '0x02',
        onApproveHash: async () => events.push('approve'), onBurnRequested: async () => events.push('requested'),
        onBurnHash: async () => events.push('hash') });
    assert.deepEqual(events, ['approve', 'requested', 'hash']);
    assert.equal(calls.filter(method => method === 'eth_sendTransaction').length, 2);
});

// ---------------------------------------------------------------------------
// End-to-end flows with mocked Solana RPC, relay, Iris and EIP-1193.

function harness() {
    const store = { runtime: { version: 1, deploymentId: 'cctp-test', state: null, journal: null, pendingDeposit: null,
        preparedWithdrawal: null, lease: null }, withdrawals: [] };
    const makeRuntime = () => {
        const runtime = new BrowserWalletRuntime();
        runtime.init = async () => {};
        runtime.manifest = { deployment_id: 'cctp-test', billing_asset: 'usdc' };
        runtime.config = { funding, wallet_core: {} };
        runtime.reload = async () => {
            runtime.runtime = structuredClone(store.runtime);
            runtime.withdrawals = structuredClone(store.withdrawals);
            return runtime.runtime;
        };
        runtime.commit = async next => {
            store.runtime = structuredClone(next);
            runtime.runtime = structuredClone(next);
            return runtime.runtime;
        };
        runtime.worker = { call: async (operation, payload) => {
            if (operation === 'generateDeposit') return { secret: SECRET, registration_commitment: COMMITMENT };
            if (operation === 'withdrawalNullifier') return '0x1234';
            assert.equal(operation, 'confirmDeposit');
            return { note_id: payload.args.note_id, deposit_amount: payload.args.amount, expiry_ts: payload.args.expiry_ts,
                secret_s: SECRET };
        } };
        runtime.nextDepositPath = async () => ({ note_id: NOTE_ID, active_root: '0x1', siblings: new Array(32).fill('0x0') });
        return runtime;
    };
    const programData = base58Encode(new Uint8Array(32).fill(12));
    const accounts = new Map([
        [funding.vault_state, rpcAccount(funding.program_id, vaultAccountData(funding, { nextNoteId: NOTE_ID }))],
        [funding.program_id, rpcAccount(UPGRADEABLE_LOADER, Uint8Array.from([2, 0, 0, 0, ...new Uint8Array(32).fill(12)]), true)],
        [programData, rpcAccount(UPGRADEABLE_LOADER, Uint8Array.from([3, 0, 0, 0, ...new Array(9).fill(0)]))]
    ]);
    // prepared: submit token → what the relay prepared; submits: every /v2/relay/submit body;
    // submitted: tx signature → hex of the complete bytes submit returned. expiredTokens,
    // dropSubmitResponses (the response is lost after the relay broadcast) and tamper drive failures.
    // sent: what the wallet broadcast; relayBroadcasts: what the relay itself broadcast on submit
    // (only with relayBroadcastsOnSubmit); history: address → signatures of landed transactions.
    const state = { ataBalance: 0n, sent: [], relay: [], evm: [], evmSent: [], solanaMessages: new Map(), tables: [],
        outboundForward: 56_352, prepared: new Map(), submits: [], submitted: new Map(), expiredTokens: new Set(),
        dropSubmitResponses: 0, tamper: null, relayBroadcastsOnSubmit: false, relayBroadcasts: [], history: new Map() };
    const issueToken = (bytes, { signers, format, tables = [] }) => {
        const token = `submit-${state.prepared.size + 1}`;
        state.prepared.set(token, { bytes: Uint8Array.from(bytes), signers, format, tables });
        return token;
    };
    const setAta = amount => {
        state.ataBalance = amount;
        accounts.set(ATA, rpcAccount(TOKEN_PROGRAM_ID, tokenAccountData({ owner: EK, amount })));
    };
    const setTable = addresses => {
        state.tables = [{ address: ALT_KEY, addresses }];
        accounts.set(ALT_KEY, rpcAccount(LOOKUP_TABLE_PROGRAM, lookupTableData(addresses)));
    };
    const plan = () => store.runtime.pendingDeposit?.cctp;
    const json = body => new Response(JSON.stringify(body), { status: 200 });
    const discriminator = name => sha256(new TextEncoder().encode(`global:${name}`)).slice(0, 8);
    // Land a fully signed transaction: verify it, log it in `log` and every key's history, apply its effects.
    const land = (bytes, log) => {
        const decoded = decodeTransaction(bytes, state.tables);
        decoded.signatures.forEach((signature, index) => assert.ok(
            ed25519.verify(signature, decoded.message, base58Decode(decoded.staticKeys[index], 32)),
            'every signature is present and valid'));
        log.push(decoded);
        const signature = base58Encode(decoded.signatures[0]);
        for (const key of new Set(decoded.staticKeys)) state.history.set(key, [...(state.history.get(key) || []), signature]);
        const programs = decoded.instructions.map(ix => ix.programId);
        const vaultIx = decoded.instructions.find(ix => ix.programId === funding.program_id
            && ['execute_deposit', 'execute_close', 'execute_escape'].some(name =>
                Buffer.from(ix.data.slice(0, 8)).equals(Buffer.from(discriminator(name)))));
        if (programs.includes(MESSAGE_TRANSMITTER_V2)) {
            accounts.set(usedNonce(NONCE).toBase58(), rpcAccount(MESSAGE_TRANSMITTER_V2,
                Uint8Array.of(212, 222, 157, 252, 130, 71, 179, 238, 1)));
            setAta(state.ataBalance + 9_700_000n);
        } else if (vaultIx && Buffer.from(vaultIx.data.slice(0, 8)).equals(Buffer.from(discriminator('execute_deposit')))) {
            accounts.set(NOTE, rpcAccount(funding.program_id, noteAccountData(funding, { noteId: NOTE_ID,
                commitment: COMMITMENT, amount: state.depositAmount })));
            accounts.set(funding.vault_state, rpcAccount(funding.program_id, vaultAccountData(funding, { nextNoteId: NOTE_ID + 1 })));
            setAta(state.ataBalance - state.depositAmount - 100_000n);
        } else if (vaultIx) {
            accounts.set(cctpNotePda(funding, 3), rpcAccount(funding.program_id, noteAccountData(funding,
                { noteId: 3, status: 4, commitment: COMMITMENT })));
            setAta(5_000_000n - 250_000n);
        } else if (programs.includes(TOKEN_MESSENGER_MINTER_V2)) {
            const burn = state.pendingBurn;
            accounts.set(burn.event, rpcAccount(MESSAGE_TRANSMITTER_V2,
                messageSentData(outboundMessage({ target: burn.target, amount: burn.amount }))));
            state.solanaMessages.set(signature, burn);
            setAta(0n);
        }
        else setAta(0n);
        return signature;
    };
    const rpc = (method, params) => {
        switch (method) {
        case 'getGenesisHash': return funding.genesis_hash;
        case 'getAccountInfo': return { context: { slot: 9 }, value: accounts.get(params[0]) || null };
        case 'getMultipleAccounts': return { context: { slot: 9 }, value: params[0].map(address => accounts.get(address) || null) };
        case 'getBalance': return { value: 0 };
        case 'getMinimumBalanceForRentExemption': return (128 + params[0]) * 6960;
        case 'getSignatureStatuses': return { value: params[0].map(() => ({ slot: 10, confirmationStatus: 'finalized', err: null })) };
        case 'getBlockHeight': return state.blockHeight ?? 1;
        case 'getSlot': return 9;
        case 'isBlockhashValid':
            assert.equal(params[0], BLOCKHASH);
            return { context: { slot: 9 }, value: !state.invalidBlockhash };
        case 'getLatestBlockhash':
            assert.equal(params[0].minContextSlot, 9);
            return { context: { slot: 9 }, value: { blockhash: BLOCKHASH, lastValidBlockHeight: 500 } };
        case 'sendTransaction': return land(Buffer.from(params[0], 'base64'), state.sent);
        case 'getSignaturesForAddress': return [...(state.history.get(params[0]) || [])].reverse()
            .map(signature => ({ signature, slot: 10, err: null, memo: null, blockTime: null, confirmationStatus: 'finalized' }));
        default: throw new Error(`unexpected RPC ${method}`);
        }
    };
    const submit = body => {
        const invalid = message => ({ status: 400, error: { code: 'invalid_request', message } });
        const entry = state.prepared.get(body.token);
        if (!entry) return invalid('unknown submit token');
        if (state.expiredTokens.has(body.token)) {
            return { status: 409, error: { code: 'relay_transaction_expired', message: 'the blockhash expired; prepare again' } };
        }
        const sent = decodeTransaction(Uint8Array.from(body.transaction), entry.tables);
        if (!Buffer.from(sent.message).equals(Buffer.from(decodeTransaction(entry.bytes, entry.tables).message))) {
            return invalid('the message differs from the prepared one');
        }
        const ekIndex = sent.staticKeys.indexOf(EK);
        let ekSigned = false;
        try {
            ekSigned = ed25519.verify(sent.signatures[ekIndex], sent.message, base58Decode(EK, 32));
        } catch {
            ekSigned = false;
        }
        if (!ekSigned) return invalid('missing or invalid ek signature');
        const full = Uint8Array.from(body.transaction);
        for (const keypair of entry.signers) {
            const index = sent.staticKeys.indexOf(keypair.publicKey.toBase58());
            full.set(ed25519.sign(sent.message, keypair.secretKey.slice(0, 32)), 1 + index * 64);
        }
        const signature = base58Encode(full.slice(1, 65));
        state.submitted.set(signature, hex(full));
        const response = { signature, transaction: { format: entry.format, bytes: [...full], last_valid_height: 500 } };
        if (state.relayBroadcastsOnSubmit) land(full, state.relayBroadcasts);
        if (state.dropSubmitResponses > 0) {
            state.dropSubmitResponses -= 1;
            throw new TypeError('the connection dropped after the relay broadcast');
        }
        return state.tamper ? state.tamper(response) : response;
    };
    const relay = async (path, body) => {
        state.relay.push({ path, body });
        if (path === '/v2/relay/submit') {
            state.submits.push(structuredClone(body));
            return submit(body);
        }
        if (path === '/v2/relay') {
            return { relayer: RELAYER, fee_account: FEE_ACCOUNT, margin_bps: 2000, sol_usd_micros: '150000000',
                usdc_mint: USDC_MINT, iris_url: 'https://iris.example', burn_minimum: state.burnMinimum ?? '1000000',
                quotes: { deposit: '100000', receive: '0', close: '250000', escape: '400000', burn: '40000', sweep: '40000' } };
        }
        if (path === '/v2/relay/receives/prepare') {
            assert.equal(body.owner, EK);
            if (!accounts.has(ATA)) {
                return { status: 409, error: { code: 'insufficient_funds', message: 'ATA(owner) does not exist' } };
            }
            const message = inboundMessage(plan());
            const instructions = receiveInstructions({ message, attestation: attest(message) });
            const addresses = receiveTableOf(instructions);
            setTable(addresses);
            return { fee: '0', nonce: hex(NONCE), recipient_token_account: ATA,
                transaction: { format: 'solana-v0-transaction-v1', bytes: [...relayV0Transaction(instructions, addresses)],
                    last_valid_height: 500, lookup_tables: [{ address: ALT_KEY, addresses }] } };
        }
        if (path === '/v2/relay/deposits/prepare') {
            assert.equal(body.depositor, EK);
            const amount = BigInt(body.amount);
            state.depositAmount = amount;
            setTable(DEPOSIT_TABLE);
            const bytes = depositTx(depositInstructions({ fee: 100_000n, noteId: body.expected_note_id,
                commitment: body.commitment, amount }));
            return { fee: '100000', operation: OPERATION, note: NOTE,
                operation_rent: String(OPERATION_RENT), note_rent: String(NOTE_RENT),
                submit_token: issueToken(bytes, { signers: [relayer], format: 'solana-v0-transaction-v1',
                    tables: [{ address: ALT_KEY, addresses: DEPOSIT_TABLE }] }),
                transaction: { format: 'solana-v0-transaction-v1', bytes: [...bytes], last_valid_height: 500,
                    lookup_tables: [{ address: ALT_KEY, addresses: DEPOSIT_TABLE }] } };
        }
        if (path === '/v2/relay/sweeps/prepare') {
            const amount = state.ataBalance - 40_000n;
            const bytes = relayTransaction([feeTransfer(40_000n), transferCheckedInstruction({
                source: ATA, mint: USDC_MINT, destination: body.destination, authority: EK, amount })]);
            return { fee: '40000', amount: String(amount),
                submit_token: issueToken(bytes, { signers: [relayer], format: 'solana-legacy-transaction-v1' }),
                transaction: { format: 'solana-legacy-transaction-v1', bytes: [...bytes], last_valid_height: 500 } };
        }
        if (path === '/v2/relay/exits/prepare') {
            assert.equal(body.destination_owner, EK);
            const instructions = await exitInstructions({ publicInputs: body.public_inputs });
            setTable(EXIT_TABLE);
            const bytes = unsignedV0(instructions, EXIT_TABLE);
            return { fee: '250000', destination: ATA,
                submit_token: issueToken(bytes, { signers: [relayer], format: 'solana-v0-transaction-v1',
                    tables: [{ address: ALT_KEY, addresses: EXIT_TABLE }] }),
                transaction: { format: 'solana-v0-transaction-v1', bytes: [...bytes],
                    last_valid_height: 500, lookup_tables: [{ address: ALT_KEY, addresses: EXIT_TABLE }] } };
        }
        if (path === '/v2/relay/burns/prepare') {
            const event = Keypair.fromSeed(new Uint8Array(32).fill(62));
            const fee = 40_000n;
            const amount = state.ataBalance - fee;
            const target = { destinationDomain: body.destination_domain, mintRecipient: fromHex(body.mint_recipient),
                destinationCaller: fromHex(body.destination_caller), maxCctpFee: BigInt(body.max_cctp_fee),
                minFinalityThreshold: body.min_finality_threshold, hookData: fromHex(body.hook_data) };
            state.pendingBurn = { target, amount, event: event.publicKey.toBase58() };
            const bytes = relayTransaction(burnInstructions({ event, fee, amount, target }));
            return { fee: String(fee), amount: String(amount), message_sent_event_account: event.publicKey.toBase58(),
                submit_token: issueToken(bytes, { signers: [relayer, event], format: 'solana-legacy-transaction-v1' }),
                transaction: { format: 'solana-legacy-transaction-v1', bytes: [...bytes], last_valid_height: 500 } };
        }
        throw new Error(`unexpected relay ${path}`);
    };
    const iris = url => {
        if (url.pathname.startsWith('/v2/burn/USDC/fees/')) {
            const toSolana = url.pathname.endsWith('/5');
            const forward = toSolana ? 266_062 : state.outboundForward;
            return [{ finalityThreshold: 1000, minimumFee: 1.3, forwardFee: { low: forward, med: forward, high: forward } },
                { finalityThreshold: 2000, minimumFee: 0, forwardFee: { low: forward, med: forward, high: forward } }];
        }
        const [, , , source] = url.pathname.split('/');
        const hash = url.searchParams.get('transactionHash');
        if (source === '6') {
            assert.equal(hash, plan().burnTxHash);
            const message = inboundMessage(plan());
            return { messages: [{ status: 'complete', attestation: attest(message), message: `0x${hex(message)}` }] };
        }
        const burn = state.solanaMessages.get(hash);
        if (!burn) return { messages: [] };
        const message = outboundMessage({ target: burn.target, amount: burn.amount, filled: true });
        return { messages: [{ status: 'complete', attestation: attest(message), message: `0x${hex(message)}` }] };
    };
    const fetch = async (input, init = {}) => {
        const url = new URL(input);
        if (url.href === funding.rpc_url || url.href === `${funding.rpc_url}/`) {
            const { method, params } = JSON.parse(init.body);
            return json({ jsonrpc: '2.0', id: 1, result: rpc(method, params) });
        }
        if (url.origin === new URL(funding.protocol_server_url).origin) {
            const { status = 200, ...body } = await relay(url.pathname, init.body ? JSON.parse(init.body) : null);
            return new Response(JSON.stringify(body), { status });
        }
        if (url.origin === 'https://iris.example') return json(iris(url));
        throw new Error(`unexpected fetch ${url}`);
    };
    const evmProvider = ({ failBurnReceipt = false } = {}) => {
        let chain = 1;
        return { request: async ({ method, params }) => {
            state.evm.push(method);
            switch (method) {
            case 'eth_requestAccounts': return [BURNER];
            case 'eth_chainId': return `0x${chain.toString(16)}`;
            case 'wallet_switchEthereumChain': chain = parseInt(params[0].chainId, 16); return null;
            case 'eth_call': return `0x${(params[0].data.startsWith('0xdd62ed3e') ? 0n : 10n ** 12n).toString(16).padStart(64, '0')}`;
            case 'eth_sendTransaction': {
                const kind = params[0].data.startsWith('0x095ea7b3') ? 'approve' : 'burn';
                state.evmSent.push({ kind, ...params[0] });
                return `0x${(kind === 'approve' ? 'a' : 'b').repeat(64)}`;
            }
            case 'eth_getTransactionReceipt':
                if (failBurnReceipt && params[0] === `0x${'b'.repeat(64)}`) throw new Error('the tab closed');
                return { status: '0x1', transactionHash: params[0] };
            default: throw new Error(`unexpected EVM ${method}`);
            }
        } };
    };
    return { store, state, accounts, makeRuntime, fetch, evmProvider, setAta,
        wallet: (runtime, options = {}) => new ZkapiCctpWallet({ runtime, options: { pollIntervalMs: 1, receiveFallbackMs: 0,
            attesters: ATTESTERS, ...options } }) };
}

/** Plan a deposit, acknowledge its backup, and die while waiting for the EVM burn receipt. */
async function burnThenCrash(env) {
    const wallet = env.wallet(env.makeRuntime());
    const pending = await wallet.deposit({ sourceChain: 'base', amount: '10', finality: 'fast',
        evmProvider: env.evmProvider() });
    assert.equal(pending.status, 'backup_required');
    await wallet.acknowledgeBackup(pending.backup.operationId);
    await assert.rejects(wallet.deposit({ evmProvider: env.evmProvider({ failBurnReceipt: true }) }), /the tab closed/);
}

/**
 * Every relay-co-signed transaction the wallet broadcast is fully signed and
 * byte-identical to what /v2/relay/submit returned (never a prepared or
 * ek-signed-only transaction). Returns how many there were.
 */
function assertBroadcastsCameFromSubmit(env) {
    const relayed = env.state.sent.filter(tx => tx.accountKeys[0] === RELAYER && tx.signatures.length > 1);
    for (const tx of relayed) {
        tx.signatures.forEach((signature, index) => assert.ok(
            ed25519.verify(signature, tx.message, base58Decode(tx.staticKeys[index], 32)), 'fully signed'));
        assert.equal(env.state.submitted.get(base58Encode(tx.signatures[0])), hex(tx.bytes),
            'broadcast only as /v2/relay/submit returned it');
    }
    return relayed.length;
}

/** Burn, then Circle attests while the mint has not arrived: the plan holds the attested inbound credential. */
async function attestedWithoutMint(env, balance = 50_000_000n) {
    await burnThenCrash(env);
    env.setAta(balance);
    await rejectsAsync(env.wallet(env.makeRuntime(), { receiveFallbackMs: 10 ** 9, arrivalTimeoutMs: 20 }).deposit(),
        'cctp_arrival_pending');
    const plan = env.store.runtime.pendingDeposit.cctp;
    assert.equal(plan.phase, 'attested');
    return { source_domain: 6, message: plan.attested.message, attestation: plan.attested.attestation };
}

test('a new CCTP deposit stops for a mandatory backup before any EVM burn', async t => {
    const env = harness();
    t.mock.method(globalThis, 'fetch', env.fetch);
    const wallet = env.wallet(env.makeRuntime());
    const first = await wallet.deposit({ sourceChain: 'base', amount: '10', evmProvider: env.evmProvider() });
    assert.equal(first.status, 'backup_required');
    assert.equal(first.backup.secret, SECRET);
    assert.equal(first.backup.emergencyKey, EK);
    assert.equal(first.backup.authorizedCctpFee, env.store.runtime.pendingDeposit.cctp.maxFee);
    assert.ok(BigInt(first.backup.authorizedCctpFee) <= cctpFeePolicyCap('inbound', 10_000_000n));
    assert.equal(env.store.runtime.pendingDeposit.cctp.phase, 'backup_required');
    assert.equal(env.store.runtime.pendingDeposit.cctp.storagePersisted, false);
    // A handler that declines (returns false) keeps the plan blocked; resuming without one too.
    assert.equal((await wallet.deposit({ evmProvider: env.evmProvider(), onBackup: async () => false })).status, 'backup_required');
    assert.equal((await wallet.deposit({ evmProvider: env.evmProvider() })).status, 'backup_required');
    await rejectsAsync(wallet.burnOnEvm(env.store.runtime.pendingDeposit, { evmProvider: env.evmProvider() }),
        'cctp_backup_required');
    assert.equal(env.state.evmSent.length, 0, 'no approve or burn before the backup is acknowledged');
    // An accepting handler persists the acknowledgement before the burn prompt.
    let acknowledgedBeforeBurn = null;
    const failing = env.evmProvider({ failBurnReceipt: true });
    await assert.rejects(wallet.deposit({ evmProvider: { request: async args => {
        if (args.method === 'eth_sendTransaction') {
            acknowledgedBeforeBurn = env.store.runtime.pendingDeposit.cctp.backupAcknowledgedAt;
        }
        return failing.request(args);
    } }, onBackup: async () => true }), /the tab closed/);
    assert.ok(acknowledgedBeforeBurn > 0);
    // Attesters must be pinned: without them nothing is planned at all.
    const unpinned = harness();
    t.mock.method(globalThis, 'fetch', unpinned.fetch);
    await rejectsAsync(unpinned.wallet(unpinned.makeRuntime(), { attesters: null }).deposit({ sourceChain: 'base',
        amount: '10', evmProvider: unpinned.evmProvider() }), 'cctp_attesters_unconfigured');
});

test('a CCTP deposit resumes after a reload, ignores front-run dust and deposits only the attested net mint', async t => {
    const env = harness();
    t.mock.method(globalThis, 'fetch', env.fetch);
    await burnThenCrash(env);
    const plan = env.store.runtime.pendingDeposit;
    assert.equal(plan.cctp.phase, 'burn_requested');
    assert.equal(plan.cctp.burnTxHash, `0x${'b'.repeat(64)}`);
    const burn = env.state.evmSent.find(entry => entry.kind === 'burn');
    assert.equal(burn.to, EVM_CCTP.base.tokenMessenger.toLowerCase());
    assert.ok(burn.data.startsWith('0x779b432d'));
    assert.ok(burn.data.includes(hex(base58Decode(ATA, 32))), 'mintRecipient = ATA(ek)');
    await rejectsAsync(env.wallet(env.makeRuntime()).refund(), 'cctp_refund_too_early');
    // Someone front-runs the mint with dust into the public ATA(ek).
    env.setAta(1_000_000n);
    const resumed = await env.wallet(env.makeRuntime()).deposit();
    assert.equal(resumed.status, 'confirmed');
    assert.equal(resumed.amount, 9_600_000);
    assert.equal(env.state.evmSent.filter(entry => entry.kind === 'burn').length, 1);
    assert.equal(env.store.runtime.pendingDeposit, null);
    const prepare = env.state.relay.find(entry => entry.path === '/v2/relay/deposits/prepare').body;
    // The attested net mint (10 USDC − 0.3 feeExecuted) − the 0.1 deposit quote; the dust is not deposited.
    // The attested inbound transfer travels as the relay's sponsorship credential.
    const message = inboundMessage(plan.cctp);
    assert.deepEqual({ ...prepare, zero_path: prepare.zero_path.length }, { depositor: EK, expected_note_id: NOTE_ID,
        commitment: COMMITMENT, amount: '9600000', zero_path: 32, max_fee: String(CCTP_FEE_CAPS.deposit),
        inbound: { source_domain: 6, message: `0x${hex(message)}`, attestation: attest(message) } });
    const receive = env.state.relay.find(entry => entry.path === '/v2/relay/receives/prepare').body;
    assert.deepEqual(receive, { source_domain: 6, transaction_hash: `0x${'b'.repeat(64)}`, owner: EK, max_fee: '0' });
    assert.equal(env.state.ataBalance, 1_000_000n, 'the dust stays in ATA(ek), sweepable');
    const [receiveTx, depositTx] = env.state.sent;
    assert.equal(receiveTx.version, 0);
    assert.equal(receiveTx.signatures.length, 1, 'the relayer-signed receive is broadcast as is');
    assert.equal(depositTx.accountKeys[0], RELAYER);
    assert.equal(assertBroadcastsCameFromSubmit(env), 1);
    assert.deepEqual(env.state.submits.map(entry => entry.token), ['submit-1']);
});

test('dust alone never counts as the arrival of a CCTP transfer', async t => {
    const env = harness();
    t.mock.method(globalThis, 'fetch', env.fetch);
    await burnThenCrash(env);
    env.setAta(50_000_000n);
    await rejectsAsync(env.wallet(env.makeRuntime(), { receiveFallbackMs: 10 ** 9, arrivalTimeoutMs: 20 }).deposit(),
        'cctp_arrival_pending');
    assert.equal(env.state.relay.some(entry => entry.path === '/v2/relay/deposits/prepare'), false);
    assert.equal(env.store.runtime.pendingDeposit.cctp.phase, 'attested');
    assert.equal(env.store.runtime.pendingDeposit.cctp.attested.netAmount, '9700000');
});

test('a prefunded or malformed nonce PDA never proves arrival even with enough USDC in the ATA', async t => {
    const env = harness();
    t.mock.method(globalThis, 'fetch', env.fetch);
    await attestedWithoutMint(env);
    for (const [owner, data] of [
        [SystemProgram.programId.toBase58(), new Uint8Array()],
        [SystemProgram.programId.toBase58(), Uint8Array.of(212, 222, 157, 252, 130, 71, 179, 238, 1)],
        [MESSAGE_TRANSMITTER_V2, Uint8Array.of(1)],
        [MESSAGE_TRANSMITTER_V2, Uint8Array.of(212, 222, 157, 252, 130, 71, 179, 238, 0)]
    ]) {
        env.accounts.set(usedNonce(NONCE).toBase58(), rpcAccount(owner, data));
        await rejectsAsync(env.wallet(env.makeRuntime(), { receiveFallbackMs: 10 ** 9, arrivalTimeoutMs: 20 }).deposit(),
            'cctp_arrival_pending');
        assert.equal(env.state.relay.some(entry => entry.path === '/v2/relay/deposits/prepare'), false);
    }
});

test('a refund keeps the intent\'s authorized CCTP fee unless the user authorizes a new one within policy', async t => {
    const env = harness();
    t.mock.method(globalThis, 'fetch', env.fetch);
    await burnThenCrash(env);
    env.setAta(9_700_000n);
    const intentBefore = env.store.runtime.pendingDeposit.cctp.intent;
    // Circle's quote rose: the persisted refund target is not raised silently.
    env.state.outboundForward = 900_000;
    await rejectsAsync(env.wallet(env.makeRuntime()).refund({ force: true }), 'cctp_fee_above_authorized');
    assert.equal(env.state.relay.some(entry => entry.path === '/v2/relay/burns/prepare'), false);
    await rejectsAsync(env.wallet(env.makeRuntime()).refund({ force: true, maxCctpFee: 2_000_000n }), 'cctp_fee_above_policy');
    const result = await env.wallet(env.makeRuntime()).refund({ force: true, maxCctpFee: 1_200_000n });
    assert.equal(result.attestation.message.length > 2, true);
    assert.equal(result.amount, '9660000');
    const body = env.state.relay.find(entry => entry.path === '/v2/relay/burns/prepare').body;
    assert.equal(body.max_cctp_fee, '1200000');
    assert.equal(body.mint_recipient, hex(evmBytes32(BURNER)));
    assert.equal(body.min_finality_threshold, 2000);
    assert.equal(body.max_fee, String(relayFeeCap('burn')));
    assert.equal('inbound' in body, false, 'no attested inbound transfer is known, so no credential is sent');
    assert.equal(assertBroadcastsCameFromSubmit(env), 1);
    const archived = env.store.runtime.cctpArchive.at(-1);
    assert.equal(archived.cctp.phase, 'refunded');
    assert.equal(archived.secret, SECRET, 'the secret is archived, never deleted');
    assert.equal(archived.cctp.intent, intentBefore, 'the intent (and its refund fee) was never rewritten');
    assert.equal(archived.cctp.refundMaxCctpFee, '1200000');
});

/** In-memory stand-ins for the IndexedDB withdrawal-record moves (the store module needs a browser). */
function withRecordStore(env, runtime) {
    runtime.detachClosedWithdrawal = async details => {
        const record = { recordId: `rec-${details.noteId}`, mode: details.mode, phase: 'closed_unconfirmed',
            noteId: details.noteId, destination: details.destination, revision: 1, createdAt: Date.now(),
            ...(details.cctpExit ? { cctpExit: details.cctpExit } : {}) };
        env.store.withdrawals.push(record);
        env.store.runtime = { ...env.store.runtime, state: null, preparedWithdrawal: null };
        return structuredClone(record);
    };
    runtime.updateWithdrawal = async (recordId, changes) => {
        const index = env.store.withdrawals.findIndex(record => record.recordId === recordId);
        env.store.withdrawals[index] = { ...env.store.withdrawals[index], ...changes,
            revision: env.store.withdrawals[index].revision + 1 };
        return structuredClone(env.store.withdrawals[index]);
    };
    runtime.prepareWithdrawal = async (mode, destination) => {
        const plan = { mode, destination, phase: 'prepared', operationId: 'exit-op', noteId: 3, clearanceReserved: true,
            public_inputs: { ...PUBLIC_INPUTS, valid_until: Math.floor(Date.now() / 1000) + 600 }, proof: PROOF };
        env.store.runtime = { ...env.store.runtime, preparedWithdrawal: plan };
        return structuredClone(plan);
    };
    return runtime;
}

test('a mutual CCTP exit closes into ATA(ek) with an ek-signed relay transaction, then burns to the EVM recipient', async t => {
    const env = harness();
    t.mock.method(globalThis, 'fetch', env.fetch);
    env.store.runtime.state = { note_id: 3, secret_s: SECRET, current_balance: 5_000_000 };
    const runtime = withRecordStore(env, env.makeRuntime());
    await rejectsAsync(env.wallet(runtime).exit({ kind: 'mutual', destinationChain: 'base',
        recipient: '0x000000000000000000000000000000000000dEaD' }), 'cctp_recipient_rejected');
    assert.equal(env.state.relay.length, 0, 'a dead recipient is refused before any request');
    // The relay would refuse the burn (4.71 USDC after fees < 5): refused before the irreversible close.
    env.state.burnMinimum = '5000000';
    let prepared = 0;
    const prepare = runtime.prepareWithdrawal;
    runtime.prepareWithdrawal = async (...args) => { prepared += 1; return prepare(...args); };
    await assert.rejects(env.wallet(runtime).exit({ kind: 'mutual', destinationChain: 'base', recipient: RECIPIENT }),
        error => error.code === 'cctp_exit_below_minimum' && error.expected === 4_710_000n && error.minimum === 5_000_000n);
    assert.equal(prepared, 0, 'no clearance reserved and no proof made');
    assert.equal(env.state.relay.some(entry => entry.path !== '/v2/relay'), false, 'nothing prepared at the relay');
    env.state.burnMinimum = '1000000';
    // A relayed escape prepays its fee from ATA(ek): an empty account is refused up front.
    await rejectsAsync(env.wallet(runtime).exit({ kind: 'escape', destinationChain: 'base', recipient: RECIPIENT }),
        'cctp_escape_fee_required');
    const result = await env.wallet(runtime).exit({ kind: 'mutual', destinationChain: 'base', recipient: RECIPIENT });
    assert.equal(result.status, 'attested');
    const exit = env.state.relay.find(entry => entry.path === '/v2/relay/exits/prepare').body;
    assert.deepEqual({ kind: exit.kind, owner: exit.destination_owner, maxFee: exit.max_fee },
        { kind: 'mutual', owner: EK, maxFee: String(CCTP_FEE_CAPS.close) });
    assert.equal('inbound' in exit, false, 'the note backs an exit; no inbound credential');
    const record = env.store.withdrawals[0];
    assert.equal(record.phase, 'closed');
    assert.equal(record.cctpExit.phase, 'attested');
    // The CCTP fee ceiling was fixed at proving time and used unchanged for the burn.
    const burn = env.state.relay.find(entry => entry.path === '/v2/relay/burns/prepare').body;
    assert.equal(burn.max_cctp_fee, record.cctpExit.maxCctpFee);
    assert.deepEqual({ ...burn, max_cctp_fee: undefined }, { owner: EK, destination_domain: 6,
        mint_recipient: hex(evmBytes32(RECIPIENT)), destination_caller: '00'.repeat(32), max_cctp_fee: undefined,
        min_finality_threshold: 1000, hook_data: hex(encodeForwardHook({ createAtaOwner: null })),
        max_fee: String(relayFeeCap('burn')) });
    assert.equal(record.cctpExit.burn.amount, '4710000');
    assert.equal(runtime.snapshot().withdrawals[0].cctpExit.ekSeed, undefined, 'the key seed never reaches the UI snapshot');
    const again = await env.wallet(runtime).resumeExit(record.recordId);
    assert.equal(again.attestation, record.cctpExit.burn.attestation.attestation);
    assert.equal(env.state.sent.length, 2, 'one close, one burn; resuming never burns again');
    assert.equal(assertBroadcastsCameFromSubmit(env), 2, 'the close and the burn went through /v2/relay/submit');
    assert.deepEqual(env.state.submits.map(entry => entry.token), ['submit-1', 'submit-2']);
});

test('without a relayer the wallet reports that funds are safe in ATA(ek) and offers the self-funded path', async t => {
    const env = harness();
    t.mock.method(globalThis, 'fetch', async (input, init) => {
        if (new URL(input).pathname === '/v2/relay') {
            return new Response(JSON.stringify({ error: { code: 'relay_disabled', message: 'off' } }), { status: 404 });
        }
        return env.fetch(input, init);
    });
    const runtime = env.makeRuntime();
    env.store.runtime.pendingDeposit = { operationId: 'op', secret: SECRET, commitment: COMMITMENT, phase: 'cctp',
        cctp: { phase: 'arrived', ekPublicKey: EK, ata: ATA, attested: { netAmount: '1000000' }, receive: null } };
    env.setAta(1_000_000n);
    await rejectsAsync(env.wallet(runtime).deposit(), 'relay_unavailable');
    await assert.rejects(env.wallet(runtime).deposit(), error => error.emergencyKey === EK && error.emergencyAccount === ATA
        && error.balance === '1000000' && error.selfFundedAvailable === true && error.message.includes('safe'));
    const info = await env.wallet(runtime).emergencyInfo();
    assert.deepEqual({ ...info }, { emergencyKey: EK, emergencyAccount: ATA, balance: '1000000', relayAvailable: false,
        selfFundedAvailable: true });
    await rejectsAsync(env.wallet(runtime).deposit({ selfFunded: true }), 'cctp_ek_needs_sol');
});

test('hard relay fee caps cannot be raised by host configuration', () => {
    assert.throws(() => resolveCctpOptions({ feeCaps: { deposit: 400_001n } }), /only be lowered/);
    assert.equal(resolveCctpOptions({ feeCaps: { deposit: 1n } }).feeCaps.deposit, 1n);
});

test('backup import after browser loss recovers emergency funds without reburning', async t => {
    const env = harness();
    t.mock.method(globalThis, 'fetch', env.fetch);
    const original = env.wallet(env.makeRuntime());
    const { backup } = await original.deposit({ sourceChain: 'base', amount: '10', evmProvider: env.evmProvider() });
    assert.match(backup.recoveryScope, /Used notes require/);
    env.store.runtime.pendingDeposit = null;
    env.setAta(1_000_000n);
    const wallet = env.wallet(env.makeRuntime());
    await rejectsAsync(wallet.importBackup({ ...backup, emergencyKey: RELAYER }), 'cctp_backup_invalid');
    assert.equal((await wallet.importBackup(backup)).status, 'emergency_key_restored');
    await rejectsAsync(wallet.deposit({ evmProvider: env.evmProvider() }), 'cctp_burn_hash_unknown');
    assert.equal(env.state.evmSent.length, 0, 'import never authorizes another EVM burn');
    const destination = usdcAssociatedTokenAddress(RELAYER);
    env.accounts.set(destination, rpcAccount(TOKEN_PROGRAM_ID, tokenAccountData({ owner: RELAYER, amount: 0n })));
    const sweep = await wallet.sweep({ to: destination });
    assert.equal(sweep.amount, '960000');
    assert.equal(assertBroadcastsCameFromSubmit(env), 1);
    assert.equal('inbound' in env.state.relay.find(entry => entry.path === '/v2/relay/sweeps/prepare').body, false,
        'an imported backup has no attested inbound transfer to present');
    assert.equal(env.store.runtime.pendingDeposit, null);
    assert.equal(env.store.runtime.cctpArchive.at(-1).secret, SECRET);
});

test('backup import restores a never-used note and refuses used state or an occupied wallet', async t => {
    const env = harness();
    t.mock.method(globalThis, 'fetch', env.fetch);
    const { backup } = await env.wallet(env.makeRuntime()).deposit({
        sourceChain: 'base', amount: '10', evmProvider: env.evmProvider() });
    env.store.runtime.pendingDeposit = null;
    env.accounts.set(NOTE, rpcAccount(funding.program_id, noteAccountData(funding, {
        noteId: NOTE_ID, commitment: COMMITMENT, amount: 9_400_000n })));
    const runtime = env.makeRuntime();
    runtime.remoteJson = async () => ({ status: 'found', nullifier_status: 'spent' });
    const wallet = env.wallet(runtime);
    await rejectsAsync(wallet.importBackup(backup, { restoreUnspentNote: true, noteId: NOTE_ID }), 'cctp_used_note_backup');
    assert.equal(env.store.runtime.state, null);
    runtime.remoteJson = async () => { throw new Error('operator offline'); };
    assert.equal((await wallet.importBackup(backup, { restoreUnspentNote: true, noteId: NOTE_ID })).status, 'unspent_note_restored');
    assert.equal(env.store.runtime.state.secret_s, SECRET);
    await assert.rejects(wallet.importBackup(backup), /empty wallet/);
});

test('imported emergency backup retains the bound refund recipient and timing', async t => {
    const env = harness();
    t.mock.method(globalThis, 'fetch', env.fetch);
    const { backup } = await env.wallet(env.makeRuntime()).deposit({
        sourceChain: 'base', amount: '10', evmProvider: env.evmProvider() });
    env.store.runtime.pendingDeposit = null;
    env.setAta(1_000_000n);
    const wallet = env.wallet(env.makeRuntime());
    await wallet.importBackup(backup);
    await assert.rejects(wallet.refund(), /refund/i);
    await wallet.refund({ force: true });
    const request = env.state.relay.find(entry => entry.path === '/v2/relay/burns/prepare').body;
    assert.equal(request.mint_recipient, hex(evmBytes32(BURNER)));
    assert.equal(request.destination_domain, EVM_CCTP.base.domain);
});

test('expired inbound attestations are re-attested before fallback receiving', async t => {
    const env = harness();
    let reattested = false;
    t.mock.method(globalThis, 'fetch', async (input, init) => {
        const url = new URL(input);
        if (url.pathname.startsWith('/v2/reattest/')) {
            reattested = true;
            return new Response('{}', { status: 200 });
        }
        if (url.pathname === '/v2/messages/6' && !reattested) {
            const message = inboundMessage(env.store.runtime.pendingDeposit.cctp, { body: { expirationBlock: 9n } });
            return new Response(JSON.stringify({ messages: [{ status: 'complete',
                message: `0x${hex(message)}`, attestation: attest(message) }] }), { status: 200 });
        }
        return env.fetch(input, init);
    });
    await burnThenCrash(env);
    env.setAta(0n);
    await env.wallet(env.makeRuntime()).deposit();
    assert.equal(reattested, true);
    assert.ok(env.store.runtime.state);
});

test('a journaled refund burn blocks an overlapping inbound sweep', async () => {
    const wallet = new ZkapiCctpWallet({ runtime: {} });
    wallet.currentDeposit = async () => ({ cctp: { phase: 'arrived',
        refundBurn: { signature: 'pending', finalizedAt: null } } });
    await rejectsAsync(wallet.sweepSource(null), 'cctp_burn_pending');
});

test('a finalized burn remains attestable after the rent payer reclaims MessageSent', async t => {
    const env = harness();
    let reclaimedRead = false;
    t.mock.method(globalThis, 'fetch', async (input, init) => {
        if (new URL(input).origin === new URL(funding.rpc_url).origin) {
            const request = JSON.parse(init.body);
            if (request.method === 'getAccountInfo' && request.params[0] === env.state.pendingBurn?.event) {
                reclaimedRead = true;
                return new Response(JSON.stringify({ jsonrpc: '2.0', id: request.id,
                    result: { context: { slot: 10 }, value: null } }), { status: 200 });
            }
        }
        return env.fetch(input, init);
    });
    await burnThenCrash(env);
    env.setAta(1_000_000n);
    const result = await env.wallet(env.makeRuntime()).refund({ force: true });
    assert.ok(result.attestation);
    assert.ok(result.finalizedAt);
    assert.ok(reclaimedRead);
});

test('subsidy exhaustion does not block a later Circle-forwarded arrival', async t => {
    const env = harness();
    let refused = false;
    t.mock.method(globalThis, 'fetch', async (input, init) => {
        if (new URL(input).pathname === '/v2/relay/receives/prepare') {
            refused = true;
            env.setAta(9_700_000n);
            env.accounts.set(usedNonce(NONCE).toBase58(), rpcAccount(MESSAGE_TRANSMITTER_V2,
                Uint8Array.of(212, 222, 157, 252, 130, 71, 179, 238, 1)));
            return new Response(JSON.stringify({ error: { code: 'receive_budget_exhausted', message: 'daily budget exhausted' } }),
                { status: 429 });
        }
        return env.fetch(input, init);
    });
    await burnThenCrash(env);
    env.setAta(0n);
    await env.wallet(env.makeRuntime()).deposit();
    assert.ok(refused);
    assert.ok(env.store.runtime.state);
});

test('a refund burn journaled before submit is re-submitted with the same token after a crash and carries the inbound credential', async t => {
    const env = harness();
    t.mock.method(globalThis, 'fetch', env.fetch);
    const inbound = await attestedWithoutMint(env);
    // The relay signs and broadcasts, but the response never reaches the wallet.
    env.state.dropSubmitResponses = 1;
    await rejectsAsync(env.wallet(env.makeRuntime()).refund({ force: true }), 'relayer_unreachable');
    const journaled = env.store.runtime.pendingDeposit.cctp.refundBurn;
    assert.deepEqual({ signature: journaled.signature, token: journaled.submitToken, event: journaled.eventAccount,
        amount: journaled.amount, recipient: journaled.target.mintRecipient },
    { signature: null, token: 'submit-1', event: env.state.pendingBurn.event, amount: '49960000',
        recipient: hex(evmBytes32(BURNER)) }, 'the ek-signed burn is findable before the relay answers');
    assert.equal(env.state.sent.length, 0, 'the wallet broadcasts nothing before submit returns');
    await rejectsAsync(env.wallet(env.makeRuntime()).sweep({ to: usdcAssociatedTokenAddress(RELAYER) }), 'cctp_burn_pending');
    const result = await env.wallet(env.makeRuntime()).refund({ force: true });
    assert.ok(result.attestation);
    assert.equal(result.signature, base58Encode(Uint8Array.from(result.bytes.slice(1, 65))));
    assert.equal(env.state.relay.filter(entry => entry.path === '/v2/relay/burns/prepare').length, 1, 'resumed, not re-prepared');
    assert.equal(env.state.submits.length, 2);
    assert.deepEqual(env.state.submits[1], env.state.submits[0], 'the same token and ek-signed bytes');
    assert.deepEqual(env.state.relay.find(entry => entry.path === '/v2/relay/burns/prepare').body.inbound, inbound);
    assert.equal(assertBroadcastsCameFromSubmit(env), 1);
});

test('relay expiry is not trusted until finalized height passes the journaled lifetime', async t => {
    const env = harness();
    t.mock.method(globalThis, 'fetch', env.fetch);
    await burnThenCrash(env);
    env.setAta(0n);
    env.state.dropSubmitResponses = 1;
    await rejectsAsync(env.wallet(env.makeRuntime()).deposit(), 'relayer_unreachable');
    const journaled = env.store.runtime.pendingDeposit.cctp;
    assert.deepEqual({ phase: journaled.phase, signature: journaled.deposit.signature, token: journaled.deposit.submitToken },
        { phase: 'signed', signature: null, token: 'submit-1' });
    assert.equal(env.state.sent.length, 1, 'only the relayer-signed receive was broadcast');
    env.state.expiredTokens.add('submit-1');
    await rejectsAsync(env.wallet(env.makeRuntime()).deposit(), 'cctp_relay_pending');
    assert.equal(env.state.relay.filter(entry => entry.path === '/v2/relay/deposits/prepare').length, 1);
    env.state.blockHeight = 501;
    const confirmed = await env.wallet(env.makeRuntime()).deposit();
    assert.equal(confirmed.status, 'confirmed');
    assert.deepEqual(env.state.submits.map(entry => entry.token), ['submit-1', 'submit-1', 'submit-1', 'submit-2']);
    assert.deepEqual(env.state.submits[1], env.state.submits[0]);
    assert.equal(env.state.relay.filter(entry => entry.path === '/v2/relay/deposits/prepare').length, 2);
    assert.equal(assertBroadcastsCameFromSubmit(env), 1);
});

test('relay-supplied lifetime cannot shorten the trusted expiry bound', async t => {
    const env = harness();
    let forged = false;
    t.mock.method(globalThis, 'fetch', async (input, init) => {
        const response = await env.fetch(input, init);
        if (new URL(input).pathname === '/v2/relay/deposits/prepare') {
            const body = await response.json();
            body.transaction.last_valid_height = 0;
            forged = true;
            return new Response(JSON.stringify(body), { status: 200 });
        }
        return response;
    });
    await burnThenCrash(env);
    env.setAta(0n);
    env.state.dropSubmitResponses = 1;
    await rejectsAsync(env.wallet(env.makeRuntime()).deposit(), 'relayer_unreachable');
    const saved = env.store.runtime.pendingDeposit.cctp.deposit;
    assert.equal(forged, true);
    assert.equal(saved.lastValidHeight, 0);
    assert.equal(saved.expiryHeight, 500);
    env.state.expiredTokens.add('submit-1');
    await rejectsAsync(env.wallet(env.makeRuntime()).deposit({ selfFunded: true }), 'cctp_relay_pending');
    assert.equal(env.state.relay.filter(entry => entry.path === '/v2/relay/deposits/prepare').length, 1);
});

test('an unknown blockhash is rejected before signing and an old journal gains a durable RPC expiry bound', async t => {
    const env = harness();
    t.mock.method(globalThis, 'fetch', env.fetch);
    await burnThenCrash(env);
    env.setAta(0n);
    env.state.invalidBlockhash = true;
    await rejectsAsync(env.wallet(env.makeRuntime()).deposit(), 'cctp_relay_tx_rejected');
    assert.equal(env.state.submits.length, 0);
    env.state.invalidBlockhash = false;
    env.state.dropSubmitResponses = 1;
    await rejectsAsync(env.wallet(env.makeRuntime()).deposit(), 'relayer_unreachable');
    delete env.store.runtime.pendingDeposit.cctp.deposit.expiryHeight;
    env.state.dropSubmitResponses = 1;
    await rejectsAsync(env.wallet(env.makeRuntime()).deposit(), 'relayer_unreachable');
    assert.equal(env.store.runtime.pendingDeposit.cctp.deposit.expiryHeight, 500);
});

test('an ek-signed deposit the relay never submits falls back to the self-funded path once its blockhash expired', async t => {
    const env = harness();
    t.mock.method(globalThis, 'fetch', env.fetch);
    await burnThenCrash(env);
    env.setAta(0n);
    env.state.dropSubmitResponses = 1;
    await rejectsAsync(env.wallet(env.makeRuntime()).deposit(), 'relayer_unreachable');
    let relayAnswer = { status: 400, code: 'invalid_request' }; // the relay's simulation fails
    t.mock.method(globalThis, 'fetch', async (input, init) => (new URL(input).pathname.startsWith('/v2/relay')
        ? new Response(JSON.stringify({ error: { code: relayAnswer.code, message: 'no' } }), { status: relayAnswer.status })
        : env.fetch(input, init)));
    // Within its lifetime the ek-signed deposit may still land: the self-funded path stays blocked.
    await rejectsAsync(env.wallet(env.makeRuntime()).deposit({ selfFunded: true }), 'invalid_request');
    relayAnswer = { status: 503, code: 'relayer_unavailable' };
    await rejectsAsync(env.wallet(env.makeRuntime()).deposit({ selfFunded: true }), 'relayer_unavailable');
    assert.equal(env.store.runtime.pendingDeposit.cctp.phase, 'signed');
    // Past lastValidHeight it either landed (the note is checked) or never will.
    env.state.blockHeight = 501;
    relayAnswer = { status: 400, code: 'invalid_request' }; // e.g. ticket rejected after relay key rotation
    await rejectsAsync(env.wallet(env.makeRuntime()).deposit({ selfFunded: true }), 'cctp_ek_needs_sol');
    const plan = env.store.runtime.pendingDeposit.cctp;
    assert.deepEqual({ phase: plan.phase, deposit: plan.deposit }, { phase: 'arrived', deposit: null });
    assert.equal(env.state.relay.filter(entry => entry.path === '/v2/relay/deposits/prepare').length, 1, 'never re-prepared');
    assert.equal(env.state.sent.length, 1, 'only the relayer-signed receive was broadcast');
});

test('a tampered submit response is refused, nothing is broadcast, and the journaled transit sweep resumes', async t => {
    const env = harness();
    t.mock.method(globalThis, 'fetch', env.fetch);
    const inbound = await attestedWithoutMint(env);
    const destination = usdcAssociatedTokenAddress(RELAYER);
    env.accounts.set(destination, rpcAccount(TOKEN_PROGRAM_ID, tokenAccountData({ owner: RELAYER, amount: 0n })));
    const flip = (response, index) => {
        const bytes = [...response.transaction.bytes];
        bytes[index] ^= 1;
        return { signature: base58Encode(Uint8Array.from(bytes.slice(1, 65))), transaction: { ...response.transaction, bytes } };
    };
    for (const tamper of [
        response => flip(response, response.transaction.bytes.length - 1), // a different message
        response => flip(response, 65), // a changed ek signature
        response => flip(response, 1) // an invalid relayer signature
    ]) {
        env.state.tamper = tamper;
        await rejectsAsync(env.wallet(env.makeRuntime()).sweep({ to: destination }), 'cctp_relay_tx_rejected');
        assert.equal(env.state.sent.length, 0, 'nothing is broadcast');
        const pending = env.store.runtime.pendingDeposit.cctp.sweep;
        assert.deepEqual({ signature: pending.signature, token: pending.submitToken }, { signature: null, token: 'submit-1' });
    }
    // Submit refusals surface with their code and keep the journaled sweep.
    const fetch = env.fetch;
    t.mock.method(globalThis, 'fetch', async (input, init) => (new URL(input).pathname === '/v2/relay/submit'
        ? new Response(JSON.stringify({ error: { code: 'relay_backing_spent', message: 'credential spent' } }), { status: 429 })
        : fetch(input, init)));
    await rejectsAsync(env.wallet(env.makeRuntime()).sweep({ to: destination }), 'relay_backing_spent');
    t.mock.method(globalThis, 'fetch', fetch);
    env.state.tamper = null;
    const swept = await env.wallet(env.makeRuntime()).sweep({ to: destination });
    assert.equal(swept.amount, '49960000');
    assert.equal(env.state.relay.filter(entry => entry.path === '/v2/relay/sweeps/prepare').length, 1);
    assert.deepEqual([...new Set(env.state.submits.map(entry => entry.token))], ['submit-1']);
    assert.deepEqual(env.state.relay.find(entry => entry.path === '/v2/relay/sweeps/prepare').body.inbound, inbound);
    assert.equal(assertBroadcastsCameFromSubmit(env), 1);
    assert.equal(env.store.runtime.pendingDeposit, null);
});

/** Route every relay endpoint to a 503 (the relay is gone); returns the relay paths the wallet still tried. */
function relayGone(t, env) {
    const tried = [];
    t.mock.method(globalThis, 'fetch', async (input, init) => {
        const { pathname } = new URL(input);
        if (!pathname.startsWith('/v2/relay')) return env.fetch(input, init);
        tried.push(pathname);
        return new Response(JSON.stringify({ error: { code: 'relayer_unavailable', message: 'gone' } }), { status: 503 });
    });
    return tried;
}

test('a refund burn the relay broadcast unseen is found on chain after the relay is gone and its blockhash expired, never burned again', async t => {
    const env = harness();
    t.mock.method(globalThis, 'fetch', env.fetch);
    await attestedWithoutMint(env);
    // The relay signs and broadcasts the burn (event account created, ATA(ek) emptied); the response is lost.
    env.state.relayBroadcastsOnSubmit = true;
    env.state.dropSubmitResponses = 1;
    await rejectsAsync(env.wallet(env.makeRuntime()).refund({ force: true }), 'relayer_unreachable');
    const journaled = env.store.runtime.pendingDeposit.cctp.refundBurn;
    assert.deepEqual({ signature: journaled.signature, token: journaled.submitToken, event: journaled.eventAccount },
        { signature: null, token: 'submit-1', event: env.state.pendingBurn.event });
    assert.equal(env.state.relayBroadcasts.length, 1);
    const landed = base58Encode(env.state.relayBroadcasts[0].signatures[0]);
    assert.ok(env.accounts.get(journaled.eventAccount), 'the MessageSent event account exists');
    assert.equal(env.state.ataBalance, 0n);
    env.state.relayBroadcastsOnSubmit = false;
    const tried = relayGone(t, env);
    // Within its lifetime the burn's fate is unknown: nothing is re-prepared.
    await rejectsAsync(env.wallet(env.makeRuntime(), { irisUrl: 'https://iris.example' }).refund({ force: true }),
        'relayer_unavailable');
    assert.equal(env.store.runtime.pendingDeposit.cctp.refundBurn.signature, null);
    // Past lastValidHeight the event account's history shows the burn landed.
    env.state.blockHeight = 501;
    const result = await env.wallet(env.makeRuntime(), { irisUrl: 'https://iris.example' }).refund({ force: true });
    assert.equal(result.signature, landed);
    assert.equal(result.landedUnseen, true);
    assert.ok(result.finalizedAt);
    assert.equal(result.expired, undefined);
    assert.equal(result.attestation.message.length > 2, true);
    assert.ok(result.attestation.attestation);
    assert.deepEqual(tried, ['/v2/relay/submit', '/v2/relay/submit'], 'only the journaled token was re-submitted');
    assert.equal(env.state.relay.filter(entry => entry.path === '/v2/relay/burns/prepare').length, 1, 'never re-prepared');
    assert.equal(env.state.sent.length, 0, 'the wallet broadcast no burn');
    assert.equal(env.state.relayBroadcasts.length, 1, 'one burn on chain');
    assert.equal(env.store.runtime.pendingDeposit, null);
    const archived = env.store.runtime.cctpArchive.at(-1).cctp;
    assert.deepEqual({ phase: archived.phase, signature: archived.refundBurn.signature,
        landedUnseen: archived.refundBurn.landedUnseen }, { phase: 'refunded', signature: landed, landedUnseen: true });
});

test('a transit sweep the relay broadcast unseen completes as landed once the relay is gone and its blockhash expired', async t => {
    const env = harness();
    t.mock.method(globalThis, 'fetch', env.fetch);
    await attestedWithoutMint(env);
    const destination = usdcAssociatedTokenAddress(RELAYER);
    env.accounts.set(destination, rpcAccount(TOKEN_PROGRAM_ID, tokenAccountData({ owner: RELAYER, amount: 0n })));
    env.state.relayBroadcastsOnSubmit = true;
    env.state.dropSubmitResponses = 1;
    await rejectsAsync(env.wallet(env.makeRuntime()).sweep({ to: destination }), 'relayer_unreachable');
    assert.equal(env.store.runtime.pendingDeposit.cctp.sweep.signature, null);
    assert.equal(env.state.relayBroadcasts.length, 1);
    assert.equal(env.state.ataBalance, 0n, 'ATA(ek) was emptied by the relay-broadcast sweep');
    env.state.relayBroadcastsOnSubmit = false;
    const tried = relayGone(t, env);
    env.state.blockHeight = 501;
    const swept = await env.wallet(env.makeRuntime()).sweep({ to: destination });
    assert.deepEqual(swept, { signature: null, destination, amount: '49960000' });
    assert.deepEqual(tried, ['/v2/relay/submit']);
    assert.equal(env.state.relay.filter(entry => entry.path === '/v2/relay/sweeps/prepare').length, 1, 'never re-prepared');
    assert.equal(env.state.sent.length, 0, 'the wallet broadcast nothing');
    assert.equal(env.store.runtime.pendingDeposit, null);
    const archived = env.store.runtime.cctpArchive.at(-1).cctp;
    assert.deepEqual({ phase: archived.phase, landedUnseen: archived.sweep.landedUnseen }, { phase: 'swept', landedUnseen: true });
});
