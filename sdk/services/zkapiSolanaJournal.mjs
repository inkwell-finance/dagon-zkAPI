import { canonicalChainId } from './zkapiLedgerIdentity.mjs';
import {
    base58Decode,
    base58Encode,
    validatePreparedSolanaOperation
} from './zkapiSolanaTransport.mjs';

export const SOLANA_JOURNAL_VERSION = 1;
const SIGNED_TRANSACTION_FORMAT = 'solana-legacy-transaction-v1';
const PHASES = Object.freeze(['prepared', 'signed', 'submitted', 'finalized']);
const PHASE_INDEX = new Map(PHASES.map((phase, index) => [phase, index]));
const FELT = /^0x[0-9a-f]{64}$/i;

function byteArray(value, label) {
    if (value instanceof Uint8Array) return [...value];
    if (Array.isArray(value)
        && value.every(byte => Number.isInteger(byte) && byte >= 0 && byte <= 255)) {
        return [...value];
    }
    throw new TypeError(`${label} must be a byte array.`);
}

function cloneOperation(operation) {
    return {
        transactions: operation.transactions.map(transaction => ({
            format: transaction.format,
            bytes: byteArray(transaction.bytes, 'prepared Solana message'),
            required_signers: transaction.required_signers.map((signer) => (
                byteArray(signer, 'prepared Solana signer')
            )),
            last_valid_height: transaction.last_valid_height
        }))
    };
}

function journalIdentity(value) {
    if (!value || value.version !== SOLANA_JOURNAL_VERSION
        || !['deposit', 'mutual', 'escape', 'finalize'].includes(value.kind)
        || typeof value.operationId !== 'string' || !value.operationId
        || typeof value.deploymentId !== 'string' || !value.deploymentId
        || value.backend !== 'dagon.solana.groth16.v1'
        || !FELT.test(value.protocolBinding || '')) {
        throw new Error('The durable Solana operation has an invalid identity.');
    }
    canonicalChainId(value.chainId, 'journal chain ID');
    base58Decode(value.programId, 32, 'journal program ID');
    base58Decode(value.vault, 32, 'journal vault state');
    base58Decode(value.payer, 32, 'journal payer');
    return value;
}

function equalBytes(left, right) {
    return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

function assertStage(stage, prepared, index) {
    if (!stage || stage.index !== index || !PHASE_INDEX.has(stage.phase)) {
        throw new Error('The durable Solana operation has an invalid stage.');
    }
    if (stage.phase === 'prepared') {
        if (stage.signature != null || stage.signedTransaction != null) {
            throw new Error('An unsigned Solana journal stage contains signed data.');
        }
        return;
    }
    if (stage.format !== SIGNED_TRANSACTION_FORMAT) {
        throw new Error('The durable Solana stage uses an unsupported transaction format.');
    }
    const transaction = byteArray(stage.signedTransaction, 'journaled signed transaction');
    const message = byteArray(prepared.bytes, 'prepared Solana message');
    if (transaction.length !== message.length + 65 || transaction[0] !== 1
        || !equalBytes(transaction.slice(65), message)) {
        throw new Error('The journaled wallet transaction does not match its prepared message.');
    }
    const signature = base58Decode(stage.signature, 64, 'journaled Solana signature');
    if (signature.every(byte => byte === 0)
        || !equalBytes(signature, transaction.slice(1, 65))) {
        throw new Error('The journaled Solana signature does not match its transaction.');
    }
    if (PHASE_INDEX.get(stage.phase) >= PHASE_INDEX.get('submitted')
        && !Number.isSafeInteger(stage.submittedAt)) {
        throw new Error('A submitted Solana journal stage has no durable timestamp.');
    }
    if (stage.phase === 'finalized') {
        canonicalChainId(stage.finalizedSlot, 'finalized Solana slot');
        if (!Number.isSafeInteger(stage.finalizedAt)) {
            throw new Error('A finalized Solana journal stage has no durable timestamp.');
        }
    }
}

export function assertSolanaOperationJournal(journal, expected = {}) {
    journalIdentity(journal);
    for (const [key, value] of Object.entries(expected)) {
        if (value == null) continue;
        const actual = key === 'chainId' ? canonicalChainId(journal[key]) : journal[key];
        const wanted = key === 'chainId' ? canonicalChainId(value) : value;
        if (String(actual).toLowerCase() !== String(wanted).toLowerCase()) {
            throw new Error(`The durable Solana operation has a different ${key}.`);
        }
    }
    if (!Array.isArray(journal.operation?.transactions) || !Array.isArray(journal.stages)
        || journal.operation.transactions.length === 0
        || journal.stages.length !== journal.operation.transactions.length) {
        throw new Error('The durable Solana operation has an invalid transaction plan.');
    }
    validatePreparedSolanaOperation({
        operation: journal.operation,
        payer: base58Decode(journal.payer, 32),
        programId: base58Decode(journal.programId, 32),
        vaultState: base58Decode(journal.vault, 32)
    });
    journal.stages.forEach((stage, index) => {
        if (index > 0 && stage.phase !== 'prepared'
            && journal.stages[index - 1].phase !== 'finalized') {
            throw new Error('The durable Solana stages are out of order.');
        }
        assertStage(stage, journal.operation.transactions[index], index);
    });
    return journal;
}

export function createSolanaOperationJournal({
    kind,
    operationId,
    deploymentId,
    backend,
    chainId,
    protocolBinding,
    programId,
    vault,
    payer,
    operation,
    now = Date.now()
}) {
    const payerBytes = base58Decode(payer, 32, 'journal payer');
    validatePreparedSolanaOperation({
        operation,
        payer: payerBytes,
        programId: base58Decode(programId, 32, 'journal program ID'),
        vaultState: base58Decode(vault, 32, 'journal vault state')
    });
    const journal = {
        version: SOLANA_JOURNAL_VERSION,
        kind,
        operationId,
        deploymentId,
        backend,
        chainId: canonicalChainId(chainId),
        protocolBinding: String(protocolBinding).toLowerCase(),
        programId,
        vault,
        payer,
        createdAt: now,
        operation: cloneOperation(operation),
        stages: operation.transactions.map((_, index) => ({ index, phase: 'prepared' }))
    };
    return assertSolanaOperationJournal(journal);
}

function updateStage(journal, index, update) {
    assertSolanaOperationJournal(journal);
    if (!Number.isSafeInteger(index) || index < 0 || index >= journal.stages.length) {
        throw new Error('The Solana journal stage index is invalid.');
    }
    if (index > 0 && journal.stages[index - 1].phase !== 'finalized') {
        throw new Error('A later Solana stage cannot advance before the previous stage finalizes.');
    }
    const stages = journal.stages.map(stage => ({ ...stage,
        ...(stage.signedTransaction ? { signedTransaction: [...stage.signedTransaction] } : {}) }));
    stages[index] = update(stages[index]);
    return assertSolanaOperationJournal({
        ...journal,
        operation: cloneOperation(journal.operation),
        stages
    });
}

export function recordSolanaSignedStage(journal, event, now = Date.now()) {
    return updateStage(journal, event?.index, (stage) => {
        const signedTransaction = byteArray(event?.signedTransaction, 'signed Solana transaction');
        const signature = String(event?.signature || '');
        if (stage.phase !== 'prepared') {
            if (stage.signature === signature && equalBytes(stage.signedTransaction, signedTransaction)) {
                return stage;
            }
            throw new Error('A different signed transaction is already journaled for this Solana stage.');
        }
        return {
            ...stage,
            phase: 'signed',
            format: event.format,
            signature,
            signedTransaction,
            signedAt: now
        };
    });
}

export function recordSolanaSubmittedStage(journal, event, now = Date.now()) {
    return updateStage(journal, event?.index, (stage) => {
        if (!['signed', 'submitted'].includes(stage.phase) || stage.signature !== event?.signature) {
            throw new Error('Only the journaled Solana transaction can be marked submitted.');
        }
        return stage.phase === 'submitted' ? stage : {
            ...stage,
            phase: 'submitted',
            submittedAt: now
        };
    });
}

export function recordSolanaFinalizedStage(journal, event, now = Date.now()) {
    return updateStage(journal, event?.index, (stage) => {
        if (!['submitted', 'finalized'].includes(stage.phase) || stage.signature !== event?.signature) {
            throw new Error('Only a submitted Solana transaction can be marked finalized.');
        }
        const finalizedSlot = canonicalChainId(
            event?.confirmation?.slot ?? event?.finalizedSlot,
            'finalized Solana slot'
        );
        if (stage.phase === 'finalized') {
            if (stage.finalizedSlot !== finalizedSlot) {
                throw new Error('The finalized Solana slot changed in durable recovery state.');
            }
            return stage;
        }
        return {
            ...stage,
            phase: 'finalized',
            finalizedSlot,
            finalizedAt: now
        };
    });
}

export function resumeSolanaOperationJournal(journal, expected = {}) {
    assertSolanaOperationJournal(journal, expected);
    const startIndex = journal.stages.findIndex(stage => stage.phase !== 'finalized');
    return Object.freeze({
        completed: startIndex === -1,
        startIndex: startIndex === -1 ? journal.stages.length : startIndex,
        operation: cloneOperation(journal.operation),
        signedTransactions: journal.stages.map(stage => (
            stage.signedTransaction ? Uint8Array.from(stage.signedTransaction) : null
        )),
        signatures: journal.stages.map(stage => stage.signature || null)
    });
}

export function solanaJournalSignatureForTransaction(transaction) {
    const bytes = byteArray(transaction, 'signed Solana transaction');
    if (bytes.length < 65 || bytes[0] !== 1) {
        throw new Error('The signed Solana transaction has an invalid signature section.');
    }
    return base58Encode(bytes.slice(1, 65));
}
