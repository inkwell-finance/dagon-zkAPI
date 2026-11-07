const integer = value => Number.isSafeInteger(value) && value >= 0;
const seconds = value => integer(value) && value > 0 && value * 1000 <= 8.64e15;

/**
 * Informational expiry deadlines of confirmed deposits. Expiry alone never
 * moves funds: a note past its expiry can still be swept by the vault's
 * permissionless treasury claim, so the history only states the deadline.
 * A note that was withdrawn, or whose escape started (escape records are
 * created only from finalized Solana state), has no deadline left to show.
 */
export function deriveExpiryRecords(deposits = [], withdrawals = [], nowMs = Date.now()) {
    return deposits.flatMap(deposit => {
        if (deposit.status !== 'confirmed' || !seconds(deposit.expiryTs)) return [];
        if (!Number.isFinite(nowMs) || deposit.expiryTs * 1000 > nowMs || withdrawals.some(record =>
            record.deploymentId === deposit.deploymentId && record.noteId === deposit.noteId
            && ((record.payoutVerified === true && record.phase === 'closed')
                || (record.mode === 'escape' && ['pending_withdrawal', 'payout_parked'].includes(record.chainStatus)
                    && integer(record.startBlockNumber) && record.startBlockNumber > 0)))) return [];
        return [{
            recordId: `${deposit.recordId}:expiry`, type: 'expiry',
            status: 'expired', deploymentId: deposit.deploymentId,
            noteId: deposit.noteId, expiryTs: deposit.expiryTs,
            createdAt: deposit.expiryTs * 1000,
            detail: 'No automatic refund. Expiry alone does not transfer funds.'
        }];
    });
}
