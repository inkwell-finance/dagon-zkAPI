// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title Errors – Custom revert reasons for zkAPI
library Errors {
    error InvalidNativeValue();
    error NativeTransferFailed();
    /// @notice finalizeEscapeWithdrawal was called with too little gas to forward ESCAPE_PAYOUT_GAS.
    error InsufficientPayoutGas();
    /// @notice The supplied proof did not verify.
    error InvalidProof();

    /// @notice The Merkle path does not reproduce the current root (deposit or leaf retirement).
    error StaleRoot();

    /// @notice The nullifier has already been consumed or challenged.
    error ReplayedNullifier();

    /// @notice The escape's successor nullifier was spent by a defeat, so the escaped state is stale.
    error SupersededState();

    /// @notice The note is not in Active status.
    error NoteNotActive();

    /// @notice The note is in PendingWithdrawal status (unexpected).
    error NotePendingWithdrawal();

    /// @notice The note is past its claimable time, so exits are closed.
    error NoteExpired();

    /// @notice The note has not yet reached its claimable time.
    error NoteNotExpired();

    /// @notice The note is not in Closed status.
    error NoteNotClosed();

    /// @notice The withdrawal's registration or note fields do not match the stored note.
    error NoteMismatch();

    /// @notice The withdrawal proof is past its validUntil.
    error ExitProofExpired();

    /// @notice The deposit amount is zero or otherwise insufficient.
    error InsufficientDeposit();

    /// @notice The commitment is zero or otherwise invalid.
    error InvalidCommitment();

    /// @notice finalBalance + conceded exceeds the deposit amount.
    error InvalidBalance();

    /// @notice The challenge period has already elapsed.
    error ChallengeExpired();

    /// @notice The challenge period has not yet elapsed.
    error ChallengeNotExpired();

    /// @notice Expected PendingWithdrawal status but note is not pending.
    error NotPendingWithdrawal();

    /// @notice A defeat's request nullifier is not the pending successor nullifier, or an escape's
    ///         successor nullifier is zero or equal to its nullifier.
    error NotSuccessorNullifier();

    /// @notice A raise's request nullifier is not the escaped nullifier.
    error NullifierMismatch();

    /// @notice A raise would not increase the concession.
    error ConcessionNotRaised();

    /// @notice A proof is for another protocol, chain, contract, or signing key.
    error InvalidDeploymentBinding();

    /// @notice The sibling array length or values are invalid.
    error InvalidSiblings();

    /// @notice A zero amount was provided where a nonzero value is required.
    error ZeroAmount();

    /// @notice The contract is paused.
    error Paused();

    /// @notice The contract is not paused.
    error NotPaused();

    /// @notice A new pause needs PAUSE_COOLDOWN after the previous pause ended.
    error PauseCooldown();

    /// @notice The caller is not authorized for this operation.
    error Unauthorized();

    /// @notice A field value is outside the BN254 scalar field.
    error InvalidFelt();
}
