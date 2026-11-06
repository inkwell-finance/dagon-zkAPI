// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title Events – All events emitted by ZkApiVault
abstract contract Events {
    event NoteDeposited(
        uint32 indexed noteId, bytes32 indexed commitment, uint128 amount, uint64 expiryTs, uint256 newRoot
    );

    event MutualClose(uint32 indexed noteId, uint256 nullifier, uint128 finalBalance, address destination);

    event EscapeWithdrawalInitiated(
        uint32 indexed noteId,
        uint256 nullifier,
        uint256 nextNullifier,
        uint128 finalBalance,
        uint128 conceded,
        address destination,
        uint64 challengeDeadline
    );

    event EscapeWithdrawalDefeated(uint32 indexed noteId, uint256 nullifier, uint256 nextNullifier);

    event EscapeConcessionRaised(uint32 indexed noteId, uint256 nullifier, uint128 conceded, uint128 finalBalance);

    event EscapeWithdrawalFinalized(
        uint32 indexed noteId, uint256 nullifier, uint128 finalBalance, address destination
    );

    /// @notice The destination refused or outspent ESCAPE_PAYOUT_GAS; `amount` was credited to
    ///         escapePayoutCredits(destination). EscapeWithdrawalFinalized follows in the same call.
    event EscapePayoutDeferred(uint32 indexed noteId, address indexed destination, uint128 amount);

    event EscapePayoutClaimed(address indexed destination, uint128 amount);

    event ExpiredClaimed(uint32 indexed noteId, uint128 depositAmount);

    event ClosedLeafRetired(uint32 indexed noteId, uint256 newRoot);

    event VaultPaused(uint64 pausedAt);

    event VaultUnpaused(uint64 unpausedAt);

    event ProofAdapterSet(address indexed newAdapter);

    event TreasurySet(address indexed newTreasury);

    event TreasuryWithdrawn(address indexed treasury, uint128 amount);
}