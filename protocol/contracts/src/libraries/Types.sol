// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title Types – Shared zkAPI v2 data structures
library Types {
    enum NoteStatus {
        Uninitialized,
        Active,
        PendingWithdrawal,
        Closed,
        /// @dev Value 4 is reserved (the deleted two-phase `Challenged` status); never assigned.
        ReservedChallenged
    }

    struct Note {
        bytes32 commitment;
        uint128 depositAmount;
        uint64 expiryTs;
        NoteStatus status;
        /// @notice Set by a defeat: an expiry sweep waits until at least this time (plus pause time).
        uint64 claimableAfter;
        /// @notice totalPausedDuration when the note was deposited.
        uint64 pausedOffset;
    }

    struct PendingWithdrawalData {
        bool exists;
        uint256 withdrawalNullifier;
        uint256 nextNullifier;
        uint128 stateBalance;
        uint128 conceded;
        uint128 finalBalance;
        address destination;
        uint64 challengeDeadline;
    }

    /// @dev Field order is the exact Groth16 public-input order.
    struct RequestPublicInputs {
        uint16 protocolVersion;
        uint64 chainId;
        address contractAddress;
        uint256 activeRoot;
        uint256 stateSigningKeyX;
        uint256 stateSigningKeyY;
        uint64 requestTime;
        uint128 solvencyBound;
        uint256 requestNullifier;
        uint256 authorizationTag;
        uint256 anonymousCommitmentX;
        uint256 anonymousCommitmentY;
    }

    /// @dev Field order is the exact Groth16 public-input order, except that the adapter packs
    /// (noteId, depositAmount, expiryTs) into the single input `noteId * 2^192 + depositAmount * 2^64 + expiryTs`.
    struct WithdrawalPublicInputs {
        uint16 protocolVersion;
        uint64 chainId;
        address contractAddress;
        uint256 registration;
        uint256 stateSigningKeyX;
        uint256 stateSigningKeyY;
        uint256 clearanceSigningKeyX;
        uint256 clearanceSigningKeyY;
        uint32 noteId;
        uint128 depositAmount;
        uint64 expiryTs;
        uint128 finalBalance;
        address destination;
        uint256 withdrawalNullifier;
        bool hasClearance;
        uint256 nextNullifier;
        uint128 conceded;
        uint64 validUntil;
    }
}
