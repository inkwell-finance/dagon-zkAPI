// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

import {Types} from "./libraries/Types.sol";
import {Errors} from "./libraries/Errors.sol";
import {Events} from "./libraries/Events.sol";
import {MerkleUpdateLib} from "./libraries/MerkleUpdateLib.sol";
import {NoteLeafLib} from "./libraries/NoteLeafLib.sol";
import {IZkApiProofAdapter} from "./interfaces/IZkApiProofAdapter.sol";

/// @title ZkApiVault
/// @notice Native ETH settlement in whole gwei with in-protocol BN254 Groth16 verification.
/// @dev Concession exit with leaf-bound, root-free exits. An escape from state S_k names its
///      nullifier N and the derived successor nullifier N+, concedes c, and pays B_k - c after the
///      challenge period. Only a request proof at N+ (the owner spent the successor) defeats it; a
///      request proof at N can only raise c, up to that request's solvency bound. Exits compare the
///      proof's registration and note fields with the stored note, so they take no Merkle path or
///      root and never remove the leaf; retireClosedLeaf removes a Closed note's leaf.
///      A pause blocks exits for at most MAX_PAUSE_DURATION, blocks claimExpired while it lasts and
///      extends every note's claimableAt by the paused time since its deposit.
contract ZkApiVault is ReentrancyGuard, Ownable, Events {
    uint16 public constant PROTOCOL_VERSION = 2;
    uint64 public constant DEFAULT_CHALLENGE_PERIOD = 24 hours;
    uint64 public constant EXPIRY_BUCKET = 1 days;
    uint256 public constant MERKLE_DEPTH = 32;
    /// @notice Longest time a pause blocks exits and expiry sweeps.
    uint64 public constant MAX_PAUSE_DURATION = 7 days;
    /// @notice Minimum time between the end of a pause and the next pause.
    uint64 public constant PAUSE_COOLDOWN = 1 days;
    /// @notice Gas forwarded to an escape destination by finalizeEscapeWithdrawal. A destination
    ///         that rejects or needs more is credited instead (claimEscapePayout forwards all gas).
    uint256 public constant ESCAPE_PAYOUT_GAS = 100_000;
    /// @dev gasleft() needed before the push so it always gets the full ESCAPE_PAYOUT_GAS:
    ///      ESCAPE_PAYOUT_GAS * 64 / 63 plus cold access, value transfer and new-account charges.
    uint256 private constant ESCAPE_PAYOUT_MIN_GAS = 140_000;

    uint8 private constant NULLIFIER_CONSUMED = 1;
    uint8 private constant NULLIFIER_CHALLENGED = 2;

    /// Native asset sentinel retained for deployment and client compatibility.
    address public constant billingToken = address(0);
    uint256 public constant nativeAssetWeiPerUnit = 1 gwei;
    uint128 public constant MAX_NATIVE_UNITS = 9_007_199_254_740_991;
    uint64 public immutable noteTtl;
    uint64 public immutable challengePeriod;
    uint128 public immutable requestChargeCap;
    IZkApiProofAdapter public immutable proofAdapter;
    uint256 public immutable stateSigningKeyX;
    uint256 public immutable stateSigningKeyY;
    uint256 public immutable clearanceSigningKeyX;
    uint256 public immutable clearanceSigningKeyY;

    address public treasury;
    bool public paused;
    /// @notice Start of the current pause; zero while unpaused.
    uint64 public pausedAt;
    uint256 public currentRoot;
    /// @notice Operator shares and swept deposits (gwei units) owed to the treasury; paid by withdrawTreasury.
    uint128 public treasuryAccrued;
    uint32 public nextNoteId;
    /// @notice Sum of the effective durations of all finished pauses.
    uint64 public totalPausedDuration;
    /// @notice End of the latest finished pause: its unpause time, capped at pausedAt + MAX_PAUSE_DURATION.
    uint64 public lastPauseEnd;

    mapping(uint32 => Types.Note) public notes;
    mapping(uint32 => Types.PendingWithdrawalData) public pendingWithdrawals;
    /// @dev 0 unused or released, 1 consumed, 2 challenged.
    mapping(uint256 => uint8) private _nullifierState;
    /// @notice Escape payouts (gwei units) whose push failed, per destination; see claimEscapePayout.
    mapping(address => uint128) public escapePayoutCredits;

    modifier whenNotPaused() {
        if (paused) revert Errors.Paused();
        _;
    }

    /// @dev Exits and expiry sweeps reopen at pausedAt + MAX_PAUSE_DURATION even if never unpaused.
    modifier whenNotEffectivelyPaused() {
        if (_effectivelyPaused()) revert Errors.Paused();
        _;
    }

    constructor(
        address treasury_,
        uint64 noteTtl_,
        uint64 challengePeriod_,
        uint128 requestChargeCap_,
        address proofAdapter_,
        uint256 stateSigningKeyX_,
        uint256 stateSigningKeyY_,
        uint256 clearanceSigningKeyX_,
        uint256 clearanceSigningKeyY_,
        address owner_
    ) Ownable(owner_) {
        if (treasury_ == address(0) || proofAdapter_ == address(0) || challengePeriod_ == 0) {
            revert Errors.Unauthorized();
        }
        _requireField(stateSigningKeyX_);
        _requireField(stateSigningKeyY_);
        _requireField(clearanceSigningKeyX_);
        _requireField(clearanceSigningKeyY_);
        if (
            (stateSigningKeyX_ == 0 && stateSigningKeyY_ == 0)
                || (clearanceSigningKeyX_ == 0 && clearanceSigningKeyY_ == 0)
        ) revert Errors.InvalidDeploymentBinding();

        if (requestChargeCap_ == 0 || requestChargeCap_ > MAX_NATIVE_UNITS) {
            revert Errors.InvalidBalance();
        }
        treasury = treasury_;
        noteTtl = noteTtl_;
        challengePeriod = challengePeriod_;
        requestChargeCap = requestChargeCap_;
        proofAdapter = IZkApiProofAdapter(proofAdapter_);
        stateSigningKeyX = stateSigningKeyX_;
        stateSigningKeyY = stateSigningKeyY_;
        clearanceSigningKeyX = clearanceSigningKeyX_;
        clearanceSigningKeyY = clearanceSigningKeyY_;
        currentRoot = _computeEmptyTreeRoot();
    }

    function deposit(bytes32 commitment, uint128 amount, uint256[32] calldata siblings)
        external
        payable
        nonReentrant
        whenNotPaused
    {
        if (amount > MAX_NATIVE_UNITS || msg.value != uint256(amount) * nativeAssetWeiPerUnit) {
            revert Errors.InvalidNativeValue();
        }
        if (amount == 0) revert Errors.ZeroAmount();
        if (commitment == bytes32(0)) revert Errors.InvalidCommitment();
        _requireField(uint256(commitment));

        uint32 noteId = nextNoteId;
        uint256 rawExpiry = block.timestamp + noteTtl;
        uint256 bucketedExpiry = ((rawExpiry + EXPIRY_BUCKET - 1) / EXPIRY_BUCKET) * EXPIRY_BUCKET;
        if (bucketedExpiry > type(uint64).max) revert Errors.InvalidFelt();
        uint64 expiryTs = uint64(bucketedExpiry);
        uint256 newLeaf = NoteLeafLib.computeLeaf(noteId, commitment, amount, expiryTs);
        uint256 newRoot = MerkleUpdateLib.verifyAndUpdate(currentRoot, noteId, 0, newLeaf, siblings);

        currentRoot = newRoot;
        Types.Note storage note = notes[noteId];
        note.commitment = commitment;
        note.depositAmount = amount;
        note.expiryTs = expiryTs;
        note.status = Types.NoteStatus.Active;
        uint64 offset = _pausedDurationNow();
        if (offset != 0) note.pausedOffset = offset;
        nextNoteId = noteId + 1;
        emit NoteDeposited(noteId, commitment, amount, expiryTs, newRoot);
    }

    /// @notice Closes an Active note with a clearance-backed withdrawal proof. Consumes N only; the
    ///         leaf stays in the tree until retireClosedLeaf.
    function mutualClose(Types.WithdrawalPublicInputs calldata inputs, bytes calldata proof)
        external
        nonReentrant
        whenNotEffectivelyPaused
    {
        _validateWithdrawalBinding(inputs);
        if (!inputs.hasClearance || inputs.nextNullifier != 0 || inputs.conceded != 0) {
            revert Errors.InvalidDeploymentBinding();
        }
        if (block.timestamp > inputs.validUntil) revert Errors.ExitProofExpired();
        Types.Note storage note = _exitableNote(inputs);
        uint256 nullifier = inputs.withdrawalNullifier;
        if (_nullifierState[nullifier] != 0) revert Errors.ReplayedNullifier();
        proofAdapter.assertValidWithdrawal(inputs, proof);

        _nullifierState[nullifier] = NULLIFIER_CONSUMED;
        uint128 operatorShare = note.depositAmount - inputs.finalBalance;
        note.status = Types.NoteStatus.Closed;
        _pay(inputs.destination, inputs.finalBalance, operatorShare);
        emit MutualClose(inputs.noteId, nullifier, inputs.finalBalance, inputs.destination);
    }

    /// @notice Starts an escape from the state at N, paying finalBalance = B - conceded after the
    ///         challenge period unless a request proof at nextNullifier defeats it. Consumes N and N+.
    function initiateEscapeWithdrawal(Types.WithdrawalPublicInputs calldata inputs, bytes calldata proof)
        external
        nonReentrant
        whenNotEffectivelyPaused
    {
        _validateWithdrawalBinding(inputs);
        if (inputs.hasClearance) revert Errors.InvalidDeploymentBinding();
        if (block.timestamp > inputs.validUntil) revert Errors.ExitProofExpired();
        Types.Note storage note = _exitableNote(inputs);
        uint256 nullifier = inputs.withdrawalNullifier;
        uint256 nextNullifier = inputs.nextNullifier;
        if (nextNullifier == 0 || nextNullifier == nullifier) revert Errors.NotSuccessorNullifier();
        if (_nullifierState[nullifier] != 0) revert Errors.ReplayedNullifier();
        uint8 nextState = _nullifierState[nextNullifier];
        // The successor of this state was spent (it defeated an escape), so this state is stale.
        if (nextState == NULLIFIER_CHALLENGED) revert Errors.SupersededState();
        if (nextState != 0) revert Errors.ReplayedNullifier();
        proofAdapter.assertValidWithdrawal(inputs, proof);

        _nullifierState[nullifier] = NULLIFIER_CONSUMED;
        _nullifierState[nextNullifier] = NULLIFIER_CONSUMED;
        uint64 deadline = uint64(block.timestamp) + challengePeriod;
        note.status = Types.NoteStatus.PendingWithdrawal;
        pendingWithdrawals[inputs.noteId] = Types.PendingWithdrawalData({
            exists: true,
            withdrawalNullifier: nullifier,
            nextNullifier: nextNullifier,
            stateBalance: inputs.finalBalance + inputs.conceded,
            conceded: inputs.conceded,
            finalBalance: inputs.finalBalance,
            destination: inputs.destination,
            challengeDeadline: deadline
        });
        emit EscapeWithdrawalInitiated(
            inputs.noteId, nullifier, nextNullifier, inputs.finalBalance, inputs.conceded, inputs.destination, deadline
        );
    }

    /// @notice Defeats a pending escape with a request proof at its successor nullifier N+, which only
    ///         the owner can produce after spending the successor state. Root-independent.
    /// @dev N becomes challenged (stale forever), N+ is released, the note returns to Active and an
    ///      expiry sweep waits at least challengePeriod.
    function challengeEscapeWithdrawal(uint32 noteId, Types.RequestPublicInputs calldata inputs, bytes calldata proof)
        external
        nonReentrant
    {
        (Types.Note storage note, Types.PendingWithdrawalData storage pending) = _challengeablePending(noteId);
        _validateRequestBinding(inputs);
        uint256 nextNullifier = pending.nextNullifier;
        if (inputs.requestNullifier != nextNullifier) revert Errors.NotSuccessorNullifier();
        proofAdapter.assertValidRequest(inputs, proof);

        uint256 nullifier = pending.withdrawalNullifier;
        _nullifierState[nullifier] = NULLIFIER_CHALLENGED;
        delete _nullifierState[nextNullifier];
        uint256 graceEnd = block.timestamp + challengePeriod;
        uint64 expiryTs = note.expiryTs;
        note.claimableAfter = graceEnd > expiryTs ? uint64(graceEnd) : expiryTs;
        note.status = Types.NoteStatus.Active;
        delete pendingWithdrawals[noteId];
        emit EscapeWithdrawalDefeated(noteId, nullifier, nextNullifier);
    }

    /// @notice Raises a pending escape's concession with a request proof at the escaped nullifier N,
    ///         to min(amount, solvencyBound, stateBalance). Permissionless; deadline unchanged.
    function raiseEscapeConcession(
        uint32 noteId,
        Types.RequestPublicInputs calldata inputs,
        bytes calldata proof,
        uint128 amount
    ) external nonReentrant {
        (, Types.PendingWithdrawalData storage pending) = _challengeablePending(noteId);
        _validateRequestBinding(inputs);
        uint256 nullifier = pending.withdrawalNullifier;
        if (inputs.requestNullifier != nullifier) revert Errors.NullifierMismatch();
        uint128 stateBalance = pending.stateBalance;
        uint128 raised = amount < inputs.solvencyBound ? amount : inputs.solvencyBound;
        if (raised > stateBalance) raised = stateBalance;
        if (raised <= pending.conceded) revert Errors.ConcessionNotRaised();
        proofAdapter.assertValidRequest(inputs, proof);

        uint128 finalBalance = stateBalance - raised;
        pending.conceded = raised;
        pending.finalBalance = finalBalance;
        emit EscapeConcessionRaised(noteId, nullifier, raised, finalBalance);
    }

    /// @notice Pays an undefeated escape after its deadline and closes the note. Permissionless and
    ///         open while paused. The rest of the deposit accrues to the treasury, and
    ///         finalBalance is pushed to the destination with ESCAPE_PAYOUT_GAS or, if that push
    ///         fails, credited to escapePayoutCredits[destination], so a destination that refuses
    ///         ETH can neither keep the note pending nor lock the operator share.
    function finalizeEscapeWithdrawal(uint32 noteId) external nonReentrant {
        Types.Note storage note = notes[noteId];
        Types.PendingWithdrawalData storage pending = pendingWithdrawals[noteId];
        if (note.status != Types.NoteStatus.PendingWithdrawal || !pending.exists) {
            revert Errors.NotPendingWithdrawal();
        }
        if (block.timestamp <= pending.challengeDeadline) revert Errors.ChallengeNotExpired();

        uint256 nullifier = pending.withdrawalNullifier;
        uint128 finalBalance = pending.finalBalance;
        address destination = pending.destination;
        uint128 operatorShare = note.depositAmount - finalBalance;
        note.status = Types.NoteStatus.Closed;
        delete pendingWithdrawals[noteId];
        if (operatorShare != 0) treasuryAccrued += operatorShare;
        if (finalBalance != 0 && !_pushEscapePayout(destination, finalBalance)) {
            escapePayoutCredits[destination] += finalBalance;
            emit EscapePayoutDeferred(noteId, destination, finalBalance);
        }
        emit EscapeWithdrawalFinalized(noteId, nullifier, finalBalance, destination);
    }

    /// @notice Pays `destination` all of its credited escape payouts, forwarding all gas. Anyone may
    ///         call it, but only `destination` is paid; if the transfer fails the credit is kept.
    ///         Open while paused.
    function claimEscapePayout(address destination) external nonReentrant {
        uint128 amount = escapePayoutCredits[destination];
        if (amount == 0) revert Errors.ZeroAmount();
        delete escapePayoutCredits[destination];
        _transfer(destination, amount);
        emit EscapePayoutClaimed(destination, amount);
    }

    /// @notice Sweeps an Active note to the treasury from its claimableAt on. The leaf stays.
    function claimExpired(uint32 noteId) external nonReentrant whenNotEffectivelyPaused {
        Types.Note storage note = notes[noteId];
        if (note.status != Types.NoteStatus.Active) revert Errors.NoteNotActive();
        if (block.timestamp < _claimableAt(note)) revert Errors.NoteNotExpired();
        uint128 amount = note.depositAmount;
        note.status = Types.NoteStatus.Closed;
        treasuryAccrued += amount;
        emit ExpiredClaimed(noteId, amount);
    }

    /// @notice Pays everything accrued to the current treasury. Permissionless and open while paused.
    /// @dev Payouts to users never depend on the treasury accepting ETH: a treasury that reverts
    ///      only blocks this call until the owner sets a working one.
    function withdrawTreasury() external nonReentrant {
        uint128 amount = treasuryAccrued;
        if (amount == 0) revert Errors.ZeroAmount();
        treasuryAccrued = 0;
        address recipient = treasury;
        _transfer(recipient, amount);
        emit TreasuryWithdrawn(recipient, amount);
    }

    /// @notice Removes a Closed note's leaf from the request tree at the current root, so no request
    ///         can be proven from it any more. Permissionless and open while paused.
    function retireClosedLeaf(uint32 noteId, uint256[32] calldata siblings) external {
        Types.Note storage note = notes[noteId];
        if (note.status != Types.NoteStatus.Closed) revert Errors.NoteNotClosed();
        // A second retirement fails StaleRoot: the slot already holds zero.
        uint256 newRoot = MerkleUpdateLib.verifyAndUpdate(currentRoot, noteId, _leaf(noteId, note), 0, siblings);
        currentRoot = newRoot;
        emit ClosedLeafRetired(noteId, newRoot);
    }

    function setTreasury(address newTreasury) external onlyOwner {
        if (newTreasury == address(0)) revert Errors.Unauthorized();
        treasury = newTreasury;
        emit TreasurySet(newTreasury);
    }

    /// @notice Blocks deposits until unpause, and exits and expiry sweeps for at most
    ///         MAX_PAUSE_DURATION. Challenge, raise, finalize, claimEscapePayout, retireClosedLeaf
    ///         and withdrawTreasury stay open.
    function pause() external onlyOwner {
        if (paused) revert Errors.Paused();
        uint64 end = lastPauseEnd;
        if (end != 0 && block.timestamp < uint256(end) + PAUSE_COOLDOWN) revert Errors.PauseCooldown();
        paused = true;
        pausedAt = uint64(block.timestamp);
        emit VaultPaused(uint64(block.timestamp));
    }

    function unpause() external onlyOwner {
        if (!paused) revert Errors.NotPaused();
        uint64 start = pausedAt;
        uint64 end = _effectivePauseEnd(start);
        totalPausedDuration += end - start;
        lastPauseEnd = end;
        paused = false;
        pausedAt = 0;
        emit VaultUnpaused(uint64(block.timestamp));
    }

    /// @notice 0 unused or released, 1 consumed, 2 challenged.
    function nullifierState(uint256 nullifier) external view returns (uint8) {
        return _nullifierState[nullifier];
    }

    /// @notice True for a consumed or challenged nullifier.
    function usedNullifiers(uint256 nullifier) external view returns (bool) {
        return _nullifierState[nullifier] != 0;
    }

    /// @notice max(expiryTs, claimableAfter) plus the effective pause time since the note's deposit,
    ///         including a running pause. Exits succeed before it, claimExpired from it on.
    function claimableAt(uint32 noteId) external view returns (uint64) {
        return _claimableAt(notes[noteId]);
    }

    /// @dev The note checks shared by escape and close: Active, the proof's registration and note
    ///      fields equal the stored note, finalBalance + conceded <= deposit, and before claimableAt.
    function _exitableNote(Types.WithdrawalPublicInputs calldata inputs)
        private
        view
        returns (Types.Note storage note)
    {
        note = notes[inputs.noteId];
        if (note.status != Types.NoteStatus.Active) revert Errors.NoteNotActive();
        if (
            inputs.registration != uint256(note.commitment) || inputs.depositAmount != note.depositAmount
                || inputs.expiryTs != note.expiryTs
        ) revert Errors.NoteMismatch();
        if (uint256(inputs.finalBalance) + inputs.conceded > note.depositAmount) revert Errors.InvalidBalance();
        if (block.timestamp >= _claimableAt(note)) revert Errors.NoteExpired();
    }

    function _challengeablePending(uint32 noteId)
        private
        view
        returns (Types.Note storage note, Types.PendingWithdrawalData storage pending)
    {
        note = notes[noteId];
        pending = pendingWithdrawals[noteId];
        if (note.status != Types.NoteStatus.PendingWithdrawal || !pending.exists) {
            revert Errors.NotPendingWithdrawal();
        }
        if (block.timestamp > pending.challengeDeadline) revert Errors.ChallengeExpired();
    }

    function _claimableAt(Types.Note storage note) private view returns (uint64) {
        uint64 base = note.expiryTs;
        uint64 after_ = note.claimableAfter;
        if (after_ > base) base = after_;
        return base + (_pausedDurationNow() - note.pausedOffset);
    }

    function _effectivelyPaused() private view returns (bool) {
        return paused && block.timestamp < uint256(pausedAt) + MAX_PAUSE_DURATION;
    }

    /// @dev min(now, start + MAX_PAUSE_DURATION).
    function _effectivePauseEnd(uint64 start) private view returns (uint64) {
        uint256 cap = uint256(start) + MAX_PAUSE_DURATION;
        return uint64(block.timestamp < cap ? block.timestamp : cap);
    }

    /// @dev Effective paused time so far, including a running pause.
    function _pausedDurationNow() private view returns (uint64) {
        uint64 total = totalPausedDuration;
        if (!paused) return total;
        uint64 start = pausedAt;
        return total + (_effectivePauseEnd(start) - start);
    }

    /// @dev Pays the user's balance and accrues the operator share for withdrawTreasury.
    function _pay(address destination, uint128 balance, uint128 operatorShare) private {
        if (operatorShare != 0) treasuryAccrued += operatorShare;
        if (balance != 0) _transfer(destination, balance);
    }

    function _transfer(address destination, uint128 amount) private {
        (bool success,) = payable(destination).call{value: uint256(amount) * nativeAssetWeiPerUnit}("");
        if (!success) revert Errors.NativeTransferFailed();
    }

    /// @dev Pushes an escape payout with exactly ESCAPE_PAYOUT_GAS and no returndata copy. Reverts
    ///      unless that full stipend can be forwarded, so a caller cannot starve a destination that
    ///      accepts within it into a credit.
    function _pushEscapePayout(address destination, uint128 amount) private returns (bool success) {
        if (gasleft() < ESCAPE_PAYOUT_MIN_GAS) revert Errors.InsufficientPayoutGas();
        uint256 value = uint256(amount) * nativeAssetWeiPerUnit;
        uint256 gasLimit = ESCAPE_PAYOUT_GAS;
        assembly ("memory-safe") {
            success := call(gasLimit, destination, value, 0, 0, 0, 0)
        }
    }

    function _validateRequestBinding(Types.RequestPublicInputs calldata inputs) private view {
        if (
            inputs.protocolVersion != PROTOCOL_VERSION || inputs.chainId != block.chainid
                || inputs.contractAddress != address(this) || inputs.stateSigningKeyX != stateSigningKeyX
                || inputs.stateSigningKeyY != stateSigningKeyY
        ) revert Errors.InvalidDeploymentBinding();
    }

    function _validateWithdrawalBinding(Types.WithdrawalPublicInputs calldata inputs) private view {
        if (
            inputs.protocolVersion != PROTOCOL_VERSION || inputs.chainId != block.chainid
                || inputs.contractAddress != address(this) || inputs.stateSigningKeyX != stateSigningKeyX
                || inputs.stateSigningKeyY != stateSigningKeyY || inputs.clearanceSigningKeyX != clearanceSigningKeyX
                || inputs.clearanceSigningKeyY != clearanceSigningKeyY
        ) revert Errors.InvalidDeploymentBinding();
    }

    function _leaf(uint32 noteId, Types.Note storage note) private view returns (uint256) {
        return NoteLeafLib.computeLeaf(noteId, note.commitment, note.depositAmount, note.expiryTs);
    }

    function _computeEmptyTreeRoot() private pure returns (uint256 root) {
        for (uint256 level = 0; level < MERKLE_DEPTH;) {
            root = MerkleUpdateLib.poseidonNodeHash(root, root);
            unchecked {
                ++level;
            }
        }
    }

    function _requireField(uint256 value) private pure {
        if (value >= MerkleUpdateLib.FIELD_MODULUS) revert Errors.InvalidFelt();
    }
}
