// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ZkApiVault} from "../src/ZkApiVault.sol";
import {IZkApiProofAdapter} from "../src/interfaces/IZkApiProofAdapter.sol";
import {Types} from "../src/libraries/Types.sol";
import {Errors} from "../src/libraries/Errors.sol";
import {Events} from "../src/libraries/Events.sol";
import {Bn254Poseidon} from "../src/libraries/Bn254Poseidon.sol";
import {NoteLeafLib} from "../src/libraries/NoteLeafLib.sol";

/// @dev Isolates vault checks; the real adapter has separate Groth16 fixture tests. Request
///      proofs are accepted only when registered; withdrawal proofs unless the proof is "bad".
contract MockProofAdapter is IZkApiProofAdapter {
    mapping(bytes32 => bool) private acceptedRequests;

    function acceptRequest(Types.RequestPublicInputs calldata inputs, bytes calldata proof) external {
        acceptedRequests[keccak256(abi.encode(inputs, proof))] = true;
    }

    function assertValidRequest(Types.RequestPublicInputs calldata inputs, bytes calldata proof) external view {
        if (!acceptedRequests[keccak256(abi.encode(inputs, proof))]) revert Errors.InvalidProof();
    }

    function assertValidWithdrawal(Types.WithdrawalPublicInputs calldata, bytes calldata proof) external pure {
        if (keccak256(proof) == keccak256("bad")) revert Errors.InvalidProof();
    }
}

contract RejectingTreasury {
    receive() external payable {
        revert();
    }
}

/// @dev Mock-adapter logic tests for the concession exit (Design C), leaf-bound root-free exits
///      and the bounded pause. Nullifiers N0..N3 name the chain S0 -> S1 -> S2 -> S3 of note 0.
contract ZkApiVaultTest is Test {
    uint256 constant DOMAIN_NODE = 0x7a6b6170692e76322e6e6f6465;
    uint128 constant DEPOSIT = 1_000_000;
    uint128 constant B1 = 900_000;
    uint128 constant B2 = 850_000;
    uint128 constant SB = 100_000;
    uint256 constant N0 = 1001;
    uint256 constant N1 = 1002;
    uint256 constant N2 = 1003;
    uint256 constant N3 = 1004;
    uint256 constant STATE_X = 11;
    uint256 constant STATE_Y = 12;
    uint256 constant CLEAR_X = 13;
    uint256 constant CLEAR_Y = 14;
    uint64 constant CHALLENGE = 24 hours;
    uint64 constant T0 = 1_700_000_000;
    bytes constant EVIDENCE = hex"cafe";

    MockProofAdapter adapter;
    ZkApiVault vault;
    address user = address(0x1234);
    address treasury = address(0x5678);
    address operator = address(0x0bad);
    address stranger = address(0xd00d);
    uint256[33] zeroHashes;
    mapping(uint32 => uint256) leafAt;
    uint32 leafCount;

    function setUp() public {
        vm.warp(T0);
        for (uint256 level = 1; level <= 32; ++level) {
            zeroHashes[level] = _node(zeroHashes[level - 1], zeroHashes[level - 1]);
        }
        adapter = new MockProofAdapter();
        vault = new ZkApiVault(
            treasury, 30 days, CHALLENGE, 100_000, address(adapter), STATE_X, STATE_Y, CLEAR_X, CLEAR_Y, address(this)
        );
        _deposit(user, 42);
    }

    // ---------------------------------------------------------------- close

    function test_mutualClosePaysAndKeepsLeaf() public {
        uint256 root = vault.currentRoot();
        assertEq(root, _root());
        vm.expectEmit(true, false, false, true, address(vault));
        emit Events.MutualClose(0, N1, B1, user);
        vault.mutualClose(_close(0, N1, B1), "");
        assertEq(user.balance, uint256(B1) * 1 gwei);
        assertEq(_treasuryPaid(), uint256(DEPOSIT - B1) * 1 gwei);
        assertEq(vault.nullifierState(N1), 1);
        assertTrue(vault.usedNullifiers(N1));
        _assertStatus(0, Types.NoteStatus.Closed);
        // Exits never touch the tree.
        assertEq(vault.currentRoot(), root);
    }

    function test_closeRevertMatrix() public {
        Types.WithdrawalPublicInputs memory inputs = _close(0, N1, B1);
        inputs.hasClearance = false;
        vm.expectRevert(Errors.InvalidDeploymentBinding.selector);
        vault.mutualClose(inputs, "");

        inputs = _close(0, N1, B1);
        inputs.nextNullifier = N2;
        vm.expectRevert(Errors.InvalidDeploymentBinding.selector);
        vault.mutualClose(inputs, "");

        inputs = _close(0, N1, B1);
        inputs.conceded = 1;
        vm.expectRevert(Errors.InvalidDeploymentBinding.selector);
        vault.mutualClose(inputs, "");

        inputs = _close(0, N1, B1);
        inputs.validUntil = uint64(block.timestamp) - 1;
        vm.expectRevert(Errors.ExitProofExpired.selector);
        vault.mutualClose(inputs, "");

        inputs = _close(0, N1, DEPOSIT + 1);
        vm.expectRevert(Errors.InvalidBalance.selector);
        vault.mutualClose(inputs, "");

        inputs = _close(0, N1, B1);
        inputs.registration += 1;
        vm.expectRevert(Errors.NoteMismatch.selector);
        vault.mutualClose(inputs, "");

        _expectExitRevert(_close(0, N1, B1), "bad", Errors.InvalidProof.selector);

        _assertStatus(0, Types.NoteStatus.Active);
        assertEq(vault.nullifierState(N1), 0);
    }

    // ------------------------------------------------- withheld successor (G1)

    /// Threat: operator withholds S2 after the user released req1 (bound SB) at S1.
    function test_honestWithheldExitPaysBalanceMinusBound() public {
        Types.RequestPublicInputs memory req0 = _req(N0, SB);
        Types.RequestPublicInputs memory req1 = _req(N1, SB);
        _escape(0, N1, N2, B1 - SB, SB);

        // The operator holds every request the user made, but none at N2.
        vm.startPrank(operator);
        vm.expectRevert(Errors.NotSuccessorNullifier.selector);
        vault.challengeEscapeWithdrawal(0, req1, EVIDENCE);
        vm.expectRevert(Errors.NotSuccessorNullifier.selector);
        vault.challengeEscapeWithdrawal(0, req0, EVIDENCE);
        // A raise is capped by the bound the user already conceded.
        vm.expectRevert(Errors.ConcessionNotRaised.selector);
        vault.raiseEscapeConcession(0, req1, EVIDENCE, type(uint128).max);
        vm.expectRevert(Errors.NullifierMismatch.selector);
        vault.raiseEscapeConcession(0, req0, EVIDENCE, type(uint128).max);
        vm.stopPrank();

        _finalizeAfterDeadline(0);
        assertEq(user.balance, uint256(B1 - SB) * 1 gwei);
        assertEq(_treasuryPaid(), uint256(DEPOSIT - B1 + SB) * 1 gwei);
        _assertStatus(0, Types.NoteStatus.Closed);
        assertEq(vault.nullifierState(N1), 1);
        assertEq(vault.nullifierState(N2), 1);
    }

    /// Threat: operator withholds S1 for a user who never released a request at S1 (b = 0).
    function test_honestFreshStateExitPaysFullBalance() public {
        Types.RequestPublicInputs memory req0 = _req(N0, SB);
        _escape(0, N1, N2, B1, 0);
        vm.startPrank(operator);
        vm.expectRevert(Errors.NotSuccessorNullifier.selector);
        vault.challengeEscapeWithdrawal(0, req0, EVIDENCE);
        vm.expectRevert(Errors.NullifierMismatch.selector);
        vault.raiseEscapeConcession(0, req0, EVIDENCE, SB);
        vm.stopPrank();
        _finalizeAfterDeadline(0);
        assertEq(user.balance, uint256(B1) * 1 gwei);
        assertEq(_treasuryPaid(), uint256(DEPOSIT - B1) * 1 gwei);
    }

    // ------------------------------------------------------- stale escape (G2)

    /// Threat: a user who spent S1 (req1 at N1) escapes from S0.
    function test_staleEscapeDefeated() public {
        Types.RequestPublicInputs memory req1 = _req(N1, SB);
        _escape(0, N0, N1, DEPOSIT, 0);
        uint64 expiryTs = _expiry(0);
        uint64 deadline = _deadline(0);
        vm.warp(deadline - 10);

        vm.expectEmit(true, false, false, true, address(vault));
        emit Events.EscapeWithdrawalDefeated(0, N0, N1);
        vm.prank(operator);
        vault.challengeEscapeWithdrawal(0, req1, EVIDENCE);

        assertEq(vault.nullifierState(N0), 2);
        assertTrue(vault.usedNullifiers(N0));
        assertEq(vault.nullifierState(N1), 0);
        assertFalse(vault.usedNullifiers(N1));
        _assertStatus(0, Types.NoteStatus.Active);
        (,,,, uint64 claimableAfter,) = vault.notes(0);
        assertEq(claimableAfter, expiryTs);
        assertEq(vault.claimableAt(0), expiryTs);
        (bool exists,,,,,,,) = vault.pendingWithdrawals(0);
        assertFalse(exists);
        assertEq(user.balance, 0);
        assertEq(address(vault).balance, uint256(DEPOSIT) * 1 gwei);

        vm.warp(deadline + 1);
        vm.expectRevert(Errors.NotPendingWithdrawal.selector);
        vault.finalizeEscapeWithdrawal(0);
        vm.expectRevert(Errors.NotPendingWithdrawal.selector);
        vault.challengeEscapeWithdrawal(0, req1, EVIDENCE);

        // Re-escape from S0 is a replay of a challenged nullifier.
        _expectEscapeRevert(_escapeInputs(0, N0, N1, DEPOSIT, 0), Errors.ReplayedNullifier.selector);
    }

    /// Threat: a cheater keeps escaping from older states; each round converges.
    function test_staleEscapeRoundsConverge() public {
        Types.RequestPublicInputs memory req1 = _req(N1, SB);
        Types.RequestPublicInputs memory req2 = _req(N2, SB);
        _escape(0, N0, N1, DEPOSIT, 0);
        vault.challengeEscapeWithdrawal(0, req1, EVIDENCE);
        // Escape from S1: N1 was released, so this lands; S2 was spent, so it is defeated too.
        _escape(0, N1, N2, B1, 0);
        vault.challengeEscapeWithdrawal(0, req2, EVIDENCE);
        assertEq(vault.nullifierState(N1), 2);
        assertEq(vault.nullifierState(N2), 0);

        // S0's successor N1 is challenged: S0 is superseded. A fake older state naming N0 likewise.
        Types.WithdrawalPublicInputs memory stale = _escapeInputs(0, 999, N1, DEPOSIT, 0);
        vm.expectRevert(Errors.SupersededState.selector);
        vault.initiateEscapeWithdrawal(stale, "");
        _expectEscapeRevert(_escapeInputs(0, N0, N1, DEPOSIT, 0), Errors.ReplayedNullifier.selector);
        _expectEscapeRevert(_escapeInputs(0, N1, N2, B1, 0), Errors.ReplayedNullifier.selector);

        // The newest state S2 escapes and is judged on its own evidence.
        _escape(0, N2, N3, B2, 0);
        _finalizeAfterDeadline(0);
        assertEq(user.balance, uint256(B2) * 1 gwei);
        assertEq(_treasuryPaid(), uint256(DEPOSIT - B2) * 1 gwei);
    }

    /// A defeat near expiry leaves challengePeriod for the honest successor to exit.
    function test_defeatNearExpiryGrantsGrace() public {
        uint64 expiryTs = _expiry(0);
        Types.RequestPublicInputs memory req1 = _req(N1, SB);
        vm.warp(expiryTs - 1 hours);
        _escape(0, N0, N1, DEPOSIT, 0);
        vm.warp(expiryTs + 20 hours);
        vault.challengeEscapeWithdrawal(0, req1, EVIDENCE);
        uint64 grace = uint64(block.timestamp) + CHALLENGE;
        assertEq(vault.claimableAt(0), grace);

        vm.warp(grace - 1);
        vm.expectRevert(Errors.NoteNotExpired.selector);
        vault.claimExpired(0);
        // The successor can still exit within the grace.
        _escape(0, N1, N2, B1, 0);
        _finalizeAfterDeadline(0);
        assertEq(user.balance, uint256(B1) * 1 gwei);
    }

    function test_sweepAfterDefeatGraceWhenUserIsAbsent() public {
        uint64 expiryTs = _expiry(0);
        Types.RequestPublicInputs memory req1 = _req(N1, SB);
        vm.warp(expiryTs - 1 hours);
        _escape(0, N0, N1, DEPOSIT, 0);
        vault.challengeEscapeWithdrawal(0, req1, EVIDENCE);
        uint64 grace = uint64(block.timestamp) + CHALLENGE;
        vm.warp(grace);
        _expectEscapeRevert(_escapeInputs(0, N1, N2, B1, 0), Errors.NoteExpired.selector);
        vault.claimExpired(0);
        assertEq(_treasuryPaid(), uint256(DEPOSIT) * 1 gwei);
    }

    // ------------------------------------------------------ under-concession

    /// Threat: a user who was served req1 escapes from S1 with c = 0.
    function test_underConcessionRaisedAndCappedBySolvencyBound() public {
        Types.RequestPublicInputs memory req1 = _req(N1, SB);
        _escape(0, N1, N2, B1, 0);
        uint64 deadline = _deadline(0);

        vm.expectEmit(true, false, false, true, address(vault));
        emit Events.EscapeConcessionRaised(0, N1, SB, B1 - SB);
        vm.prank(operator);
        vault.raiseEscapeConcession(0, req1, EVIDENCE, 500_000);
        (, uint256 nullifier, uint256 nextNullifier, uint128 stateBalance, uint128 conceded, uint128 finalBalance,,
            uint64 newDeadline) = vault.pendingWithdrawals(0);
        assertEq(nullifier, N1);
        assertEq(nextNullifier, N2);
        assertEq(stateBalance, B1);
        assertEq(conceded, SB);
        assertEq(finalBalance, B1 - SB);
        assertEq(newDeadline, deadline);

        _finalizeAfterDeadline(0);
        assertEq(user.balance, uint256(B1 - SB) * 1 gwei);
        assertEq(_treasuryPaid(), uint256(DEPOSIT - B1 + SB) * 1 gwei);
    }

    function test_raiseIsCappedByAmountAndStateBalance() public {
        Types.RequestPublicInputs memory req1 = _req(N1, SB);
        Types.RequestPublicInputs memory huge = _req(N1, 2_000_000);
        _escape(0, N1, N2, B1, 0);
        vault.raiseEscapeConcession(0, req1, EVIDENCE, 30_000);
        (,,,, uint128 conceded, uint128 finalBalance,,) = vault.pendingWithdrawals(0);
        assertEq(conceded, 30_000);
        assertEq(finalBalance, B1 - 30_000);
        // A larger bound released at the same state is capped by the state balance.
        vault.raiseEscapeConcession(0, huge, EVIDENCE, type(uint128).max);
        (,,,, conceded, finalBalance,,) = vault.pendingWithdrawals(0);
        assertEq(conceded, B1);
        assertEq(finalBalance, 0);
        _finalizeAfterDeadline(0);
        assertEq(user.balance, 0);
        assertEq(_treasuryPaid(), uint256(DEPOSIT) * 1 gwei);
    }

    function test_raiseCannotLowerConcession() public {
        Types.RequestPublicInputs memory req1 = _req(N1, SB);
        Types.RequestPublicInputs memory low = _req(N1, 50_000);
        _escape(0, N1, N2, B1 - 60_000, 60_000);
        vm.expectRevert(Errors.ConcessionNotRaised.selector);
        vault.raiseEscapeConcession(0, low, EVIDENCE, type(uint128).max);
        vm.expectRevert(Errors.ConcessionNotRaised.selector);
        vault.raiseEscapeConcession(0, req1, EVIDENCE, 60_000);
        vm.expectRevert(Errors.ConcessionNotRaised.selector);
        vault.raiseEscapeConcession(0, req1, EVIDENCE, 0);
        vault.raiseEscapeConcession(0, req1, EVIDENCE, 60_001);
        (,,,, uint128 conceded,,,) = vault.pendingWithdrawals(0);
        assertEq(conceded, 60_001);
    }

    function test_raiseThenDefeatStillPossible() public {
        Types.RequestPublicInputs memory req1 = _req(N1, SB);
        Types.RequestPublicInputs memory req2 = _req(N2, SB);
        _escape(0, N1, N2, B1, 0);
        vault.raiseEscapeConcession(0, req1, EVIDENCE, SB);
        vault.challengeEscapeWithdrawal(0, req2, EVIDENCE);
        _assertStatus(0, Types.NoteStatus.Active);
        assertEq(vault.nullifierState(N1), 2);
        assertEq(vault.nullifierState(N2), 0);
    }

    function test_evidenceChecks() public {
        Types.RequestPublicInputs memory req2 = _req(N2, SB);
        _escape(0, N1, N2, B1, 0);
        // Wrong nullifier: defeat needs N+, raise needs N.
        Types.RequestPublicInputs memory other = _req(N3, SB);
        vm.expectRevert(Errors.NotSuccessorNullifier.selector);
        vault.challengeEscapeWithdrawal(0, other, EVIDENCE);
        vm.expectRevert(Errors.NullifierMismatch.selector);
        vault.raiseEscapeConcession(0, other, EVIDENCE, SB);
        vm.expectRevert(Errors.NullifierMismatch.selector);
        vault.raiseEscapeConcession(0, req2, EVIDENCE, SB);
        // Unverified proof.
        vm.expectRevert(Errors.InvalidProof.selector);
        vault.challengeEscapeWithdrawal(0, req2, hex"bad0");
        Types.RequestPublicInputs memory unproven = _requestInputs(N1, SB);
        vm.expectRevert(Errors.InvalidProof.selector);
        vault.raiseEscapeConcession(0, unproven, EVIDENCE, SB);
        // Deployment and key binding, even for evidence the adapter accepts.
        for (uint256 field = 0; field < 5; ++field) {
            Types.RequestPublicInputs memory invalid = _requestInputs(N2, SB);
            if (field == 0) invalid.protocolVersion += 1;
            if (field == 1) invalid.chainId += 1;
            if (field == 2) invalid.contractAddress = address(0xdead);
            if (field == 3) invalid.stateSigningKeyX += 1;
            if (field == 4) invalid.stateSigningKeyY += 1;
            adapter.acceptRequest(invalid, EVIDENCE);
            vm.expectRevert(Errors.InvalidDeploymentBinding.selector);
            vault.challengeEscapeWithdrawal(0, invalid, EVIDENCE);
        }
        // No pending escape.
        vm.expectRevert(Errors.NotPendingWithdrawal.selector);
        vault.challengeEscapeWithdrawal(1, req2, EVIDENCE);
        vm.expectRevert(Errors.NotPendingWithdrawal.selector);
        vault.raiseEscapeConcession(1, req2, EVIDENCE, SB);
        _assertStatus(0, Types.NoteStatus.PendingWithdrawal);
    }

    /// Defeat evidence is root-free: a request at an old root still defeats after many deposits.
    function test_defeatIgnoresRequestRoot() public {
        Types.RequestPublicInputs memory req1 = _req(N1, SB);
        _deposit(stranger, 77);
        _deposit(stranger, 78);
        assertNotEq(req1.activeRoot, vault.currentRoot());
        _escape(0, N0, N1, DEPOSIT, 0);
        vault.challengeEscapeWithdrawal(0, req1, EVIDENCE);
        _assertStatus(0, Types.NoteStatus.Active);
    }

    // --------------------------------------------------- front-running deposit

    /// Threat: deposits land between proving and submitting an exit, and during the escape.
    function test_frontRunDepositDuringEscapeHasNoEffect() public {
        Types.WithdrawalPublicInputs memory escape = _escapeInputs(0, N1, N2, B1, 0);
        Types.WithdrawalPublicInputs memory close = _close(0, N1, B1);
        uint256 rootAtProving = vault.currentRoot();
        _deposit(stranger, 77);
        assertNotEq(vault.currentRoot(), rootAtProving);
        // Proofs carry no root.
        vault.initiateEscapeWithdrawal(escape, "");
        uint256 rootAtEscape = vault.currentRoot();
        _deposit(stranger, 78);
        _deposit(stranger, 79);
        assertEq(vault.currentRoot(), _root());
        assertNotEq(vault.currentRoot(), rootAtEscape);
        _finalizeAfterDeadline(0);
        assertEq(user.balance, uint256(B1) * 1 gwei);

        // Mutual close is equally root-free.
        close = _close(1, 5001, 400_000);
        _deposit(stranger, 80);
        vault.mutualClose(close, "");
        _assertStatus(1, Types.NoteStatus.Closed);
    }

    // ------------------------------------------------------ escape revert matrix

    function test_escapeRevertMatrix() public {
        _deposit(stranger, 77); // note 1
        _deposit(stranger, 78); // note 2
        _deposit(stranger, 79); // note 3
        // Consumed: note 1 closes with 5001.
        vault.mutualClose(_close(1, 5001, 0), "");
        // Challenged: note 2 escapes from 7001 (successor 7002) and is defeated.
        Types.RequestPublicInputs memory req7002 = _req(7002, SB);
        _escape(2, 7001, 7002, DEPOSIT, 0);
        vault.challengeEscapeWithdrawal(2, req7002, EVIDENCE);
        // Pending: note 3.
        _escape(3, 8001, 8002, DEPOSIT, 0);

        Types.WithdrawalPublicInputs memory inputs;

        inputs = _escapeInputs(0, N1, N2, B1, 0);
        inputs.protocolVersion = 3;
        _expectEscapeRevert(inputs, Errors.InvalidDeploymentBinding.selector);
        inputs = _escapeInputs(0, N1, N2, B1, 0);
        inputs.contractAddress = address(0xdead);
        _expectEscapeRevert(inputs, Errors.InvalidDeploymentBinding.selector);
        inputs = _escapeInputs(0, N1, N2, B1, 0);
        inputs.clearanceSigningKeyY += 1;
        _expectEscapeRevert(inputs, Errors.InvalidDeploymentBinding.selector);

        inputs = _escapeInputs(0, N1, N2, B1, 0);
        inputs.hasClearance = true;
        _expectEscapeRevert(inputs, Errors.InvalidDeploymentBinding.selector);

        inputs = _escapeInputs(0, N1, N2, B1, 0);
        inputs.validUntil = uint64(block.timestamp) - 1;
        _expectEscapeRevert(inputs, Errors.ExitProofExpired.selector);

        inputs = _escapeInputs(0, N1, N2, B1, 0);
        inputs.noteId = 9;
        _expectEscapeRevert(inputs, Errors.NoteNotActive.selector);
        inputs = _escapeInputs(1, N1, N2, B1, 0);
        _expectEscapeRevert(inputs, Errors.NoteNotActive.selector);
        inputs = _escapeInputs(3, N1, N2, B1, 0);
        _expectEscapeRevert(inputs, Errors.NoteNotActive.selector);

        inputs = _escapeInputs(0, N1, N2, B1, 0);
        inputs.registration += 1;
        _expectEscapeRevert(inputs, Errors.NoteMismatch.selector);
        inputs = _escapeInputs(0, N1, N2, B1, 0);
        inputs.depositAmount += 1;
        _expectEscapeRevert(inputs, Errors.NoteMismatch.selector);
        inputs = _escapeInputs(0, N1, N2, B1, 0);
        inputs.expiryTs += 1 days;
        _expectEscapeRevert(inputs, Errors.NoteMismatch.selector);
        // Another note's fields cannot be borrowed.
        inputs = _escapeInputs(1, N1, N2, B1, 0);
        inputs.noteId = 0;
        _expectEscapeRevert(inputs, Errors.NoteMismatch.selector);

        _expectEscapeRevert(_escapeInputs(0, N1, N2, DEPOSIT, 1), Errors.InvalidBalance.selector);
        _expectEscapeRevert(_escapeInputs(0, N1, N2, DEPOSIT + 1, 0), Errors.InvalidBalance.selector);

        _expectEscapeRevert(_escapeInputs(0, N1, 0, B1, 0), Errors.NotSuccessorNullifier.selector);
        _expectEscapeRevert(_escapeInputs(0, N1, N1, B1, 0), Errors.NotSuccessorNullifier.selector);

        // N already consumed (by a close, or by a pending escape as N or N+).
        _expectEscapeRevert(_escapeInputs(0, 5001, N2, B1, 0), Errors.ReplayedNullifier.selector);
        _expectEscapeRevert(_escapeInputs(0, 8001, N2, B1, 0), Errors.ReplayedNullifier.selector);
        _expectEscapeRevert(_escapeInputs(0, 8002, N2, B1, 0), Errors.ReplayedNullifier.selector);
        // N challenged.
        _expectEscapeRevert(_escapeInputs(0, 7001, N2, B1, 0), Errors.ReplayedNullifier.selector);
        // N+ consumed.
        _expectEscapeRevert(_escapeInputs(0, N1, 5001, B1, 0), Errors.ReplayedNullifier.selector);
        _expectEscapeRevert(_escapeInputs(0, N1, 8002, B1, 0), Errors.ReplayedNullifier.selector);
        // N+ challenged: the escaped state is superseded.
        _expectEscapeRevert(_escapeInputs(0, N1, 7001, B1, 0), Errors.SupersededState.selector);

        _expectExitRevert(_escapeInputs(0, N1, N2, B1, 0), "bad", Errors.InvalidProof.selector);

        // Past claimableAt the note belongs to the expiry sweep.
        uint64 expiryTs = _expiry(0);
        vm.warp(expiryTs);
        inputs = _escapeInputs(0, N1, N2, B1, 0);
        _expectEscapeRevert(inputs, Errors.NoteExpired.selector);
        _expectCloseRevert(_close(0, N1, B1), Errors.NoteExpired.selector);

        _assertStatus(0, Types.NoteStatus.Active);
        assertEq(vault.nullifierState(N1), 0);
        assertEq(vault.nullifierState(N2), 0);
        assertEq(vault.nullifierState(7001), 2);
        assertEq(vault.nullifierState(7002), 0);
    }

    // ------------------------------------------------ nullifier double spend

    function test_doubleSpendAcrossEscapeAndClose() public {
        _deposit(stranger, 77); // note 1
        _deposit(stranger, 78); // note 2
        _escape(0, N1, N2, B1, 0);
        // Both escape nullifiers are consumed for every exit.
        _expectCloseRevert(_close(1, N1, 0), Errors.ReplayedNullifier.selector);
        _expectCloseRevert(_close(1, N2, 0), Errors.ReplayedNullifier.selector);
        _finalizeAfterDeadline(0);
        assertEq(vault.nullifierState(N1), 1);
        assertEq(vault.nullifierState(N2), 1);
        _expectEscapeRevert(_escapeInputs(1, N2, N3, 0, 0), Errors.ReplayedNullifier.selector);

        // A close consumes N: neither a second close nor an escape can reuse it.
        vault.mutualClose(_close(1, 5001, 0), "");
        _expectCloseRevert(_close(2, 5001, 0), Errors.ReplayedNullifier.selector);
        _expectEscapeRevert(_escapeInputs(2, 5001, 5002, 0, 0), Errors.ReplayedNullifier.selector);
        _expectEscapeRevert(_escapeInputs(2, 5000, 5001, 0, 0), Errors.ReplayedNullifier.selector);

        // After a defeat the challenged N cannot be closed; the released N+ can.
        Types.RequestPublicInputs memory req = _req(6002, SB);
        _escape(2, 6001, 6002, 0, 0);
        vault.challengeEscapeWithdrawal(2, req, EVIDENCE);
        _expectCloseRevert(_close(2, 6001, 0), Errors.ReplayedNullifier.selector);
        vault.mutualClose(_close(2, 6002, 0), "");
        assertEq(vault.nullifierState(6001), 2);
        assertEq(vault.nullifierState(6002), 1);
    }

    function test_finalizeTwiceAndAfterCloseFails() public {
        _escape(0, N1, N2, B1, 0);
        _finalizeAfterDeadline(0);
        vm.expectRevert(Errors.NotPendingWithdrawal.selector);
        vault.finalizeEscapeWithdrawal(0);
        vm.expectRevert(Errors.NoteNotActive.selector);
        vault.claimExpired(0);
        assertEq(address(vault).balance, uint256(vault.treasuryAccrued()) * 1 gwei);
        assertEq(_treasuryPaid(), uint256(DEPOSIT - B1) * 1 gwei);
        assertEq(address(vault).balance, 0);
    }

    // ------------------------------------------------------------------ pause

    function test_pauseBlocksExitsForAtMostMaxDuration() public {
        Types.WithdrawalPublicInputs memory escape = _escapeInputs(0, N1, N2, B1, 0);
        escape.validUntil = uint64(block.timestamp + 30 days);
        vm.expectEmit(false, false, false, true, address(vault));
        emit Events.VaultPaused(uint64(block.timestamp));
        vault.pause();
        assertTrue(vault.paused());
        assertEq(vault.pausedAt(), uint64(block.timestamp));
        vm.expectRevert(Errors.Paused.selector);
        vault.initiateEscapeWithdrawal(escape, "");
        _expectCloseRevert(_close(0, N1, B1), Errors.Paused.selector);
        vm.deal(stranger, uint256(DEPOSIT) * 1 gwei);
        uint256[32] memory path = _path(leafCount);
        vm.prank(stranger);
        vm.expectRevert(Errors.Paused.selector);
        vault.deposit{value: uint256(DEPOSIT) * 1 gwei}(bytes32(uint256(77)), DEPOSIT, path);

        vm.warp(T0 + vault.MAX_PAUSE_DURATION() - 1);
        vm.expectRevert(Errors.Paused.selector);
        vault.initiateEscapeWithdrawal(escape, "");
        // The pause lapses by itself for exits; deposits stay blocked until unpause.
        vm.warp(T0 + vault.MAX_PAUSE_DURATION());
        assertTrue(vault.paused());
        vault.initiateEscapeWithdrawal(escape, "");
        vm.prank(stranger);
        vm.expectRevert(Errors.Paused.selector);
        vault.deposit{value: uint256(DEPOSIT) * 1 gwei}(bytes32(uint256(77)), DEPOSIT, path);
        _finalizeAfterDeadline(0);
        assertEq(user.balance, uint256(B1) * 1 gwei);
    }

    function test_pauseCooldownAndOwnership() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, stranger));
        vault.pause();
        vm.expectRevert(Errors.NotPaused.selector);
        vault.unpause();

        vault.pause();
        vm.expectRevert(Errors.Paused.selector);
        vault.pause();
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, stranger));
        vault.unpause();
        vm.warp(T0 + 2 hours);
        vm.expectEmit(false, false, false, true, address(vault));
        emit Events.VaultUnpaused(T0 + 2 hours);
        vault.unpause();
        assertEq(vault.totalPausedDuration(), 2 hours);
        assertEq(vault.lastPauseEnd(), T0 + 2 hours);
        assertEq(vault.pausedAt(), 0);

        vm.warp(T0 + 2 hours + vault.PAUSE_COOLDOWN() - 1);
        vm.expectRevert(Errors.PauseCooldown.selector);
        vault.pause();
        vm.warp(T0 + 2 hours + vault.PAUSE_COOLDOWN());
        vault.pause();

        // A pause left in place counts only MAX_PAUSE_DURATION, and the cooldown runs from its lapse.
        uint64 secondStart = uint64(block.timestamp);
        vm.warp(secondStart + 30 days);
        vault.unpause();
        assertEq(vault.totalPausedDuration(), 2 hours + vault.MAX_PAUSE_DURATION());
        assertEq(vault.lastPauseEnd(), secondStart + vault.MAX_PAUSE_DURATION());
        vault.pause();
    }

    /// Threat: the owner pauses before expiry and never unpauses, hoping to sweep the note.
    function test_indefinitePauseThenSweepFails() public {
        uint64 expiryTs = _expiry(0);
        uint64 maxPause = vault.MAX_PAUSE_DURATION();
        vm.warp(expiryTs - 1 hours);
        vault.pause();
        vm.warp(expiryTs + 1);
        vm.expectRevert(Errors.Paused.selector);
        vault.claimExpired(0);
        assertEq(vault.claimableAt(0), expiryTs + 1 hours + 1);

        // Exits reopen exactly when the pause lapses, and the sweep moved by the whole pause.
        vm.warp(expiryTs - 1 hours + maxPause);
        assertEq(vault.claimableAt(0), expiryTs + maxPause);
        vm.expectRevert(Errors.NoteNotExpired.selector);
        vault.claimExpired(0);
        // The user keeps the hour the pause took.
        vm.warp(expiryTs + maxPause - 1);
        vm.expectRevert(Errors.NoteNotExpired.selector);
        vault.claimExpired(0);
        Types.WithdrawalPublicInputs memory escape = _escapeInputs(0, N1, N2, B1, 0);
        vault.initiateEscapeWithdrawal(escape, "");
        _finalizeAfterDeadline(0);
        assertEq(user.balance, uint256(B1) * 1 gwei);
        assertEq(_treasuryPaid(), uint256(DEPOSIT - B1) * 1 gwei);
    }

    function test_pauseExtendsClaimableAtAndBlocksSweep() public {
        uint64 expiryTs = _expiry(0);
        vm.warp(expiryTs - 1 hours);
        vault.pause();
        vm.warp(expiryTs + 2 days);
        vm.expectRevert(Errors.Paused.selector);
        vault.claimExpired(0);
        vault.unpause();
        uint64 claimable = expiryTs + 2 days + 1 hours;
        assertEq(vault.claimableAt(0), claimable);
        vm.expectRevert(Errors.NoteNotExpired.selector);
        vault.claimExpired(0);
        vm.warp(claimable);
        vm.expectEmit(true, false, false, true, address(vault));
        emit Events.ExpiredClaimed(0, DEPOSIT);
        vm.prank(stranger);
        vault.claimExpired(0);
        assertEq(_treasuryPaid(), uint256(DEPOSIT) * 1 gwei);
        _assertStatus(0, Types.NoteStatus.Closed);
    }

    function test_pausedOffsetExcludesPausesBeforeDeposit() public {
        vault.pause();
        vm.warp(T0 + 3 days);
        vault.unpause();
        _deposit(stranger, 77); // note 1
        uint64 expiry0 = _expiry(0);
        uint64 expiry1 = _expiry(1);
        (,,,,, uint64 offset1) = vault.notes(1);
        assertEq(offset1, 3 days);
        assertEq(vault.claimableAt(0), expiry0 + 3 days);
        assertEq(vault.claimableAt(1), expiry1);
        // A pause after both deposits extends both.
        vm.warp(T0 + 5 days);
        vault.pause();
        vm.warp(T0 + 6 days);
        assertEq(vault.claimableAt(0), expiry0 + 4 days);
        assertEq(vault.claimableAt(1), expiry1 + 1 days);
    }

    function test_challengeRaiseFinalizeAndRetireOpenWhilePaused() public {
        _deposit(stranger, 77); // note 1
        _deposit(stranger, 78); // note 2
        Types.RequestPublicInputs memory req1 = _req(N1, SB);
        Types.RequestPublicInputs memory req = _req(9002, SB);
        _escape(0, N1, N2, B1, 0);
        _escape(1, 9001, 9002, DEPOSIT, 0);
        vault.mutualClose(_close(2, 5001, 0), "");
        vault.pause();
        vm.warp(block.timestamp + 1 hours);
        vm.startPrank(stranger);
        vault.raiseEscapeConcession(0, req1, EVIDENCE, SB);
        vault.challengeEscapeWithdrawal(1, req, EVIDENCE);
        uint256[32] memory path2 = _path(2);
        leafAt[2] = 0;
        vault.retireClosedLeaf(2, path2);
        vm.stopPrank();
        assertEq(vault.currentRoot(), _root());
        _finalizeAfterDeadline(0);
        assertTrue(vault.paused());
        assertEq(user.balance, uint256(B1 - SB) * 1 gwei);
        _assertStatus(1, Types.NoteStatus.Active);
    }

    // -------------------------------------------------------- retireClosedLeaf

    function test_retireClosedLeafIsClosedOnly() public {
        _deposit(stranger, 77); // note 1
        _deposit(stranger, 78); // note 2
        _escape(2, 9001, 9002, DEPOSIT, 0);
        uint256[32] memory path0 = _path(0);
        vm.expectRevert(Errors.NoteNotClosed.selector);
        vault.retireClosedLeaf(0, path0);
        uint256[32] memory path2 = _path(2);
        vm.expectRevert(Errors.NoteNotClosed.selector);
        vault.retireClosedLeaf(2, path2);
        uint256[32] memory path7 = _path(7);
        vm.expectRevert(Errors.NoteNotClosed.selector);
        vault.retireClosedLeaf(7, path7);

        vault.mutualClose(_close(0, N1, B1), "");
        assertEq(vault.currentRoot(), _root());
        // Wrong path.
        uint256[32] memory wrong = _path(0);
        wrong[0] += 1;
        vm.expectRevert(Errors.StaleRoot.selector);
        vault.retireClosedLeaf(0, wrong);

        leafAt[0] = 0;
        uint256 expectedRoot = _root();
        vm.expectEmit(true, false, false, true, address(vault));
        emit Events.ClosedLeafRetired(0, expectedRoot);
        vm.prank(stranger);
        vault.retireClosedLeaf(0, path0);
        assertEq(vault.currentRoot(), expectedRoot);
        _assertStatus(0, Types.NoteStatus.Closed);
        vm.expectRevert(Errors.StaleRoot.selector);
        vault.retireClosedLeaf(0, path0);

        // A swept note can be retired as well.
        uint64 expiryTs = _expiry(1);
        vm.warp(expiryTs);
        vault.claimExpired(1);
        uint256[32] memory path1 = _path(1);
        leafAt[1] = 0;
        vault.retireClosedLeaf(1, path1);
        assertEq(vault.currentRoot(), _root());
    }

    // ---------------------------------------------------------------- griefing

    /// Threat: a third party holding the user's request proof raises the concession.
    function test_thirdPartyRaiseOnlyUpToBoundAndPaysTreasury() public {
        Types.RequestPublicInputs memory req1 = _req(N1, SB);
        _escape(0, N1, N2, B1, 0);
        vm.prank(stranger);
        vault.raiseEscapeConcession(0, req1, EVIDENCE, type(uint128).max);
        (,,,, uint128 conceded,,,) = vault.pendingWithdrawals(0);
        assertEq(conceded, SB);
        vm.prank(stranger);
        vm.expectRevert(Errors.ConcessionNotRaised.selector);
        vault.raiseEscapeConcession(0, req1, EVIDENCE, type(uint128).max);
        _finalizeAfterDeadline(0);
        assertEq(stranger.balance, 0);
        assertEq(user.balance, uint256(B1 - SB) * 1 gwei);
        assertEq(_treasuryPaid(), uint256(DEPOSIT - B1 + SB) * 1 gwei);
    }

    function test_deadlineBoundaries() public {
        Types.RequestPublicInputs memory req1 = _req(N1, SB);
        Types.RequestPublicInputs memory req2 = _req(N2, SB);
        _escape(0, N1, N2, B1, 0);
        uint64 deadline = _deadline(0);
        vm.warp(deadline);
        vm.expectRevert(Errors.ChallengeNotExpired.selector);
        vault.finalizeEscapeWithdrawal(0);
        // Raise is still open at the deadline.
        vault.raiseEscapeConcession(0, req1, EVIDENCE, SB);
        vm.warp(deadline + 1);
        vm.expectRevert(Errors.ChallengeExpired.selector);
        vault.challengeEscapeWithdrawal(0, req2, EVIDENCE);
        vm.expectRevert(Errors.ChallengeExpired.selector);
        vault.raiseEscapeConcession(0, req1, EVIDENCE, SB + 1);
        vault.finalizeEscapeWithdrawal(0);
        assertEq(user.balance, uint256(B1 - SB) * 1 gwei);
    }

    function test_defeatAtDeadlineSucceeds() public {
        Types.RequestPublicInputs memory req2 = _req(N2, SB);
        _escape(0, N1, N2, B1, 0);
        vm.warp(_deadline(0));
        vault.challengeEscapeWithdrawal(0, req2, EVIDENCE);
        _assertStatus(0, Types.NoteStatus.Active);
    }

    /// Threat: the owner sets a treasury that refuses ETH to hold user payouts hostage.
    function test_revertingTreasuryCannotBlockPayouts() public {
        _deposit(stranger, 77); // note 1
        _deposit(stranger, 78); // note 2
        vault.setTreasury(address(new RejectingTreasury()));

        vault.mutualClose(_close(0, N1, B1), "");
        assertEq(user.balance, uint256(B1) * 1 gwei);
        _escape(1, 5001, 5002, B2, 0);
        _finalizeAfterDeadline(1);
        assertEq(user.balance, uint256(B1 + B2) * 1 gwei);
        vm.warp(vault.claimableAt(2));
        vault.claimExpired(2);
        uint128 owed = (DEPOSIT - B1) + (DEPOSIT - B2) + DEPOSIT;
        assertEq(vault.treasuryAccrued(), owed);
        assertEq(address(vault).balance, uint256(owed) * 1 gwei);

        vm.prank(stranger);
        vm.expectRevert(Errors.NativeTransferFailed.selector);
        vault.withdrawTreasury();
        assertEq(vault.treasuryAccrued(), owed);

        vault.setTreasury(treasury);
        vm.expectEmit(true, false, false, true, address(vault));
        emit Events.TreasuryWithdrawn(treasury, owed);
        vm.prank(stranger);
        vault.withdrawTreasury();
        assertEq(treasury.balance, uint256(owed) * 1 gwei);
        assertEq(vault.treasuryAccrued(), 0);
        assertEq(address(vault).balance, 0);
        vm.expectRevert(Errors.ZeroAmount.selector);
        vault.withdrawTreasury();
    }

    // ---------------------------------------------------------------- helpers

    function _deposit(address from, uint256 commitment) private returns (uint32 noteId) {
        noteId = vault.nextNoteId();
        assertEq(noteId, leafCount);
        uint256[32] memory path = _path(noteId);
        vm.deal(from, from.balance + uint256(DEPOSIT) * 1 gwei);
        vm.prank(from);
        vault.deposit{value: uint256(DEPOSIT) * 1 gwei}(bytes32(commitment), DEPOSIT, path);
        (bytes32 stored, uint128 amount, uint64 expiryTs,,,) = vault.notes(noteId);
        leafAt[noteId] = NoteLeafLib.computeLeaf(noteId, stored, amount, expiryTs);
        leafCount = noteId + 1;
        assertEq(vault.currentRoot(), _root());
    }

    function _expiry(uint32 noteId) private view returns (uint64 expiryTs) {
        (,, expiryTs,,,) = vault.notes(noteId);
    }

    function _assertStatus(uint32 noteId, Types.NoteStatus expected) private view {
        (,,, Types.NoteStatus status,,) = vault.notes(noteId);
        assertEq(uint256(status), uint256(expected));
    }

    function _deadline(uint32 noteId) private view returns (uint64 deadline) {
        (,,,,,,, deadline) = vault.pendingWithdrawals(noteId);
    }

    /// @dev Pays whatever the vault accrued for the treasury (permissionless) and returns its balance.
    function _treasuryPaid() private returns (uint256) {
        if (vault.treasuryAccrued() != 0) {
            vm.prank(stranger);
            vault.withdrawTreasury();
        }
        return treasury.balance;
    }

    function _finalizeAfterDeadline(uint32 noteId) private {
        uint64 deadline = _deadline(noteId);
        if (block.timestamp <= deadline) vm.warp(deadline + 1);
        vm.prank(stranger);
        vault.finalizeEscapeWithdrawal(noteId);
    }

    function _withdrawal(uint32 noteId, uint256 nullifier, uint256 nextNullifier, uint128 finalBalance, uint128 conceded, bool clearance)
        private
        view
        returns (Types.WithdrawalPublicInputs memory)
    {
        (bytes32 commitment, uint128 amount, uint64 expiryTs,,,) = vault.notes(noteId);
        return Types.WithdrawalPublicInputs({
            protocolVersion: 2,
            chainId: uint64(block.chainid),
            contractAddress: address(vault),
            registration: uint256(commitment),
            stateSigningKeyX: STATE_X,
            stateSigningKeyY: STATE_Y,
            clearanceSigningKeyX: CLEAR_X,
            clearanceSigningKeyY: CLEAR_Y,
            noteId: noteId,
            depositAmount: amount,
            expiryTs: expiryTs,
            finalBalance: finalBalance,
            destination: user,
            withdrawalNullifier: nullifier,
            hasClearance: clearance,
            nextNullifier: nextNullifier,
            conceded: conceded,
            validUntil: uint64(block.timestamp + 1 hours)
        });
    }

    function _escapeInputs(uint32 noteId, uint256 nullifier, uint256 nextNullifier, uint128 finalBalance, uint128 conceded)
        private
        view
        returns (Types.WithdrawalPublicInputs memory)
    {
        return _withdrawal(noteId, nullifier, nextNullifier, finalBalance, conceded, false);
    }

    function _close(uint32 noteId, uint256 nullifier, uint128 finalBalance)
        private
        view
        returns (Types.WithdrawalPublicInputs memory)
    {
        return _withdrawal(noteId, nullifier, 0, finalBalance, 0, true);
    }

    function _escape(uint32 noteId, uint256 nullifier, uint256 nextNullifier, uint128 finalBalance, uint128 conceded)
        private
    {
        uint64 deadline = uint64(block.timestamp) + CHALLENGE;
        vm.expectEmit(true, false, false, true, address(vault));
        emit Events.EscapeWithdrawalInitiated(noteId, nullifier, nextNullifier, finalBalance, conceded, user, deadline);
        vault.initiateEscapeWithdrawal(_escapeInputs(noteId, nullifier, nextNullifier, finalBalance, conceded), "");
        _assertStatus(noteId, Types.NoteStatus.PendingWithdrawal);
        (bool exists, uint256 n, uint256 next, uint128 stateBalance, uint128 c, uint128 f, address destination,
            uint64 storedDeadline) = vault.pendingWithdrawals(noteId);
        assertTrue(exists);
        assertEq(n, nullifier);
        assertEq(next, nextNullifier);
        assertEq(stateBalance, finalBalance + conceded);
        assertEq(c, conceded);
        assertEq(f, finalBalance);
        assertEq(destination, user);
        assertEq(storedDeadline, deadline);
        assertEq(vault.nullifierState(nullifier), 1);
        assertEq(vault.nullifierState(nextNullifier), 1);
    }

    function _expectEscapeRevert(Types.WithdrawalPublicInputs memory inputs, bytes4 selector) private {
        vm.expectRevert(selector);
        vault.initiateEscapeWithdrawal(inputs, "");
    }

    function _expectCloseRevert(Types.WithdrawalPublicInputs memory inputs, bytes4 selector) private {
        vm.expectRevert(selector);
        vault.mutualClose(inputs, "");
    }

    function _expectExitRevert(Types.WithdrawalPublicInputs memory inputs, bytes memory proof, bytes4 selector)
        private
    {
        vm.expectRevert(selector);
        if (inputs.hasClearance) vault.mutualClose(inputs, proof);
        else vault.initiateEscapeWithdrawal(inputs, proof);
    }

    function _requestInputs(uint256 nullifier, uint128 solvencyBound)
        private
        view
        returns (Types.RequestPublicInputs memory)
    {
        return Types.RequestPublicInputs({
            protocolVersion: 2,
            chainId: uint64(block.chainid),
            contractAddress: address(vault),
            activeRoot: vault.currentRoot(),
            stateSigningKeyX: STATE_X,
            stateSigningKeyY: STATE_Y,
            requestTime: uint64(block.timestamp),
            solvencyBound: solvencyBound,
            requestNullifier: nullifier,
            authorizationTag: 103,
            anonymousCommitmentX: 104,
            anonymousCommitmentY: 105
        });
    }

    /// @dev A request proof the user released, archived by the operator.
    function _req(uint256 nullifier, uint128 solvencyBound) private returns (Types.RequestPublicInputs memory request) {
        request = _requestInputs(nullifier, solvencyBound);
        adapter.acceptRequest(request, EVIDENCE);
    }

    function _node(uint256 left, uint256 right) private pure returns (uint256) {
        return Bn254Poseidon.hash3(DOMAIN_NODE, left, right);
    }

    function _subtree(uint256 level, uint256 index) private view returns (uint256) {
        if ((index << level) >= leafCount) return zeroHashes[level];
        if (level == 0) return leafAt[uint32(index)];
        return _node(_subtree(level - 1, 2 * index), _subtree(level - 1, 2 * index + 1));
    }

    function _path(uint32 index) private view returns (uint256[32] memory siblings) {
        for (uint256 level = 0; level < 32; ++level) {
            siblings[level] = _subtree(level, (uint256(index) >> level) ^ 1);
        }
    }

    function _root() private view returns (uint256) {
        return _subtree(32, 0);
    }
}
