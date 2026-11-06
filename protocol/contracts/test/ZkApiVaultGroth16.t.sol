// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ZkApiVault} from "../src/ZkApiVault.sol";
import {Groth16ProofAdapter} from "../src/adapters/Groth16ProofAdapter.sol";
import {Types} from "../src/libraries/Types.sol";
import {Errors} from "../src/libraries/Errors.sol";
import {Bn254Poseidon} from "../src/libraries/Bn254Poseidon.sol";
import {NoteLeafLib} from "../src/libraries/NoteLeafLib.sol";

/// @dev Rust-generated proofs, real verifier and normal vault deployment.
/// Regenerate test/fixtures/vault-challenge.json with vault_challenge_fixture.rs. The fixture is one
/// chain of note 0: S0 (genesis, B = D), req0 at N0, S1 (B 900k), req1 at N1, S2 (B 850k), req2 at
/// N2, every request with solvency bound 100k; escapes esc0 (S0), esc1 (S1, c = 0), esc1_conceded
/// (S1, c = 100k), esc2 (S2) and the clearance close close2 (S2).
contract ZkApiVaultGroth16Test is Test {
    uint256 constant DOMAIN_NODE = 0x7a6b6170692e76322e6e6f6465;
    uint128 constant DEPOSIT = 1_000_000;
    uint128 constant SB = 100_000;
    address constant DEPLOYER = address(0xf00d);
    address constant USER = 0x1111111111111111111111111111111111111111;
    address constant TREASURY = address(0xbeef);
    address constant OPERATOR = address(0x0bad);

    Groth16ProofAdapter adapter;
    ZkApiVault vault;
    string fixtures;
    uint256[32] emptySiblings;

    function setUp() public {
        vm.chainId(31_337);
        vm.warp(2_000_000_000);
        fixtures = vm.readFile("test/fixtures/vault-challenge.json");
        assertEq(vm.parseJsonString(fixtures, ".circuit_id"), "zkapi-v2-concession-v1");
        uint256 zero;
        for (uint256 level = 0; level < 32; ++level) {
            emptySiblings[level] = zero;
            zero = Bn254Poseidon.hash3(DOMAIN_NODE, zero, zero);
        }
        adapter = new Groth16ProofAdapter();
        (Types.WithdrawalPublicInputs memory parameters,) = _withdrawal("esc1");
        vm.setNonce(DEPLOYER, 0);
        vm.prank(DEPLOYER);
        vault = new ZkApiVault(
            TREASURY,
            30 days,
            24 hours,
            100_000,
            address(adapter),
            parameters.stateSigningKeyX,
            parameters.stateSigningKeyY,
            parameters.clearanceSigningKeyX,
            parameters.clearanceSigningKeyY,
            address(this)
        );
        assertEq(address(vault), parameters.contractAddress);
        vm.deal(USER, uint256(DEPOSIT) * 1 gwei);
        bytes32 registration = vm.parseJsonBytes32(fixtures, ".note_a_registration");
        vm.prank(USER);
        vault.deposit{value: uint256(DEPOSIT) * 1 gwei}(registration, DEPOSIT, emptySiblings);
        assertEq(uint256(registration), parameters.registration);
        (,, uint64 expiryTs,,,) = vault.notes(0);
        assertEq(expiryTs, parameters.expiryTs);
    }

    /// Threat: the operator withholds S2 after the user released req1. The user escapes from S1
    /// conceding its bound and is paid B1 - b1 with no further action.
    function test_realHonestWithheldExitPaysBalanceMinusBound() public {
        (Types.RequestPublicInputs memory req0, bytes memory req0Proof) = _request("req0");
        (Types.RequestPublicInputs memory req1, bytes memory req1Proof) = _request("req1");
        (Types.WithdrawalPublicInputs memory esc, bytes memory escProof) = _withdrawal("esc1_conceded");
        assertEq(esc.finalBalance, 800_000);
        assertEq(esc.conceded, SB);
        assertEq(esc.withdrawalNullifier, req1.requestNullifier);
        _gas("escape (initiateEscapeWithdrawal)");
        vault.initiateEscapeWithdrawal(esc, escProof);
        _gasEnd();

        vm.startPrank(OPERATOR);
        vm.expectRevert(Errors.NotSuccessorNullifier.selector);
        vault.challengeEscapeWithdrawal(0, req1, req1Proof);
        vm.expectRevert(Errors.NotSuccessorNullifier.selector);
        vault.challengeEscapeWithdrawal(0, req0, req0Proof);
        vm.expectRevert(Errors.ConcessionNotRaised.selector);
        vault.raiseEscapeConcession(0, req1, req1Proof, type(uint128).max);
        vm.stopPrank();

        (,,,,,,, uint64 deadline) = vault.pendingWithdrawals(0);
        vm.warp(deadline + 1);
        _gas("finalizeEscapeWithdrawal");
        vault.finalizeEscapeWithdrawal(0);
        _gasEnd();
        assertEq(USER.balance, 800_000 gwei);
        assertEq(_treasuryPaid(), 200_000 gwei);
        assertEq(address(vault).balance, 0);
    }

    /// Threat: the user spent S1 and S2, then escapes from older states.
    function test_realStaleEscapesDefeatedThenSuperseded() public {
        (Types.RequestPublicInputs memory req2, bytes memory req2Proof) = _request("req2");
        (Types.WithdrawalPublicInputs memory esc1, bytes memory esc1Proof) = _withdrawal("esc1");
        (Types.WithdrawalPublicInputs memory esc0, bytes memory esc0Proof) = _withdrawal("esc0");
        vault.initiateEscapeWithdrawal(esc1, esc1Proof);
        assertEq(esc1.nextNullifier, req2.requestNullifier);

        vm.prank(OPERATOR);
        _gas("defeat (challengeEscapeWithdrawal)");
        vault.challengeEscapeWithdrawal(0, req2, req2Proof);
        _gasEnd();
        assertEq(vault.nullifierState(esc1.withdrawalNullifier), 2);
        assertEq(vault.nullifierState(esc1.nextNullifier), 0);
        (,,, Types.NoteStatus status, uint64 claimableAfter,) = vault.notes(0);
        assertEq(uint256(status), uint256(Types.NoteStatus.Active));
        assertEq(claimableAfter, esc1.expiryTs);
        (bool exists,,,,,,,) = vault.pendingWithdrawals(0);
        assertFalse(exists);

        // S0's successor nullifier is S1's, which is challenged: S0 is superseded.
        assertEq(esc0.nextNullifier, esc1.withdrawalNullifier);
        vm.expectRevert(Errors.SupersededState.selector);
        vault.initiateEscapeWithdrawal(esc0, esc0Proof);
        vm.expectRevert(Errors.ReplayedNullifier.selector);
        vault.initiateEscapeWithdrawal(esc1, esc1Proof);

        // The newest state escapes and is paid.
        (Types.WithdrawalPublicInputs memory esc2, bytes memory esc2Proof) = _withdrawal("esc2");
        vault.initiateEscapeWithdrawal(esc2, esc2Proof);
        (,,,,,,, uint64 deadline) = vault.pendingWithdrawals(0);
        vm.warp(deadline + 1);
        vault.finalizeEscapeWithdrawal(0);
        assertEq(USER.balance, 850_000 gwei);
        assertEq(_treasuryPaid(), 150_000 gwei);
    }

    /// Threat: the user spent S1 (req1) and escapes from S0.
    function test_realStaleEscapeFromGenesisDefeated() public {
        (Types.RequestPublicInputs memory req1, bytes memory req1Proof) = _request("req1");
        (Types.WithdrawalPublicInputs memory esc0, bytes memory esc0Proof) = _withdrawal("esc0");
        vault.initiateEscapeWithdrawal(esc0, esc0Proof);
        vault.challengeEscapeWithdrawal(0, req1, req1Proof);
        assertEq(vault.nullifierState(esc0.withdrawalNullifier), 2);
        assertEq(vault.nullifierState(esc0.nextNullifier), 0);
        vm.expectRevert(Errors.ReplayedNullifier.selector);
        vault.initiateEscapeWithdrawal(esc0, esc0Proof);
    }

    /// Threat: a user served req1 escapes from S1 with c = 0; the raise caps at the bound.
    function test_realUnderConcessionRaised() public {
        (Types.RequestPublicInputs memory req1, bytes memory req1Proof) = _request("req1");
        (Types.RequestPublicInputs memory req0, bytes memory req0Proof) = _request("req0");
        (Types.WithdrawalPublicInputs memory esc1, bytes memory esc1Proof) = _withdrawal("esc1");
        vault.initiateEscapeWithdrawal(esc1, esc1Proof);
        vm.expectRevert(Errors.NullifierMismatch.selector);
        vault.raiseEscapeConcession(0, req0, req0Proof, SB);

        vm.prank(OPERATOR);
        _gas("raiseEscapeConcession");
        vault.raiseEscapeConcession(0, req1, req1Proof, 500_000);
        _gasEnd();
        (,,, uint128 stateBalance, uint128 conceded, uint128 finalBalance,,) = vault.pendingWithdrawals(0);
        assertEq(stateBalance, 900_000);
        assertEq(conceded, SB);
        assertEq(finalBalance, 800_000);
        vm.expectRevert(Errors.ConcessionNotRaised.selector);
        vault.raiseEscapeConcession(0, req1, req1Proof, type(uint128).max);

        (,,,,,,, uint64 deadline) = vault.pendingWithdrawals(0);
        vm.warp(deadline + 1);
        vault.finalizeEscapeWithdrawal(0);
        assertEq(USER.balance, 800_000 gwei);
        assertEq(_treasuryPaid(), 200_000 gwei);
    }

    /// Threat: deposits change the root between proving and every exit step.
    function test_realFrontRunDepositHasNoEffect() public {
        (Types.RequestPublicInputs memory req2, bytes memory req2Proof) = _request("req2");
        (Types.WithdrawalPublicInputs memory esc1, bytes memory esc1Proof) = _withdrawal("esc1");
        _depositOther(1, bytes32(uint256(77)));
        assertNotEq(vault.currentRoot(), req2.activeRoot);
        vault.initiateEscapeWithdrawal(esc1, esc1Proof);
        _depositOther(2, bytes32(uint256(78)));
        // The defeat proof's historical root is not checked.
        vault.challengeEscapeWithdrawal(0, req2, req2Proof);

        (Types.WithdrawalPublicInputs memory close2, bytes memory close2Proof) = _withdrawal("close2");
        _depositOther(3, bytes32(uint256(79)));
        _gas("mutualClose");
        vault.mutualClose(close2, close2Proof);
        _gasEnd();
        assertEq(USER.balance, 850_000 gwei);
        assertEq(_treasuryPaid(), 150_000 gwei);
        assertEq(vault.nullifierState(close2.withdrawalNullifier), 1);

        // Every exit of the closed note now fails.
        (Types.WithdrawalPublicInputs memory esc2, bytes memory esc2Proof) = _withdrawal("esc2");
        vm.expectRevert(Errors.NoteNotActive.selector);
        vault.initiateEscapeWithdrawal(esc2, esc2Proof);
        vm.expectRevert(Errors.NoteNotActive.selector);
        vault.mutualClose(close2, close2Proof);
    }

    function test_realTamperedInputsRejected() public {
        (Types.WithdrawalPublicInputs memory esc, bytes memory escProof) = _withdrawal("esc1_conceded");
        // Under-conceding after proving: the concession is bound by the proof.
        esc.conceded = 0;
        esc.finalBalance = 900_000;
        vm.expectRevert(Errors.InvalidProof.selector);
        vault.initiateEscapeWithdrawal(esc, escProof);
        (esc, escProof) = _withdrawal("esc1_conceded");
        esc.validUntil += 1;
        vm.expectRevert(Errors.InvalidProof.selector);
        vault.initiateEscapeWithdrawal(esc, escProof);
        (esc, escProof) = _withdrawal("esc1_conceded");
        esc.nextNullifier += 1;
        vm.expectRevert(Errors.InvalidProof.selector);
        vault.initiateEscapeWithdrawal(esc, escProof);
        assertEq(vault.nullifierState(esc.withdrawalNullifier), 0);

        (esc, escProof) = _withdrawal("esc1");
        vault.initiateEscapeWithdrawal(esc, escProof);
        (Types.RequestPublicInputs memory req2, bytes memory req2Proof) = _request("req2");
        req2.activeRoot = vault.currentRoot() + 1;
        vm.expectRevert(Errors.InvalidProof.selector);
        vault.challengeEscapeWithdrawal(0, req2, req2Proof);
        (Types.RequestPublicInputs memory req1, bytes memory req1Proof) = _request("req1");
        req1.solvencyBound = 900_000;
        vm.expectRevert(Errors.InvalidProof.selector);
        vault.raiseEscapeConcession(0, req1, req1Proof, 900_000);
    }

    function test_realExitProofExpires() public {
        (Types.WithdrawalPublicInputs memory esc, bytes memory escProof) = _withdrawal("esc1");
        vm.warp(uint256(esc.validUntil) + 1);
        vm.expectRevert(Errors.ExitProofExpired.selector);
        vault.initiateEscapeWithdrawal(esc, escProof);
    }

    /// Threat: an indefinite pause; exits reopen with the real proof after MAX_PAUSE_DURATION.
    function test_realEscapeAfterPauseLapses() public {
        (Types.WithdrawalPublicInputs memory esc, bytes memory escProof) = _withdrawal("esc1_conceded");
        vault.pause();
        vm.expectRevert(Errors.Paused.selector);
        vault.initiateEscapeWithdrawal(esc, escProof);
        vm.warp(block.timestamp + vault.MAX_PAUSE_DURATION());
        vault.initiateEscapeWithdrawal(esc, escProof);
        (,,,,,,, uint64 deadline) = vault.pendingWithdrawals(0);
        vm.warp(deadline + 1);
        vault.finalizeEscapeWithdrawal(0);
        assertEq(USER.balance, 800_000 gwei);
    }

    function test_realClaimExpiredAndRetire() public {
        uint256 leaf = _leafOf(0);
        uint64 claimable = vault.claimableAt(0);
        vm.warp(claimable);
        _gas("claimExpired");
        vault.claimExpired(0);
        _gasEnd();
        assertEq(_treasuryPaid(), uint256(DEPOSIT) * 1 gwei);
        assertNotEq(leaf, 0);
        _gas("retireClosedLeaf");
        vault.retireClosedLeaf(0, emptySiblings);
        _gasEnd();
        assertEq(vault.currentRoot(), _emptyRoot());
    }

    function _depositOther(uint32 noteId, bytes32 commitment) private {
        address depositor = address(0xcafe);
        vm.deal(depositor, uint256(DEPOSIT) * 1 gwei);
        uint256[32] memory path = emptySiblings;
        // Notes 0..3 occupy the first four slots.
        uint256[4] memory leaves;
        for (uint32 i = 0; i < noteId; ++i) {
            leaves[i] = _leafOf(i);
        }
        path[0] = leaves[noteId ^ 1];
        uint32 otherPair = (noteId >> 1) ^ 1;
        path[1] = otherPair == 0 && noteId >= 2 ? _node(leaves[0], leaves[1]) : emptySiblings[1];
        vm.prank(depositor);
        vault.deposit{value: uint256(DEPOSIT) * 1 gwei}(commitment, DEPOSIT, path);
    }

    /// @dev Pays whatever the vault accrued for the treasury and returns the treasury's balance.
    function _treasuryPaid() private returns (uint256) {
        if (vault.treasuryAccrued() != 0) {
            _gas("withdrawTreasury");
            vault.withdrawTreasury();
            _gasEnd();
        }
        return TREASURY.balance;
    }

    function _leafOf(uint32 noteId) private view returns (uint256) {
        (bytes32 commitment, uint128 amount, uint64 expiry,,,) = vault.notes(noteId);
        return NoteLeafLib.computeLeaf(noteId, commitment, amount, expiry);
    }

    function _node(uint256 left, uint256 right) private pure returns (uint256) {
        return Bn254Poseidon.hash3(DOMAIN_NODE, left, right);
    }

    function _emptyRoot() private view returns (uint256) {
        return _node(emptySiblings[31], emptySiblings[31]);
    }

    function _request(string memory name) private view returns (Types.RequestPublicInputs memory, bytes memory) {
        return (
            abi.decode(
                vm.parseJsonBytes(fixtures, string.concat(".", name, ".inputs_abi")), (Types.RequestPublicInputs)
            ),
            vm.parseJsonBytes(fixtures, string.concat(".", name, ".proof_hex"))
        );
    }

    function _withdrawal(string memory name) private view returns (Types.WithdrawalPublicInputs memory, bytes memory) {
        return (
            abi.decode(
                vm.parseJsonBytes(fixtures, string.concat(".", name, ".inputs_abi")), (Types.WithdrawalPublicInputs)
            ),
            vm.parseJsonBytes(fixtures, string.concat(".", name, ".proof_hex"))
        );
    }

    string private gasLabel;
    uint256 private gasStart;

    /// @dev Execution gas of the next vault call (excludes the 21k base and calldata cost).
    function _gas(string memory label) private {
        gasLabel = label;
        gasStart = gasleft();
    }

    function _gasEnd() private {
        uint256 left = gasleft();
        uint256 used = gasStart - left;
        emit log_named_uint(string.concat("gas ", gasLabel), used);
    }
}
