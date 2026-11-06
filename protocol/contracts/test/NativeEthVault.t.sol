// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import {Test} from "forge-std/Test.sol";
import {ZkApiVault} from "../src/ZkApiVault.sol";
import {IZkApiProofAdapter} from "../src/interfaces/IZkApiProofAdapter.sol";
import {Types} from "../src/libraries/Types.sol";
import {Errors} from "../src/libraries/Errors.sol";
import {Bn254Poseidon} from "../src/libraries/Bn254Poseidon.sol";
import {Events} from "../src/libraries/Events.sol";

contract NativeProofFixture is IZkApiProofAdapter {
    function assertValidRequest(Types.RequestPublicInputs calldata, bytes calldata) external pure {}
    function assertValidWithdrawal(Types.WithdrawalPublicInputs calldata, bytes calldata) external pure {}
}

contract RejectNativePayout {
    receive() external payable {
        revert();
    }
}

contract ReenterNativePayout {
    ZkApiVault public vault;
    bool public reentered;

    constructor(ZkApiVault target) {
        vault = target;
    }

    receive() external payable {
        (reentered,) = address(vault).call(abi.encodeCall(vault.finalizeEscapeWithdrawal, (0)));
    }
}

/// Refuses ETH until switched on.
contract ToggleNativePayout {
    bool public accepting;

    function setAccepting(bool value) external {
        accepting = value;
    }

    receive() external payable {
        if (!accepting) revert();
    }
}

/// Burns all gas it is given, or (once switched) accepts ETH by writing three fresh slots,
/// which fits within ESCAPE_PAYOUT_GAS but not within a starved call.
contract GasHungryPayout {
    bool public burning = true;
    uint256 public count;
    mapping(uint256 => uint256) public slots;

    function setBurning(bool value) external {
        burning = value;
    }

    receive() external payable {
        if (burning) {
            while (true) {}
        }
        slots[++count] = 1;
        slots[++count] = 1;
    }
}

contract NativeEthVaultTest is Test {
    uint128 constant UNITS = 1_000_000;
    address user = address(0x1234);
    address treasury = address(0x5678);
    ZkApiVault vault;
    NativeProofFixture adapter;
    uint256[32] siblings;

    function setUp() public {
        uint256 zero;
        for (uint256 level; level < 32; ++level) {
            siblings[level] = zero;
            zero = Bn254Poseidon.hash3(0x7a6b6170692e76322e6e6f6465, zero, zero);
        }
        adapter = new NativeProofFixture();
        vault = new ZkApiVault(treasury, 30 days, 24 hours, 100_000, address(adapter), 11, 12, 13, 14, address(this));
        vm.deal(user, 1 ether);
    }

    function deposit() internal {
        vm.prank(user);
        vault.deposit{value: uint256(UNITS) * 1 gwei}(bytes32(uint256(42)), UNITS, siblings);
    }

    function withdrawal(address destination, bool clearance)
        internal
        view
        returns (Types.WithdrawalPublicInputs memory)
    {
        (bytes32 commitment, uint128 amount, uint64 expiryTs,,,) = vault.notes(0);
        return Types.WithdrawalPublicInputs({
            protocolVersion: 2,
            chainId: uint64(block.chainid),
            contractAddress: address(vault),
            registration: uint256(commitment),
            stateSigningKeyX: 11,
            stateSigningKeyY: 12,
            clearanceSigningKeyX: 13,
            clearanceSigningKeyY: 14,
            noteId: 0,
            depositAmount: amount,
            expiryTs: expiryTs,
            finalBalance: 700_000,
            destination: destination,
            withdrawalNullifier: 99,
            hasClearance: clearance,
            nextNullifier: clearance ? 0 : 100,
            conceded: 0,
            validUntil: uint64(block.timestamp + 1 days)
        });
    }

    function test_nativeDepositAndMutualPayout() public {
        uint256 gasBefore = gasleft();
        deposit();
        emit log_named_uint("Native deposit gas (cold fixture account)", gasBefore - gasleft());
        assertEq(address(vault.billingToken()), address(0));
        assertEq(vault.nativeAssetWeiPerUnit(), 1 gwei);
        assertEq(address(vault).balance, uint256(UNITS) * 1 gwei);
        uint256 initial = user.balance;
        vault.mutualClose(withdrawal(user, true), "");
        assertEq(user.balance - initial, 700_000 gwei);
        assertEq(_treasuryPaid(), 300_000 gwei);
        assertEq(address(vault).balance, 0);
        assertTrue(vault.usedNullifiers(99));
    }

    function test_nativeRejectsWrongOrMissingValue() public {
        vm.startPrank(user);
        vm.expectRevert(Errors.InvalidNativeValue.selector);
        vault.deposit(bytes32(uint256(42)), UNITS, siblings);
        vm.expectRevert(Errors.InvalidNativeValue.selector);
        vault.deposit{value: uint256(UNITS) * 1 gwei + 1}(bytes32(uint256(42)), UNITS, siblings);
        vm.stopPrank();
        assertEq(vault.nextNoteId(), 0);
        assertEq(address(vault).balance, 0);
    }

    function test_nativeRejectsUnsafeLedgerAmount() public {
        vm.expectRevert(Errors.InvalidNativeValue.selector);
        vault.deposit(bytes32(uint256(42)), 9_007_199_254_740_992, siblings);
    }

    function test_nativeRejectsInvalidRequestChargeCap() public {
        uint128 unsafeCap = vault.MAX_NATIVE_UNITS() + 1;
        vm.expectRevert(Errors.InvalidBalance.selector);
        new ZkApiVault(treasury, 30 days, 24 hours, 0, address(adapter), 11, 12, 13, 14, address(this));
        vm.expectRevert(Errors.InvalidBalance.selector);
        new ZkApiVault(treasury, 30 days, 24 hours, unsafeCap, address(adapter), 11, 12, 13, 14, address(this));
    }

    function test_rejectedPayoutPreservesNoteAndFunds() public {
        deposit();
        RejectNativePayout recipient = new RejectNativePayout();
        Types.WithdrawalPublicInputs memory inputs = withdrawal(address(recipient), true);
        uint256 root = vault.currentRoot();
        vm.expectRevert(Errors.NativeTransferFailed.selector);
        vault.mutualClose(inputs, "");
        assertEq(vault.currentRoot(), root);
        assertEq(address(vault).balance, uint256(UNITS) * 1 gwei);
        assertFalse(vault.usedNullifiers(99));
        (,,, Types.NoteStatus status,,) = vault.notes(0);
        assertEq(uint256(status), uint256(Types.NoteStatus.Active));
    }

    /// Threat: the owner points the treasury at a contract that refuses ETH to hold payouts hostage.
    function test_rejectingTreasuryDoesNotBlockUserPayout() public {
        deposit();
        vault.setTreasury(address(new RejectNativePayout()));
        uint256 userBalance = user.balance;
        vault.mutualClose(withdrawal(user, true), "");
        assertEq(user.balance - userBalance, 700_000 gwei);
        assertEq(vault.treasuryAccrued(), 300_000);
        assertEq(address(vault).balance, 300_000 gwei);
        vm.expectRevert(Errors.NativeTransferFailed.selector);
        vault.withdrawTreasury();
        assertEq(vault.treasuryAccrued(), 300_000);
        vault.setTreasury(treasury);
        assertEq(_treasuryPaid(), 300_000 gwei);
        assertEq(address(vault).balance, 0);
    }

    /// Threat: a user escapes to a destination that refuses ETH so finalization reverts forever,
    /// locking the operator's share (everything already served) in the vault at the cost of one
    /// gwei unit. The payout is credited instead; the share accrues and the note closes.
    function test_rejectingEscapeDestinationCannotLockOperatorShare() public {
        deposit();
        ToggleNativePayout recipient = new ToggleNativePayout();
        vault.initiateEscapeWithdrawal(withdrawal(address(recipient), false), "");
        (,,,,,,, uint64 deadline) = vault.pendingWithdrawals(0);
        vm.warp(deadline + 1);
        vm.expectEmit(true, true, false, true, address(vault));
        emit Events.EscapePayoutDeferred(0, address(recipient), 700_000);
        vm.prank(address(0xbeef));
        vault.finalizeEscapeWithdrawal(0);
        (,,, Types.NoteStatus status,,) = vault.notes(0);
        assertEq(uint256(status), uint256(Types.NoteStatus.Closed));
        (bool exists,,,,,,,) = vault.pendingWithdrawals(0);
        assertFalse(exists);
        assertEq(vault.escapePayoutCredits(address(recipient)), 700_000);
        assertEq(_treasuryPaid(), 300_000 gwei);
        vm.expectRevert(Errors.NativeTransferFailed.selector);
        vault.claimEscapePayout(address(recipient));
        assertEq(vault.escapePayoutCredits(address(recipient)), 700_000);
        recipient.setAccepting(true);
        vm.expectEmit(true, false, false, true, address(vault));
        emit Events.EscapePayoutClaimed(address(recipient), 700_000);
        vm.prank(address(0xbeef));
        vault.claimEscapePayout(address(recipient));
        assertEq(address(recipient).balance, 700_000 gwei);
        assertEq(vault.escapePayoutCredits(address(recipient)), 0);
        assertEq(address(vault).balance, 0);
        vm.expectRevert(Errors.ZeroAmount.selector);
        vault.claimEscapePayout(address(recipient));
    }

    /// A destination that burns all gas it is given costs at most ESCAPE_PAYOUT_GAS, and a caller
    /// cannot starve an accepting destination into a credit: every gas limit pays it or reverts.
    function test_escapePayoutGasIsBoundedAndCannotBeStarved() public {
        deposit();
        GasHungryPayout recipient = new GasHungryPayout();
        vault.initiateEscapeWithdrawal(withdrawal(address(recipient), false), "");
        (,,,,,,, uint64 deadline) = vault.pendingWithdrawals(0);
        vm.warp(deadline + 1);
        bytes memory finalize = abi.encodeCall(vault.finalizeEscapeWithdrawal, (0));
        uint256 snapshot = vm.snapshotState();
        // 5M gas offered; an uncapped push would burn 63/64 of it.
        uint256 before = gasleft();
        vault.finalizeEscapeWithdrawal{gas: 5_000_000}(0);
        assertLt(before - gasleft(), vault.ESCAPE_PAYOUT_GAS() + 150_000);
        assertEq(vault.escapePayoutCredits(address(recipient)), 700_000);
        vm.revertToState(snapshot);
        recipient.setBurning(false);
        snapshot = vm.snapshotState();
        uint256 paid;
        uint256 reverted;
        for (uint256 limit = 30_000; limit <= 400_000; limit += 5_000) {
            (bool ok,) = address(vault).call{gas: limit}(finalize);
            assertEq(vault.escapePayoutCredits(address(recipient)), 0);
            (,,, Types.NoteStatus status,,) = vault.notes(0);
            if (ok) {
                ++paid;
                assertEq(address(recipient).balance, 700_000 gwei);
            } else {
                ++reverted;
                assertEq(uint256(status), uint256(Types.NoteStatus.PendingWithdrawal));
            }
            vm.revertToState(snapshot);
        }
        assertGt(paid, 0);
        assertGt(reverted, 0);
    }

    function test_nativeEscapeAndReentrancyGuard() public {
        deposit();
        ReenterNativePayout recipient = new ReenterNativePayout(vault);
        vault.initiateEscapeWithdrawal(withdrawal(address(recipient), false), "");
        (bool exists,,,,,,, uint64 deadline) = vault.pendingWithdrawals(0);
        assertTrue(exists);
        vm.warp(deadline + 1);
        vault.finalizeEscapeWithdrawal(0);
        assertFalse(recipient.reentered());
        assertEq(address(recipient).balance, 700_000 gwei);
        assertEq(_treasuryPaid(), 300_000 gwei);
    }

    function test_nativeExpiryPayout() public {
        deposit();
        (,, uint64 expiry,,,) = vault.notes(0);
        vm.warp(expiry);
        vault.claimExpired(0);
        assertEq(_treasuryPaid(), uint256(UNITS) * 1 gwei);
        assertEq(address(vault).balance, 0);
    }

    /// @dev Pays whatever the vault accrued for the treasury and returns the treasury's balance.
    function _treasuryPaid() internal returns (uint256) {
        if (vault.treasuryAccrued() != 0) vault.withdrawTreasury();
        return treasury.balance;
    }
}
