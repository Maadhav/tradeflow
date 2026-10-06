// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {TestStablecoin} from "../src/TestStablecoin.sol";
import {LoanNotes} from "../src/LoanNotes.sol";
import {TradeflowMarket} from "../src/TradeflowMarket.sol";

contract TradeflowMarketTest is Test {
    TestStablecoin usdc;
    LoanNotes notes;
    TradeflowMarket market;

    address forwarder = makeAddr("forwarder");
    address settlement = makeAddr("offramp");
    address borrower = makeAddr("borrower");
    address ben = makeAddr("ben"); // crypto lender
    address ana = makeAddr("ana"); // fiat lender (platform-held wallet)

    function setUp() public {
        usdc = new TestStablecoin("Test USD Coin", "tUSDC");
        notes = new LoanNotes("https://tradeflow.example/notes/{id}.json");
        market = new TradeflowMarket(forwarder, usdc, notes, settlement);
        notes.setMarket(address(market));
        usdc.setMinter(address(this), true);
        usdc.mint(ben, 100_000e6);
    }

    function _report(TradeflowMarket.Action action, bytes memory payload) internal {
        vm.prank(forwarder);
        market.onReport("", abi.encode(uint8(action), payload));
    }

    function _list(uint256 target) internal returns (uint256) {
        _report(
            TradeflowMarket.Action.ListLoan,
            abi.encode(
                borrower, uint8(0), uint8(2), bytes3("EUR"), uint32(1500), uint32(60),
                uint256(9_250_000), uint256(108_000_000), target, keccak256("doc-1"), "INV-2026-0142"
            )
        );
        return market.loanCount();
    }

    function test_fullLifecycle_cryptoAndFiatLenders() public {
        uint256 id = _list(10_000e6);

        // KYC for Ben via CRE, then Ben funds 6,000 with stablecoins.
        _report(TradeflowMarket.Action.VerifyLender, abi.encode(ben, true, keccak256("kyc-ben")));
        vm.startPrank(ben);
        usdc.approve(address(market), type(uint256).max);
        market.fund(id, 6_000e6);
        vm.stopPrank();

        // Ana pays 4,000 by bank transfer; the on-ramp mints into the market, then CRE credits it.
        usdc.mint(address(market), 4_000e6);
        assertEq(market.unallocated(), 4_000e6);
        _report(TradeflowMarket.Action.FiatFunding, abi.encode(id, ana, uint256(4_000e6), keccak256("dep-1")));
        assertEq(notes.balanceOf(ana, id), 4_000e6);
        assertEq(uint8(market.getLoan(id).status), uint8(TradeflowMarket.Status.Funded));

        // CRE confirms the fiat payout to the business; stablecoins go to the off-ramp.
        _report(TradeflowMarket.Action.Disbursed, abi.encode(id, keccak256("payout-1")));
        assertEq(usdc.balanceOf(settlement), 10_000e6);

        // Buyer pays 10,250; on-ramped into the market; CRE confirms with two sources.
        usdc.mint(address(market), 10_250e6);
        _report(TradeflowMarket.Action.Repaid, abi.encode(id, uint256(10_250e6), keccak256("pay-1")));

        // Ben claims onchain; Ana is redeemed to her bank through the off-ramp.
        vm.prank(ben);
        market.claim(id);
        assertEq(usdc.balanceOf(ben), 100_000e6 - 6_000e6 + 6_150e6);
        _report(TradeflowMarket.Action.FiatRedeemed, abi.encode(id, ana, keccak256("redeem-ana")));
        assertEq(usdc.balanceOf(settlement), 10_000e6 + 4_100e6);
        assertEq(market.reserved(), 0);
        assertEq(notes.totalSupply(id), 0);
    }

    function test_unverifiedLenderCannotFund() public {
        uint256 id = _list(1_000e6);
        vm.startPrank(ben);
        usdc.approve(address(market), type(uint256).max);
        vm.expectRevert(abi.encodeWithSelector(TradeflowMarket.NotVerified.selector, ben));
        market.fund(id, 500e6);
        vm.stopPrank();
    }

    function test_fiatFundingNeedsOnRampedFunds() public {
        uint256 id = _list(1_000e6);
        vm.prank(forwarder);
        vm.expectRevert(abi.encodeWithSelector(TradeflowMarket.InsufficientUnallocated.selector, 0, 500e6));
        market.onReport("", abi.encode(uint8(TradeflowMarket.Action.FiatFunding), abi.encode(id, ana, uint256(500e6), keccak256("dep-x"))));
    }

    function test_reconciliationMismatchPausesFunding() public {
        uint256 id = _list(1_000e6);
        _report(TradeflowMarket.Action.VerifyLender, abi.encode(ben, true, keccak256("kyc-ben")));
        _report(TradeflowMarket.Action.Reconciliation, abi.encode(false, uint256(1), uint256(2), uint256(3), keccak256("snap")));
        assertTrue(market.fundingPaused());
        vm.startPrank(ben);
        usdc.approve(address(market), type(uint256).max);
        vm.expectRevert(TradeflowMarket.FundingIsPaused.selector);
        market.fund(id, 100e6);
        vm.stopPrank();
    }

    function test_lateLoanFreezesBorrower() public {
        uint256 id = _list(1_000e6);
        _report(TradeflowMarket.Action.VerifyLender, abi.encode(ben, true, keccak256("kyc-ben")));
        vm.startPrank(ben);
        usdc.approve(address(market), type(uint256).max);
        market.fund(id, 1_000e6);
        vm.stopPrank();
        _report(TradeflowMarket.Action.Disbursed, abi.encode(id, keccak256("payout-2")));
        _report(TradeflowMarket.Action.LoanStatus, abi.encode(id, uint8(TradeflowMarket.Status.Late), true));
        assertTrue(market.frozenBorrower(borrower));
        // A frozen business cannot list again.
        vm.prank(forwarder);
        vm.expectRevert(abi.encodeWithSelector(TradeflowMarket.Frozen.selector, borrower));
        market.onReport(
            "",
            abi.encode(
                uint8(TradeflowMarket.Action.ListLoan),
                abi.encode(borrower, uint8(0), uint8(2), bytes3("EUR"), uint32(1500), uint32(60), uint256(1), uint256(1), uint256(1e6), keccak256("doc-2"), "INV-2")
            )
        );
    }

    function test_policyRejectsBadGrade() public {
        vm.prank(forwarder);
        vm.expectRevert(abi.encodeWithSelector(TradeflowMarket.PolicyRejected.selector, uint8(5), uint32(1500)));
        market.onReport(
            "",
            abi.encode(
                uint8(TradeflowMarket.Action.ListLoan),
                abi.encode(borrower, uint8(0), uint8(5), bytes3("EUR"), uint32(1500), uint32(60), uint256(1), uint256(1), uint256(1e6), keccak256("doc-3"), "INV-3")
            )
        );
    }

    function test_onlyForwarderCanReport() public {
        vm.expectRevert();
        market.onReport("", abi.encode(uint8(1), bytes("")));
    }

    function test_notesOnlyMoveBetweenVerifiedHolders() public {
        uint256 id = _list(1_000e6);
        _report(TradeflowMarket.Action.VerifyLender, abi.encode(ben, true, keccak256("kyc-ben")));
        vm.startPrank(ben);
        usdc.approve(address(market), type(uint256).max);
        market.fund(id, 500e6);
        address stranger = makeAddr("stranger");
        vm.expectRevert(abi.encodeWithSelector(LoanNotes.UnverifiedHolder.selector, stranger));
        notes.safeTransferFrom(ben, stranger, id, 100e6, "");
        vm.stopPrank();
    }
}
