// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test, Vm} from "forge-std/Test.sol";
import {IToken} from "@tokenysolutions/t-rex/contracts/token/IToken.sol";
import {IIdentityRegistry} from "@tokenysolutions/t-rex/contracts/registry/interface/IIdentityRegistry.sol";
import {IModularCompliance} from "@tokenysolutions/t-rex/contracts/compliance/modular/IModularCompliance.sol";
import {AgentRoleUpgradeable} from "@tokenysolutions/t-rex/contracts/roles/AgentRoleUpgradeable.sol";
import {IIdentity} from "@onchain-id/solidity/contracts/interface/IIdentity.sol";
import {IdentityProxy} from "@onchain-id/solidity/contracts/proxy/IdentityProxy.sol";
import {TestStablecoin} from "../src/TestStablecoin.sol";
import {CreClaimIssuer} from "../src/CreClaimIssuer.sol";
import {TradeflowMarket} from "../src/TradeflowMarket.sol";
import {TradeflowDeployer, Deployment} from "../script/Deploy.s.sol";

contract TradeflowMarketTest is Test, TradeflowDeployer {
    TestStablecoin usdc;
    TradeflowMarket market;
    IIdentityRegistry registry;
    CreClaimIssuer issuer;
    address identityAuthority;

    address forwarder = makeAddr("forwarder");
    address settlement = makeAddr("offramp");
    address borrower = makeAddr("borrower");
    address ben = makeAddr("ben"); // crypto lender
    address cara = makeAddr("cara"); // second crypto lender
    address ana = makeAddr("ana"); // fiat lender (platform-held wallet)
    address stranger = makeAddr("stranger"); // never KYC-verified

    uint16 constant US = 840;
    uint16 constant DE = 276;

    function setUp() public {
        Deployment memory d = _deployTradeflow(forwarder, settlement, address(this));
        usdc = d.stablecoin;
        market = d.market;
        registry = d.identityRegistry;
        issuer = d.claimIssuer;
        identityAuthority = d.identityAuthority;
        usdc.setMinter(address(this), true);
        usdc.mint(ben, 100_000e6);
        usdc.mint(cara, 100_000e6);
        usdc.mint(stranger, 100_000e6);
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
                uint256(9_250_000), uint256(108_000_000), target, keccak256(abi.encode("doc", market.loanCount())), "INV-2026-0142"
            )
        );
        return market.loanCount();
    }

    function _kyc(address lender, bool verified, uint16 country) internal {
        _report(TradeflowMarket.Action.VerifyLender, abi.encode(lender, verified, keccak256(abi.encode("kyc", lender)), country));
    }

    function _fund(address lender, uint256 id, uint256 amount) internal {
        vm.startPrank(lender);
        usdc.approve(address(market), type(uint256).max);
        market.fund(id, amount);
        vm.stopPrank();
    }

    function _token(uint256 id) internal view returns (IToken) {
        return IToken(market.loanToken(id));
    }

    // ---------------------------------------------------------------------
    // Lifecycle (existing behaviour, now on ERC-3643 notes)
    // ---------------------------------------------------------------------

    function test_fullLifecycle_cryptoAndFiatLenders() public {
        uint256 id = _list(10_000e6);
        IToken note = _token(id);

        // KYC for Ben via CRE, then Ben funds 6,000 with stablecoins.
        _kyc(ben, true, US);
        _fund(ben, id, 6_000e6);

        // Ana pays 4,000 by bank transfer; CRE verified her KYC first; the on-ramp mints into the
        // market, then CRE credits it.
        _kyc(ana, true, DE);
        usdc.mint(address(market), 4_000e6);
        assertEq(market.unallocated(), 4_000e6);
        _report(TradeflowMarket.Action.FiatFunding, abi.encode(id, ana, uint256(4_000e6), keccak256("dep-1")));
        assertEq(note.balanceOf(ana), 4_000e6);
        assertEq(note.totalSupply(), 10_000e6);
        assertEq(uint8(market.getLoan(id).status), uint8(TradeflowMarket.Status.Funded));

        // CRE confirms the fiat payout to the business; stablecoins go to the off-ramp.
        _report(TradeflowMarket.Action.Disbursed, abi.encode(id, keccak256("payout-1")));
        assertEq(usdc.balanceOf(settlement), 10_000e6);

        // Buyer pays 10,250; on-ramped into the market; CRE confirms with two sources.
        usdc.mint(address(market), 10_250e6);
        _report(TradeflowMarket.Action.Repaid, abi.encode(id, uint256(10_250e6), keccak256("pay-1")));

        // Ben claims onchain; Ana is redeemed to her bank through the off-ramp. Both burn notes.
        vm.prank(ben);
        market.claim(id);
        assertEq(usdc.balanceOf(ben), 100_000e6 - 6_000e6 + 6_150e6);
        assertEq(note.balanceOf(ben), 0);
        _report(TradeflowMarket.Action.FiatRedeemed, abi.encode(id, ana, keccak256("redeem-ana")));
        assertEq(note.balanceOf(ana), 0);
        assertEq(usdc.balanceOf(settlement), 10_000e6 + 4_100e6);
        assertEq(market.reserved(), 0);
        assertEq(note.totalSupply(), 0);
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
        _kyc(ana, true, DE);
        vm.prank(forwarder);
        vm.expectRevert(abi.encodeWithSelector(TradeflowMarket.InsufficientUnallocated.selector, 0, 500e6));
        market.onReport("", abi.encode(uint8(TradeflowMarket.Action.FiatFunding), abi.encode(id, ana, uint256(500e6), keccak256("dep-x"))));
    }

    function test_fiatFundingNeedsVerifiedLender() public {
        uint256 id = _list(1_000e6);
        usdc.mint(address(market), 500e6);
        vm.prank(forwarder);
        vm.expectRevert(abi.encodeWithSelector(TradeflowMarket.NotVerified.selector, ana));
        market.onReport("", abi.encode(uint8(TradeflowMarket.Action.FiatFunding), abi.encode(id, ana, uint256(500e6), keccak256("dep-y"))));
    }

    function test_reconciliationMismatchPausesFunding() public {
        uint256 id = _list(1_000e6);
        _kyc(ben, true, US);
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
        _kyc(ben, true, US);
        _fund(ben, id, 1_000e6);
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

    // ---------------------------------------------------------------------
    // ERC-3643 token per loan
    // ---------------------------------------------------------------------

    function test_listingDeploysCompliantErc3643Token() public {
        vm.recordLogs();
        uint256 id = _list(1_000e6);
        address tokenAddr = market.loanToken(id);
        assertTrue(tokenAddr != address(0));

        // LoanTokenDeployed(loanId, token) was emitted with the stored address.
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool seen;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].emitter == address(market) && logs[i].topics[0] == TradeflowMarket.LoanTokenDeployed.selector) {
                assertEq(uint256(logs[i].topics[1]), id);
                assertEq(abi.decode(logs[i].data, (address)), tokenAddr);
                seen = true;
            }
        }
        assertTrue(seen);

        IToken note = IToken(tokenAddr);
        assertEq(note.name(), "Tradeflow Loan Note 1");
        assertEq(note.symbol(), "TFN1");
        assertEq(note.decimals(), 6);
        assertEq(note.totalSupply(), 0);
        assertFalse(note.paused());
        assertEq(address(note.identityRegistry()), address(registry));
        assertEq(address(registry), address(market.identityRegistry()));

        // The compliance is a ModularCompliance proxy bound to this token, with no modules.
        IModularCompliance compliance = note.compliance();
        assertEq(compliance.getTokenBound(), tokenAddr);
        assertEq(compliance.getModules().length, 0);

        // The market owns the token and is its agent.
        assertTrue(AgentRoleUpgradeable(tokenAddr).isAgent(address(market)));
        assertEq(AgentRoleUpgradeable(tokenAddr).owner(), address(market));

        // Each loan gets its own token.
        uint256 id2 = _list(2_000e6);
        assertTrue(market.loanToken(id2) != tokenAddr);
        assertEq(_token(id2).symbol(), "TFN2");
    }

    function test_tokenRefusesToMintToUnverifiedWallet() public {
        uint256 id = _list(1_000e6);
        IToken note = _token(id);
        // Even the market, the token's agent, cannot mint to a wallet the registry does not verify.
        vm.prank(address(market));
        vm.expectRevert("Identity is not verified.");
        note.mint(stranger, 1e6);
        // And through the market the stranger cannot fund.
        vm.startPrank(stranger);
        usdc.approve(address(market), type(uint256).max);
        vm.expectRevert(abi.encodeWithSelector(TradeflowMarket.NotVerified.selector, stranger));
        market.fund(id, 1e6);
        vm.stopPrank();
    }

    function test_unverifiedWalletCannotReceiveTransfer() public {
        uint256 id = _list(1_000e6);
        _kyc(ben, true, US);
        _fund(ben, id, 500e6);
        IToken note = _token(id);
        vm.prank(ben);
        vm.expectRevert("Transfer not possible");
        note.transfer(stranger, 100e6);
        // transferFrom is held to the same rule.
        vm.prank(ben);
        note.approve(stranger, 100e6);
        vm.prank(stranger);
        vm.expectRevert("Transfer not possible");
        note.transferFrom(ben, stranger, 100e6);
    }

    function test_verifiedLenderFundsAndTransfersToVerifiedLender() public {
        uint256 id = _list(1_000e6);
        _kyc(ben, true, US);
        _kyc(cara, true, DE);
        _fund(ben, id, 500e6);
        IToken note = _token(id);
        assertEq(note.balanceOf(ben), 500e6);

        vm.prank(ben);
        assertTrue(note.transfer(cara, 200e6));
        assertEq(note.balanceOf(ben), 300e6);
        assertEq(note.balanceOf(cara), 200e6);

        // Cara can also fund directly and later claims her share pro rata.
        _fund(cara, id, 500e6);
        _report(TradeflowMarket.Action.Disbursed, abi.encode(id, keccak256("payout-3")));
        usdc.mint(address(market), 1_025e6);
        _report(TradeflowMarket.Action.Repaid, abi.encode(id, uint256(1_025e6), keccak256("pay-3")));
        uint256 before = usdc.balanceOf(cara);
        vm.prank(cara);
        market.claim(id);
        assertEq(usdc.balanceOf(cara) - before, 717_500_000); // 700 notes of 1,000, of 1,025 repaid
        assertEq(note.balanceOf(cara), 0);
        assertEq(note.totalSupply(), 300e6);
    }

    // ---------------------------------------------------------------------
    // CRE KYC -> ONCHAINID identity, claim and registry
    // ---------------------------------------------------------------------

    function test_verifyLenderRegistersIdentityWithCreClaim() public {
        bytes32 kycRef = keccak256(abi.encode("kyc", ben));
        vm.recordLogs();
        _kyc(ben, true, US);
        IIdentity identity = registry.identity(ben);
        assertTrue(address(identity) != address(0));
        assertTrue(registry.contains(ben));
        assertTrue(registry.isVerified(ben));
        assertEq(registry.investorCountry(ben), US);

        // IdentityRegistered(lender, identity, country) and LenderVerified were emitted.
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool registered;
        bool verifiedLog;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].emitter != address(market)) continue;
            if (logs[i].topics[0] == TradeflowMarket.IdentityRegistered.selector) {
                assertEq(address(uint160(uint256(logs[i].topics[1]))), ben);
                (address id_, uint16 country) = abi.decode(logs[i].data, (address, uint16));
                assertEq(id_, address(identity));
                assertEq(country, US);
                registered = true;
            }
            if (logs[i].topics[0] == TradeflowMarket.LenderVerified.selector) verifiedLog = true;
        }
        assertTrue(registered && verifiedLog);

        // The identity is a proxy managed by the market and carries the KYC claim from CreClaimIssuer.
        assertTrue(identity.keyHasPurpose(keccak256(abi.encode(address(market))), 1));
        (uint256 topic, uint256 scheme, address claimIssuer_, bytes memory sig, bytes memory data,) =
            identity.getClaim(keccak256(abi.encode(address(issuer), uint256(1))));
        assertEq(topic, 1);
        assertEq(scheme, 3);
        assertEq(claimIssuer_, address(issuer));
        assertEq(sig.length, 0);
        assertEq(data, abi.encode(kycRef));
        assertTrue(issuer.isClaimValid(identity, 1, sig, data));
        assertFalse(issuer.isClaimValid(identity, 1, sig, abi.encode(bytes32("other"))));

        // A second verification reuses the identity and updates the country.
        _kyc(ben, true, DE);
        assertEq(address(registry.identity(ben)), address(identity));
        assertEq(registry.investorCountry(ben), DE);
        assertTrue(registry.isVerified(ben));
    }

    function test_revokingKycBlocksFundingAndTransfers() public {
        uint256 id = _list(1_000e6);
        _kyc(ben, true, US);
        _kyc(cara, true, DE);
        _fund(ben, id, 400e6);
        IToken note = _token(id);
        IIdentity caraIdentity = registry.identity(cara);

        // CRE withdraws Cara's KYC: the claim is revoked, the registry stops verifying her.
        _kyc(cara, false, DE);
        assertFalse(registry.isVerified(cara));
        assertFalse(issuer.isClaimValid(caraIdentity, 1, "", abi.encode(keccak256(abi.encode("kyc", cara)))));
        vm.prank(ben);
        vm.expectRevert("Transfer not possible");
        note.transfer(cara, 100e6);
        vm.startPrank(cara);
        usdc.approve(address(market), type(uint256).max);
        vm.expectRevert(abi.encodeWithSelector(TradeflowMarket.NotVerified.selector, cara));
        market.fund(id, 100e6);
        vm.stopPrank();

        // Revoking again is a no-op, not a stuck report.
        _kyc(cara, false, DE);

        // Revoking Ben blocks his further funding too.
        _kyc(ben, false, US);
        vm.prank(ben);
        vm.expectRevert(abi.encodeWithSelector(TradeflowMarket.NotVerified.selector, ben));
        market.fund(id, 100e6);

        // A new CRE KYC report restores Cara on the same identity.
        _kyc(cara, true, DE);
        assertEq(address(registry.identity(cara)), address(caraIdentity));
        assertTrue(registry.isVerified(cara));
        vm.prank(ben);
        note.transfer(cara, 100e6);
        assertEq(note.balanceOf(cara), 100e6);
    }

    function test_revokingUnknownLenderIsNoop() public {
        _kyc(stranger, false, US);
        assertFalse(registry.contains(stranger));
        assertFalse(registry.isVerified(stranger));
    }

    function test_onlyMarketRecordsOrRevokesClaims() public {
        _kyc(ben, true, US);
        address benIdentity = address(registry.identity(ben));
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(CreClaimIssuer.OnlyMarket.selector, stranger));
        issuer.recordClaim(benIdentity, 1, "x");
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(CreClaimIssuer.OnlyMarket.selector, stranger));
        issuer.revokeClaim(keccak256(abi.encode(address(issuer), uint256(1))), benIdentity);
        // Not even the issuer's management key (the operator) can record claims.
        vm.expectRevert(abi.encodeWithSelector(CreClaimIssuer.OnlyMarket.selector, address(this)));
        issuer.recordClaim(benIdentity, 1, "x");
        vm.expectRevert(CreClaimIssuer.MarketAlreadySet.selector);
        issuer.setMarket(stranger);
        vm.expectRevert(CreClaimIssuer.NoSignatures.selector);
        issuer.revokeClaimBySignature("");
    }

    function test_selfMadeIdentityCannotForgeCreClaim() public {
        // A stranger deploys their own ONCHAINID and tries to attach a KYC claim "from" CreClaimIssuer.
        vm.startPrank(stranger);
        IIdentity fake = IIdentity(address(new IdentityProxy(identityAuthority, stranger)));
        vm.expectRevert("invalid claim");
        fake.addClaim(1, 3, address(issuer), "", abi.encode(bytes32("kyc")), "");
        vm.stopPrank();
        assertFalse(issuer.isClaimValid(fake, 1, "", abi.encode(bytes32("kyc"))));
    }

    // ---------------------------------------------------------------------
    // Delinquency pauses the loan's notes
    // ---------------------------------------------------------------------

    function test_latePausesTokenAndRepaidUnpauses() public {
        uint256 id = _list(1_000e6);
        _kyc(ben, true, US);
        _kyc(cara, true, DE);
        _fund(ben, id, 1_000e6);
        _report(TradeflowMarket.Action.Disbursed, abi.encode(id, keccak256("payout-4")));
        IToken note = _token(id);
        assertFalse(note.paused());

        _report(TradeflowMarket.Action.LoanStatus, abi.encode(id, uint8(TradeflowMarket.Status.Late), false));
        assertTrue(note.paused());
        vm.prank(ben);
        vm.expectRevert("Pausable: paused");
        note.transfer(cara, 100e6);
        // A second Late report does not fail on the already paused token.
        _report(TradeflowMarket.Action.LoanStatus, abi.encode(id, uint8(TradeflowMarket.Status.Late), false));
        assertTrue(note.paused());

        usdc.mint(address(market), 1_025e6);
        _report(TradeflowMarket.Action.Repaid, abi.encode(id, uint256(1_025e6), keccak256("pay-4")));
        assertFalse(note.paused());
        vm.prank(ben);
        note.transfer(cara, 100e6);
        assertEq(note.balanceOf(cara), 100e6);
    }

    function test_defaultKeepsTokenPaused() public {
        uint256 id = _list(1_000e6);
        _kyc(ben, true, US);
        _fund(ben, id, 1_000e6);
        _report(TradeflowMarket.Action.Disbursed, abi.encode(id, keccak256("payout-5")));
        _report(TradeflowMarket.Action.LoanStatus, abi.encode(id, uint8(TradeflowMarket.Status.Late), true));
        _report(TradeflowMarket.Action.LoanStatus, abi.encode(id, uint8(TradeflowMarket.Status.Defaulted), true));
        assertTrue(_token(id).paused());
        assertEq(uint8(market.getLoan(id).status), uint8(TradeflowMarket.Status.Defaulted));
    }

    function test_claimBurnsNotes() public {
        uint256 id = _list(1_000e6);
        _kyc(ben, true, US);
        _fund(ben, id, 1_000e6);
        _report(TradeflowMarket.Action.Disbursed, abi.encode(id, keccak256("payout-6")));
        usdc.mint(address(market), 1_025e6);
        _report(TradeflowMarket.Action.Repaid, abi.encode(id, uint256(1_025e6), keccak256("pay-6")));
        IToken note = _token(id);
        assertEq(note.balanceOf(ben), 1_000e6);

        vm.recordLogs();
        vm.prank(ben);
        market.claim(id);
        assertEq(note.balanceOf(ben), 0);
        assertEq(note.totalSupply(), 0);
        // The burn shows up as an ERC-20 Transfer to the zero address.
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool burned;
        for (uint256 i = 0; i < logs.length; i++) {
            if (
                logs[i].emitter == address(note) && logs[i].topics[0] == keccak256("Transfer(address,address,uint256)")
                    && logs[i].topics[2] == bytes32(0)
            ) burned = abi.decode(logs[i].data, (uint256)) == 1_000e6;
        }
        assertTrue(burned);
        vm.prank(ben);
        vm.expectRevert(TradeflowMarket.NothingToClaim.selector);
        market.claim(id);
    }
}
