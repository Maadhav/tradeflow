// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {ReceiverTemplate} from "./cre/ReceiverTemplate.sol";
import {LoanNotes} from "./LoanNotes.sol";

/// @title TradeflowMarket
/// @notice Credit marketplace for real-world business financing (invoices, bills of lading,
///         equipment). Every state change that depends on off-chain truth arrives as a signed
///         Chainlink CRE report through the forwarder:
///           - listing after document verification and confidential credit grading
///           - lender KYC (allowlist for the notes)
///           - fiat funding after the deposit is verified and on-ramped
///           - disbursement after the fiat payout to the business is confirmed
///           - repayment after two independent sources confirm the buyer paid
///           - fiat redemption for lenders who funded by bank transfer
///           - late/default status and the three-way reconciliation circuit breaker
///         Lenders who hold stablecoins fund and claim directly onchain.
contract TradeflowMarket is ReceiverTemplate, ReentrancyGuard {
    using SafeERC20 for IERC20;

    enum Status {
        None,
        Listed,
        Funded,
        Disbursed,
        Repaid,
        Late,
        Defaulted
    }

    enum Action {
        None,
        ListLoan,
        VerifyLender,
        FiatFunding,
        Disbursed,
        Repaid,
        FiatRedeemed,
        LoanStatus,
        Reconciliation
    }

    struct Loan {
        address borrower;
        uint8 assetType; // 0 invoice, 1 bill of lading, 2 equipment, 3 working capital
        uint8 riskGrade; // 1 = A (best) ... 5 = E
        bytes3 currency; // currency of the underlying document, e.g. "EUR"
        Status status;
        uint32 aprBps;
        uint32 tenorDays;
        uint64 listedAt;
        uint64 fundedAt;
        uint64 disbursedAt;
        uint64 maturity;
        uint64 repaidAt;
        uint256 faceValueMinor; // document value in its currency, 2 decimals
        uint256 fxRateE8; // currency -> USD rate used at listing (Chainlink Data Feed)
        uint256 target; // funding target in stablecoin units (6 decimals)
        uint256 funded;
        uint256 fiatFunded;
        uint256 repaidAmount; // principal + interest received (6 decimals)
        bytes32 docHash; // hash of the verified document set
        string ref; // public reference, e.g. "INV-2026-0142"
    }

    struct Reconciliation {
        bool ok;
        uint64 at;
        uint256 fiatReceived;
        uint256 stablecoinsHeld;
        uint256 notesOutstanding;
        bytes32 snapshotHash;
    }

    IERC20 public immutable stablecoin;
    LoanNotes public immutable notes;

    address public settlementAccount; // off-ramp operator that pays fiat out
    uint8 public maxRiskGrade = 4; // owner policy: grades worse than this are never listed
    uint32 public maxAprBps = 3000; // owner policy cap
    bool public fundingPaused;
    uint32 public secondsPerDay = 1 days; // demo deployments may accelerate time (e.g. 60s = 1 day)

    uint256 public loanCount;
    uint256 public reserved; // stablecoins owed to loans or lenders, held by this contract
    uint256 public totalFiatIn; // stablecoins credited from verified fiat deposits

    mapping(uint256 => Loan) private s_loans;
    mapping(address => bool) public frozenBorrower;
    mapping(bytes32 => bool) public usedRef; // deposit, payout and payment references (replay guard)
    Reconciliation public lastReconciliation;

    event LoanListed(
        uint256 indexed loanId,
        address indexed borrower,
        string ref,
        uint256 target,
        uint32 aprBps,
        uint32 tenorDays,
        uint8 riskGrade,
        bytes32 docHash
    );
    event LenderVerified(address indexed lender, bool verified, bytes32 kycRef);
    event Funded(uint256 indexed loanId, address indexed lender, uint256 amount, bool viaFiat, bytes32 ref);
    event LoanFullyFunded(uint256 indexed loanId, address indexed borrower, uint256 amount);
    event Disbursed(uint256 indexed loanId, uint256 amount, bytes32 payoutRef, uint64 maturity);
    event Repaid(uint256 indexed loanId, uint256 amount, bytes32 paymentRef);
    event Claimed(uint256 indexed loanId, address indexed lender, uint256 notesBurned, uint256 payout);
    event FiatRedeemed(uint256 indexed loanId, address indexed lender, uint256 payout, bytes32 payoutRef);
    event StatusChanged(uint256 indexed loanId, Status status);
    event BorrowerFrozen(address indexed borrower, uint256 indexed loanId);
    event Reconciled(bool ok, uint256 fiatReceived, uint256 stablecoinsHeld, uint256 notesOutstanding, bytes32 snapshotHash);
    event FundingPaused(bool paused);
    event SettlementAccountSet(address indexed account);
    event PolicySet(uint8 maxRiskGrade, uint32 maxAprBps);
    event ClockSet(uint32 secondsPerDay);

    error UnknownAction(uint8 action);
    error BadStatus(uint256 loanId, Status status);
    error FundingIsPaused();
    error Frozen(address borrower);
    error PolicyRejected(uint8 riskGrade, uint32 aprBps);
    error NotVerified(address lender);
    error OverTarget(uint256 remaining);
    error RefUsed(bytes32 ref);
    error InsufficientUnallocated(uint256 available, uint256 needed);
    error NothingToClaim();
    error ZeroAmount();
    error NoSettlementAccount();

    constructor(address forwarder, IERC20 stablecoin_, LoanNotes notes_, address settlementAccount_)
        ReceiverTemplate(forwarder)
    {
        stablecoin = stablecoin_;
        notes = notes_;
        settlementAccount = settlementAccount_;
        emit SettlementAccountSet(settlementAccount_);
    }

    // ---------------------------------------------------------------------
    // Lender actions (stablecoin holders)
    // ---------------------------------------------------------------------

    /// @notice Fund a listed loan with stablecoins. The lender must be KYC-verified by CRE.
    function fund(uint256 loanId, uint256 amount) external nonReentrant {
        if (!notes.isVerifiedHolder(msg.sender)) revert NotVerified(msg.sender);
        stablecoin.safeTransferFrom(msg.sender, address(this), amount);
        _fund(loanId, msg.sender, amount, false, bytes32(0));
    }

    /// @notice Claim principal plus interest after the loan is repaid.
    function claim(uint256 loanId) external nonReentrant {
        uint256 payout = _redeem(loanId, msg.sender);
        stablecoin.safeTransfer(msg.sender, payout);
    }

    // ---------------------------------------------------------------------
    // CRE reports
    // ---------------------------------------------------------------------

    function _processReport(bytes calldata report) internal override {
        (uint8 action, bytes memory payload) = abi.decode(report, (uint8, bytes));
        if (action == uint8(Action.ListLoan)) _listLoan(payload);
        else if (action == uint8(Action.VerifyLender)) _verifyLender(payload);
        else if (action == uint8(Action.FiatFunding)) _fiatFunding(payload);
        else if (action == uint8(Action.Disbursed)) _disbursed(payload);
        else if (action == uint8(Action.Repaid)) _repaid(payload);
        else if (action == uint8(Action.FiatRedeemed)) _fiatRedeemed(payload);
        else if (action == uint8(Action.LoanStatus)) _loanStatus(payload);
        else if (action == uint8(Action.Reconciliation)) _reconciliation(payload);
        else revert UnknownAction(action);
    }

    function _listLoan(bytes memory payload) internal {
        (
            address borrower,
            uint8 assetType,
            uint8 riskGrade,
            bytes3 currency,
            uint32 aprBps,
            uint32 tenorDays,
            uint256 faceValueMinor,
            uint256 fxRateE8,
            uint256 target,
            bytes32 docHash,
            string memory ref
        ) = abi.decode(payload, (address, uint8, uint8, bytes3, uint32, uint32, uint256, uint256, uint256, bytes32, string));

        if (frozenBorrower[borrower]) revert Frozen(borrower);
        // Policy is enforced onchain, never trusted from the report.
        if (riskGrade == 0 || riskGrade > maxRiskGrade || aprBps == 0 || aprBps > maxAprBps) {
            revert PolicyRejected(riskGrade, aprBps);
        }
        if (target == 0) revert ZeroAmount();
        if (usedRef[docHash]) revert RefUsed(docHash);
        usedRef[docHash] = true;

        uint256 loanId = ++loanCount;
        Loan storage l = s_loans[loanId];
        l.borrower = borrower;
        l.assetType = assetType;
        l.riskGrade = riskGrade;
        l.currency = currency;
        l.status = Status.Listed;
        l.aprBps = aprBps;
        l.tenorDays = tenorDays;
        l.listedAt = uint64(block.timestamp);
        l.faceValueMinor = faceValueMinor;
        l.fxRateE8 = fxRateE8;
        l.target = target;
        l.docHash = docHash;
        l.ref = ref;

        emit LoanListed(loanId, borrower, ref, target, aprBps, tenorDays, riskGrade, docHash);
    }

    function _verifyLender(bytes memory payload) internal {
        (address lender, bool verified, bytes32 kycRef) = abi.decode(payload, (address, bool, bytes32));
        notes.setVerifiedHolder(lender, verified);
        emit LenderVerified(lender, verified, kycRef);
    }

    function _fiatFunding(bytes memory payload) internal {
        (uint256 loanId, address lender, uint256 amount, bytes32 depositRef) =
            abi.decode(payload, (uint256, address, uint256, bytes32));
        if (usedRef[depositRef]) revert RefUsed(depositRef);
        usedRef[depositRef] = true;
        // The on-ramped stablecoins must already sit in the contract, unallocated.
        uint256 available = unallocated();
        if (available < amount) revert InsufficientUnallocated(available, amount);
        if (!notes.isVerifiedHolder(lender)) notes.setVerifiedHolder(lender, true);
        totalFiatIn += amount;
        s_loans[loanId].fiatFunded += amount;
        _fund(loanId, lender, amount, true, depositRef);
    }

    function _disbursed(bytes memory payload) internal {
        (uint256 loanId, bytes32 payoutRef) = abi.decode(payload, (uint256, bytes32));
        Loan storage l = s_loans[loanId];
        if (l.status != Status.Funded) revert BadStatus(loanId, l.status);
        if (settlementAccount == address(0)) revert NoSettlementAccount();
        if (usedRef[payoutRef]) revert RefUsed(payoutRef);
        usedRef[payoutRef] = true;

        l.status = Status.Disbursed;
        l.disbursedAt = uint64(block.timestamp);
        l.maturity = uint64(block.timestamp) + uint64(l.tenorDays) * secondsPerDay;
        reserved -= l.funded;
        // Stablecoins move to the off-ramp operator, which has already paid the business in fiat.
        stablecoin.safeTransfer(settlementAccount, l.funded);
        emit Disbursed(loanId, l.funded, payoutRef, l.maturity);
        emit StatusChanged(loanId, Status.Disbursed);
    }

    function _repaid(bytes memory payload) internal {
        (uint256 loanId, uint256 amount, bytes32 paymentRef) = abi.decode(payload, (uint256, uint256, bytes32));
        Loan storage l = s_loans[loanId];
        if (l.status != Status.Disbursed && l.status != Status.Late) revert BadStatus(loanId, l.status);
        if (usedRef[paymentRef]) revert RefUsed(paymentRef);
        usedRef[paymentRef] = true;
        // The buyer's payment, on-ramped to stablecoins, must already be in the contract.
        uint256 available = unallocated();
        if (available < amount) revert InsufficientUnallocated(available, amount);

        l.status = Status.Repaid;
        l.repaidAt = uint64(block.timestamp);
        l.repaidAmount = amount;
        reserved += amount;
        emit Repaid(loanId, amount, paymentRef);
        emit StatusChanged(loanId, Status.Repaid);
    }

    function _fiatRedeemed(bytes memory payload) internal {
        (uint256 loanId, address lender, bytes32 payoutRef) = abi.decode(payload, (uint256, address, bytes32));
        if (usedRef[payoutRef]) revert RefUsed(payoutRef);
        usedRef[payoutRef] = true;
        if (settlementAccount == address(0)) revert NoSettlementAccount();
        uint256 payout = _redeem(loanId, lender);
        // Off-ramp operator pays the lender's bank account in fiat.
        stablecoin.safeTransfer(settlementAccount, payout);
        emit FiatRedeemed(loanId, lender, payout, payoutRef);
    }

    function _loanStatus(bytes memory payload) internal {
        (uint256 loanId, uint8 newStatus, bool freezeBorrower) = abi.decode(payload, (uint256, uint8, bool));
        Loan storage l = s_loans[loanId];
        if (l.status != Status.Disbursed && l.status != Status.Late) revert BadStatus(loanId, l.status);
        Status s = Status(newStatus);
        if (s != Status.Late && s != Status.Defaulted) revert BadStatus(loanId, s);
        l.status = s;
        emit StatusChanged(loanId, s);
        if (freezeBorrower && !frozenBorrower[l.borrower]) {
            frozenBorrower[l.borrower] = true;
            emit BorrowerFrozen(l.borrower, loanId);
        }
    }

    function _reconciliation(bytes memory payload) internal {
        (bool ok, uint256 fiatReceived, uint256 stablecoinsHeld, uint256 notesOutstanding, bytes32 snapshotHash) =
            abi.decode(payload, (bool, uint256, uint256, uint256, bytes32));
        lastReconciliation = Reconciliation(ok, uint64(block.timestamp), fiatReceived, stablecoinsHeld, notesOutstanding, snapshotHash);
        emit Reconciled(ok, fiatReceived, stablecoinsHeld, notesOutstanding, snapshotHash);
        if (!ok && !fundingPaused) {
            fundingPaused = true;
            emit FundingPaused(true);
        }
    }

    // ---------------------------------------------------------------------
    // Internals
    // ---------------------------------------------------------------------

    function _fund(uint256 loanId, address lender, uint256 amount, bool viaFiat, bytes32 ref) internal {
        if (fundingPaused) revert FundingIsPaused();
        if (amount == 0) revert ZeroAmount();
        Loan storage l = s_loans[loanId];
        if (l.status != Status.Listed) revert BadStatus(loanId, l.status);
        if (frozenBorrower[l.borrower]) revert Frozen(l.borrower);
        uint256 remaining = l.target - l.funded;
        if (amount > remaining) revert OverTarget(remaining);

        l.funded += amount;
        reserved += amount;
        notes.mint(lender, loanId, amount);
        emit Funded(loanId, lender, amount, viaFiat, ref);

        if (l.funded == l.target) {
            l.status = Status.Funded;
            l.fundedAt = uint64(block.timestamp);
            emit StatusChanged(loanId, Status.Funded);
            emit LoanFullyFunded(loanId, l.borrower, l.target);
        }
    }

    function _redeem(uint256 loanId, address lender) internal returns (uint256 payout) {
        Loan storage l = s_loans[loanId];
        if (l.status != Status.Repaid) revert BadStatus(loanId, l.status);
        uint256 bal = notes.balanceOf(lender, loanId);
        if (bal == 0) revert NothingToClaim();
        payout = (bal * l.repaidAmount) / l.target;
        notes.burn(lender, loanId, bal);
        reserved -= payout;
        emit Claimed(loanId, lender, bal, payout);
    }

    // ---------------------------------------------------------------------
    // Views
    // ---------------------------------------------------------------------

    function getLoan(uint256 loanId) external view returns (Loan memory) {
        return s_loans[loanId];
    }

    /// @notice Stablecoins in the contract not yet owed to any loan or lender (e.g. a fiat
    ///         deposit that has been on-ramped but not yet credited by CRE).
    function unallocated() public view returns (uint256) {
        uint256 bal = stablecoin.balanceOf(address(this));
        return bal > reserved ? bal - reserved : 0;
    }

    /// @notice Compact view used by the CRE monitor workflow.
    function loanStates(uint256 fromId, uint256 toId)
        external
        view
        returns (uint8[] memory statuses, uint64[] memory maturities, uint256[] memory funded, uint256[] memory fiatFunded)
    {
        if (toId > loanCount) toId = loanCount;
        uint256 n = toId >= fromId ? toId - fromId + 1 : 0;
        statuses = new uint8[](n);
        maturities = new uint64[](n);
        funded = new uint256[](n);
        fiatFunded = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {
            Loan storage l = s_loans[fromId + i];
            statuses[i] = uint8(l.status);
            maturities[i] = l.maturity;
            funded[i] = l.funded;
            fiatFunded[i] = l.fiatFunded;
        }
    }

    // ---------------------------------------------------------------------
    // Owner policy
    // ---------------------------------------------------------------------

    function setSettlementAccount(address account) external onlyOwner {
        settlementAccount = account;
        emit SettlementAccountSet(account);
    }

    function setPolicy(uint8 maxRiskGrade_, uint32 maxAprBps_) external onlyOwner {
        maxRiskGrade = maxRiskGrade_;
        maxAprBps = maxAprBps_;
        emit PolicySet(maxRiskGrade_, maxAprBps_);
    }

    /// @notice Demo clock. Production keeps 1 day; a hackathon demo can compress it.
    function setSecondsPerDay(uint32 secondsPerDay_) external onlyOwner {
        secondsPerDay = secondsPerDay_;
        emit ClockSet(secondsPerDay_);
    }

    /// @notice Only the operator can lift the circuit breaker, after investigating.
    function resumeFunding() external onlyOwner {
        fundingPaused = false;
        emit FundingPaused(false);
    }
}
