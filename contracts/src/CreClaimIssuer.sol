// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Identity} from "@onchain-id/solidity/contracts/Identity.sol";
import {IIdentity} from "@onchain-id/solidity/contracts/interface/IIdentity.sol";
import {IClaimIssuer} from "@onchain-id/solidity/contracts/interface/IClaimIssuer.sol";

/// @title CreClaimIssuer
/// @notice The trusted claim issuer of Tradeflow's ERC-3643 identity registry, with Chainlink CRE
///         as the authority behind every claim.
///
///         In ONCHAINID a claim issuer is itself an identity, and a claim on a lender's identity is
///         valid when the issuer says so through `isClaimValid`. A standard ONCHAINID ClaimIssuer
///         answers by checking an ECDSA signature from one of its claim keys. Here the authority
///         is a CRE report instead: the lender workflow checks the KYC file inside the enclave, the
///         Chainlink forwarder delivers the signed report to the market, and only then does the
///         market record the claim in this contract (or revoke it when KYC is withdrawn). No key
///         signs claims and no one else can record them.
///
///         The T-REX TrustedIssuersRegistry lists this contract for claim topic 1 (KYC), so
///         `IdentityRegistry.isVerified(wallet)` is true exactly while a recorded, unrevoked claim
///         sits on the wallet's identity.
contract CreClaimIssuer is IClaimIssuer, Identity {
    /// @notice The market that applies CRE KYC reports. Set once by the management key.
    address public market;

    /// @dev identity => claim topic => keccak256 of the claim data the market recorded.
    ///      Zero means no claim, or a revoked one.
    mapping(address => mapping(uint256 => bytes32)) private s_claims;

    event MarketSet(address indexed market);
    event ClaimRecorded(address indexed identity, uint256 indexed topic, bytes data);
    event ClaimRecordRevoked(address indexed identity, uint256 indexed topic);

    error OnlyMarket(address caller);
    error MarketAlreadySet();
    error NoSignatures();

    /// @param managementKey operator key that manages this issuer's own identity and sets the market
    constructor(address managementKey) Identity(managementKey, false) {}

    modifier onlyMarket() {
        if (msg.sender != market) revert OnlyMarket(msg.sender);
        _;
    }

    function setMarket(address market_) external onlyManager {
        if (market != address(0)) revert MarketAlreadySet();
        market = market_;
        emit MarketSet(market_);
    }

    /// @notice Record a claim after a CRE KYC report. The market then adds the same topic and
    ///         data to the lender's identity, where the identity registry reads it.
    function recordClaim(address identity, uint256 topic, bytes calldata data) external onlyMarket {
        s_claims[identity][topic] = keccak256(data);
        emit ClaimRecorded(identity, topic, data);
    }

    /// @inheritdoc IClaimIssuer
    /// @dev Called by the market when a CRE report withdraws KYC. Idempotent: revoking a claim
    ///      that is missing or already revoked returns false instead of reverting, so a repeated
    ///      report cannot get stuck.
    function revokeClaim(bytes32 claimId, address identity) external override onlyMarket returns (bool) {
        (uint256 topic,,,,,) = IIdentity(identity).getClaim(claimId);
        if (topic == 0 || s_claims[identity][topic] == bytes32(0)) return false;
        delete s_claims[identity][topic];
        emit ClaimRecordRevoked(identity, topic);
        return true;
    }

    /// @inheritdoc IClaimIssuer
    /// @dev Claims from this issuer carry no signature, so there is nothing to revoke by signature.
    function revokeClaimBySignature(bytes calldata) external pure override {
        revert NoSignatures();
    }

    /// @inheritdoc IClaimIssuer
    /// @dev Always false: revocation is tracked per identity and topic, see `isClaimValid`.
    function isClaimRevoked(bytes calldata) external pure override returns (bool) {
        return false;
    }

    /// @notice True only for a claim the market recorded for this identity and topic, with this
    ///         exact data, and has not revoked. The signature argument is ignored (see above).
    function isClaimValid(IIdentity identity, uint256 claimTopic, bytes memory, bytes memory data)
        public
        view
        override(Identity, IClaimIssuer)
        returns (bool)
    {
        bytes32 recorded = s_claims[address(identity)][claimTopic];
        return recorded != bytes32(0) && recorded == keccak256(data);
    }
}
