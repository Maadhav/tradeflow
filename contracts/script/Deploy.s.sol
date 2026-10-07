// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Script, console2} from "forge-std/Script.sol";
import {Token} from "@tokenysolutions/t-rex/contracts/token/Token.sol";
import {ClaimTopicsRegistry} from "@tokenysolutions/t-rex/contracts/registry/implementation/ClaimTopicsRegistry.sol";
import {IdentityRegistry} from "@tokenysolutions/t-rex/contracts/registry/implementation/IdentityRegistry.sol";
import {IdentityRegistryStorage} from "@tokenysolutions/t-rex/contracts/registry/implementation/IdentityRegistryStorage.sol";
import {TrustedIssuersRegistry} from "@tokenysolutions/t-rex/contracts/registry/implementation/TrustedIssuersRegistry.sol";
import {ModularCompliance} from "@tokenysolutions/t-rex/contracts/compliance/modular/ModularCompliance.sol";
import {TREXImplementationAuthority} from "@tokenysolutions/t-rex/contracts/proxy/authority/TREXImplementationAuthority.sol";
import {ITREXImplementationAuthority} from "@tokenysolutions/t-rex/contracts/proxy/authority/ITREXImplementationAuthority.sol";
import {IdentityRegistryProxy} from "@tokenysolutions/t-rex/contracts/proxy/IdentityRegistryProxy.sol";
import {IdentityRegistryStorageProxy} from "@tokenysolutions/t-rex/contracts/proxy/IdentityRegistryStorageProxy.sol";
import {ClaimTopicsRegistryProxy} from "@tokenysolutions/t-rex/contracts/proxy/ClaimTopicsRegistryProxy.sol";
import {TrustedIssuersRegistryProxy} from "@tokenysolutions/t-rex/contracts/proxy/TrustedIssuersRegistryProxy.sol";
import {IIdentityRegistry} from "@tokenysolutions/t-rex/contracts/registry/interface/IIdentityRegistry.sol";
import {IIdentityRegistryStorage} from "@tokenysolutions/t-rex/contracts/registry/interface/IIdentityRegistryStorage.sol";
import {IClaimTopicsRegistry} from "@tokenysolutions/t-rex/contracts/registry/interface/IClaimTopicsRegistry.sol";
import {ITrustedIssuersRegistry} from "@tokenysolutions/t-rex/contracts/registry/interface/ITrustedIssuersRegistry.sol";
import {AgentRoleUpgradeable} from "@tokenysolutions/t-rex/contracts/roles/AgentRoleUpgradeable.sol";
import {Identity} from "@onchain-id/solidity/contracts/Identity.sol";
import {ImplementationAuthority} from "@onchain-id/solidity/contracts/proxy/ImplementationAuthority.sol";
import {IClaimIssuer} from "@onchain-id/solidity/contracts/interface/IClaimIssuer.sol";
import {TestStablecoin} from "../src/TestStablecoin.sol";
import {CreClaimIssuer} from "../src/CreClaimIssuer.sol";
import {TradeflowMarket} from "../src/TradeflowMarket.sol";

struct Deployment {
    TestStablecoin stablecoin;
    TradeflowMarket market;
    IIdentityRegistry identityRegistry;
    CreClaimIssuer claimIssuer;
    address trexAuthority;
    address identityAuthority;
}

/// @notice Deploys the whole suite. Shared by the Deploy script and the tests.
///         - T-REX v4 implementations (Token, IdentityRegistry, IdentityRegistryStorage,
///           ClaimTopicsRegistry, TrustedIssuersRegistry, ModularCompliance) behind one reference
///           TREXImplementationAuthority
///         - ONE shared identity registry (+ storage), requiring claim topic 1 (KYC), with
///           CreClaimIssuer as the only trusted issuer for it
///         - the ONCHAINID Identity implementation and its authority, for lender identity proxies
///         - the stablecoin and the market; the market is an agent of the identity registry and the
///           only account that can record or revoke claims in CreClaimIssuer
///         `admin` must be the caller of the deploying transactions: it owns the T-REX suite and
///         holds the management key of CreClaimIssuer's own identity.
abstract contract TradeflowDeployer {
    uint256 internal constant KYC_TOPIC = 1;

    function _deployTradeflow(address forwarder, address settlement, address admin)
        internal
        returns (Deployment memory d)
    {
        TREXImplementationAuthority trexAuthority = new TREXImplementationAuthority(true, address(0), address(0));
        trexAuthority.addAndUseTREXVersion(
            ITREXImplementationAuthority.Version(4, 1, 6),
            ITREXImplementationAuthority.TREXContracts({
                tokenImplementation: address(new Token()),
                ctrImplementation: address(new ClaimTopicsRegistry()),
                irImplementation: address(new IdentityRegistry()),
                irsImplementation: address(new IdentityRegistryStorage()),
                tirImplementation: address(new TrustedIssuersRegistry()),
                mcImplementation: address(new ModularCompliance())
            })
        );
        // ONCHAINID library pattern: the implementation is locked, identities are proxies.
        Identity identityImplementation = new Identity(admin, true);
        d.identityAuthority = address(new ImplementationAuthority(address(identityImplementation)));
        d.trexAuthority = address(trexAuthority);

        address irs = address(new IdentityRegistryStorageProxy(d.trexAuthority));
        address ctr = address(new ClaimTopicsRegistryProxy(d.trexAuthority));
        address tir = address(new TrustedIssuersRegistryProxy(d.trexAuthority));
        d.identityRegistry = IIdentityRegistry(address(new IdentityRegistryProxy(d.trexAuthority, tir, ctr, irs)));
        IIdentityRegistryStorage(irs).bindIdentityRegistry(address(d.identityRegistry));
        IClaimTopicsRegistry(ctr).addClaimTopic(KYC_TOPIC);

        d.claimIssuer = new CreClaimIssuer(admin);
        uint256[] memory topics = new uint256[](1);
        topics[0] = KYC_TOPIC;
        ITrustedIssuersRegistry(tir).addTrustedIssuer(IClaimIssuer(address(d.claimIssuer)), topics);

        d.stablecoin = new TestStablecoin("Test USD Coin", "tUSDC");
        d.market = new TradeflowMarket(
            forwarder, d.stablecoin, settlement, d.identityRegistry, d.claimIssuer, d.trexAuthority, d.identityAuthority
        );
        AgentRoleUpgradeable(address(d.identityRegistry)).addAgent(address(d.market));
        d.claimIssuer.setMarket(address(d.market));
    }
}

/// @notice Deploys the suite and wires roles.
/// Env:
///   FORWARDER          CRE forwarder the market trusts (MockKeystoneForwarder for simulation)
///   SETTLEMENT_ACCOUNT off-ramp operator address (receives stablecoins on payouts)
///   ONRAMP_OPERATOR    address allowed to mint test stablecoins when fiat arrives
///   SECONDS_PER_DAY    demo clock (default 86400)
contract Deploy is Script, TradeflowDeployer {
    function run() external {
        address forwarder = vm.envAddress("FORWARDER");
        address settlement = vm.envAddress("SETTLEMENT_ACCOUNT");
        address onramp = vm.envAddress("ONRAMP_OPERATOR");
        uint256 secondsPerDay = vm.envOr("SECONDS_PER_DAY", uint256(1 days));

        vm.startBroadcast();
        (, address deployer,) = vm.readCallers();
        Deployment memory d = _deployTradeflow(forwarder, settlement, deployer);
        d.stablecoin.setMinter(onramp, true);
        if (secondsPerDay != 1 days) d.market.setSecondsPerDay(uint32(secondsPerDay));
        vm.stopBroadcast();

        console2.log("STABLECOIN", address(d.stablecoin));
        console2.log("MARKET", address(d.market));
        console2.log("IDENTITY_REGISTRY", address(d.identityRegistry));
        console2.log("CLAIM_ISSUER", address(d.claimIssuer));
        console2.log("TREX_AUTHORITY", d.trexAuthority);
        console2.log("IDENTITY_AUTHORITY", d.identityAuthority);

        string memory obj = "deploy";
        vm.serializeAddress(obj, "stablecoin", address(d.stablecoin));
        vm.serializeAddress(obj, "identityRegistry", address(d.identityRegistry));
        vm.serializeAddress(obj, "claimIssuer", address(d.claimIssuer));
        vm.serializeAddress(obj, "forwarder", forwarder);
        vm.serializeUint(obj, "chainId", block.chainid);
        string memory json = vm.serializeAddress(obj, "market", address(d.market));
        vm.writeJson(json, string.concat("./deployments/", vm.envOr("DEPLOY_NAME", vm.toString(block.chainid)), ".json"));
    }
}
