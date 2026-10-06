// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Script, console2} from "forge-std/Script.sol";
import {TestStablecoin} from "../src/TestStablecoin.sol";
import {LoanNotes} from "../src/LoanNotes.sol";
import {TradeflowMarket} from "../src/TradeflowMarket.sol";

/// @notice Deploys the stablecoin, notes and market, and wires roles.
/// Env:
///   FORWARDER          CRE forwarder the market trusts (MockKeystoneForwarder for simulation)
///   SETTLEMENT_ACCOUNT off-ramp operator address (receives stablecoins on payouts)
///   ONRAMP_OPERATOR    address allowed to mint test stablecoins when fiat arrives
///   SECONDS_PER_DAY    demo clock (default 86400)
///   NOTES_URI          metadata URI template
contract Deploy is Script {
    function run() external {
        address forwarder = vm.envAddress("FORWARDER");
        address settlement = vm.envAddress("SETTLEMENT_ACCOUNT");
        address onramp = vm.envAddress("ONRAMP_OPERATOR");
        uint256 secondsPerDay = vm.envOr("SECONDS_PER_DAY", uint256(1 days));
        string memory uri = vm.envOr("NOTES_URI", string("https://tradeflow.codedecoders.io/notes/{id}.json"));

        vm.startBroadcast();
        TestStablecoin usdc = new TestStablecoin("Test USD Coin", "tUSDC");
        LoanNotes notes = new LoanNotes(uri);
        TradeflowMarket market = new TradeflowMarket(forwarder, usdc, notes, settlement);
        notes.setMarket(address(market));
        usdc.setMinter(onramp, true);
        if (secondsPerDay != 1 days) market.setSecondsPerDay(uint32(secondsPerDay));
        vm.stopBroadcast();

        console2.log("STABLECOIN", address(usdc));
        console2.log("NOTES", address(notes));
        console2.log("MARKET", address(market));

        string memory obj = "deploy";
        vm.serializeAddress(obj, "stablecoin", address(usdc));
        vm.serializeAddress(obj, "notes", address(notes));
        vm.serializeAddress(obj, "forwarder", forwarder);
        vm.serializeUint(obj, "chainId", block.chainid);
        string memory json = vm.serializeAddress(obj, "market", address(market));
        vm.writeJson(json, string.concat("./deployments/", vm.envOr("DEPLOY_NAME", vm.toString(block.chainid)), ".json"));
    }
}
