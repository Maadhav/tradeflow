// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/// @title TestStablecoin
/// @notice 6-decimal test stablecoin used on testnet. The on-ramp operator mints it when
///         fiat arrives, and lenders can use the faucet to try crypto funding.
contract TestStablecoin is ERC20, Ownable {
    mapping(address => bool) public isMinter;
    mapping(address => uint256) public lastDrip;

    uint256 public constant DRIP_AMOUNT = 10_000e6;
    uint256 public constant DRIP_COOLDOWN = 1 hours;

    event MinterSet(address indexed account, bool allowed);

    error NotMinter(address caller);
    error DripCooldown(uint256 availableAt);

    constructor(string memory name_, string memory symbol_) ERC20(name_, symbol_) Ownable(msg.sender) {}

    function decimals() public pure override returns (uint8) {
        return 6;
    }

    function setMinter(address account, bool allowed) external onlyOwner {
        isMinter[account] = allowed;
        emit MinterSet(account, allowed);
    }

    /// @notice Mint by an authorised minter (the on-ramp operator in the demo).
    function mint(address to, uint256 amount) external {
        if (!isMinter[msg.sender] && msg.sender != owner()) revert NotMinter(msg.sender);
        _mint(to, amount);
    }

    /// @notice Testnet faucet for lenders who want to fund with stablecoins.
    function drip() external {
        uint256 availableAt = lastDrip[msg.sender] + DRIP_COOLDOWN;
        if (lastDrip[msg.sender] != 0 && block.timestamp < availableAt) revert DripCooldown(availableAt);
        lastDrip[msg.sender] = block.timestamp;
        _mint(msg.sender, DRIP_AMOUNT);
    }
}
