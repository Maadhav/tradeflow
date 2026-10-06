// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {ERC1155} from "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/// @title LoanNotes
/// @notice One ERC-1155 token id per loan. A lender's balance is their share of the loan,
///         in stablecoin units (6 decimals). Notes can only be held by KYC-verified wallets:
///         the market adds wallets to the allowlist after a CRE-verified KYC check.
contract LoanNotes is ERC1155, Ownable {
    address public market;
    mapping(address => bool) public isVerifiedHolder;
    mapping(uint256 => uint256) public totalSupply;

    event MarketSet(address indexed market);
    event HolderVerified(address indexed account, bool verified);

    error OnlyMarket(address caller);
    error MarketAlreadySet();
    error UnverifiedHolder(address account);

    constructor(string memory uri_) ERC1155(uri_) Ownable(msg.sender) {}

    modifier onlyMarket() {
        if (msg.sender != market) revert OnlyMarket(msg.sender);
        _;
    }

    function setMarket(address market_) external onlyOwner {
        if (market != address(0)) revert MarketAlreadySet();
        market = market_;
        emit MarketSet(market_);
    }

    function setVerifiedHolder(address account, bool verified) external onlyMarket {
        isVerifiedHolder[account] = verified;
        emit HolderVerified(account, verified);
    }

    function mint(address to, uint256 id, uint256 amount) external onlyMarket {
        _mint(to, id, amount, "");
    }

    function burn(address from, uint256 id, uint256 amount) external onlyMarket {
        _burn(from, id, amount);
    }

    /// @dev Mints and burns are market-controlled. Holder-to-holder transfers require both
    ///      sides to be verified, which keeps the notes inside the KYC perimeter.
    function _update(address from, address to, uint256[] memory ids, uint256[] memory values) internal override {
        if (from != address(0) && to != address(0)) {
            if (!isVerifiedHolder[from]) revert UnverifiedHolder(from);
            if (!isVerifiedHolder[to]) revert UnverifiedHolder(to);
        }
        if (to != address(0) && from == address(0) && !isVerifiedHolder[to]) revert UnverifiedHolder(to);
        super._update(from, to, ids, values);
        for (uint256 i = 0; i < ids.length; i++) {
            if (from == address(0)) totalSupply[ids[i]] += values[i];
            if (to == address(0)) totalSupply[ids[i]] -= values[i];
        }
    }
}
