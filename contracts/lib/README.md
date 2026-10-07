# Vendored libraries

| Directory | Source | Version | License |
|---|---|---|---|
| `forge-std/` | foundry-rs/forge-std | as committed | MIT / Apache-2.0 |
| `openzeppelin-contracts/` | OpenZeppelin/openzeppelin-contracts | 5.1.0 | MIT |
| `T-REX/` | [TokenySolutions/T-REX](https://github.com/TokenySolutions/T-REX) (ERC-3643) | tag `4.1.6` | GPL-3.0 |
| `onchain-id/` | [onchain-id/solidity](https://github.com/onchain-id/solidity) (ONCHAINID) | tag `2.2.1` | GPL-3.0 |
| `openzeppelin-contracts-4.9.3/` | OpenZeppelin/openzeppelin-contracts, `contracts/` only | tag `v4.9.3` | MIT |
| `openzeppelin-contracts-upgradeable-4.9.3/` | OpenZeppelin/openzeppelin-contracts-upgradeable, `contracts/` only | tag `v4.9.3` | MIT |

T-REX and ONCHAINID are copies of the upstream `contracts/` directories (plus `LICENSE.md`, `package.json`
and `README.md`), without their `_testContracts` folders and ONCHAINID's `Test.sol`. Every license header is
kept. The **only** change to their sources: `pragma solidity 0.8.17;` was relaxed to
`pragma solidity ^0.8.17;` so they compile in the same unit as our contracts with solc 0.8.26 (via IR). The
market deploys T-REX and ONCHAINID proxies itself, so it has to be compiled together with them; a second
solc version cannot do that.

Both upstreams are written against OpenZeppelin 4.9.3 (T-REX's lockfile), while our own code uses
OpenZeppelin 5.1.0. `foundry.toml` resolves this with context remappings: inside `lib/T-REX/` and
`lib/onchain-id/`, `@openzeppelin/contracts/` points at the 4.9.3 copy; `@openzeppelin/contracts-upgradeable/`
(used only by T-REX) points at the 4.9.3 upgradeable copy; everywhere else `@openzeppelin/contracts/` is 5.1.0.

Licensing: T-REX and ONCHAINID are GPL-3.0. `TradeflowMarket` and `CreClaimIssuer` link them (and the market
embeds their proxy creation code), so the compiled combined work falls under GPL-3.0 terms.
