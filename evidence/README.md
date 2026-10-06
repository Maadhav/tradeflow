# Evidence: CRE workflow simulations on Ethereum Sepolia

Every run below is `cre workflow simulate <workflow> --target sepolia --broadcast` (CRE CLI v1.37),
executed by the app as the loan moved through its lifecycle. Each onchain write is a signed CRE report
delivered through the Sepolia **MockKeystoneForwarder** (`0x15fC6ae953E024d975e77382eEeC56A9101f9F88`) to the market contract.

| Contract | Address |
|---|---|
| TradeflowMarket (CRE receiver) | [`0xdF95F021BdE2724b4AFb53f71D1eEe6ECd79AD13`](https://sepolia.etherscan.io/address/0xdF95F021BdE2724b4AFb53f71D1eEe6ECd79AD13) |
| LoanNotes (KYC-gated ERC-1155) | [`0xa0556F810c67B2F80B64E14E16d05cBf76b73d22`](https://sepolia.etherscan.io/address/0xa0556F810c67B2F80B64E14E16d05cBf76b73d22) |
| Test stablecoin (tUSDC) | [`0xD2AA07c08abd81c02aB76A2658E1Bf6C0FC25093`](https://sepolia.etherscan.io/address/0xD2AA07c08abd81c02aB76A2658E1Bf6C0FC25093) |

| # | Workflow · handler | Trigger | CRE capabilities used | Outcome | Sepolia transaction | Log |
|---|---|---|---|---|---|---|
| 1 | `listing` · verify-and-list | HTTP | Confidential Workflow (TEE, `handlerInTee`), HTTP in enclave, EVM read (Chainlink EUR/USD Data Feed), EVM write | Listed INV-2026-0142: grade A, APR 9%, advance $9382, EUR/USD 1.127025 | [0x22db61cd…](https://sepolia.etherscan.io/tx/0x22db61cd6b673ff91f987affe6d3bc249de0aafd3e7d5c6f05d7367aa5069d30) | [log](logs/01-verify-and-list.log) |
| 2 | `listing` · verify-and-list | HTTP | Confidential Workflow (TEE, `handlerInTee`), HTTP in enclave, EVM read (Chainlink EUR/USD Data Feed), EVM write | Rejected INV-2026-0999: buyer disputed the document | (no write: rejected) | [log](logs/02-verify-and-list.log) |
| 3 | `lender` · verify-lender | HTTP | Confidential HTTP (Vault DON secret), EVM write | KYC verified: lender-ana-ruiz-u4ap | [0x182b31a6…](https://sepolia.etherscan.io/tx/0x182b31a6d24a8f81e174405863683fccd3f302f498321f50372f5a3c1f115aec) | [log](logs/03-verify-lender.log) |
| 4 | `lender` · credit-fiat-deposit | HTTP | Confidential HTTP, EVM read (Chainlink EUR/USD + market), EVM write | Credited $3374.31285 for 3000 EUR; on-ramp 1.12477095 vs Chainlink 1.127025 | [0x46d34b57…](https://sepolia.etherscan.io/tx/0x46d34b57e56c416432a10c5279907bf6a9a40b31f9041ba4e79b7fcd4a13529d) | [log](logs/04-credit-fiat-deposit.log) |
| 5 | `lender` · verify-lender | HTTP | Confidential HTTP (Vault DON secret), EVM write | KYC verified: lender-ben-carter-rio9 | [0x80dbaba9…](https://sepolia.etherscan.io/tx/0x80dbaba98b227a5aedbaafcace0f60733272ba957c0d7f93b3ce99120585cadf) | [log](logs/05-verify-lender.log) |
| 6 | `settlement` · disburse-on-funded | EVM log | EVM log trigger, HTTP POST with consensus, EVM read/write | Paid $9382 to the business (PO-B-00001), loan 1 | [0x24a8e7aa…](https://sepolia.etherscan.io/tx/0x24a8e7aada3d9bd7914211a923207f695257da2204180ceb541ce327a95c5c83) | [log](logs/06-disburse-on-funded.log) |
| 7 | `settlement` · confirm-repayment | HTTP | HTTP trigger, `runInNodeMode` over two sources with consensus, EVM read/write | Repayment $9520.802191 from Kaffeehaus Berlin GmbH, confirmed by collection bank and payment processor | [0xe2634574…](https://sepolia.etherscan.io/tx/0xe2634574c9f81725f8a4a8ca66af7cc7b6487c0ec50648451fb31f72565eeb0e) | [log](logs/07-confirm-repayment.log) |
| 8 | `settlement` · redeem-fiat-lenders | EVM log | EVM log trigger, HTTP with consensus, EVM read/write | lender-ana-ruiz-u4ap paid $3424.23419 (PO-L-00003) | [0xe42003b4…](https://sepolia.etherscan.io/tx/0xe42003b4efdf65c69908dfbd1a0c478222d5e8f019f8e1d6470eb9141af2410b) | [log](logs/08-redeem-fiat-lenders.log) |
| 9 | `monitor` · watch-and-reconcile | Cron | Cron trigger, EVM read, HTTP with consensus, EVM write | Reconciliation passed | [0x42cc7948…](https://sepolia.etherscan.io/tx/0x42cc7948ba30fa719756958876eefefd9e173663aa11dcc46a3749fedcd5018a) | [log](logs/09-watch-and-reconcile.log) |
| 10 | `monitor` · watch-and-reconcile | Cron | Cron trigger, EVM read, HTTP with consensus, EVM write | Reconciliation FAILED (funding paused) | [0xe6c2cba0…](https://sepolia.etherscan.io/tx/0xe6c2cba09893aefbeb7281111a2b029765ea5ce586b17e60c3adeccdf3426217) | [log](logs/10-watch-and-reconcile.log) |
| 11 | `monitor` · watch-and-reconcile | Cron | Cron trigger, EVM read, HTTP with consensus, EVM write | Reconciliation passed | [0x0fedf31f…](https://sepolia.etherscan.io/tx/0x0fedf31fb3e2db52ea7923cc1c24a5d9b8c486abd918f868e32e10835dd64778) | [log](logs/11-watch-and-reconcile.log) |
| 12 | `listing` · verify-and-list | HTTP | Confidential Workflow (TEE, `handlerInTee`), HTTP in enclave, EVM read (Chainlink EUR/USD Data Feed), EVM write | Listed INV-2026-0388: grade D, APR 19%, advance $3200 | [0x73dcfcb5…](https://sepolia.etherscan.io/tx/0x73dcfcb5558647be61fe0ea4b3a4a8d89b4740f649e068f46537d2cfc393e572) | [log](logs/12-verify-and-list.log) |
| 13 | `settlement` · disburse-on-funded | EVM log | EVM log trigger, HTTP POST with consensus, EVM read/write | Paid $3200 to the business (PO-B-00004), loan 2 | [0xb89bb788…](https://sepolia.etherscan.io/tx/0xb89bb7888d39ae12235c380fcbc8918ba9ec669fc16b606b65b6412b975cff90) | [log](logs/13-disburse-on-funded.log) |
| 14 | `monitor` · watch-and-reconcile | Cron | Cron trigger, EVM read, HTTP with consensus, EVM write | Reconciliation passed; loan 2 late, business frozen | [0xdc633f6d…](https://sepolia.etherscan.io/tx/0xdc633f6d2491981a2eaa3ae4c5c854a8f7999e64198a5ab625f63de9f2d432d7)<br>[0xc5ff3559…](https://sepolia.etherscan.io/tx/0xc5ff35595c249ec8c0ebc5f043da0c7be8d148eab726ec7364a203aca3b34287) | [log](logs/14-watch-and-reconcile.log) |

Generated by `scripts/export-evidence.ts` from the app's run history.
