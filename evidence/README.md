# Evidence: CRE workflow simulations on Ethereum Sepolia

Every run below is `cre workflow simulate <workflow> --target sepolia --broadcast` (CRE CLI v1.37),
executed by the app as the loan moved through its lifecycle. Each onchain write is a signed CRE report
delivered through the Sepolia **MockKeystoneForwarder** (`0x15fC6ae953E024d975e77382eEeC56A9101f9F88`) to the market contract.

| Contract | Address |
|---|---|
| TradeflowMarket (CRE receiver) | [`0xAFBE1e5a086a49AB431A02243C29956408536192`](https://sepolia.etherscan.io/address/0xAFBE1e5a086a49AB431A02243C29956408536192) |
| LoanNotes (KYC-gated ERC-1155) | [`0x0FD05De1A1Bae6031d3b1b1648Dd8Fd21511059B`](https://sepolia.etherscan.io/address/0x0FD05De1A1Bae6031d3b1b1648Dd8Fd21511059B) |
| Test stablecoin (tUSDC) | [`0x3Ca6F7d61A8bD23b141BDBa15A199d5346c472Ad`](https://sepolia.etherscan.io/address/0x3Ca6F7d61A8bD23b141BDBa15A199d5346c472Ad) |

| # | Workflow · handler | Trigger | CRE capabilities used | Outcome | Sepolia transaction | Log |
|---|---|---|---|---|---|---|
| 1 | `listing` · verify-and-list | HTTP | Confidential Workflow (TEE, `handlerInTee`), HTTP in enclave, EVM read (Chainlink EUR/USD Data Feed), EVM write | Listed INV-2026-0142: grade A, APR 9%, advance $9335, EUR/USD 1.12137 | [0x25ac6b6d…](https://sepolia.etherscan.io/tx/0x25ac6b6db627578f8912728aaef293e6152e8e43d5580418fe92f75064a8f6d3) | [log](logs/01-verify-and-list.log) |
| 2 | `listing` · verify-and-list | HTTP | Confidential Workflow (TEE, `handlerInTee`), HTTP in enclave, EVM read (Chainlink EUR/USD Data Feed), EVM write | Rejected INV-2026-0999: buyer has not confirmed the document | (no write: rejected) | [log](logs/02-verify-and-list.log) |
| 3 | `lender` · credit-fiat-deposit | HTTP | Confidential HTTP, EVM read (Chainlink EUR/USD + market), EVM write | Credited $3357.38178 for 3000 EUR; on-ramp 1.11912726 vs Chainlink 1.12137 | [0x4182a20e…](https://sepolia.etherscan.io/tx/0x4182a20e12a43db6e85c5d7906d50cbbed2273b4b754e7b3d27fa8811f24e0eb) | [log](logs/03-credit-fiat-deposit.log) |
| 4 | `lender` · verify-lender | HTTP | Confidential HTTP (Vault DON secret), EVM write | KYC verified: lender-ben | [0x86281e86…](https://sepolia.etherscan.io/tx/0x86281e86ea065fd39720d26af3e6747c5cb96a55eba6189614c2bae313d89431) | [log](logs/04-verify-lender.log) |
| 5 | `settlement` · disburse-on-funded | EVM log | EVM log trigger, HTTP POST with consensus, EVM read/write | Paid $9335 to the business (PO-B-00001), loan 1 | [0x421029e2…](https://sepolia.etherscan.io/tx/0x421029e2a30070de6d98b3661960364c970e7f48a7af16bd097ed364b2e5a5a8) | [log](logs/05-disburse-on-funded.log) |
| 6 | `settlement` · confirm-repayment | HTTP | HTTP trigger, `runInNodeMode` over two sources with consensus, EVM read/write | Repayment $9473.1 from Kaffeehaus Berlin GmbH, confirmed by collection bank and payment processor | [0x460e3683…](https://sepolia.etherscan.io/tx/0x460e3683564ac6a484a5d80972b7a2a7570d0d642d3b0b9ec7fa2dddef207039) | [log](logs/06-confirm-repayment.log) |
| 7 | `settlement` · redeem-fiat-lenders | EVM log | EVM log trigger, HTTP with consensus, EVM read/write | lender-ana paid $3407.05017 (PO-L-00002) | [0x8d11525e…](https://sepolia.etherscan.io/tx/0x8d11525ef2353ee243773ada789947167d767369644d65c67489ac526e4f0c40) | [log](logs/07-redeem-fiat-lenders.log) |
| 8 | `monitor` · watch-and-reconcile | Cron | Cron trigger, EVM read, HTTP with consensus, EVM write | Reconciliation passed | [0xcfc8831e…](https://sepolia.etherscan.io/tx/0xcfc8831e96800c4fb48547df2906fbc2830915db9da1c3f5c1563c61c8786b3c) | [log](logs/08-watch-and-reconcile.log) |
| 9 | `monitor` · watch-and-reconcile | Cron | Cron trigger, EVM read, HTTP with consensus, EVM write | Reconciliation FAILED (funding paused) | [0x6b215265…](https://sepolia.etherscan.io/tx/0x6b215265b2dbe44d8f8244d85981aa6a7e61c33c666a095b1562a532e7a51c4e) | [log](logs/09-watch-and-reconcile.log) |
| 10 | `listing` · verify-and-list | HTTP | Confidential Workflow (TEE, `handlerInTee`), HTTP in enclave, EVM read (Chainlink EUR/USD Data Feed), EVM write | Listed INV-2026-0388: grade D, APR 19%, advance $3200 | [0xa782c169…](https://sepolia.etherscan.io/tx/0xa782c169664f5c00224ebd58e0a09c130b3bdc35f58bf3ff20a282c94df64dcb) | [log](logs/10-verify-and-list.log) |
| 11 | `settlement` · disburse-on-funded | EVM log | EVM log trigger, HTTP POST with consensus, EVM read/write | Paid $3200 to the business (PO-B-00003), loan 2 | [0x6d044497…](https://sepolia.etherscan.io/tx/0x6d04449761b6a24cc68df1f664f44d0b5f08da8d54a0c4855192d8555203d954) | [log](logs/11-disburse-on-funded.log) |
| 12 | `monitor` · watch-and-reconcile | Cron | Cron trigger, EVM read, HTTP with consensus, EVM write | Reconciliation passed; loan 2 late, business frozen | [0xe0507cab…](https://sepolia.etherscan.io/tx/0xe0507cabfad380b401aebda8b314235425e76a59ed2dc40f58314ccb1fbf47fa)<br>[0x26f041c2…](https://sepolia.etherscan.io/tx/0x26f041c225ded0d5bc3bb1a8c163d3eb7c0b10f8da98a7680a2501c291112db7) | [log](logs/12-watch-and-reconcile.log) |

Generated by `scripts/export-evidence.ts` from the app's run history.
