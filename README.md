# Tradeflow

Trade finance for goods already on their way. Exporters get paid the day their goods ship.
Investors fund them from a bank account or a USDC wallet and are repaid when the buyer pays.

Built during TOKEN2049 Origins, 6 to 7 October 2026.
[Demo video](https://drive.google.com/file/d/1Ybdj3qras6ssJICdjLtYIC57j3Bb1RMm/view?usp=sharing)

## How it works

1. A business uploads an invoice, bill of lading or equipment order.
2. Its buyer confirms the document through a link.
3. A private credit review grades it and lists it as a loan with its own ERC-3643 token.
4. Verified investors fund it by bank transfer or USDC.
5. The business is paid once the loan is fully funded.
6. The buyer pays on the usual terms and investors are repaid with interest.

Late loans lock the business and pause the loan's token. If the bank, on-ramp and market books
disagree, new funding pauses.

## Chainlink CRE

Every decision that depends on off-chain data is a CRE workflow that writes a signed report to the
market contract. The contract still enforces its own rules: grade and APR limits, frozen businesses,
replayed references, and stablecoins that never arrived.

| Workflow | Trigger | What it does |
|---|---|---|
| `listing` | HTTP | Runs in a TEE (Confidential Workflow). Checks the registry, sanctions and the private credit file; only the grade, APR, advance and a document hash leave. Prices with the Chainlink EUR/USD feed, lists the loan and deploys its token. |
| `lender` | HTTP | KYC over Confidential HTTP, then registers the investor in the ERC-3643 identity registry. For bank deposits: instructs the on-ramp, rejects a rate more than 1% off the feed, checks the USDC arrived, mints notes. |
| `settlement` | EVM log, HTTP | Pays the business when a loan is funded. Confirms repayment only when the collection bank and the payment processor agree (`runInNodeMode` consensus). Repays bank investors. |
| `monitor` | Cron | Marks late loans, pauses their tokens and freezes the business. Reconciles the bank, on-ramp and market books and pauses funding on a mismatch. |

## ERC-3643 loan notes

Each loan is its own T-REX token (`TFN<id>`), minted 1:1 with the USDC lent and burned on repayment.
All loan tokens share one identity registry. Each investor gets an ONCHAINID identity with a KYC
claim from `CreClaimIssuer`, which only the `lender` workflow can write to.

## On Ethereum Sepolia

| Contract | Address |
|---|---|
| TradeflowMarket | [`0xBbF0D99c0E710792FdBF696bda9a135475f8F8cF`](https://sepolia.etherscan.io/address/0xBbF0D99c0E710792FdBF696bda9a135475f8F8cF) |
| Identity registry | [`0x8be92721B216A7D35D9D61F370AE5432D7D0916A`](https://sepolia.etherscan.io/address/0x8be92721B216A7D35D9D61F370AE5432D7D0916A) |
| CreClaimIssuer | [`0x7439254a4F4C41A271911b72f76bd1e7246f35Fb`](https://sepolia.etherscan.io/address/0x7439254a4F4C41A271911b72f76bd1e7246f35Fb) |
| Test stablecoin (tUSDC) | [`0x223E1BcE28382C2718b1cf0322F7002bb102b17B`](https://sepolia.etherscan.io/address/0x223E1BcE28382C2718b1cf0322F7002bb102b17B) |

The CRE workflows reach Sepolia through a [NOWNodes](https://nownodes.io) RPC endpoint
(`eth-sepolia.nownodes.io`): every data feed read, contract read and report write in the 14 runs went through it.

All 14 workflow runs, with full CLI output and their transactions: [`evidence/`](evidence/).

## Run it locally

Needs Bun, Foundry and the CRE CLI.

```bash
bash scripts/dev-up.sh       # anvil fork of Sepolia, fresh contracts, app on :8787
open http://localhost:8787
tail -f .run/rails.log       # every workflow run, live
bun scripts/e2e.ts           # the full lifecycle, 15 checks
cd contracts && forge test
```

## Repo

- `contracts/`: the market, one ERC-3643 token per loan, the claim issuer, the test stablecoin (Foundry)
- `cre/`: the four workflows (TypeScript SDK)
- `services/rails/`: the app server, the web app, and the simulated third parties the workflows call
  (document registry, credit bureau, KYC, on-ramp, bank, payment processor, payouts)
- `evidence/`: the Sepolia run logs

Built by Maadhav Sharma, [CodeDecoders](https://codedecoders.io).
