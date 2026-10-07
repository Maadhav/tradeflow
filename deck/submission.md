# Tradeflow: BuilderBase submission text

## Project name
Tradeflow

## Tagline
Fund the goods already on their way: invoice financing where every off-chain decision runs as a Chainlink CRE workflow and every loan is an ERC-3643 token.

## Short description
Small exporters wait 60 to 180 days to be paid for goods they have already shipped. Tradeflow lets a business request an advance on a confirmed invoice, bill of lading or equipment order from its own portal. Its buyer confirms the document through a link, and investors fund it from theirs, by bank transfer or with USDC from their own wallet, and follow their positions in a portfolio. The business is paid out in fiat, and when the buyer pays, investors are repaid automatically. Every decision that depends on facts outside the chain is made by a Chainlink CRE workflow and lands onchain as a signed report:
- the credit review, run as a confidential (TEE) handler;
- lender KYC, and ordering the on-ramp to convert bank transfers, over Confidential HTTP;
- payouts and repayments, through log triggers with two-source consensus;
- risk and reserve monitoring, on a cron schedule with an onchain circuit breaker.

## How it works
- **Listing workflow (HTTP trigger, `handlerInTee`, AWS Nitro):**
  - Inside the enclave: fetches the business's credit file, the document registry record and a sanctions screen, then scores them.
  - Only the grade, APR, advance amount and a document hash leave the enclave.
  - Before writing, it checks the document was not financed already. Non-USD documents are priced with the Chainlink EUR/USD Data Feed.
- **Lender workflow:**
  - KYC over Confidential HTTP with a Vault DON secret, which issues the lender's ERC-3643 KYC claim and registers the wallet in the identity registry.
  - When the bank reports a lender's transfer, the workflow sets a price limit from the Data Feed and instructs the on-ramp over Confidential HTTP to convert it and deliver USDC to the market (sent once, idempotent by reference). It then checks the executed rate and that the USDC arrived before notes are issued.
- **Settlement workflow:**
  - An EVM log trigger on full funding instructs the fiat payout to the business.
  - The buyer's repayment is accepted only when the collection bank and the payment processor agree (node-mode consensus).
  - A second log trigger pays bank-transfer lenders back in fiat; wallet lenders claim USDC.
- **Tokenization (ERC-3643):**
  - Each loan is its own T-REX token (TFN1, TFN2, and so on), deployed by the market when the listing report lands.
  - Lenders hold ONCHAINID identities in a shared ERC-3643 identity registry. CRE is the trusted claim issuer: only the KYC workflow's report can write a lender's KYC claim, so only verified wallets can hold or receive notes, whether they lent by bank transfer or in USDC.
  - A late loan's token is paused until it is repaid.
- **Monitor workflow (cron):**
  - Marks overdue loans Late or Defaulted and freezes the business.
  - Runs a three-way reconciliation (bank books, on-ramp mints, onchain credits). A mismatch pauses new funding onchain until an operator resumes it.

## Product
- **Business portal (/business):** create an account, an overview of advances, amounts owed by buyers and repayments, every document with its status and buyer link, and a form to request financing with the document attached.
- **Investor portal (/investor):** start by bank transfer or with a wallet, pass KYC, then a portfolio (invested, expected returns, received, ready to claim, positions held as ERC-3643 notes) and a marketplace of open loans.
- **Buyer link:** the buyer confirms or disputes the document, and later pays it.
- **Operations console:** reserve checks, the funding circuit breaker and loan health.

## Built with
Chainlink CRE (TypeScript SDK; HTTP, cron and EVM log triggers; Confidential Workflows via `handlerInTee`; Confidential HTTP; consensus; EVM read and write through the CRE forwarder), the Chainlink EUR/USD Data Feed, Solidity (Foundry; ERC-3643 T-REX and ONCHAINID; the market contract as a CRE report receiver), Ethereum Sepolia, Bun, React and viem.

## Partner technology (Chainlink CRE track)
CRE is the orchestration layer of the whole product: four workflows, seven handlers, and every state change in the market contract arrives as a CRE report.

Confidential Workflow evidence:
- The listing handler is registered with `handlerInTee`.
- It processes the credit file, registry and sanctions responses, plus the rails API secret, inside the enclave.
- It was simulated successfully with the CRE CLI (`cre workflow simulate --broadcast`), writing real Sepolia transactions.
- The terminal output, including the CLI's TEE execution banner, is in the demo video and in `evidence/logs/` in the repo.

## Links
- Repo: https://github.com/Maadhav/tradeflow
- Project link (hosted demo video): (your video link)
- Slides: (Google Drive link to Tradeflow.pptx)
- CRE simulation evidence: https://github.com/Maadhav/tradeflow/tree/main/evidence (14 runs on Ethereum Sepolia with full terminal output and transaction links; the listing run shows the TEE execution banner)

## Team
Maadhav Sharma, Founder & CEO, CodeDecoders (the team behind GSOS).
