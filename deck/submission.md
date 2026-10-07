# Tradeflow: BuilderBase submission text

## Project name
Tradeflow

## Tagline
Fund the goods already on their way: invoice financing where every off-chain decision runs as a Chainlink CRE workflow and settles onchain.

## Short description
Small exporters wait 60 to 180 days to be paid for goods they have already shipped. Tradeflow lets a business request an advance on a confirmed invoice, bill of lading or equipment order. Its buyer confirms the document through a link, and lenders fund it by bank transfer or with USDC from their own wallet. The business is paid out in fiat, and when the buyer pays, lenders are repaid automatically. Every decision that depends on facts outside the chain is made by a Chainlink CRE workflow and lands onchain as a signed report:
- the credit review, run as a confidential (TEE) handler;
- lender KYC and fiat deposits, over Confidential HTTP;
- payouts and repayments, through log triggers with two-source consensus;
- risk and reserve monitoring, on a cron schedule with an onchain circuit breaker.

## How it works
- **Listing workflow (HTTP trigger, `handlerInTee`, AWS Nitro):**
  - Inside the enclave: fetches the business's credit file, the document registry record and a sanctions screen, then scores them.
  - Only the grade, APR, advance amount and a document hash leave the enclave.
  - Before writing, it checks the document was not financed already. Non-USD documents are priced with the Chainlink EUR/USD Data Feed.
- **Lender workflow:**
  - KYC over Confidential HTTP with a Vault DON secret, which allowlists the lender's wallet for KYC-gated ERC-1155 loan notes.
  - Bank-transfer deposits are verified over Confidential HTTP. The on-ramp's rate must stay within a tolerance of the Data Feed before notes are issued.
- **Settlement workflow:**
  - An EVM log trigger on full funding instructs the fiat payout to the business.
  - The buyer's repayment is accepted only when the collection bank and the payment processor agree (node-mode consensus).
  - A second log trigger pays bank-transfer lenders back in fiat; wallet lenders claim USDC.
- **Monitor workflow (cron):**
  - Marks overdue loans Late or Defaulted and freezes the business.
  - Runs a three-way reconciliation (bank books, on-ramp mints, onchain credits). A mismatch pauses new funding onchain until an operator resumes it.

## Built with
Chainlink CRE (TypeScript SDK; HTTP, cron and EVM log triggers; Confidential Workflows via `handlerInTee`; Confidential HTTP; consensus; EVM read and write through the CRE forwarder), the Chainlink EUR/USD Data Feed, Solidity (Foundry; ERC-1155 loan notes; the market contract as a CRE report receiver), Ethereum Sepolia, Bun, React and viem.

## Partner technology (Chainlink CRE track)
CRE is the orchestration layer of the whole product: four workflows, seven handlers, and every state change in the market contract arrives as a CRE report.

Confidential Workflow evidence:
- The listing handler is registered with `handlerInTee`.
- It processes the credit file, registry and sanctions responses, plus the rails API secret, inside the enclave.
- It was simulated successfully with the CRE CLI (`cre workflow simulate --broadcast`), writing real Sepolia transactions.
- The terminal output, including the CLI's TEE execution banner, is in the demo video and in `evidence/logs/` in the repo.

## Links
- Repo: https://github.com/Maadhav/tradeflow
- Live demo: (to add)
- Slides: (Google Drive link to Tradeflow.pptx, to add)
- Evidence: https://github.com/Maadhav/tradeflow/tree/main/evidence

## Team
Maadhav Sharma, Founder & CEO, CodeDecoders (the team behind GSOS).
