# Tradeflow

**Real-world business credit, verified by Chainlink CRE.**

Exporters, shippers and manufacturers wait 60 to 180 days to be paid. Tradeflow lets them sell that
wait to lenders: a business signs up and enters an invoice, bill of lading or equipment order, its
buyer confirms the document through a link, and lenders fund it from a bank account or with
stablecoins from their own wallet. Every step that depends on off-chain truth (is the document real
and confirmed by the buyer, did the deposit arrive, did the business get paid, did the buyer pay, do
the books still agree) is decided by a **Chainlink CRE workflow**, which writes a signed report to
the market contract. Nothing moves onchain on someone's word.

Built during TOKEN2049 Origins (6 to 7 October 2026).

## How CRE runs the product

Four workflows, every core capability, each doing a real job:

| Workflow | Trigger | CRE capabilities | What it decides |
|---|---|---|---|
| `listing` | HTTP (the buyer confirms or disputes a document) | **Confidential Workflow (TEE)** with `handlerInTee`, HTTP inside the enclave, **EVM read** of the Chainlink EUR/USD Data Feed and the market, **EVM write** | Registry check (document found, buyer confirmed, not disputed), sanctions screen and a credit scorecard on the business's private credit file, in a handler declared for TEE execution (AWS Nitro) on a deployed DON (`cre workflow simulate` runs it locally). Only derived values cross back: grade, APR, advance, document hash. On the DON it refuses a document the market has already financed, prices non-USD documents with the FX feed and lists the loan. |
| `lender` | HTTP (KYC done; deposit settled) | **Confidential HTTP** (Vault DON secret injected only in the enclave, single execution), EVM read of the Chainlink feed and the market, EVM write | KYC allowlist for the loan notes. For bank-transfer funding: fetches the deposit and KYC file confidentially, rejects the on-ramp's FX rate if it deviates from Chainlink EUR/USD by more than 1%, recomputes the stablecoin amount and confirms it really reached the market before crediting notes. |
| `settlement` | **EVM log** (`LoanFullyFunded`, `Repaid`) and HTTP (payment notice) | Log triggers, HTTP with consensus, `runInNodeMode` across two sources, EVM read of the Chainlink feed and the market, EVM write | Pays the business in fiat when a loan is fully funded (idempotent payout, then releases USDC to the off-ramp). Confirms the buyer's payment of the full document amount only when the collection bank **and** the buyer's payment processor agree on every node, values it with the Chainlink EUR/USD feed, marks the loan repaid with the lenders' share (advance plus interest) and pays the balance to the business. Pays bank-transfer lenders back to their bank when a loan is repaid. |
| `monitor` | **Cron** | EVM read, HTTP with consensus, EVM write | Marks overdue loans Late (then Defaulted) and freezes the business. Three-way reconciliation every run: bank books = on-ramp mints = credited onchain, plus solvency. Any mismatch pauses new funding onchain (circuit breaker). |

Policy is enforced onchain, never trusted from a report: the market rejects grades or APRs outside
owner policy, frozen businesses, replayed references, and fiat credits whose stablecoins are not
actually in the contract.

## Architecture

```
 business enters document ──► buyer confirms (link) ──► listing (TEE) ──ListLoan──┐
 lender (bank) ──► on-ramp mints USDC ──► lender (Conf. HTTP) ──FiatFunding───────┤
 lender (own wallet) ────────────────────────────── approve + fund() ─────────────┤
                                                                                  ▼
                                  TradeflowMarket  (CRE ReceiverTemplate, KYC-gated ERC-1155 notes)
                                       │ LoanFullyFunded            │ Repaid
                                       ▼                            ▼
                             settlement: pay business      settlement: repay fiat lenders
 buyer pays (link) ──► bank + payment processor ──► settlement: two-source confirm ──Repaid──►
 cron ──► monitor: late/default + three-way reconciliation ──► circuit breaker
```

- `contracts/`: Foundry. `TradeflowMarket` (receiver via Chainlink's `ReceiverTemplate`),
  `LoanNotes` (ERC-1155, transferable only between KYC-verified holders), `TestStablecoin`.
- `cre/`: the CRE project (`listing`, `lender`, `settlement`, `monitor`), TypeScript SDK.
- `services/rails/`: the off-chain world the workflows talk to (document registry, credit bureau,
  sanctions, KYC, on-ramp, collection bank, payment processor, payout provider, operator books),
  the app API (sign-up, documents, buyer portal, wallet signer), the bridge that runs the workflows
  through `cre workflow simulate --broadcast` and streams their output, and the web app.

## The product, step by step

1. **A business signs up** on Raise capital: legal name, country, company registration number, bank
   account for payouts and work email. The server generates the business's onchain address (its key
   stays in a custody file on the server, never in a response) and gives the browser a sign-in key
   (only its hash is stored). A registered business signs in again with its country, registration
   number and the work email on file; registering the same company twice is refused.
2. **It enters a document** (invoice, bill of lading or equipment order): number, buyer, buyer email
   and country, amount in EUR or USD, issue and due dates, what is being sold, and optionally the
   file itself (PDF, PNG or JPG, up to 5 MB, hashed into the document hash). It gets a **buyer link**
   and sends it to the buyer (the app opens an email to the buyer's address with the link in it).
3. **The buyer opens the link** (`/buyer/<token>`), sees the document and confirms it or disputes it
   with a reason. Either answer starts the `listing` workflow: a confirmed document is scored and
   listed, a disputed one is rejected with `buyer disputed the document`. The outcome is kept on the
   document. If a run stops before the workflow decides (a server restart, a timeout), the business
   can start the review again; when the workflow says no, the buyer page tells the buyer to pay the
   supplier directly.
4. **Lenders sign up on a loan page.** Bank transfer: name, email, country and the bank account for
   repayments. USDC: connect a wallet and prove it is yours (a browser wallet signs a one-time
   message, which sends no transaction), then name, email and country. KYC runs through the `lender`
   workflow, which verifies the wallet for loan notes onchain.
5. **They fund.** Bank transfer: transfer details, then the deposit lands, the on-ramp mints USDC
   into the market and the `lender` workflow checks it before crediting notes. USDC: the wallet
   signs `approve` and `fund` (and the faucet `drip` when it holds no USDC).
6. **Fully funded**: `settlement` pays the business in fiat and starts the loan clock.
7. **The buyer pays the full document amount through the same link**, in the document's currency,
   to the collection account. The on-ramp converts the lenders' share (advance plus interest) into
   USDC in the market. `settlement` confirms the payment with the collection bank and the payment
   processor, values it with the EUR/USD feed, marks the loan repaid with the lenders' share, pays
   the balance to the business and pays bank-transfer lenders back to their bank; USDC lenders
   `claim` from their wallet.
8. **`monitor`** marks overdue loans late (and freezes the business), and pauses new funding if the
   bank books, the on-ramp books and the market ever disagree. Operations can book an unmatched
   deposit to see it trip, correct the books and resume.

**Wallets.** On Sepolia the app uses the lender's browser wallet. Locally (no browser wallet can
reach the anvil fork) each browser gets **its own built-in wallet**: a fresh key held in the
server's custody file, which signs only when the browser sends the wallet key it was given (kept in
that browser), and only four calls: `approve` (spender must be the market) and `drip` on the
stablecoin, `fund` and `claim` on the market. Anything else is refused. The local chain pays its
gas. No two browsers share a wallet, so every new lender goes through sign-up and KYC.

**Reference data of the third parties** (`services/rails/seed.ts`): the credit bureau has files for
four companies, and gives any other registration number a deterministic synthetic file derived from
`keccak256(country | registration number)`. The KYC provider rejects residents of KP, IR, SY and CU.

| Business | Country | Registration number |
|---|---|---|
| Sierra Verde Coffee Exporters | CO | 900482115-3 |
| Pacific Freight Lines | SG | 201412345K |
| Medina Textiles | MX | MTE180503KL2 |
| Rapid Parts Trading | AE | CN-3307119 |

## Run it locally

```bash
bash scripts/dev-up.sh       # anvil fork of Sepolia on :8545, fresh deployment, CRE config, app on :8787
open http://localhost:8787
tail -f .run/rails.log       # every workflow run, line by line, while it runs
bun scripts/e2e.ts           # the whole lifecycle through the API, asserting every run and onchain result
```

`dev-up.sh` wipes the local state each time. Each workflow line in `.run/rails.log` is prefixed with
its run, for example `[run 1 listing/verify-and-list] ... [USER LOG] registry: document found, buyer
confirmed`; the same lines stream into the expanded activity rows in the app. To follow only the
workflows' own step logs: `tail -f .run/rails.log | grep --line-buffered 'USER LOG'`.

The rails API key the workflows use is generated each time the app starts. The app writes it, with
the simulation signer, to its own env file (`services/rails/data/cre.local.env`, owner read/write
only, gitignored) and passes that file to the CLI, so no key is shared between deployments or kept
in the repo. Run any workflow directly with that file (business ids come from `/api/state`):

```bash
cd cre
cre workflow simulate listing --target local --non-interactive --trigger-index 0 --env ../services/rails/data/cre.local.env \
  --http-payload '{"borrowerId":"<business id>","docNumber":"INV-2026-0142","tenorDays":60}' --broadcast
cre workflow simulate monitor --target local --non-interactive --trigger-index 0 --env ../services/rails/data/cre.local.env --broadcast
```

Contracts: `cd contracts && forge test`.

### App API

| Endpoint | What it does |
|---|---|
| `POST /api/businesses` | Sign up a business; returns its sign-in key |
| `POST /api/business-sessions` | Sign a business in again: country, registration number and the work email on file |
| `GET /api/businesses/:id` | The business's own documents with their buyer links and review status (needs `x-business-key`) |
| `POST /api/documents` | Enter a document, optional file; returns the buyer link (needs `x-business-key`) |
| `POST /api/documents/review` | Start the review again after a run that did not finish (needs `x-business-key`) |
| `GET /api/buyer/:token` | Buyer portal: the document, the supplier, whether it is financed and the loan once it is |
| `POST /api/buyer/:token/confirm`, `/dispute`, `/pay` | The buyer's answers; confirm and dispute start `listing`, pay (the full document amount) starts `settlement` |
| `POST /api/lenders/challenge`, `POST /api/lenders`, `POST /api/lenders/:id/kyc` | Lender sign-up with proof of wallet ownership, and KYC (runs `lender`) |
| `POST /api/onramp/intent`, `/deposit-received` | Bank-transfer funding |
| `POST /api/wallet/builtin`, `GET /api/wallet/:address`, `POST /api/wallet/send`, `GET /api/tx/:hash` | A browser's own built-in wallet (local only; `x-wallet-key`), balances, signing, transaction status |
| `POST /api/monitor/run`, `/api/ops/book-unmatched-deposit`, `/api/ops/correct-books`, `/api/ops/resume` | Operations |
| `GET /api/state`, `GET /api/runs`, `GET /api/runs/:id`, `GET /api/config` | Public state (never emails, bank accounts, buyer links or keys) and workflow runs |

## Evidence

Simulation logs with transaction hashes are in [`evidence/`](evidence/).

---

Built by Maadhav Sharma at [CodeDecoders](https://codedecoders.io), the team behind
[GSOS](https://gsos.io), stablecoin infrastructure for licensed operators.
