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
| `lender` | HTTP (KYC done; deposit settled) | **Confidential HTTP** (Vault DON secret injected only in the enclave, single execution), EVM read of the Chainlink feed, the market and the ERC-3643 identity registry, EVM write | KYC: reports the lender's verified wallet and KYC country (ISO 3166 numeric), and the market registers it in the **ERC-3643 identity registry** with a KYC claim issued by CRE. For bank-transfer funding: fetches the deposit and KYC file confidentially, rejects the on-ramp's FX rate if it deviates from Chainlink EUR/USD by more than 1%, recomputes the stablecoin amount and confirms it really reached the market and the wallet is verified before crediting loan notes. |
| `settlement` | **EVM log** (`LoanFullyFunded`, `Repaid`) and HTTP (payment notice) | Log triggers, HTTP with consensus, `runInNodeMode` across two sources, EVM read of the Chainlink feed and the market, EVM write | Pays the business in fiat when a loan is fully funded (idempotent payout, then releases USDC to the off-ramp). Confirms the buyer's payment of the full document amount only when the collection bank **and** the buyer's payment processor agree on every node, values it with the Chainlink EUR/USD feed, marks the loan repaid with the lenders' share (advance plus interest) and pays the balance to the business. Pays bank-transfer lenders back to their bank when a loan is repaid. |
| `monitor` | **Cron** | EVM read, HTTP with consensus, EVM write | Marks overdue loans Late (then Defaulted), which pauses the loan's ERC-3643 token, and freezes the business. Three-way reconciliation every run: bank books = on-ramp mints = credited onchain, plus solvency. Any mismatch pauses new funding onchain (circuit breaker). |

Policy is enforced onchain, never trusted from a report: the market rejects grades or APRs outside
owner policy, frozen businesses, replayed references, and fiat credits whose stablecoins are not
actually in the contract.

## Architecture

```
 business enters document ──► buyer confirms (link) ──► listing (TEE) ──ListLoan──┐
 lender (bank) ──► on-ramp mints USDC ──► lender (Conf. HTTP) ──FiatFunding───────┤
 lender (own wallet) ────────────────────────────── approve + fund() ─────────────┤
                                                                                  ▼
                                  TradeflowMarket  (CRE ReceiverTemplate, one ERC-3643 token per loan)
                                       │ LoanFullyFunded            │ Repaid
                                       ▼                            ▼
                             settlement: pay business      settlement: repay fiat lenders
 buyer pays (link) ──► bank + payment processor ──► settlement: two-source confirm ──Repaid──►
 cron ──► monitor: late/default + three-way reconciliation ──► circuit breaker
```

- `contracts/`: Foundry. `TradeflowMarket` (receiver via Chainlink's `ReceiverTemplate`), which
  deploys an ERC-3643 (T-REX) token per loan; the shared ERC-3643 identity registry and
  `CreClaimIssuer` (see [Tokenization](#tokenization-erc-3643)); `TestStablecoin`.
- `cre/`: the CRE project (`listing`, `lender`, `settlement`, `monitor`), TypeScript SDK.
- `services/rails/`: the off-chain world the workflows talk to (document registry, credit bureau,
  sanctions, KYC, on-ramp, collection bank, payment processor, payout provider, operator books),
  the app API (sign-up, documents, buyer portal, wallet signer), the bridge that runs the workflows
  through `cre workflow simulate --broadcast` and streams their output, and the web app.

## The product, step by step

1. **A business signs up** at `/business` (Raise capital): legal name, country, company registration number, bank
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
4. **Lenders start investing** at `/investor` (Invest). Bank transfer: name, email, country and the
   bank account for repayments. USDC: connect a wallet and prove it is yours (a browser wallet signs a
   one-time message, which sends no transaction), then name, email and country. KYC runs through the
   `lender` workflow, which registers the wallet in the ERC-3643 identity registry, so it can hold
   loan notes. The browser gets an investor sign-in key (only its hash is stored); an investor signs
   in again by email (bank transfer) or by proving the wallet again (USDC).
5. **They fund** from the marketplace (`/investor/marketplace`), on the loan's page, with the method
   they signed up with. Bank transfer: transfer details, then the deposit lands, the on-ramp mints USDC
   into the market and the `lender` workflow checks it before crediting notes. USDC: the wallet
   signs `approve` and `fund` (and the faucet `drip` when it holds no USDC). Either way the market
   mints the loan's ERC-3643 token (`TFN<id>`) to the lender's wallet, one note per USDC unit.
6. **Fully funded**: `settlement` pays the business in fiat and starts the loan clock.
7. **The buyer pays the full document amount through the same link**, in the document's currency,
   to the collection account. The on-ramp converts the lenders' share (advance plus interest) into
   USDC in the market. `settlement` confirms the payment with the collection bank and the payment
   processor, values it with the EUR/USD feed, marks the loan repaid with the lenders' share, pays
   the balance to the business and pays bank-transfer lenders back to their bank; USDC lenders
   `claim` from their wallet. Both burn the lender's notes.
8. **`monitor`** marks overdue loans late (which pauses the loan's token, and freezes the business), and pauses new funding if the
   bank books, the on-ramp books and the market ever disagree. Operations can book an unmatched
   deposit to see it trip, correct the books and resume.

### The two portals

| Path | What it shows |
|---|---|
| `/` | The product, public figures, and the two ways in: Invest and Raise capital |
| `/investor` | Start investing or sign in; once signed in, the **Portfolio**: summary (invested, expected returns, received, ready to claim), positions with their notes, payouts and claims, bank-transfer deposits, and identity status |
| `/investor/marketplace`, `/investor/loans/:id` | Open loans, and each loan's page with the funding panel for the investor's own method and their position in it |
| `/business` | Create the business account or sign in; once signed in, the **Overview**: totals (advanced, owed by buyers, repaid, in review), the next item due, every document with its status and buyer link, recent reviews |
| `/business/new`, `/business/loans/:id` | Request financing (the document form, then the buyer link), and a read-only page for each of the business's loans with the buyer payment link |
| `/buyer/:token`, `/ops` | The buyer's page, and the operator console (linked from the footer) |

Each portal keeps its own session in the browser, so signing out of one leaves the other signed in.
Signing out also revokes that browser's key on the server. A key stops working after 30 days unused;
a sign-in never pushes out a key a browser is using, and sign-ins that prove only an email (or a
registration number) are limited to ten per account per hour.
Older `/loans/:id` links open the investor's loan page.

## Tokenization: ERC-3643

Loan notes are permissioned security tokens under **ERC-3643 (T-REX)**, the standard for tokens
that only verified investors may hold.

- **One token per loan.** When the `listing` report lands, the market deploys the loan's own T-REX
  token: an ERC-20 with 6 decimals named `Tradeflow Loan Note <id>`, symbol `TFN<id>`
  (`market.loanToken(id)`, event `LoanTokenDeployed`). Funding mints notes 1:1 with the USDC lent;
  a `claim` or a fiat redemption burns them. A lender's holding of loan N is
  `IERC20(loanToken(N)).balanceOf(lender)`.
- **One shared identity registry.** Every loan token checks the same ERC-3643 identity registry
  (`market.identityRegistry()`). A wallet is verified when `isVerified(wallet)` is true.
- **ONCHAINID identities.** Each verified lender gets an ONCHAINID identity, registered with the ISO
  3166 numeric code of their KYC country, holding a KYC claim (event `IdentityRegistered`). A KYC
  country without a numeric code is refused by the workflow, never registered as 0.
- **CRE as the trusted claim issuer.** The KYC claim is issued by `CreClaimIssuer`, the registry's
  trusted issuer, and is written only through `lender` workflow reports (action 2, `VerifyLender`:
  `(address lender, bool verified, bytes32 kycRef, uint16 country)`).
- **Pause on delinquency.** When `monitor` marks a loan Late or Defaulted, its token is paused and
  notes stop moving; Repaid unpauses it.

`contracts/deployments/<name>.json` holds `chainId`, `forwarder`, `market`, `stablecoin`,
`identityRegistry` and `claimIssuer`; loan tokens are found through the market. The app shows each
loan's token on the loan page (Verification, Loan notes) and `/api/state` returns it per loan
(`loanToken`).

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

`dev-up.sh` wipes the local state each time. The app reads the market's event history from the block
it was deployed in, found once (from forge's broadcast receipt, else a search of the chain) and kept
in the state file; set `DEPLOY_BLOCK` when the RPC has pruned that block. It reads events in windows
of `LOG_WINDOW` blocks (default 10,000, under the caps of public RPCs) and only scans new blocks after
that. Each workflow line in `.run/rails.log` is prefixed with
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
| `GET /api/businesses/:id` | The business's own documents with their buyer links, review status and loan once listed, and its overview: advanced, owed by buyers, repaid, in review, next due (needs `x-business-key`) |
| `POST /api/documents` | Enter a document, optional file; returns the buyer link (needs `x-business-key`) |
| `POST /api/documents/review` | Start the review again after a run that did not finish (needs `x-business-key`) |
| `GET /api/buyer/:token` | Buyer portal: the document, the supplier, whether it is financed and the loan once it is |
| `POST /api/buyer/:token/confirm`, `/dispute`, `/pay` | The buyer's answers; confirm and dispute start `listing`, pay (the full document amount) starts `settlement` |
| `POST /api/lenders/challenge`, `POST /api/lenders`, `POST /api/lenders/:id/kyc` | Lender sign-up with proof of wallet ownership (returns the investor's sign-in key), and KYC (runs `lender`) |
| `POST /api/investors/sign-in` | An investor signs in again: by email (bank transfer), or by wallet with a signed challenge or the built-in wallet's key (USDC); returns a new sign-in key |
| `POST /api/investors/:id/sign-out`, `POST /api/businesses/:id/sign-out` | Sign out: revokes the key sent (`x-investor-key` or `x-business-key`) |
| `GET /api/investors/:id/portfolio` | The investor's own portfolio: positions read from the chain (notes, principal, expected payout, received, claimable, payout reference), deposits, totals and identity status (needs `x-investor-key`) |
| `POST /api/onramp/intent`, `/deposit-received` | Bank-transfer funding |
| `POST /api/wallet/builtin`, `GET /api/wallet/:address`, `POST /api/wallet/send`, `GET /api/tx/:hash` | A browser's own built-in wallet (local only; `x-wallet-key`), balances, signing, transaction status |
| `POST /api/monitor/run`, `/api/ops/book-unmatched-deposit`, `/api/ops/correct-books`, `/api/ops/resume` | Operations |
| `GET /api/state`, `GET /api/runs`, `GET /api/runs/:id`, `GET /api/config` | Public state (never emails, bank accounts, buyer links or keys; each loan with its ERC-3643 `loanToken`), workflow runs, and the deployment (`identityRegistry`, `claimIssuer`) |

## Evidence

Simulation logs with transaction hashes are in [`evidence/`](evidence/).

---

Built by Maadhav Sharma at [CodeDecoders](https://codedecoders.io), the team behind
[GSOS](https://gsos.io), stablecoin infrastructure for licensed operators.
