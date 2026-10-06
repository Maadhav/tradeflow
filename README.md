# Tradeflow

**Real-world business credit, verified by Chainlink CRE.**

Exporters, shippers and manufacturers wait 60 to 180 days to be paid. Tradeflow lets them sell that
wait to lenders: a business submits an invoice, bill of lading or equipment order, and lenders fund
it from a bank account or with stablecoins. Every step that depends on off-chain truth (is the
invoice real, did the deposit arrive, did the business get paid, did the buyer pay, do the books
still agree) is decided by a **Chainlink CRE workflow**, which writes a signed report to the market
contract. Nothing moves onchain on someone's word.

Built during TOKEN2049 Origins (6 to 7 October 2026).

## How CRE runs the product

Four workflows, every core capability, each doing a real job:

| Workflow | Trigger | CRE capabilities | What it decides |
|---|---|---|---|
| `listing` | HTTP (business submits a document) | **Confidential Workflow (TEE)** with `handlerInTee`, HTTP inside the enclave, **EVM read** of the Chainlink EUR/USD Data Feed, **EVM write** | Registry check, sanctions screen and a credit scorecard run on the business's private credit file inside the enclave. Only derived values cross back: grade, APR, advance, document hash. The FX feed prices non-USD documents and the loan is listed. |
| `lender` | HTTP (KYC done; deposit settled) | **Confidential HTTP** (Vault DON secret injected only in the enclave, single execution), EVM read of the Chainlink feed and the market, EVM write | KYC allowlist for the loan notes. For bank-transfer funding: fetches the deposit and KYC file confidentially, rejects the on-ramp's FX rate if it deviates from Chainlink EUR/USD by more than 1%, recomputes the stablecoin amount and confirms it really reached the market before crediting notes. |
| `settlement` | **EVM log** (`LoanFullyFunded`, `Repaid`) and HTTP (payment notice) | Log triggers, HTTP with consensus, `runInNodeMode` across two sources, EVM read/write | Pays the business in fiat when a loan is fully funded (idempotent payout, then releases USDC to the off-ramp). Marks a loan repaid only when the collection bank **and** the buyer's payment processor agree on every node. Pays bank-transfer lenders back to their bank when a loan is repaid. |
| `monitor` | **Cron** | EVM read, HTTP with consensus, EVM write | Marks overdue loans Late (then Defaulted) and freezes the business. Three-way reconciliation every run: bank books = on-ramp mints = credited onchain, plus solvency. Any mismatch pauses new funding onchain (circuit breaker). |

Policy is enforced onchain, never trusted from a report: the market rejects grades or APRs outside
owner policy, frozen businesses, replayed references, and fiat credits whose stablecoins are not
actually in the contract.

## Architecture

```
 business ──submit──►  listing (TEE) ──ListLoan──────────┐
 lender (bank) ──► on-ramp mints USDC ──► lender (Conf. HTTP) ──FiatFunding──┤
 lender (USDC) ─────────────────────────────── fund() ───────────────────────┤
                                                                             ▼
                                  TradeflowMarket  (CRE ReceiverTemplate, KYC-gated ERC-1155 notes)
                                       │ LoanFullyFunded            │ Repaid
                                       ▼                            ▼
                             settlement: pay business      settlement: repay fiat lenders
 buyer pays ──► bank + payment processor ──► settlement: two-source confirm ──Repaid──►
 cron ──► monitor: late/default + three-way reconciliation ──► circuit breaker
```

- `contracts/`: Foundry. `TradeflowMarket` (receiver via Chainlink's `ReceiverTemplate`),
  `LoanNotes` (ERC-1155, transferable only between KYC-verified holders), `TestStablecoin`.
- `cre/`: the CRE project (`listing`, `lender`, `settlement`, `monitor`), TypeScript SDK.
- `services/rails/`: the off-chain world the workflows talk to (document registry, credit bureau,
  sanctions, KYC, on-ramp, collection bank, payment processor, payout provider, operator books),
  the bridge that runs the workflows through `cre workflow simulate --broadcast`, and the web app.

## Run it

```bash
./scripts/dev-up.sh          # anvil fork of Sepolia, deploy, configure CRE, start the app
open http://localhost:8787
```

Run any workflow directly:

```bash
cd cre
cre workflow simulate listing --target local --non-interactive --trigger-index 0 \
  --http-payload '{"borrowerId":"biz-sierra-verde","docNumber":"INV-2026-0142","tenorDays":60}' --broadcast
cre workflow simulate monitor --target local --non-interactive --trigger-index 0 --broadcast
```

Contracts: `cd contracts && forge test`.

## Evidence

Simulation logs with transaction hashes are in [`evidence/`](evidence/).

---

Built by Maadhav Sharma at [CodeDecoders](https://codedecoders.io), the team behind
[GSOS](https://gsos.io), stablecoin infrastructure for licensed operators.
