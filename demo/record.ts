// Records a captioned walkthrough of the full Tradeflow flow against the local stack.
// Usage: bun run record.ts   (stack must be running: scripts/dev-up.sh)
// Output: demo/out/tradeflow-walkthrough.webm (+ .mp4 via ffmpeg)

import { chromium, type Page } from 'playwright'
import { mkdirSync, readdirSync, renameSync } from 'node:fs'

const BASE = process.env.BASE ?? 'http://localhost:8787'
const EXPLORER = process.env.EXPLORER // e.g. https://eth-sepolia.blockscout.com
const OUT_NAME = process.env.OUT_NAME ?? 'tradeflow-walkthrough'
const OUT = new URL('./out/', import.meta.url).pathname
mkdirSync(OUT, { recursive: true })

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))
const api = async (path: string) => (await fetch(`${BASE}${path}`)).json() as Promise<any>

async function caption(page: Page, title: string, body = '') {
  await page.evaluate(
    ([t, b]) => {
      let el = document.getElementById('__cap')
      if (!el) {
        el = document.createElement('div')
        el.id = '__cap'
        el.style.cssText =
          'position:fixed;left:50%;bottom:24px;transform:translateX(-50%);z-index:9999;max-width:880px;width:calc(100% - 48px);' +
          'background:rgba(15,29,46,.94);color:#fff;border-radius:12px;padding:14px 18px;font:15px/1.45 "Instrument Sans",system-ui,sans-serif;' +
          'box-shadow:0 10px 30px rgba(0,0,0,.25)'
        document.body.appendChild(el)
      }
      el.innerHTML = `<div style="font-weight:700;font-size:16px;margin-bottom:${b ? 4 : 0}px">${t}</div>${b ? `<div style="opacity:.85">${b}</div>` : ''}`
    },
    [title, body],
  )
}

/** Cut to the block explorer for a transaction, then come back to the app. */
async function showTx(page: Page, tx: string | undefined, title: string, body = '') {
  if (!EXPLORER || !tx) return
  const back = page.url()
  await page.goto(`${EXPLORER}/tx/${tx}`, { waitUntil: 'domcontentloaded', timeout: 60_000 }).catch(() => {})
  await sleep(3500)
  await caption(page, title, body)
  await sleep(6500)
  await page.goto(back, { waitUntil: 'domcontentloaded' })
  await sleep(2000)
}

async function showAddress(page: Page, address: string, title: string, body = '') {
  if (!EXPLORER) return
  const back = page.url()
  await page.goto(`${EXPLORER}/address/${address}`, { waitUntil: 'domcontentloaded', timeout: 60_000 }).catch(() => {})
  await sleep(3500)
  await caption(page, title, body)
  await sleep(6000)
  await page.goto(back, { waitUntil: 'domcontentloaded' })
  await sleep(2000)
}

async function latestRunId() {
  const runs = await api('/api/runs')
  return runs[0]?.id ?? 0
}

/** Wait until a run newer than `after` for this handler has finished. */
async function waitRun(after: number, handler: string, timeoutMs = 360_000) {
  const start = Date.now()
  while (Date.now() - start < timeoutMs) {
    const runs = await api('/api/runs')
    const r = runs.find((x: any) => x.id > after && x.handler === handler && (x.status === 'success' || x.status === 'failed'))
    if (r) return r
    await sleep(1500)
  }
  throw new Error(`timeout waiting for ${handler}`)
}

async function waitLoan(id: number, pred: (l: any) => boolean, timeoutMs = 360_000) {
  const start = Date.now()
  while (Date.now() - start < timeoutMs) {
    const s = await api('/api/state')
    const l = s.loans.find((x: any) => x.id === id)
    if (l && pred(l)) return l
    await sleep(1500)
  }
  throw new Error(`timeout waiting for loan ${id}`)
}

async function clickButton(page: Page, name: RegExp | string) {
  const b = page.getByRole('button', { name }).first()
  await b.scrollIntoViewIfNeeded()
  await b.click()
}

async function nav(page: Page, label: string) {
  await page.getByRole('link', { name: label, exact: true }).first().click()
  await sleep(1200)
}

async function main() {
  const browser = await chromium.launch({ headless: true })
  const context = await browser.newContext({
    viewport: { width: 1440, height: 900 },
    recordVideo: { dir: OUT, size: { width: 1440, height: 900 } },
  })
  const page = await context.newPage()
  await page.goto(BASE)
  await sleep(1500)

  // 1. Intro
  await caption(page, 'Tradeflow: real-world business credit, verified by Chainlink CRE', 'Businesses get paid now instead of waiting 60 to 180 days. Lenders fund from a bank account or with stablecoins. Every step that depends on off-chain truth runs through a CRE workflow.')
  await sleep(6000)
  const cfg = await api('/api/config')
  await showAddress(page, cfg.deployment.market, 'The market contract on Ethereum Sepolia', 'Every state change below arrives as a signed CRE report through the Chainlink forwarder. Watch the transactions appear here.')

  // 2. Business submits an invoice -> listing workflow (TEE)
  await nav(page, 'Business')
  await caption(page, 'Step 1. A coffee exporter submits an unpaid invoice', 'Sierra Verde (Colombia) is owed €9,250 by Kaffeehaus Berlin, due in 60 days. Click "Request financing".')
  await sleep(4000)
  let after = await latestRunId()
  const row = page.locator('div.row.between', { hasText: 'INV-2026-0142' })
  await row.getByRole('button', { name: 'Request financing' }).click()
  await caption(page, 'CRE listing workflow is running inside a TEE', 'Inside a secure enclave: document registry check, sanctions screening and a credit scorecard on the private credit file. Then Chainlink EUR/USD prices the invoice and the loan is listed onchain.')
  let run = await waitRun(after, 'verify-and-list')
  await sleep(2500)
  const d0 = run.resultData ?? {}
  await caption(
    page,
    `Listed: grade ${d0.grade}, ${(Number(d0.aprBps) / 100).toFixed(0)}% APR, $${(Number(d0.target) / 1e6).toLocaleString('en-US')} advance (EUR/USD ${(Number(d0.fxRateE8) / 1e8).toFixed(4)} from Chainlink)`,
    'Only derived values left the enclave: grade, APR, advance and a document hash. The credit file never did.',
  )
  await sleep(5000)
  await showTx(page, run.resultData?.tx, 'On Sepolia: the CRE listing report', 'Sent through the Chainlink forwarder to the market: LoanListed.')

  // 3. A bad document gets rejected
  after = await latestRunId()
  await page.locator('div.row.between', { hasText: 'INV-2026-0999' }).getByRole('button', { name: 'Request financing' }).click()
  await caption(page, 'A document the buyer never confirmed', 'Same workflow, different outcome: the registry says the buyer has not confirmed this invoice, so nothing is listed.')
  await waitRun(after, 'verify-and-list')
  await sleep(4500)

  // 4. Marketplace -> loan
  await nav(page, 'Marketplace')
  await caption(page, 'Step 2. The request appears on the marketplace', 'Verified by Chainlink CRE, with grade, APR, term and funding progress.')
  await sleep(4500)
  await page.locator('a.loan').first().click()
  await sleep(1500)
  await caption(page, 'Loan page', 'What CRE verified, the Chainlink FX rate used at listing, and the lifecycle of the loan.')
  await sleep(4500)

  // 5. Ana funds by bank transfer -> lender workflow (Confidential HTTP)
  await caption(page, 'Step 3. Ana funds €3,000 by bank transfer', 'She gets payment instructions from the on-ramp, like any bank transfer.')
  await page.locator('#fiat-amount').fill('3000')
  await sleep(1200)
  await clickButton(page, 'Get payment instructions')
  await sleep(3000)
  after = await latestRunId()
  await clickButton(page, 'Simulate the bank transfer arriving')
  await caption(page, 'Bank → on-ramp → CRE', 'The on-ramp converts EUR to USDC and mints it into the market. CRE fetches the deposit and Ana\'s KYC over Confidential HTTP, checks the on-ramp rate against Chainlink EUR/USD and confirms the USDC really arrived before crediting her notes.')
  run = await waitRun(after, 'credit-fiat-deposit')
  await sleep(3000)
  await caption(page, 'Ana is credited with loan notes', 'The notes are KYC-gated: they can only be held by verified wallets.')
  await sleep(4500)
  await showTx(page, run.resultData?.tx, 'On Sepolia: the CRE fiat-funding report', 'The market only credits notes because the on-ramped USDC is already sitting in the contract, unallocated.')

  // 6. Ben verifies KYC and funds the rest with USDC -> payout via log trigger
  await clickButton(page, 'Stablecoins')
  await sleep(1500)
  after = await latestRunId()
  await caption(page, 'Step 4. Ben funds the rest with USDC', 'First his KYC is verified by a CRE workflow over Confidential HTTP.')
  await clickButton(page, 'Verify KYC with CRE first')
  await waitRun(after, 'verify-lender')
  await sleep(6000)
  const loan = await waitLoan(1, () => true)
  const remaining = (BigInt(loan.target) - BigInt(loan.funded)).toString()
  await page.locator('#usdc-amount').fill((Number(remaining) / 1e6).toString())
  await sleep(1200)
  after = await latestRunId()
  await clickButton(page, 'Approve and fund')
  await caption(page, 'Fully funded → CRE pays the business', 'The LoanFullyFunded event triggers the settlement workflow: it instructs the payout provider to pay Sierra Verde in fiat, then releases the USDC to the off-ramp and starts the loan clock.')
  run = await waitRun(after, 'disburse-on-funded')
  await sleep(5000)
  await showTx(page, run.resultData?.tx, 'On Sepolia: CRE releases the funds', 'Started by the LoanFullyFunded event (EVM log trigger), after the fiat payout to the business was confirmed.')

  // 7. Buyer repays -> two-source confirmation -> fiat redemption via log trigger
  after = await latestRunId()
  await caption(page, 'Step 5. The buyer pays the invoice', 'CRE only marks the loan repaid when the collection bank AND the buyer\'s payment processor agree on the amount.')
  await clickButton(page, /Kaffeehaus Berlin GmbH pays|pays$/)
  const repay = await waitRun(after, 'confirm-repayment')
  await caption(page, 'Repaid → CRE pays Ana back to her bank', 'The Repaid event triggers another CRE run that pays every bank-transfer lender back in fiat. Ben claims his share onchain.')
  run = await waitRun(after, 'redeem-fiat-lenders')
  await sleep(4000)
  await showTx(page, repay.resultData?.tx, 'On Sepolia: repayment confirmed by two sources', 'The collection bank and the payment processor agreed on every node before this report was written.')
  await showTx(page, run.resultData?.redeemed?.[0]?.tx, 'On Sepolia: Ana redeemed to her bank', 'Her notes are burned and her share moves to the off-ramp, which pays her account in EUR.')
  await clickButton(page, /Claim as/)
  await sleep(6000)

  // 8. Operations: reconciliation + circuit breaker
  await nav(page, 'Operations')
  await caption(page, 'Step 6. Operations', 'Every CRE run, the fiat that moved through the rails, and the three-way reconciliation: bank books = on-ramp mints = credited onchain.')
  await sleep(5000)
  after = await latestRunId()
  await clickButton(page, 'Run CRE monitor now')
  await waitRun(after, 'watch-and-reconcile')
  await sleep(3500)
  await caption(page, 'Now someone books a deposit at the bank that never reached the chain', 'Click "Inject a books mismatch", then run the monitor again.')
  await clickButton(page, 'Inject a books mismatch')
  await sleep(3000)
  after = await latestRunId()
  await clickButton(page, 'Run CRE monitor now')
  run = await waitRun(after, 'watch-and-reconcile')
  await sleep(2500)
  await caption(page, 'Circuit breaker: funding paused onchain', 'CRE reported the mismatch and the market paused all new funding until an operator investigates.')
  await sleep(6000)
  await showTx(page, run.resultData?.reconciliation?.tx, 'On Sepolia: the failed reconciliation report', 'Reconciled(ok = false) and FundingPaused(true), written by the CRE monitor.')
  await clickButton(page, 'Correct the books')
  await sleep(2000)
  await clickButton(page, 'Resume funding')
  await sleep(4000)

  // 9. Overdue loan -> late + business frozen
  await nav(page, 'Business')
  after = await latestRunId()
  await caption(page, 'Step 7. A riskier business with a short invoice', 'Rapid Parts (UAE) is graded D at 19% APR. The demo clock runs 1 day = 60 seconds.')
  await page.locator('div.row.between', { hasText: 'INV-2026-0388' }).getByRole('button', { name: 'Request financing' }).click()
  await waitRun(after, 'verify-and-list')
  await sleep(3000)
  await nav(page, 'Marketplace')
  await page.locator('a.loan', { hasText: 'spare parts' }).first().click()
  await sleep(2000)
  await clickButton(page, 'Stablecoins')
  const l2 = (await api('/api/state')).loans.find((x: any) => x.ref === 'INV-2026-0388')
  await page.locator('#usdc-amount').fill((Number(l2.target) / 1e6).toString())
  after = await latestRunId()
  await clickButton(page, 'Approve and fund')
  await caption(page, 'Funded and paid out', 'The business is paid. Its invoice is due in one demo day.')
  await waitRun(after, 'disburse-on-funded')
  await caption(page, 'The buyer does not pay…', 'Waiting for the due date to pass.')
  await sleep(65_000)
  await nav(page, 'Operations')
  after = await latestRunId()
  await clickButton(page, 'Run CRE monitor now')
  await caption(page, 'CRE monitor: overdue', 'The scheduled monitor finds the loan past maturity, marks it Late and freezes the business so it cannot raise again.')
  run = await waitRun(after, 'watch-and-reconcile')
  await sleep(4000)
  await showTx(page, run.resultData?.statusChanges?.[0]?.tx, 'On Sepolia: loan marked Late, business frozen', 'StatusChanged and BorrowerFrozen, written by the CRE monitor.')
  await nav(page, 'Marketplace')
  await caption(page, 'That is Tradeflow', 'Four CRE workflows orchestrate the whole product: a TEE for private credit data, Confidential HTTP for bank and KYC APIs, log triggers for payouts and repayments, and a cron monitor for risk and reserves. Built at TOKEN2049 Origins by CodeDecoders, the team behind GSOS.')
  await sleep(9000)

  await context.close()
  await browser.close()
  const vid = readdirSync(OUT).filter((f) => f.endsWith('.webm') && !f.startsWith('tradeflow'))
  if (vid[0]) renameSync(`${OUT}${vid[0]}`, `${OUT}${OUT_NAME}.webm`)
  console.log('saved', `${OUT}${OUT_NAME}.webm`)
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
