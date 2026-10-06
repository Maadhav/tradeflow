// Records a captioned walkthrough of Tradeflow in one continuous take: two businesses sign up and
// enter their own invoices, buyers confirm or dispute them through their links, two lenders sign up
// and fund (bank transfer and a wallet), the buyer pays, operations trips and clears the reserve
// circuit breaker, and an unpaid loan goes late.
// Usage: bun run record.ts   (stack must be running and fresh: bash scripts/dev-up.sh)
// Env: BASE (app, default http://localhost:8787), EXPLORER (block explorer for transaction
// cutaways, e.g. https://eth-sepolia.blockscout.com; leave unset locally), OUT_NAME (video name).
// Output: demo/out/<OUT_NAME>.webm (convert to .mp4 with ffmpeg)

import { chromium, type Locator, type Page } from 'playwright'
import { mkdirSync, renameSync } from 'node:fs'
import { writeInvoicePdf } from './invoice-pdf'

const BASE = process.env.BASE ?? 'http://localhost:8787'
const ORIGIN = new URL(BASE).origin
const EXPLORER = process.env.EXPLORER // e.g. https://eth-sepolia.blockscout.com
const OUT_NAME = process.env.OUT_NAME ?? 'tradeflow-walkthrough'
const OUT = new URL('./out/', import.meta.url).pathname
mkdirSync(OUT, { recursive: true })

const VIEW = { width: 1440, height: 900 }
const BAND = 112 // caption band under the app, so captions never cover it

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))
const api = async (path: string) => (await fetch(`${BASE}${path}`)).json() as Promise<any>
const pad = (n: number) => String(n).padStart(2, '0')
const day = (offset: number) => {
  const d = new Date()
  d.setDate(d.getDate() + offset)
  return d
}
const iso = (d: Date) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`
const usd = (usd6: string | number | bigint, digits = 0) =>
  (Number(BigInt(usd6)) / 1e6).toLocaleString('en-US', { style: 'currency', currency: 'USD', minimumFractionDigits: digits, maximumFractionDigits: digits })
const pct = (bps: number) => `${(Number(bps) / 100).toFixed(Number(bps) % 100 === 0 ? 0 : 1)}%`

// ---------------------------------------------------------------------------
// Stage: caption band, cursor, pacing
// ---------------------------------------------------------------------------

/**
 * Runs in every page of the app: the page scrolls inside the area above the caption band, toasts
 * sit above the band, and a cursor follows the mouse so viewers see what is clicked.
 */
function stage([origin, band]: [string, number]) {
  if (location.origin !== origin) return
  const scrollPage = window.scrollTo.bind(window)
  ;(window as any).scrollTo = (...args: any[]) => (document.body ? document.body.scrollTo(...(args as [number, number])) : scrollPage(...(args as [number, number])))
  const install = () => {
    if (document.getElementById('__stage')) return
    const style = document.createElement('style')
    style.id = '__stage'
    style.textContent =
      `html{height:100%;overflow:hidden}` +
      `body{height:calc(100vh - ${band}px)!important;min-height:0!important;overflow-y:auto;overflow-x:hidden}` +
      `.toast{bottom:${band + 20}px!important}` +
      `#__cursor{position:fixed;left:-40px;top:-40px;z-index:10001;pointer-events:none;width:22px;height:22px;transition:transform .12s}` +
      `#__cursor.down{transform:scale(.82)}` +
      `#__ring{position:fixed;z-index:10000;pointer-events:none;width:34px;height:34px;margin:-17px 0 0 -17px;border-radius:50%;border:3px solid #f2b705;opacity:0}` +
      `#__ring.go{animation:__ring .45s ease-out}` +
      `@keyframes __ring{from{opacity:.9;transform:scale(.4)}to{opacity:0;transform:scale(1.4)}}`
    document.head.appendChild(style)
    const cursor = document.createElement('div')
    cursor.id = '__cursor'
    cursor.innerHTML =
      '<svg width="22" height="22" viewBox="0 0 22 22"><path d="M3 2l14 9.2-6.3 1.1 3.7 6.9-2.6 1.4-3.7-6.9L3 18z" fill="#14202b" stroke="#fff" stroke-width="1.5" stroke-linejoin="round"/></svg>'
    const ring = document.createElement('div')
    ring.id = '__ring'
    document.body.append(cursor, ring)
    document.addEventListener('mousemove', (e) => ((cursor.style.left = `${e.clientX - 3}px`), (cursor.style.top = `${e.clientY - 2}px`)), true)
    document.addEventListener('mousedown', (e) => {
      cursor.classList.add('down')
      ring.style.left = `${e.clientX}px`
      ring.style.top = `${e.clientY}px`
      ring.classList.remove('go')
      void ring.offsetWidth
      ring.classList.add('go')
    }, true)
    document.addEventListener('mouseup', () => cursor.classList.remove('down'), true)
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', install)
  else install()
}

let shown = { title: '', body: '' }
async function paint(page: Page) {
  await page
    .evaluate(
      ([t, b, origin, band]) => {
        let el = document.getElementById('__cap')
        if (!el) {
          el = document.createElement('div')
          el.id = '__cap'
          document.body.appendChild(el)
        }
        const inApp = location.origin === origin
        el.style.cssText = inApp
          ? `position:fixed;left:0;right:0;bottom:0;height:${band}px;z-index:9999;background:#14202b;color:#fff;border-top:3px solid #f2b705;` +
            'font:15px/1.45 Archivo,system-ui,sans-serif;display:flex;align-items:center'
          : 'position:fixed;left:50%;bottom:24px;transform:translateX(-50%);z-index:9999;max-width:900px;width:calc(100% - 48px);' +
            'background:rgba(20,32,43,.95);color:#fff;border-radius:12px;padding:14px 18px;font:15px/1.45 Archivo,system-ui,sans-serif;box-shadow:0 10px 30px rgba(0,0,0,.25)'
        const inner = `<div style="font-weight:700;font-size:${inApp ? 19 : 16}px;margin-bottom:${b ? 4 : 0}px">${t}</div>${b ? `<div style="opacity:.86">${b}</div>` : ''}`
        el.innerHTML = inApp ? `<div style="max-width:1200px;width:100%;margin:0 auto;padding:0 24px;box-sizing:border-box">${inner}</div>` : inner
      },
      [shown.title, shown.body, ORIGIN, BAND] as [string, string, string, number],
    )
    .catch(() => {})
}

async function caption(page: Page, title: string, body = '') {
  shown = { title, body }
  await paint(page)
}

/** Shows a caption and holds it long enough to read at a brisk pace. */
async function say(page: Page, title: string, body = '', extraMs = 0) {
  await caption(page, title, body)
  const words = `${title} ${body}`.split(/\s+/).length
  await sleep(Math.min(9000, Math.max(2600, 900 + words * 210)) + extraMs)
}

let mouse = { x: VIEW.width / 2, y: (VIEW.height - BAND) / 2 }
async function glide(page: Page, x: number, y: number) {
  const steps = Math.max(8, Math.min(28, Math.round(Math.hypot(x - mouse.x, y - mouse.y) / 40)))
  await page.mouse.move(x, y, { steps })
  mouse = { x, y }
}

async function point(page: Page, target: Locator) {
  await target.scrollIntoViewIfNeeded()
  const box = await target.boundingBox()
  if (box) await glide(page, box.x + Math.min(box.width / 2, 120), box.y + box.height / 2)
}

async function click(page: Page, target: Locator) {
  await target.waitFor({ state: 'visible', timeout: 60_000 })
  await point(page, target)
  await sleep(180)
  await target.click()
  await sleep(250)
}

/** Types like a person: one key at a time, with a little variation. */
async function type(page: Page, target: Locator, text: string) {
  await click(page, target)
  for (const ch of text) {
    await page.keyboard.type(ch)
    await sleep(16 + Math.random() * 38)
  }
  await sleep(200)
}

async function choose(page: Page, target: Locator, value: string) {
  await point(page, target)
  await target.focus()
  await sleep(250)
  await target.selectOption(value)
  await sleep(350)
}

async function setDate(page: Page, target: Locator, value: string) {
  await point(page, target)
  await sleep(150)
  await target.fill(value)
  await sleep(350)
}

const button = (page: Page, name: string | RegExp) => page.getByRole('button', { name, exact: typeof name === 'string' }).first()

/** Scrolls an element into the middle of the stage, smoothly. */
async function reveal(target: Locator, block: 'start' | 'center' | 'end' = 'center') {
  await target.waitFor({ state: 'visible', timeout: 60_000 })
  await target.evaluate((el, b) => el.scrollIntoView({ behavior: 'smooth', block: b as ScrollLogicalPosition }), block)
  await sleep(700)
}

async function toTop(page: Page) {
  await page.evaluate(() => document.body.scrollTo({ top: 0, behavior: 'smooth' }))
  await sleep(600)
}

async function nav(page: Page, label: string) {
  await click(page, page.locator('nav.nav').getByRole('link', { name: label, exact: true }))
  await sleep(900)
}

/** Full navigation inside the app (a link opened from an email, a page reload). */
async function open(page: Page, url: string) {
  await page.goto(url, { waitUntil: 'domcontentloaded' })
  await page.locator('header.top').waitFor()
  await paint(page)
  await page.mouse.move(mouse.x, mouse.y)
  await sleep(1200)
}

const panel = (page: Page, title: string) => page.locator('section.panel').filter({ has: page.getByRole('heading', { name: title, exact: true }) })

// ---------------------------------------------------------------------------
// Copy and error audit (product UI only; the caption band is excluded)
// ---------------------------------------------------------------------------

const problems: string[] = []
const BANNED = /\b(chainlink|cre|workflows?|hackathon|sandbox|demo|tests?|simulat\w*|mock\w*)\b|[\u2013\u2014]/gi
async function audit(page: Page, where: string) {
  if (new URL(page.url()).origin !== ORIGIN) return
  const found = await page
    .evaluate((re) => {
      const clone = document.body.cloneNode(true) as HTMLElement
      clone.querySelectorAll('#__cap, #__cursor, #__ring, .log').forEach((n) => n.remove())
      const text = clone.innerText
      const bad = [...text.matchAll(new RegExp(re, 'gi'))].map((m) => text.slice(Math.max(0, m.index! - 30), m.index! + m[0].length + 30).replace(/\s+/g, ' '))
      const alerts = [...document.querySelectorAll('.toast.bad, [role=alert]')].map((n) => (n as HTMLElement).innerText.trim()).filter(Boolean)
      return { bad, alerts }
    }, BANNED.source)
    .catch(() => ({ bad: [] as string[], alerts: [] as string[] }))
  for (const b of found.bad) problems.push(`${where}: banned copy "${b}"`)
  for (const a of found.alerts) problems.push(`${where}: error shown "${a}"`)
}

// ---------------------------------------------------------------------------
// Runs, loans and the explorer
// ---------------------------------------------------------------------------

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
    if (r) {
      if (r.status === 'failed') problems.push(`run ${r.id} ${handler} failed`)
      return r
    }
    await sleep(1000)
  }
  throw new Error(`timeout waiting for ${handler}`)
}

async function waitLoan(ref: string, pred: (l: any) => boolean = () => true, timeoutMs = 360_000) {
  const start = Date.now()
  while (Date.now() - start < timeoutMs) {
    const s = await api('/api/state')
    const l = s.loans.find((x: any) => x.ref === ref)
    if (l && pred(l)) return l
    await sleep(1000)
  }
  throw new Error(`timeout waiting for loan ${ref}`)
}

/** Opens the newest activity row in a panel, preferably while its run is still going. */
async function openNewestRun(page: Page, panelTitle: string) {
  const row = panel(page, panelTitle).locator('details.event').first()
  await row.locator('.dot.running, .dot.queued').waitFor({ timeout: 20_000 }).catch(() => {})
  await reveal(row, 'start')
  await click(page, row.locator('summary'))
  return row
}

async function closeRun(page: Page, row: Locator) {
  if (await row.evaluate((d) => (d as HTMLDetailsElement).open).catch(() => false)) await click(page, row.locator('summary'))
}

async function chainTime(rpcUrl: string): Promise<number> {
  const res = await fetch(rpcUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_getBlockByNumber', params: ['latest', false] }),
  })
  return Number(((await res.json()) as any).result.timestamp)
}

const AD_HOSTS = /adx\.ws|id5-sync|czilladx|adbutler|coinzilla|slise|bitmedia|hypelab|sevio|adsterra|a-ads|cointraffic|getsalt|specify|ads\.|\/ads\/|doubleclick|googlesyndication|adform|revive/i

/** Runs in every explorer page: removes sponsored blocks whenever the explorer renders one. */
function hideExplorerAds() {
  if (!/blockscout/.test(location.host)) return
  const hide = (el: Element | null) => el instanceof HTMLElement && (el.style.display = 'none')
  const strip = () => {
    for (const el of Array.from(document.querySelectorAll('iframe, ins'))) el.remove()
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const text = (el.textContent ?? '').trim()
      if (text.length > 300) continue
      if (/casino|free spins|claim bonus/i.test(text) || /^Sponsored:/i.test(text)) hide(el)
      else if (/^Sponsored$/i.test(text)) {
        let label: Element = el
        while (!label.nextElementSibling && label.parentElement) label = label.parentElement
        hide(label)
        hide(label.nextElementSibling)
      }
    }
  }
  let queued = false
  const schedule = () => {
    if (queued) return
    queued = true
    requestAnimationFrame(() => ((queued = false), strip()))
  }
  new MutationObserver(schedule).observe(document, { childList: true, subtree: true, characterData: true })
}

/** Wait until the explorer has indexed the transaction, so it shows as confirmed. */
async function waitIndexed(tx: string, timeoutMs = 60_000) {
  const start = Date.now()
  while (Date.now() - start < timeoutMs) {
    try {
      const r = (await (await fetch(`${EXPLORER}/api/v2/transactions/${tx}`)).json()) as any
      if (r?.status === 'ok' && r?.block_number) return
    } catch {}
    await sleep(2500)
  }
}

/** Cut to the block explorer for a transaction, then come back to the app. */
async function showTx(page: Page, tx: string | undefined, title: string, body = '') {
  if (!EXPLORER || !tx) return
  const back = page.url()
  const keep = shown
  await waitIndexed(tx)
  await page.goto(`${EXPLORER}/tx/${tx}`, { waitUntil: 'domcontentloaded', timeout: 60_000 }).catch(() => {})
  await sleep(3500)
  await caption(page, title, body)
  await sleep(6500)
  shown = keep
  await open(page, back)
}

// ---------------------------------------------------------------------------
// Flows shared by both businesses
// ---------------------------------------------------------------------------

type Biz = { name: string; country: string; registration: string; bank: string; email: string }
type Doc = {
  number: string
  currency: 'EUR' | 'USD'
  amount: string
  buyer: string
  buyerEmail: string
  buyerCountry: string
  issued: Date
  due: Date
  description: string
  file?: string
}

async function signUpBusiness(page: Page, b: Biz) {
  await type(page, page.locator('#biz-name'), b.name)
  await choose(page, page.locator('#biz-country'), b.country)
  await type(page, page.locator('#biz-registrationNumber'), b.registration)
  await type(page, page.locator('#biz-bankAccount'), b.bank)
  await type(page, page.locator('#biz-email'), b.email)
  await click(page, button(page, 'Create business account'))
  await page.getByRole('heading', { name: 'Request financing', exact: true }).waitFor({ timeout: 30_000 })
  await sleep(1200)
}

/** Fills the request form and returns the buyer link the app creates. */
async function requestFinancing(page: Page, d: Doc, beforeSubmit?: () => Promise<void>) {
  await reveal(page.getByRole('heading', { name: 'Request financing', exact: true }), 'start')
  await type(page, page.locator('#doc-number'), d.number)
  if (d.currency !== 'EUR') await choose(page, page.getByLabel('Currency'), d.currency)
  await type(page, page.locator('#doc-amount'), d.amount)
  await type(page, page.locator('#doc-buyer'), d.buyer)
  await type(page, page.locator('#doc-buyerEmail'), d.buyerEmail)
  await choose(page, page.locator('#doc-buyerCountry'), d.buyerCountry)
  await setDate(page, page.locator('#doc-issuedAt'), iso(d.issued))
  await setDate(page, page.locator('#doc-dueDate'), iso(d.due))
  await type(page, page.locator('#doc-description'), d.description)
  if (d.file) {
    await point(page, page.locator('label.file'))
    await page.locator('#doc-file').setInputFiles(d.file)
    await sleep(900)
  }
  if (beforeSubmit) await beforeSubmit()
  await click(page, button(page, /Create buyer link|Send to buyer for confirmation/))
  const link = page.locator('.linkbox input').first()
  await link.waitFor({ timeout: 30_000 })
  await toTop(page)
  await sleep(800)
  return link.inputValue()
}

/** After a buyer responds: back on the business page, watch the review run stream live. */
async function watchReview(page: Page, after: number) {
  await open(page, `${BASE}/business`)
  const row = await openNewestRun(page, 'Recent reviews')
  const run = await waitRun(after, 'verify-and-list')
  await sleep(1800)
  return { run, row }
}

// ---------------------------------------------------------------------------
// The walkthrough
// ---------------------------------------------------------------------------

async function main() {
  const cfg = await api('/api/config')
  const net = cfg.deploymentName === 'sepolia' ? 'Ethereum Sepolia' : 'a local fork of Ethereum Sepolia'
  const invoice = writeInvoicePdf({ issued: day(0), due: day(60) })

  const browser = await chromium.launch({ headless: true })
  const context = await browser.newContext({ viewport: VIEW, recordVideo: { dir: OUT, size: VIEW } })
  await context.addInitScript(hideExplorerAds)
  await context.addInitScript(stage, [ORIGIN, BAND] as [string, number])
  await context.route('**/*', (route) => (AD_HOSTS.test(route.request().url()) ? route.abort() : route.continue()))
  const page = await context.newPage()
  page.on('pageerror', (e) => problems.push(`page error: ${e.message.split('\n')[0]}`))
  let after = 0
  let run: any

  // 1. Intro
  await open(page, BASE)
  await say(
    page,
    'Tradeflow: invoice financing that settles onchain',
    `Businesses sell unpaid invoices to lenders. Every decision that depends on off-chain facts runs as a Chainlink CRE workflow and lands onchain as a signed report. Recorded on ${net}.`,
    1500,
  )
  await audit(page, 'marketplace (empty)')

  // 2. Sierra Verde signs up and requests financing with its own invoice
  await nav(page, 'Raise capital')
  await say(page, 'A coffee exporter in Colombia signs up', 'Sierra Verde enters its own details. The registration number is how the credit bureau finds its file.')
  await signUpBusiness(page, {
    name: 'Sierra Verde Coffee Exporters',
    country: 'CO',
    registration: '900482115-3',
    bank: 'Bancolombia 112-345678-90',
    email: 'finance@sierraverde.co',
  })
  await caption(page, 'It requests financing for an unpaid invoice', 'INV-2026-0142: EUR 9,250 owed by Kaffeehaus Berlin, due in 60 days. The PDF is attached and its fingerprint goes into the document hash.')
  const link1 = await requestFinancing(page, {
    number: 'INV-2026-0142',
    currency: 'EUR',
    amount: '9250.00',
    buyer: 'Kaffeehaus Berlin GmbH',
    buyerEmail: 'payables@kaffeehaus-berlin.de',
    buyerCountry: 'DE',
    issued: day(0),
    due: day(60),
    description: '16 bags of specialty washed Arabica',
    file: invoice,
  })
  await say(page, 'Nothing is listed until the buyer confirms', 'The app creates a link for the buyer. Sierra Verde emails it to Kaffeehaus Berlin.')
  await audit(page, 'business: waiting for buyer')

  // 3. The buyer confirms; the listing workflow reviews it live
  await caption(page, 'The buyer opens the link', 'Kaffeehaus Berlin checks the supplier, amount, dates and the attached file.')
  await open(page, link1)
  await sleep(2500)
  await audit(page, 'buyer portal (pending)')
  await type(page, page.locator('#buyer-name'), 'Jonas Weber')
  after = await latestRunId()
  await click(page, button(page, 'Confirm invoice'))
  await caption(page, 'Invoice confirmed', "The buyer's answer starts the listing workflow.")
  await sleep(2200)
  await caption(
    page,
    'Listing workflow, streaming live',
    'The handler is declared for TEE execution (AWS Nitro) on a deployed DON. Here it runs in the CRE simulator (cre workflow simulate --broadcast), which writes real transactions.',
  )
  const review1 = await watchReview(page, after)
  run = review1.run
  await say(page, 'Confidential compute for the credit file', 'On a DON this handler runs in an enclave: the credit file is scored there, and only grade, APR, advance and a document hash leave it.')
  const d0 = run.resultData ?? {}
  await say(
    page,
    `Listed: grade ${d0.grade}, ${pct(d0.aprBps)} APR, ${usd(d0.target ?? 0)} advance`,
    `Priced with the Chainlink EUR/USD Data Feed at ${(Number(d0.fxRateE8) / 1e8).toFixed(4)}, then written onchain through the CRE forwarder.`,
  )
  await audit(page, 'business: listed')
  await closeRun(page, review1.row)
  await showTx(page, d0.tx, 'The listing report onchain', 'Delivered through the CRE forwarder to the market contract: LoanListed.')

  // 4. A second invoice, which the buyer disputes
  await caption(page, 'A second invoice: EUR 50,000 to Northbrook Trading, UK', 'Same business, a different buyer.')
  const link2 = await requestFinancing(page, {
    number: 'INV-2026-0999',
    currency: 'EUR',
    amount: '50000.00',
    buyer: 'Northbrook Trading Ltd',
    buyerEmail: 'ap@northbrook-trading.co.uk',
    buyerCountry: 'GB',
    issued: day(0),
    due: day(90),
    description: '87 bags of washed Arabica, Huila Supremo',
  })
  await caption(page, 'Northbrook does not recognise this invoice', 'The buyer disputes it and says why.')
  await open(page, link2)
  await sleep(1800)
  await click(page, button(page, 'Dispute'))
  await type(page, page.locator('#buyer-reason'), 'We have no order for this. Our only open order with Sierra Verde is PO 4471 for EUR 5,000.')
  after = await latestRunId()
  await click(page, button(page, 'Send dispute'))
  await sleep(1800)
  await audit(page, 'buyer portal (disputed)')
  await caption(page, 'The listing workflow rejects it', 'A dispute is a hard stop: nothing is written onchain.')
  const review2 = await watchReview(page, after)
  await say(page, 'Not approved: buyer disputed the document', "Sierra Verde sees the reason and the buyer's note.")
  await closeRun(page, review2.row)
  await reveal(panel(page, 'Your requests'), 'start')
  await sleep(2500)
  await audit(page, 'business: requests')

  // 5. The marketplace
  await nav(page, 'Marketplace')
  await say(page, 'The loan is on the marketplace', 'Lenders see the grade, APR, term and funding progress. Never the credit file.')
  await click(page, page.locator('a.loan').first())
  await say(page, 'The loan page', 'What was verified, the reference rate used at listing, and where the loan is in its life.')
  await audit(page, 'loan page (open)')

  // 6. Ana signs up and funds EUR 3,000 by bank transfer
  const loan1 = await waitLoan('INV-2026-0142')
  const fund = panel(page, 'Fund this loan')
  await reveal(fund, 'start')
  await caption(page, 'Ana lends from her bank account', 'She signs up on the Bank transfer tab: name, email, country and the account her repayments go to.')
  await type(page, page.locator('#lend-bank-name'), 'Ana Ruiz')
  await type(page, page.locator('#lend-bank-email'), 'ana.ruiz@example.com')
  await choose(page, page.locator('#lend-bank-country'), 'ES')
  await type(page, page.locator('#lend-bank-bankAccount'), 'ES91 2100 0418 4502 0005 1332')
  after = await latestRunId()
  await click(page, button(page, 'Verify identity to lend'))
  await caption(page, 'KYC over Confidential HTTP', 'The lender workflow fetches her KYC file over Confidential HTTP (the API secret is injected by the capability, not held in workflow code), then allowlists her for loan notes onchain.')
  await waitRun(after, 'verify-lender')
  await page.locator('#fiat-amount').waitFor({ timeout: 60_000 })
  await sleep(1500)
  await caption(page, 'Verified. She funds EUR 3,000', 'Transfer details with a reference, like any bank payment.')
  await type(page, page.locator('#fiat-amount'), '3000')
  await click(page, button(page, 'Get transfer details'))
  await button(page, "I've sent the transfer").waitFor({ timeout: 30_000 })
  await sleep(2500)
  after = await latestRunId()
  await click(page, button(page, "I've sent the transfer"))
  await caption(
    page,
    'The deposit is checked before any notes are issued',
    'The workflow reads the deposit over Confidential HTTP, checks the on-ramp rate against the EUR/USD Data Feed and confirms the USDC is in the market.',
  )
  run = await waitRun(after, 'credit-fiat-deposit')
  await page.getByText('in loan notes issued').first().waitFor({ timeout: 30_000 }).catch(() => {})
  await say(page, 'Ana holds loan notes', 'Credited onchain through the CRE forwarder. Notes can only be held by verified lenders.')
  await audit(page, 'loan page: bank transfer credited')
  await showTx(page, run.resultData?.tx, 'The funding report onchain', 'FiatFunding, written through the CRE forwarder after the deposit checks passed.')

  // 7. Ben connects a wallet, signs up and funds the rest in USDC
  await reveal(fund, 'start')
  await click(page, page.getByRole('tab', { name: 'USDC' }))
  await say(
    page,
    'Ben lends USDC from a wallet',
    cfg.builtinWallets
      ? 'No browser wallet can reach this local chain, so the app gives this browser its own wallet and signs for it on the server. On Sepolia lenders connect their own.'
      : 'He connects his own wallet and signs each transaction in it.',
  )
  await click(page, button(page, /Create a wallet|Connect wallet/))
  await page.locator('#lend-usdc-name').waitFor({ timeout: 30_000 })
  await type(page, page.locator('#lend-usdc-name'), 'Ben Carter')
  await type(page, page.locator('#lend-usdc-email'), 'ben.carter@example.com')
  await choose(page, page.locator('#lend-usdc-country'), 'US')
  after = await latestRunId()
  await click(page, button(page, 'Verify identity to lend'))
  await caption(page, 'Same KYC workflow, for a wallet', 'Approved, and the wallet is allowlisted for loan notes onchain.')
  await waitRun(after, 'verify-lender')
  await page.locator('#usdc-amount').waitFor({ timeout: 60_000 })
  await sleep(1500)
  await caption(page, 'Get USDC, then fund the rest', 'Each step is a wallet transaction: the faucet, then approve and fund.')
  await page.locator('.balance b', { hasText: '$' }).waitFor({ timeout: 30_000 })
  await sleep(600)
  const getUsdc = button(page, 'Get USDC')
  if (await getUsdc.isVisible().catch(() => false)) {
    await click(page, getUsdc)
    await page.getByText('USDC added to your wallet').first().waitFor({ timeout: 90_000 })
    await sleep(1500)
  }
  await click(page, button(page, 'Fund the rest'))
  await sleep(800)
  after = await latestRunId()
  await click(page, button(page, /^Fund \$/))
  await waitLoan('INV-2026-0142', (l) => Number(l.status) >= 2, 120_000)
  await caption(
    page,
    'Fully funded: the payout starts on its own',
    'The LoanFullyFunded event triggers the settlement workflow (EVM log trigger). It pays Sierra Verde in fiat, then releases the USDC and starts the loan clock.',
  )
  run = await waitRun(after, 'disburse-on-funded')
  await waitLoan('INV-2026-0142', (l) => Number(l.status) === 3)
  await sleep(2500)
  await toTop(page)
  await say(page, 'Paid out to Sierra Verde', `${usd(loan1.target)} advanced, in fiat, to its bank account.`)
  await audit(page, 'loan page: paid out')
  await showTx(page, run.resultData?.tx, 'The payout report onchain', 'Written after the fiat payout was confirmed. It releases the USDC and starts the loan clock.')

  // 8. The buyer pays through the same link; two sources must agree
  await caption(page, 'The buyer pays through the same link', 'The full invoice amount, in euros, to the collection account.')
  await open(page, link1)
  await reveal(page.getByRole('heading', { name: /^Pay this/ }), 'start')
  await sleep(1500)
  after = await latestRunId()
  await click(page, button(page, /^Pay /))
  await caption(
    page,
    'Repayment needs two sources to agree',
    'In node mode the workflow asks the collection bank and the payment processor; consensus marks the loan repaid only if both match. The EUR/USD feed values it.',
  )
  await page.getByText('Payment received').first().waitFor({ timeout: 180_000 })
  await sleep(2000)
  await audit(page, 'buyer portal: paid')
  await caption(page, 'Repaid. Ana is paid back to her bank', 'The Repaid event triggers another settlement run that pays bank-transfer lenders.')
  await waitRun(after, 'redeem-fiat-lenders')
  await open(page, `${BASE}/loans/${loan1.id}`)
  await reveal(panel(page, 'Repaid'), 'start')
  await say(page, 'Ben claims his share from his wallet', 'Advance plus interest, paid in USDC.')
  await click(page, button(page, /^Claim \$/))
  await page.locator('.progress-list li.done', { hasText: /^Claimed/ }).first().waitFor({ timeout: 90_000 })
  await sleep(1500)
  await reveal(panel(page, 'Lifecycle'), 'start')
  await say(page, 'Every step of the loan, settled', 'Verified, funded by bank transfer and USDC, paid out, repaid, and lenders paid back.')
  await audit(page, 'loan page: repaid and claimed')

  // 9. Operations: the reserve check and the circuit breaker
  await nav(page, 'Operations')
  await say(page, 'Operations: the reserve check', 'The monitor is a cron workflow; Run check fires the same trigger now. Bank books, on-ramp mints and onchain credits must agree.')
  after = await latestRunId()
  await click(page, button(page, 'Run check'))
  let row = await openNewestRun(page, 'Automated checks')
  run = await waitRun(after, 'watch-and-reconcile')
  after = run.id
  await sleep(1500)
  await toTop(page)
  await say(page, 'Reserves match', 'Bank, on-ramp and ledger agree, and the market is solvent.')
  await closeRun(page, row)
  await caption(page, 'Now the bank books a deposit that never reached the chain', 'An operator tool records it, so the books disagree.')
  await click(page, page.locator('details.tools > summary'))
  await click(page, button(page, 'Book unmatched deposit'))
  await sleep(1800)
  await toTop(page)
  await click(page, button(page, 'Run check'))
  row = await openNewestRun(page, 'Automated checks')
  run = await waitRun(after, 'watch-and-reconcile')
  after = run.id
  await sleep(1500)
  await toTop(page)
  await page.locator('.net', { hasText: 'Funding paused' }).waitFor({ timeout: 30_000 }).catch(() => {})
  await point(page, page.locator('.net'))
  await say(page, 'Mismatch: funding paused onchain', 'The monitor writes the failed reconciliation and the market stops new funding. The header shows it.')
  await audit(page, 'operations: paused')
  await closeRun(page, row)
  await showTx(page, run.resultData?.reconciliation?.tx, 'The failed reconciliation onchain', 'Reconciled(ok = false) and FundingPaused(true), written by the monitor.')
  await caption(page, 'The operator corrects the books and resumes funding', 'Then the check runs again.')
  await reveal(page.locator('details.tools'), 'center')
  await page.locator('details.tools').evaluate((d) => ((d as HTMLDetailsElement).open = true))
  await click(page, button(page, 'Correct the books'))
  await sleep(1500)
  await toTop(page)
  await click(page, button(page, 'Resume funding'))
  await sleep(2000)
  await click(page, button(page, 'Run check'))
  run = await waitRun(after, 'watch-and-reconcile')
  after = run.id
  await sleep(2000)
  await say(page, 'Books agree again', 'The check passes and funding is open.')
  await audit(page, 'operations: resumed')

  // 10. A riskier business with a 1-day invoice, which is not paid on time
  await nav(page, 'Raise capital')
  await caption(page, 'A second business: Rapid Parts Trading, UAE', 'It signs up the same way, with its own registration number.')
  await click(page, button(page, 'Switch business'))
  await signUpBusiness(page, {
    name: 'Rapid Parts Trading',
    country: 'AE',
    registration: 'CN-3307119',
    bank: 'AE07 0331 2345 6789 0123 456',
    email: 'finance@rapidparts.ae',
  })
  await caption(page, 'A USD 4,000 invoice, due tomorrow', 'Owed by Gulf Auto Services, issued 29 days ago.')
  const link3 = await requestFinancing(page, {
    number: 'INV-2026-0388',
    currency: 'USD',
    amount: '4000.00',
    buyer: 'Gulf Auto Services LLC',
    buyerEmail: 'accounts@gulfautoservices.ae',
    buyerCountry: 'AE',
    issued: day(-29),
    due: day(1),
    description: 'Brake kits and filters for a fleet service',
  })
  await caption(page, 'The buyer confirms', 'Same link, same review.')
  await open(page, link3)
  await sleep(1500)
  await type(page, page.locator('#buyer-name'), 'Omar Haddad')
  after = await latestRunId()
  await click(page, button(page, 'Confirm invoice'))
  await sleep(1500)
  await caption(page, 'Listing workflow, streaming live', 'A weaker credit file means a lower grade, a higher APR and a smaller advance.')
  const review3 = await watchReview(page, after)
  const d3 = review3.run.resultData ?? {}
  await say(page, `Listed: grade ${d3.grade}, ${pct(d3.aprBps)} APR, ${usd(d3.target ?? 0)} advance`, 'A USD invoice needs no conversion.')
  await closeRun(page, review3.row)
  await nav(page, 'Marketplace')
  await click(page, page.locator('a.loan', { hasText: 'Rapid Parts Trading' }).first())
  await reveal(panel(page, 'Fund this loan'), 'start')
  await click(page, page.getByRole('tab', { name: 'USDC' }))
  await caption(page, 'Ben funds it in full from his wallet', 'Already verified, so it is one amount and one click.')
  await page.locator('#usdc-amount').waitFor({ timeout: 30_000 })
  await click(page, button(page, 'Fund the rest'))
  after = await latestRunId()
  await click(page, button(page, /^Fund \$/))
  await waitLoan('INV-2026-0388', (l) => Number(l.status) >= 2, 120_000)
  await caption(page, 'Fully funded and paid out', 'The same log trigger pays Rapid Parts and starts a 1-day loan clock.')
  await waitRun(after, 'disburse-on-funded')
  const loan3 = await waitLoan('INV-2026-0388', (l) => Number(l.status) === 3)
  await sleep(2000)
  await toTop(page)
  const maturity = Number(loan3.maturity)
  const countdown = async () => {
    const left = Math.max(0, maturity + 2 - (await chainTime(cfg.rpcUrl)))
    await caption(
      page,
      'The buyer does not pay',
      `On this deployment the loan clock runs one day per minute. The 1-day term ends in ${left} s, then the cron monitor finds it past due.`,
    )
    return left
  }
  await countdown()
  await sleep(2500)
  await reveal(panel(page, 'Lifecycle'), 'start')
  for (let i = 0; i < 6 && (await countdown()) > 0; i++) await sleep(1000)
  await nav(page, 'Raise capital')
  for (let i = 0; i < 8 && (await countdown()) > 0; i++) await sleep(1000)
  await nav(page, 'Operations')
  while ((await countdown()) > 0) await sleep(1000)
  after = await latestRunId()
  await click(page, button(page, 'Run check'))
  row = await openNewestRun(page, 'Automated checks')
  run = await waitRun(after, 'watch-and-reconcile')
  await sleep(2000)
  await say(page, 'Late, and the business is frozen', 'The monitor marks the loan Late and freezes Rapid Parts onchain, so it cannot list again until it settles.')
  await closeRun(page, row)
  await showTx(page, run.resultData?.statusChanges?.[0]?.tx, 'Late status onchain', 'StatusChanged and BorrowerFrozen, written by the monitor.')
  await nav(page, 'Raise capital')
  await sleep(1500)
  await say(page, 'Rapid Parts sees why', 'New requests cannot be listed until the overdue invoice is settled.')
  await audit(page, 'business: frozen')

  // 11. Finale
  await nav(page, 'Marketplace')
  await say(
    page,
    'Tradeflow, run by four Chainlink CRE workflows',
    'A TEE-declared handler for credit files, Confidential HTTP for KYC and bank APIs, the EUR/USD Data Feed, log and cron triggers, two-source consensus, writes through the forwarder. Built by CodeDecoders, the team behind GSOS.',
    3000,
  )
  await audit(page, 'marketplace (final)')

  const video = page.video()
  await context.close()
  await browser.close()
  if (video) renameSync(await video.path(), `${OUT}${OUT_NAME}.webm`)
  console.log('saved', `${OUT}${OUT_NAME}.webm`)
  if (problems.length) console.log(`problems (${problems.length}):\n  ${[...new Set(problems)].join('\n  ')}`)
  else console.log('no problems found')
}

main().catch((e) => {
  console.error(e)
  if (problems.length) console.error(`problems so far:\n  ${problems.join('\n  ')}`)
  process.exit(1)
})
