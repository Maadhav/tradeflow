// End-to-end check of the whole product against a running stack, through the same API the app uses:
// businesses sign up (and sign in) and enter their documents, buyers confirm, dispute and pay through
// the buyer portal, lenders sign up (KYC, with proof of wallet ownership) and fund by bank transfer or
// with a built-in wallet of their own.
// Every step runs the real CRE workflows (simulate --broadcast) and asserts the run result or the
// onchain state.
// Usage: bun scripts/e2e.ts [baseUrl]   (default http://localhost:8787, fresh stack from dev-up.sh)

import { generatePrivateKey, privateKeyToAccount } from '../services/rails/node_modules/viem/_esm/accounts/index.js'

const BASE = process.argv[2] ?? 'http://localhost:8787'
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

async function request(path: string, body?: unknown, headers: Record<string, string> = {}) {
  const res = await fetch(
    `${BASE}${path}`,
    body === undefined
      ? { headers }
      : { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) },
  )
  return { status: res.status, data: (await res.json()) as any }
}
async function call(path: string, body?: unknown, headers: Record<string, string> = {}) {
  const { status, data } = await request(path, body, headers)
  if (status >= 400) throw new Error(`${path}: ${status} ${data.error ?? ''}`)
  return data
}
const biz = (key: string) => ({ 'x-business-key': key })
function expect(cond: unknown, message: string): asserts cond {
  if (!cond) throw new Error(message)
}

const config = await call('/api/config')
const { market, stablecoin } = config.deployment as { market: string; stablecoin: string }

// ---- runs, loans and chain reads ----
const latestRun = async () => ((await call('/api/runs')) as any[])[0]?.id ?? 0

/** Wait for a run by id; fail with its last log lines if the run failed. */
async function waitRunId(id: number, timeoutMs = 300_000) {
  const start = Date.now()
  while (Date.now() - start < timeoutMs) {
    const r = await call(`/api/runs/${id}`)
    if (r.status === 'success') return r
    if (r.status === 'failed') throw new Error(`run ${id} ${r.handler} failed:\n${r.logs.slice(-8).join('\n')}`)
    await sleep(1000)
  }
  throw new Error(`timed out waiting for run ${id}`)
}

/** Wait for the first run of a handler queued after `after` (log-triggered runs). */
async function waitRun(after: number, handler: string, timeoutMs = 300_000) {
  const start = Date.now()
  while (Date.now() - start < timeoutMs) {
    const r = ((await call('/api/runs')) as any[]).find((x) => x.id > after && x.handler === handler)
    if (r) return waitRunId(r.id, timeoutMs - (Date.now() - start))
    await sleep(1000)
  }
  throw new Error(`timed out waiting for ${handler}`)
}

const loanByDoc = async (docHash: string) => (await call('/api/state')).loans.find((l: any) => l.docHash === docHash)
async function waitLoan(docHash: string, status: number, timeoutMs = 300_000) {
  const start = Date.now()
  while (Date.now() - start < timeoutMs) {
    const l = await loanByDoc(docHash)
    if (l?.status === status) return l
    await sleep(1000)
  }
  throw new Error(`loan never reached status ${status}`)
}

async function ethCall(to: string, data: string): Promise<string> {
  const res = await fetch(config.rpcUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_call', params: [{ to, data }, 'latest'] }),
  })
  return ((await res.json()) as any).result
}

// ---- calldata (ABI-encoded by hand: selectors of the allowlisted calls plus one that is not) ----
const word = (v: bigint | number | string) => BigInt(v).toString(16).padStart(64, '0')
const addr = (a: string) => a.toLowerCase().replace(/^0x/, '').padStart(64, '0')
const calldata = {
  approve: (spender: string, amount: bigint) => `0x095ea7b3${addr(spender)}${word(amount)}`,
  drip: () => '0x9f678cca',
  fund: (loanId: number, amount: bigint) => `0xa65e2cfd${word(loanId)}${word(amount)}`,
  claim: (loanId: number) => `0x379607f5${word(loanId)}`,
  transfer: (to: string, amount: bigint) => `0xa9059cbb${addr(to)}${word(amount)}`,
  frozenBorrower: (who: string) => `0x35f2a45d${addr(who)}`,
}
/** A built-in wallet of this run's own (as a browser without a wallet extension gets one). */
let wallet = { address: '', key: '' }
const walletHeaders = () => ({ 'x-wallet-key': wallet.key })
async function send(to: string, data: string) {
  const r = await call('/api/wallet/send', { from: wallet.address, to, data }, walletHeaders())
  expect(r.status === 'success', `wallet transaction ${r.hash} ${r.status}`)
  return r.hash as string
}

// ---- fixtures ----
const day = (offset: number) => new Date(Date.now() + offset * 86_400_000).toISOString().slice(0, 10)
const pdf = (title: string) => {
  const content = `BT /F1 14 Tf 24 90 Td (${title}) Tj ET`
  const body = [
    '%PDF-1.4',
    '1 0 obj <</Type /Catalog /Pages 2 0 R>> endobj',
    '2 0 obj <</Type /Pages /Kids [3 0 R] /Count 1>> endobj',
    '3 0 obj <</Type /Page /Parent 2 0 R /MediaBox [0 0 300 144] /Contents 4 0 R /Resources <</Font <</F1 5 0 R>>>>>> endobj',
    `4 0 obj <</Length ${content.length}>> stream\n${content}\nendstream endobj`,
    '5 0 obj <</Type /Font /Subtype /Type1 /BaseFont /Helvetica>> endobj',
    'trailer <</Root 1 0 R>>',
    '%%EOF',
  ].join('\n')
  return { name: `${title}.pdf`, type: 'application/pdf', base64: Buffer.from(body).toString('base64') }
}
const tokenOf = (buyerLink: string) => buyerLink.split('/').pop()!

let failures = 0
async function step(name: string, fn: () => Promise<string | void>) {
  const t = Date.now()
  try {
    const note = await fn()
    console.log(`  ok   ${name}${note ? ` (${note})` : ''} ${((Date.now() - t) / 1000).toFixed(0)}s`)
  } catch (e) {
    failures++
    console.log(`  FAIL ${name}\n       ${(e as Error).message.split('\n').join('\n       ')}`)
    throw e
  }
}

console.log(`Tradeflow end-to-end against ${BASE}`)
const ctx: Record<string, any> = {}
try {
  await step('Sierra Verde signs up, buyer confirms INV-2026-0142, listed', async () => {
    const { business, key } = await call('/api/businesses', {
      name: 'Sierra Verde Coffee Exporters',
      country: 'CO',
      registrationNumber: '900482115-3',
      bankAccount: 'CO-BANC-4471-2290',
      email: 'finance@sierraverde.co',
    })
    expect(typeof key === 'string' && key.length >= 32, 'sign-up returned no sign-in key')
    ctx.sierra = business
    ctx.sierraKey = key
    const again = await request('/api/businesses', {
      name: 'Someone Else Ltd',
      country: 'CO',
      registrationNumber: '900 482 115 3',
      bankAccount: 'GB00 OTHER 1234',
      email: 'someone@else.example',
    })
    expect(again.status === 409 && !again.data.business, `registering the same registration number again: expected 409, got ${again.status}`)
    const wrongEmail = await request('/api/business-sessions', { country: 'CO', registrationNumber: '900482115-3', email: 'someone@else.example' })
    expect(wrongEmail.status === 401 && !wrongEmail.data.key, `sign-in with the wrong email: expected 401, got ${wrongEmail.status}`)
    const signIn = await call('/api/business-sessions', { country: 'CO', registrationNumber: '900.482.115-3', email: 'Finance@SierraVerde.co' })
    expect(signIn.business.id === business.id && signIn.key && signIn.key !== key, 'signing in did not return the same business with a new key')
    const anon = await request(`/api/businesses/${business.id}`)
    expect(anon.status === 401, `business view without a key: expected 401, got ${anon.status}`)
    const forged = await request(`/api/businesses/${business.id}`, undefined, biz('not-the-key'))
    expect(forged.status === 401, `business view with a wrong key: expected 401, got ${forged.status}`)
    const anonDoc = await request('/api/documents', { businessId: business.id, type: 'invoice', number: 'X-1' })
    expect(anonDoc.status === 401, `document without a key: expected 401, got ${anonDoc.status}`)

    const reg = await call('/api/documents', {
      businessId: business.id,
      type: 'invoice',
      number: 'INV-2026-0142',
      buyer: 'Kaffeehaus Berlin GmbH',
      buyerEmail: 'payables@kaffeehaus-berlin.de',
      buyerCountry: 'DE',
      amountMinor: 925_000,
      currency: 'EUR',
      issuedAt: day(0),
      dueDate: day(60),
      description: '4 containers of washed Arabica',
      file: pdf('INV-2026-0142'),
    }, biz(key))
    expect(reg.document.status === 'awaiting_buyer' && reg.document.fileSha256, 'document not registered with its file')
    expect(reg.document.title === 'Invoice advance: 4 containers of washed Arabica', `unexpected title ${reg.document.title}`)
    ctx.inv = reg.document
    ctx.invToken = tokenOf(reg.buyerLink)

    const portal = await call(`/api/buyer/${ctx.invToken}`)
    expect(portal.business.name === business.name && !portal.document.token && !portal.document.buyerEmail, 'buyer portal shows the wrong view')
    const file = await fetch(`${BASE}/api/buyer/${ctx.invToken}/file`)
    expect(file.ok && (await file.text()).startsWith('%PDF-'), 'attached file not served to the buyer')

    const { runId } = await call(`/api/buyer/${ctx.invToken}/confirm`, { name: 'Jonas Weber' })
    const again2 = await request(`/api/buyer/${ctx.invToken}/confirm`, {})
    expect(again2.status === 409, 'a second confirmation was accepted')
    const r = await waitRunId(runId)
    expect(r.resultData?.listed, `not listed: ${r.resultData?.reason}`)
    expect(r.resultData.grade === 'A', `expected grade A, got ${r.resultData.grade}`)
    expect(r.logs.some((l: string) => l.includes('registry: document found, buyer confirmed')), 'listing run has no registry step log')
    const loan = await waitLoan(ctx.inv.docHash, 1)
    ctx.loan = loan
    const own = await call(`/api/businesses/${business.id}`, undefined, biz(key))
    const doc = own.documents.find((d: any) => d.number === 'INV-2026-0142')
    expect(doc?.review?.status === 'listed' && doc.buyerLink === reg.buyerLink, `business view: review ${JSON.stringify(doc?.review)}`)
    const retry = await request('/api/documents/review', { businessId: business.id, number: 'INV-2026-0142' }, biz(key))
    expect(retry.status === 409, `starting the review of a listed document again: expected 409, got ${retry.status}`)
    return `loan ${loan.id}, grade A, target $${Number(loan.target) / 1e6}`
  })

  await step('buyer disputes INV-2026-0999, listing rejected', async () => {
    const reg = await call('/api/documents', {
      businessId: ctx.sierra.id,
      type: 'invoice',
      number: 'INV-2026-0999',
      buyer: 'Northbrook Trading Ltd',
      buyerEmail: 'accounts@northbrook.co.uk',
      buyerCountry: 'GB',
      amountMinor: 5_000_000,
      currency: 'EUR',
      issuedAt: day(0),
      dueDate: day(60),
      description: 'specialty coffee lot',
    }, biz(ctx.sierraKey))
    const { runId } = await call(`/api/buyer/${tokenOf(reg.buyerLink)}/dispute`, { reason: 'We never ordered this lot.' })
    const r = await waitRunId(runId)
    expect(r.resultData?.listed === false, 'disputed document was listed')
    expect(r.resultData.reason === 'buyer disputed the document', `unexpected reason: ${r.resultData.reason}`)
    await sleep(500)
    const own = await call(`/api/businesses/${ctx.sierra.id}`, undefined, biz(ctx.sierraKey))
    const doc = own.documents.find((d: any) => d.number === 'INV-2026-0999')
    expect(doc?.review?.status === 'rejected' && doc.review.reason === 'buyer disputed the document', `review not kept on the document: ${JSON.stringify(doc?.review)}`)
    const retry = await request('/api/documents/review', { businessId: ctx.sierra.id, number: 'INV-2026-0999' }, biz(ctx.sierraKey))
    expect(retry.status === 409, `starting a decided review again: expected 409, got ${retry.status}`)
    return r.resultData.reason
  })

  await step('re-registering INV-2026-0142 for the same buyer is refused', async () => {
    const { status, data } = await request('/api/documents', {
      businessId: ctx.sierra.id,
      type: 'invoice',
      number: 'inv 2026 0142',
      buyer: 'Kaffeehaus Berlin GmbH',
      buyerEmail: 'payables@kaffeehaus-berlin.de',
      buyerCountry: 'DE',
      amountMinor: 925_000,
      currency: 'EUR',
      issuedAt: day(0),
      dueDate: day(60),
      description: '4 containers of washed Arabica',
    }, biz(ctx.sierraKey))
    expect(status === 409, `expected 409, got ${status}`)

    // Two submissions of a new document with a file at the same moment: only one is registered.
    const both = await Promise.all(
      [0, 1].map(() =>
        request('/api/documents', {
          businessId: ctx.sierra.id,
          type: 'invoice',
          number: 'INV-2026-0500',
          buyer: 'Cafe Lumen SAS',
          buyerEmail: 'compta@cafelumen.example',
          buyerCountry: 'FR',
          amountMinor: 120_000,
          currency: 'EUR',
          issuedAt: day(0),
          dueDate: day(30),
          description: 'roasted coffee samples',
          file: pdf('INV-2026-0500'),
        }, biz(ctx.sierraKey)),
      ),
    )
    const codes = both.map((x) => x.status).sort()
    expect(codes[0] === 201 && codes[1] === 409, `concurrent duplicate submissions: got ${codes.join(', ')}`)
    return data.error
  })

  await step('Ana Ruiz (bank transfer) verified onchain, EUR 3,000 credited', async () => {
    const { lender, runId } = await call('/api/lenders', {
      name: 'Ana Ruiz',
      email: 'ana.ruiz@example.es',
      country: 'ES',
      funding: 'fiat',
      bankAccount: 'ES91 2100 0418 4502 0005 1332',
    })
    ctx.ana = lender
    const kyc = await waitRunId(runId)
    expect(kyc.resultData?.verified, 'KYC not verified')
    const w = await call(`/api/wallet/${lender.wallet}`)
    expect(w.verified === true, 'lender wallet not verified onchain')

    const { intent } = await call('/api/onramp/intent', { lenderId: lender.id, loanId: ctx.loan.id, amountMinor: 300_000, currency: 'EUR' })
    // The same transfer reported twice at once is received once.
    const twice = await Promise.all([0, 1].map(() => request('/api/onramp/deposit-received', { reference: intent.reference })))
    const ok = twice.filter((x) => x.status === 200)
    expect(ok.length === 1 && twice.some((x) => x.status === 409), `concurrent deposits: got ${twice.map((x) => x.status).join(', ')}`)
    const res = ok[0].data
    expect(res.run.status === 'success' && res.intent.status === 'credited', 'deposit not credited')
    const deposits = (await call('/api/state')).bankCredits.filter((c: any) => c.reference === intent.reference)
    expect(deposits.length === 1, `bank booked ${deposits.length} credits for one transfer`)
    const loan = await loanByDoc(ctx.inv.docHash)
    expect(BigInt(loan.fiatFunded) === BigInt(res.intent.stablecoinAmount), 'credited amount not onchain')
    return `$${(Number(res.intent.stablecoinAmount) / 1e6).toFixed(2)}`
  })

  await step('USDC lenders must prove the wallet is theirs', async () => {
    expect(config.builtinWallets === true, 'the local deployment offers no built-in wallets')
    wallet = await call('/api/wallet/builtin', {})
    expect(wallet.address && wallet.key, 'no built-in wallet created')
    const other = await call('/api/wallet/builtin', {})
    expect(other.address !== wallet.address, 'two browsers got the same built-in wallet')
    const lender = { name: 'Mallory', email: 'mallory@example.com', country: 'KP', funding: 'stablecoin' }
    const bare = await request('/api/lenders', { ...lender, wallet: wallet.address })
    expect(bare.status === 401, `sign-up with someone else's wallet and no proof: expected 401, got ${bare.status}`)
    const wrongKey = await request('/api/lenders', { ...lender, wallet: wallet.address }, { 'x-wallet-key': other.key })
    expect(wrongKey.status === 401, `sign-up with another wallet's key: expected 401, got ${wrongKey.status}`)

    // A browser wallet signs the one-time challenge; a signature from any other key is refused.
    const owner = privateKeyToAccount(generatePrivateKey())
    const intruder = privateKeyToAccount(generatePrivateKey())
    const c1 = await call('/api/lenders/challenge', { wallet: owner.address })
    const forged = await request('/api/lenders', { ...lender, wallet: owner.address, nonce: c1.nonce, signature: await intruder.signMessage({ message: c1.message }) })
    expect(forged.status === 401, `sign-up signed by another key: expected 401, got ${forged.status}`)
    const replay = await request('/api/lenders', { ...lender, wallet: owner.address, nonce: c1.nonce, signature: await owner.signMessage({ message: c1.message }) })
    expect(replay.status === 401, `reusing a challenge: expected 401, got ${replay.status}`)
    const c2 = await call('/api/lenders/challenge', { wallet: owner.address })
    const chen = await request('/api/lenders', {
      name: 'Chen Wei',
      email: 'chen.wei@example.sg',
      country: 'SG',
      funding: 'stablecoin',
      wallet: owner.address,
      nonce: c2.nonce,
      signature: await owner.signMessage({ message: c2.message }),
    })
    expect(chen.status === 201 && chen.data.lender.wallet === owner.address, `signed sign-up: ${chen.status} ${chen.data.error ?? ''}`)
    expect((await waitRunId(chen.data.runId)).resultData?.verified, 'KYC of the signed-up wallet not verified')
    const state = await call('/api/state')
    expect(!state.lenders.some((l: any) => l.wallet === wallet.address), 'an unproven sign-up was stored')
  })

  await step('Ben Carter (USDC, his own built-in wallet) verified, funds the rest, payout runs', async () => {
    const { status, data } = await request('/api/lenders', {
      name: 'Ben Carter',
      email: 'ben.carter@example.com',
      country: 'US',
      funding: 'stablecoin',
      wallet: wallet.address,
    }, walletHeaders())
    expect(status === 201, `${status} ${data.error}`)
    ctx.ben = data.lender
    expect((await waitRunId(data.runId)).resultData?.verified, 'KYC not verified')
    expect((await call(`/api/wallet/${wallet.address}`)).verified === true, 'wallet not verified onchain')

    const loan = await loanByDoc(ctx.inv.docHash)
    const remaining = BigInt(loan.target) - BigInt(loan.funded)
    let w = await call(`/api/wallet/${wallet.address}`)
    expect(BigInt(w.usdc) === 0n && BigInt(w.eth) > 0n, 'a new built-in wallet should start with gas and no USDC')
    if (BigInt(w.usdc) < remaining) await send(stablecoin, calldata.drip())
    w = await call(`/api/wallet/${wallet.address}`)
    expect(BigInt(w.usdc) >= remaining, `wallet has ${w.usdc}, needs ${remaining}`)
    if (BigInt(w.allowance) < remaining) await send(stablecoin, calldata.approve(market, remaining))
    const after = await latestRun()
    await send(market, calldata.fund(loan.id, remaining))
    const r = await waitRun(after, 'disburse-on-funded')
    await waitLoan(ctx.inv.docHash, 3)
    return `$${Number(remaining) / 1e6} funded, payout ${r.resultData?.payoutRef}`
  })

  await step('buyer pays the full invoice: lenders repaid, balance to the business, Ana repaid to her bank, Ben claims', async () => {
    const before = await call(`/api/buyer/${ctx.invToken}`)
    expect(before.loan?.status === 3 && before.financing === 'financed', `loan not payable (status ${before.loan?.status})`)
    expect(before.collection?.account?.startsWith('DE'), 'a EUR invoice should be paid to the EUR collection account')
    const loan = await loanByDoc(ctx.inv.docHash)
    const owed = BigInt(loan.target) + (BigInt(loan.target) * BigInt(loan.aprBps) * BigInt(loan.tenorDays)) / (10_000n * 365n)
    const after = await latestRun()
    const paid = await call(`/api/buyer/${ctx.invToken}/pay`, {})
    expect(paid.amountMinor === 925_000 && paid.currency === 'EUR', `buyer was billed ${paid.amountMinor} ${paid.currency}, not the invoice amount`)
    expect(paid.run.status === 'success', `repayment not confirmed: ${paid.run.logs?.slice(-3).join(' | ')}`)
    const d = paid.run.resultData
    expect(BigInt(d.amount) === owed && BigInt(d.balance) > 0n && BigInt(d.paidUsd6) === owed + BigInt(d.balance), `split wrong: ${JSON.stringify(d)}`)
    const repaid = await waitLoan(ctx.inv.docHash, 4)
    expect(BigInt(repaid.repaidAmount) === owed, `lenders were repaid ${repaid.repaidAmount}, owed ${owed}`)
    const balance = (await call('/api/state')).payouts.find((p: any) => p.idempotencyKey === `balance-${loan.id}`)
    expect(balance && BigInt(balance.amount) === BigInt(d.balance) && balance.kind === 'business', 'balance not paid to the business')
    const red = await waitRun(after, 'redeem-fiat-lenders')
    expect(red.resultData?.redeemed?.some((x: any) => x.lender === ctx.ana.id), 'Ana was not repaid')
    const portal = await call(`/api/buyer/${ctx.invToken}`)
    expect(portal.loan.status === 4 && Number(portal.loan.repaidAt) > 0 && portal.payment?.amountMinor === 925_000, 'buyer portal does not show the invoice paid')

    const w = await call(`/api/wallet/${wallet.address}`)
    expect(BigInt(w.notes[String(ctx.loan.id)] ?? 0) > 0n, 'Ben holds no notes to claim')
    await send(market, calldata.claim(ctx.loan.id))
    const w2 = await call(`/api/wallet/${wallet.address}`)
    expect(!w2.notes[String(ctx.loan.id)] && BigInt(w2.usdc) > BigInt(w.usdc), 'claim did not pay out')
    return `paid EUR ${paid.amountMinor / 100}, $${(Number(owed) / 1e6).toFixed(2)} to lenders, $${(Number(d.balance) / 1e6).toFixed(2)} balance, Ben claimed $${(Number(BigInt(w2.usdc) - BigInt(w.usdc)) / 1e6).toFixed(2)}`
  })

  await step('monitor: reconciliation passes', async () => {
    const r = await call('/api/monitor/run', {})
    expect(r.resultData?.reconciliation?.ok === true, JSON.stringify(r.resultData?.reconciliation))
  })

  await step('monitor: unmatched deposit pauses funding until the books are corrected', async () => {
    await call('/api/ops/book-unmatched-deposit', {})
    const r = await call('/api/monitor/run', {})
    const s = await call('/api/state')
    expect(r.resultData?.reconciliation?.ok === false && s.snapshot.fundingPaused, 'circuit breaker did not trip')
    await call('/api/ops/correct-books', {})
    await call('/api/ops/resume', {})
    const r2 = await call('/api/monitor/run', {})
    const s2 = await call('/api/state')
    expect(r2.resultData?.reconciliation?.ok === true && !s2.snapshot.fundingPaused, 'books corrected but monitor still failing')
  })

  await step('Rapid Parts (grade D) funded, past maturity: marked late, business frozen', async () => {
    const { business, key } = await call('/api/businesses', {
      name: 'Rapid Parts Trading',
      country: 'AE',
      registrationNumber: 'CN-3307119',
      bankAccount: 'AE-ENBD-3307-1192',
      email: 'accounts@rapidparts.ae',
    })
    const reg = await call('/api/documents', {
      businessId: business.id,
      type: 'invoice',
      number: 'INV-2026-0388',
      buyer: 'Gulf Auto Services LLC',
      buyerEmail: 'ap@gulfauto.ae',
      buyerCountry: 'AE',
      amountMinor: 400_000,
      currency: 'USD',
      issuedAt: day(0),
      dueDate: day(1),
      description: 'spare parts order',
    }, biz(key))
    ctx.rapidToken = tokenOf(reg.buyerLink)
    const listed = await waitRunId((await call(`/api/buyer/${ctx.rapidToken}/confirm`, {})).runId)
    expect(listed.resultData?.listed && listed.resultData.grade === 'D', `expected grade D listed, got ${JSON.stringify(listed.resultData)}`)
    const loan = await waitLoan(reg.document.docHash, 1)

    let w = await call(`/api/wallet/${wallet.address}`)
    const amount = BigInt(loan.target)
    expect(BigInt(w.usdc) >= amount, `wallet has ${w.usdc}, needs ${amount}`)
    if (BigInt(w.allowance) < amount) await send(stablecoin, calldata.approve(market, amount))
    const after = await latestRun()
    await send(market, calldata.fund(loan.id, amount))
    await waitRun(after, 'disburse-on-funded')
    const disbursed = await waitLoan(reg.document.docHash, 3)

    // Demo clock: one loan day is 60 seconds. Wait past maturity, then run the monitor.
    const waitMs = Number(disbursed.maturity) * 1000 - Date.now() + 5_000
    if (waitMs > 0) await sleep(waitMs)
    let late: any
    for (let i = 0; i < 6 && !late; i++) {
      const r = await call('/api/monitor/run', {})
      late = r.resultData?.statusChanges?.find((c: any) => Number(c.loanId) === loan.id && c.status === 'late')
      if (!late) await sleep(10_000)
    }
    expect(late?.businessFrozen, 'monitor did not mark the loan late')
    await waitLoan(reg.document.docHash, 5)
    const frozen = await ethCall(market, calldata.frozenBorrower(business.wallet))
    expect(BigInt(frozen) === 1n, 'business not frozen onchain')
    const portal = await call(`/api/buyer/${ctx.rapidToken}`)
    expect(portal.loan.status === 5 && portal.collection?.account?.startsWith('US-ACH'), 'buyer portal does not show the invoice overdue')
    return `loan ${loan.id} late, ${business.name} frozen`
  })

  await step('built-in wallets sign only for their own browser, and only allowlisted calls', async () => {
    const send = (data: string, to = stablecoin, headers = walletHeaders()) => request('/api/wallet/send', { from: wallet.address, to, data }, headers)
    const transfer = await send(calldata.transfer(ctx.sierra.wallet, 1n))
    expect(transfer.status === 400, `transfer: expected 400, got ${transfer.status}`)
    const approveOther = await send(calldata.approve(ctx.sierra.wallet, 1n))
    expect(approveOther.status === 400, `approve to another spender: expected 400, got ${approveOther.status}`)
    const wrongTarget = await send(calldata.claim(1))
    expect(wrongTarget.status === 400, `claim on the stablecoin: expected 400, got ${wrongTarget.status}`)
    const noKey = await send(calldata.drip(), stablecoin, {})
    expect(noKey.status === 401, `send without the wallet key: expected 401, got ${noKey.status}`)
    return transfer.data.error
  })

  await step('no public response exposes emails, bank accounts, buyer links or keys', async () => {
    const [s, runs, buyerPortal, rapidPortal] = await Promise.all([
      call('/api/state'),
      call('/api/runs'),
      call(`/api/buyer/${ctx.invToken}`),
      call(`/api/buyer/${ctx.rapidToken}`),
    ])
    const secrets = [
      'finance@sierraverde.co',
      'accounts@rapidparts.ae',
      'payables@kaffeehaus-berlin.de',
      'accounts@northbrook.co.uk',
      'ap@gulfauto.ae',
      'ana.ruiz@example.es',
      'ben.carter@example.com',
      'ES91 2100',
      'CO-BANC-4471',
      'AE-ENBD-3307',
      ctx.invToken,
      ctx.rapidToken,
      ctx.sierraKey,
      wallet.key,
    ]
    const views: [string, unknown][] = [
      ['/api/state', s],
      ['/api/runs', runs],
      ['/api/buyer (Sierra Verde)', buyerPortal],
      ['/api/buyer (Rapid Parts)', rapidPortal],
    ]
    for (const [name, view] of views) {
      const text = JSON.stringify(view)
      for (const secret of secrets) expect(!text.includes(secret), `${name} leaks ${secret.slice(0, 6)}...`)
    }
    // The rails the workflows call answer only to this server's own key, not to a literal from the repo.
    const rails = await request('/v1/onramp/lenders?loanId=1', undefined, { 'x-api-key': 'sandbox-key-local' })
    expect(rails.status === 401, `the rails accepted the repo's old API key (${rails.status})`)
    // Buyer links appear only in the business's own, signed-in view.
    const own = JSON.stringify(await call(`/api/businesses/${ctx.sierra.id}`, undefined, biz(ctx.sierraKey)))
    expect(own.includes(ctx.invToken), "the business's own view lacks its buyer link")
    expect(s.documents.length >= 4 && s.businesses.length === 2 && s.lenders.length === 3, 'state is missing records')
  })
} catch {
  // reported by step()
}
console.log(failures ? `\n${failures} step failed` : '\nall steps passed')
process.exit(failures ? 1 : 0)
