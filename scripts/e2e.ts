// End-to-end check of the full loan lifecycle against a running stack.
// Every step runs the real CRE workflow (simulate --broadcast) and asserts the onchain result.
// Usage: bun scripts/e2e.ts [baseUrl]   (default http://localhost:8787, fresh stack from dev-up.sh)

const BASE = process.argv[2] ?? 'http://localhost:8787'
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

async function call(path: string, body?: unknown) {
  const res = await fetch(`${BASE}${path}`, body === undefined ? undefined : {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  })
  const data = await res.json()
  if (!res.ok) throw new Error(`${path}: ${data.error ?? res.status}`)
  return data
}

const runs = () => call('/api/runs') as Promise<any[]>
const latestRun = async () => (await runs())[0]?.id ?? 0
const loanByRef = async (ref: string) => (await call('/api/state')).loans.find((l: any) => l.ref === ref)

async function waitRun(after: number, handler: string, timeoutMs = 300_000) {
  const start = Date.now()
  while (Date.now() - start < timeoutMs) {
    const r = (await runs()).find((x) => x.id > after && x.handler === handler && ['success', 'failed'].includes(x.status))
    if (r) {
      if (r.status !== 'success') throw new Error(`${handler} failed:\n${r.logs.slice(-8).join('\n')}`)
      return r
    }
    await sleep(1000)
  }
  throw new Error(`timed out waiting for ${handler}`)
}

async function waitLoan(ref: string, status: number, timeoutMs = 300_000) {
  const start = Date.now()
  while (Date.now() - start < timeoutMs) {
    const l = await loanByRef(ref)
    if (l?.status === status) return l
    await sleep(1000)
  }
  throw new Error(`loan ${ref} never reached status ${status}`)
}

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

const REF = 'INV-2026-0142'
console.log(`Tradeflow end-to-end against ${BASE}`)
try {
  await step('listing: document verified in the TEE and listed', async () => {
    const after = await latestRun()
    await call('/api/business/submit', { docNumber: REF })
    const r = await waitRun(after, 'verify-and-list')
    if (!r.resultData?.listed) throw new Error(`not listed: ${r.resultData?.reason}`)
    return `grade ${r.resultData.grade}, target $${Number(r.resultData.target) / 1e6}`
  })

  await step('listing: unconfirmed document is rejected', async () => {
    const after = await latestRun()
    await call('/api/business/submit', { docNumber: 'INV-2026-0999' })
    const r = await waitRun(after, 'verify-and-list')
    if (r.resultData?.listed !== false) throw new Error('unconfirmed document was listed')
    return r.resultData.reason
  })

  const loan = await loanByRef(REF)

  await step('lender: bank-transfer deposit verified and credited', async () => {
    const { intent } = await call('/api/onramp/intent', { lenderId: 'lender-ana', loanId: loan.id, amountMinor: 300_000, currency: 'EUR' })
    const res = await call('/api/onramp/simulate-deposit', { reference: intent.reference })
    if (res.run.status !== 'success') throw new Error('deposit not credited')
    return `$${(Number(res.intent.stablecoinAmount) / 1e6).toFixed(2)}`
  })

  await step('lender: stablecoin lender passes KYC', async () => {
    const after = await latestRun()
    await call('/api/lender/onboard', { lenderId: 'lender-ben' })
    const r = await waitRun(after, 'verify-lender')
    if (!r.resultData?.verified) throw new Error('KYC not verified')
  })

  await step('settlement: full funding triggers the payout (log trigger)', async () => {
    const l = await loanByRef(REF)
    const remaining = (BigInt(l.target) - BigInt(l.funded)).toString()
    const after = await latestRun()
    await call('/api/demo-wallet/fund', { loanId: loan.id, amountUsd: Number(remaining) / 1e6 })
    const r = await waitRun(after, 'disburse-on-funded')
    await waitLoan(REF, 3)
    return r.resultData?.payoutRef
  })

  await step('settlement: repayment confirmed by two sources, fiat lender redeemed', async () => {
    const after = await latestRun()
    await call('/api/buyer/pay', { loanId: loan.id })
    await waitRun(after, 'confirm-repayment')
    await waitLoan(REF, 4)
    const red = await waitRun(after, 'redeem-fiat-lenders')
    if (!red.resultData?.redeemed?.length) throw new Error('no fiat lender redeemed')
    await call('/api/demo-wallet/claim', { loanId: loan.id })
    return `${red.resultData.redeemed.length} redeemed`
  })

  await step('monitor: reconciliation passes', async () => {
    const r = await call('/api/monitor/run', {})
    if (!r.resultData?.reconciliation?.ok) throw new Error(JSON.stringify(r.resultData?.reconciliation))
  })

  await step('monitor: books mismatch pauses funding', async () => {
    await call('/api/demo/tamper', {})
    const r = await call('/api/monitor/run', {})
    const s = await call('/api/state')
    await call('/api/demo/untamper', {})
    await call('/api/ops/resume', {})
    if (r.resultData?.reconciliation?.ok !== false || !s.snapshot.fundingPaused) throw new Error('circuit breaker did not trip')
  })
} catch {
  // reported by step()
}
console.log(failures ? `\n${failures} step failed` : '\nall steps passed')
process.exit(failures ? 1 : 0)
