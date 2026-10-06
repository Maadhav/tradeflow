import React, { useCallback, useEffect, useState } from 'react'
import { createRoot } from 'react-dom/client'

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

type Any = any
const STATUS: Record<number, { label: string; tone: string }> = {
  1: { label: 'Open', tone: 'open' },
  2: { label: 'Funded', tone: 'good' },
  3: { label: 'Active', tone: 'good' },
  4: { label: 'Repaid', tone: 'good' },
  5: { label: 'Late', tone: 'warn' },
  6: { label: 'Defaulted', tone: 'bad' },
}
const ASSET = ['Invoice advance', 'Bill of lading', 'Equipment finance', 'Working capital']
const GRADE = ['', 'A', 'B', 'C', 'D', 'E']
const COUNTRY: Record<string, string> = {
  CO: 'Colombia', DE: 'Germany', SG: 'Singapore', US: 'United States', MX: 'Mexico', AE: 'UAE', GB: 'United Kingdom', ES: 'Spain',
}

const usd = (v: string | number | bigint | undefined, digits = 0) =>
  (Number(BigInt(v ?? 0)) / 1e6).toLocaleString('en-US', { style: 'currency', currency: 'USD', minimumFractionDigits: digits, maximumFractionDigits: digits })
const money = (minor: number | string, ccy: string, digits = 0) =>
  (Number(minor) / 100).toLocaleString('en-US', { style: 'currency', currency: ccy, minimumFractionDigits: digits, maximumFractionDigits: digits })
const days = (n: number) => `${n} day${n === 1 ? '' : 's'}`
const pct = (bps: number) => `${(bps / 100).toFixed(bps % 100 === 0 ? 0 : 1)}%`
const rate = (e8: string | number) => (Number(e8) / 1e8).toFixed(4)
const ccyOf = (hex: string) => {
  try {
    return hex.slice(2).match(/../g)!.map((b) => String.fromCharCode(parseInt(b, 16))).join('')
  } catch {
    return 'USD'
  }
}
const short = (h?: string) => (h ? `${h.slice(0, 6)}…${h.slice(-4)}` : '')
const ago = (iso?: string) => {
  if (!iso) return ''
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000)
  if (s < 60) return 'just now'
  if (s < 3600) return `${Math.floor(s / 60)} min ago`
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`
  return new Date(iso).toLocaleDateString('en-GB', { day: 'numeric', month: 'short' })
}

async function api<T = Any>(path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, body === undefined ? undefined : { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
  const data = await res.json()
  if (!res.ok) throw new Error(data.error ?? `Request failed (${res.status})`)
  return data
}

// ---------------------------------------------------------------------------
// Live data
// ---------------------------------------------------------------------------

function useLive() {
  const [state, setState] = useState<Any>(null)
  const [runs, setRuns] = useState<Any[]>([])
  const [seed, setSeed] = useState<Any>(null)
  const [config, setConfig] = useState<Any>(null)
  const [wallet, setWallet] = useState<Any>(null)

  const refresh = useCallback(async () => {
    const [s, r, w] = await Promise.all([api('/api/state'), api('/api/runs'), api('/api/demo-wallet')])
    setState(s)
    setRuns(r)
    setWallet(w)
  }, [])

  useEffect(() => {
    api('/api/seed').then(setSeed)
    api('/api/config').then(setConfig)
    refresh()
    const t = setInterval(refresh, 6000)
    let ws: WebSocket | undefined
    let closed = false
    const connect = () => {
      ws = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws`)
      ws.onmessage = (m) => {
        const msg = JSON.parse(m.data)
        if (msg.type === 'run') {
          setRuns((prev) => [msg.data, ...prev.filter((x) => x.id !== msg.data.id)].sort((a, b) => b.id - a.id))
          if (msg.data.status === 'success' || msg.data.status === 'failed') refresh()
        } else refresh()
      }
      ws.onclose = () => {
        if (!closed) setTimeout(connect, 2000)
      }
    }
    connect()
    return () => {
      closed = true
      clearInterval(t)
      ws?.close()
    }
  }, [refresh])

  return { state, runs, seed, config, wallet, refresh }
}
type Live = ReturnType<typeof useLive>

const docFor = (live: Live, ref: string) => live.seed?.documents.find((d: Any) => d.number === ref)
const bizFor = (live: Live, wallet: string) => live.seed?.borrowers.find((b: Any) => b.wallet.toLowerCase() === String(wallet).toLowerCase())
const lenderFor = (live: Live, wallet: string) => live.seed?.lenders.find((l: Any) => l.wallet.toLowerCase() === String(wallet).toLowerCase())
const dueOf = (loan: Any) => BigInt(loan.target) + (BigInt(loan.target) * BigInt(loan.aprBps) * BigInt(loan.tenorDays)) / (10_000n * 365n)

// ---------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------

function usePath() {
  const [path, setPath] = useState(location.pathname)
  useEffect(() => {
    const on = () => setPath(location.pathname)
    window.addEventListener('popstate', on)
    return () => window.removeEventListener('popstate', on)
  }, [])
  const go = (p: string) => {
    history.pushState({}, '', p)
    setPath(p)
    window.scrollTo(0, 0)
  }
  return { path, go }
}

type Go = (p: string) => void
function Link({ to, go, className, children }: { to: string; go: Go; className?: string; children: React.ReactNode }) {
  return (
    <a
      href={to}
      className={className}
      onClick={(e) => {
        if (e.metaKey || e.ctrlKey) return
        e.preventDefault()
        go(to)
      }}
    >
      {children}
    </a>
  )
}

// ---------------------------------------------------------------------------
// Shared components
// ---------------------------------------------------------------------------

function useToast() {
  const [toast, setToast] = useState<{ text: string; bad?: boolean } | null>(null)
  useEffect(() => {
    if (!toast) return
    const t = setTimeout(() => setToast(null), 6000)
    return () => clearTimeout(t)
  }, [toast])
  return { toast, notify: (text: string, bad = false) => setToast({ text, bad }) }
}
type Notify = (text: string, bad?: boolean) => void

function useAction(live: Live, notify: Notify) {
  const [busy, setBusy] = useState('')
  const run = async (key: string, fn: () => Promise<unknown>, done?: string) => {
    setBusy(key)
    try {
      await fn()
      if (done) notify(done)
      await live.refresh()
      return true
    } catch (e) {
      notify((e as Error).message, true)
      return false
    } finally {
      setBusy('')
    }
  }
  return { busy, run }
}

function Tx({ h, live }: { h?: string; live: Live }) {
  if (!h) return null
  const base = live.config?.explorer
  return base ? (
    <a className="hash" href={`${base}/tx/${h}`} target="_blank" rel="noreferrer">
      {short(h)}
    </a>
  ) : (
    <span className="hash">{short(h)}</span>
  )
}

function Status({ s }: { s: number }) {
  const st = STATUS[s]
  return st ? <span className={`tag ${st.tone}`}>{st.label}</span> : null
}

function Lane({ from, to, progress, status }: { from?: string; to?: string; progress: number; status: number }) {
  const p = Math.max(0, Math.min(100, progress))
  const cls = status === 4 ? 'done' : status >= 5 ? 'late' : ''
  return (
    <div className="lane" aria-label={`${COUNTRY[from ?? ''] ?? from} to ${COUNTRY[to ?? ''] ?? to}, ${p.toFixed(0)}% funded`}>
      <div className="port">
        {from}
        <small>{COUNTRY[from ?? ''] ?? ''}</small>
      </div>
      <div className={`route ${cls}`}>
        <div className="sailed" style={{ width: `${p}%` }} />
        <div className="ship" style={{ left: `${p}%` }} />
      </div>
      <div className="port">
        {to}
        <small>{COUNTRY[to ?? ''] ?? ''}</small>
      </div>
    </div>
  )
}

const RUN_NAME: Record<string, string> = {
  'verify-and-list': 'Document review',
  'verify-lender': 'Lender verification',
  'credit-fiat-deposit': 'Deposit verification',
  'disburse-on-funded': 'Payout to business',
  'confirm-repayment': 'Repayment confirmation',
  'redeem-fiat-lenders': 'Payout to lenders',
  'watch-and-reconcile': 'Risk and reserve check',
}

function runSummary(run: Any, live: Live): string | null {
  const d = run.resultData
  if (run.status === 'failed') {
    const err = [...(run.logs ?? [])].reverse().find((l: string) => /error|rejected|failed/i.test(l) && !/Simulation/i.test(l))
    return err ? err.replace(/^.*?(Error:|error:)\s*/i, '').slice(0, 160) : 'Did not complete'
  }
  if (!d) return run.status === 'running' ? 'In progress' : run.status === 'queued' ? 'Waiting to start' : null
  switch (run.handler) {
    case 'verify-and-list':
      if (!d.listed) return `Not approved: ${d.reason}`
      return `Approved ${d.docNumber}: grade ${d.grade}, ${pct(d.aprBps)} APR, ${usd(d.target)} advance${d.currency === 'USD' ? '' : ` at ${d.currency}/USD ${rate(d.fxRateE8)}`}`
    case 'verify-lender': {
      const l = live.seed?.lenders.find((x: Any) => x.id === d.lenderId)
      return d.verified ? `${l?.name ?? d.lenderId} verified` : `${l?.name ?? d.lenderId} not verified (${d.status})`
    }
    case 'credit-fiat-deposit':
      return `${fiatText(d.fiat)} received, ${usd(d.stablecoins, 2)} credited at ${rate(d.providerRate)} (reference ${rate(d.chainlinkRate)})`
    case 'disburse-on-funded':
      return d.disbursed ? `${usd(d.amount)} paid to the business, ${d.payoutRef}` : `Skipped: ${d.reason}`
    case 'confirm-repayment':
      return `${usd(d.amount, 2)} from ${d.payer}, matched at the bank and the payment processor`
    case 'redeem-fiat-lenders':
      return d.redeemed?.length
        ? d.redeemed.map((r: Any) => `${live.seed?.lenders.find((x: Any) => x.id === r.lender)?.name ?? r.lender} paid ${usd(r.payout, 2)}`).join(', ')
        : 'No bank-transfer lenders on this loan'
    case 'watch-and-reconcile': {
      const changes = (d.statusChanges ?? []).map((c: Any) => `loan ${c.loanId} ${c.status}`).join(', ')
      return `${d.reconciliation?.ok ? 'Reserves match' : 'Reserve mismatch, funding paused'}${changes ? `; ${changes}, business frozen` : ''}`
    }
  }
  return null
}

/** Dot colour reflects the outcome, not just that the run finished. */
function runTone(run: Any): string {
  if (run.status !== 'success') return run.status
  const d = run.resultData ?? {}
  if (run.handler === 'watch-and-reconcile') return d.reconciliation?.ok === false ? 'bad' : d.statusChanges?.length ? 'warn' : 'success'
  if (run.handler === 'verify-and-list' && d.listed === false) return 'warn'
  if (run.handler === 'verify-lender' && d.verified === false) return 'warn'
  return 'success'
}

const fiatText = (s: string) => {
  const m = /^(\d+(?:\.\d+)?) (EUR|USD)$/.exec(s ?? '')
  return m ? money(Math.round(Number(m[1]) * 100), m[2]) : s
}

/** Only the workflow's own log lines and its result, without tool chatter. */
function runDetail(run: Any): string {
  const lines = (run.logs ?? [])
    .filter((l: string) => l.includes('[USER LOG]'))
    .map((l: string) => l.replace(/^.*\[USER LOG\]\s*/, ''))
  const result = run.resultData ? JSON.stringify(run.resultData, null, 2) : ''
  return [...lines, result].filter(Boolean).join('\n')
}

function Activity({ runs, live, empty }: { runs: Any[]; live: Live; empty: string }) {
  if (runs.length === 0) return <div className="empty">{empty}</div>
  return (
    <div className="activity">
      {runs.map((run) => {
        const summary = runSummary(run, live)
        const tx = run.resultData?.tx ?? run.resultData?.reconciliation?.tx ?? run.resultData?.redeemed?.[0]?.tx
        return (
          <details key={run.id} className="event">
            <summary>
              <span className={`dot ${runTone(run)}`} aria-label={run.status} />
              <span>
                <div className="name">{RUN_NAME[run.handler] ?? run.handler}</div>
                {summary ? <div className={`sum ${run.status === 'failed' ? 'bad' : ''}`}>{summary}</div> : null}
              </span>
              <span className="when">
                {ago(run.finishedAt ?? run.startedAt ?? run.queuedAt)}
                {tx ? (
                  <div>
                    <Tx h={tx} live={live} />
                  </div>
                ) : null}
              </span>
            </summary>
            {runDetail(run) ? <pre>{runDetail(run)}</pre> : null}
          </details>
        )
      })}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Marketplace
// ---------------------------------------------------------------------------

function LoanCard({ loan, live, go }: { loan: Any; live: Live; go: Go }) {
  const doc = docFor(live, loan.ref)
  const biz = bizFor(live, loan.borrower)
  const progress = Number((BigInt(loan.funded) * 1000n) / BigInt(loan.target || 1)) / 10
  return (
    <Link to={`/loans/${loan.id}`} go={go} className="loan">
      <div className="loan-top">
        <span className="kind">{ASSET[loan.assetType]}</span>
        <Status s={loan.status} />
      </div>
      <div className="row" style={{ alignItems: 'flex-start', flexWrap: 'nowrap', gap: 12 }}>
        <span className="grade" title="Risk grade">
          {GRADE[loan.riskGrade]}
        </span>
        <div>
          <div className="loan-title">{doc?.title ?? loan.ref}</div>
          <div className="loan-who">{biz?.name}</div>
        </div>
      </div>
      <Lane from={biz?.country} to={doc?.buyerCountry} progress={loan.status === 1 ? progress : 100} status={loan.status} />
      <div className="lane-caption">
        <span>
          {loan.status === 1
            ? `${usd(loan.funded)} raised`
            : loan.status === 4
              ? `Repaid ${usd(loan.repaidAmount)}`
              : loan.status >= 5
                ? 'Payment overdue'
                : loan.status === 3
                  ? `Due ${usd(dueOf(loan))}`
                  : 'Paying out'}
        </span>
        <span>{loan.status === 1 ? `${progress.toFixed(0)}% funded` : ''}</span>
      </div>
      <dl className="terms" style={{ margin: 0 }}>
        <div>
          <dt>APR</dt>
          <dd>{pct(loan.aprBps)}</dd>
        </div>
        <div>
          <dt>Term</dt>
          <dd>{days(loan.tenorDays)}</dd>
        </div>
        <div>
          <dt>Advance</dt>
          <dd>{usd(loan.target)}</dd>
        </div>
      </dl>
    </Link>
  )
}

function Marketplace({ live, go }: { live: Live; go: Go }) {
  const loans: Any[] = live.state?.loans ?? []
  const snap = live.state?.snapshot
  const financed = loans.filter((l) => l.status >= 3).reduce((s, l) => s + BigInt(l.target), 0n)
  const repaid = loans.filter((l) => l.status === 4).reduce((s, l) => s + BigInt(l.repaidAmount), 0n)
  const open = loans.filter((l) => l.status === 1)
  const ordered = [...open.slice().reverse(), ...loans.filter((l) => l.status !== 1).reverse()]
  return (
    <>
      <h1 className="display">Fund the goods already on their way.</h1>
      <p className="lede">
        Short-term financing for verified invoices and shipping documents. Lend from your bank account or in USDC, and get paid back when the buyer pays.
      </p>
      <div className="ledger">
        <div>
          <b>{usd(financed)}</b>
          <span>advanced to businesses</span>
        </div>
        <div>
          <b>{open.length}</b>
          <span>{open.length === 1 ? 'request open for funding' : 'requests open for funding'}</span>
        </div>
        <div>
          <b>{usd(repaid)}</b>
          <span>repaid to lenders</span>
        </div>
      </div>
      {snap?.fundingPaused ? (
        <div className="panel notice bad" style={{ marginBottom: 20, borderRadius: 'var(--r-md)' }}>
          New funding is paused while a reserve check is reviewed.
        </div>
      ) : null}
      <div className="page-head" style={{ marginBottom: 16 }}>
        <h2>Financing requests</h2>
      </div>
      {loans.length === 0 ? (
        <div className="panel empty">
          No financing requests yet.{' '}
          <Link to="/business" go={go}>
            Request financing for a document
          </Link>
          .
        </div>
      ) : (
        <div className="board">
          {ordered.map((l) => (
            <LoanCard key={l.id} loan={l} live={live} go={go} />
          ))}
        </div>
      )}
    </>
  )
}

// ---------------------------------------------------------------------------
// Loan page
// ---------------------------------------------------------------------------

function BankTransfer({ loan, live, notify }: { loan: Any; live: Live; notify: Notify }) {
  const ana = live.seed?.lenders.find((l: Any) => l.id === 'lender-ana')
  const { busy, run } = useAction(live, notify)
  const [amount, setAmount] = useState('')
  const [reference, setReference] = useState<string | null>(null)
  const intent = (live.state?.intents ?? []).find((i: Any) => i.reference === reference)
  const depositRun = live.runs.find((r) => r.handler === 'credit-fiat-deposit' && r.input.includes(reference ?? '~'))

  if (!reference || !intent) {
    return (
      <div className="stack">
        <div className="small muted">Paying from {ana?.name}'s EUR account ending {String(ana?.bankAccount ?? '').slice(-4)}.</div>
        <label className="field">
          Amount
          <div className="input">
            <span>EUR</span>
            <input id="fiat-amount" inputMode="decimal" placeholder="0" value={amount} onChange={(e) => setAmount(e.target.value.replace(/[^0-9.]/g, ''))} />
          </div>
        </label>
        <button
          className="btn primary block"
          disabled={!!busy || !Number(amount)}
          onClick={() =>
            run('intent', async () => {
              const r = await api('/api/onramp/intent', { lenderId: 'lender-ana', loanId: loan.id, amountMinor: Math.round(Number(amount) * 100), currency: 'EUR' })
              setReference(r.intent.reference)
            })
          }
        >
          Get transfer details
        </button>
      </div>
    )
  }

  const received = intent.status !== 'awaiting_funds'
  const credited = intent.status === 'credited'
  const verifying = received && !credited && depositRun && depositRun.status !== 'failed'
  return (
    <div className="stack">
      <dl className="instructions" style={{ margin: 0 }}>
        <div>
          <dt>Send</dt>
          <dd>{money(intent.amountMinor, intent.currency, 2)}</dd>
        </div>
        <div>
          <dt>To</dt>
          <dd>Tradeflow Client Funds, DE89 3704 0044 0532 0130 00</dd>
        </div>
        <div>
          <dt>Reference</dt>
          <dd className="code">{intent.reference}</dd>
        </div>
      </dl>
      {!received ? (
        <button
          className="btn primary block"
          disabled={!!busy}
          onClick={() => run('deposit', () => api('/api/onramp/simulate-deposit', { reference: intent.reference }))}
        >
          {busy === 'deposit' ? 'Waiting for your transfer…' : "I've sent the transfer"}
        </button>
      ) : null}
      <ul className="progress-list">
        <li className={received ? 'done' : busy === 'deposit' ? 'now' : ''}>Transfer received</li>
        <li className={received ? 'done' : ''}>Converted to USDC{intent.fxRateE8 ? ` at ${rate(intent.fxRateE8)}` : ''}</li>
        <li className={credited ? 'done' : verifying ? 'now' : ''}>Deposit verified</li>
        <li className={credited ? 'done' : ''}>{credited ? `${usd(intent.stablecoinAmount, 2)} in loan notes issued` : 'Loan notes issued'}</li>
      </ul>
      {credited ? (
        <button
          className="btn quiet block"
          onClick={() => {
            setReference(null)
            setAmount('')
          }}
        >
          Make another transfer
        </button>
      ) : null}
    </div>
  )
}

function UsdcFunding({ loan, live, notify }: { loan: Any; live: Live; notify: Notify }) {
  const { busy, run } = useAction(live, notify)
  const [amount, setAmount] = useState('')
  const remaining = Number(BigInt(loan.target) - BigInt(loan.funded)) / 1e6
  const w = live.wallet
  const kycRunning = live.runs.some((r) => r.handler === 'verify-lender' && (r.status === 'running' || r.status === 'queued'))
  if (!w) return null
  return (
    <div className="stack">
      <div className="small muted">
        Wallet {short(w.address)} holds {usd(w.usdc, 2)} USDC.
      </div>
      {!w.verified ? (
        <button className="btn primary block" disabled={!!busy || kycRunning} onClick={() => run('kyc', () => api('/api/lender/onboard', { lenderId: 'lender-ben' }))}>
          {kycRunning ? 'Verifying your identity…' : 'Verify identity to lend'}
        </button>
      ) : (
        <>
          <label className="field">
            Amount
            <div className="input">
              <span>USDC</span>
              <input id="usdc-amount" inputMode="decimal" placeholder={remaining.toLocaleString('en-US')} value={amount} onChange={(e) => setAmount(e.target.value.replace(/[^0-9.]/g, ''))} />
            </div>
          </label>
          <div className="row small" style={{ justifyContent: 'space-between' }}>
            <span className="muted">{usd(BigInt(loan.target) - BigInt(loan.funded), 2)} left to raise</span>
            <button className="btn quiet" style={{ padding: '4px 10px' }} onClick={() => setAmount(String(remaining))}>
              Fund the rest
            </button>
          </div>
          <button
            className="btn primary block"
            disabled={!!busy || !Number(amount)}
            onClick={() =>
              run('fund', () => api('/api/demo-wallet/fund', { loanId: loan.id, amountUsd: Number(amount) }), `Funded ${usd(Math.round(Number(amount) * 1e6), 2)}`).then(
                (ok) => ok && setAmount(''),
              )
            }
          >
            {busy === 'fund' ? 'Funding…' : amount ? `Fund ${usd(Math.round(Number(amount) * 1e6), 2)}` : 'Fund'}
          </button>
        </>
      )}
    </div>
  )
}

function LoanPage({ id, live, go, notify }: { id: number; live: Live; go: Go; notify: Notify }) {
  const loan = live.state?.loans?.find((l: Any) => l.id === id)
  const [tab, setTab] = useState<'bank' | 'usdc'>('bank')
  const { busy, run } = useAction(live, notify)
  if (!live.state) return <div className="empty">Loading…</div>
  if (!loan)
    return (
      <div className="panel empty">
        This loan does not exist.{' '}
        <Link to="/" go={go}>
          Back to the marketplace
        </Link>
      </div>
    )

  const doc = docFor(live, loan.ref)
  const biz = bizFor(live, loan.borrower)
  const ccy = ccyOf(loan.currency)
  const progress = Number((BigInt(loan.funded) * 1000n) / BigInt(loan.target || 1)) / 10
  const fundings = (live.state.fundings ?? []).filter((f: Any) => Number(f.loanId) === id)
  const loanRuns = live.runs.filter((r) => r.loanId === id || r.input.includes(loan.ref))
  const repayment = (live.state.bankCredits ?? []).find((c: Any) => c.kind === 'repayment' && c.reference.startsWith(`PAY-${id}-`))
  const disbursedPayout = (live.state.payouts ?? []).find((p: Any) => p.kind === 'business' && p.loanId === id)
  const held = BigInt(live.wallet?.notes?.[String(id)] ?? 0)
  const claimable = loan.status === 4 && held > 0n ? (held * BigInt(loan.repaidAmount)) / BigInt(loan.target) : 0n

  const steps = [
    { what: 'Verified and listed', detail: `Document and buyer confirmed, sanctions screened, credit reviewed privately (grade ${GRADE[loan.riskGrade]}).`, done: true },
    {
      what: 'Funded by lenders',
      detail: loan.status === 1 ? `${usd(loan.funded)} of ${usd(loan.target)} raised.` : `${usd(loan.target)} raised, ${usd(loan.fiatFunded)} by bank transfer.`,
      done: loan.status >= 2,
    },
    {
      what: 'Paid to the business',
      detail: disbursedPayout ? `${usd(disbursedPayout.amount)} sent to ${biz?.name}, ${disbursedPayout.payoutRef}.` : 'Paid out in local currency as soon as the loan is fully funded.',
      done: loan.status >= 3,
    },
    {
      what: loan.status === 5 ? 'Payment overdue' : loan.status === 6 ? 'Defaulted' : 'Repaid by the buyer',
      detail:
        loan.status === 4
          ? `${usd(loan.repaidAmount, 2)} received from ${doc?.buyer}.`
          : loan.status >= 5
            ? `${doc?.buyer} has not paid. ${biz?.name} cannot raise again until it is settled.`
            : `${usd(dueOf(loan), 2)} due from ${doc?.buyer} after ${days(loan.tenorDays)}.`,
      done: loan.status === 4,
      bad: loan.status >= 5,
    },
  ]
  const nowIdx = steps.findIndex((s) => !s.done && !s.bad)

  return (
    <>
      <div className="crumb">
        <Link to="/" go={go}>
          Marketplace
        </Link>{' '}
        / <span className="code">{loan.ref}</span>
      </div>
      <div className="page-head" style={{ marginBottom: 20 }}>
        <div>
          <h1>{doc?.title ?? loan.ref}</h1>
          <div className="muted" style={{ marginTop: 6 }}>
            {biz?.name}, selling to {doc?.buyer}
          </div>
        </div>
        <Status s={loan.status} />
      </div>

      <div className="split">
        <div className="stack" style={{ gap: 20 }}>
          <div className="panel panel-pad">
            <Lane from={biz?.country} to={doc?.buyerCountry} progress={loan.status === 1 ? progress : 100} status={loan.status} />
          </div>
          <dl className="facts" style={{ margin: 0 }}>
            <div>
              <dt>Advance</dt>
              <dd>{usd(loan.target)}</dd>
            </div>
            <div>
              <dt>APR</dt>
              <dd>{pct(loan.aprBps)}</dd>
            </div>
            <div>
              <dt>Term</dt>
              <dd>{days(loan.tenorDays)}</dd>
            </div>
            <div>
              <dt>Risk grade</dt>
              <dd>{GRADE[loan.riskGrade]}</dd>
            </div>
          </dl>

          <section className="panel">
            <div className="panel-head">
              <h2>Verification</h2>
              <span className="verified">Documents verified</span>
            </div>
            <table className="kv">
              <tbody>
                <tr>
                  <td>Document</td>
                  <td>
                    {ASSET[loan.assetType]} <span className="code">{loan.ref}</span> for {money(loan.faceValueMinor, ccy)}
                  </td>
                </tr>
                <tr>
                  <td>Buyer</td>
                  <td>
                    {doc?.buyer}, {COUNTRY[doc?.buyerCountry] ?? doc?.buyerCountry}. Confirmed with the document registry.
                  </td>
                </tr>
                <tr>
                  <td>Exchange rate</td>
                  <td>{ccy === 'USD' ? 'Priced in USD' : `${ccy}/USD ${rate(loan.fxRateE8)} reference rate at listing`}</td>
                </tr>
                <tr>
                  <td>Credit review</td>
                  <td>Grade {GRADE[loan.riskGrade]}. Run in a secure enclave: the business's financial data is never shared.</td>
                </tr>
                <tr>
                  <td>Fingerprint</td>
                  <td className="code">{short(loan.docHash)}</td>
                </tr>
              </tbody>
            </table>
          </section>

          <section className="panel">
            <div className="panel-head">
              <h2>Lifecycle</h2>
            </div>
            <ol className="steps">
              {steps.map((s, i) => (
                <li key={s.what} className={s.bad ? 'bad' : s.done ? 'done' : i === nowIdx ? 'now' : ''}>
                  <div>
                    <div className="what">{s.what}</div>
                    <div className="detail">{s.detail}</div>
                  </div>
                </li>
              ))}
            </ol>
          </section>

          <section className="panel">
            <div className="panel-head">
              <h2>Lenders</h2>
              <span className="small muted">{fundings.length}</span>
            </div>
            {fundings.length === 0 ? (
              <div className="empty">Be the first to fund this loan.</div>
            ) : (
              <div className="scroll">
                <table>
                  <thead>
                    <tr>
                      <th>Lender</th>
                      <th>Paid by</th>
                      <th className="r">Amount</th>
                      <th className="r">Transaction</th>
                    </tr>
                  </thead>
                  <tbody>
                    {fundings.map((f: Any) => (
                      <tr key={`${f.tx}-${f.lender}`}>
                        <td>{lenderFor(live, f.lender)?.name ?? short(f.lender)}</td>
                        <td>{f.viaFiat ? 'Bank transfer' : 'USDC'}</td>
                        <td className="r">{usd(f.amount, 2)}</td>
                        <td className="r">
                          <Tx h={f.tx} live={live} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        </div>

        <div className="stack" style={{ gap: 20 }}>
          {loan.status === 1 ? (
            <section className="panel panel-pad stack" style={{ gap: 16 }}>
              <h2>Fund this loan</h2>
              {live.state.snapshot?.fundingPaused ? (
                <div className="small" style={{ color: 'var(--bad)' }}>
                  Funding is paused while a reserve check is reviewed.
                </div>
              ) : (
                <>
                  <div className="tabs" role="tablist">
                    <button role="tab" aria-selected={tab === 'bank'} className={tab === 'bank' ? 'on' : ''} onClick={() => setTab('bank')}>
                      Bank transfer
                    </button>
                    <button role="tab" aria-selected={tab === 'usdc'} className={tab === 'usdc' ? 'on' : ''} onClick={() => setTab('usdc')}>
                      USDC
                    </button>
                  </div>
                  {tab === 'bank' ? <BankTransfer loan={loan} live={live} notify={notify} /> : <UsdcFunding loan={loan} live={live} notify={notify} />}
                </>
              )}
            </section>
          ) : null}

          {loan.status === 3 || loan.status === 5 ? (
            <section className="panel panel-pad stack">
              <h2>Repayment</h2>
              <div className="small muted">
                {usd(dueOf(loan), 2)} due from {doc?.buyer}. Lenders are paid once the bank and the payment processor both confirm the payment.
              </div>
              <button className="btn block" disabled={!!busy} onClick={() => run('pay', () => api('/api/buyer/pay', { loanId: id }), 'Repayment confirmed')}>
                {busy === 'pay' ? 'Confirming payment…' : 'Collect repayment'}
              </button>
            </section>
          ) : null}

          {loan.status === 4 ? (
            <section className="panel panel-pad stack">
              <h2>Repaid</h2>
              <div className="small muted">
                {usd(loan.repaidAmount, 2)} received{repayment ? ` (${repayment.reference})` : ''}. Bank-transfer lenders have been paid to their accounts.
              </div>
              {claimable > 0n ? (
                <button className="btn primary block" disabled={!!busy} onClick={() => run('claim', () => api('/api/demo-wallet/claim', { loanId: id }), `Claimed ${usd(claimable, 2)}`)}>
                  {busy === 'claim' ? 'Claiming…' : `Claim ${usd(claimable, 2)}`}
                </button>
              ) : (
                <div className="small muted">Your wallet has claimed its share.</div>
              )}
            </section>
          ) : null}

          <section className="panel">
            <div className="panel-head">
              <h2>Activity</h2>
            </div>
            <Activity runs={loanRuns.slice(0, 10)} live={live} empty="Activity on this loan will appear here." />
          </section>
        </div>
      </div>
    </>
  )
}

// ---------------------------------------------------------------------------
// Raise capital (business)
// ---------------------------------------------------------------------------

function Business({ live, notify }: { live: Live; notify: Notify }) {
  const { busy, run } = useAction(live, notify)
  const listed = new Set((live.state?.loans ?? []).map((l: Any) => l.ref))
  const reviewing = new Set(
    live.runs.filter((r) => r.handler === 'verify-and-list' && (r.status === 'running' || r.status === 'queued')).map((r) => JSON.parse(r.input).docNumber),
  )
  const declined = new Map(
    live.runs
      .filter((r) => r.handler === 'verify-and-list' && r.resultData && !r.resultData.listed)
      .map((r) => [r.resultData.docNumber, r.resultData.reason]),
  )
  return (
    <>
      <h1 className="display">Get paid for shipped goods today.</h1>
      <p className="lede">Request an advance on an invoice, bill of lading or equipment order. Most requests are reviewed in under a minute.</p>
      <div className="split" style={{ marginTop: 36 }}>
        <div className="stack" style={{ gap: 16 }}>
          {(live.seed?.borrowers ?? []).map((b: Any) => (
            <section key={b.id} className="panel">
              <div className="panel-head">
                <div>
                  <h2>{b.name}</h2>
                  <div className="small muted">
                    {COUNTRY[b.country]}, trading for {b.credit.yearsTrading} years
                  </div>
                </div>
              </div>
              {live.seed.documents
                .filter((d: Any) => d.borrowerId === b.id)
                .map((d: Any) => (
                  <div key={d.number} className="doc">
                    <div>
                      <div className="t">{d.title}</div>
                      <div className="m">
                        <span className="code">{d.number}</span>, {money(d.amountMinor, d.currency)} from {d.buyer}, due in {days(d.dueInDays)}
                      </div>
                      {declined.has(d.number) && !listed.has(d.number) ? (
                        <div className="small" style={{ color: 'var(--bad)', marginTop: 4 }}>
                          Not approved: {declined.get(d.number)}
                        </div>
                      ) : null}
                    </div>
                    {listed.has(d.number) ? (
                      <span className="tag good">Listed</span>
                    ) : reviewing.has(d.number) ? (
                      <span className="tag open">In review</span>
                    ) : (
                      <button
                        className="btn"
                        disabled={!!busy}
                        onClick={() => run(d.number, () => api('/api/business/submit', { docNumber: d.number }), `${d.number} submitted for review`)}
                      >
                        Request financing
                      </button>
                    )}
                  </div>
                ))}
            </section>
          ))}
        </div>
        <section className="panel">
          <div className="panel-head">
            <h2>Recent reviews</h2>
          </div>
          <Activity runs={live.runs.filter((r) => r.handler === 'verify-and-list').slice(0, 10)} live={live} empty="Reviews of your documents will appear here." />
        </section>
      </div>
    </>
  )
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

function Operations({ live, notify }: { live: Live; notify: Notify }) {
  const { busy, run } = useAction(live, notify)
  const snap = live.state?.snapshot
  const books = live.state?.books
  const recon = snap?.recon
  const hasRecon = recon && Number(recon[1]) > 0
  const movements = [
    ...(live.state?.intents ?? []).map((i: Any) => ({ key: i.reference, at: i.settledAt ?? i.createdAt, what: 'Lender deposit', ref: i.reference, amount: money(i.amountMinor, i.currency, 2), state: i.status })),
    ...(live.state?.payouts ?? []).map((p: Any) => ({ key: p.payoutRef, at: p.createdAt, what: p.kind === 'business' ? 'Payout to business' : 'Payout to lender', ref: p.payoutRef, amount: usd(p.amount, 2), state: 'sent' })),
    ...(live.state?.bankCredits ?? [])
      .filter((c: Any) => c.kind === 'repayment')
      .map((c: Any) => ({ key: c.reference, at: c.valueDate, what: 'Buyer repayment', ref: c.reference, amount: money(c.amountMinor, c.currency, 2), state: 'received' })),
  ].sort((a, b) => String(b.at).localeCompare(String(a.at)))
  const STATE_TONE: Record<string, string> = { credited: 'good', sent: 'good', received: 'good', settled: 'warn', awaiting_funds: '', failed: 'bad' }
  const STATE_LABEL: Record<string, string> = { credited: 'Credited', sent: 'Sent', received: 'Received', settled: 'Verifying', awaiting_funds: 'Awaiting', failed: 'Failed' }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Operations</h1>
          <p className="lede" style={{ marginTop: 8 }}>
            Money movements, automated checks and the reserve position.
          </p>
        </div>
      </div>

      <section className="panel">
        <div className="panel-head">
          <h2>Reserve check</h2>
          <div className="row">
            <button className="btn" disabled={!!busy} onClick={() => run('check', () => api('/api/monitor/run', {}), 'Reserve check complete')}>
              {busy === 'check' ? 'Checking…' : 'Run check'}
            </button>
            {snap?.fundingPaused ? (
              <button className="btn danger" disabled={!!busy} onClick={() => run('resume', () => api('/api/ops/resume', {}), 'Funding resumed')}>
                Resume funding
              </button>
            ) : null}
          </div>
        </div>
        {snap?.fundingPaused ? (
          <div className="notice bad">Mismatch found. New funding is paused until an operator resumes it.</div>
        ) : hasRecon ? (
          <div className={`notice ${recon[0] ? 'good' : 'idle'}`}>
            {recon[0]
              ? `Bank, on-ramp and ledger agree, checked ${ago(new Date(Number(recon[1]) * 1000).toISOString())}`
              : `The last check found a mismatch (${ago(new Date(Number(recon[1]) * 1000).toISOString())}). Run the check again to confirm the books are back in line.`}
          </div>
        ) : (
          <div className="notice idle">No reserve check has run yet.</div>
        )}
        <div className="legs">
          <div>
            <span>Cash received at the bank</span>
            <b>{usd(books?.bankUsd6, 2)}</b>
          </div>
          <div>
            <span>USDC minted by the on-ramp</span>
            <b>{usd(books?.onrampUsd6, 2)}</b>
          </div>
          <div>
            <span>Credited to lenders onchain</span>
            <b>{usd(snap?.totalFiatIn, 2)}</b>
          </div>
        </div>
      </section>

      <div className="split" style={{ marginTop: 24 }}>
        <section className="panel">
          <div className="panel-head">
            <h2>Automated checks</h2>
            <span className="small muted">{live.runs.length}</span>
          </div>
          <Activity runs={live.runs.slice(0, 30)} live={live} empty="Checks will appear here as loans move." />
        </section>
        <div className="stack" style={{ gap: 20 }}>
          <section className="panel">
            <div className="panel-head">
              <h2>Money movements</h2>
            </div>
            {movements.length === 0 ? (
              <div className="empty">No money has moved yet.</div>
            ) : (
              <div className="scroll">
                <table>
                  <tbody>
                    {movements.map((m) => (
                      <tr key={m.key}>
                        <td>
                          {m.what}
                          <div className="small muted code">{m.ref}</div>
                        </td>
                        <td className="r">
                          {m.amount}
                          <div>
                            <span className={`tag ${STATE_TONE[m.state] ?? ''}`}>{STATE_LABEL[m.state] ?? m.state}</span>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
          <section className="panel">
            <div className="panel-head">
              <h2>Lenders</h2>
            </div>
            {(live.seed?.lenders ?? []).map((l: Any) => (
              <div key={l.id} className="doc">
                <div>
                  <div className="t">{l.name}</div>
                  <div className="m">
                    {COUNTRY[l.country] ?? l.country}, lends by {l.funding === 'fiat' ? 'bank transfer' : 'USDC'}
                  </div>
                </div>
                <div className="row" style={{ gap: 8, flexWrap: 'nowrap' }}>
                  <span className={`tag ${l.kycStatus === 'approved' ? 'good' : 'warn'}`}>{l.kycStatus === 'approved' ? 'Approved' : 'Pending'}</span>
                  <button className="btn quiet" disabled={!!busy} onClick={() => run(`kyc-${l.id}`, () => api('/api/lender/onboard', { lenderId: l.id }), `Identity check started for ${l.name}`)}>
                    Check
                  </button>
                </div>
              </div>
            ))}
          </section>
        </div>
      </div>

      <details className="tools">
        <summary>Test tools</summary>
        <div className="panel panel-pad row">
          <span className="small muted" style={{ flex: '1 1 260px' }}>
            Book a deposit at the bank without a matching on-ramp mint, then run the reserve check to see funding pause.
          </span>
          <button className="btn quiet" disabled={!!busy} onClick={() => run('tamper', () => api('/api/demo/tamper', {}), 'Unmatched deposit booked')}>
            Book unmatched deposit
          </button>
          {live.state?.ledgerAdjustments?.length ? (
            <button className="btn quiet" disabled={!!busy} onClick={() => run('untamper', () => api('/api/demo/untamper', {}), 'Books corrected')}>
              Correct the books
            </button>
          ) : null}
        </div>
      </details>
    </>
  )
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

function App() {
  const live = useLive()
  const { path, go } = usePath()
  const { toast, notify } = useToast()
  const busy = live.runs.some((r) => r.status === 'running' || r.status === 'queued')
  const paused = Boolean(live.state?.snapshot?.fundingPaused)
  const loanMatch = path.match(/^\/loans\/(\d+)/)
  const page = loanMatch ? (
    <LoanPage id={Number(loanMatch[1])} live={live} go={go} notify={notify} />
  ) : path === '/business' ? (
    <Business live={live} notify={notify} />
  ) : path === '/ops' ? (
    <Operations live={live} notify={notify} />
  ) : (
    <Marketplace live={live} go={go} />
  )
  const nav: [string, string][] = [
    ['/', 'Marketplace'],
    ['/business', 'Raise capital'],
    ['/ops', 'Operations'],
  ]
  return (
    <>
      <header className="top">
        <div className="top-inner">
          <Link to="/" go={go} className="wordmark">
            <svg width="22" height="22" viewBox="0 0 22 22" aria-hidden="true">
              <circle cx="4" cy="11" r="3" fill="#f2b705" />
              <circle cx="18" cy="11" r="3" fill="none" stroke="#fff" strokeWidth="2" />
              <path d="M8 11h6" stroke="#fff" strokeWidth="2" strokeDasharray="2 2" />
            </svg>
            Tradeflow
          </Link>
          <nav className="nav" aria-label="Main">
            {nav.map(([to, label]) => (
              <Link key={to} to={to} go={go} className={(to === '/' ? path === '/' || path.startsWith('/loans') : path === to) ? 'on' : ''}>
                {label}
              </Link>
            ))}
          </nav>
          <div className="net" role="status">
            <span className={`pip ${busy ? 'busy' : paused ? 'alert' : ''}`} />
            <span>{busy ? 'Verifying' : paused ? 'Funding paused' : 'All systems normal'}</span>
          </div>
        </div>
      </header>
      <main>
        {live.state ? (
          page
        ) : (
          <div className="loading" role="status">
            Loading
          </div>
        )}
      </main>
      <footer className="foot">
        <div>
          <span>Tradeflow</span>
          <span>
            Built by{' '}
            <a href="https://codedecoders.io" target="_blank" rel="noreferrer">
              CodeDecoders
            </a>
          </span>
        </div>
      </footer>
      {toast ? <div className={`toast ${toast.bad ? 'bad' : ''}`}>{toast.text}</div> : null}
    </>
  )
}

createRoot(document.getElementById('root')!).render(<App />)
