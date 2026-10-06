import React, { useCallback, useEffect, useMemo, useState } from 'react'
import { createRoot } from 'react-dom/client'

// ---------------------------------------------------------------------------
// Data
// ---------------------------------------------------------------------------

type Any = any
const STATUS = ['None', 'Listed', 'Funded', 'Disbursed', 'Repaid', 'Late', 'Defaulted']
const ASSET = ['Invoice advance', 'Bill of lading', 'Equipment finance', 'Working capital']
const GRADE = ['-', 'A', 'B', 'C', 'D', 'E']

const usd = (v: string | number | bigint | undefined, digits = 0) => {
  const n = Number(BigInt(v ?? 0)) / 1e6
  return n.toLocaleString('en-US', { style: 'currency', currency: 'USD', maximumFractionDigits: digits, minimumFractionDigits: digits })
}
const money = (minor: number | string, ccy: string) =>
  (Number(minor) / 100).toLocaleString('en-US', { style: 'currency', currency: ccy, maximumFractionDigits: 0 })
const pct = (bps: number) => `${(bps / 100).toFixed(1)}%`
const fx = (e8: string | number) => (Number(e8) / 1e8).toFixed(4)
const ccyOf = (hex: string) => {
  try {
    return hex.slice(2).match(/../g)!.map((b) => String.fromCharCode(parseInt(b, 16))).join('')
  } catch {
    return 'USD'
  }
}
const short = (h?: string) => (h ? `${h.slice(0, 8)}…${h.slice(-6)}` : '')
const ago = (iso?: string) => {
  if (!iso) return ''
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000)
  if (s < 60) return `${Math.floor(s)}s ago`
  if (s < 3600) return `${Math.floor(s / 60)}m ago`
  return `${Math.floor(s / 3600)}h ago`
}

async function api<T = Any>(path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, body === undefined ? undefined : { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
  const data = await res.json()
  if (!res.ok) throw new Error(data.error ?? `HTTP ${res.status}`)
  return data
}

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
    const t = setInterval(refresh, 5000)
    let ws: WebSocket | undefined
    const connect = () => {
      ws = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws`)
      ws.onmessage = (m) => {
        const msg = JSON.parse(m.data)
        if (msg.type === 'run') {
          setRuns((prev) => {
            const next = prev.filter((x) => x.id !== msg.data.id)
            return [msg.data, ...next].sort((a, b) => b.id - a.id)
          })
          if (msg.data.status === 'success' || msg.data.status === 'failed') refresh()
        } else refresh()
      }
      ws.onclose = () => setTimeout(connect, 2000)
    }
    connect()
    return () => {
      clearInterval(t)
      ws?.close()
    }
  }, [refresh])

  return { state, runs, seed, config, wallet, refresh }
}

type Live = ReturnType<typeof useLive>

function docFor(seed: Any, ref: string) {
  return seed?.documents.find((d: Any) => d.number === ref)
}
function bizFor(seed: Any, wallet: string) {
  return seed?.borrowers.find((b: Any) => b.wallet.toLowerCase() === wallet.toLowerCase())
}

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

function Link({ to, go, children, className }: { to: string; go: (p: string) => void; children: React.ReactNode; className?: string }) {
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
// Shared bits
// ---------------------------------------------------------------------------

function Hash({ h, config }: { h?: string; config: Any }) {
  if (!h) return null
  const url = config?.explorer ? `${config.explorer}/tx/${h}` : undefined
  return url ? (
    <a className="hash" href={url} target="_blank" rel="noreferrer">
      {short(h)}
    </a>
  ) : (
    <span className="hash">{short(h)}</span>
  )
}

function StatusChip({ s }: { s: number }) {
  const name = STATUS[s] ?? 'Unknown'
  const cls = s === 1 ? 'blue' : s === 2 || s === 3 ? 'green' : s === 4 ? 'green' : s === 5 ? 'warn' : s === 6 ? 'stop' : ''
  return <span className={`chip ${cls}`}>{name}</span>
}

function useToast() {
  const [msg, setMsg] = useState<string | null>(null)
  useEffect(() => {
    if (!msg) return
    const t = setTimeout(() => setMsg(null), 6000)
    return () => clearTimeout(t)
  }, [msg])
  return { msg, show: setMsg }
}

function runSummary(run: Any): string | null {
  const d = run.resultData
  if (run.status === 'failed') {
    const err = [...(run.logs ?? [])].reverse().find((l: string) => /error|failed|rejected/i.test(l))
    return err ? `Failed: ${err.replace(/^.*?(Error:|error:)/i, '').slice(0, 140)}` : 'Failed'
  }
  if (!d) return null
  if (run.workflow === 'listing') {
    if (!d.listed) return `Rejected: ${d.reason}`
    const fxText = d.currency === 'USD' ? '' : `, ${d.currency}/USD ${fx(d.fxRateE8)} from Chainlink`
    return `Listed ${d.docNumber}: grade ${d.grade}, ${pct(d.aprBps)} APR, ${usd(d.target)} advance${fxText}`
  }
  if (run.handler === 'verify-lender') return d.verified ? `KYC verified: ${d.lenderId} (${d.level})` : `KYC not approved: ${d.lenderId}`
  if (run.handler === 'credit-fiat-deposit')
    return `Credited ${usd(d.stablecoins, 2)} for ${d.fiat}; on-ramp rate ${fx(d.providerRate)} vs Chainlink ${fx(d.chainlinkRate)}`
  if (run.handler === 'disburse-on-funded') return d.disbursed ? `Paid ${usd(d.amount)} to the business (${d.payoutRef})` : `Skipped: ${d.reason}`
  if (run.handler === 'confirm-repayment') return `Repayment of ${usd(d.amount, 2)} confirmed by the collection bank and the payment processor`
  if (run.handler === 'redeem-fiat-lenders')
    return d.redeemed?.length ? `Paid back to bank: ${d.redeemed.map((r: Any) => `${r.lender} ${usd(r.payout, 2)} (${r.payoutRef})`).join(', ')}` : 'No bank-transfer lenders to repay'
  if (run.workflow === 'monitor') {
    const r = d.reconciliation
    const changes = (d.statusChanges ?? []).map((c: Any) => `loan ${c.loanId} ${c.status}, business frozen`).join('; ')
    return `Reconciliation ${r?.ok ? 'passed' : 'FAILED, funding paused'}${changes ? ` · ${changes}` : ''}`
  }
  return null
}

function RunLine({ run, config }: { run: Any; config: Any }) {
  const summary = runSummary(run)
  const dur = run.startedAt && run.finishedAt ? `${((new Date(run.finishedAt).getTime() - new Date(run.startedAt).getTime()) / 1000).toFixed(0)}s` : ''
  return (
    <details className="run">
      <summary>
        <span className={`status-dot s-${run.status}`} title={run.status} />
        <span>
          <span className="wf">{run.workflow}</span> <span className="muted">· {run.handler}</span>
          <div className="small muted">
            {run.trigger === 'evm-log' ? 'EVM log trigger' : run.trigger === 'cron' ? 'Cron trigger' : 'HTTP trigger'} · {run.input.length > 70 ? `${run.input.slice(0, 70)}…` : run.input}
          </div>
          {summary ? <div className={`small ${run.status === 'failed' ? '' : ''}`} style={{ marginTop: 3, color: run.status === 'failed' ? 'var(--stop)' : 'var(--ink)' }}>{summary}</div> : null}
        </span>
        <span className="small muted" style={{ textAlign: 'right' }}>
          {run.status === 'running' ? 'running…' : run.status === 'queued' ? 'queued' : `${run.status} ${dur}`}
          <div>{ago(run.finishedAt ?? run.startedAt ?? run.queuedAt)}</div>
          {run.txHashes?.slice(0, 2).map((h: string) => (
            <div key={h}>
              <Hash h={h} config={config} />
            </div>
          ))}
        </span>
      </summary>
      {run.logs?.length ? <pre>{run.logs.join('\n')}</pre> : null}
    </details>
  )
}

// ---------------------------------------------------------------------------
// Marketplace
// ---------------------------------------------------------------------------

function LoanCard({ loan, live, go }: { loan: Any; live: Live; go: (p: string) => void }) {
  const doc = docFor(live.seed, loan.ref)
  const biz = bizFor(live.seed, loan.borrower)
  const progress = Number((BigInt(loan.funded) * 1000n) / BigInt(loan.target || 1)) / 10
  return (
    <Link to={`/loans/${loan.id}`} go={go} className="card loan">
      <div className="row between">
        <span className="chip">{ASSET[loan.assetType]}</span>
        <StatusChip s={loan.status} />
      </div>
      <div className="row" style={{ alignItems: 'flex-start', flexWrap: 'nowrap' }}>
        <div className="grade" title="Risk grade from the confidential credit check">{GRADE[loan.riskGrade]}</div>
        <div>
          <div className="title">{doc?.title ?? loan.ref}</div>
          <div className="small muted">
            {biz?.name ?? short(loan.borrower)} · {biz?.country} → {doc?.buyerCountry}
          </div>
        </div>
      </div>
      <div className="terms">
        <div className="term">
          <div className="k">APR</div>
          <div className="v">{pct(loan.aprBps)}</div>
        </div>
        <div className="term">
          <div className="k">Term</div>
          <div className="v">{loan.tenorDays} days</div>
        </div>
        <div className="term">
          <div className="k">Target</div>
          <div className="v">{usd(loan.target)}</div>
        </div>
      </div>
      <div className="stack" style={{ gap: 6 }}>
        <div className="bar">
          <span style={{ width: `${Math.min(progress, 100)}%` }} />
        </div>
        <div className="row between small">
          <span className="muted">{usd(loan.funded)} raised</span>
          <span className="muted">{progress.toFixed(0)}%</span>
        </div>
      </div>
      <div className="verified">
        <span className="dot" /> Verified by Chainlink CRE · {loan.ref}
      </div>
    </Link>
  )
}

function Marketplace({ live, go }: { live: Live; go: (p: string) => void }) {
  const loans = live.state?.loans ?? []
  const snap = live.state?.snapshot
  const financed = loans.filter((l: Any) => l.status >= 3).reduce((s: bigint, l: Any) => s + BigInt(l.target), 0n)
  const verifiedRuns = live.runs.filter((r) => r.status === 'success').length
  return (
    <>
      <h1>Real-world business credit, checked by Chainlink CRE.</h1>
      <p className="lead">
        Exporters, shippers and manufacturers get paid now instead of waiting 60 to 180 days. Lenders fund from a bank account or with
        stablecoins. Every document, deposit, payout and repayment is verified by a Chainlink CRE workflow before it changes anything onchain.
      </p>
      <div className="grid cols-4">
        <div className="card kpi">
          <div className="label">Financed to businesses</div>
          <div className="value">{usd(financed)}</div>
        </div>
        <div className="card kpi">
          <div className="label">Open for funding</div>
          <div className="value">{loans.filter((l: Any) => l.status === 1).length}</div>
        </div>
        <div className="card kpi">
          <div className="label">Fiat funded via on-ramp</div>
          <div className="value">{usd(snap?.totalFiatIn)}</div>
        </div>
        <div className="card kpi">
          <div className="label">CRE workflow runs</div>
          <div className="value">{verifiedRuns}</div>
        </div>
      </div>
      {snap?.fundingPaused ? (
        <div className="banner stop section">
          Funding is paused: the last CRE reconciliation found a mismatch between bank, on-ramp and onchain records.
        </div>
      ) : null}
      <div className="section row between">
        <h2 style={{ margin: 0 }}>Financing requests</h2>
        <Link to="/business" go={go} className="btn ghost">
          Submit a document
        </Link>
      </div>
      <div className="grid cols-3 section" style={{ marginTop: 12 }}>
        {loans.length === 0 ? (
          <div className="card empty">No financing requests yet. Submit a document from the Business page.</div>
        ) : (
          [...loans].reverse().map((l: Any) => <LoanCard key={l.id} loan={l} live={live} go={go} />)
        )}
      </div>
    </>
  )
}

// ---------------------------------------------------------------------------
// Loan detail
// ---------------------------------------------------------------------------

function LoanDetail({ id, live, go, toast }: { id: number; live: Live; go: (p: string) => void; toast: (m: string) => void }) {
  const loan = live.state?.loans?.find((l: Any) => l.id === id)
  const [tab, setTab] = useState<'fiat' | 'crypto'>('fiat')
  const [amount, setAmount] = useState('')
  const [busy, setBusy] = useState('')
  const [intent, setIntent] = useState<Any>(null)
  if (!loan) return <div className="card empty">Loading loan {id}…</div>

  const doc = docFor(live.seed, loan.ref)
  const biz = bizFor(live.seed, loan.borrower)
  const ccy = ccyOf(loan.currency)
  const remaining = BigInt(loan.target) - BigInt(loan.funded)
  const fundings = (live.state?.fundings ?? []).filter((f: Any) => Number(f.loanId) === id)
  const loanRuns = live.runs.filter(
    (r) => r.loanId === id || r.input.includes(`"loanId":${id}`) || r.input.includes(loan.ref) || (intent && r.input.includes(intent.reference)),
  )
  const interest = (BigInt(loan.target) * BigInt(loan.aprBps) * BigInt(loan.tenorDays)) / (10_000n * 365n)
  const ben = live.seed?.lenders.find((l: Any) => l.id === 'lender-ben')
  const ana = live.seed?.lenders.find((l: Any) => l.id === 'lender-ana')

  const act = async (label: string, fn: () => Promise<unknown>, done?: string) => {
    setBusy(label)
    try {
      await fn()
      if (done) toast(done)
      await live.refresh()
    } catch (e) {
      toast(`Failed: ${(e as Error).message}`)
    } finally {
      setBusy('')
    }
  }

  const steps = [
    { what: 'Document verified and listed', done: loan.status >= 1, detail: `Registry check, sanctions screen and credit grade ${GRADE[loan.riskGrade]} computed inside a TEE` },
    { what: 'Fully funded', done: loan.status >= 2 && loan.status !== 1, detail: `${usd(loan.funded)} of ${usd(loan.target)}, ${usd(loan.fiatFunded)} by bank transfer` },
    { what: 'Paid out to the business', done: loan.status >= 3, detail: loan.disbursedAt > 0 ? `Fiat payout confirmed by CRE, stablecoins released to the off-ramp` : 'CRE pays the business when the loan is fully funded' },
    { what: loan.status === 5 ? 'Overdue: business frozen' : loan.status === 6 ? 'Defaulted' : 'Repaid by the buyer', done: loan.status === 4, fail: loan.status >= 5, detail: loan.status === 4 ? `${usd(loan.repaidAmount, 2)} confirmed by the bank and the payment processor` : `Due ${usd(BigInt(loan.target) + interest, 2)}` },
  ]
  const nowIdx = steps.findIndex((s) => !s.done)

  return (
    <>
      <div className="small muted">
        <Link to="/" go={go}>
          Marketplace
        </Link>{' '}
        / {loan.ref}
      </div>
      <div className="row between" style={{ marginTop: 8 }}>
        <h1 style={{ margin: 0 }}>{doc?.title ?? loan.ref}</h1>
        <StatusChip s={loan.status} />
      </div>
      <p className="lead" style={{ marginTop: 6 }}>
        {biz?.name} ({biz?.country}) · buyer {doc?.buyer} ({doc?.buyerCountry})
      </p>
      <div className="split">
        <div className="stack" style={{ gap: 14 }}>
          <div className="card">
            <div className="grid cols-4" style={{ gap: 10 }}>
              <div className="kpi">
                <div className="label">Advance</div>
                <div className="value">{usd(loan.target)}</div>
              </div>
              <div className="kpi">
                <div className="label">APR</div>
                <div className="value">{pct(loan.aprBps)}</div>
              </div>
              <div className="kpi">
                <div className="label">Term</div>
                <div className="value">{loan.tenorDays}d</div>
              </div>
              <div className="kpi">
                <div className="label">Grade</div>
                <div className="value">{GRADE[loan.riskGrade]}</div>
              </div>
            </div>
          </div>
          <div className="card">
            <h3>What CRE verified</h3>
            <table>
              <tbody>
                <tr>
                  <td className="muted">Document</td>
                  <td>
                    {ASSET[loan.assetType]} {loan.ref}, face value {money(loan.faceValueMinor, ccy)}
                  </td>
                </tr>
                <tr>
                  <td className="muted">FX at listing</td>
                  <td>
                    {ccy === 'USD' ? 'USD document, no conversion' : `${ccy}/USD ${fx(loan.fxRateE8)} from the Chainlink Data Feed`}
                  </td>
                </tr>
                <tr>
                  <td className="muted">Credit check</td>
                  <td>Run inside a TEE. Only the grade and terms left the enclave; the credit file never did.</td>
                </tr>
                <tr>
                  <td className="muted">Document hash</td>
                  <td className="mono">{short(loan.docHash)}</td>
                </tr>
              </tbody>
            </table>
          </div>
          <div className="card">
            <h3>Lifecycle</h3>
            <div className="steps">
              {steps.map((s, i) => (
                <div key={s.what} className={`step ${s.fail ? 'fail' : s.done ? 'done' : i === nowIdx ? 'now' : ''}`}>
                  <span className="mark" />
                  <div>
                    <div className="what">{s.what}</div>
                    <div className="detail">{s.detail}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
          <div className="card">
            <h3>Lenders</h3>
            {fundings.length === 0 ? (
              <div className="muted small">No funding yet.</div>
            ) : (
              <div className="tbl">
                <table>
                  <thead>
                    <tr>
                      <th>Lender</th>
                      <th>Route</th>
                      <th>Amount</th>
                      <th>Tx</th>
                    </tr>
                  </thead>
                  <tbody>
                    {fundings.map((f: Any) => {
                      const who = live.seed?.lenders.find((l: Any) => l.wallet.toLowerCase() === String(f.lender).toLowerCase())
                      return (
                        <tr key={f.tx + f.lender}>
                          <td>{who?.name ?? short(f.lender)}</td>
                          <td>{f.viaFiat ? <span className="chip blue">Bank → on-ramp</span> : <span className="chip">USDC</span>}</td>
                          <td>{usd(f.amount, 2)}</td>
                          <td>
                            <Hash h={f.tx} config={live.config} />
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>

        <div className="stack" style={{ gap: 14 }}>
          {loan.status === 1 ? (
            <div className="card stack">
              <h3 style={{ margin: 0 }}>Fund this loan</h3>
              <div className="small muted">{usd(remaining)} left to raise. Notes are only issued to KYC-verified lenders.</div>
              <div className="tabs" role="tablist">
                <button className={tab === 'fiat' ? 'on' : ''} onClick={() => setTab('fiat')}>
                  Bank transfer
                </button>
                <button className={tab === 'crypto' ? 'on' : ''} onClick={() => setTab('crypto')}>
                  Stablecoins
                </button>
              </div>
              {tab === 'fiat' ? (
                <div className="stack">
                  <div className="small">
                    Lending as <b>{ana?.name}</b> ({ana?.country}), KYC {ana?.kycStatus}. Paying in EUR from {ana?.bankAccount}.
                  </div>
                  {!intent ? (
                    <>
                      <label className="field">
                        Amount (EUR)
                        <input id="fiat-amount" inputMode="decimal" placeholder="e.g. 3000" value={amount} onChange={(e) => setAmount(e.target.value)} />
                      </label>
                      <button
                        className="btn"
                        disabled={!!busy || !Number(amount)}
                        onClick={() =>
                          act('intent', async () => {
                            const r = await api('/api/onramp/intent', { lenderId: 'lender-ana', loanId: id, amountMinor: Math.round(Number(amount) * 100), currency: 'EUR' })
                            setIntent(r)
                          })
                        }
                      >
                        Get payment instructions
                      </button>
                    </>
                  ) : (
                    <div className="stack">
                      <div className="card tight" style={{ background: 'var(--wash)', border: 0 }}>
                        <div className="small muted">Transfer {money(intent.intent.amountMinor, 'EUR')} to</div>
                        <div className="mono">{intent.instructions.iban}</div>
                        <div className="small muted" style={{ marginTop: 6 }}>
                          Reference
                        </div>
                        <div className="mono">{intent.instructions.reference}</div>
                      </div>
                      <button
                        className="btn accent"
                        disabled={!!busy}
                        onClick={() =>
                          act(
                            'deposit',
                            async () => {
                              const r = await api('/api/onramp/simulate-deposit', { reference: intent.intent.reference })
                              if (r.run?.status !== 'success') throw new Error('CRE did not credit the deposit, see Operations')
                              setIntent(null)
                              setAmount('')
                            },
                            'Deposit verified by CRE and credited as loan notes',
                          )
                        }
                      >
                        {busy === 'deposit' ? 'Bank → on-ramp → CRE verifying…' : 'Simulate the bank transfer arriving'}
                      </button>
                      <div className="small muted">
                        The on-ramp converts EUR to USDC and mints it into the market. CRE then checks the deposit privately, compares the rate with
                        Chainlink EUR/USD and credits the notes.
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <div className="stack">
                  <div className="small">
                    Lending as <b>{ben?.name}</b> from demo wallet <span className="mono">{short(live.wallet?.address)}</span> · balance{' '}
                    {usd(live.wallet?.usdc, 0)} tUSDC
                  </div>
                  {!live.wallet?.verified ? (
                    <button
                      className="btn"
                      disabled={!!busy}
                      onClick={() => act('kyc', () => api('/api/lender/onboard', { lenderId: 'lender-ben' }), 'KYC workflow started on CRE')}
                    >
                      {busy === 'kyc' ? 'Starting…' : 'Verify KYC with CRE first'}
                    </button>
                  ) : (
                    <>
                      <label className="field">
                        Amount (USDC)
                        <input id="usdc-amount" inputMode="decimal" placeholder={`up to ${Number(remaining) / 1e6}`} value={amount} onChange={(e) => setAmount(e.target.value)} />
                      </label>
                      <button
                        className="btn accent"
                        disabled={!!busy || !Number(amount)}
                        onClick={() =>
                          act('fund', () => api('/api/demo-wallet/fund', { loanId: id, amountUsd: Number(amount) }), 'Funded with stablecoins').then(() => setAmount(''))
                        }
                      >
                        {busy === 'fund' ? 'Approving and funding…' : 'Approve and fund'}
                      </button>
                    </>
                  )}
                </div>
              )}
            </div>
          ) : null}

          {loan.status === 3 || loan.status === 5 ? (
            <div className="card stack">
              <h3 style={{ margin: 0 }}>Repayment (sandbox)</h3>
              <div className="small muted">
                The buyer pays {usd(BigInt(loan.target) + interest, 2)}. The payment processor captures it, the collection bank receives it, and CRE
                only marks the loan repaid when both sources agree.
              </div>
              <button className="btn accent" disabled={!!busy} onClick={() => act('pay', () => api('/api/buyer/pay', { loanId: id }), 'Repayment confirmed by CRE')}>
                {busy === 'pay' ? 'Buyer paying, CRE checking two sources…' : `${doc?.buyer ?? 'Buyer'} pays`}
              </button>
            </div>
          ) : null}

          {loan.status === 4 ? (
            <div className="card stack">
              <h3 style={{ margin: 0 }}>Repaid</h3>
              <div className="small muted">Bank-transfer lenders are paid back to their bank automatically. Stablecoin lenders claim onchain.</div>
              <button className="btn" disabled={!!busy} onClick={() => act('claim', () => api('/api/demo-wallet/claim', { loanId: id }), 'Claimed principal and interest')}>
                {busy === 'claim' ? 'Claiming…' : `Claim as ${ben?.name}`}
              </button>
            </div>
          ) : null}

          <div className="card stack">
            <div className="row between">
              <h3 style={{ margin: 0 }}>CRE activity for this loan</h3>
              <span className="cre-pill">
                <span className="dot live" /> live
              </span>
            </div>
            {loanRuns.length === 0 ? <div className="small muted">Workflow runs will appear here.</div> : loanRuns.slice(0, 8).map((r) => <RunLine key={r.id} run={r} config={live.config} />)}
          </div>
        </div>
      </div>
    </>
  )
}

// ---------------------------------------------------------------------------
// Business
// ---------------------------------------------------------------------------

function Business({ live, toast, go }: { live: Live; toast: (m: string) => void; go: (p: string) => void }) {
  const [busy, setBusy] = useState('')
  const listed = new Set((live.state?.loans ?? []).map((l: Any) => l.ref))
  const listingRuns = live.runs.filter((r) => r.workflow === 'listing')
  return (
    <>
      <h1>Get paid now for goods you have already shipped.</h1>
      <p className="lead">
        Submit an invoice, bill of lading or equipment order. A Chainlink CRE workflow verifies it with the registry, screens sanctions and grades
        your credit inside a secure enclave, so your financial data is never exposed. Approved requests are listed for lenders straight away.
      </p>
      <div className="split">
        <div className="stack">
          {(live.seed?.borrowers ?? []).map((b: Any) => (
            <div key={b.id} className="card stack">
              <div className="row between">
                <div>
                  <h3 style={{ margin: 0 }}>{b.name}</h3>
                  <div className="small muted">
                    {b.country} · {b.credit.yearsTrading} years trading · payout to {b.bankAccount}
                  </div>
                </div>
              </div>
              {live.seed.documents
                .filter((d: Any) => d.borrowerId === b.id)
                .map((d: Any) => (
                  <div key={d.number} className="row between" style={{ borderTop: '1px solid var(--line)', paddingTop: 10 }}>
                    <div>
                      <div style={{ fontWeight: 600 }}>{d.title}</div>
                      <div className="small muted">
                        {d.number} · {money(d.amountMinor, d.currency)} · buyer {d.buyer} · {d.dueInDays} days
                      </div>
                    </div>
                    {listed.has(d.number) ? (
                      <span className="chip green">Listed</span>
                    ) : (
                      <button
                        className="btn"
                        disabled={!!busy}
                        onClick={async () => {
                          setBusy(d.number)
                          try {
                            await api('/api/business/submit', { docNumber: d.number })
                            toast(`Submitted ${d.number}. CRE is verifying it now.`)
                          } catch (e) {
                            toast(`Failed: ${(e as Error).message}`)
                          } finally {
                            setBusy('')
                          }
                        }}
                      >
                        {busy === d.number ? 'Submitting…' : 'Request financing'}
                      </button>
                    )}
                  </div>
                ))}
            </div>
          ))}
        </div>
        <div className="card stack">
          <div className="row between">
            <h3 style={{ margin: 0 }}>Verification runs</h3>
            <span className="cre-pill">Confidential Workflow · TEE</span>
          </div>
          {listingRuns.length === 0 ? <div className="small muted">No submissions yet.</div> : listingRuns.slice(0, 10).map((r) => <RunLine key={r.id} run={r} config={live.config} />)}
        </div>
      </div>
    </>
  )
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

function Ops({ live, toast }: { live: Live; toast: (m: string) => void }) {
  const [busy, setBusy] = useState('')
  const snap = live.state?.snapshot
  const books = live.state?.books
  const recon = snap?.recon
  const act = async (label: string, fn: () => Promise<unknown>, done: string) => {
    setBusy(label)
    try {
      await fn()
      toast(done)
      await live.refresh()
    } catch (e) {
      toast(`Failed: ${(e as Error).message}`)
    } finally {
      setBusy('')
    }
  }
  const counts = useMemo(() => {
    const by: Record<string, number> = {}
    for (const r of live.runs) by[r.workflow] = (by[r.workflow] ?? 0) + 1
    return by
  }, [live.runs])

  return (
    <>
      <h1>Operations</h1>
      <p className="lead">
        Every change onchain comes from a signed Chainlink CRE report. This console shows each workflow run, the money that moved through the
        rails, and the three-way reconciliation that pauses funding if the books ever disagree.
      </p>
      <div className="grid cols-4">
        {['listing', 'lender', 'settlement', 'monitor'].map((w) => (
          <div key={w} className="card kpi">
            <div className="label">{w} workflow</div>
            <div className="value">{counts[w] ?? 0} runs</div>
          </div>
        ))}
      </div>

      <div className="card section stack">
        <div className="row between">
          <h2 style={{ margin: 0 }}>Three-way reconciliation</h2>
          <div className="row">
            <button className="btn" disabled={!!busy} onClick={() => act('monitor', () => api('/api/monitor/run', {}), 'Monitor workflow finished')}>
              {busy === 'monitor' ? 'CRE monitor running…' : 'Run CRE monitor now'}
            </button>
            <button className="btn ghost" disabled={!!busy} onClick={() => act('tamper', () => api('/api/demo/tamper', {}), 'A deposit was booked at the bank without a matching mint')}>
              Inject a books mismatch
            </button>
            {live.state?.ledgerAdjustments?.length ? (
              <button className="btn ghost" disabled={!!busy} onClick={() => act('untamper', () => api('/api/demo/untamper', {}), 'Books corrected')}>
                Correct the books
              </button>
            ) : null}
            {snap?.fundingPaused ? (
              <button className="btn danger" disabled={!!busy} onClick={() => act('resume', () => api('/api/ops/resume', {}), 'Funding resumed by the operator')}>
                Resume funding
              </button>
            ) : null}
          </div>
        </div>
        {snap?.fundingPaused ? (
          <div className="banner stop">Circuit breaker on: new funding is paused until an operator resumes it.</div>
        ) : recon && Number(recon[1]) > 0 ? (
          <div className={`banner ${recon[0] ? 'ok' : 'stop'}`}>
            {recon[0] ? 'Last reconciliation passed' : 'Last reconciliation failed'} · {ago(new Date(Number(recon[1]) * 1000).toISOString())}
          </div>
        ) : (
          <div className="banner info">No reconciliation has run yet.</div>
        )}
        <div className="recon">
          <div className="leg">
            <div className="small muted">Bank books: cash received</div>
            <div className="v">{usd(books?.bankUsd6, 2)}</div>
          </div>
          <div className="leg">
            <div className="small muted">On-ramp books: stablecoins minted</div>
            <div className="v">{usd(books?.onrampUsd6, 2)}</div>
          </div>
          <div className="leg">
            <div className="small muted">Onchain: credited as loan notes</div>
            <div className="v">{usd(snap?.totalFiatIn, 2)}</div>
          </div>
        </div>
        <div className="small muted">
          Market holds {usd(snap?.held, 2)} against {usd(snap?.reserved, 2)} owed to loans and lenders.
        </div>
      </div>

      <div className="split section">
        <div className="stack">
          <h2>Workflow runs</h2>
          {live.runs.length === 0 ? <div className="card empty">No runs yet.</div> : live.runs.slice(0, 30).map((r) => <RunLine key={r.id} run={r} config={live.config} />)}
        </div>
        <div className="stack">
          <h2>Fiat moved through the rails</h2>
          <div className="card tbl">
            <table>
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Ref</th>
                  <th>Amount</th>
                </tr>
              </thead>
              <tbody>
                {(live.state?.intents ?? []).map((i: Any) => (
                  <tr key={i.reference}>
                    <td>
                      Deposit <span className={`chip ${i.status === 'credited' ? 'green' : i.status === 'settled' ? 'warn' : ''}`}>{i.status}</span>
                    </td>
                    <td className="mono">{i.reference}</td>
                    <td>{money(i.amountMinor, i.currency)}</td>
                  </tr>
                ))}
                {(live.state?.payouts ?? []).map((p: Any) => (
                  <tr key={p.payoutRef}>
                    <td>Payout to {p.kind}</td>
                    <td className="mono">{p.payoutRef}</td>
                    <td>{usd(p.amount, 2)}</td>
                  </tr>
                ))}
                {(live.state?.bankCredits ?? [])
                  .filter((c: Any) => c.kind === 'repayment')
                  .map((c: Any) => (
                    <tr key={c.reference}>
                      <td>Repayment</td>
                      <td className="mono">{c.reference}</td>
                      <td>{money(c.amountMinor, c.currency)}</td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
          <h2 className="section">Lenders</h2>
          <div className="card stack">
            {(live.seed?.lenders ?? []).map((l: Any) => (
              <div key={l.id} className="row between">
                <div>
                  <div style={{ fontWeight: 600 }}>{l.name}</div>
                  <div className="small muted">
                    {l.country} · funds by {l.funding === 'fiat' ? 'bank transfer' : 'stablecoins'} · KYC {l.kycStatus}
                  </div>
                </div>
                <button
                  className="btn ghost"
                  disabled={!!busy}
                  onClick={() => act(`kyc-${l.id}`, () => api('/api/lender/onboard', { lenderId: l.id }), `KYC workflow started for ${l.name}`)}
                >
                  Run KYC on CRE
                </button>
              </div>
            ))}
          </div>
        </div>
      </div>
    </>
  )
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

function App() {
  const live = useLive()
  const { path, go } = usePath()
  const { msg, show } = useToast()
  const running = live.runs.some((r) => r.status === 'running' || r.status === 'queued')
  const loanMatch = path.match(/^\/loans\/(\d+)/)
  const page = loanMatch ? (
    <LoanDetail id={Number(loanMatch[1])} live={live} go={go} toast={show} />
  ) : path === '/business' ? (
    <Business live={live} toast={show} go={go} />
  ) : path === '/ops' ? (
    <Ops live={live} toast={show} />
  ) : (
    <Marketplace live={live} go={go} />
  )
  const nav = [
    ['/', 'Marketplace'],
    ['/business', 'Business'],
    ['/ops', 'Operations'],
  ]
  return (
    <>
      <header className="top">
        <div className="top-inner">
          <Link to="/" go={go} className="brand">
            <span className="brand-mark">tf</span> Tradeflow
          </Link>
          <nav className="nav">
            {nav.map(([to, label]) => (
              <Link key={to} to={to} go={go} className={(to === '/' ? path === '/' || path.startsWith('/loans') : path === to) ? 'active' : ''}>
                {label}
              </Link>
            ))}
          </nav>
          <div className="top-right">
            <span className="cre-pill" title="Workflows run on Chainlink CRE">
              <span className={`dot ${running ? 'live' : ''}`} /> {running ? 'CRE workflow running' : 'Chainlink CRE'}
            </span>
          </div>
        </div>
      </header>
      <main>{page}</main>
      <footer className="foot">
        <span>Tradeflow · built at TOKEN2049 Origins on Chainlink CRE</span>
        <span>by CodeDecoders, the team behind GSOS · gsos.io</span>
      </footer>
      {msg ? <div className="toast">{msg}</div> : null}
    </>
  )
}

createRoot(document.getElementById('root')!).render(<App />)
