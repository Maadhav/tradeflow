// The operator console: reserve checks, money movements, automated checks and investors.

import React from 'react'
import { Activity, ago, api, countryName, isActive, kycRunFor, money, short, usd, useAction, type Any, type Live, type Notify } from './shared'

export function Operations({ live, notify }: { live: Live; notify: Notify }) {
  const { busy, run } = useAction(live, notify)
  const snap = live.state?.snapshot
  const books = live.state?.books
  const recon = snap?.recon
  const hasRecon = recon && Number(recon[1]) > 0
  const lenders: Any[] = [...(live.state?.lenders ?? [])].sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)))
  const movements = [
    ...(live.state?.intents ?? []).map((i: Any) => ({ key: i.reference, at: i.settledAt ?? i.createdAt, what: 'Investor deposit', ref: i.reference, amount: money(i.amountMinor, i.currency, 2), state: i.status })),
    ...(live.state?.payouts ?? []).map((p: Any) => ({
      key: p.payoutRef,
      at: p.createdAt,
      what: p.kind === 'lender' ? 'Payout to investor' : String(p.idempotencyKey).startsWith('balance-') ? 'Balance to business' : 'Payout to business',
      ref: p.payoutRef,
      amount: usd(p.amount, 2),
      state: 'sent',
    })),
    ...(live.state?.bankCredits ?? [])
      .filter((c: Any) => c.kind === 'repayment')
      .map((c: Any) => ({ key: c.reference, at: c.valueDate, what: 'Buyer repayment', ref: c.reference, amount: money(c.amountMinor, c.currency, 2), state: 'received' })),
  ].sort((a, b) => String(b.at).localeCompare(String(a.at)))
  const STATE_TONE: Record<string, string> = { credited: 'good', sent: 'good', received: 'good', settled: 'warn', awaiting_funds: '', failed: 'bad' }
  const STATE_LABEL: Record<string, string> = { credited: 'Credited', sent: 'Sent', received: 'Received', settled: 'Verifying', awaiting_funds: 'Awaiting', failed: 'Failed' }
  const KYC: Record<string, { label: string; tone: string }> = {
    approved: { label: 'Approved', tone: 'good' },
    pending: { label: 'Pending', tone: 'warn' },
    rejected: { label: 'Rejected', tone: 'bad' },
  }

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
            <span>Credited to investors onchain</span>
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
      </div>

      <section className="panel" style={{ marginTop: 24 }}>
        <div className="panel-head">
          <h2>Investors</h2>
          {lenders.length ? <span className="small muted">{lenders.length}</span> : null}
        </div>
        {lenders.length === 0 ? (
          <div className="empty">No investors yet. Investors sign up from the Invest page.</div>
        ) : (
          <div className="scroll">
            <table>
              <thead>
                <tr>
                  <th>Investor</th>
                  <th className="hide-sm">Country</th>
                  <th>Funds by</th>
                  <th>Identity check</th>
                  <th className="r">
                    <span className="vh">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {lenders.map((l) => {
                  const k = KYC[l.kycStatus] ?? KYC.pending
                  const checking = isActive(kycRunFor(live, l.id))
                  return (
                    <tr key={l.id}>
                      <td>
                        {l.name}
                        <div className="small muted">Joined {ago(l.createdAt)}</div>
                      </td>
                      <td className="hide-sm">{countryName(l.country)}</td>
                      <td>
                        {l.funding === 'fiat' ? 'Bank transfer' : 'USDC'}
                        {l.funding === 'fiat' ? null : <div className="small muted code">{short(l.wallet)}</div>}
                      </td>
                      <td>
                        <span className={`tag ${k.tone}`}>{k.label}</span>
                        {checking ? <div className="small muted">Checking now</div> : null}
                      </td>
                      <td className="r">
                        <button
                          className="btn quiet sm"
                          disabled={!!busy || checking}
                          onClick={() => run(`kyc-${l.id}`, () => api(`/api/lenders/${l.id}/kyc`, {}), `Identity check started for ${l.name}`)}
                        >
                          Check
                        </button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <details className="tools">
        <summary>Operator tools</summary>
        <div className="panel panel-pad row">
          <span className="small muted" style={{ flex: '1 1 260px' }}>
            Book a bank deposit that has no matching on-ramp mint. The next reserve check finds the mismatch and pauses new funding until the books are corrected.
          </span>
          <button className="btn quiet" disabled={!!busy} onClick={() => run('book', () => api('/api/ops/book-unmatched-deposit', {}), 'Unmatched deposit booked')}>
            Book unmatched deposit
          </button>
          {live.state?.ledgerAdjustments?.length ? (
            <button className="btn quiet" disabled={!!busy} onClick={() => run('correct', () => api('/api/ops/correct-books', {}), 'Books corrected')}>
              Correct the books
            </button>
          ) : null}
        </div>
      </details>
    </>
  )
}
