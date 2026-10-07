// The landing page: what Tradeflow does, the public figures, and the two ways in.

import React from 'react'
import { LoanCard } from './loan'
import { Link, pct, usd, type Any, type Go, type Live, type Session } from './shared'

export function Landing({ live, go, session }: { live: Live; go: Go; session: Session }) {
  const loans: Any[] = live.state?.loans ?? []
  const financed = loans.filter((l) => l.status >= 3).reduce((s, l) => s + BigInt(l.target), 0n)
  const repaid = loans.filter((l) => l.status === 4).reduce((s, l) => s + BigInt(l.repaidAmount), 0n)
  const open = loans.filter((l) => l.status === 1)
  const aprs = open.map((l) => Number(l.aprBps))
  const terms = open.map((l) => Number(l.tenorDays))
  const range = (xs: number[], f: (n: number) => string) => (Math.min(...xs) === Math.max(...xs) ? f(xs[0]!) : `${f(Math.min(...xs))} to ${f(Math.max(...xs))}`)
  const featured = [...open].sort((a, b) => b.id - a.id).slice(0, 3)
  return (
    <>
      <h1 className="display">Trade finance for goods already on their way.</h1>
      <p className="lede">
        Businesses get paid today for invoices and shipping documents their buyers have confirmed. Investors fund them from a bank account or in USDC, and are repaid when the buyer pays.
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
          <span>repaid to investors</span>
        </div>
      </div>

      <div className="entries">
        <Link to="/investor" go={go} className="entry">
          <span className="eyebrow">Invest</span>
          <h2>Earn on trade a buyer has confirmed</h2>
          <p>Fund short-term loans backed by invoices, bills of lading and equipment orders. Each loan has a risk grade, an APR and a fixed term.</p>
          <ul className="ticks">
            <li>Invest from your bank account or in USDC</li>
            {open.length ? (
              <li>
                {range(aprs, pct)} APR over {range(terms, (n) => String(n))} days on open loans
              </li>
            ) : (
              <li>Repaid with interest when the buyer pays</li>
            )}
            <li>Your loan notes are ERC-3643 tokens held in your name</li>
          </ul>
          <span className="btn primary">{session.investor ? 'Open your portfolio' : 'Start investing'}</span>
        </Link>
        <Link to="/business" go={go} className="entry">
          <span className="eyebrow">Raise capital</span>
          <h2>Get paid for shipped goods today</h2>
          <p>Request an advance on a document your buyer owes you for. Your buyer confirms it, investors fund it, and the advance is paid to your bank.</p>
          <ul className="ticks">
            <li>Invoices, bills of lading and equipment orders</li>
            <li>Your credit file is reviewed privately, never shown to investors</li>
            <li>Paid out as soon as the advance is fully funded</li>
          </ul>
          <span className="btn primary">{session.business ? 'Open your overview' : 'Create business account'}</span>
        </Link>
      </div>

      {featured.length ? (
        <section className="featured">
          <div className="page-head" style={{ marginBottom: 16, alignItems: 'baseline' }}>
            <h2>Open for funding</h2>
            <Link to="/investor/marketplace" go={go} className="more">
              See all {open.length} in the marketplace
            </Link>
          </div>
          <div className="board">
            {featured.map((l) => (
              <LoanCard key={l.id} loan={l} live={live} go={go} to={`/investor/loans/${l.id}`} />
            ))}
          </div>
        </section>
      ) : null}
    </>
  )
}
