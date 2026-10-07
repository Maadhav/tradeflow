// One loan, as both portals show it: its card in a list, and its detail page (trade lane, terms,
// verification with the ERC-3643 loan notes, lifecycle, investors and activity). Each portal adds its
// own panels beside the detail: the investor's funding panel and position, the business's buyer link.

import React from 'react'
import {
  Activity,
  Addr,
  ASSET,
  bizFor,
  ccyOf,
  CopyLink,
  countryName,
  days,
  docFor,
  docType,
  dueOf,
  fmtDate,
  GRADE,
  Lane,
  lenderFor,
  Link,
  money,
  noteSymbol,
  pct,
  rate,
  sentence,
  short,
  Status,
  Tx,
  usd,
  ZERO_ADDRESS,
  type Any,
  type Go,
  type Live,
} from './shared'

export const fundedPct = (loan: Any) => Number((BigInt(loan.funded) * 1000n) / BigInt(loan.target || 1)) / 10

/** A loan card for lists: kind, grade, title, business, trade lane with funding progress, and terms. */
export function LoanCard({ loan, live, go, to, note }: { loan: Any; live: Live; go: Go; to: string; note?: React.ReactNode }) {
  const doc = docFor(live, loan)
  const biz = bizFor(live, loan.borrower)
  const progress = fundedPct(loan)
  return (
    <Link to={to} go={go} className="loan">
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
      {note ? <div className="loan-note">{note}</div> : null}
    </Link>
  )
}

/** Everything the loan page and its side panels derive from the public state. */
export function loanContext(loan: Any, live: Live) {
  const doc = docFor(live, loan)
  const biz = bizFor(live, loan.borrower)
  const ccy = ccyOf(loan.currency)
  const payouts: Any[] = (live.state?.payouts ?? []).filter((p: Any) => p.loanId === loan.id)
  return {
    doc,
    biz,
    ccy,
    progress: fundedPct(loan),
    fundings: (live.state?.fundings ?? []).filter((f: Any) => Number(f.loanId) === loan.id) as Any[],
    runs: live.runs.filter((r) => r.loanId === loan.id || String(r.input ?? '').includes(loan.ref)),
    repayment: (live.state?.bankCredits ?? []).find((c: Any) => c.kind === 'repayment' && c.reference.startsWith(`PAY-${loan.id}-`)),
    disbursedPayout: payouts.find((p) => p.kind === 'business' && String(p.idempotencyKey).startsWith('disburse-')),
    balancePayout: payouts.find((p) => p.kind === 'business' && String(p.idempotencyKey).startsWith('balance-')),
    lenderPayouts: payouts.filter((p) => p.kind === 'lender'),
    buyer: (doc?.buyer as string | undefined) ?? 'the buyer',
    noun: docType(doc?.type).noun,
    face: money(loan.faceValueMinor, ccy, 2),
    owed: usd(dueOf(loan), 2),
    // One due date everywhere: the document's. Lateness comes from the onchain clock, so a late loan
    // also says when it went overdue (the maturity it missed), without changing the due date.
    dueText: fmtDate(doc?.dueDate ?? loan.maturity),
    overdueSince: loan.status >= 5 ? fmtDate(loan.maturity) : '',
    bizName: (biz?.name as string | undefined) ?? 'the business',
  }
}
export type LoanCtx = ReturnType<typeof loanContext>

export function LoanMissing({ go, to, label, text = 'This loan does not exist.' }: { go: Go; to: string; label: string; text?: string }) {
  return (
    <div className="panel empty">
      {text}{' '}
      <Link to={to} go={go}>
        {label}
      </Link>
    </div>
  )
}

/**
 * The loan page body. `children` are the portal's own panels, shown above the activity. `tag` is the
 * status in the page header, in the words of the portal's own lists (the loan's public status when
 * none is given).
 */
export function LoanDetail({
  loan,
  live,
  go,
  crumb,
  tag,
  children,
}: {
  loan: Any
  live: Live
  go: Go
  crumb: { to: string; label: string }
  tag?: React.ReactNode
  children?: React.ReactNode
}) {
  const c = loanContext(loan, live)
  const { doc, biz, ccy, buyer, noun } = c
  const steps = [
    { what: 'Verified and listed', detail: `Document and buyer confirmed, sanctions screened, credit reviewed privately (grade ${GRADE[loan.riskGrade]}).`, done: true },
    {
      what: 'Funded by investors',
      detail: loan.status === 1 ? `${usd(loan.funded)} of ${usd(loan.target)} raised.` : `${usd(loan.target)} raised, ${usd(loan.fiatFunded)} by bank transfer.`,
      done: loan.status >= 2,
    },
    {
      what: 'Paid to the business',
      detail: c.disbursedPayout
        ? `${usd(c.disbursedPayout.amount)} sent to ${biz?.name}, ${c.disbursedPayout.payoutRef}.`
        : 'Paid out in local currency as soon as the loan is fully funded.',
      done: loan.status >= 3,
    },
    {
      what: loan.status === 5 ? 'Payment overdue' : loan.status === 6 ? 'Defaulted' : 'Repaid by the buyer',
      detail:
        loan.status === 4
          ? `${sentence(buyer)} paid the ${noun}. Investors received ${usd(loan.repaidAmount, 2)}${c.balancePayout ? `, and ${c.bizName} the balance of ${usd(c.balancePayout.amount, 2)}` : ''}.`
          : loan.status >= 5
            ? `${sentence(buyer)} has not paid. ${biz?.name ?? 'The business'} cannot raise new financing.`
            : `${sentence(buyer)} pays the ${noun}, ${c.face}, after ${days(loan.tenorDays)}. Investors receive ${c.owed}, and the balance goes to ${c.bizName}.`,
      done: loan.status === 4,
      bad: loan.status >= 5,
    },
  ]
  const nowIdx = steps.findIndex((s) => !s.done && !s.bad)

  return (
    <>
      <div className="crumb">
        <Link to={crumb.to} go={go}>
          {crumb.label}
        </Link>{' '}
        / <span className="code">{loan.ref}</span>
      </div>
      <div className="page-head" style={{ marginBottom: 20 }}>
        <div>
          <h1>{doc?.title ?? loan.ref}</h1>
          <div className="muted" style={{ marginTop: 6 }}>
            {biz?.name}, selling to {buyer}
          </div>
        </div>
        {tag ?? <Status s={loan.status} />}
      </div>

      <div className="split loan-split">
        <div className="stack loan-main" style={{ gap: 20 }}>
          <div className="panel panel-pad loan-key">
            <Lane from={biz?.country} to={doc?.buyerCountry} progress={loan.status === 1 ? c.progress : 100} status={loan.status} />
          </div>
          <dl className="facts loan-key" style={{ margin: 0 }}>
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

          <section className="panel loan-more">
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
                    {doc?.fileName ? <div className="small muted">Attached: {doc.fileName}</div> : null}
                  </td>
                </tr>
                <tr>
                  <td>Buyer</td>
                  <td>
                    {buyer}, {countryName(doc?.buyerCountry)}.{' '}
                    {doc?.respondedAt ? `Confirmed by ${doc.respondedBy || 'the buyer'} on ${fmtDate(doc.respondedAt)}.` : 'Confirmed by the buyer.'}
                  </td>
                </tr>
                <tr>
                  <td>Exchange rate</td>
                  <td>{ccy === 'USD' ? 'Priced in USD' : `${ccy}/USD ${rate(loan.fxRateE8)} reference rate at listing`}</td>
                </tr>
                <tr>
                  <td>Credit review</td>
                  <td>Grade {GRADE[loan.riskGrade]}. Reviewed privately: the business's financial data is never shown to investors.</td>
                </tr>
                <tr>
                  <td>Fingerprint</td>
                  <td className="code">{short(loan.docHash)}</td>
                </tr>
                {loan.loanToken && loan.loanToken !== ZERO_ADDRESS ? (
                  <tr>
                    <td>Loan notes</td>
                    <td>
                      <Addr a={loan.loanToken} live={live}>
                        ERC-3643 token {noteSymbol(loan.id)}
                      </Addr>{' '}
                      {live.config?.explorer ? null : <span className="code small muted">{short(loan.loanToken)}</span>}
                      <div className="small muted">
                        One token for this loan, held only by investors with a verified identity.
                        {loan.status >= 5 ? ' Transfers are paused until the loan is repaid.' : ''}
                      </div>
                    </td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </section>

          <section className="panel loan-more">
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

          <section className="panel loan-more">
            <div className="panel-head">
              <h2>Investors</h2>
              <span className="small muted">{c.fundings.length}</span>
            </div>
            {c.fundings.length === 0 ? (
              <div className="empty">No one has funded this loan yet.</div>
            ) : (
              <div className="scroll">
                <table>
                  <thead>
                    <tr>
                      <th>Investor</th>
                      <th>Paid by</th>
                      <th className="r">Amount</th>
                      <th className="r">Transaction</th>
                    </tr>
                  </thead>
                  <tbody>
                    {c.fundings.map((f: Any) => (
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

        <div className="stack loan-side" style={{ gap: 20 }}>
          {children}
          <section className="panel loan-activity">
            <div className="panel-head">
              <h2>Activity</h2>
            </div>
            <Activity runs={c.runs.slice(0, 10)} live={live} empty="Activity on this loan will appear here." />
          </section>
        </div>
      </div>
    </>
  )
}

/**
 * Where the loan stands once it is no longer raising: funded, being repaid, repaid or in default.
 * The business also sees its buyer link here, which its buyer pays through.
 */
export function LoanStatusPanel({ loan, live, audience, buyerLink, children }: { loan: Any; live: Live; audience: 'investor' | 'business'; buyerLink?: string | null; children?: React.ReactNode }) {
  const c = loanContext(loan, live)
  const business = audience === 'business'
  const investors = c.fundings.length === 1 ? '1 investor' : `${c.fundings.length} investors`
  const link =
    business && buyerLink !== undefined ? (
      buyerLink ? (
        <div className="fld">
          <span className="lbl">Buyer link</span>
          <CopyLink path={buyerLink} stacked />
          <div className="hint">
            {loan.status >= 3 ? `Send this link to ${c.buyer} so they can pay.` : `${sentence(c.buyer)} pays through this link when the ${c.noun} is due.`}
          </div>
        </div>
      ) : (
        <div className="small muted">Loading your buyer link…</div>
      )
    ) : null

  if (loan.status === 1)
    return business ? (
      <section className="panel panel-pad stack">
        <h2>Raising</h2>
        <div className="small muted">
          {usd(loan.funded)} of {usd(loan.target)} raised ({c.progress.toFixed(0)}%). The advance is paid to your bank account as soon as investors fully fund it.
        </div>
        {link}
      </section>
    ) : null

  if (loan.status === 2)
    return (
      <section className="panel panel-pad stack">
        <h2>Fully funded</h2>
        <div className="small muted">
          {usd(loan.target)} raised from {investors}. The advance is being paid to {business ? 'your bank account' : c.bizName} now.
        </div>
        {children}
        {link}
      </section>
    )

  if (loan.status === 3 || loan.status === 5)
    return (
      <section className="panel panel-pad stack">
        <h2>Repayment</h2>
        {loan.status === 5 ? <div className="say bad small">{c.overdueSince ? `Payment has been overdue since ${c.overdueSince}.` : 'Payment is overdue.'}</div> : null}
        <div className="small muted">
          {sentence(c.buyer)} pays the {c.noun}, {c.face}
          {c.dueText ? `, due on ${c.dueText}` : ''}, through {business ? 'the buyer link' : 'their payment link'}. Once the bank and the payment processor both confirm the payment, investors receive{' '}
          {c.owed} and the balance goes to {business ? 'you' : c.bizName}.
        </div>
        {children}
        {link}
      </section>
    )

  if (loan.status === 4)
    return (
      <section className="panel panel-pad stack">
        <h2>Repaid</h2>
        <div className="small muted">
          {business
            ? `${sentence(c.buyer)} paid the ${c.noun}. Investors received ${usd(loan.repaidAmount, 2)}${c.balancePayout ? `, and the balance of ${usd(c.balancePayout.amount, 2)} was paid to your bank account (${c.balancePayout.payoutRef})` : ''}.`
            : `${usd(loan.repaidAmount, 2)} repaid to investors${c.repayment ? ` (${c.repayment.reference})` : ''}.${
                BigInt(loan.fiatFunded) === 0n
                  ? ''
                  : c.lenderPayouts.length
                    ? ' Bank-transfer investors have been paid to their accounts.'
                    : ' Paying bank-transfer investors to their accounts now.'
              }`}
        </div>
        {children}
      </section>
    )

  if (loan.status === 6)
    return (
      <section className="panel panel-pad stack">
        <h2>Defaulted</h2>
        <div className="say bad small">
          {business
            ? `${sentence(c.buyer)} has not paid the ${c.noun}. New requests from your business cannot be listed.`
            : `${sentence(c.buyer)} has not paid the ${c.noun}. The loan is in default and its ${noteSymbol(loan.id)} notes are paused.`}
        </div>
        {children}
        {link}
      </section>
    )

  return null
}
