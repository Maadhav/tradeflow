// The business portal (/business): create the account or sign in, then an overview of the business
// (totals, next due item, documents with their statuses and buyer links), the request financing form,
// and a read-only page for each of its loans.

import React, { useEffect, useState } from 'react'
import { LoanDetail, LoanMissing, LoanStatusPanel } from './loan'
import {
  Activity,
  addDays,
  api,
  bizHeaders,
  BUSINESS_STATUS,
  ccyOf,
  CopyLink,
  CountryField,
  countryName,
  days,
  daysBetween,
  decimal,
  docType,
  DOC_TYPES,
  emailError,
  Field,
  fileSize,
  fmtDate,
  isoDay,
  Link,
  Loading,
  money,
  need,
  Redirect,
  rememberReturn,
  runInput,
  sameAddr,
  sentence,
  StateText,
  takeReturn,
  TextField,
  Tiles,
  usd,
  useAction,
  useForm,
  type Any,
  type ApiError,
  type BizSession,
  type BusinessView,
  type Go,
  type Live,
  type Notify,
  type ReqState,
  type Session,
} from './shared'

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

export function Business({
  path,
  live,
  go,
  replace,
  notify,
  session,
  view,
}: {
  path: string
  live: Live
  go: Go
  replace: Go
  notify: Notify
  session: Session
  view: BusinessView
}) {
  const [lost, setLost] = useState(false)
  const { setBusiness, business } = session
  useEffect(() => {
    if (view.missing) {
      setBusiness(null)
      setLost(true)
    }
  }, [view.missing, setBusiness])
  useEffect(() => {
    if (business) setLost(false)
  }, [business])

  if (!business) {
    if (path !== '/business') {
      rememberReturn('business', path)
      return <Redirect to="/business" replace={replace} />
    }
    const signedIn = () => {
      const next = takeReturn('business')
      if (next && next !== '/business') go(next)
    }
    return <BusinessSignup live={live} notify={notify} session={session} lost={lost} onSignedIn={signedIn} />
  }
  if (!view.data)
    return view.error ? (
      <div className="panel empty stack" style={{ justifyItems: 'center' }} role="alert">
        <div>{view.error}</div>
        <button className="btn quiet" onClick={() => void view.reload()}>
          Try again
        </button>
      </div>
    ) : (
      <Loading text="Loading your account" />
    )
  if (path === '/business') return <Overview data={view.data} reload={view.reload} live={live} go={go} notify={notify} session={session} />
  if (path === '/business/new') return <NewRequest data={view.data} reload={view.reload} live={live} go={go} notify={notify} session={session} />
  const loanMatch = path.match(/^\/business\/loans\/(\d+)$/)
  if (loanMatch) return <BusinessLoan key={loanMatch[1]} id={Number(loanMatch[1])} data={view.data} live={live} go={go} />
  return <Redirect to="/business" replace={replace} />
}

// ---------------------------------------------------------------------------
// Overview
// ---------------------------------------------------------------------------

type Totals = {
  advancedUsd6: string | bigint
  outstandingUsd6: string | bigint
  repaidUsd6: string | bigint
  inReview: number
  nextDue?: { docNumber: string; buyer: string; dueDate: string | number; amountMinor: number | string; currency: string; maturity?: string | number; late?: boolean }
}

/** The loans of this business, by document number. */
const loansOf = (live: Live, business: Any): Any[] => (live.state?.loans ?? []).filter((l: Any) => sameAddr(l.borrower, business.wallet))
/** A loan's document amount in USD (6 decimals), at the rate it was listed with. */
const faceUsd6 = (l: Any) => (BigInt(l.faceValueMinor) * BigInt(BigInt(l.fxRateE8 || 0) > 0n ? l.fxRateE8 : 100_000_000)) / 10_000n

/** The server's overview totals; worked out from the public state when the server does not send them. */
function overviewOf(data: Any, docs: Any[], live: Live): Totals {
  if (data.overview) return data.overview
  const loans = loansOf(live, data.business)
  const owed = loans.filter((l) => l.status === 3 || l.status === 5)
  const next = [...owed].sort((a, b) => Number(a.maturity) - Number(b.maturity))[0]
  const nextDoc = next ? docs.find((d) => d.number === next.ref) : undefined
  return {
    advancedUsd6: loans.filter((l) => l.status >= 3).reduce((s, l) => s + BigInt(l.target), 0n),
    outstandingUsd6: owed.reduce((s, l) => s + faceUsd6(l), 0n),
    repaidUsd6: loans.filter((l) => l.status === 4).reduce((s, l) => s + faceUsd6(l), 0n),
    inReview: docs.filter((d) => d.status !== 'awaiting_buyer' && (d.review?.status ?? 'in_review') === 'in_review' && !loanOfDoc(d, live, data.business)).length,
    nextDue: next
      ? {
          docNumber: next.ref,
          buyer: nextDoc?.buyer ?? 'Your buyer',
          dueDate: nextDoc?.dueDate ?? next.maturity,
          amountMinor: next.faceValueMinor,
          currency: ccyOf(next.currency),
          maturity: next.maturity,
          late: next.status >= 5,
        }
      : undefined,
  }
}

/** Days from today to a due date ('YYYY-MM-DD' or unix seconds). */
function daysTo(v: string | number): number {
  const s = String(v)
  const today = isoDay(new Date())
  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return daysBetween(today, s)
  if (/^\d+$/.test(s)) return daysBetween(today, isoDay(new Date(Number(s) * 1000)))
  return 0
}

function Overview({ data, reload, live, go, notify, session }: { data: Any; reload: () => Promise<void>; live: Live; go: Go; notify: Notify; session: Session }) {
  const { business } = data
  const auth = session.business!
  const docs: Any[] = [...(data.documents ?? [])].sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)))
  const runs = live.runs.filter((r) => r.handler === 'verify-and-list' && runInput(r).borrowerId === business.id)
  const overdue = loansOf(live, business).filter((l) => l.status >= 5)
  // The market freezes a business when one of its loans goes late, and keeps it frozen after.
  const frozen = overdue.length > 0 || data.overview?.frozen === true
  const o = overviewOf(data, docs, live)
  const inReview = Number(o.inReview ?? 0)
  return (
    <>
      <div className="page-head">
        <div>
          <h1>{business.name}</h1>
          <div className="muted" style={{ marginTop: 6 }}>
            {countryName(business.country)}
            {business.registrationNumber ? `, registration ${business.registrationNumber}` : ''}
          </div>
        </div>
        <Link to="/business/new" go={go} className="btn primary">
          Request financing
        </Link>
      </div>
      <div className="dash">
        {frozen ? <FrozenNotice overdue={overdue} docs={docs} /> : null}
        <Tiles
          label="Business summary"
          items={[
            { label: 'Advanced to date', value: usd(o.advancedUsd6), note: 'Paid to your bank account' },
            { label: 'Owed by buyers', value: usd(o.outstandingUsd6), note: 'On financed documents not yet paid' },
            { label: 'Repaid', value: usd(o.repaidUsd6), note: 'Paid by buyers' },
            { label: 'In review', value: <span className="num">{inReview}</span>, note: inReview === 1 ? 'Document being reviewed' : 'Documents being reviewed' },
          ]}
        />
        <div className="split">
          <Documents docs={docs} live={live} business={business} go={go} auth={auth} notify={notify} reload={reload} />
          <div className="stack" style={{ gap: 20 }}>
            <NextDue o={o} docs={docs} live={live} business={business} go={go} />
            <section className="panel">
              <div className="panel-head">
                <h2>Business profile</h2>
              </div>
              <table className="kv">
                <tbody>
                  <tr>
                    <td>Legal name</td>
                    <td>{business.name}</td>
                  </tr>
                  <tr>
                    <td>Country</td>
                    <td>{countryName(business.country)}</td>
                  </tr>
                  <tr>
                    <td>Registration</td>
                    <td className="code">{business.registrationNumber}</td>
                  </tr>
                  {business.email ? (
                    <tr>
                      <td>Work email</td>
                      <td style={{ overflowWrap: 'anywhere' }}>{business.email}</td>
                    </tr>
                  ) : null}
                  <tr>
                    <td>Payouts to</td>
                    <td>
                      Account ending <span className="code">{business.bankAccountEnding}</span>
                    </td>
                  </tr>
                </tbody>
              </table>
            </section>
            <section className="panel">
              <div className="panel-head">
                <h2>Recent reviews</h2>
              </div>
              <Activity runs={runs.slice(0, 6)} live={live} empty="Reviews start as soon as a buyer responds to one of your documents." />
            </section>
          </div>
        </div>
      </div>
    </>
  )
}

/** A late loan freezes the business onchain: say why, and who still has to pay. */
function FrozenNotice({ overdue, docs }: { overdue: Any[]; docs: Any[] }) {
  return (
    <div className="banner bad" role="status">
      {frozenText(overdue, docs)}
    </div>
  )
}
function frozenText(overdue: Any[], docs: Any[]): string {
  if (!overdue.length) return 'A payment on one of your financed documents was late, so new requests from this business cannot be listed.'
  const buyers = [...new Set(overdue.map((l) => docs.find((d) => d.number === l.ref)?.buyer).filter(Boolean))]
  return `Payment on ${overdue.map((l: Any) => l.ref).join(', ')} is overdue, so new requests from this business cannot be listed.${
    buyers.length ? ` Ask ${buyers.join(' and ')} to pay through the buyer link.` : ''
  }`
}

function NextDue({ o, docs, live, business, go }: { o: Totals; docs: Any[]; live: Live; business: Any; go: Go }) {
  const n = o.nextDue
  const doc = n ? docs.find((d) => d.number === n.docNumber) : undefined
  const loan = doc ? loanOfDoc(doc, live, business) : undefined
  // One due date everywhere: the document's. A late loan missed its onchain maturity, which can fall
  // before or after that date, so it also says since when it is overdue.
  const late = n?.late === true
  const since = late && Number(n?.maturity) > 0 ? n!.maturity! : undefined
  const left = n ? daysTo(n.dueDate) : 0
  const overdueDays = since !== undefined ? -daysTo(since) : -left
  const when: ReqState | null = !n
    ? null
    : late || left < 0
      ? { label: overdueDays > 0 ? `${days(overdueDays)} overdue` : 'Overdue', tone: 'bad' }
      : left > 0
        ? { label: left === 1 ? 'Tomorrow' : `In ${days(left)}`, tone: 'info' }
        : { label: 'Due today', tone: 'warn' }
  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Next due</h2>
        {when ? <StateText s={when} /> : null}
      </div>
      <div className="panel-pad">
        {n ? (
          <div className="next-due">
            <div className="nd-date">{fmtDate(n.dueDate)}</div>
            {since !== undefined ? <div className="small say bad">Overdue since {fmtDate(since)}</div> : null}
            <div className="nd-amount">{money(n.amountMinor, String(n.currency).startsWith('0x') ? ccyOf(n.currency) : n.currency, 2)}</div>
            <div className="small muted">
              From {n.buyer} for <span className="code">{n.docNumber}</span>
            </div>
            {loan ? (
              <div className="small" style={{ marginTop: 8 }}>
                <Link to={`/business/loans/${loan.id}`} go={go}>
                  View loan
                </Link>
              </div>
            ) : null}
          </div>
        ) : (
          <div className="small muted">Nothing is due. When a financed document comes due, its buyer pays through the buyer link and it shows here.</div>
        )}
      </div>
    </section>
  )
}

/** Every document with its status; buyer link actions while the buyer has not answered; the loan once listed. */
function Documents({
  docs,
  live,
  business,
  go,
  auth,
  notify,
  reload,
}: {
  docs: Any[]
  live: Live
  business: Any
  go: Go
  auth: BizSession
  notify: Notify
  reload: () => Promise<void>
}) {
  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Documents</h2>
        {docs.length ? <span className="small muted">{docs.length}</span> : null}
      </div>
      {docs.length === 0 ? (
        <div className="empty">
          You have no documents yet.{' '}
          <Link to="/business/new" go={go}>
            Request financing
          </Link>{' '}
          for an invoice, bill of lading or equipment order, then send the buyer link to your buyer.
        </div>
      ) : (
        <div className="scroll">
          <table className="rtable docs">
            <thead>
              <tr>
                <th>Document</th>
                <th>Buyer</th>
                <th className="r">Amount</th>
                <th>Due</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {docs.map((d) => {
                const st = requestState(d, live, business)
                const loan = st.loanId ? loanOfDoc(d, live, business) : undefined
                // A late loan keeps the document's due date, and says since when it is overdue.
                const overdueSince = loan && Number(loan.status) >= 5 && Number(loan.maturity) > 0 ? fmtDate(loan.maturity) : ''
                const kind = docType(d.type)
                const description = String(d.title ?? '').startsWith(kind.prefix) ? String(d.title).slice(kind.prefix.length) : d.title
                const pending = d.status === 'awaiting_buyer' && !!d.buyerLink
                const sub = pending || !!st.reason || !!st.retry || !!d.disputeReason
                const label = (
                  <>
                    {kind.label} <span className="code">{d.number}</span>
                  </>
                )
                return (
                  <React.Fragment key={`${d.number}|${d.buyer}`}>
                    <tr className={sub ? 'has-sub' : ''}>
                      <td className="cell-main">
                        {st.loanId ? (
                          <Link to={`/business/loans/${st.loanId}`} go={go} className="title-link">
                            {label}
                          </Link>
                        ) : (
                          <span className="strong">{label}</span>
                        )}
                        <div className="small muted">{description}</div>
                      </td>
                      <td data-label="Buyer">
                        {d.buyer}
                        <div className="small muted">{countryName(d.buyerCountry)}</div>
                      </td>
                      <td data-label="Amount" className="r">
                        {money(d.amountMinor, d.currency, 2)}
                      </td>
                      <td data-label="Due">
                        {fmtDate(d.dueDate)}
                        {overdueSince ? <div className="small say bad">Overdue since {overdueSince}</div> : null}
                      </td>
                      <td data-label="Status">
                        <StateText s={st} />
                        {st.loanId ? (
                          <div className="small">
                            <Link to={`/business/loans/${st.loanId}`} go={go}>
                              View loan
                            </Link>
                          </div>
                        ) : null}
                      </td>
                    </tr>
                    {sub ? (
                      <tr className="sub">
                        <td colSpan={5}>
                          {pending ? (
                            <div className="stack" style={{ gap: 8 }}>
                              <div className="small muted">Send this link to {d.buyer} so they can confirm the {kind.noun}. Nothing is listed until they do.</div>
                              <CopyLink path={d.buyerLink} />
                              {d.buyerEmail ? (
                                <div>
                                  <a className="btn quiet sm" href={mailtoFor(d, business)}>
                                    Email the link to {d.buyerEmail}
                                  </a>
                                </div>
                              ) : null}
                            </div>
                          ) : null}
                          <StateDetail st={st} doc={d} auth={auth} notify={notify} reload={reload} live={live} />
                          {d.disputeReason ? <div className="small muted">Buyer's note: {d.disputeReason}</div> : null}
                        </td>
                      </tr>
                    ) : null}
                  </React.Fragment>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}

// ---------------------------------------------------------------------------
// Request financing (/business/new)
// ---------------------------------------------------------------------------

function NewRequest({ data, reload, live, go, notify, session }: { data: Any; reload: () => Promise<void>; live: Live; go: Go; notify: Notify; session: Session }) {
  const { business } = data
  const auth = session.business!
  const [sent, setSent] = useState<{ document: Any; buyerLink: string } | null>(null)
  const docs: Any[] = data.documents ?? []
  const sentDoc = sent ? { ...sent.document, buyerLink: sent.buyerLink, ...docs.find((d) => d.number === sent.document.number && d.buyer === sent.document.buyer) } : null
  const overdue = loansOf(live, business).filter((l) => l.status >= 5)
  const frozen = overdue.length > 0 || data.overview?.frozen === true
  return (
    <>
      <div className="crumb">
        <Link to="/business" go={go}>
          Overview
        </Link>{' '}
        / Request financing
      </div>
      <div className="page-head" style={{ marginBottom: 24 }}>
        <div>
          <h1>Request financing</h1>
          <div className="muted" style={{ marginTop: 6, maxWidth: '62ch' }}>
            Add a document your buyer owes you for. We create a link for your buyer to confirm it; once they do, it is reviewed and listed for investors.
          </div>
        </div>
      </div>
      <div className="split">
        {sentDoc ? (
          <WaitingPanel
            doc={sentDoc}
            live={live}
            business={business}
            go={go}
            auth={auth}
            notify={notify}
            reload={reload}
            onNew={() => {
              setSent(null)
              window.scrollTo(0, 0)
            }}
          />
        ) : (
          <RequestForm
            business={business}
            auth={auth}
            live={live}
            frozen={frozen ? frozenText(overdue, docs) : ''}
            onSent={(r) => {
              setSent(r)
              window.scrollTo(0, 0)
              void reload()
            }}
          />
        )}
        <section className="panel">
          <div className="panel-head">
            <h2>What happens next</h2>
          </div>
          <ol className="steps">
            <li className={sentDoc ? 'done' : 'now'}>
              <div>
                <div className="what">Create the buyer link</div>
                <div className="detail">Enter the document as it was issued. Attach the file if you have it.</div>
              </div>
            </li>
            <li className={sentDoc ? 'now' : ''}>
              <div>
                <div className="what">Your buyer confirms it</div>
                <div className="detail">Send them the link. They confirm the document, or dispute it with a reason you can see.</div>
              </div>
            </li>
            <li>
              <div>
                <div className="what">Reviewed and listed</div>
                <div className="detail">We check the document and your credit file privately, then list it for investors with a grade and an APR.</div>
              </div>
            </li>
            <li>
              <div>
                <div className="what">Paid to your bank</div>
                <div className="detail">As soon as investors fully fund the advance it is paid to your account ending {business.bankAccountEnding}.</div>
              </div>
            </li>
          </ol>
        </section>
      </div>
    </>
  )
}

// ---------------------------------------------------------------------------
// Loan page (business, read only)
// ---------------------------------------------------------------------------

function BusinessLoan({ id, data, live, go }: { id: number; data: Any; live: Live; go: Go }) {
  const loan = live.state?.loans?.find((l: Any) => l.id === id)
  if (!loan) return <LoanMissing go={go} to="/business" label="Back to your overview" />
  if (!sameAddr(loan.borrower, data.business.wallet))
    return <LoanMissing go={go} to="/business" label="Back to your overview" text="This loan belongs to another business." />
  const doc = (data.documents ?? []).find((d: Any) => d.number === loan.ref)
  const st = BUSINESS_STATUS[Number(loan.status)]
  return (
    <LoanDetail loan={loan} live={live} go={go} crumb={{ to: '/business', label: 'Overview' }} tag={st ? <StateText s={st} /> : undefined}>
      <LoanStatusPanel loan={loan} live={live} audience="business" buyerLink={doc ? (doc.buyerLink ?? null) : undefined} />
    </LoanDetail>
  )
}

// ---------------------------------------------------------------------------
// Statuses, sign-up and sign-in, the request form
// ---------------------------------------------------------------------------

/** The listed loan behind a document: the server's summary, else matched in the public state. */
function loanOfDoc(doc: Any, live: Live, business: Any): Any | undefined {
  if (doc.loan) return doc.loan
  return (live.state?.loans ?? []).find((l: Any) => l.ref === doc.number && sameAddr(l.borrower, business.wallet))
}

/** What the business can do after a review said no, by the workflow's reason. */
function nextStep(reason: string, doc: Any): string {
  if (/disputed/.test(reason)) return `Talk to ${doc.buyer} about the reason they gave.`
  if (/credit grade/.test(reason)) return 'Your credit file is below what investors can finance today. You can request financing for other documents once it improves.'
  if (/sanctions/.test(reason)) return 'Requests from this business cannot be financed.'
  if (/already financed/.test(reason)) return 'A document with this fingerprint has been financed before, so it cannot be financed again.'
  return ''
}

/** Where a business's request stands: the buyer's response, then the review (kept by the server), then the loan onchain. */
function requestState(doc: Any, live: Live, business: Any): ReqState {
  const loan = loanOfDoc(doc, live, business)
  if (loan) return { ...(BUSINESS_STATUS[Number(loan.status)] ?? BUSINESS_STATUS[1]!), loanId: Number(loan.id) }
  if (doc.status === 'awaiting_buyer') return { label: 'Waiting for buyer', tone: 'warn' }
  const review = doc.review ?? { status: 'in_review' }
  if (review.status === 'rejected') return { label: 'Not approved', tone: 'bad', reason: sentence(review.reason), next: nextStep(review.reason ?? '', doc) }
  if (review.status === 'failed') return { label: 'Review did not finish', tone: 'warn', retry: true }
  if (review.status === 'listed') return { label: 'Listed', tone: 'info' }
  return { label: 'In review', tone: 'info' }
}

function BusinessSignup({ live, notify, session, lost, onSignedIn }: { live: Live; notify: Notify; session: Session; lost: boolean; onSignedIn: () => void }) {
  const [mode, setMode] = useState<'create' | 'signin'>(lost ? 'signin' : 'create')
  const [carry, setCarry] = useState<{ country: string; registrationNumber: string; note: string } | null>(null)
  const switchTo = (m: 'create' | 'signin') => {
    setCarry(null)
    setMode(m)
  }
  return (
    <>
      <h1 className="display">Get paid for shipped goods today.</h1>
      <p className="lede">Request an advance on an invoice, bill of lading or equipment order. Your buyer confirms the document, investors fund it, and the advance is paid to your bank.</p>
      <div className="split" style={{ marginTop: 36 }}>
        <section className="panel">
          <div className="panel-head">
            <h2>{mode === 'create' ? 'Tell us about your business' : 'Sign in to your business account'}</h2>
          </div>
          {lost && mode === 'signin' && !carry ? (
            <div className="notice idle">This browser is no longer signed in to your business account. Sign in with your country, registration number and work email.</div>
          ) : null}
          {carry ? <div className="notice idle">{carry.note}</div> : null}
          {mode === 'create' ? (
            <CreateBusiness
              live={live}
              notify={notify}
              session={session}
              onSignedIn={onSignedIn}
              onExists={(c) => {
                setCarry(c)
                setMode('signin')
              }}
              onSignIn={() => switchTo('signin')}
            />
          ) : (
            <SignInBusiness
              key={carry ? 'carry' : 'plain'}
              live={live}
              notify={notify}
              session={session}
              initial={carry}
              onCreate={() => switchTo('create')}
              onSignedIn={onSignedIn}
            />
          )}
        </section>
        <section className="panel">
          <div className="panel-head">
            <h2>How it works</h2>
          </div>
          <ol className="steps">
            <li>
              <div>
                <div className="what">Tell us about your business</div>
                <div className="detail">We use your registration number to pull your credit file. It is reviewed privately and never shown to investors.</div>
              </div>
            </li>
            <li>
              <div>
                <div className="what">Add a document</div>
                <div className="detail">An invoice, bill of lading or equipment order that a buyer owes you for.</div>
              </div>
            </li>
            <li>
              <div>
                <div className="what">Your buyer confirms it</div>
                <div className="detail">Send your buyer the link we create. Once they confirm, the request is reviewed and listed.</div>
              </div>
            </li>
            <li>
              <div>
                <div className="what">Get paid</div>
                <div className="detail">When investors fully fund the advance it is paid to your bank account. Your buyer pays the full amount on the due date, and the balance after investors are repaid comes to you.</div>
              </div>
            </li>
          </ol>
        </section>
      </div>
    </>
  )
}

function CreateBusiness({
  live,
  notify,
  session,
  onExists,
  onSignIn,
  onSignedIn,
}: {
  live: Live
  notify: Notify
  session: Session
  onExists: (c: { country: string; registrationNumber: string; note: string }) => void
  onSignIn: () => void
  onSignedIn: () => void
}) {
  const f = useForm('biz', { name: '', country: '', registrationNumber: '', bankAccount: '', email: '' })
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    const v = f.values
    const ok = f.check({
      name: need(v.name, 'Enter the legal name of your business.'),
      country: v.country ? undefined : 'Choose the country where your business is registered.',
      registrationNumber: need(v.registrationNumber, 'Enter your company registration number.'),
      bankAccount: need(v.bankAccount, 'Enter the bank account where advances should be paid.'),
      email: emailError(v.email),
    })
    if (!ok) return
    setBusy(true)
    setError('')
    try {
      const r = await api('/api/businesses', {
        name: v.name.trim(),
        country: v.country,
        registrationNumber: v.registrationNumber.trim(),
        bankAccount: v.bankAccount.trim(),
        email: v.email.trim(),
      })
      session.setBusiness({ id: r.business.id, key: r.key })
      notify(`Welcome to Tradeflow, ${r.business.name}`)
      onSignedIn()
      void live.refresh()
    } catch (err) {
      if ((err as ApiError).status === 409) {
        onExists({
          country: v.country,
          registrationNumber: v.registrationNumber.trim(),
          note: 'A business with this registration number is already registered. Sign in with the work email on file. Nothing you entered was saved.',
        })
      } else setError((err as Error).message)
    } finally {
      setBusy(false)
    }
  }
  return (
    <form className="form panel-pad" onSubmit={submit} noValidate>
      <div className="form-grid">
        <TextField f={f} name="name" label="Legal name" autoComplete="organization" className="span" />
        <CountryField f={f} name="country" label="Country" />
        <TextField f={f} name="registrationNumber" label="Company registration number" autoComplete="off" spellCheck={false} />
        <TextField
          f={f}
          name="bankAccount"
          label="Bank account for payouts"
          placeholder="IBAN or account number"
          hint="Advances are paid to this account."
          autoComplete="off"
          spellCheck={false}
        />
        <TextField f={f} name="email" label="Work email" type="email" inputMode="email" autoComplete="email" spellCheck={false} />
      </div>
      {error ? (
        <div className="say bad small" role="alert">
          {error}
        </div>
      ) : null}
      <div className="form-foot">
        <button className="btn primary" disabled={busy}>
          {busy ? 'Creating your account…' : 'Create business account'}
        </button>
        <span className="hint">
          Already registered?{' '}
          <button type="button" className="linkish" onClick={onSignIn}>
            Sign in
          </button>
        </span>
      </div>
    </form>
  )
}

function SignInBusiness({
  live,
  notify,
  session,
  initial,
  onCreate,
  onSignedIn,
}: {
  live: Live
  notify: Notify
  session: Session
  initial: { country: string; registrationNumber: string } | null
  onCreate: () => void
  onSignedIn: () => void
}) {
  const f = useForm('signin', { country: initial?.country ?? '', registrationNumber: initial?.registrationNumber ?? '', email: '' })
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    const v = f.values
    const ok = f.check({
      country: v.country ? undefined : 'Choose the country where your business is registered.',
      registrationNumber: need(v.registrationNumber, 'Enter your company registration number.'),
      email: emailError(v.email),
    })
    if (!ok) return
    setBusy(true)
    setError('')
    try {
      const r = await api('/api/business-sessions', { country: v.country, registrationNumber: v.registrationNumber.trim(), email: v.email.trim() })
      session.setBusiness({ id: r.business.id, key: r.key })
      notify(`Signed in as ${r.business.name}`)
      onSignedIn()
      void live.refresh()
    } catch (err) {
      setError((err as Error).message)
    } finally {
      setBusy(false)
    }
  }
  return (
    <form className="form panel-pad" onSubmit={submit} noValidate>
      <div className="form-grid">
        <CountryField f={f} name="country" label="Country" />
        <TextField f={f} name="registrationNumber" label="Company registration number" autoComplete="off" spellCheck={false} />
        <TextField f={f} name="email" label="Work email" type="email" inputMode="email" autoComplete="email" spellCheck={false} className="span" hint="The email you signed up with." />
      </div>
      {error ? (
        <div className="say bad small" role="alert">
          {error}
        </div>
      ) : null}
      <div className="form-foot">
        <button className="btn primary" disabled={busy}>
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
        <span className="hint">
          New to Tradeflow?{' '}
          <button type="button" className="linkish" onClick={onCreate}>
            Create business account
          </button>
        </span>
      </div>
    </form>
  )
}

function readFile(file: File): Promise<string> {
  return new Promise((ok, fail) => {
    const r = new FileReader()
    r.onload = () => ok(String(r.result).split(',')[1] ?? '')
    r.onerror = () => fail(new Error('We could not read that file. Choose it again.'))
    r.readAsDataURL(file)
  })
}
const FILE_TYPES: Record<string, string> = { pdf: 'application/pdf', png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg' }

function RequestForm({
  business,
  auth,
  live,
  frozen,
  onSent,
}: {
  business: Any
  auth: BizSession
  live: Live
  /** Why new requests cannot be listed, when the business is frozen. */
  frozen: string
  onSent: (r: { document: Any; buyerLink: string }) => void
}) {
  const today = isoDay(new Date())
  const maxDue = addDays(today, 365)
  const f = useForm('doc', {
    type: 'invoice',
    number: '',
    amount: '',
    currency: 'EUR',
    buyer: '',
    buyerEmail: '',
    buyerCountry: '',
    issuedAt: '',
    dueDate: '',
    description: '',
  })
  const [file, setFile] = useState<File | null>(null)
  const [fileError, setFileError] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const v = f.values
  const kind = docType(v.type)
  const amt = Number(v.amount || 0)
  const dueIn = v.dueDate ? daysBetween(today, v.dueDate) : 0

  const pick = (e: React.ChangeEvent<HTMLInputElement>) => {
    const x = e.target.files?.[0] ?? null
    e.target.value = ''
    if (!x) return
    const ext = x.name.split('.').pop()?.toLowerCase() ?? ''
    if (!FILE_TYPES[ext] && !Object.values(FILE_TYPES).includes(x.type)) {
      setFileError('Attach a PDF, PNG or JPG file.')
      return
    }
    if (x.size > 5 * 1024 * 1024) {
      setFileError(`That file is ${fileSize(x.size)}. Attach a file of 5 MB or less.`)
      return
    }
    setFileError('')
    setFile(x)
  }

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    const ok = f.check({
      number: need(v.number, `Enter the ${kind.noun} number.`),
      amount: !v.amount ? 'Enter the amount.' : !(amt >= 1) ? 'Enter an amount of at least 1.00.' : amt > 5_000_000 ? 'Enter an amount of 5,000,000.00 or less.' : undefined,
      buyer: need(v.buyer, 'Enter the legal name of your buyer.'),
      buyerEmail: emailError(v.buyerEmail),
      buyerCountry: v.buyerCountry ? undefined : "Choose your buyer's country.",
      issuedAt: !v.issuedAt ? 'Enter the issue date.' : v.issuedAt > today ? 'The issue date cannot be in the future.' : undefined,
      dueDate: !v.dueDate
        ? 'Enter the due date.'
        : v.issuedAt && v.dueDate <= v.issuedAt
          ? 'The due date must be after the issue date.'
          : v.dueDate <= today
            ? 'The due date must be in the future.'
            : v.dueDate > maxDue
              ? `The due date must be within a year, by ${fmtDate(maxDue)}.`
              : undefined,
      description: need(v.description, 'Describe what is being sold.'),
    })
    if (!ok) return
    setBusy(true)
    setError('')
    try {
      const upload = file ? { name: file.name, type: file.type || FILE_TYPES[file.name.split('.').pop()?.toLowerCase() ?? ''], base64: await readFile(file) } : undefined
      const r = await api('/api/documents', {
        businessId: business.id,
        type: v.type,
        number: v.number.trim(),
        buyer: v.buyer.trim(),
        buyerEmail: v.buyerEmail.trim(),
        buyerCountry: v.buyerCountry,
        amountMinor: Math.round(amt * 100),
        currency: v.currency,
        issuedAt: v.issuedAt,
        dueDate: v.dueDate,
        description: v.description.trim(),
        ...(upload ? { file: upload } : {}),
      }, bizHeaders(auth))
      onSent(r)
      void live.refresh()
    } catch (err) {
      const message = (err as Error).message
      if ((err as ApiError).status === 409) f.check({ number: message })
      else setError(message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Document details</h2>
      </div>
      {frozen ? <div className="notice bad">{frozen}</div> : null}
      <form className="form panel-pad" onSubmit={submit} noValidate>
        <fieldset className="fld">
          <legend>Document type</legend>
          <div className="seg">
            {DOC_TYPES.map((t) => (
              <label key={t.value} className={v.type === t.value ? 'on' : ''}>
                <input type="radio" name="doc-type" value={t.value} checked={v.type === t.value} onChange={() => f.put('type', t.value)} />
                {t.label}
              </label>
            ))}
          </div>
        </fieldset>
        <div className="form-grid">
          <TextField f={f} name="number" label="Document number" autoComplete="off" spellCheck={false} />
          <Field f={f} name="amount" label="Amount" hint={amt >= 1 ? money(Math.round(amt * 100), v.currency, 2) : 'Between 1.00 and 5,000,000.00'}>
            <div className={`input ${f.errors.amount ? 'invalid' : ''}`}>
              <select aria-label="Currency" value={v.currency} onChange={(e) => f.put('currency', e.target.value)}>
                <option value="EUR">EUR</option>
                <option value="USD">USD</option>
              </select>
              <input {...f.field('amount', true)} inputMode="decimal" autoComplete="off" placeholder="0.00" onChange={(e) => f.put('amount', decimal(e.target.value, 2))} />
            </div>
          </Field>
          <TextField f={f} name="buyer" label="Buyer legal name" autoComplete="off" className="span" />
          <TextField
            f={f}
            name="buyerEmail"
            label="Buyer email"
            type="email"
            inputMode="email"
            autoComplete="off"
            spellCheck={false}
            hint="Where you will send the buyer link, usually accounts payable."
          />
          <CountryField f={f} name="buyerCountry" label="Buyer country" />
          <TextField f={f} name="issuedAt" label="Issue date" type="date" max={today} />
          <TextField
            f={f}
            name="dueDate"
            label="Due date"
            type="date"
            min={addDays(v.issuedAt && v.issuedAt > today ? v.issuedAt : today, 1)}
            max={maxDue}
            hint={dueIn > 0 ? `Due in ${days(dueIn)}` : 'Within the next 365 days'}
          />
          <TextField
            f={f}
            name="description"
            label="What is being sold"
            maxLength={80}
            autoComplete="off"
            className="span"
            hint={`Investors see: ${kind.prefix}${v.description.trim() || 'your description'}`}
          />
          <div className="fld span">
            <span className="lbl">
              Attach the document <span className="opt">Optional</span>
            </span>
            {file ? (
              <div className="file picked">
                <span className="file-name">{file.name}</span>
                <span className="small muted">{fileSize(file.size)}</span>
                <button type="button" className="btn quiet sm" onClick={() => setFile(null)}>
                  Remove
                </button>
              </div>
            ) : (
              <label className="file" htmlFor="doc-file">
                <input
                  id="doc-file"
                  type="file"
                  className="vh"
                  accept=".pdf,.png,.jpg,.jpeg,application/pdf,image/png,image/jpeg"
                  aria-describedby={fileError ? 'doc-file-err' : 'doc-file-hint'}
                  onChange={pick}
                />
                <span className="btn quiet sm" aria-hidden="true">
                  Choose file
                </span>
                <span className="hint" id="doc-file-hint">
                  PDF, PNG or JPG, up to 5 MB. Its fingerprint is recorded with the request.
                </span>
              </label>
            )}
            {fileError ? (
              <div className="err" id="doc-file-err" role="alert">
                {fileError}
              </div>
            ) : null}
          </div>
        </div>
        {error ? (
          <div className="say bad small" role="alert">
            {error}
          </div>
        ) : null}
        <div className="form-foot">
          <button className="btn primary" disabled={busy || !!frozen}>
            {busy ? 'Creating the buyer link…' : 'Create buyer link'}
          </button>
          <span className="hint">You send this link to your buyer so they can confirm the {kind.noun}. Nothing is listed until they do.</span>
        </div>
      </form>
    </section>
  )
}

/** An email to the buyer, opened in the business's own mail app, with the buyer link in it. */
function mailtoFor(doc: Any, business: Any): string {
  const noun = docType(doc.type).noun
  const subject = `Please confirm ${noun} ${doc.number} from ${business.name}`
  const body = [
    'Hello,',
    '',
    `${business.name} is financing ${noun} ${doc.number} (${money(doc.amountMinor, doc.currency, 2)}, due ${fmtDate(doc.dueDate)}) with Tradeflow.`,
    'Please check the details and confirm it, or tell us what is wrong, through this link:',
    `${location.origin}${doc.buyerLink}`,
    '',
    'Thank you,',
    business.name,
  ].join('\n')
  return `mailto:${encodeURIComponent(doc.buyerEmail ?? '')}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`
}

/** Starts the review again after a run that did not finish. */
function RetryReview({ doc, auth, notify, reload, live }: { doc: Any; auth: BizSession; notify: Notify; reload: () => Promise<void>; live: Live }) {
  const { busy, run } = useAction(live, notify)
  return (
    <button
      type="button"
      className="btn quiet sm"
      disabled={!!busy}
      onClick={() => run('retry', async () => {
        await api('/api/documents/review', { businessId: doc.businessId, number: doc.number }, bizHeaders(auth))
        await reload()
      }, 'Review started again')}
    >
      {busy ? 'Starting the review…' : 'Start the review again'}
    </button>
  )
}

/** Why a request is where it is, and what to do next. */
function StateDetail({ st, doc, auth, notify, reload, live }: { st: ReqState; doc: Any; auth: BizSession; notify: Notify; reload: () => Promise<void>; live: Live }) {
  if (st.reason)
    return (
      <>
        <div className="say bad small">{st.reason}.</div>
        {st.next ? <div className="small muted">{st.next}</div> : null}
      </>
    )
  if (st.retry)
    return (
      <div className="stack" style={{ gap: 8, justifyItems: 'start' }}>
        <div className="say warn small">The review stopped before it reached a decision. Nothing was decided about this {docType(doc.type).noun}.</div>
        <RetryReview doc={doc} auth={auth} notify={notify} reload={reload} live={live} />
      </div>
    )
  return null
}

function WaitingPanel({
  doc,
  live,
  business,
  go,
  auth,
  notify,
  reload,
  onNew,
}: {
  doc: Any
  live: Live
  business: Any
  go: Go
  auth: BizSession
  notify: Notify
  reload: () => Promise<void>
  onNew: () => void
}) {
  const st = requestState(doc, live, business)
  const waiting = doc.status === 'awaiting_buyer'
  const noun = docType(doc.type).noun
  const title = waiting ? `Waiting for ${doc.buyer} to confirm` : doc.status === 'disputed' ? `${doc.buyer} disputed this ${noun}` : `${doc.buyer} confirmed this ${noun}`
  return (
    <section className="panel" aria-live="polite">
      <div className="panel-head">
        <h2>{title}</h2>
        {waiting ? null : <StateText s={st} />}
      </div>
      <div className="panel-pad stack" style={{ gap: 16 }}>
        <div>
          <div style={{ fontWeight: 600 }}>{doc.title}</div>
          <div className="small muted">
            <span className="code">{doc.number}</span>, {money(doc.amountMinor, doc.currency, 2)}, due {fmtDate(doc.dueDate)}
          </div>
        </div>
        {waiting ? (
          <>
            <CopyLink path={doc.buyerLink} />
            {doc.buyerEmail ? (
              <div>
                <a className="btn quiet" href={mailtoFor(doc, business)}>
                  Email the link to {doc.buyerEmail}
                </a>
              </div>
            ) : null}
            <p className="small" style={{ margin: 0 }}>
              Share this link with your buyer. Once they confirm, the request is reviewed and listed.
            </p>
          </>
        ) : st.reason || st.retry ? (
          <StateDetail st={st} doc={doc} auth={auth} notify={notify} reload={reload} live={live} />
        ) : st.loanId ? (
          <div className="small">
            <Link to={`/business/loans/${st.loanId}`} go={go}>
              View loan
            </Link>
          </div>
        ) : (
          <div className="small muted">The request is being reviewed. This usually takes under a minute.</div>
        )}
        <div className="row">
          <Link to="/business" go={go} className="btn">
            Back to overview
          </Link>
          <button className="btn quiet" onClick={onNew}>
            Request financing for another document
          </button>
        </div>
      </div>
    </section>
  )
}
