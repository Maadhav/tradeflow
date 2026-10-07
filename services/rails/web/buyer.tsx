// The buyer's page: confirm or dispute a document, then pay it through the same link when it is due.

import React, { useCallback, useEffect, useState } from 'react'
import { api, countryName, docType, Field, fmtDate, money, need, sentence, TextField, useForm, type Any, type ApiError, type Live } from './shared'

export function BuyerPortal({ token, live }: { token: string; live: Live }) {
  const [data, setData] = useState<Any>(null)
  const [missing, setMissing] = useState(false)
  const [loadError, setLoadError] = useState('')
  const load = useCallback(async () => {
    try {
      setData(await api(`/api/buyer/${encodeURIComponent(token)}`))
      setMissing(false)
      setLoadError('')
    } catch (e) {
      if ((e as ApiError).status === 404) setMissing(true)
      else setLoadError((e as Error).message)
    }
  }, [token])
  useEffect(() => {
    void load()
  }, [load, live.state])

  if (missing)
    return (
      <div className="portal">
        <div className="panel panel-pad stack">
          <h1>This link is not valid</h1>
          <p className="muted" style={{ margin: 0 }}>
            Check that you copied the whole link, or ask your supplier to send it again.
          </p>
        </div>
      </div>
    )
  if (!data)
    return (
      <div className="loading" role="status">
        {loadError || 'Loading'}
      </div>
    )
  return <BuyerDocument token={token} data={data} live={live} reload={load} />
}

function BuyerDocument({ token, data, live, reload }: { token: string; data: Any; live: Live; reload: () => Promise<void> }) {
  const { document: doc, business, loan, payment, collection, financing } = data
  const kind = docType(doc.type)
  const Kind = sentence(kind.noun)
  const description = String(doc.title ?? '').startsWith(kind.prefix) ? doc.title.slice(kind.prefix.length) : doc.title
  const f = useForm('buyer', { name: '', reason: '' })
  const [busy, setBusy] = useState('')
  const [error, setError] = useState('')
  const [disputing, setDisputing] = useState(false)
  const [payState, setPayState] = useState<'idle' | 'paying' | 'received' | 'unconfirmed'>('idle')
  const [payError, setPayError] = useState('')
  const pending = doc.status === 'awaiting_buyer'
  const status = Number(loan?.status ?? 0)
  const payable = status === 3 || status === 5
  // The buyer pays the full document amount, in its currency; Tradeflow repays the lenders and pays the balance to the supplier.
  const due = money(doc.amountMinor, doc.currency, 2)
  const paidOn = fmtDate(loan?.repaidAt)
  const base = `/api/buyer/${encodeURIComponent(token)}`
  const fileUrl = doc.fileName ? `${base}/file` : undefined

  const respond = async (what: 'confirm' | 'dispute') => {
    const v = f.values
    const ok =
      what === 'confirm'
        ? f.check({ name: need(v.name, `Enter your name to confirm this ${kind.noun}.`) })
        : f.check({ reason: need(v.reason, `Tell ${business.name} what is wrong with this ${kind.noun}.`) })
    if (!ok) return
    setBusy(what)
    setError('')
    try {
      await api(`${base}/${what}`, what === 'confirm' ? { name: v.name.trim() } : { reason: v.reason.trim() })
      await reload()
    } catch (e) {
      setError((e as Error).message)
      if ((e as ApiError).status === 409) await reload()
    } finally {
      setBusy('')
    }
  }

  const pay = async () => {
    setPayState('paying')
    setPayError('')
    try {
      const r = await api(`${base}/pay`, {})
      setPayState(r?.run?.status === 'failed' ? 'unconfirmed' : 'received')
      await reload()
    } catch (e) {
      setPayError((e as Error).message)
      setPayState('idle')
    }
  }

  const details = (
    <section className="panel">
      <div className="panel-head">
        <h2>{Kind} details</h2>
      </div>
      <table className="kv">
        <tbody>
          <tr>
            <td>Supplier</td>
            <td>
              {business.name}, {countryName(business.country)}
            </td>
          </tr>
          <tr>
            <td>Document</td>
            <td>
              {kind.label} <span className="code">{doc.number}</span>
              {description ? <div className="small muted">{description}</div> : null}
            </td>
          </tr>
          <tr>
            <td>Amount</td>
            <td>{money(doc.amountMinor, doc.currency, 2)}</td>
          </tr>
          <tr>
            <td>Issued</td>
            <td>{fmtDate(doc.issuedAt)}</td>
          </tr>
          <tr>
            <td>Due</td>
            <td>{fmtDate(doc.dueDate)}</td>
          </tr>
          <tr>
            <td>Attached file</td>
            <td>
              {doc.fileName && fileUrl ? (
                <a href={fileUrl} target="_blank" rel="noreferrer">
                  {doc.fileName}
                </a>
              ) : (
                (doc.fileName ?? 'None')
              )}
            </td>
          </tr>
        </tbody>
      </table>
    </section>
  )

  if (pending)
    return (
      <div className="portal">
        <div>
          <h1>
            {doc.buyer}, please confirm this {kind.noun}
          </h1>
          <p className="lede">
            {business.name} wants to finance this {kind.noun} with Tradeflow. Check that the details match your records. If it is financed, you pay the full amount through this page when it
            is due.
          </p>
        </div>
        {details}
        <section className="panel panel-pad stack" style={{ gap: 20 }}>
          <form
            className="form"
            noValidate
            onSubmit={(e) => {
              e.preventDefault()
              void respond('confirm')
            }}
          >
            <TextField f={f} name="name" label="Your full name" autoComplete="name" hint={`Recorded as the person who confirmed this ${kind.noun}.`} />
            <div className="row">
              <button className="btn primary" disabled={!!busy}>
                {busy === 'confirm' ? 'Confirming…' : `Confirm ${kind.noun}`}
              </button>
              <button type="button" className="btn quiet" aria-expanded={disputing} aria-controls="buyer-dispute" disabled={!!busy} onClick={() => setDisputing((d) => !d)}>
                Dispute
              </button>
            </div>
          </form>
          {disputing ? (
            <form
              id="buyer-dispute"
              className="form dispute"
              noValidate
              onSubmit={(e) => {
                e.preventDefault()
                void respond('dispute')
              }}
            >
              <Field f={f} name="reason" label={`What is wrong with this ${kind.noun}?`} hint={`${business.name} will see your reason.`}>
                <textarea className="ctl" rows={4} maxLength={500} {...f.field('reason', true)} />
              </Field>
              <div>
                <button className="btn danger" disabled={!!busy}>
                  {busy === 'dispute' ? 'Sending dispute…' : 'Send dispute'}
                </button>
              </div>
            </form>
          ) : null}
          {error ? (
            <div className="say bad small" role="alert">
              {error}
            </div>
          ) : null}
        </section>
      </div>
    )

  return (
    <div className="portal">
      <div>
        <h1>
          {kind.label} <span className="code">{doc.number}</span>
        </h1>
        <p className="lede">
          From {business.name}, {countryName(business.country)}
        </p>
      </div>
      {doc.status === 'disputed' ? (
        <div className="done-box idle" role="status">
          <div>
            Dispute sent.
            {doc.disputeReason ? <div className="small">Your reason: {doc.disputeReason}</div> : null}
          </div>
        </div>
      ) : (
        <div className="done-box" role="status">
          <div>
            {Kind} confirmed. {business.name} can see your confirmation.
            {doc.respondedBy ? (
              <div className="small">
                Confirmed by {doc.respondedBy}
                {doc.respondedAt ? ` on ${fmtDate(doc.respondedAt)}` : ''}.
              </div>
            ) : null}
          </div>
        </div>
      )}

      {doc.status === 'confirmed' && payable ? (
        <section className="panel" aria-live="polite">
          <div className="panel-head">
            <h2>Pay this {kind.noun}</h2>
            {status === 5 ? <span className="tag bad">Overdue</span> : null}
          </div>
          <table className="kv">
            <tbody>
              <tr>
                <td>Amount due</td>
                <td>
                  <b>{due}</b>
                </td>
              </tr>
              {status === 5 && fmtDate(loan.maturity) ? (
                <tr>
                  <td>Was due</td>
                  <td>{fmtDate(loan.maturity)}</td>
                </tr>
              ) : fmtDate(doc.dueDate) ? (
                <tr>
                  <td>Due date</td>
                  <td>{fmtDate(doc.dueDate)}</td>
                </tr>
              ) : null}
              <tr>
                <td>Pay to</td>
                <td>{collection?.beneficiary ?? 'Tradeflow Collections'}</td>
              </tr>
              <tr>
                <td>Account</td>
                <td className="code">{collection?.account}</td>
              </tr>
              <tr>
                <td>Reference</td>
                <td className="code">{collection?.reference ?? doc.number}</td>
              </tr>
            </tbody>
          </table>
          <div className="panel-pad stack" style={{ borderTop: '1px solid var(--line)' }}>
            {payState === 'received' ? (
              <div className="done-box">Payment received</div>
            ) : payState === 'unconfirmed' ? (
              <div className="say warn small" role="alert">
                Your payment was sent but is not confirmed yet. Do not pay again. Check this page in a few minutes.
              </div>
            ) : (
              <>
                <button className="btn primary block" disabled={payState === 'paying'} onClick={pay}>
                  {payState === 'paying' ? `Paying ${due}…` : `Pay ${due}`}
                </button>
                <div className="small muted">
                  {payState === 'paying'
                    ? 'Confirming your payment with the bank and the payment processor. This takes about a minute.'
                    : `This pays the ${kind.noun} in full. Your payment is matched at the bank and the payment processor before the ${kind.noun} is marked paid; Tradeflow repays the lenders and pays the balance to ${business.name}.`}
                </div>
              </>
            )}
            {payError ? (
              <div className="say bad small" role="alert">
                {payError}
              </div>
            ) : null}
          </div>
        </section>
      ) : null}

      {doc.status === 'confirmed' && status === 4 ? (
        <section className="panel panel-pad stack">
          <h2>{paidOn ? `Paid on ${paidOn}` : 'Paid in full'}</h2>
          <div className="small muted">
            Payment received{payment ? `: ${money(payment.amountMinor, payment.currency, 2)}` : ''}. There is nothing more to pay on this {kind.noun}.
          </div>
        </section>
      ) : null}

      {doc.status === 'confirmed' && status === 6 ? (
        <div className="say bad small">
          This {kind.noun} is in default. Contact {business.name} to settle it.
        </div>
      ) : null}

      {doc.status === 'confirmed' && !loan && financing === 'not_financed' ? (
        <section className="panel panel-pad stack">
          <h2>Not financed by Tradeflow</h2>
          <div className="small muted">
            Tradeflow is not financing this {kind.noun}. Pay {business.name} directly, as agreed with them.
          </div>
        </section>
      ) : doc.status === 'confirmed' && status < 3 ? (
        <p className="small muted" style={{ margin: 0 }}>
          {loan
            ? `Nothing to pay yet. When this ${kind.noun} is due, come back to this page to pay it.`
            : `Nothing to pay yet. ${business.name}'s request is being reviewed. If it is financed, you pay this ${kind.noun} through this page when it is due; if not, you pay ${business.name} as usual.`}
        </p>
      ) : null}

      {details}
    </div>
  )
}
