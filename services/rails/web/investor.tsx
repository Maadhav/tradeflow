// The investor portal (/investor): start investing or sign in, then a portfolio, a marketplace of open
// loans, and each loan's page with a funding panel bound to the investor's own method.

import React, { useEffect, useState } from 'react'
import { formatUnits, parseUnits } from 'viem'
import { calls } from './abi'
import { LoanCard, LoanDetail, LoanMissing, LoanStatusPanel, loanContext } from './loan'
import {
  Addr,
  api,
  ConnectWallet,
  contractsOf,
  countryName,
  days,
  decimal,
  docFor,
  emailError,
  fmtDate,
  GRADE,
  isActive,
  kycRunFor,
  lenderFor,
  Link,
  Loading,
  money,
  need,
  noteSymbol,
  pct,
  rate,
  Redirect,
  rememberReturn,
  request,
  RunLog,
  runSummary,
  sameAddr,
  short,
  StateText,
  stepText,
  takeReturn,
  TextField,
  CountryField,
  Tiles,
  toUsd6,
  TxSteps,
  usd,
  usdExact,
  useAccount,
  useAction,
  useForm,
  userLines,
  useTxFlow,
  walletIntro,
  ccyOf,
  type Account,
  type Any,
  type Go,
  type InvestorView,
  type Live,
  type Notify,
  type Plan,
  type ReqState,
  type Session,
} from './shared'
import { proveWallet, savedBuiltin, walletKind, type WalletSession } from './wallet'

// ---------------------------------------------------------------------------
// Portfolio data helpers
// ---------------------------------------------------------------------------

/** A 6-decimal USD amount as the server sends it (an integer string), tolerant of a decimal string. */
const u6 = (v: Any): bigint => {
  if (v === undefined || v === null || v === '') return 0n
  if (typeof v === 'bigint') return v
  const s = String(v)
  try {
    return s.includes('.') ? parseUnits(s, 6) : BigInt(s)
  } catch {
    return 0n
  }
}
const NAMED_STATUS: Record<string, number> = { open: 1, listed: 1, funded: 2, active: 3, repaid: 4, late: 5, defaulted: 6 }
const statusOf = (s: Any): number => (typeof s === 'number' ? s : /^\d+$/.test(String(s)) ? Number(s) : (NAMED_STATUS[String(s).toLowerCase()] ?? 0))
/** A position's loan status: the onchain number when the server sends it (so a loan still raising reads as 1), else the named status. */
const posStatus = (p: Any): number => statusOf(p.loanStatus ?? p.status)
const gradeOf = (g: Any): string => (typeof g === 'number' || /^\d+$/.test(String(g)) ? (GRADE[Number(g)] ?? '') : String(g ?? ''))
const notesText = (p: Any) =>
  `${(Number(u6(p.notes)) / 1e6).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })} ${p.symbol || noteSymbol(p.loanId)}`
/** Notes held, the same in the positions table and on the loan page: once paid back (notes burned), "Redeemed". */
function NotesHeld({ p }: { p: Any }) {
  return u6(p.notes) === 0n && u6(p.receivedUsd6) > 0n ? <span className="muted">Redeemed</span> : <>{notesText(p)}</>
}

/** From the investor's side, a loan still raising is one they have funded. */
const POSITION_STATUS: Record<number, { label: string; tone: string }> = {
  1: { label: 'Funded', tone: 'good' },
  2: { label: 'Funded', tone: 'good' },
  3: { label: 'Active', tone: 'good' },
  4: { label: 'Repaid', tone: 'good' },
  5: { label: 'Late', tone: 'warn' },
  6: { label: 'Defaulted', tone: 'bad' },
}
function PositionTag({ s }: { s: number }) {
  const st = POSITION_STATUS[s]
  return st ? <span className={`tag ${st.tone}`}>{st.label}</span> : null
}
/** Still working: the principal is out and the payout is to come. */
const outstanding = (s: number) => s === 1 || s === 2 || s === 3 || s === 5

/** Claimable first, then late, active, funded and raising, then closed; newest loan first within each. */
function sortPositions(positions: Any[]): Any[] {
  const rank = (p: Any) => {
    if (u6(p.claimableUsd6) > 0n) return 0
    return ({ 5: 1, 3: 2, 2: 3, 1: 4, 6: 5, 4: 6 } as Record<number, number>)[posStatus(p)] ?? 7
  }
  return [...positions].sort((a, b) => rank(a) - rank(b) || Number(b.loanId) - Number(a.loanId))
}

/** The four summary figures, by the definitions on the tiles. */
function totalsOf(positions: Any[]) {
  let invested = 0n
  let interest = 0n
  let received = 0n
  let claimable = 0n
  for (const p of positions) {
    const s = posStatus(p)
    if (outstanding(s)) {
      invested += u6(p.principalUsd6)
      const gain = u6(p.expectedUsd6) - u6(p.principalUsd6)
      if (gain > 0n) interest += gain
    }
    received += u6(p.receivedUsd6)
    claimable += u6(p.claimableUsd6)
  }
  return { invested, interest, received, claimable }
}

type KycState = 'verified' | 'pending' | 'rejected'
/** Verified once the wallet is in the ERC-3643 identity registry (or the identity run just said so). */
function kycState(lender: Any, live: Live): KycState {
  const run = kycRunFor(live, lender.id)
  if (lender.verifiedOnchain === true) return 'verified'
  if (lender.kycStatus === 'rejected' || run?.resultData?.verified === false) return 'rejected'
  if (run?.resultData?.verified === true) return 'verified'
  return 'pending'
}
// The identity provider does not accept residents of these countries.
const KYC_BLOCKED = ['KP', 'IR', 'SY', 'CU']
function declinedReason(lender: Any, live: Live): string {
  const run = kycRunFor(live, lender.id)
  const where = countryName(lender.country)
  if (run?.resultData?.status === 'unsupported country') return `We cannot accept investors resident in ${where} yet.`
  if (KYC_BLOCKED.includes(lender.country)) return `Our identity provider declined this identity: it does not accept investors resident in ${where}.`
  return 'Our identity provider declined this identity.'
}

/** Whether this browser can connect the account's wallet: any browser wallet, or the built-in wallet it holds. */
const canConnect = (live: Live, lender: Any) => walletKind(live.config ?? {}) !== 'builtin' || sameAddr(savedBuiltin()?.address, lender.wallet)
const ELSEWHERE = "This account's wallet is kept in the browser you signed up in. Open Tradeflow there to fund or claim."

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

export function Investor({
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
  view: InvestorView
}) {
  const [lost, setLost] = useState(false)
  const { setInvestor, investor } = session
  useEffect(() => {
    if (view.missing) {
      setInvestor(null)
      setLost(true)
    }
  }, [view.missing, setInvestor])
  useEffect(() => {
    if (investor) setLost(false)
  }, [investor])

  if (!investor) {
    if (path !== '/investor') {
      rememberReturn('investor', path)
      return <Redirect to="/investor" replace={replace} />
    }
    return <InvestorStart live={live} notify={notify} session={session} go={go} lost={lost} />
  }
  if (!view.data)
    return view.error ? (
      <div className="panel empty stack" style={{ justifyItems: 'center' }}>
        <div>{view.error}</div>
        <button className="btn quiet" onClick={() => void view.reload()}>
          Try again
        </button>
      </div>
    ) : (
      <Loading text="Loading your portfolio" />
    )
  const data = view.data
  if (path === '/investor') return <Portfolio data={data} live={live} go={go} notify={notify} session={session} reload={view.reload} />
  if (path === '/investor/marketplace') return <Marketplace data={data} live={live} go={go} />
  const loanMatch = path.match(/^\/investor\/loans\/(\d+)$/)
  if (loanMatch)
    return <InvestorLoan key={loanMatch[1]} id={Number(loanMatch[1])} data={data} live={live} go={go} notify={notify} session={session} reload={view.reload} />
  return <Redirect to="/investor" replace={replace} />
}

// ---------------------------------------------------------------------------
// Start investing, sign in
// ---------------------------------------------------------------------------

type SignedIn = (lender: Any, key: string, welcome: string) => void

function InvestorStart({ live, notify, session, go, lost }: { live: Live; notify: Notify; session: Session; go: Go; lost: boolean }) {
  const [mode, setMode] = useState<'create' | 'signin'>(lost ? 'signin' : 'create')
  const [method, setMethod] = useState<'bank' | 'usdc'>(() => (session.wallet ? 'usdc' : 'bank'))
  useEffect(() => {
    if (lost) setMode('signin')
  }, [lost])
  const done: SignedIn = (lender, key, welcome) => {
    session.setInvestor({ id: lender.id, key })
    notify(welcome)
    const next = takeReturn('investor')
    if (next && next !== '/investor') go(next)
    void live.refresh()
  }
  return (
    <>
      <h1 className="display">Fund the goods already on their way.</h1>
      <p className="lede">
        Short-term loans backed by invoices and shipping documents their buyers have confirmed. Invest from your bank account or in USDC, and get paid back when the buyer pays.
      </p>
      <div className="split" style={{ marginTop: 36 }}>
        <section className="panel">
          <div className="panel-head">
            <h2>{mode === 'create' ? 'Start investing' : 'Sign in to your investor account'}</h2>
          </div>
          {lost && mode === 'signin' ? <div className="notice idle">This browser is no longer signed in to your investor account. Sign in again to continue.</div> : null}
          <div className="panel-pad stack" style={{ gap: 18 }}>
            <div className="tabs" role="tablist" aria-label="How you invest">
              <button role="tab" aria-selected={method === 'bank'} className={method === 'bank' ? 'on' : ''} onClick={() => setMethod('bank')}>
                Bank transfer
              </button>
              <button role="tab" aria-selected={method === 'usdc'} className={method === 'usdc' ? 'on' : ''} onClick={() => setMethod('usdc')}>
                USDC
              </button>
            </div>
            {mode === 'create' ? (
              method === 'bank' ? (
                <InvestorSignup key="bank" funding="fiat" live={live} onDone={done} />
              ) : (
                <UsdcStart live={live} session={session} onDone={done} />
              )
            ) : method === 'bank' ? (
              <EmailSignIn onDone={done} />
            ) : (
              <WalletSignIn live={live} session={session} onDone={done} />
            )}
            <div className="hint switch">
              {mode === 'create' ? (
                <>
                  Already investing?{' '}
                  <button type="button" className="linkish" onClick={() => setMode('signin')}>
                    Sign in
                  </button>
                </>
              ) : (
                <>
                  New to Tradeflow?{' '}
                  <button type="button" className="linkish" onClick={() => setMode('create')}>
                    Start investing
                  </button>
                </>
              )}
            </div>
          </div>
        </section>
        <section className="panel">
          <div className="panel-head">
            <h2>How it works</h2>
          </div>
          <ol className="steps">
            <li>
              <div>
                <div className="what">Verify your identity once</div>
                <div className="detail">Before your first investment we check your identity and register your wallet in the ERC-3643 identity registry, so it can hold loan notes.</div>
              </div>
            </li>
            <li>
              <div>
                <div className="what">Choose a loan</div>
                <div className="detail">Each loan is backed by an invoice, bill of lading or equipment order its buyer has confirmed, with a risk grade, an APR and a fixed term.</div>
              </div>
            </li>
            <li>
              <div>
                <div className="what">Fund it</div>
                <div className="detail">Send a bank transfer or fund in USDC from your wallet. You receive the loan's notes, one for each dollar you lend.</div>
              </div>
            </li>
            <li>
              <div>
                <div className="what">Get paid back</div>
                <div className="detail">When the buyer pays, you receive your principal plus interest: paid to your bank account, or claimed to your wallet.</div>
              </div>
            </li>
          </ol>
        </section>
      </div>
    </>
  )
}

/** Sign-up for either method. Creating the account starts the identity check. */
function InvestorSignup({ funding, wallet, live, onDone }: { funding: 'fiat' | 'stablecoin'; wallet?: WalletSession | null; live: Live; onDone: SignedIn }) {
  const fiat = funding === 'fiat'
  const f = useForm(fiat ? 'lend-bank' : 'lend-usdc', { name: '', email: '', country: '', bankAccount: '' })
  const [busy, setBusy] = useState<'' | 'sign' | 'verify'>('')
  const [error, setError] = useState('')
  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    const v = f.values
    const ok = f.check({
      name: need(v.name, 'Enter your full name.'),
      email: emailError(v.email),
      country: v.country ? undefined : 'Choose the country you live in.',
      bankAccount: fiat ? need(v.bankAccount, 'Enter the bank account where repayments should go.') : undefined,
    })
    if (!ok) return
    setBusy('verify')
    setError('')
    try {
      // A USDC investor proves the connected wallet is theirs before it is tied to their identity.
      const proof = !fiat && wallet ? await proveWallet(wallet, () => setBusy('sign')) : { body: {}, headers: {} }
      setBusy('verify')
      const body = {
        name: v.name.trim(),
        email: v.email.trim(),
        country: v.country,
        funding,
        ...(fiat ? { bankAccount: v.bankAccount.trim() } : { wallet: wallet?.address, ...proof.body }),
      }
      const { status, data } = await request('/api/lenders', body, proof.headers)
      const lender = data.lender
      if (lender.funding !== funding) {
        setError(
          fiat
            ? 'This email is registered to invest in USDC. Choose USDC above, or use a different email.'
            : 'This email is registered to invest by bank transfer. Choose Bank transfer above, or use a different email.',
        )
        return
      }
      if (!fiat && !sameAddr(lender.wallet, wallet?.address)) {
        setError(`This email is registered with wallet ${short(lender.wallet)}. Connect that wallet, or use a different email.`)
        return
      }
      if (!data.key) {
        setError('Your account was created, but we could not sign you in. Choose Sign in below to continue.')
        return
      }
      // Load the identity run before the portfolio opens, so its progress shows straight away.
      await live.refresh()
      // 200: the email (or wallet) already had an account, which signs in as it is; nothing entered here was saved.
      onDone(
        lender,
        data.key,
        status === 201
          ? `Welcome to Tradeflow, ${lender.name}`
          : `This ${fiat ? 'email' : 'wallet'} already has an investor account. We signed you in; the details you entered were not saved.`,
      )
    } catch (err) {
      setError((err as Error).message)
    } finally {
      setBusy('')
    }
  }
  return (
    <form className="form" onSubmit={submit} noValidate>
      <div className="small muted">
        {fiat
          ? 'Invest from your bank account. We verify your identity once, before your first transfer.'
          : wallet?.kind === 'injected'
            ? `Investing from wallet ${short(wallet?.address)}. Your wallet asks you to sign a message that proves it is yours (no transaction is sent), then we verify your identity once.`
            : `Investing from this browser's wallet ${short(wallet?.address)}. We verify your identity once, before you fund.`}
      </div>
      <TextField f={f} name="name" label="Full name" autoComplete="name" />
      <TextField f={f} name="email" label="Email" type="email" inputMode="email" autoComplete="email" spellCheck={false} />
      <CountryField f={f} name="country" label="Country" />
      {fiat ? (
        <TextField
          f={f}
          name="bankAccount"
          label="Bank account for repayments"
          placeholder="IBAN or account number"
          hint="When a buyer pays, your share is paid to this account."
          autoComplete="off"
          spellCheck={false}
        />
      ) : null}
      {error ? (
        <div className="say bad small" role="alert">
          {error}
        </div>
      ) : null}
      <button className="btn primary block" disabled={!!busy}>
        {busy === 'sign' ? 'Sign the message in your wallet…' : busy ? 'Verifying your identity…' : 'Verify identity to invest'}
      </button>
    </form>
  )
}

/** USDC sign-up: connect the wallet first; a wallet that already has an account signs in instead. */
function UsdcStart({ live, session, onDone }: { live: Live; session: Session; onDone: SignedIn }) {
  const w = session.wallet
  if (!w)
    return (
      <div className="stack">
        <div className="small muted">{walletIntro(live, 'fund')}</div>
        <ConnectWallet session={session} live={live} />
      </div>
    )
  if (lenderFor(live, w.address)) return <WalletSignIn live={live} session={session} onDone={onDone} known />
  return <InvestorSignup key={w.address} funding="stablecoin" wallet={w} live={live} onDone={onDone} />
}

function EmailSignIn({ onDone }: { onDone: SignedIn }) {
  const f = useForm('investor-signin', { email: '' })
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!f.check({ email: emailError(f.values.email) })) return
    setBusy(true)
    setError('')
    try {
      const r = await api('/api/investors/sign-in', { email: f.values.email.trim() })
      if (!r?.key || !r?.lender) throw new Error('We could not sign you in just now. Try again in a moment.')
      onDone(r.lender, r.key, `Signed in as ${r.lender.name}`)
    } catch (err) {
      setError((err as Error).message)
    } finally {
      setBusy(false)
    }
  }
  return (
    <form className="form" onSubmit={submit} noValidate>
      <div className="small muted">If you invest by bank transfer, sign in with the email you signed up with.</div>
      <TextField f={f} name="email" label="Email" type="email" inputMode="email" autoComplete="email" spellCheck={false} />
      {error ? (
        <div className="say bad small" role="alert">
          {error}
        </div>
      ) : null}
      <button className="btn primary block" disabled={busy}>
        {busy ? 'Signing in…' : 'Sign in'}
      </button>
    </form>
  )
}

/** A USDC investor signs in by proving the wallet: a signed message, or this browser's wallet key. */
function WalletSignIn({ live, session, onDone, known }: { live: Live; session: Session; onDone: SignedIn; known?: boolean }) {
  const [busy, setBusy] = useState<'' | 'sign' | 'check'>('')
  const [error, setError] = useState('')
  const w = session.wallet
  if (!w)
    return (
      <div className="stack">
        <div className="small muted">If you invest in USDC, connect the wallet you invest from, then sign a message that proves it is yours. Signing sends no transaction.</div>
        <ConnectWallet session={session} live={live} />
      </div>
    )
  const signIn = async () => {
    setBusy('check')
    setError('')
    try {
      const proof = await proveWallet(w, () => setBusy('sign'))
      setBusy('check')
      const r = await api('/api/investors/sign-in', { wallet: w.address, ...proof.body }, proof.headers)
      if (!r?.key || !r?.lender) throw new Error('We could not sign you in just now. Try again in a moment.')
      onDone(r.lender, r.key, `Signed in as ${r.lender.name}`)
    } catch (err) {
      setError((err as Error).message)
    } finally {
      setBusy('')
    }
  }
  return (
    <div className="stack">
      <div className="small muted">
        {known ? `Wallet ${short(w.address)} already has an investor account. ` : ''}
        {w.kind === 'injected' ? 'Your wallet asks you to sign a message that proves it is yours. Signing sends no transaction.' : "You sign in with this browser's wallet."}
      </div>
      <button className="btn primary block" disabled={!!busy} onClick={signIn}>
        {busy === 'sign' ? 'Sign the message in your wallet…' : busy ? 'Signing in…' : `Sign in with ${short(w.address)}`}
      </button>
      {error ? (
        <div className="say bad small" role="alert">
          {error}
        </div>
      ) : null}
      <div className="row small" style={{ justifyContent: 'space-between' }}>
        <span className="muted">Not the wallet you invest from?</span>
        <button type="button" className="linkish" disabled={!!busy} onClick={() => session.disconnect()}>
          Disconnect
        </button>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Portfolio
// ---------------------------------------------------------------------------

function Portfolio({ data, live, go, notify, session, reload }: { data: Any; live: Live; go: Go; notify: Notify; session: Session; reload: () => Promise<void> }) {
  const lender = data.lender
  const fiat = lender.funding === 'fiat'
  const kyc = kycState(lender, live)
  const positions = sortPositions(data.positions ?? [])
  const t = totalsOf(positions)
  const active = positions.filter((p) => outstanding(posStatus(p))).length
  const tiles = [
    { label: 'Invested', value: usd(t.invested, 2), note: active === 0 ? 'No active loans' : active === 1 ? 'In 1 active loan' : `In ${active} active loans` },
    { label: 'Expected returns', value: usd(t.interest, 2), note: 'Interest still to come' },
    { label: 'Received', value: usd(t.received, 2), note: fiat ? 'Paid to your bank account' : 'Claimed to your wallet' },
    ...(fiat ? [] : [{ label: 'Ready to claim', value: usd(t.claimable, 2), note: t.claimable > 0n ? 'Repaid, waiting for you to claim' : 'Nothing to claim' }]),
  ]
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Portfolio</h1>
          <div className="muted" style={{ marginTop: 6 }}>
            {lender.name}, investing {fiat ? 'by bank transfer' : 'in USDC'}.
          </div>
        </div>
        <Link to="/investor/marketplace" go={go} className="btn primary">
          Browse the marketplace
        </Link>
      </div>
      <div className="dash">
        {data.warning ? (
          <div className="banner warn" role="status">
            {data.warning}
          </div>
        ) : null}
        {kyc === 'verified' ? null : <IdentityStatus lender={lender} live={live} notify={notify} kyc={kyc} />}
        <Tiles label="Portfolio summary" items={tiles} />
        <Positions positions={positions} lender={lender} live={live} go={go} notify={notify} session={session} reload={reload} />
        <div className="split">
          {fiat ? <Deposits deposits={data.deposits ?? []} live={live} go={go} /> : <WalletPanel lender={lender} live={live} session={session} />}
          <IdentityPanel lender={lender} live={live} kyc={kyc} />
        </div>
      </div>
    </>
  )
}

/** Shown until the investor is verified: the identity check with its live log, or why it was declined. */
function IdentityStatus({ lender, live, notify, kyc }: { lender: Any; live: Live; notify: Notify; kyc: KycState }) {
  const { busy, run } = useAction(live, notify)
  const kycRun = kycRunFor(live, lender.id)
  const checking = isActive(kycRun) || busy === 'kyc'
  const failed = !checking && kycRun?.status === 'failed'
  if (kyc === 'rejected')
    return (
      <section className="panel status-card bad" role="status">
        <div className="panel-head">
          <h2>We could not verify your identity</h2>
          <StateText s={{ label: 'Declined', tone: 'bad' }} />
        </div>
        <div className="panel-pad stack">
          <p className="say bad small">{declinedReason(lender, live)}</p>
          <p className="small muted" style={{ margin: 0 }}>
            {/* Starting again with the same email (or wallet) signs back in to this account, so new details need a new one. */}
            This account cannot invest. To start again with different details, sign out and start investing with a different{' '}
            {lender.funding === 'fiat' ? 'email' : 'wallet'}.
          </p>
        </div>
      </section>
    )
  const state: ReqState = checking ? { label: 'In progress', tone: 'info' } : failed ? { label: 'Did not finish', tone: 'warn' } : { label: 'Not started', tone: 'warn' }
  return (
    <section className="panel status-card" aria-live="polite">
      <div className="panel-head">
        <h2>Verifying your identity</h2>
        <StateText s={state} />
      </div>
      <div className="panel-pad stack" style={{ gap: 14 }}>
        <p className="small muted" style={{ margin: 0 }}>
          We check your identity once, then register your wallet in the ERC-3643 identity registry so it can hold loan notes. You can browse the marketplace now; funding opens as soon as this is
          done.
        </p>
        <ul className="progress-list">
          <li className="done">Details received</li>
          <li className={checking ? 'now' : failed ? 'fail' : ''}>{checking ? 'Checking your identity' : 'Identity check'}</li>
          <li>Registered in the ERC-3643 identity registry</li>
          <li>Approved to invest</li>
        </ul>
        {kycRun && (isActive(kycRun) || userLines(kycRun).length) ? (
          <div className="runlog">
            <RunLog run={kycRun} />
          </div>
        ) : null}
        {failed ? <div className="say bad small">The identity check did not finish. Start it again.</div> : null}
        {!checking && (!kycRun || failed) ? (
          <div>
            <button className="btn primary" onClick={() => run('kyc', () => api(`/api/lenders/${lender.id}/kyc`, {}))}>
              Verify identity to invest
            </button>
          </div>
        ) : null}
      </div>
    </section>
  )
}

function Positions({
  positions,
  lender,
  live,
  go,
  notify,
  session,
  reload,
}: {
  positions: Any[]
  lender: Any
  live: Live
  go: Go
  notify: Notify
  session: Session
  reload: () => Promise<void>
}) {
  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Positions</h2>
        {positions.length ? <span className="small muted">{positions.length}</span> : null}
      </div>
      {positions.length === 0 ? (
        <div className="empty">
          You have no positions yet.{' '}
          <Link to="/investor/marketplace" go={go}>
            Browse the marketplace
          </Link>{' '}
          to fund your first loan.
        </div>
      ) : (
        <div className="scroll">
          <table className="rtable">
            <thead>
              <tr>
                <th>Loan</th>
                <th className="r">APR, term</th>
                <th className="r">Notes held</th>
                <th className="r">Principal</th>
                <th className="r">Expected payout</th>
                <th>Status</th>
                <th>Due</th>
              </tr>
            </thead>
            <tbody>
              {positions.map((p) => {
                const s = posStatus(p)
                const loan = (live.state?.loans ?? []).find((l: Any) => l.id === Number(p.loanId))
                // The document's due date, as on the loan page; a late loan also says since when it is overdue.
                const docDue = p.dueDate ?? (loan ? docFor(live, loan)?.dueDate : undefined)
                const due = fmtDate(docDue) || fmtDate(p.maturity)
                const overdueSince = s >= 5 && Number(p.maturity) > 0 ? fmtDate(p.maturity) : ''
                return (
                  <tr key={p.loanId}>
                    <td className="cell-main">
                      <div className="loan-cell">
                        <span className="grade sm" title="Risk grade">
                          {gradeOf(p.grade)}
                        </span>
                        <div>
                          <Link to={`/investor/loans/${p.loanId}`} go={go} className="title-link">
                            {p.title || p.ref}
                          </Link>
                          <div className="small muted">
                            {p.businessName}
                            {p.businessName ? ', ' : ''}
                            <span className="code">{p.ref}</span>
                          </div>
                        </div>
                      </div>
                    </td>
                    <td data-label="APR, term" className="r">
                      {pct(Number(p.aprBps))}
                      <div className="small muted">{days(Number(p.tenorDays))}</div>
                    </td>
                    <td data-label="Notes held" className="r">
                      <NotesHeld p={p} />
                    </td>
                    <td data-label="Principal" className="r">
                      {usd(u6(p.principalUsd6), 2)}
                    </td>
                    <td data-label="Expected payout" className="r">
                      {usd(u6(p.expectedUsd6), 2)}
                    </td>
                    <td data-label="Status" className="cell-status">
                      <PositionTag s={s} />
                      {s === 1 && loan ? <div className="small muted">Raising, {((Number(loan.funded) / Number(loan.target || 1)) * 100).toFixed(0)}% funded</div> : null}
                      <PositionAction p={p} lender={lender} live={live} notify={notify} session={session} reload={reload} />
                    </td>
                    <td data-label="Due">
                      {due || <span className="muted">After payout</span>}
                      {overdueSince ? <div className="small say bad">Overdue since {overdueSince}</div> : null}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}

/** What the investor can do with a position: claim it (USDC), or see where the bank payout went. */
function PositionAction({ p, lender, live, notify, session, reload, block }: { p: Any; lender: Any; live: Live; notify: Notify; session: Session; reload: () => Promise<void>; block?: boolean }) {
  const s = posStatus(p)
  if (lender.funding === 'fiat') {
    if (p.payoutRef)
      return (
        <div>
          <span className="state good">Paid to your bank</span>
          <div className="small muted code">{p.payoutRef}</div>
        </div>
      )
    return s === 4 ? (
      <div>
        <span className="state info">Paying to your bank</span>
      </div>
    ) : null
  }
  if (u6(p.claimableUsd6) > 0n) return <ClaimAction p={p} lender={lender} live={live} notify={notify} session={session} reload={reload} block={block} />
  if (s === 4 && u6(p.receivedUsd6) > 0n)
    return (
      <div>
        <span className="state good">Claimed</span>
      </div>
    )
  return null
}

/** Claims a repaid USDC position from the investor's own wallet (connecting it first if needed). */
function ClaimAction({ p, lender, live, notify, session, reload, block }: { p: Any; lender: Any; live: Live; notify: Notify; session: Session; reload: () => Promise<void>; block?: boolean }) {
  const flow = useTxFlow(session, live)
  const [claimed, setClaimed] = useState('')
  const [connecting, setConnecting] = useState(false)
  const [connectError, setConnectError] = useState('')
  const contracts = contractsOf(live)
  if (claimed)
    return (
      <div>
        <span className="state good">Claimed {claimed}</span>
      </div>
    )
  const label = usd(u6(p.claimableUsd6), 2)
  const cls = block ? 'btn primary block' : 'btn primary sm'
  const w = session.wallet
  if (w && !sameAddr(w.address, lender.wallet))
    return (
      <span className="small muted">
        Connect wallet <span className="code">{short(lender.wallet)}</span> to claim {label}.
      </span>
    )
  if (!w && !canConnect(live, lender)) return <span className="small muted">Claim {label} from the browser you signed up in.</span>
  if (!w) {
    const connect = async () => {
      setConnecting(true)
      setConnectError('')
      try {
        await session.connect()
      } catch (e) {
        setConnectError((e as Error).message)
      } finally {
        setConnecting(false)
      }
    }
    return (
      <div className="claim">
        <button className={cls} disabled={connecting} onClick={connect}>
          {connecting ? 'Connecting…' : `Connect wallet to claim ${label}`}
        </button>
        {connectError ? (
          <div className="say bad small" role="alert">
            {connectError}
          </div>
        ) : null}
      </div>
    )
  }
  const claim = async () => {
    if (!contracts) return
    const ok = await flow.run([
      {
        key: 'claim',
        amount: label,
        call: calls.claim(contracts, Number(p.loanId)),
        reverted: 'The claim was reverted. This wallet may have claimed already. Refresh the page to check.',
      },
    ])
    if (ok) {
      setClaimed(label)
      notify(`Claimed ${label}`)
      await reload()
    }
  }
  return (
    <div className="claim">
      <button className={cls} disabled={flow.running || !contracts} onClick={claim}>
        {flow.current ? `${stepText(flow.current)}…` : `Claim ${label}`}
      </button>
      {block ? <TxSteps flow={flow} live={live} /> : null}
      {flow.error ? (
        <div className="say bad small" role="alert">
          {flow.error}
        </div>
      ) : null}
    </div>
  )
}

const DEPOSIT_STATE: Record<string, ReqState> = {
  awaiting_funds: { label: 'Awaiting your transfer', tone: 'warn' },
  received: { label: 'Received', tone: 'info' },
  settled: { label: 'Converted', tone: 'info' },
  credited: { label: 'Credited', tone: 'good' },
  failed: { label: 'Not verified', tone: 'bad' },
}

function Deposits({ deposits, live, go }: { deposits: Any[]; live: Live; go: Go }) {
  const rows = [...deposits].sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)))
  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Deposits</h2>
        {rows.length ? <span className="small muted">{rows.length}</span> : null}
      </div>
      {rows.length === 0 ? (
        <div className="empty">
          No bank transfers yet. Choose a loan in the{' '}
          <Link to="/investor/marketplace" go={go}>
            marketplace
          </Link>{' '}
          and enter an amount to get transfer details.
        </div>
      ) : (
        <div className="scroll">
          <table className="rtable">
            <thead>
              <tr>
                <th>Reference</th>
                <th>Loan</th>
                <th className="r">Amount</th>
                <th className="r">In USDC</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((d) => {
                const st = DEPOSIT_STATE[d.status] ?? { label: String(d.status), tone: 'info' }
                const loan = (live.state?.loans ?? []).find((l: Any) => l.id === Number(d.loanId))
                return (
                  <tr key={d.reference}>
                    <td className="cell-main">
                      <span className="code strong">{d.reference}</span>
                      <div className="small muted">{fmtDate(d.createdAt)}</div>
                    </td>
                    <td data-label="Loan">
                      <Link to={`/investor/loans/${d.loanId}`} go={go} className="title-link">
                        {loan?.ref ?? `Loan ${d.loanId}`}
                      </Link>
                    </td>
                    <td data-label="Amount" className="r">
                      {money(d.amountMinor, d.currency, 2)}
                    </td>
                    <td data-label="In USDC" className="r">
                      {d.stablecoinAmount ? usd(u6(d.stablecoinAmount), 2) : <span className="muted">Not yet</span>}
                      {d.fxRateE8 && d.currency !== 'USD' ? <div className="small muted">at {rate(d.fxRateE8)}</div> : null}
                    </td>
                    <td data-label="Status">
                      <StateText s={st} />
                      {d.status === 'awaiting_funds' ? (
                        <div className="small">
                          <Link to={`/investor/loans/${d.loanId}`} go={go}>
                            See transfer details
                          </Link>
                        </div>
                      ) : null}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}

function WalletPanel({ lender, live, session }: { lender: Any; live: Live; session: Session }) {
  const account = useAccount(lender.wallet, live)
  const w = session.wallet
  const connected = !!w && sameAddr(w.address, lender.wallet)
  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Wallet</h2>
        <StateText s={connected ? { label: 'Connected', tone: 'good' } : { label: 'Not connected', tone: 'warn' }} />
      </div>
      <div className="panel-pad stack">
        <div className="balance">
          <div>
            <span className="small muted">USDC balance</span>
            <b>{account.info ? usd(account.info.usdc, 2) : '…'}</b>
          </div>
        </div>
        <div className="small muted">
          You fund loans and claim repayments from wallet{' '}
          <Addr a={lender.wallet} live={live}>
            <span className="code">{short(lender.wallet)}</span>
          </Addr>
          .
        </div>
        {connected ? null : w ? (
          <div className="stack" style={{ gap: 8 }}>
            <div className="say warn small">
              Wallet <span className="code">{short(w.address)}</span> is connected, but this account uses <span className="code">{short(lender.wallet)}</span>. Connect that wallet to fund
              or claim.
            </div>
            <div>
              <button className="btn quiet sm" onClick={() => session.disconnect()}>
                Disconnect {short(w.address)}
              </button>
            </div>
          </div>
        ) : canConnect(live, lender) ? (
          <ConnectWallet session={session} live={live} />
        ) : (
          <div className="say warn small">{ELSEWHERE}</div>
        )}
      </div>
    </section>
  )
}

function IdentityPanel({ lender, live, kyc }: { lender: Any; live: Live; kyc: KycState }) {
  const fiat = lender.funding === 'fiat'
  const check: ReqState =
    kyc === 'verified' ? { label: 'Approved', tone: 'good' } : kyc === 'rejected' ? { label: 'Declined', tone: 'bad' } : { label: 'In progress', tone: 'info' }
  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Identity</h2>
        {kyc === 'verified' ? <span className="verified">Verified</span> : null}
      </div>
      <table className="kv">
        <tbody>
          <tr>
            <td>Identity check</td>
            <td>
              <StateText s={check} />
            </td>
          </tr>
          <tr>
            <td>Registry</td>
            <td>
              {/* The identity run's own verdict lands a moment before the portfolio's chain read catches up. */}
              {lender.verifiedOnchain || kyc === 'verified' ? 'Registered in the ERC-3643 identity registry' : <span className="muted">Not registered yet</span>}
              {lender.identity ? (
                <div className="small muted">
                  ONCHAINID{' '}
                  <Addr a={lender.identity} live={live} />
                </div>
              ) : null}
            </td>
          </tr>
          <tr>
            <td>Wallet</td>
            <td>
              <Addr a={lender.wallet} live={live} />
              <div className="small muted">{fiat ? 'Held for you by Tradeflow. Your loan notes are kept here.' : 'Your own wallet. Your loan notes are kept here.'}</div>
            </td>
          </tr>
          <tr>
            <td>Funding</td>
            <td>{fiat ? 'Bank transfer' : 'USDC'}</td>
          </tr>
          <tr>
            <td>Country</td>
            <td>{countryName(lender.country)}</td>
          </tr>
        </tbody>
      </table>
    </section>
  )
}

// ---------------------------------------------------------------------------
// Marketplace
// ---------------------------------------------------------------------------

type Sort = 'new' | 'apr' | 'term' | 'left'
function Marketplace({ data, live, go }: { data: Any; live: Live; go: Go }) {
  const [sort, setSort] = useState<Sort>('new')
  const kyc = kycState(data.lender, live)
  const open: Any[] = (live.state?.loans ?? []).filter((l: Any) => l.status === 1)
  const left = (l: Any) => BigInt(l.target) - BigInt(l.funded)
  const ordered = [...open].sort((a, b) =>
    sort === 'apr' ? b.aprBps - a.aprBps || b.id - a.id : sort === 'term' ? a.tenorDays - b.tenorDays || b.id - a.id : sort === 'left' ? Number(left(a) - left(b)) || b.id - a.id : b.id - a.id,
  )
  const toRaise = open.reduce((s, l) => s + left(l), 0n)
  const mine = new Map<number, bigint>((data.positions ?? []).map((p: Any) => [Number(p.loanId), u6(p.principalUsd6)]))
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Marketplace</h1>
          <p className="lede" style={{ marginTop: 8 }}>
            Loans open for funding. Each is backed by a document its buyer has confirmed, and graded by a private credit review.
          </p>
        </div>
      </div>
      <div className="dash">
        {live.state?.snapshot?.fundingPaused ? <div className="banner bad">New funding is paused while a reserve check is reviewed.</div> : null}
        {kyc === 'pending' ? (
          <div className="banner warn">
            Funding opens once your identity is verified.{' '}
            <Link to="/investor" go={go}>
              See where your check stands
            </Link>
            .
          </div>
        ) : kyc === 'rejected' ? (
          <div className="banner bad">Your identity could not be verified, so this account cannot fund loans.</div>
        ) : null}
        {open.length === 0 ? (
          <div className="panel empty">No loans are open for funding right now. New loans appear here as soon as their documents are verified.</div>
        ) : (
          <>
            <div className="toolbar">
              <span className="muted">
                <b className="num">{open.length}</b> {open.length === 1 ? 'loan' : 'loans'} open, <b className="num">{usd(toRaise)}</b> left to raise
              </span>
              <label className="sort">
                <span>Sort by</span>
                <select className="ctl" value={sort} onChange={(e) => setSort(e.target.value as Sort)}>
                  <option value="new">Newest</option>
                  <option value="apr">Highest APR</option>
                  <option value="term">Shortest term</option>
                  <option value="left">Closest to funded</option>
                </select>
              </label>
            </div>
            <div className="board">
              {ordered.map((l) => (
                <LoanCard
                  key={l.id}
                  loan={l}
                  live={live}
                  go={go}
                  to={`/investor/loans/${l.id}`}
                  note={mine.get(l.id) ? <span className="state good">You invested {usd(mine.get(l.id), 2)}</span> : undefined}
                />
              ))}
            </div>
          </>
        )}
      </div>
    </>
  )
}

// ---------------------------------------------------------------------------
// Loan page (investor)
// ---------------------------------------------------------------------------

function InvestorLoan({ id, data, live, go, notify, session, reload }: { id: number; data: Any; live: Live; go: Go; notify: Notify; session: Session; reload: () => Promise<void> }) {
  const loan = live.state?.loans?.find((l: Any) => l.id === id)
  if (!loan) return <LoanMissing go={go} to="/investor/marketplace" label="Back to the marketplace" />
  const position = (data.positions ?? []).find((p: Any) => Number(p.loanId) === id)
  const mine = position ? <YourPosition p={position} lender={data.lender} loan={loan} live={live} notify={notify} session={session} reload={reload} /> : null
  // An investor with a position sees its status in the header, as in the portfolio; anyone else, the loan's.
  return (
    <LoanDetail
      loan={loan}
      live={live}
      go={go}
      crumb={position ? { to: '/investor', label: 'Portfolio' } : { to: '/investor/marketplace', label: 'Marketplace' }}
      tag={position ? <PositionTag s={posStatus(position)} /> : undefined}
    >
      {loan.status === 1 ? (
        <>
          <FundPanel loan={loan} lender={data.lender} live={live} go={go} notify={notify} session={session} />
          {mine}
        </>
      ) : (
        <>
          {mine}
          <LoanStatusPanel loan={loan} live={live} audience="investor" />
        </>
      )}
    </LoanDetail>
  )
}

/** The investor's own stake in this loan, with the claim or the bank payout once it is repaid. */
function YourPosition({ p, lender, loan, live, notify, session, reload }: { p: Any; lender: Any; loan: Any; live: Live; notify: Notify; session: Session; reload: () => Promise<void> }) {
  const s = posStatus(p)
  const fiat = lender.funding === 'fiat'
  const c = loanContext(loan, live)
  const expected = usd(u6(p.expectedUsd6), 2)
  const received = u6(p.receivedUsd6)
  const where = fiat ? 'paid to your bank account' : 'to claim from your wallet'
  const note =
    s === 1
      ? `The loan is still raising. Once it is fully funded and paid out, you receive ${expected} when ${c.buyer} pays, ${where}.`
      : s === 2
        ? `The advance is being paid out now. You receive ${expected} when ${c.buyer} pays, ${where}.`
        : s === 3
          ? `${c.dueText ? `Due on ${c.dueText}. ` : ''}You receive ${expected} when ${c.buyer} pays, ${where}.`
          : ''
  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Your position</h2>
        <PositionTag s={s} />
      </div>
      <dl className="pos-grid">
        <div>
          <dt>Notes held</dt>
          <dd>
            <NotesHeld p={p} />
          </dd>
        </div>
        <div>
          <dt>Principal</dt>
          <dd>{usd(u6(p.principalUsd6), 2)}</dd>
        </div>
        <div>
          <dt>Expected payout</dt>
          <dd>{expected}</dd>
        </div>
        <div>
          <dt>{fiat ? 'Paid to your bank' : 'Received'}</dt>
          <dd>{usd(received, 2)}</dd>
        </div>
      </dl>
      <div className="panel-pad stack pos-foot">
        {note ? <div className="small muted">{note}</div> : null}
        {s === 5 ? <div className="say warn small">Payment is overdue. Your {p.symbol || noteSymbol(p.loanId)} notes are paused until it is settled.</div> : null}
        {s === 6 ? <div className="say bad small">The loan is in default. Your {p.symbol || noteSymbol(p.loanId)} notes are paused.</div> : null}
        {s === 4 ? (
          fiat ? (
            p.payoutRef ? (
              <div className="say good small">
                {usd(received, 2)} paid to your bank account, reference <span className="code">{p.payoutRef}</span>.
              </div>
            ) : (
              <div className="small muted">Paying {expected} to your bank account now.</div>
            )
          ) : u6(p.claimableUsd6) > 0n ? (
            <ClaimAction p={p} lender={lender} live={live} notify={notify} session={session} reload={reload} block />
          ) : (
            <div className="say good small">{usd(received, 2)} claimed to your wallet.</div>
          )
        ) : null}
      </div>
    </section>
  )
}

/** Funding, bound to the investor's own method. Disabled with the reason until the identity is verified. */
function FundPanel({ loan, lender, live, go, notify, session }: { loan: Any; lender: Any; live: Live; go: Go; notify: Notify; session: Session }) {
  const fiat = lender.funding === 'fiat'
  const kyc = kycState(lender, live)
  const checking = isActive(kycRunFor(live, lender.id))
  let body: React.ReactNode
  if (live.state?.snapshot?.fundingPaused) body = <div className="say bad small">Funding is paused while a reserve check is reviewed.</div>
  else if (kyc === 'rejected') body = <div className="say bad small">Your identity could not be verified, so this account cannot fund loans.</div>
  else if (kyc === 'pending')
    body = (
      <>
        <div className="say warn small">Funding opens once your identity is verified.</div>
        <div className="small muted">
          {checking ? (
            'Your identity check is running now. This panel opens when it is done.'
          ) : (
            <>
              Your identity check has not finished.{' '}
              <Link to="/investor" go={go}>
                See where it stands
              </Link>
              .
            </>
          )}
        </div>
        <button className="btn primary block" disabled>
          {fiat ? 'Get transfer details' : 'Fund'}
        </button>
      </>
    )
  else body = fiat ? <Transfer loan={loan} live={live} notify={notify} lender={lender} /> : <UsdcGate loan={loan} lender={lender} live={live} notify={notify} session={session} />
  return (
    <section className="panel panel-pad stack" style={{ gap: 16 }}>
      <h2>Fund this loan</h2>
      <div className="who">
        <span>
          Investing as <b>{lender.name}</b>
          {fiat ? (
            ' by bank transfer'
          ) : (
            <>
              {' '}
              from <span className="code">{short(lender.wallet)}</span>
            </>
          )}
        </span>
      </div>
      {body}
    </section>
  )
}

/** USDC funding needs the investor's own wallet connected in this browser. */
function UsdcGate({ loan, lender, live, notify, session }: { loan: Any; lender: Any; live: Live; notify: Notify; session: Session }) {
  const w = session.wallet
  const mine = !!w && sameAddr(w.address, lender.wallet)
  const account = useAccount(mine ? w!.address : undefined, live)
  if (!w && !canConnect(live, lender)) return <div className="say warn small">{ELSEWHERE}</div>
  if (!w)
    return (
      <div className="stack">
        <div className="small muted">{walletIntro(live, 'fund')}</div>
        <ConnectWallet session={session} live={live} />
      </div>
    )
  if (!mine)
    return (
      <div className="stack">
        <div className="say warn small">
          Wallet <span className="code">{short(w.address)}</span> is connected, but your investor account uses <span className="code">{short(lender.wallet)}</span>. Connect that wallet to fund.
        </div>
        <button className="btn quiet block" onClick={() => session.disconnect()}>
          Disconnect {short(w.address)}
        </button>
      </div>
    )
  return <UsdcFund loan={loan} live={live} notify={notify} session={session} account={account} />
}

// ---------------------------------------------------------------------------
// Funding flows (bank transfer, USDC)
// ---------------------------------------------------------------------------

const ACCOUNT: Record<string, string> = { EUR: 'DE89 3704 0044 0532 0130 00', USD: 'US-ACH 021000021 / 9988776655' }

function Transfer({ loan, live, notify, lender }: { loan: Any; live: Live; notify: Notify; lender: Any }) {
  const { busy, run } = useAction(live, notify)
  const currency = ccyOf(loan.currency) === 'USD' ? 'USD' : 'EUR'
  const [amount, setAmount] = useState('')
  const [error, setError] = useState('')
  // undefined: pick up a transfer already in flight for this loan; null: start a new one.
  const [picked, setPicked] = useState<string | null | undefined>(undefined)
  const [instructions, setInstructions] = useState<Any>(null)
  const intents: Any[] = live.state?.intents ?? []
  const inFlight = intents.find((i) => i.lenderId === lender.id && Number(i.loanId) === loan.id && (i.status === 'awaiting_funds' || i.status === 'received' || i.status === 'settled'))
  const reference = picked === undefined ? inFlight?.reference : picked
  const intent = reference ? intents.find((i) => i.reference === reference) : undefined
  const depositRun = reference ? live.runs.find((r) => r.handler === 'credit-fiat-deposit' && r.input.includes(reference)) : undefined
  const remaining = BigInt(loan.target) - BigInt(loan.funded)
  // The on-ramp converts at its own quote, close to the reference rate the loan was priced at.
  const quoteE8 = currency === 'USD' ? 100_000_000n : (BigInt(loan.fxRateE8 || 0) * 9_980n) / 10_000n
  const minor = Math.round(Number(amount || 0) * 100)
  const estimate = (BigInt(minor) * quoteE8 * 10_000n) / 100_000_000n
  const maxMinor = quoteE8 > 0n ? (remaining * 100_000_000n) / (quoteE8 * 10_000n) : 0n

  if (!intent) {
    const submit = () => {
      const problem = !minor
        ? 'Enter how much to send.'
        : quoteE8 > 0n && BigInt(minor) > maxMinor
          ? `That is more than the ${usd(remaining, 2)} left to raise. Enter ${money(Number(maxMinor), currency, 2)} or less.`
          : ''
      setError(problem)
      if (problem) return
      run('intent', async () => {
        const r = await api('/api/onramp/intent', { lenderId: lender.id, loanId: loan.id, amountMinor: minor, currency })
        setInstructions(r.instructions ?? null)
        setPicked(r.intent.reference)
      })
    }
    return (
      <div className="stack">
        <div className="fld">
          <label htmlFor="fiat-amount">Amount</label>
          <div className={`input ${error ? 'invalid' : ''}`}>
            <span>{currency}</span>
            <input
              id="fiat-amount"
              inputMode="decimal"
              autoComplete="off"
              placeholder="0"
              value={amount}
              aria-invalid={error ? true : undefined}
              aria-describedby={error ? 'fiat-amount-err' : 'fiat-amount-hint'}
              onChange={(e) => {
                setAmount(decimal(e.target.value, 2))
                setError('')
              }}
            />
          </div>
          {error ? (
            <div className="err" id="fiat-amount-err">
              {error}
            </div>
          ) : (
            <div className="hint" id="fiat-amount-hint">
              {minor && currency !== 'USD' ? `About ${usd(estimate, 2)} in USDC once your transfer arrives. ` : ''}
              {usd(remaining, 2)} left to raise.
            </div>
          )}
        </div>
        <button className="btn primary block" disabled={!!busy} onClick={submit}>
          {busy === 'intent' ? 'Getting transfer details…' : 'Get transfer details'}
        </button>
      </div>
    )
  }

  const received = intent.status !== 'awaiting_funds'
  const credited = intent.status === 'credited'
  const failed = intent.status === 'failed' || (!credited && depositRun?.status === 'failed')
  const verifying = received && !credited && !failed && (busy === 'deposit' || isActive(depositRun))
  const ccy = intent.currency
  return (
    <div className="stack">
      <dl className="instructions" style={{ margin: 0 }}>
        <div>
          <dt>Send</dt>
          <dd>{money(intent.amountMinor, ccy, 2)}</dd>
        </div>
        <div>
          <dt>To</dt>
          <dd>
            {instructions?.beneficiary ?? 'Tradeflow Client Funds'}, {instructions?.iban ?? ACCOUNT[ccy] ?? ACCOUNT.EUR}
          </dd>
        </div>
        <div>
          <dt>Reference</dt>
          <dd className="code">{intent.reference}</dd>
        </div>
      </dl>
      {!received ? (
        <>
          <div className="small muted">Include the reference so we can match your transfer to this loan.</div>
          <button className="btn primary block" disabled={!!busy} onClick={() => run('deposit', () => api('/api/onramp/deposit-received', { reference: intent.reference }))}>
            {busy === 'deposit' ? 'Waiting for your transfer…' : "I've sent the transfer"}
          </button>
        </>
      ) : null}
      <ul className="progress-list" aria-live="polite">
        <li className={received ? 'done' : busy === 'deposit' ? 'now' : ''}>Transfer received</li>
        <li className={intent.fxRateE8 ? 'done' : received && !failed ? 'now' : ''}>Converted to USDC{intent.fxRateE8 ? ` at ${rate(intent.fxRateE8)}` : ''}</li>
        <li className={credited ? 'done' : failed ? 'fail' : verifying ? 'now' : ''}>Deposit verified</li>
        <li className={credited ? 'done' : ''}>
          {credited ? `${usd(intent.stablecoinAmount, 2)} in loan notes issued (${noteSymbol(loan.id)})` : 'Loan notes issued'}
        </li>
      </ul>
      {failed ? (
        <div className="say bad small" role="alert">
          {depositRun ? `We could not verify this deposit: ${runSummary(depositRun, live)}` : 'We could not verify this deposit.'}
        </div>
      ) : null}
      {credited || failed ? (
        <button
          className="btn quiet block"
          onClick={() => {
            setPicked(null)
            setInstructions(null)
            setAmount('')
          }}
        >
          Make another transfer
        </button>
      ) : null}
    </div>
  )
}

function UsdcFund({ loan, live, notify, session, account }: { loan: Any; live: Live; notify: Notify; session: Session; account: Account }) {
  const flow = useTxFlow(session, live)
  const faucet = useTxFlow(session, live)
  const [amount, setAmount] = useState('')
  const [error, setError] = useState('')
  const info = account.info
  const contracts = contractsOf(live)
  const remaining = BigInt(loan.target) - BigInt(loan.funded)
  const balance = BigInt(info?.usdc ?? 0)
  const value = toUsd6(amount)
  const busy = flow.running || faucet.running

  const getUsdc = async () => {
    if (!contracts) return
    const ok = await faucet.run([{ key: 'drip', call: calls.drip(contracts), reverted: 'The USDC faucet tops up each wallet once an hour. Try again later.' }])
    if (ok) {
      notify('USDC added to your wallet')
      await account.reload()
    }
  }
  const fund = async () => {
    if (!contracts) return
    const problem = !value
      ? 'Enter how much USDC to invest.'
      : value > remaining
        ? `That is more than the ${usdExact(remaining)} left to raise.`
        : value > balance
          ? `Your wallet holds ${usd(balance, 2)}. Get USDC or enter a smaller amount.`
          : ''
    setError(problem)
    if (problem || !value) return
    const label = usdExact(value)
    const plan: Plan[] = []
    if (BigInt(info?.allowance ?? 0) < value)
      plan.push({ key: 'approve', call: calls.approve(contracts, value), reverted: 'The approval was reverted. Refresh the page and try again.' })
    plan.push({
      key: 'fund',
      amount: label,
      call: calls.fund(contracts, loan.id, value),
      reverted: 'Funding was reverted. The loan may be fully funded or paused. Refresh the page to see what is left to raise.',
    })
    if (await flow.run(plan)) {
      setAmount('')
      notify(`Funded ${label}`)
      await account.reload()
    }
  }

  return (
    <div className="stack">
      <div className="balance">
        <div>
          <span className="small muted">Wallet balance</span>
          <b>{info ? usd(info.usdc, 2) : '…'}</b>
        </div>
        {info && (balance === 0n || (value !== null && value > balance)) ? (
          <button className="btn quiet sm" disabled={busy || !contracts} onClick={getUsdc}>
            {faucet.current ? `${stepText(faucet.current)}…` : 'Get USDC'}
          </button>
        ) : null}
      </div>
      <TxSteps flow={faucet} live={live} />
      {faucet.error ? (
        <div className="say bad small" role="alert">
          {faucet.error}
        </div>
      ) : null}
      {session.wallet?.kind === 'injected' && info && BigInt(info.eth ?? 0) === 0n ? (
        <div className="say warn small">This wallet has no ETH for network fees. Add Sepolia ETH to continue.</div>
      ) : null}
      <div className="fld">
        <label htmlFor="usdc-amount">Amount</label>
        <div className={`input ${error ? 'invalid' : ''}`}>
          <span>USDC</span>
          <input
            id="usdc-amount"
            inputMode="decimal"
            autoComplete="off"
            placeholder="0.00"
            value={amount}
            aria-invalid={error ? true : undefined}
            aria-describedby={error ? 'usdc-amount-err' : undefined}
            onChange={(e) => {
              setAmount(decimal(e.target.value, 6))
              setError('')
              if (!flow.running && flow.steps.length) flow.reset()
            }}
          />
        </div>
        {error ? (
          <div className="err" id="usdc-amount-err">
            {error}
          </div>
        ) : null}
      </div>
      <div className="row small" style={{ justifyContent: 'space-between' }}>
        <span className="muted">{usdExact(remaining)} left to raise</span>
        <button
          className="btn quiet sm"
          disabled={busy}
          onClick={() => {
            setAmount(formatUnits(remaining, 6))
            setError('')
          }}
        >
          Fund the rest
        </button>
      </div>
      <button className="btn primary block" disabled={busy || !contracts} onClick={fund}>
        {flow.current ? `${stepText(flow.current)}…` : value ? `Fund ${usdExact(value)}` : 'Fund'}
      </button>
      <TxSteps flow={flow} live={live} />
      {flow.error ? (
        <div className="say bad small" role="alert">
          {flow.error}
        </div>
      ) : null}
    </div>
  )
}
