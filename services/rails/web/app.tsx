// Tradeflow web app: the landing page, the investor portal (/investor), the business portal
// (/business), the buyer's page (/buyer/:token) and the operator console (/ops).

import React from 'react'
import { createRoot } from 'react-dom/client'
import { Business } from './business'
import { BuyerPortal } from './buyer'
import { Investor } from './investor'
import { Landing } from './landing'
import { Operations } from './ops'
import { isActive, Link, NameMenu, Redirect, useBusinessView, useInvestorView, useLive, usePath, useSession, useToast, WalletChip, Wordmark, type Go } from './shared'

/** The operator console is linked from here only (and not from the buyer's page). */
function Footer({ go }: { go?: Go }) {
  return (
    <footer className="foot">
      <div>
        <span>Tradeflow</span>
        <span className="foot-links">
          {go ? (
            <Link to="/ops" go={go}>
              Operator console
            </Link>
          ) : null}
          <span>
            Built by{' '}
            <a href="https://codedecoders.io" target="_blank" rel="noreferrer">
              CodeDecoders
            </a>
          </span>
        </span>
      </div>
    </footer>
  )
}

type Portal = 'landing' | 'investor' | 'business' | 'ops'
const portalOf = (path: string): Portal =>
  /^\/investor(\/|$)/.test(path) ? 'investor' : /^\/business(\/|$)/.test(path) ? 'business' : path === '/ops' ? 'ops' : 'landing'

function App() {
  const live = useLive()
  const session = useSession(live.config)
  const { path: raw, go, replace } = usePath()
  const path = raw.length > 1 ? raw.replace(/\/+$/, '') : raw
  const { toast, notify } = useToast()
  const portal = portalOf(path)
  // Each portal loads its own signed-in view; the other one stays idle.
  const investorView = useInvestorView(portal === 'investor' ? session.investor : null, live)
  const businessView = useBusinessView(portal === 'business' ? session.business : null, live)
  const toastEl = toast ? (
    <div className={`toast ${toast.bad ? 'bad' : ''}`} role="status">
      {toast.text}
    </div>
  ) : null

  const buyer = path.match(/^\/buyer\/([^/]+)/)
  if (buyer)
    return (
      <>
        <header className="top">
          <div className="top-inner">
            <Wordmark />
          </div>
        </header>
        <main>
          <BuyerPortal token={buyer[1]!} live={live} />
        </main>
        <Footer />
        {toastEl}
      </>
    )

  const busy = live.runs.some((r) => isActive(r))
  const paused = Boolean(live.state?.snapshot?.fundingPaused)
  const oldLoan = path.match(/^\/loans\/(\d+)/)
  const page = oldLoan ? (
    <Redirect to={`/investor/loans/${oldLoan[1]}`} replace={replace} />
  ) : portal === 'investor' ? (
    <Investor path={path} live={live} go={go} replace={replace} notify={notify} session={session} view={investorView} />
  ) : portal === 'business' ? (
    <Business path={path} live={live} go={go} replace={replace} notify={notify} session={session} view={businessView} />
  ) : portal === 'ops' ? (
    <Operations live={live} notify={notify} />
  ) : path === '/' ? (
    <Landing live={live} go={go} session={session} />
  ) : (
    <Redirect to="/" replace={replace} />
  )

  // The name menu shows whenever this portal has a session, so Sign out works even while the account is loading or failing to load.
  const signedInHere = portal === 'investor' ? !!session.investor : portal === 'business' ? !!session.business : false
  const investor = portal === 'investor' && session.investor ? investorView.data?.lender : null
  const business = portal === 'business' && session.business ? businessView.data?.business : null
  // A loan page sits under Portfolio when the investor holds a position in it, else under Marketplace.
  const loanId = path.match(/^\/investor\/loans\/(\d+)$/)?.[1]
  const held = !!loanId && (investorView.data?.positions ?? []).some((p: { loanId: unknown }) => String(p.loanId) === loanId)
  const nav: [string, string, boolean][] =
    portal === 'investor' && session.investor
      ? [
          ['/investor', 'Portfolio', path === '/investor' || held],
          ['/investor/marketplace', 'Marketplace', path === '/investor/marketplace' || (!!loanId && !held)],
        ]
      : portal === 'business' && session.business
        ? [
            ['/business', 'Overview', path === '/business' || path.startsWith('/business/loans/')],
            ['/business/new', 'Request financing', path === '/business/new'],
          ]
        : [
            ['/investor', 'Invest', portal === 'investor'],
            ['/business', 'Raise capital', portal === 'business'],
          ]
  // The wallet chip belongs to USDC investing: shown in the investor portal unless the account funds by bank transfer.
  const showWallet = portal === 'investor' && !!session.wallet && investor?.funding !== 'fiat'
  const signOut = (which: 'investor' | 'business') => {
    // The server forgets this browser's key too, so it stops working even if a copy of it is kept.
    const s = which === 'investor' ? session.investor : session.business
    if (s)
      void fetch(`/api/${which === 'investor' ? 'investors' : 'businesses'}/${encodeURIComponent(s.id)}/sign-out`, {
        method: 'POST',
        headers: which === 'investor' ? { 'x-investor-key': s.key } : { 'x-business-key': s.key },
      }).catch(() => {})
    if (which === 'investor') session.setInvestor(null)
    else session.setBusiness(null)
    notify('Signed out')
    if (path !== `/${which}`) go(`/${which}`)
  }

  return (
    <>
      <header className="top">
        <div className="top-inner">
          <Wordmark go={go} />
          <nav className="nav" aria-label="Main">
            {nav.map(([to, label, on]) => (
              <Link key={to} to={to} go={go} className={on ? 'on' : ''}>
                {label}
              </Link>
            ))}
          </nav>
          <div className="net" role="status">
            <span className={`pip ${live.offline ? 'alert' : busy ? 'busy' : paused ? 'alert' : ''}`} />
            <span>{live.offline ? 'Reconnecting' : busy ? 'Verifying' : paused ? 'Funding paused' : 'All systems normal'}</span>
          </div>
          {showWallet || signedInHere ? (
            <div className="acct">
              {showWallet ? <WalletChip session={session} /> : null}
              {portal === 'investor' && session.investor ? (
                <NameMenu
                  name={investor?.name}
                  detail={!investor ? 'Investor account' : investor.funding === 'fiat' ? 'Investor, bank transfer' : 'Investor, USDC'}
                  onSignOut={() => signOut('investor')}
                />
              ) : null}
              {portal === 'business' && session.business ? <NameMenu name={business?.name} detail="Business account" onSignOut={() => signOut('business')} /> : null}
            </div>
          ) : null}
        </div>
      </header>
      <main>
        {live.state ? (
          page
        ) : (
          <div className="loading" role="status">
            {live.offline ? 'Could not reach Tradeflow. Retrying' : 'Loading'}
          </div>
        )}
      </main>
      <Footer go={go} />
      {toastEl}
    </>
  )
}

createRoot(document.getElementById('root')!).render(<App />)
