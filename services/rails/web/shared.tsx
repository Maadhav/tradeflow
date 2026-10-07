// What every page shares: formatting, the API, sessions, live data, routing, and the building blocks
// both portals reuse (the trade lane, activity rows with their live logs, forms, wallet transactions).

import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { parseUnits } from 'viem'
import { type Call } from './abi'
import {
  connect as connectWallet,
  disconnect as forgetWallet,
  restore as restoreWallet,
  savedBuiltin,
  sendTx,
  switchChain,
  walletKind,
  watch as watchWallet,
  type TxStage,
  type WalletSession,
} from './wallet'

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

export type Any = any
/** A loan's status as investors and the public see it (one short word, shown as a tag). */
export const STATUS: Record<number, { label: string; tone: string }> = {
  1: { label: 'Listed', tone: 'open' },
  2: { label: 'Funded', tone: 'good' },
  3: { label: 'Active', tone: 'good' },
  4: { label: 'Repaid', tone: 'good' },
  5: { label: 'Late', tone: 'warn' },
  6: { label: 'Defaulted', tone: 'bad' },
}
export const ASSET = ['Invoice advance', 'Bill of lading', 'Equipment finance', 'Working capital']
export const GRADE = ['', 'A', 'B', 'C', 'D', 'E']
export const COUNTRIES: [string, string][] = (
  [
    ['AE', 'United Arab Emirates'], ['AR', 'Argentina'], ['AT', 'Austria'], ['AU', 'Australia'], ['BD', 'Bangladesh'],
    ['BE', 'Belgium'], ['BR', 'Brazil'], ['CA', 'Canada'], ['CH', 'Switzerland'], ['CI', "Côte d'Ivoire"], ['CL', 'Chile'],
    ['CN', 'China'], ['CO', 'Colombia'], ['CR', 'Costa Rica'], ['CU', 'Cuba'], ['CZ', 'Czechia'], ['DE', 'Germany'],
    ['DK', 'Denmark'], ['EC', 'Ecuador'], ['EG', 'Egypt'], ['ES', 'Spain'], ['ET', 'Ethiopia'], ['FI', 'Finland'],
    ['FR', 'France'], ['GB', 'United Kingdom'], ['GH', 'Ghana'], ['GR', 'Greece'], ['HK', 'Hong Kong'], ['HU', 'Hungary'],
    ['ID', 'Indonesia'], ['IE', 'Ireland'], ['IL', 'Israel'], ['IN', 'India'], ['IR', 'Iran'], ['IT', 'Italy'],
    ['JP', 'Japan'], ['KE', 'Kenya'], ['KP', 'North Korea'], ['KR', 'South Korea'], ['LK', 'Sri Lanka'], ['MA', 'Morocco'],
    ['MX', 'Mexico'], ['MY', 'Malaysia'], ['NG', 'Nigeria'], ['NL', 'Netherlands'], ['NO', 'Norway'], ['NZ', 'New Zealand'],
    ['PA', 'Panama'], ['PE', 'Peru'], ['PH', 'Philippines'], ['PK', 'Pakistan'], ['PL', 'Poland'], ['PT', 'Portugal'],
    ['QA', 'Qatar'], ['RO', 'Romania'], ['SA', 'Saudi Arabia'], ['SE', 'Sweden'], ['SG', 'Singapore'], ['SY', 'Syria'],
    ['TH', 'Thailand'], ['TR', 'Türkiye'], ['TW', 'Taiwan'], ['TZ', 'Tanzania'], ['UG', 'Uganda'], ['US', 'United States'],
    ['UY', 'Uruguay'], ['VN', 'Vietnam'], ['ZA', 'South Africa'],
  ] as [string, string][]
).sort((a, b) => a[1].localeCompare(b[1]))
export const COUNTRY: Record<string, string> = Object.fromEntries(COUNTRIES)
export const PORT: Record<string, string> = { ...COUNTRY, AE: 'UAE' }
export const countryName = (c?: string) => (c ? (COUNTRY[c] ?? c) : '')

export const DOC_TYPES = [
  { value: 'invoice', label: 'Invoice', noun: 'invoice', prefix: 'Invoice advance: ' },
  { value: 'bill_of_lading', label: 'Bill of lading', noun: 'bill of lading', prefix: 'Supply chain finance: ' },
  { value: 'equipment', label: 'Equipment order', noun: 'equipment order', prefix: 'Equipment finance: ' },
]
export const docType = (t?: string) => DOC_TYPES.find((d) => d.value === t) ?? DOC_TYPES[0]

export const usd = (v: string | number | bigint | undefined, digits = 0) =>
  (Number(BigInt(v ?? 0)) / 1e6).toLocaleString('en-US', { style: 'currency', currency: 'USD', minimumFractionDigits: digits, maximumFractionDigits: digits })
/** USDC to the cent, or to the last digit when an amount has fractions of a cent (so labels match what is sent). */
export const usdExact = (v: bigint) =>
  (Number(v) / 1e6).toLocaleString('en-US', { style: 'currency', currency: 'USD', minimumFractionDigits: 2, maximumFractionDigits: v % 10_000n === 0n ? 2 : 6 })
export const money = (minor: number | string, ccy: string, digits = 0) =>
  (Number(minor) / 100).toLocaleString('en-US', { style: 'currency', currency: ccy, minimumFractionDigits: digits, maximumFractionDigits: digits })
export const days = (n: number) => `${n} day${n === 1 ? '' : 's'}`
export const pct = (bps: number) => `${(bps / 100).toFixed(bps % 100 === 0 ? 0 : 1)}%`
export const rate = (e8: string | number) => (Number(e8) / 1e8).toFixed(4)
export const ccyOf = (hex: string) => {
  try {
    return hex.slice(2).match(/../g)!.map((b) => String.fromCharCode(parseInt(b, 16))).join('')
  } catch {
    return 'USD'
  }
}
export const short = (h?: string) => (h ? `${h.slice(0, 6)}…${h.slice(-4)}` : '')
export const ago = (iso?: string) => {
  if (!iso) return ''
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000)
  if (s < 60) return 'just now'
  if (s < 3600) return `${Math.floor(s / 60)} min ago`
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`
  return new Date(iso).toLocaleDateString('en-GB', { day: 'numeric', month: 'short' })
}
/** Dates arrive as 'YYYY-MM-DD', ISO timestamps or unix seconds (onchain). */
export const fmtDate = (v?: string | number) => {
  const s = String(v ?? '')
  if (!s || s === '0') return ''
  const dateOnly = /^\d{4}-\d{2}-\d{2}$/.test(s)
  const d = /^\d+$/.test(s) ? new Date(Number(s) * (Number(s) < 1e12 ? 1000 : 1)) : new Date(s)
  if (Number.isNaN(d.getTime())) return s
  return d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', ...(dateOnly ? { timeZone: 'UTC' } : {}) })
}
export const sentence = (s?: string) => (s ? s.charAt(0).toUpperCase() + s.slice(1) : '')
export const last4 = (s?: string) => String(s ?? '').replace(/\s/g, '').slice(-4)
export const fileSize = (n: number) => (n < 1024 * 1024 ? `${Math.max(1, Math.round(n / 1024))} KB` : `${(n / 1048576).toFixed(1)} MB`)
/** Keeps digits and a single decimal point, with at most `places` decimals. */
export const decimal = (v: string, places: number) => {
  const s = v.replace(/[^0-9.]/g, '')
  const i = s.indexOf('.')
  return i < 0 ? s : `${s.slice(0, i)}.${s.slice(i + 1).replace(/\./g, '').slice(0, places)}`
}
export const toUsd6 = (v: string): bigint | null => {
  try {
    const n = parseUnits(v || '0', 6)
    return n > 0n ? n : null
  } catch {
    return null
  }
}
export const isoDay = (d: Date) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`
export const addDays = (iso: string, n: number) => {
  const d = new Date(`${iso}T00:00:00`)
  d.setDate(d.getDate() + n)
  return isoDay(d)
}
export const daysBetween = (a: string, b: string) => Math.round((new Date(`${b}T00:00:00`).getTime() - new Date(`${a}T00:00:00`).getTime()) / 86_400_000)

export type ApiError = Error & { status?: number }
export async function request<T = Any>(path: string, body?: unknown, headers: Record<string, string> = {}): Promise<{ status: number; data: T }> {
  let res: Response
  try {
    res = await fetch(
      path,
      body === undefined ? { headers } : { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) },
    )
  } catch {
    throw Object.assign(new Error('Could not reach Tradeflow. Check your connection and try again.'), { status: 0 })
  }
  const data = await res.json().catch(() => ({}))
  if (!res.ok) throw Object.assign(new Error(data.error ?? `Something went wrong (${res.status}). Try again.`), { status: res.status })
  return { status: res.status, data }
}
export const api = async <T = Any,>(path: string, body?: unknown, headers?: Record<string, string>): Promise<T> => (await request<T>(path, body, headers)).data

// ---------------------------------------------------------------------------
// Sessions (per viewer, in this browser only)
// ---------------------------------------------------------------------------

// Each portal keeps its own session key, so signing out of one leaves the other signed in.
export const KEY = { business: 'tradeflow.business', investor: 'tradeflow.investor', wallet: 'tradeflow.wallet' }
export const stored = {
  get(key: string): string | null {
    try {
      return window.localStorage.getItem(key)
    } catch {
      return null
    }
  },
  set(key: string, value: string | null) {
    try {
      if (value === null) window.localStorage.removeItem(key)
      else window.localStorage.setItem(key, value)
    } catch {}
  },
}

export function useStored(key: string) {
  const [value, setValue] = useState<string | null>(() => stored.get(key))
  useEffect(() => {
    const on = (e: StorageEvent) => {
      if (e.key === key) setValue(e.newValue)
    }
    window.addEventListener('storage', on)
    return () => window.removeEventListener('storage', on)
  }, [key])
  const set = useCallback(
    (v: string | null) => {
      stored.set(key, v)
      setValue(v)
    },
    [key],
  )
  return [value, set] as const
}

/** A signed-in business or investor: its id and the key the server issued to this browser. */
export type PortalSession = { id: string; key: string }
export type BizSession = PortalSession
export type InvestorSession = PortalSession
export const parseSession = (raw: string | null): PortalSession | null => {
  try {
    const b = raw ? JSON.parse(raw) : null
    return b && typeof b.id === 'string' && typeof b.key === 'string' ? { id: b.id, key: b.key } : null
  } catch {
    return null
  }
}
export const bizHeaders = (b: BizSession) => ({ 'x-business-key': b.key })
export const investorHeaders = (i: InvestorSession) => ({ 'x-investor-key': i.key })

function usePortalSession(key: string) {
  const [raw, setRaw] = useStored(key)
  const value = useMemo(() => parseSession(raw), [raw])
  const set = useCallback((s: PortalSession | null) => setRaw(s ? JSON.stringify({ id: s.id, key: s.key }) : null), [setRaw])
  return [value, set] as const
}

export const parseWallet = (raw: string | null): WalletSession | null => {
  try {
    const w = raw ? JSON.parse(raw) : null
    return w && /^0x[0-9a-fA-F]{40}$/.test(w.address) && (w.kind === 'injected' || w.kind === 'builtin') ? w : null
  } catch {
    return null
  }
}

export function useSession(config: Any) {
  const [business, setBusiness] = usePortalSession(KEY.business)
  const [investor, setInvestor] = usePortalSession(KEY.investor)
  const [walletRaw, setWalletRaw] = useStored(KEY.wallet)
  const wallet = useMemo(() => parseWallet(walletRaw), [walletRaw])
  const [wrongChain, setWrongChain] = useState(false)
  const setWallet = useCallback((w: WalletSession | null) => setWalletRaw(w ? JSON.stringify({ address: w.address, kind: w.kind }) : null), [setWalletRaw])

  // A remembered wallet is checked against this deployment before it is trusted again.
  useEffect(() => {
    if (!config || !wallet) return
    let stale = false
    restoreWallet(wallet, config).then((w) => {
      if (stale) return
      if (!w) setWallet(null)
      else if (w.address !== wallet.address) setWallet(w)
    })
    return () => {
      stale = true
    }
  }, [config, wallet, setWallet])

  const kind = wallet?.kind
  useEffect(() => {
    if (!config || kind !== 'injected') {
      setWrongChain(false)
      return
    }
    return watchWallet(config, {
      account: (a) => setWallet(a ? { address: a, kind: 'injected' } : null),
      chain: (ok) => setWrongChain(!ok),
    })
  }, [config, kind, setWallet])

  const connect = useCallback(
    async (fresh = false) => {
      if (!config) throw new Error('Tradeflow is still loading. Try again in a moment.')
      const w = await connectWallet(config, { fresh })
      setWallet(w)
      return w
    },
    [config, setWallet],
  )
  const disconnect = useCallback(() => {
    if (wallet) void forgetWallet(wallet)
    setWallet(null)
  }, [wallet, setWallet])
  const fixChain = useCallback(() => switchChain(config ?? {}), [config])

  return { business, setBusiness, investor, setInvestor, wallet, wrongChain, connect, disconnect, fixChain }
}
export type Session = ReturnType<typeof useSession>

// ---------------------------------------------------------------------------
// Live data
// ---------------------------------------------------------------------------

export function useLive() {
  const [state, setState] = useState<Any>(null)
  const [runs, setRuns] = useState<Any[]>([])
  const [config, setConfig] = useState<Any>(null)
  const [offline, setOffline] = useState(false)
  const hasConfig = useRef(false)

  const refresh = useCallback(async () => {
    if (!hasConfig.current)
      api('/api/config').then(
        (c) => {
          hasConfig.current = true
          setConfig(c)
        },
        () => {},
      )
    try {
      const [s, r] = await Promise.all([api('/api/state'), api('/api/runs')])
      setState(s)
      setRuns(r)
      setOffline(false)
    } catch {
      setOffline(true)
    }
  }, [])

  useEffect(() => {
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

  return { state, runs, config, offline, refresh }
}
export type Live = ReturnType<typeof useLive>

export const sameAddr = (a?: string | null, b?: string | null) => !!a && !!b && a.toLowerCase() === b.toLowerCase()
export const bizFor = (live: Live, wallet: string) => (live.state?.businesses ?? []).find((b: Any) => sameAddr(b.wallet, wallet))
export const lenderFor = (live: Live, wallet?: string) => (live.state?.lenders ?? []).find((l: Any) => sameAddr(l.wallet, wallet))
export const lenderById = (live: Live, id?: string | null) => (id ? (live.state?.lenders ?? []).find((l: Any) => l.id === id) : undefined)
/** The registry record behind a loan (document numbers are unique per business). */
export const docFor = (live: Live, loan: Any) => {
  const docs = (live.state?.documents ?? []).filter((d: Any) => d.number === loan.ref)
  if (docs.length < 2) return docs[0]
  const biz = bizFor(live, loan.borrower)
  return docs.find((d: Any) => d.businessId === biz?.id) ?? docs[0]
}
export const dueOf = (loan: Any) => BigInt(loan.target) + (BigInt(loan.target) * BigInt(loan.aprBps) * BigInt(loan.tenorDays)) / (10_000n * 365n)
export const runInput = (run: Any): Any => {
  try {
    return JSON.parse(run.input) ?? {}
  } catch {
    return {}
  }
}
export const isActive = (run?: Any) => run?.status === 'running' || run?.status === 'queued'
export const kycRunFor = (live: Live, lenderId: string) => live.runs.find((r) => r.handler === 'verify-lender' && runInput(r).lenderId === lenderId)
export const contractsOf = (live: Live) => {
  const d = live.config?.deployment
  return d?.market && d?.stablecoin ? { market: d.market, stablecoin: d.stablecoin } : null
}

/** Balance, allowance, verification and loan notes (per-loan ERC-3643 token balances) for any address, refreshed as the market moves. */
export function useAccount(address: string | undefined, live: Live) {
  const [info, setInfo] = useState<Any>(null)
  const [error, setError] = useState('')
  const current = useRef(address)
  current.current = address
  const load = useCallback(async () => {
    if (!address) return
    try {
      const w = await api(`/api/wallet/${address}`)
      if (sameAddr(current.current, address)) {
        setInfo({ ...w, requested: address })
        setError('')
      }
    } catch (e) {
      if (sameAddr(current.current, address)) setError((e as Error).message)
    }
  }, [address])
  useEffect(() => {
    setInfo(null)
    setError('')
  }, [address])
  useEffect(() => {
    void load()
  }, [load, live.state])
  return { info: info && sameAddr(info.requested, address) ? info : null, error, reload: load }
}
export type Account = ReturnType<typeof useAccount>

/** A business's own view (signed in): its profile and documents, including the buyer links. */
export function useBusinessView(session: BizSession | null, live: Live) {
  const [data, setData] = useState<Any>(null)
  const [missing, setMissing] = useState(false)
  const [error, setError] = useState('')
  const id = session?.id ?? null
  const key = session?.key ?? null
  const current = useRef(id)
  current.current = id
  const load = useCallback(async () => {
    if (!id || !key) return
    try {
      const d = await api(`/api/businesses/${encodeURIComponent(id)}`, undefined, { 'x-business-key': key })
      if (current.current === id) {
        setData(d)
        setMissing(false)
        setError('')
      }
    } catch (e) {
      if (current.current !== id) return
      const status = (e as ApiError).status
      if (status === 404 || status === 401) setMissing(true)
      else setError((e as Error).message)
    }
  }, [id, key])
  useEffect(() => {
    setData(null)
    setMissing(false)
    setError('')
  }, [id])
  useEffect(() => {
    void load()
  }, [load, live.state])
  return { data: data?.business?.id === id ? data : null, missing, error, reload: load }
}
export type BusinessView = ReturnType<typeof useBusinessView>

/** An investor's own view (signed in): profile, identity status, positions, deposits and totals. */
export function useInvestorView(session: InvestorSession | null, live: Live) {
  const [data, setData] = useState<Any>(null)
  const [missing, setMissing] = useState(false)
  const [error, setError] = useState('')
  const id = session?.id ?? null
  const key = session?.key ?? null
  const current = useRef(id)
  current.current = id
  const load = useCallback(async () => {
    if (!id || !key) return
    try {
      const d = await api(`/api/investors/${encodeURIComponent(id)}/portfolio`, undefined, { 'x-investor-key': key })
      if (current.current === id) {
        setData(d)
        setMissing(false)
        setError('')
      }
    } catch (e) {
      if (current.current !== id) return
      const status = (e as ApiError).status
      if (status === 404 || status === 401) setMissing(true)
      else setError((e as Error).message)
    }
  }, [id, key])
  useEffect(() => {
    setData(null)
    setMissing(false)
    setError('')
  }, [id])
  useEffect(() => {
    void load()
  }, [load, live.state])
  return { data: data?.lender?.id === id ? data : null, missing, error, reload: load }
}
export type InvestorView = ReturnType<typeof useInvestorView>

// ---------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------

export function usePath() {
  const [path, setPath] = useState(location.pathname)
  useEffect(() => {
    const on = () => setPath(location.pathname)
    window.addEventListener('popstate', on)
    return () => window.removeEventListener('popstate', on)
  }, [])
  const go = useCallback((p: string) => {
    history.pushState({}, '', p)
    setPath(p)
    window.scrollTo(0, 0)
  }, [])
  /** Swaps the current address without a new history entry (redirects). */
  const replace = useCallback((p: string) => {
    history.replaceState({}, '', p)
    setPath(p)
  }, [])
  return { path, go, replace }
}

export type Go = (p: string) => void

/** Where a signed-out visitor was heading, per portal, so signing in takes them there. */
const returnTo: Record<'investor' | 'business', string | null> = { investor: null, business: null }
export const rememberReturn = (portal: 'investor' | 'business', path: string) => {
  returnTo[portal] = path
}
/** The page to open after signing in (and forgets it). */
export const takeReturn = (portal: 'investor' | 'business'): string | null => {
  const p = returnTo[portal]
  returnTo[portal] = null
  return p
}

/** Sends the browser elsewhere without adding a history entry. */
export function Redirect({ to, replace }: { to: string; replace: Go }) {
  useEffect(() => {
    replace(to)
  }, [to, replace])
  return null
}
export function Link({ to, go, className, children }: { to: string; go: Go; className?: string; children: React.ReactNode }) {
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

export function useToast() {
  const [toast, setToast] = useState<{ text: string; bad?: boolean } | null>(null)
  useEffect(() => {
    if (!toast) return
    const t = setTimeout(() => setToast(null), 6000)
    return () => clearTimeout(t)
  }, [toast])
  return { toast, notify: (text: string, bad = false) => setToast({ text, bad }) }
}
export type Notify = (text: string, bad?: boolean) => void

export function useAction(live: Live, notify: Notify) {
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

export function Tx({ h, live }: { h?: string; live: Live }) {
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

/** A contract address, linked to the block explorer when there is one. */
export function Addr({ a, live, children }: { a?: string; live: Live; children?: React.ReactNode }) {
  if (!a) return null
  const base = live.config?.explorer
  const label = children ?? <span className="code">{short(a)}</span>
  return base ? (
    <a className="hash" href={`${base}/address/${a}`} target="_blank" rel="noreferrer">
      {label}
    </a>
  ) : (
    <span className={children ? undefined : 'hash'}>{label}</span>
  )
}

/** Each loan's notes are its own ERC-3643 token, named by the market when the loan is listed. */
export const noteSymbol = (loanId: number | string) => `TFN${loanId}`
export const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000'

export function Status({ s }: { s: number }) {
  const st = STATUS[s]
  return st ? <span className={`tag ${st.tone}`}>{st.label}</span> : null
}

export function Lane({ from, to, progress, status }: { from?: string; to?: string; progress: number; status: number }) {
  const p = Math.max(0, Math.min(100, progress))
  const cls = status === 4 ? 'done' : status >= 5 ? 'late' : ''
  return (
    <div className="lane" aria-label={`${countryName(from)} to ${countryName(to)}, ${p.toFixed(0)}% funded`}>
      <div className="port">
        {from}
        <small>{PORT[from ?? ''] ?? ''}</small>
      </div>
      <div className={`route ${cls}`}>
        <div className="sailed" style={{ width: `${p}%` }} />
        <div className="ship" style={{ left: `${p}%` }} />
      </div>
      <div className="port">
        {to}
        <small>{PORT[to ?? ''] ?? ''}</small>
      </div>
    </div>
  )
}

/** Quiet coloured status text: used where a status can be more than one short word. */
export type ReqState = { label: string; tone: 'info' | 'good' | 'warn' | 'bad'; reason?: string; next?: string; retry?: boolean; loanId?: number }
export function StateText({ s }: { s: ReqState }) {
  return <span className={`state ${s.tone}`}>{s.label}</span>
}
/** A loan's status as its business sees it, on the overview and on the loan's page alike. */
export const BUSINESS_STATUS: Record<number, ReqState> = {
  1: { label: 'Listed', tone: 'info' },
  2: { label: 'Funded', tone: 'good' },
  3: { label: 'Paid out', tone: 'good' },
  4: { label: 'Repaid', tone: 'good' },
  5: { label: 'Late', tone: 'bad' },
  6: { label: 'Defaulted', tone: 'bad' },
}

export function Wordmark({ go }: { go?: Go }) {
  const mark = (
    <>
      <svg width="22" height="22" viewBox="0 0 22 22" aria-hidden="true">
        <circle cx="4" cy="11" r="3" fill="#f2b705" />
        <circle cx="18" cy="11" r="3" fill="none" stroke="#fff" strokeWidth="2" />
        <path d="M8 11h6" stroke="#fff" strokeWidth="2" strokeDasharray="2 2" />
      </svg>
      Tradeflow
    </>
  )
  return go ? (
    <Link to="/" go={go} className="wordmark">
      {mark}
    </Link>
  ) : (
    <span className="wordmark">{mark}</span>
  )
}

export function Loading({ text = 'Loading' }: { text?: string }) {
  return (
    <div className="loading" role="status">
      {text}
    </div>
  )
}

/** Summary figures at the top of a dashboard: label, value and an optional quiet note. */
export type Tile = { label: string; value: React.ReactNode; note?: React.ReactNode }
export function Tiles({ items, label }: { items: Tile[]; label: string }) {
  return (
    <dl className={`tiles tiles-${items.length}`} aria-label={label}>
      {items.map((t) => (
        <div key={t.label}>
          <dt>{t.label}</dt>
          <dd>{t.value}</dd>
          {t.note ? <div className="tile-note">{t.note}</div> : null}
        </div>
      ))}
    </dl>
  )
}

export function CopyLink({ path, label = 'Buyer link', open = 'Open buyer page', compact, stacked }: { path: string; label?: string; open?: string; compact?: boolean; stacked?: boolean }) {
  const url = `${location.origin}${path}`
  const input = useRef<HTMLInputElement>(null)
  const [copied, setCopied] = useState(false)
  useEffect(() => {
    if (!copied) return
    const t = setTimeout(() => setCopied(false), 2000)
    return () => clearTimeout(t)
  }, [copied])
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(url)
      setCopied(true)
    } catch {
      input.current?.focus()
      input.current?.select()
    }
  }
  return (
    <div className={`linkbox ${compact ? 'compact' : ''} ${stacked ? 'stacked' : ''}`}>
      <input ref={input} className="ctl code" readOnly value={url} aria-label={label} onFocus={(e) => e.currentTarget.select()} />
      <button type="button" className="btn quiet" onClick={copy} aria-live="polite">
        {copied ? 'Copied' : 'Copy link'}
      </button>
      {compact ? null : (
        <a className="btn quiet" href={path} target="_blank" rel="noreferrer">
          {open}
        </a>
      )}
    </div>
  )
}

// ---------------- forms ----------------

export type Errors = Record<string, string | undefined>
export const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/
export const need = (v: string, message: string) => (v.trim() ? undefined : message)
export const emailError = (v: string) => (!v.trim() ? 'Enter an email address.' : EMAIL.test(v.trim()) ? undefined : 'Enter a valid email address, like name@company.com.')

export function useForm<T extends Record<string, string>>(prefix: string, initial: T) {
  const [values, setValues] = useState<T>(initial)
  const [errors, setErrors] = useState<Errors>({})
  const put = (name: string, value: string) => {
    setValues((x) => ({ ...x, [name]: value }))
    setErrors((x) => (x[name] ? { ...x, [name]: undefined } : x))
  }
  /** Shows the errors and moves focus to the first one. True when there are none. */
  const check = (errs: Errors) => {
    setErrors(errs)
    const first = Object.keys(errs).find((k) => errs[k])
    if (first) document.getElementById(`${prefix}-${first}`)?.focus()
    return !first
  }
  const field = (name: string, hint?: boolean) => {
    const id = `${prefix}-${name}`
    return {
      id,
      name,
      value: values[name] ?? '',
      onChange: (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) => put(name, e.target.value),
      'aria-invalid': errors[name] ? true : undefined,
      'aria-describedby': errors[name] ? `${id}-err` : hint ? `${id}-hint` : undefined,
    }
  }
  return { prefix, values, errors, put, check, field }
}
/** What the field components need from a form. */
export type Form = { prefix: string; errors: Errors; field: (name: string, hint?: boolean) => Any }

export function Field({ f, name, label, hint, className, children }: { f: Form; name: string; label: React.ReactNode; hint?: React.ReactNode; className?: string; children: React.ReactNode }) {
  const id = `${f.prefix}-${name}`
  const err = f.errors[name]
  return (
    <div className={`fld ${className ?? ''}`}>
      <label htmlFor={id}>{label}</label>
      {children}
      {err ? (
        <div className="err" id={`${id}-err`}>
          {err}
        </div>
      ) : hint ? (
        <div className="hint" id={`${id}-hint`}>
          {hint}
        </div>
      ) : null}
    </div>
  )
}

export type TextProps = { f: Form; name: string; label: React.ReactNode; hint?: React.ReactNode; className?: string } & React.InputHTMLAttributes<HTMLInputElement>
export function TextField({ f, name, label, hint, className, ...rest }: TextProps) {
  return (
    <Field f={f} name={name} label={label} hint={hint} className={className}>
      <input className="ctl" type="text" {...rest} {...f.field(name, !!hint)} />
    </Field>
  )
}

export function CountryField({ f, name, label, hint, className }: { f: Form; name: string; label: string; hint?: React.ReactNode; className?: string }) {
  return (
    <Field f={f} name={name} label={label} hint={hint} className={className}>
      <select className="ctl" autoComplete="country" {...f.field(name, !!hint)}>
        <option value="">Choose a country</option>
        {COUNTRIES.map(([code, n]) => (
          <option key={code} value={code}>
            {n}
          </option>
        ))}
      </select>
    </Field>
  )
}

// ---------------- wallet transactions ----------------

export type TxStep = { key: 'approve' | 'fund' | 'drip' | 'claim'; amount?: string; state: 'idle' | TxStage | 'done' | 'failed'; hash?: string }
export type Plan = { key: TxStep['key']; amount?: string; call: Call; reverted: string }

export function stepText(s: TxStep): string {
  const a = s.amount ?? ''
  const text: Record<TxStep['key'], Record<TxStep['state'], string>> = {
    approve: { idle: 'Approve USDC', sign: 'Approve in your wallet', pending: 'Approving USDC', done: 'USDC approved', failed: 'USDC not approved' },
    fund: { idle: `Fund ${a}`, sign: 'Confirm funding in your wallet', pending: 'Funding', done: `Funded ${a}`, failed: 'Not funded' },
    drip: { idle: 'Get USDC', sign: 'Confirm in your wallet', pending: 'Getting USDC', done: 'USDC added to your wallet', failed: 'No USDC added' },
    claim: { idle: `Claim ${a}`, sign: 'Confirm the claim in your wallet', pending: 'Claiming', done: `Claimed ${a}`, failed: 'Not claimed' },
  }
  return text[s.key][s.state]
}

/** Runs wallet transactions one after another, keeping each one's state and hash for display. */
export function useTxFlow(session: Session, live: Live) {
  const [steps, setSteps] = useState<TxStep[]>([])
  const [error, setError] = useState('')
  const [running, setRunning] = useState(false)
  const run = async (plan: Plan[]) => {
    const w = session.wallet
    if (!w || !live.config) return false
    setError('')
    setRunning(true)
    setSteps(plan.map((p) => ({ key: p.key, amount: p.amount, state: 'idle' })))
    const patch = (i: number, s: Partial<TxStep>) => setSteps((xs) => xs.map((x, j) => (j === i ? { ...x, ...s } : x)))
    let i = 0
    try {
      for (; i < plan.length; i++) {
        const at = i
        const hash = await sendTx(w, live.config, plan[at].call, {
          reverted: plan[at].reverted,
          onStage: (stage, h) => patch(at, { state: stage, hash: h }),
        })
        patch(at, { state: 'done', hash })
      }
      return true
    } catch (e) {
      patch(i, { state: 'failed' })
      setError((e as Error).message)
      return false
    } finally {
      setRunning(false)
      void live.refresh()
    }
  }
  const current = steps.find((s) => s.state === 'sign' || s.state === 'pending')
  const reset = () => {
    setSteps([])
    setError('')
  }
  return { steps, error, running, current, run, reset }
}
export type TxFlow = ReturnType<typeof useTxFlow>

export function TxSteps({ flow, live }: { flow: TxFlow; live: Live }) {
  if (!flow.steps.length) return null
  return (
    <ul className="progress-list" aria-live="polite">
      {flow.steps.map((s, i) => (
        <li key={i} className={s.state === 'done' ? 'done' : s.state === 'failed' ? 'fail' : s.state === 'idle' ? '' : 'now'}>
          <span>{stepText(s)}</span>
          {s.hash ? <Tx h={s.hash} live={live} /> : null}
        </li>
      ))}
    </ul>
  )
}

/** What connecting means here, in words: the investor's own browser wallet, or a built-in one Tradeflow signs for. */
export function walletIntro(live: Live, purpose: 'fund' | 'claim'): string {
  const kind = walletKind(live.config ?? {})
  if (purpose === 'claim')
    return kind === 'builtin' ? "Connect this browser's wallet to claim your share." : 'Connect the wallet you invested from to claim your share.'
  return kind === 'builtin'
    ? 'No browser wallet is available here, so Tradeflow gives this browser its own wallet and signs its transactions for you. Its key stays with Tradeflow.'
    : 'Invest from your own wallet. You approve each transaction in your wallet.'
}

export function ConnectWallet({ session, live }: { session: Session; live: Live }) {
  const [busy, setBusy] = useState('')
  const [error, setError] = useState('')
  const builtin = walletKind(live.config ?? {}) === 'builtin'
  const saved = builtin ? savedBuiltin() : null
  const go = async (fresh: boolean) => {
    setBusy(fresh ? 'new' : 'connect')
    setError('')
    try {
      await session.connect(fresh)
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy('')
    }
  }
  return (
    <div className="stack" style={{ gap: 8 }}>
      <button className="btn primary block" disabled={!!busy} onClick={() => go(false)}>
        {busy === 'connect' ? 'Connecting…' : builtin && !saved ? 'Create a wallet' : 'Connect wallet'}
      </button>
      {saved ? (
        <div className="row small" style={{ justifyContent: 'space-between' }}>
          <span className="muted">
            This browser's wallet: <span className="code">{short(saved.address)}</span>
          </span>
          <button className="linkish" disabled={!!busy} onClick={() => go(true)}>
            {busy === 'new' ? 'Creating…' : 'Create a new wallet'}
          </button>
        </div>
      ) : null}
      {error ? (
        <div className="say bad small" role="alert">
          {error}
        </div>
      ) : null}
    </div>
  )
}

/** A header chip that opens a small menu; closes on an outside click or Escape. */
function useMenu() {
  const [open, setOpen] = useState(false)
  const box = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (!open) return
    const down = (e: MouseEvent) => {
      if (!box.current?.contains(e.target as Node)) setOpen(false)
    }
    const key = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false)
    }
    document.addEventListener('mousedown', down)
    document.addEventListener('keydown', key)
    return () => {
      document.removeEventListener('mousedown', down)
      document.removeEventListener('keydown', key)
    }
  }, [open])
  return { open, setOpen, box }
}

export function WalletChip({ session }: { session: Session }) {
  const m = useMenu()
  const w = session.wallet
  if (!w) return null
  return (
    <div className="menu-wrap" ref={m.box}>
      <button className="chip" aria-haspopup="menu" aria-expanded={m.open} onClick={() => m.setOpen((o) => !o)}>
        <span className={`pip ${session.wrongChain ? 'alert' : ''}`} aria-hidden="true" />
        <span className="code">{short(w.address)}</span>
        <span className="vh">wallet menu</span>
      </button>
      {m.open ? (
        <div className="menu" role="menu">
          <div className="menu-note">
            {w.kind === 'builtin' ? "This browser's wallet. Tradeflow signs its transactions." : session.wrongChain ? 'Your wallet is on another network' : 'Browser wallet'}
            <span className="code">{w.address}</span>
          </div>
          {session.wrongChain ? (
            <button
              role="menuitem"
              onClick={() => {
                m.setOpen(false)
                void session.fixChain().catch(() => {})
              }}
            >
              Switch to Sepolia
            </button>
          ) : null}
          <button
            role="menuitem"
            onClick={() => {
              m.setOpen(false)
              session.disconnect()
            }}
          >
            Disconnect
          </button>
        </div>
      ) : null}
    </div>
  )
}

const initials = (name: string) =>
  name
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((w) => w[0]!.toUpperCase())
    .join('')

/**
 * The signed-in name in the header, with Sign out (which ends only this portal's session). It shows as
 * soon as the portal has a session, before the account has loaded (or when loading it fails), so Sign
 * out is always there.
 */
export function NameMenu({ name, detail, onSignOut }: { name?: string; detail?: string; onSignOut: () => void }) {
  const m = useMenu()
  const label = name || 'Your account'
  return (
    <div className="menu-wrap" ref={m.box}>
      <button className="chip person" aria-haspopup="menu" aria-expanded={m.open} onClick={() => m.setOpen((o) => !o)}>
        <span className="avatar" aria-hidden="true">
          {name ? (
            initials(name) || '?'
          ) : (
            <svg width="14" height="14" viewBox="0 0 14 14">
              <circle cx="7" cy="4.5" r="2.6" fill="currentColor" />
              <path d="M2 13c0-2.9 2.2-4.8 5-4.8s5 1.9 5 4.8" fill="currentColor" />
            </svg>
          )}
        </span>
        <span className="nm">{label}</span>
        <span className="vh">account menu</span>
      </button>
      {m.open ? (
        <div className="menu" role="menu">
          <div className="menu-note">
            {name ? (
              <>
                Signed in as
                <span className="strong">{name}</span>
                {detail ? <span>{detail}</span> : null}
              </>
            ) : (
              <>
                Signed in to your
                <span className="strong">{detail ? sentence(detail) : 'Account'}</span>
              </>
            )}
          </div>
          <button
            role="menuitem"
            onClick={() => {
              m.setOpen(false)
              onSignOut()
            }}
          >
            Sign out
          </button>
        </div>
      ) : null}
    </div>
  )
}

// ---------------- activity ----------------

export const RUN_NAME: Record<string, string> = {
  'verify-and-list': 'Document review',
  'verify-lender': 'Investor verification',
  'credit-fiat-deposit': 'Deposit verification',
  'disburse-on-funded': 'Payout to business',
  'confirm-repayment': 'Repayment confirmation',
  'redeem-fiat-lenders': 'Payout to investors',
  'watch-and-reconcile': 'Risk and reserve check',
}

export function runSummary(run: Any, live: Live): string | null {
  const d = run.resultData
  if (run.status === 'failed') {
    const err = [...(run.logs ?? [])].reverse().find((l: string) => /error|rejected|failed/i.test(l) && !/Simulation/i.test(l))
    const text = err ? err.replace(/^.*?(Error:|error:)\s*/i, '').slice(0, 160) : ''
    return text && !/workflow|simulat|chainlink|\bcre\b/i.test(text) ? text : 'Did not complete'
  }
  if (!d) return run.status === 'running' ? 'In progress' : run.status === 'queued' ? 'Waiting to start' : null
  switch (run.handler) {
    case 'verify-and-list':
      if (!d.listed) return `Not approved: ${d.reason}`
      return `Approved ${d.docNumber}: grade ${d.grade}, ${pct(d.aprBps)} APR, ${usd(d.target)} advance${d.currency === 'USD' ? '' : ` at ${d.currency}/USD ${rate(d.fxRateE8)}`}`
    case 'verify-lender': {
      const name = lenderById(live, d.lenderId)?.name ?? d.lenderId
      return d.verified ? `${name} verified` : `${name} not verified (${d.status})`
    }
    case 'credit-fiat-deposit':
      return `${fiatText(d.fiat)} received, ${usd(d.stablecoins, 2)} credited at ${rate(d.providerRate)} (reference ${rate(d.chainlinkRate)})`
    case 'disburse-on-funded':
      return d.disbursed ? `${usd(d.amount)} paid to the business, ${d.payoutRef}` : `Skipped: ${d.reason}`
    case 'confirm-repayment': {
      const paid = d.paid ? money(d.paid.amountMinor, d.paid.currency, 2) : usd(d.amount, 2)
      const balance = BigInt(d.balance ?? 0) > 0n ? `, ${usd(d.balance, 2)} balance to the business` : ''
      return `${paid} from ${d.payer}, matched at the bank and the payment processor: ${usd(d.amount, 2)} to investors${balance}`
    }
    case 'redeem-fiat-lenders':
      return d.redeemed?.length
        ? d.redeemed.map((r: Any) => `${lenderById(live, r.lender)?.name ?? lenderFor(live, r.lender)?.name ?? r.lender} paid ${usd(r.payout, 2)}`).join(', ')
        : 'No bank-transfer investors on this loan'
    case 'watch-and-reconcile': {
      const changes = (d.statusChanges ?? []).map((c: Any) => `loan ${c.loanId} ${c.status}${c.tokenPaused ? ` (${noteSymbol(c.loanId)} paused)` : ''}`).join(', ')
      return `${d.reconciliation?.ok ? 'Reserves match' : 'Reserve mismatch, funding paused'}${changes ? `; ${changes}, business frozen` : ''}`
    }
  }
  return null
}

/** Dot colour reflects the outcome, not just that the run finished. */
export function runTone(run: Any): string {
  if (run.status !== 'success') return run.status
  const d = run.resultData ?? {}
  if (run.handler === 'watch-and-reconcile') return d.reconciliation?.ok === false ? 'bad' : d.statusChanges?.length ? 'warn' : 'success'
  if (run.handler === 'verify-and-list' && d.listed === false) return 'warn'
  if (run.handler === 'verify-lender' && d.verified === false) return 'warn'
  return 'success'
}

export const fiatText = (s: string) => {
  const m = /^(\d+(?:\.\d+)?) (EUR|USD)$/.exec(s ?? '')
  return m ? money(Math.round(Number(m[1]) * 100), m[2]) : s
}

/** The run's own step log lines (tool chatter dropped), with the time they were logged. */
export function userLines(run: Any): { at: string; text: string }[] {
  return (run.logs ?? []).flatMap((l: string) => {
    const i = l.indexOf('[USER LOG]')
    if (i < 0) return []
    // The CLI stamps each line with the server's wall clock time (its "Z" suffix does not mean UTC), so show it as printed.
    const at = /T(\d{2}:\d{2}:\d{2})/.exec(l.slice(0, i))?.[1] ?? ''
    const text = l
      .slice(i + 10)
      .trim()
      .replace(/^report delivered: action=\d+ tx=/, 'recorded onchain, transaction ')
      .replace(/0x[0-9a-fA-F]{64}/g, (h) => short(h))
    return [{ at, text }]
  })
}

/** Streams the step log while the run is in flight, then shows the result. Follows the tail unless scrolled up. */
export function RunLog({ run }: { run: Any }) {
  const box = useRef<HTMLDivElement>(null)
  const stick = useRef(true)
  const lines = userLines(run)
  const active = isActive(run)
  const result = run.resultData ? JSON.stringify(run.resultData, null, 2).replace(/"chainlink(\w*)"/gi, '"reference$1"') : ''
  useEffect(() => {
    const el = box.current
    if (el && stick.current) el.scrollTop = el.scrollHeight
  }, [lines.length, active, result])
  if (!active && !lines.length && !result) return null
  return (
    <div
      ref={box}
      className="log"
      onScroll={(e) => {
        const el = e.currentTarget
        stick.current = el.scrollHeight - el.scrollTop - el.clientHeight < 24
      }}
    >
      {lines.map((l, i) => (
        <div key={i}>
          {l.at ? <span className="t">{l.at}</span> : null}
          {l.text}
        </div>
      ))}
      {active ? <div className="live">{run.status === 'queued' ? 'Waiting to start' : 'Running'}</div> : null}
      {result ? <div className="result">{result}</div> : null}
    </div>
  )
}

export function Activity({ runs, live, empty }: { runs: Any[]; live: Live; empty: string }) {
  if (runs.length === 0) return <div className="empty">{empty}</div>
  return (
    <div className="activity">
      {runs.map((run) => {
        const summary = runSummary(run, live)
        const tx = run.resultData?.tx ?? run.resultData?.reconciliation?.tx ?? run.resultData?.redeemed?.[0]?.tx
        return (
          <details
            key={run.id}
            className="event"
            onToggle={(e) => {
              // A run in progress opens at its newest line; a finished one opens at its first step.
              const log = e.currentTarget.querySelector('.log')
              if (log && e.currentTarget.open) log.scrollTop = isActive(run) ? log.scrollHeight : 0
            }}
          >
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
            <RunLog run={run} />
          </details>
        )
      })}
    </div>
  )
}
