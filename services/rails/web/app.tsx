import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { formatUnits, parseUnits } from 'viem'
import { calls, type Call } from './abi'
import {
  connect as connectWallet,
  disconnect as forgetWallet,
  proveWallet,
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
const COUNTRIES: [string, string][] = (
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
const COUNTRY: Record<string, string> = Object.fromEntries(COUNTRIES)
const PORT: Record<string, string> = { ...COUNTRY, AE: 'UAE' }
const countryName = (c?: string) => (c ? (COUNTRY[c] ?? c) : '')

const DOC_TYPES = [
  { value: 'invoice', label: 'Invoice', noun: 'invoice', prefix: 'Invoice advance: ' },
  { value: 'bill_of_lading', label: 'Bill of lading', noun: 'bill of lading', prefix: 'Supply chain finance: ' },
  { value: 'equipment', label: 'Equipment order', noun: 'equipment order', prefix: 'Equipment finance: ' },
]
const docType = (t?: string) => DOC_TYPES.find((d) => d.value === t) ?? DOC_TYPES[0]

const usd = (v: string | number | bigint | undefined, digits = 0) =>
  (Number(BigInt(v ?? 0)) / 1e6).toLocaleString('en-US', { style: 'currency', currency: 'USD', minimumFractionDigits: digits, maximumFractionDigits: digits })
/** USDC to the cent, or to the last digit when an amount has fractions of a cent (so labels match what is sent). */
const usdExact = (v: bigint) =>
  (Number(v) / 1e6).toLocaleString('en-US', { style: 'currency', currency: 'USD', minimumFractionDigits: 2, maximumFractionDigits: v % 10_000n === 0n ? 2 : 6 })
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
/** Dates arrive as 'YYYY-MM-DD', ISO timestamps or unix seconds (onchain). */
const fmtDate = (v?: string | number) => {
  const s = String(v ?? '')
  if (!s || s === '0') return ''
  const dateOnly = /^\d{4}-\d{2}-\d{2}$/.test(s)
  const d = /^\d+$/.test(s) ? new Date(Number(s) * (Number(s) < 1e12 ? 1000 : 1)) : new Date(s)
  if (Number.isNaN(d.getTime())) return s
  return d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', ...(dateOnly ? { timeZone: 'UTC' } : {}) })
}
const sentence = (s?: string) => (s ? s.charAt(0).toUpperCase() + s.slice(1) : '')
const last4 = (s?: string) => String(s ?? '').replace(/\s/g, '').slice(-4)
const fileSize = (n: number) => (n < 1024 * 1024 ? `${Math.max(1, Math.round(n / 1024))} KB` : `${(n / 1048576).toFixed(1)} MB`)
/** Keeps digits and a single decimal point, with at most `places` decimals. */
const decimal = (v: string, places: number) => {
  const s = v.replace(/[^0-9.]/g, '')
  const i = s.indexOf('.')
  return i < 0 ? s : `${s.slice(0, i)}.${s.slice(i + 1).replace(/\./g, '').slice(0, places)}`
}
const toUsd6 = (v: string): bigint | null => {
  try {
    const n = parseUnits(v || '0', 6)
    return n > 0n ? n : null
  } catch {
    return null
  }
}
const isoDay = (d: Date) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`
const addDays = (iso: string, n: number) => {
  const d = new Date(`${iso}T00:00:00`)
  d.setDate(d.getDate() + n)
  return isoDay(d)
}
const daysBetween = (a: string, b: string) => Math.round((new Date(`${b}T00:00:00`).getTime() - new Date(`${a}T00:00:00`).getTime()) / 86_400_000)

type ApiError = Error & { status?: number }
async function request<T = Any>(path: string, body?: unknown, headers: Record<string, string> = {}): Promise<{ status: number; data: T }> {
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
const api = async <T = Any,>(path: string, body?: unknown, headers?: Record<string, string>): Promise<T> => (await request<T>(path, body, headers)).data

// ---------------------------------------------------------------------------
// Sessions (per viewer, in this browser only)
// ---------------------------------------------------------------------------

const KEY = { business: 'tradeflow.business', lender: 'tradeflow.lender', wallet: 'tradeflow.wallet' }
const stored = {
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

function useStored(key: string) {
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

/** A signed-in business: its id and the key the server issued to this browser. */
type BizSession = { id: string; key: string }
const parseBusiness = (raw: string | null): BizSession | null => {
  try {
    const b = raw ? JSON.parse(raw) : null
    return b && typeof b.id === 'string' && typeof b.key === 'string' ? { id: b.id, key: b.key } : null
  } catch {
    return null
  }
}
const bizHeaders = (b: BizSession) => ({ 'x-business-key': b.key })

const parseWallet = (raw: string | null): WalletSession | null => {
  try {
    const w = raw ? JSON.parse(raw) : null
    return w && /^0x[0-9a-fA-F]{40}$/.test(w.address) && (w.kind === 'injected' || w.kind === 'builtin') ? w : null
  } catch {
    return null
  }
}

function useSession(config: Any) {
  const [businessRaw, setBusinessRaw] = useStored(KEY.business)
  const business = useMemo(() => parseBusiness(businessRaw), [businessRaw])
  const setBusiness = useCallback((b: BizSession | null) => setBusinessRaw(b ? JSON.stringify({ id: b.id, key: b.key }) : null), [setBusinessRaw])
  const [lender, setLender] = useStored(KEY.lender)
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

  return { business, setBusiness, lender, setLender, wallet, wrongChain, connect, disconnect, fixChain }
}
type Session = ReturnType<typeof useSession>

// ---------------------------------------------------------------------------
// Live data
// ---------------------------------------------------------------------------

function useLive() {
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
type Live = ReturnType<typeof useLive>

const sameAddr = (a?: string | null, b?: string | null) => !!a && !!b && a.toLowerCase() === b.toLowerCase()
const bizFor = (live: Live, wallet: string) => (live.state?.businesses ?? []).find((b: Any) => sameAddr(b.wallet, wallet))
const lenderFor = (live: Live, wallet?: string) => (live.state?.lenders ?? []).find((l: Any) => sameAddr(l.wallet, wallet))
const lenderById = (live: Live, id?: string | null) => (id ? (live.state?.lenders ?? []).find((l: Any) => l.id === id) : undefined)
/** The registry record behind a loan (document numbers are unique per business). */
const docFor = (live: Live, loan: Any) => {
  const docs = (live.state?.documents ?? []).filter((d: Any) => d.number === loan.ref)
  if (docs.length < 2) return docs[0]
  const biz = bizFor(live, loan.borrower)
  return docs.find((d: Any) => d.businessId === biz?.id) ?? docs[0]
}
const dueOf = (loan: Any) => BigInt(loan.target) + (BigInt(loan.target) * BigInt(loan.aprBps) * BigInt(loan.tenorDays)) / (10_000n * 365n)
const runInput = (run: Any): Any => {
  try {
    return JSON.parse(run.input) ?? {}
  } catch {
    return {}
  }
}
const isActive = (run?: Any) => run?.status === 'running' || run?.status === 'queued'
const kycRunFor = (live: Live, lenderId: string) => live.runs.find((r) => r.handler === 'verify-lender' && runInput(r).lenderId === lenderId)
const contractsOf = (live: Live) => {
  const d = live.config?.deployment
  return d?.market && d?.stablecoin ? { market: d.market, stablecoin: d.stablecoin } : null
}

/** Balance, allowance, verification and loan notes (per-loan ERC-3643 token balances) for any address, refreshed as the market moves. */
function useAccount(address: string | undefined, live: Live) {
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
type Account = ReturnType<typeof useAccount>

/** A business's own view (signed in): its profile and documents, including the buyer links. */
function useBusinessView(session: BizSession | null, live: Live) {
  const [data, setData] = useState<Any>(null)
  const [missing, setMissing] = useState(false)
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
      }
    } catch (e) {
      const status = (e as ApiError).status
      if ((status === 404 || status === 401) && current.current === id) setMissing(true)
    }
  }, [id, key])
  useEffect(() => {
    setData(null)
    setMissing(false)
  }, [id])
  useEffect(() => {
    void load()
  }, [load, live.state])
  return { data: data?.business?.id === id ? data : null, missing, reload: load }
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

/** A contract address, linked to the block explorer when there is one. */
function Addr({ a, live, children }: { a?: string; live: Live; children?: React.ReactNode }) {
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
const noteSymbol = (loanId: number | string) => `TFN${loanId}`
const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000'

function Status({ s }: { s: number }) {
  const st = STATUS[s]
  return st ? <span className={`tag ${st.tone}`}>{st.label}</span> : null
}

function Lane({ from, to, progress, status }: { from?: string; to?: string; progress: number; status: number }) {
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
type ReqState = { label: string; tone: 'info' | 'good' | 'warn' | 'bad'; reason?: string; next?: string; retry?: boolean; loanId?: number }
function StateText({ s }: { s: ReqState }) {
  return <span className={`state ${s.tone}`}>{s.label}</span>
}

function Wordmark({ go }: { go?: Go }) {
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

function Footer() {
  return (
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
  )
}

function CopyLink({ path, label = 'Buyer link', open = 'Open buyer link', compact, stacked }: { path: string; label?: string; open?: string; compact?: boolean; stacked?: boolean }) {
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

type Errors = Record<string, string | undefined>
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/
const need = (v: string, message: string) => (v.trim() ? undefined : message)
const emailError = (v: string) => (!v.trim() ? 'Enter an email address.' : EMAIL.test(v.trim()) ? undefined : 'Enter a valid email address, like name@company.com.')

function useForm<T extends Record<string, string>>(prefix: string, initial: T) {
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
type Form = { prefix: string; errors: Errors; field: (name: string, hint?: boolean) => Any }

function Field({ f, name, label, hint, className, children }: { f: Form; name: string; label: React.ReactNode; hint?: React.ReactNode; className?: string; children: React.ReactNode }) {
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

type TextProps = { f: Form; name: string; label: React.ReactNode; hint?: React.ReactNode; className?: string } & React.InputHTMLAttributes<HTMLInputElement>
function TextField({ f, name, label, hint, className, ...rest }: TextProps) {
  return (
    <Field f={f} name={name} label={label} hint={hint} className={className}>
      <input className="ctl" type="text" {...rest} {...f.field(name, !!hint)} />
    </Field>
  )
}

function CountryField({ f, name, label, hint, className }: { f: Form; name: string; label: string; hint?: React.ReactNode; className?: string }) {
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

type TxStep = { key: 'approve' | 'fund' | 'drip' | 'claim'; amount?: string; state: 'idle' | TxStage | 'done' | 'failed'; hash?: string }
type Plan = { key: TxStep['key']; amount?: string; call: Call; reverted: string }

function stepText(s: TxStep): string {
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
function useTxFlow(session: Session, live: Live) {
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
type TxFlow = ReturnType<typeof useTxFlow>

function TxSteps({ flow, live }: { flow: TxFlow; live: Live }) {
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

/** What connecting means here, in words: the lender's own browser wallet, or a built-in one Tradeflow signs for. */
function walletIntro(live: Live, purpose: 'fund' | 'claim'): string {
  const kind = walletKind(live.config ?? {})
  if (purpose === 'claim')
    return kind === 'builtin'
      ? 'Lent in USDC from this browser? Connect its wallet to claim your share.'
      : 'Lent in USDC? Connect the wallet you funded from to claim your share.'
  return kind === 'builtin'
    ? 'No browser wallet is available here, so Tradeflow gives this browser its own wallet and signs its transactions for you. Its key stays with Tradeflow.'
    : 'Fund from your own wallet. You approve each transaction in your wallet.'
}

function ConnectWallet({ session, live }: { session: Session; live: Live }) {
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

function WalletChip({ session }: { session: Session }) {
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
  const w = session.wallet
  if (!w) return null
  return (
    <div className="wallet" ref={box}>
      <button className="chip" aria-haspopup="menu" aria-expanded={open} onClick={() => setOpen((o) => !o)}>
        <span className={`pip ${session.wrongChain ? 'alert' : ''}`} aria-hidden="true" />
        <span className="code">{short(w.address)}</span>
        <span className="vh">wallet menu</span>
      </button>
      {open ? (
        <div className="menu" role="menu">
          <div className="menu-note">
            {w.kind === 'builtin' ? "This browser's wallet. Tradeflow signs its transactions." : session.wrongChain ? 'Your wallet is on another network' : 'Browser wallet'}
            <span className="code">{w.address}</span>
          </div>
          {session.wrongChain ? (
            <button
              role="menuitem"
              onClick={() => {
                setOpen(false)
                void session.fixChain().catch(() => {})
              }}
            >
              Switch to Sepolia
            </button>
          ) : null}
          <button
            role="menuitem"
            onClick={() => {
              setOpen(false)
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

// ---------------- activity ----------------

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
      return `${paid} from ${d.payer}, matched at the bank and the payment processor: ${usd(d.amount, 2)} to lenders${balance}`
    }
    case 'redeem-fiat-lenders':
      return d.redeemed?.length
        ? d.redeemed.map((r: Any) => `${lenderById(live, r.lender)?.name ?? lenderFor(live, r.lender)?.name ?? r.lender} paid ${usd(r.payout, 2)}`).join(', ')
        : 'No bank-transfer lenders on this loan'
    case 'watch-and-reconcile': {
      const changes = (d.statusChanges ?? []).map((c: Any) => `loan ${c.loanId} ${c.status}${c.tokenPaused ? ` (${noteSymbol(c.loanId)} paused)` : ''}`).join(', ')
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

/** The run's own step log lines (tool chatter dropped), with the time they were logged. */
function userLines(run: Any): { at: string; text: string }[] {
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
function RunLog({ run }: { run: Any }) {
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

function Activity({ runs, live, empty }: { runs: Any[]; live: Live; empty: string }) {
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

// ---------------------------------------------------------------------------
// Marketplace
// ---------------------------------------------------------------------------

function LoanCard({ loan, live, go }: { loan: Any; live: Live; go: Go }) {
  const doc = docFor(live, loan)
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
// Loan page: lender sign-up and identity check
// ---------------------------------------------------------------------------

function LenderSignup({ funding, wallet, live, onDone }: { funding: 'fiat' | 'stablecoin'; wallet?: WalletSession | null; live: Live; onDone: (lender: Any) => void }) {
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
      // A USDC lender proves the connected wallet is theirs before it is tied to their identity.
      const proof = !fiat && wallet ? await proveWallet(wallet, () => setBusy('sign')) : { body: {}, headers: {} }
      setBusy('verify')
      const body = {
        name: v.name.trim(),
        email: v.email.trim(),
        country: v.country,
        funding,
        ...(fiat ? { bankAccount: v.bankAccount.trim() } : { wallet: wallet?.address, ...proof.body }),
      }
      const { lender } = await api('/api/lenders', body, proof.headers)
      if (lender.funding !== funding) {
        setError(
          fiat
            ? 'This email is registered to lend in USDC. Use the USDC tab, or sign up with a different email.'
            : 'This email is registered to lend by bank transfer. Use the Bank transfer tab, or sign up with a different email.',
        )
        return
      }
      if (!fiat && !sameAddr(lender.wallet, wallet?.address)) {
        setError(`This email is registered with wallet ${short(lender.wallet)}. Connect that wallet, or sign up with a different email.`)
        return
      }
      onDone(lender)
      await live.refresh()
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
          ? 'Lend from your bank account. We verify your identity once, before your first transfer.'
          : wallet?.kind === 'injected'
            ? `Lending from wallet ${short(wallet?.address)}. Your wallet asks you to sign a message that proves it is yours, then we verify your identity once, before you fund.`
            : `Lending from this browser's wallet ${short(wallet?.address)}. We verify your identity once, before you fund.`}
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
          hint="When the buyer pays, your share is paid to this account."
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
        {busy === 'sign' ? 'Sign the message in your wallet…' : busy ? 'Verifying your identity…' : 'Verify identity to lend'}
      </button>
    </form>
  )
}

function KycProgress({ lender, live, notify, declinedHint }: { lender: Any; live: Live; notify: Notify; declinedHint: string }) {
  const { busy, run } = useAction(live, notify)
  const kycRun = kycRunFor(live, lender.id)
  const declined = lender.kycStatus === 'rejected' || kycRun?.resultData?.verified === false
  const checking = isActive(kycRun) || busy === 'kyc'
  const failed = !checking && kycRun?.status === 'failed'
  if (declined)
    return (
      <div className="say bad small" role="alert">
        {kycRun?.resultData?.status === 'unsupported country'
          ? 'We cannot accept lenders resident in this country yet, so this account cannot lend.'
          : 'We could not verify this identity, so this account cannot lend.'}{' '}
        {declinedHint}
      </div>
    )
  return (
    <div className="stack">
      <ul className="progress-list" aria-live="polite">
        <li className="done">Details received</li>
        <li className={checking ? 'now' : failed ? 'fail' : ''}>{checking ? 'Checking your identity' : 'Identity check'}</li>
        <li>Approved to lend</li>
      </ul>
      {failed ? <div className="say bad small">The identity check did not finish. Try again.</div> : null}
      <button className="btn primary block" disabled={checking} onClick={() => run('kyc', () => api(`/api/lenders/${lender.id}/kyc`, {}))}>
        {checking ? 'Verifying your identity…' : 'Verify identity to lend'}
      </button>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Loan page: bank transfer
// ---------------------------------------------------------------------------

const ACCOUNT: Record<string, string> = { EUR: 'DE89 3704 0044 0532 0130 00', USD: 'US-ACH 021000021 / 9988776655' }

function BankTransfer({ loan, live, notify, session }: { loan: Any; live: Live; notify: Notify; session: Session }) {
  const lender = lenderById(live, session.lender)
  const fiat = lender?.funding === 'fiat' ? lender : undefined
  const account = useAccount(fiat?.wallet, live)
  if (!fiat) return <LenderSignup funding="fiat" live={live} onDone={(l) => session.setLender(l.id)} />
  const kycRun = kycRunFor(live, fiat.id)
  const verified = account.info?.verified === true || kycRun?.resultData?.verified === true
  return (
    <div className="stack">
      <div className="who">
        <span>
          Lending as <b>{fiat.name}</b>
        </span>
        <button className="linkish" onClick={() => session.setLender(null)}>
          Switch account
        </button>
      </div>
      {verified ? (
        <Transfer loan={loan} live={live} notify={notify} lender={fiat} />
      ) : !account.info && !kycRun && !account.error ? (
        <div className="small muted">Checking your account…</div>
      ) : (
        <KycProgress lender={fiat} live={live} notify={notify} declinedHint="Switch to a different account to continue." />
      )}
    </div>
  )
}

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

// ---------------------------------------------------------------------------
// Loan page: USDC from a connected wallet
// ---------------------------------------------------------------------------

function UsdcFunding({ loan, live, notify, session, account }: { loan: Any; live: Live; notify: Notify; session: Session; account: Account }) {
  const w = session.wallet
  if (!w)
    return (
      <div className="stack">
        <div className="small muted">{walletIntro(live, 'fund')}</div>
        <ConnectWallet session={session} live={live} />
      </div>
    )
  const lender = lenderFor(live, w.address)
  if (!lender) return <LenderSignup funding="stablecoin" wallet={w} live={live} onDone={() => {}} />
  const kycRun = kycRunFor(live, lender.id)
  const verified = account.info?.verified === true || kycRun?.resultData?.verified === true
  return (
    <div className="stack">
      <div className="who">
        <span>
          Lending as <b>{lender.name}</b> from <span className="code">{short(w.address)}</span>
        </span>
      </div>
      {verified ? (
        <UsdcFund loan={loan} live={live} notify={notify} session={session} account={account} />
      ) : !account.info && !kycRun && !account.error ? (
        <div className="small muted">Checking your wallet…</div>
      ) : (
        <KycProgress lender={lender} live={live} notify={notify} declinedHint="Disconnect and use a different wallet to continue." />
      )}
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
      ? 'Enter how much USDC to lend.'
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

function ClaimPanel({ loan, live, session, account, notify }: { loan: Any; live: Live; session: Session; account: Account; notify: Notify }) {
  const flow = useTxFlow(session, live)
  const contracts = contractsOf(live)
  const held = BigInt(account.info?.notes?.[String(loan.id)] ?? 0)
  const claimable = held > 0n ? (held * BigInt(loan.repaidAmount)) / BigInt(loan.target) : 0n
  const claimed = flow.steps.some((s) => s.state === 'done')
  const claim = async () => {
    if (!contracts) return
    const label = usd(claimable, 2)
    const ok = await flow.run([
      { key: 'claim', amount: label, call: calls.claim(contracts, loan.id), reverted: 'The claim was reverted. This wallet may have claimed already. Refresh the page to check.' },
    ])
    if (ok) {
      notify(`Claimed ${label}`)
      await account.reload()
    }
  }
  if (!session.wallet)
    return (
      <>
        <div className="small muted">{walletIntro(live, 'claim')}</div>
        <ConnectWallet session={session} live={live} />
      </>
    )
  return (
    <>
      {claimable > 0n || flow.running ? (
        <button className="btn primary block" disabled={flow.running || !contracts} onClick={claim}>
          {flow.current ? `${stepText(flow.current)}…` : `Claim ${usd(claimable, 2)}`}
        </button>
      ) : !claimed && account.info ? (
        <div className="small muted">
          Wallet <span className="code">{short(session.wallet.address)}</span> has nothing to claim on this loan.
        </div>
      ) : null}
      <TxSteps flow={flow} live={live} />
      {flow.error ? (
        <div className="say bad small" role="alert">
          {flow.error}
        </div>
      ) : null}
    </>
  )
}

// ---------------------------------------------------------------------------
// Loan page
// ---------------------------------------------------------------------------

function LoanPage({ id, live, go, notify, session }: { id: number; live: Live; go: Go; notify: Notify; session: Session }) {
  const loan = live.state?.loans?.find((l: Any) => l.id === id)
  const [tab, setTab] = useState<'bank' | 'usdc'>(() => (session.wallet && !session.lender ? 'usdc' : 'bank'))
  const account = useAccount(session.wallet?.address, live)
  const biz = loan ? bizFor(live, loan.borrower) : undefined
  const mine = !!biz && biz.id === session.business?.id
  const owner = useBusinessView(mine ? session.business : null, live)
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

  const doc = docFor(live, loan)
  const ccy = ccyOf(loan.currency)
  const progress = Number((BigInt(loan.funded) * 1000n) / BigInt(loan.target || 1)) / 10
  const fundings = (live.state.fundings ?? []).filter((f: Any) => Number(f.loanId) === id)
  const loanRuns = live.runs.filter((r) => r.loanId === id || r.input.includes(loan.ref))
  const repayment = (live.state.bankCredits ?? []).find((c: Any) => c.kind === 'repayment' && c.reference.startsWith(`PAY-${id}-`))
  const payouts: Any[] = (live.state.payouts ?? []).filter((p: Any) => p.loanId === id)
  const disbursedPayout = payouts.find((p) => p.kind === 'business' && String(p.idempotencyKey).startsWith('disburse-'))
  const balancePayout = payouts.find((p) => p.kind === 'business' && String(p.idempotencyKey).startsWith('balance-'))
  const lenderPayouts = payouts.filter((p) => p.kind === 'lender')
  const buyerLink = owner.data?.documents?.find((d: Any) => d.number === loan.ref)?.buyerLink
  const buyer = doc?.buyer ?? 'the buyer'
  const noun = docType(doc?.type).noun
  const face = money(loan.faceValueMinor, ccy, 2)
  const owed = usd(dueOf(loan), 2)
  // Lateness comes from the onchain clock, so a late loan shows the maturity it missed.
  const dueText = loan.status >= 5 ? fmtDate(loan.maturity) : fmtDate(doc?.dueDate ?? loan.maturity)

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
          ? `${sentence(buyer)} paid the ${noun}. Lenders received ${usd(loan.repaidAmount, 2)}${balancePayout ? `, and ${biz?.name ?? 'the business'} the balance of ${usd(balancePayout.amount, 2)}` : ''}.`
          : loan.status >= 5
            ? `${sentence(buyer)} has not paid. ${biz?.name} cannot raise again until it is settled.`
            : `${sentence(buyer)} pays the ${noun}, ${face}, after ${days(loan.tenorDays)}. Lenders receive ${owed}, and the balance goes to ${biz?.name ?? 'the business'}.`,
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
            {biz?.name}, selling to {buyer}
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
                  <td>Grade {GRADE[loan.riskGrade]}. Reviewed privately: the business's financial data is never shown to lenders.</td>
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
                        One token for this loan, held only by lenders with a verified identity.
                        {loan.status >= 5 ? ' Transfers are paused until the loan is repaid.' : ''}
                      </div>
                    </td>
                  </tr>
                ) : null}
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
                <div className="say bad small">Funding is paused while a reserve check is reviewed.</div>
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
                  {tab === 'bank' ? (
                    <BankTransfer loan={loan} live={live} notify={notify} session={session} />
                  ) : (
                    <UsdcFunding loan={loan} live={live} notify={notify} session={session} account={account} />
                  )}
                </>
              )}
            </section>
          ) : null}

          {loan.status === 2 ? (
            <section className="panel panel-pad stack">
              <h2>Fully funded</h2>
              <div className="small muted">
                {usd(loan.target)} raised from {fundings.length === 1 ? '1 lender' : `${fundings.length} lenders`}. The advance is being paid to {biz?.name ?? 'the business'} now.
              </div>
              {BigInt(account.info?.notes?.[String(loan.id)] ?? 0) > 0n ? (
                <div className="say good small">
                  Wallet <span className="code">{short(session.wallet?.address)}</span> holds {usd(account.info.notes[String(loan.id)], 2)} of this loan in{' '}
                  {noteSymbol(loan.id)} notes.
                </div>
              ) : null}
            </section>
          ) : null}

          {loan.status === 3 || loan.status === 5 ? (
            <section className="panel panel-pad stack">
              <h2>Repayment</h2>
              {loan.status === 5 ? <div className="say bad small">Payment is overdue{dueText ? `. It was due on ${dueText}` : ''}.</div> : null}
              <div className="small muted">
                {sentence(buyer)} pays the {noun}, {face}
                {loan.status < 5 && dueText ? `, on ${dueText}` : ''}, through their payment link. Once the bank and the payment processor both confirm the payment, lenders receive {owed} and
                the balance goes to {biz?.name ?? 'the business'}.
              </div>
              {mine ? (
                buyerLink ? (
                  <div className="fld">
                    <span className="lbl">Buyer payment link</span>
                    <CopyLink path={buyerLink} label="Buyer payment link" open="Open payment page" stacked />
                    <div className="hint">Send this link to {buyer} so they can pay.</div>
                  </div>
                ) : (
                  <div className="small muted">Loading your buyer payment link…</div>
                )
              ) : null}
            </section>
          ) : null}

          {loan.status === 4 ? (
            <section className="panel panel-pad stack">
              <h2>Repaid</h2>
              <div className="small muted">
                {usd(loan.repaidAmount, 2)} repaid to lenders{repayment ? ` (${repayment.reference})` : ''}.
                {BigInt(loan.fiatFunded) === 0n
                  ? ''
                  : lenderPayouts.length
                    ? ' Bank-transfer lenders have been paid to their accounts.'
                    : ' Paying bank-transfer lenders to their accounts now.'}
              </div>
              <ClaimPanel loan={loan} live={live} session={session} account={account} notify={notify} />
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

const LOAN_STATE: Record<number, ReqState> = {
  1: { label: 'Listed', tone: 'info' },
  2: { label: 'Funded', tone: 'good' },
  3: { label: 'Paid out', tone: 'good' },
  4: { label: 'Repaid', tone: 'good' },
  5: { label: 'Late', tone: 'bad' },
  6: { label: 'Defaulted', tone: 'bad' },
}

/** What the business can do after a review said no, by the workflow's reason. */
function nextStep(reason: string, doc: Any): string {
  if (/disputed/.test(reason)) return `Talk to ${doc.buyer} about the reason they gave.`
  if (/credit grade/.test(reason)) return 'Your credit file is below what lenders can finance today. You can request financing for other documents once it improves.'
  if (/sanctions/.test(reason)) return 'Requests from this business cannot be financed.'
  if (/already financed/.test(reason)) return 'A document with this fingerprint has been financed before, so it cannot be financed again.'
  return ''
}

/** Where a business's request stands: the buyer's response, then the review (kept by the server), then the loan onchain. */
function requestState(doc: Any, live: Live, business: Any): ReqState {
  const loan = (live.state?.loans ?? []).find((l: Any) => l.ref === doc.number && sameAddr(l.borrower, business.wallet))
  if (loan) return { ...(LOAN_STATE[loan.status] ?? LOAN_STATE[1]), loanId: loan.id }
  if (doc.status === 'awaiting_buyer') return { label: 'Waiting for buyer', tone: 'warn' }
  const review = doc.review ?? { status: 'in_review' }
  if (review.status === 'rejected') return { label: 'Not approved', tone: 'bad', reason: sentence(review.reason), next: nextStep(review.reason ?? '', doc) }
  if (review.status === 'failed') return { label: 'Review did not finish', tone: 'warn', retry: true }
  if (review.status === 'listed') return { label: 'Listed', tone: 'info' }
  return { label: 'In review', tone: 'info' }
}

function Business({ live, notify, go, session }: { live: Live; notify: Notify; go: Go; session: Session }) {
  const view = useBusinessView(session.business, live)
  const [lost, setLost] = useState(false)
  const { setBusiness } = session
  useEffect(() => {
    if (view.missing) {
      setBusiness(null)
      setLost(true)
    }
  }, [view.missing, setBusiness])
  if (!session.business) return <BusinessSignup live={live} notify={notify} session={session} lost={lost} />
  if (!view.data)
    return (
      <div className="loading" role="status">
        Loading your account
      </div>
    )
  return <BusinessHome data={view.data} reload={view.reload} live={live} go={go} notify={notify} session={session} />
}

function BusinessSignup({ live, notify, session, lost }: { live: Live; notify: Notify; session: Session; lost: boolean }) {
  const [mode, setMode] = useState<'create' | 'signin'>(lost ? 'signin' : 'create')
  const [carry, setCarry] = useState<{ country: string; registrationNumber: string; note: string } | null>(null)
  const switchTo = (m: 'create' | 'signin') => {
    setCarry(null)
    setMode(m)
  }
  return (
    <>
      <h1 className="display">Get paid for shipped goods today.</h1>
      <p className="lede">Request an advance on an invoice, bill of lading or equipment order. Your buyer confirms the document, lenders fund it, and the advance is paid to your bank.</p>
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
              onExists={(c) => {
                setCarry(c)
                setMode('signin')
              }}
              onSignIn={() => switchTo('signin')}
            />
          ) : (
            <SignInBusiness key={carry ? 'carry' : 'plain'} live={live} notify={notify} session={session} initial={carry} onCreate={() => switchTo('create')} />
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
                <div className="detail">We use your registration number to pull your credit file. It is reviewed privately and never shown to lenders.</div>
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
                <div className="detail">When lenders fully fund the advance it is paid to your bank account. Your buyer pays the full amount on the due date, and the balance after lenders are repaid comes to you.</div>
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
}: {
  live: Live
  notify: Notify
  session: Session
  onExists: (c: { country: string; registrationNumber: string; note: string }) => void
  onSignIn: () => void
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
            Sign in instead
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
}: {
  live: Live
  notify: Notify
  session: Session
  initial: { country: string; registrationNumber: string } | null
  onCreate: () => void
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
            Create a business account
          </button>
        </span>
      </div>
    </form>
  )
}

function BusinessHome({ data, reload, live, go, notify, session }: { data: Any; reload: () => Promise<void>; live: Live; go: Go; notify: Notify; session: Session }) {
  const { business } = data
  const auth = session.business!
  const [sent, setSent] = useState<{ document: Any; buyerLink: string } | null>(null)
  const docs: Any[] = [...(data.documents ?? [])].sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)))
  const sentDoc = sent ? { ...sent.document, buyerLink: sent.buyerLink, ...docs.find((d) => d.number === sent.document.number && d.buyer === sent.document.buyer) } : null
  const runs = live.runs.filter((r) => r.handler === 'verify-and-list' && runInput(r).borrowerId === business.id)
  const overdue = (live.state?.loans ?? []).filter((l: Any) => sameAddr(l.borrower, business.wallet) && l.status >= 5)
  return (
    <>
      <div className="page-head">
        <div>
          <h1>{business.name}</h1>
          <div className="muted" style={{ marginTop: 6 }}>
            {countryName(business.country)}
            {business.registrationNumber ? `, registration ${business.registrationNumber}` : ''}
            {business.bankAccountEnding ? `. Payouts to the account ending ${business.bankAccountEnding}.` : ''}
          </div>
        </div>
        <button className="btn quiet" onClick={() => session.setBusiness(null)}>
          Switch business
        </button>
      </div>
      <div className="split">
        <div className="stack" style={{ gap: 20 }}>
          {sentDoc ? (
            <WaitingPanel doc={sentDoc} live={live} business={business} go={go} auth={auth} notify={notify} reload={reload} onNew={() => setSent(null)} />
          ) : (
            <RequestForm
              business={business}
              auth={auth}
              live={live}
              overdue={overdue}
              onSent={(r) => {
                setSent(r)
                void reload()
              }}
            />
          )}
          <Requests docs={docs} live={live} business={business} go={go} auth={auth} notify={notify} reload={reload} />
        </div>
        <section className="panel">
          <div className="panel-head">
            <h2>Recent reviews</h2>
          </div>
          <Activity runs={runs.slice(0, 10)} live={live} empty="Reviews start as soon as a buyer responds to one of your documents." />
        </section>
      </div>
    </>
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
  overdue,
  onSent,
}: {
  business: Any
  auth: BizSession
  live: Live
  overdue: Any[]
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
        <h2>Request financing</h2>
      </div>
      {overdue.length ? (
        <div className="notice bad">
          Payment on {overdue.map((l: Any) => l.ref).join(', ')} is overdue. New requests cannot be listed until it is settled.
        </div>
      ) : null}
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
            hint={`Lenders see: ${kind.prefix}${v.description.trim() || 'your description'}`}
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
          <button className="btn primary" disabled={busy}>
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
            <Link to={`/loans/${st.loanId}`} go={go}>
              View the listing
            </Link>
          </div>
        ) : (
          <div className="small muted">The request is being reviewed. This usually takes under a minute.</div>
        )}
        <div>
          <button className="btn quiet" onClick={onNew}>
            Request financing for another document
          </button>
        </div>
      </div>
    </section>
  )
}

function Requests({
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
        <h2>Your requests</h2>
        {docs.length ? <span className="small muted">{docs.length}</span> : null}
      </div>
      {docs.length === 0 ? (
        <div className="empty">No requests yet. Add a document above and send its buyer link to your buyer to get started.</div>
      ) : (
        docs.map((d) => {
          const st = requestState(d, live, business)
          return (
            <div key={`${d.number}|${d.buyer}`} className="req">
              <div className="req-main">
                <div className="t">
                  {st.loanId ? (
                    <Link to={`/loans/${st.loanId}`} go={go}>
                      {d.title}
                    </Link>
                  ) : (
                    d.title
                  )}
                </div>
                <div className="m">
                  <span className="code">{d.number}</span>, {money(d.amountMinor, d.currency, 2)} from {d.buyer}, due {fmtDate(d.dueDate)}
                </div>
                <StateDetail st={st} doc={d} auth={auth} notify={notify} reload={reload} live={live} />
                {d.disputeReason ? <div className="small muted">Buyer's note: {d.disputeReason}</div> : null}
                {d.status === 'awaiting_buyer' && d.buyerLink ? <CopyLink path={d.buyerLink} compact /> : null}
              </div>
              <StateText s={st} />
            </div>
          )
        })
      )}
    </section>
  )
}

// ---------------------------------------------------------------------------
// Buyer portal
// ---------------------------------------------------------------------------

function BuyerPortal({ token, live }: { token: string; live: Live }) {
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

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

function Operations({ live, notify }: { live: Live; notify: Notify }) {
  const { busy, run } = useAction(live, notify)
  const snap = live.state?.snapshot
  const books = live.state?.books
  const recon = snap?.recon
  const hasRecon = recon && Number(recon[1]) > 0
  const lenders: Any[] = [...(live.state?.lenders ?? [])].sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)))
  const movements = [
    ...(live.state?.intents ?? []).map((i: Any) => ({ key: i.reference, at: i.settledAt ?? i.createdAt, what: 'Lender deposit', ref: i.reference, amount: money(i.amountMinor, i.currency, 2), state: i.status })),
    ...(live.state?.payouts ?? []).map((p: Any) => ({
      key: p.payoutRef,
      at: p.createdAt,
      what: p.kind === 'lender' ? 'Payout to lender' : String(p.idempotencyKey).startsWith('balance-') ? 'Balance to business' : 'Payout to business',
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
          <h2>Lenders</h2>
          {lenders.length ? <span className="small muted">{lenders.length}</span> : null}
        </div>
        {lenders.length === 0 ? (
          <div className="empty">No lenders yet. Lenders sign up from the funding panel on any open request.</div>
        ) : (
          <div className="scroll">
            <table>
              <thead>
                <tr>
                  <th>Lender</th>
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

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

function App() {
  const live = useLive()
  const session = useSession(live.config)
  const { path, go } = usePath()
  const { toast, notify } = useToast()
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
          <BuyerPortal token={buyer[1]} live={live} />
        </main>
        <Footer />
        {toastEl}
      </>
    )

  const busy = live.runs.some((r) => isActive(r))
  const paused = Boolean(live.state?.snapshot?.fundingPaused)
  const loanMatch = path.match(/^\/loans\/(\d+)/)
  const page = loanMatch ? (
    <LoanPage key={loanMatch[1]} id={Number(loanMatch[1])} live={live} go={go} notify={notify} session={session} />
  ) : path === '/business' ? (
    <Business live={live} notify={notify} go={go} session={session} />
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
          <Wordmark go={go} />
          <nav className="nav" aria-label="Main">
            {nav.map(([to, label]) => (
              <Link key={to} to={to} go={go} className={(to === '/' ? path === '/' || path.startsWith('/loans') : path === to) ? 'on' : ''}>
                {label}
              </Link>
            ))}
          </nav>
          <div className="net" role="status">
            <span className={`pip ${live.offline ? 'alert' : busy ? 'busy' : paused ? 'alert' : ''}`} />
            <span>{live.offline ? 'Reconnecting' : busy ? 'Verifying' : paused ? 'Funding paused' : 'All systems normal'}</span>
          </div>
          <WalletChip session={session} />
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
      <Footer />
      {toastEl}
    </>
  )
}

createRoot(document.getElementById('root')!).render(<App />)
