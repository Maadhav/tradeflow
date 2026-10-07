// Tradeflow rails sandbox.
//
// Plays every off-chain party the CRE workflows talk to:
//   - document registry (documents a business enters, confirmed or disputed by its buyer),
//     credit bureau and sanctions screening (listing workflow, declared for TEE execution on a
//     deployed DON; simulated locally)
//   - KYC provider and the on-ramp/bank that receives lender deposits (lender workflow,
//     called through Confidential HTTP)
//   - the collection bank and the buyer's payment processor (two independent repayment sources)
//   - the payout provider (fiat out to businesses and fiat lenders)
//   - the operator's books (for the monitor's three-way reconciliation)
// It also serves the app: business and lender sign-up, the buyer portal, built-in wallets (local
// deployments only) that sign a strict allowlist of calls, runs the CRE workflows through the CLI
// simulator and serves the web app.

import { chmodSync, existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'
import {
  BaseError,
  ContractFunctionRevertedError,
  decodeFunctionData,
  encodeFunctionData,
  getAddress,
  isAddress,
  keccak256,
  toHex,
  parseAbiItem,
  type Address,
  type Hash,
  type Hex,
} from 'viem'
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts'
import { bureauFile, kycDecision, normalizeRegistration } from './seed'
import { makeChain, marketAbi, walletAbi, errorsAbi, loanTokenAbi, type Deployment } from './chain'
import { makeBridge, type WorkflowRun } from './bridge'
import index from './web/index.html'

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const ROOT = new URL('../../', import.meta.url).pathname
const KEYS: Record<string, `0x${string}`> = (await Bun.file(`${ROOT}.secrets/keys.json`).exists())
  ? await Bun.file(`${ROOT}.secrets/keys.json`).json()
  : {}
const PORT = Number(process.env.PORT ?? 8787)
const RPC_URL = process.env.RPC_URL ?? 'http://127.0.0.1:8545'
const DEPLOYMENT = process.env.DEPLOYMENT ?? 'local'
// The key the workflows use to call the /v1 rails. Random per process unless set, and handed to the
// CLI through this deployment's own env file (see the bridge below), never through cre/.env.
const API_KEY = process.env.RAILS_API_KEY || randomBytes(24).toString('base64url')
const CRE_SIGNER_KEY = (process.env.CRE_ETH_PRIVATE_KEY ?? KEYS.creSigner) as `0x${string}` | undefined
const OPERATOR_KEY = (process.env.ONRAMP_OPERATOR_KEY ?? KEYS.platform) as `0x${string}`
const OWNER_KEY = (process.env.OWNER_KEY ?? KEYS.platform) as `0x${string}`
const CRE_BIN = process.env.CRE_BIN ?? `${process.env.HOME}/.cre/bin/cre`
const CRE_TARGET = process.env.CRE_TARGET ?? 'local'
const AUTO_RUN = process.env.AUTO_RUN !== '0'

const deployment: Deployment = await Bun.file(`${ROOT}contracts/deployments/${DEPLOYMENT}.json`).json()
const chain = makeChain(RPC_URL, deployment, OPERATOR_KEY)
// Built-in wallets: one fresh account per browser, its key in the custody file. Only on the local
// deployment, whose chain (anvil) tops up their gas; public deployments use the lender's own wallet.
const BUILTIN_WALLETS = DEPLOYMENT === 'local'

// ---------------------------------------------------------------------------
// State (persisted to a JSON file so restarts keep the history)
// ---------------------------------------------------------------------------

/** A sign-in key handed to a browser: only its sha256 is kept, with when it was issued and last used. */
type SessionKey = { hash: string; issuedAt: number; usedAt: number; unproven?: boolean }
type Business = {
  id: string
  name: string
  country: string
  registrationNumber: string
  bankAccount: string
  email: string
  wallet: Address // fresh EOA generated here; the key is in the custody file
  sessions: SessionKey[] // the sign-in keys handed to this business's browsers
  createdAt: string
}
type DocType = 'invoice' | 'bill_of_lading' | 'equipment'
type FinDocument = {
  number: string
  type: DocType
  businessId: string
  buyer: string
  buyerEmail: string
  buyerCountry: string
  amountMinor: number // 2 decimals
  currency: 'EUR' | 'USD'
  issuedAt: string
  dueDate: string
  dueInDays: number
  title: string
  fileName?: string
  fileSha256?: string
  status: 'awaiting_buyer' | 'confirmed' | 'disputed'
  token: string // buyer portal link; never leaves the business's own view
  respondedAt?: string
  respondedBy?: string
  disputeReason?: string
  review?: Review // outcome of the latest finished listing run
  createdAt: string
}
/** Where the listing review of a document stands: decided by the workflow, or a run that did not finish. */
type Review = { status: 'listed' | 'rejected' | 'failed'; reason?: string; runId: number; at: string }
type Lender = {
  id: string
  name: string
  email: string
  country: string
  funding: 'fiat' | 'stablecoin'
  wallet: Address // fiat: custody EOA; stablecoin: the lender's connected wallet
  bankAccount?: string
  kycStatus: 'approved' | 'pending' | 'rejected'
  kycLevel: string
  sessions: SessionKey[] // the sign-in keys handed to this investor's browsers
  createdAt: string
}
type Intent = {
  reference: string
  lenderId: string
  loanId: number
  amountMinor: number // fiat, 2 decimals
  currency: 'EUR' | 'USD'
  createdAt: string
  status: 'awaiting_funds' | 'received' | 'settled' | 'credited' | 'failed' // received: at the bank; settled: converted by the on-ramp
  fxRateE8?: string
  stablecoinAmount?: string // 6 decimals
  mintTx?: string
  settledAt?: string
}
type Payout = { idempotencyKey: string; payoutRef: string; kind: 'business' | 'lender'; loanId: number; beneficiaryId: string; amount: string; createdAt: string }
type BankCredit = { reference: string; amountMinor: number; currency: 'EUR' | 'USD'; payer: string; valueDate: string; kind: 'deposit' | 'repayment' }
type PspPayment = { reference: string; status: 'captured'; amountMinor: number; currency: 'EUR' | 'USD'; payer: string; capturedAt: string; loanId?: number }
type Listing = { docNumber: string; borrowerId: string; submittedAt: string; tenorDays: number; runId?: number }

type State = {
  businesses: Business[]
  documents: FinDocument[]
  lenders: Lender[]
  intents: Intent[]
  payouts: Payout[]
  bankCredits: BankCredit[]
  pspPayments: PspPayment[]
  listings: Listing[]
  ledgerAdjustments: { at: string; note: string; usd6: string }[]
  runs: WorkflowRun[]
  deployBlock?: { market: string; block: string } // where the market's event history starts, pinned once known
}

const DATA_DIR = `${import.meta.dir}/data`
const UPLOADS_DIR = `${DATA_DIR}/uploads`
const STATE_FILE = `${DATA_DIR}/state.${DEPLOYMENT}.json`
const CUSTODY_FILE = `${DATA_DIR}/custody.${DEPLOYMENT}.json`
mkdirSync(DATA_DIR, { recursive: true })

const loaded = (await Bun.file(STATE_FILE).exists()) ? await Bun.file(STATE_FILE).json() : {}
const state = loaded as State
for (const key of ['businesses', 'documents', 'lenders', 'intents', 'payouts', 'bankCredits', 'pspPayments', 'listings', 'ledgerAdjustments', 'runs'] as const) {
  if (!Array.isArray(state[key])) (state as Record<string, unknown>)[key] = [] // older state files lack the newer arrays
}
// Older state files keep only the key hashes: those keys stay valid, as if issued now.
for (const a of [...state.businesses, ...state.lenders] as (Business & { sessionHashes?: string[] })[]) {
  if (!Array.isArray(a.sessions)) a.sessions = (a.sessionHashes ?? []).map((hash) => ({ hash, issuedAt: Date.now(), usedAt: Date.now() }))
  delete a.sessionHashes
}
// The run queue lives in memory, so a run that was queued or running when the server stopped will
// never finish. Record it as failed, so it can be started again.
for (const r of state.runs) {
  if (r.status !== 'queued' && r.status !== 'running') continue
  r.status = 'failed'
  r.finishedAt = new Date().toISOString()
  r.logs.push('stopped by a server restart')
}
let saveTimer: ReturnType<typeof setTimeout> | undefined
let chainChanged = () => {} // set below: marks the cached chain reads stale (see swr)
function persist() {
  chainChanged()
  clearTimeout(saveTimer)
  saveTimer = setTimeout(() => Bun.write(STATE_FILE, JSON.stringify(state, null, 2)), 50)
}

// Custody: keys of the wallets generated for businesses and bank-transfer lenders. Kept in its own
// file (owner read/write only), never in state, never in a response, never logged.
// A built-in wallet's entry also holds the sha256 of the browser key that may sign for it.
const custody: Record<string, { address: Address; privateKey: Hex; keyHash?: string; createdAt: string }> = existsSync(CUSTODY_FILE)
  ? JSON.parse(readFileSync(CUSTODY_FILE, 'utf8'))
  : {}
function custodyWallet(ownerId: string): Address {
  const privateKey = generatePrivateKey()
  const { address } = privateKeyToAccount(privateKey)
  custody[ownerId] = { address, privateKey, createdAt: nowIso() }
  writeFileSync(CUSTODY_FILE, JSON.stringify(custody, null, 2), { mode: 0o600 })
  return address
}

/** Secrets handed to a browser: only their sha256 is kept, and checks compare in constant time. */
const newSecret = () => randomBytes(32).toString('base64url')
const sha256 = (s: string) => createHash('sha256').update(s).digest('hex')
const sameHash = (a: string, b: string) => a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b))

// ---------------------------------------------------------------------------
// CRE bridge
// ---------------------------------------------------------------------------

const sockets = new Set<import('bun').ServerWebSocket<unknown>>()
function broadcast(type: string, data: unknown) {
  const msg = JSON.stringify({ type, data })
  for (const s of sockets) s.send(msg)
}

// The CLI reads its secrets from an env file, which wins over the process environment. Each
// deployment writes its own (owner read/write only), so instances never share the rails API key.
const CRE_ENV_FILE = `${DATA_DIR}/cre.${DEPLOYMENT}.env`
writeFileSync(CRE_ENV_FILE, `${CRE_SIGNER_KEY ? `CRE_ETH_PRIVATE_KEY=${CRE_SIGNER_KEY}\n` : ''}RAILS_API_KEY_VAR=${API_KEY}\n`, { mode: 0o600 })
chmodSync(CRE_ENV_FILE, 0o600)

const bridge = makeBridge(
  {
    creBin: CRE_BIN,
    projectDir: `${ROOT}cre`,
    target: CRE_TARGET,
    broadcast: true,
    envFile: CRE_ENV_FILE,
    env: { CRE_TARGET },
    onUpdate: (run) => broadcast('run', run),
  },
  state.runs,
  persist,
)
persist() // keeps the runs recorded as failed after a restart

const WF = {
  listing: { workflow: 'listing', handler: 'verify-and-list', triggerIndex: 0, trigger: 'http' as const },
  kyc: { workflow: 'lender', handler: 'verify-lender', triggerIndex: 0, trigger: 'http' as const },
  fiatFunding: { workflow: 'lender', handler: 'credit-fiat-deposit', triggerIndex: 1, trigger: 'http' as const },
  disburse: { workflow: 'settlement', handler: 'disburse-on-funded', triggerIndex: 0, trigger: 'evm-log' as const },
  repayment: { workflow: 'settlement', handler: 'confirm-repayment', triggerIndex: 1, trigger: 'http' as const },
  redeemFiat: { workflow: 'settlement', handler: 'redeem-fiat-lenders', triggerIndex: 2, trigger: 'evm-log' as const },
  monitor: { workflow: 'monitor', handler: 'watch-and-reconcile', triggerIndex: 0, trigger: 'cron' as const },
}
const inFlight = (handler: string, input: string) =>
  state.runs.find((r) => r.handler === handler && r.input === input && (r.status === 'queued' || r.status === 'running'))

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const json = (data: unknown, status = 200) =>
  new Response(JSON.stringify(data, (_, v) => (typeof v === 'bigint' ? v.toString() : v)), {
    status,
    headers: { 'content-type': 'application/json', 'access-control-allow-origin': '*' },
  })
const authed = (req: Request) => req.headers.get('x-api-key') === API_KEY
const unauthorized = () => json({ error: 'invalid api key' }, 401)
const nowIso = () => new Date().toISOString()
/** What the outside parties do, printed next to the workflow runs: `[on-ramp] ...`, `[bank] ...`. */
const railsLog = (party: string, message: string) => console.log(`[${party}] ${message}`)
const fiatText = (minor: number, ccy: string) => `${ccy} ${(minor / 100).toLocaleString('en-US', { minimumFractionDigits: 2 })}`
const ccyRateE8 = async (currency: 'EUR' | 'USD'): Promise<bigint> => {
  if (currency === 'USD') return 100_000_000n
  // The on-ramp quotes its own EUR rate (slightly off the Chainlink feed, like a real provider).
  const feed = await chain.publicClient.readContract({
    address: '0x1a81afB8146aeFfCFc5E50e8479e826E7D55b910',
    abi: [parseAbiItem('function latestRoundData() view returns (uint80,int256,uint256,uint256,uint80)')],
    functionName: 'latestRoundData',
  })
  const answer = feed[1] as bigint
  return (answer * 9_980n) / 10_000n // provider spread: 0.2% below the feed
}
const toUsd6 = (amountMinor: number, rateE8: bigint) => (BigInt(amountMinor) * rateE8 * 10_000n) / 100_000_000n
const money = (minor: number | bigint, currency: string) =>
  `${currency} ${(Number(minor) / 100).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`

/** A request the user can fix: answered as { error } with a 4xx status. */
class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message)
  }
}
function fail(status: number, message: string): never {
  throw new ApiError(status, message)
}
async function body<T>(req: Request, optional = false): Promise<Partial<T>> {
  const raw = await req.text()
  if (optional && raw.trim() === '') return {}
  try {
    const v = JSON.parse(raw)
    if (v && typeof v === 'object' && !Array.isArray(v)) return v
  } catch {}
  return fail(400, 'Send the request body as a JSON object.')
}
const text = (v: unknown, max = 200) => (typeof v === 'string' ? v.trim().slice(0, max) : '')
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/
const countryCode = (v: unknown) => {
  const c = text(v).toUpperCase()
  return /^[A-Z]{2}$/.test(c) ? c : undefined
}
const slug = (s: string, max = 24) =>
  s
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[̀-ͯ]/g, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+/, '')
    .slice(0, max)
    .replace(/-+$/, '') || 'account'
const suffix = () => Array.from(randomBytes(4), (b) => (b % 36).toString(36)).join('')
const newToken = () => randomBytes(18).toString('base64url') // 24 url-safe chars

const DAY_MS = 86_400_000
const isoDate = (v: unknown) => {
  if (typeof v !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(v)) return undefined
  const t = Date.parse(`${v}T00:00:00Z`)
  return Number.isFinite(t) && new Date(t).toISOString().slice(0, 10) === v ? v : undefined
}
const daysUntil = (date: string) => Math.round((Date.parse(`${date}T00:00:00Z`) - Date.parse(`${nowIso().slice(0, 10)}T00:00:00Z`)) / DAY_MS)

const DOC_TYPES: DocType[] = ['invoice', 'bill_of_lading', 'equipment']
const TITLE_PREFIX: Record<DocType, string> = {
  invoice: 'Invoice advance: ',
  bill_of_lading: 'Supply chain finance: ',
  equipment: 'Equipment finance: ',
}
const normalizeBuyer = (s: string) => s.toLowerCase().replace(/\s+/g, ' ').trim()
const docHashOf = (d: FinDocument): Hex =>
  keccak256(toHex(`${d.number}|${d.businessId}|${d.amountMinor}|${d.currency}|${d.buyer}|${d.fileSha256 ?? ''}`))

/** What other viewers may see. Never email, bank account, buyer link, review or keys. */
const publicBusiness = (b: Business) => ({ id: b.id, name: b.name, country: b.country, wallet: b.wallet, createdAt: b.createdAt })
const publicDocument = ({ token: _t, buyerEmail: _e, review: _r, ...d }: FinDocument) => ({ ...d, docHash: docHashOf(d as FinDocument) })
/** The business's own view of itself (signed in): adds what it entered, the bank account as its last four characters. */
const ownBusiness = (b: Business) => ({
  ...publicBusiness(b),
  registrationNumber: b.registrationNumber,
  email: b.email,
  bankAccountEnding: b.bankAccount.replace(/\s/g, '').slice(-4),
})
const publicLender = (l: Lender) => ({
  id: l.id,
  name: l.name,
  country: l.country,
  funding: l.funding,
  wallet: l.wallet,
  kycStatus: l.kycStatus,
  kycLevel: l.kycLevel,
  createdAt: l.createdAt,
})
const buyerLink = (d: FinDocument) => `/buyer/${d.token}`
/** Where buyers pay financed documents, by currency. */
const COLLECTION: Record<'EUR' | 'USD', { beneficiary: string; account: string }> = {
  EUR: { beneficiary: 'Tradeflow Collections', account: 'DE44 5001 0517 5407 3249 31' },
  USD: { beneficiary: 'Tradeflow Collections', account: 'US-ACH 021000021 / 4455667788' },
}

/** Uploaded documents: PDF, PNG or JPG, identified by their bytes rather than the name the browser sent. */
const FILE_KINDS = [
  { ext: 'pdf', type: 'application/pdf', magic: [0x25, 0x50, 0x44, 0x46, 0x2d] },
  { ext: 'png', type: 'image/png', magic: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] },
  { ext: 'jpg', type: 'image/jpeg', magic: [0xff, 0xd8, 0xff] },
]
const MAX_FILE_BYTES = 5 * 1024 * 1024
const fileKind = (bytes: Uint8Array) => FILE_KINDS.find((k) => k.magic.every((b, i) => bytes[i] === b))
const uploadPath = (d: FinDocument) => `${UPLOADS_DIR}/${d.businessId}/${d.fileSha256!.slice(0, 16)}-${d.fileName}`

/** The loan listed for a document (matched by its document hash), if any. */
async function loanFor(doc: FinDocument) {
  if (doc.status !== 'confirmed') return undefined
  const hash = docHashOf(doc)
  const count = Number(await chain.publicClient.readContract({ address: deployment.market, abi: marketAbi, functionName: 'loanCount' }))
  for (let id = count; id >= 1; id--) {
    const l = await chain.readLoan(BigInt(id))
    if (l.docHash === hash) return { id, ...l }
  }
  return undefined
}
const dueOf = (loan: { target: bigint; aprBps: number; tenorDays: number }) =>
  loan.target + (loan.target * BigInt(loan.aprBps) * BigInt(loan.tenorDays)) / (10_000n * 365n)

const docByToken = (token: string) =>
  state.documents.find((d) => d.token === token) ?? fail(404, 'This link is not valid. Ask your supplier to send it again.')

/** A signed-in business: the browser sends the key it got when it signed up or signed in. */
function signedIn(req: Request, businessId: unknown): Business {
  const business = typeof businessId === 'string' ? state.businesses.find((x) => x.id === businessId) : undefined
  if (!business) fail(404, 'We could not find this business account. Sign in again to continue.')
  if (!sessionFor(business, req.headers.get('x-business-key'))) {
    fail(401, 'This browser is no longer signed in to the business account. Sign in again to continue.')
  }
  return business
}

// Sign-in keys expire when a browser has not used them for SESSION_IDLE_MS, not by count. An account
// keeps at most SESSION_CAP keys, dropping the least recently used, so a browser in use is never
// pushed out. A sign-in that proves nothing but an email (or a registration number) is limited to
// UNPROVEN_PER_HOUR per account, so it takes many hours of such sign-ins to push out even an idle key.
const SESSION_IDLE_MS = 30 * DAY_MS
const SESSION_CAP = 50
const UNPROVEN_PER_HOUR = 10
const HOUR_MS = 3_600_000
const USED_AT_STEP_MS = 10 * 60_000 // a key's last use is saved to disk at most this often
type Account = { sessions: SessionKey[] }

/** The live session of the key a browser sent, its last use refreshed; undefined when the key is unknown or expired. */
function sessionFor(account: Account, key: string | null): SessionKey | undefined {
  if (!key) return undefined
  const now = Date.now()
  const hash = sha256(key)
  const session = account.sessions.find((s) => sameHash(s.hash, hash) && now - s.usedAt < SESSION_IDLE_MS)
  if (session) {
    const stale = now - session.usedAt > USED_AT_STEP_MS
    session.usedAt = now
    if (stale) persist()
  }
  return session
}
/** A new sign-in key for a business or an investor. `unproven`: the caller proved only an email or a registration number. */
function issueSession(account: Account, opts: { unproven?: boolean } = {}): string {
  const now = Date.now()
  const live = account.sessions.filter((s) => now - s.usedAt < SESSION_IDLE_MS)
  if (opts.unproven && live.filter((s) => s.unproven && now - s.issuedAt < HOUR_MS).length >= UNPROVEN_PER_HOUR) {
    fail(429, 'This account has been signed in too many times in the last hour. Wait an hour, then sign in again.')
  }
  const kept = live.sort((a, b) => b.usedAt - a.usedAt).slice(0, SESSION_CAP - 1)
  const key = newSecret()
  account.sessions = [{ hash: sha256(key), issuedAt: now, usedAt: now, ...(opts.unproven ? { unproven: true } : {}) }, ...kept]
  persist()
  return key
}
/** Signing out: the key the browser sent stops working. */
function endSession(account: Account, key: string | null) {
  if (!key) return
  const hash = sha256(key)
  const before = account.sessions.length
  account.sessions = account.sessions.filter((s) => !sameHash(s.hash, hash))
  if (account.sessions.length !== before) persist()
}

/** Where the review of a document stands: a run in flight, else the outcome saved when the last run ended. */
function reviewOf(doc: FinDocument): { status: 'in_review' | Review['status']; reason?: string; runId?: number } | undefined {
  if (doc.status === 'awaiting_buyer') return undefined
  const listing = state.listings.find((l) => l.borrowerId === doc.businessId && l.docNumber === doc.number)
  const run = listing?.runId ? state.runs.find((r) => r.id === listing.runId) : undefined
  if (run && (run.status === 'queued' || run.status === 'running')) return { status: 'in_review', runId: run.id }
  if (doc.review) return doc.review
  if (run?.status === 'failed') return { status: 'failed', runId: run.id }
  return { status: 'in_review', runId: run?.id }
}

/** Start the listing workflow for a document the buyer has responded to, and keep its outcome on the document. */
function submitListing(doc: FinDocument) {
  doc.dueInDays = Math.max(1, daysUntil(doc.dueDate))
  const { run, done } = bridge.start({
    ...WF.listing,
    httpPayload: { borrowerId: doc.businessId, docNumber: doc.number, tenorDays: doc.dueInDays },
  })
  state.listings.unshift({ docNumber: doc.number, borrowerId: doc.businessId, submittedAt: nowIso(), tenorDays: doc.dueInDays, runId: run.id })
  persist()
  broadcast('rails', { kind: 'document', number: doc.number, status: doc.status })
  void done.then((r) => {
    const d = r.resultData
    doc.review =
      r.status === 'success' && d?.listed === true
        ? { status: 'listed', runId: r.id, at: nowIso() }
        : r.status === 'success' && d?.listed === false
          ? { status: 'rejected', reason: String(d.reason ?? ''), runId: r.id, at: nowIso() }
          : { status: 'failed', runId: r.id, at: nowIso() }
    persist()
    broadcast('rails', { kind: 'review', number: doc.number, status: doc.review.status })
  })
  return run.id
}

/** One request at a time per key (a transfer reference, a loan): a second one arriving meanwhile is refused. */
const locks = new Set<string>()
const converting = new Set<string>() // on-ramp conversions in flight, by transfer reference
async function exclusive<T>(key: string, busy: string, fn: () => Promise<T>): Promise<T> {
  if (locks.has(key)) fail(409, busy)
  locks.add(key)
  try {
    return await fn()
  } finally {
    locks.delete(key)
  }
}

/** Start the KYC workflow for a lender (or return the one already queued). */
function runKyc(l: Lender) {
  const input = { lenderId: l.id }
  return inFlight(WF.kyc.handler, JSON.stringify(input))?.id ?? bridge.start({ ...WF.kyc, httpPayload: input }).run.id
}
/** Verified onchain: the wallet is in the ERC-3643 identity registry with a valid KYC claim. */
const isVerified = (wallet: Address) => chain.isVerified(wallet)

// ---------------------------------------------------------------------------
// Built-in wallets: one real EOA per browser, its key in the custody file. The browser holds a
// random wallet key that lets it ask for a signature; the wallet signs only approve (to the
// market) and the faucet on the stablecoin, and fund and claim on the market.
// ---------------------------------------------------------------------------

const builtinId = (address: Address) => `wallet-${getAddress(address)}`
/** The built-in wallet the request may sign for: it must send the wallet key for that address. */
function builtinFor(req: Request, addressRaw: unknown) {
  if (!BUILTIN_WALLETS) fail(404, 'This deployment has no built-in wallets. Connect a browser wallet instead.')
  const entry = typeof addressRaw === 'string' && isAddress(addressRaw, { strict: false }) ? custody[builtinId(addressRaw as Address)] : undefined
  const key = req.headers.get('x-wallet-key') ?? ''
  if (!entry?.keyHash || !key || !sameHash(entry.keyHash, sha256(key))) {
    fail(401, 'This browser can no longer use that wallet. Disconnect it, then connect a wallet again.')
  }
  return { address: entry.address, client: chain.walletFor(entry.privateKey) }
}

/** The local chain pays the gas of built-in wallets: top one up when it runs low. */
async function topUpGas(address: Address) {
  const balance = await chain.publicClient.getBalance({ address })
  if (balance >= 10n ** 17n) return // 0.1 ETH
  await chain.publicClient.request({ method: 'anvil_setBalance', params: [address, toHex(10n ** 18n)] } as any)
}

// Lenders who connect a browser wallet prove they control it by signing a one-time message.
const challenges = new Map<string, { wallet: Address; message: string; expires: number }>()
const CHALLENGE_MS = 10 * 60_000
function challengeFor(wallet: Address) {
  const now = Date.now()
  for (const [k, c] of challenges) if (c.expires < now) challenges.delete(k)
  const nonce = randomBytes(16).toString('hex')
  const message = `Sign in to Tradeflow to lend from this wallet.\n\nWallet: ${wallet}\nNonce: ${nonce}\n\nSigning is free and does not send a transaction.`
  challenges.set(nonce, { wallet, message, expires: now + CHALLENGE_MS })
  return { nonce, message }
}
/** True when `signature` is the wallet's signature of a challenge issued to it (each challenge works once). */
async function provesWallet(wallet: Address, nonce: unknown, signature: unknown): Promise<boolean> {
  const c = typeof nonce === 'string' ? challenges.get(nonce) : undefined
  if (!c || c.expires < Date.now() || c.wallet !== wallet || typeof signature !== 'string' || !/^0x[0-9a-fA-F]+$/.test(signature)) return false
  challenges.delete(nonce as string)
  return chain.publicClient.verifyMessage({ address: wallet, message: c.message, signature: signature as Hex }).catch(() => false)
}

type AllowedCall = { to: Address; data: Hex; functionName: 'approve' | 'drip' | 'fund' | 'claim'; args: readonly unknown[] }

function allowedCall(toRaw: unknown, dataRaw: unknown): AllowedCall | undefined {
  if (typeof toRaw !== 'string' || !isAddress(toRaw, { strict: false })) return undefined
  if (typeof dataRaw !== 'string' || !/^0x[0-9a-fA-F]{8,}$/.test(dataRaw)) return undefined
  const to = getAddress(toRaw)
  const data = dataRaw.toLowerCase() as Hex
  let decoded: ReturnType<typeof decodeFunctionData<typeof walletAbi>>
  try {
    decoded = decodeFunctionData({ abi: walletAbi, data })
  } catch {
    return undefined
  }
  // Canonical encoding only: no trailing bytes, no dirty padding.
  if (encodeFunctionData({ abi: walletAbi, functionName: decoded.functionName, args: decoded.args } as any).toLowerCase() !== data) return undefined
  const args = (decoded.args ?? []) as readonly unknown[]
  const toToken = to === getAddress(deployment.stablecoin)
  const toMarket = to === getAddress(deployment.market)
  const ok =
    (toToken && decoded.functionName === 'approve' && getAddress(args[0] as string) === getAddress(deployment.market)) ||
    (toToken && decoded.functionName === 'drip') ||
    (toMarket && (decoded.functionName === 'fund' || decoded.functionName === 'claim'))
  return ok ? { to, data, functionName: decoded.functionName, args } : undefined
}

const usd6 = (v: unknown) => `$${(Number(v) / 1e6).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`

/** Explain why a wallet transaction would revert, in words the lender can act on. */
function revertMessage(e: unknown): string {
  const reverted = e instanceof BaseError ? e.walk((x) => x instanceof ContractFunctionRevertedError) : undefined
  const data = reverted instanceof ContractFunctionRevertedError ? reverted.data : undefined
  const args = (data?.args ?? []) as readonly unknown[]
  switch (data?.errorName) {
    case 'NotVerified':
    case 'UnverifiedHolder':
      return 'This wallet is not verified to lend yet. Verify your identity, then try again.'
    case 'EnforcedPause':
      return 'Transfers of this loan note are paused while the loan is overdue.'
    case 'FundingIsPaused':
      return 'New funding is paused while the books are reconciled. Try again later.'
    case 'OverTarget':
      return `That is more than the ${usd6(args[0])} this loan still needs. Enter ${usd6(args[0])} or less.`
    case 'BadStatus':
      return 'This loan is not open for that right now. Refresh to see its latest status.'
    case 'Frozen':
      return 'This business is frozen after a late repayment, so its loans cannot take new funding.'
    case 'NothingToClaim':
      return 'This wallet has nothing to claim on this loan.'
    case 'ZeroAmount':
      return 'Enter an amount greater than zero.'
    case 'ERC20InsufficientBalance':
      return 'There is not enough USDC in this wallet. Get USDC or enter a smaller amount.'
    case 'ERC20InsufficientAllowance':
      return 'Approve USDC for this amount first, then fund.'
    case 'DripCooldown':
      return `USDC can be requested once an hour. Try again after ${new Date(Number(args[0]) * 1000).toISOString().slice(11, 16)} UTC.`
  }
  // ERC-3643 tokens and registries revert with a reason string rather than a custom error.
  const reason = reverted instanceof ContractFunctionRevertedError ? (reverted.reason ?? '') : ''
  if (/not verified|identity/i.test(reason)) return 'This wallet is not verified to lend yet. Verify your identity, then try again.'
  if (/paused/i.test(reason)) return 'Transfers of this loan note are paused while the loan is overdue.'
  if (/transfer not possible/i.test(reason)) return 'Loan notes can only move to a wallet with a verified identity.'
  return `The transaction would fail${data?.errorName ? ` (${data.errorName})` : ''}. Refresh and try again.`
}

let walletQueue: Promise<unknown> = Promise.resolve()
/** Built-in wallet transactions go out one at a time, so nonces never collide. */
function sendBuiltin(wallet: ReturnType<typeof builtinFor>, call: AllowedCall): Promise<{ hash: Hash; status: 'success' | 'reverted' }> {
  const job = walletQueue.then(async () => {
    await topUpGas(wallet.address)
    try {
      await chain.publicClient.simulateContract({
        address: call.to,
        abi: [...walletAbi, ...errorsAbi],
        functionName: call.functionName,
        args: call.args,
        account: wallet.client.account!,
      } as any)
    } catch (e) {
      fail(409, revertMessage(e))
    }
    return chain.sendData(wallet.client, call.to, call.data)
  })
  walletQueue = job.catch(() => {})
  return job
}

// ---------------------------------------------------------------------------
// Event watcher: market events start the log-triggered settlement workflows
// ---------------------------------------------------------------------------

const topic = (sig: string) => keccak256(toHex(sig))
const FULLY_FUNDED = topic('LoanFullyFunded(uint256,address,uint256)')
const REPAID = topic('Repaid(uint256,uint256,bytes32)')
let lastBlock = await chain.publicClient.getBlockNumber()

/**
 * The block the market was deployed in, where its event history starts. Pinned once known: DEPLOY_BLOCK,
 * else the block kept in state for this market, else the receipt of the deploy transaction that forge
 * saved, else a search of the chain. A pruning RPC cannot say whether the market existed at an old
 * block, so a search that met such a block is used for this run only and never kept.
 */
async function findDeployBlock(): Promise<bigint> {
  if (process.env.DEPLOY_BLOCK) return BigInt(process.env.DEPLOY_BLOCK)
  const market = deployment.market.toLowerCase()
  if (state.deployBlock?.market.toLowerCase() === market) return BigInt(state.deployBlock.block)
  const found = (await deployReceiptBlock()) ?? (await searchDeployBlock())
  if (found.certain) {
    state.deployBlock = { market: deployment.market, block: String(found.block) }
    persist()
  } else {
    console.warn(`deploy block: this RPC no longer serves the old blocks, so the market's history is read from block ${found.block}, which may be after its deployment. Set DEPLOY_BLOCK to the block it was deployed in.`)
  }
  return found.block
}
/** The deploy transaction's block, from forge's broadcast receipts (newest run first). */
async function deployReceiptBlock(): Promise<{ block: bigint; certain: boolean } | undefined> {
  const dir = `${ROOT}contracts/broadcast/Deploy.s.sol/${deployment.chainId}`
  let files: string[] = []
  try {
    files = readdirSync(dir).filter((f) => /^run-\d+\.json$/.test(f)).sort().reverse()
  } catch {
    return undefined
  }
  const market = deployment.market.toLowerCase()
  for (const f of files) {
    let receipts: { contractAddress?: string | null; blockNumber?: string }[] = []
    try {
      receipts = JSON.parse(readFileSync(`${dir}/${f}`, 'utf8')).receipts ?? []
    } catch {
      continue
    }
    const r = receipts.find((x) => x.contractAddress?.toLowerCase() === market && x.blockNumber)
    if (!r) continue
    const block = BigInt(r.blockNumber!)
    // The same address can come from an older local fork: the market must have code at that block.
    const code = await chain.publicClient.getCode({ address: deployment.market, blockNumber: block }).catch(() => undefined)
    if (code === '0x') continue
    return { block, certain: true }
  }
  return undefined
}
/** First block where the market has code (binary search). */
async function searchDeployBlock(): Promise<{ block: bigint; certain: boolean }> {
  let lo = 0n
  let hi = lastBlock
  let certain = true
  while (lo < hi) {
    const mid = (lo + hi) / 2n
    const code = await chain.publicClient.getCode({ address: deployment.market, blockNumber: mid }).catch(() => {
      certain = false
      return undefined
    })
    if (code && code !== '0x') hi = mid
    else lo = mid + 1n
  }
  return { block: lo, certain }
}
const deployBlock = await findDeployBlock()

// Market event history, read in windows that public RPCs accept (they cap eth_getLogs at 10k to 50k
// blocks) and cached per query, so a refresh reads only the blocks added since. The newest
// REORG_DEPTH blocks are read again on every call and never cached.
const LOG_WINDOW = BigInt(process.env.LOG_WINDOW ?? 10_000)
const REORG_DEPTH = BigInt(process.env.REORG_DEPTH ?? (DEPLOYMENT === 'local' ? 0 : 12))
const LOG_PARALLEL = 4 // windows read at once
const logScans = new Map<string, { to: bigint; logs: unknown[]; busy: Promise<unknown> }>()
const windowsOf = (from: bigint, to: bigint) => {
  const out: [bigint, bigint][] = []
  for (let a = from; a <= to; a += LOG_WINDOW) out.push([a, a + LOG_WINDOW - 1n < to ? a + LOG_WINDOW - 1n : to])
  return out
}
async function readWindows<T>(from: bigint, to: bigint, read: (fromBlock: bigint, toBlock: bigint) => Promise<T[]>, onWindow?: (to: bigint, logs: T[]) => void): Promise<T[]> {
  const all: T[] = []
  const ws = windowsOf(from, to)
  for (let i = 0; i < ws.length; i += LOG_PARALLEL) {
    const batch = ws.slice(i, i + LOG_PARALLEL)
    const results = await Promise.all(batch.map(([a, b]) => read(a, b)))
    results.forEach((logs, j) => {
      all.push(...logs)
      onWindow?.(batch[j]![1], logs)
    })
  }
  return all
}
/** Every log of one query since the market was deployed. Calls with the same key run one after another. */
function scanLogs<T>(key: string, read: (fromBlock: bigint, toBlock: bigint) => Promise<T[]>): Promise<T[]> {
  let entry = logScans.get(key)
  if (!entry) logScans.set(key, (entry = { to: deployBlock - 1n, logs: [], busy: Promise.resolve() }))
  const e = entry
  const run = e.busy.then(async () => {
    const head = await chain.publicClient.getBlockNumber({ cacheTime: 0 })
    const safe = head - REORG_DEPTH
    // Confirmed blocks: cached window by window, so a failure keeps what was read before it.
    if (e.to < safe)
      await readWindows(e.to + 1n, safe, read, (to, logs) => {
        e.logs.push(...logs)
        e.to = to
      })
    const recent = e.to < head ? await readWindows(e.to + 1n, head, read) : []
    return [...(e.logs as T[]), ...recent]
  })
  e.busy = run.catch(() => {})
  return run
}

async function watch() {
  try {
    const head = await chain.publicClient.getBlockNumber()
    if (head <= lastBlock) return
    const logs = await chain.publicClient.getLogs({
      address: deployment.market,
      fromBlock: lastBlock + 1n,
      toBlock: head,
    })
    lastBlock = head
    for (const log of logs) {
      chainChanged()
      broadcast('chain', { tx: log.transactionHash, topic: log.topics[0], block: String(log.blockNumber) })
      if (!AUTO_RUN) continue
      const t = log.topics[0]
      if (t !== FULLY_FUNDED && t !== REPAID) continue
      const index = await chain.eventIndexIn(log.transactionHash as Hash, t)
      const wf = t === FULLY_FUNDED ? WF.disburse : WF.redeemFiat
      void bridge.enqueue({ ...wf, evmTxHash: log.transactionHash!, evmEventIndex: index })
    }
  } catch (e) {
    console.error('watch error', (e as Error).message)
  }
}
setInterval(watch, 3000)

// ---------------------------------------------------------------------------
// Monitor schedule (the cron workflow, run on an interval in the sandbox)
// ---------------------------------------------------------------------------

const MONITOR_EVERY_MS = Number(process.env.MONITOR_EVERY_MS ?? 0)
if (MONITOR_EVERY_MS > 0) setInterval(() => void bridge.enqueue({ ...WF.monitor }), MONITOR_EVERY_MS)

// ---------------------------------------------------------------------------
// Investor portfolio and business overview (signed-in views, read from the chain)
// ---------------------------------------------------------------------------

/** A signed-in investor: the browser sends the key it got when it signed up or signed in. */
function signedInInvestor(req: Request, lenderId: unknown): Lender {
  const lender = typeof lenderId === 'string' ? state.lenders.find((x) => x.id === lenderId) : undefined
  if (!lender) fail(404, 'We could not find this investor account. Sign in again to continue.')
  if (!sessionFor(lender, req.headers.get('x-investor-key'))) {
    fail(401, 'This browser is no longer signed in to the investor account. Sign in again to continue.')
  }
  return lender
}

/** Where to send a bank transfer for a deposit: the client funds account in the deposit's currency. */
const transferInstructions = (i: Intent) => ({
  beneficiary: 'Tradeflow Client Funds',
  iban: i.currency === 'EUR' ? 'DE89 3704 0044 0532 0130 00' : 'US-ACH 021000021 / 9988776655',
  reference: i.reference,
})

const regions = new Intl.DisplayNames(['en'], { type: 'region' })
const countryName = (code: string) => {
  try {
    return regions.of(code) ?? code
  } catch {
    return code
  }
}

/** Where an investor's identity check stands: the provider's decision, the latest KYC run and the registry. */
function identityOf(l: Lender, verifiedOnchain: boolean) {
  const input = JSON.stringify({ lenderId: l.id })
  const run = state.runs.find((r) => r.handler === WF.kyc.handler && r.input === input)
  const decided = run?.status === 'success' && run.resultData?.verified === false
  const status: 'verified' | 'pending' | 'rejected' = verifiedOnchain
    ? 'verified'
    : l.kycStatus === 'rejected' || decided
      ? 'rejected'
      : 'pending'
  const reason =
    status !== 'rejected'
      ? run?.status === 'failed'
        ? 'The identity check did not finish. Start it again.'
        : undefined
      : l.kycStatus === 'rejected'
        ? `Our identity provider does not accept residents of ${countryName(l.country)}, so this account cannot invest.`
        : typeof run?.resultData?.reason === 'string'
          ? run.resultData.reason
          : 'Your identity could not be verified, so this account cannot invest.'
  return { identityStatus: status, kycRunId: run?.id, ...(reason ? { kycReason: reason } : {}) }
}

const GRADES = 'ABCDE'
/** A position's status, from its loan's onchain status (1 Listed and 2 Funded both read as funded). */
const POSITION_STATUS: Record<number, 'funded' | 'active' | 'repaid' | 'late' | 'defaulted'> = {
  1: 'funded',
  2: 'funded',
  3: 'active',
  4: 'repaid',
  5: 'late',
  6: 'defaulted',
}

/** What an investor holds of each loan today: the balance of every loan's ERC-3643 token. */
async function notesByLoan(wallet: Address): Promise<Map<number, bigint>> {
  const count = Number(await chain.publicClient.readContract({ address: deployment.market, abi: marketAbi, functionName: 'loanCount' }))
  const held = await Promise.all(
    Array.from({ length: count }, async (_, i) => {
      const token = await chain.loanToken(i + 1)
      const notes = token ? await chain.publicClient.readContract({ address: token, abi: loanTokenAbi, functionName: 'balanceOf', args: [wallet] }) : 0n
      return [i + 1, notes] as const
    }),
  )
  return new Map(held.filter(([, n]) => n > 0n))
}

/**
 * An investor's portfolio. Positions come from the market's Funded events for the investor's wallet;
 * what they hold is the balance of each loan's ERC-3643 token, what they received is the payout of
 * their Claimed events (a USDC claim or a bank redemption, both burn the notes). Chain reads go out
 * together, so the client folds them into a few batched requests. When the event history cannot be
 * read, the portfolio still answers: positions from the notes held today (one note per USDC lent),
 * bank payouts from the payout books, and a warning that the history is incomplete.
 */
async function portfolioOf(lender: Lender) {
  const wallet = lender.wallet
  const market = deployment.market
  const key = (eventName: string) => `${eventName}|${wallet.toLowerCase()}`
  const principal = new Map<number, bigint>()
  const received = new Map<number, bigint>()
  const add = (m: Map<number, bigint>, id: number, v: bigint) => m.set(id, (m.get(id) ?? 0n) + v)
  let identity: Address | undefined
  let warning: string | undefined
  const [history, verifiedOnchain] = await Promise.all([
    Promise.all([
      scanLogs(key('Funded'), (fromBlock, toBlock) =>
        chain.publicClient.getContractEvents({ address: market, abi: marketAbi, eventName: 'Funded', args: { lender: wallet }, fromBlock, toBlock }),
      ),
      scanLogs(key('Claimed'), (fromBlock, toBlock) =>
        chain.publicClient.getContractEvents({ address: market, abi: marketAbi, eventName: 'Claimed', args: { lender: wallet }, fromBlock, toBlock }),
      ),
      scanLogs(key('IdentityRegistered'), (fromBlock, toBlock) =>
        chain.publicClient.getContractEvents({ address: market, abi: marketAbi, eventName: 'IdentityRegistered', args: { lender: wallet }, fromBlock, toBlock }),
      ),
    ]).catch((e: Error) => {
      console.error('portfolio history', e.message.split('\n')[0])
      return undefined
    }),
    isVerified(wallet),
  ])
  if (history) {
    const [fundedLogs, claimedLogs, identityLogs] = history
    for (const e of fundedLogs) add(principal, Number(e.args.loanId), e.args.amount ?? 0n)
    for (const e of claimedLogs) add(received, Number(e.args.loanId), e.args.payout ?? 0n)
    identity = identityLogs.at(-1)?.args.identity
  } else {
    warning = 'We could not load your full history just now, so positions you have been paid for may be missing. Refresh in a minute.'
    for (const [id, notes] of await notesByLoan(wallet)) principal.set(id, notes)
    for (const p of state.payouts) if (p.kind === 'lender' && p.beneficiaryId === lender.id && principal.has(p.loanId)) add(received, p.loanId, BigInt(p.amount))
  }

  const ids = [...principal.keys()].sort((a, b) => b - a) // newest loan first
  const reads = await Promise.all(
    ids.map(async (id) => {
      const [loan, token] = await Promise.all([chain.readLoan(BigInt(id)), chain.loanToken(id)])
      const notes = token ? await chain.publicClient.readContract({ address: token, abi: loanTokenAbi, functionName: 'balanceOf', args: [wallet] }) : 0n
      return { id, loan, token, notes }
    }),
  )

  const docs = new Map(state.documents.map((d) => [docHashOf(d), d]))
  const businesses = new Map(state.businesses.map((b) => [b.wallet.toLowerCase(), b]))
  const positions = reads.map(({ id, loan, token, notes }) => {
    const lent = principal.get(id)!
    const repaid = loan.status === 4
    // What the market pays per note: the lenders' share over the target (principal plus interest).
    const owed = repaid ? loan.repaidAmount : dueOf(loan)
    const expected = loan.target > 0n ? (lent * owed) / loan.target : lent
    const claimable = repaid && lender.funding === 'stablecoin' && notes > 0n ? (notes * loan.repaidAmount) / loan.target : 0n
    const doc = docs.get(loan.docHash)
    const payout = state.payouts.find((p) => p.kind === 'lender' && p.beneficiaryId === lender.id && p.loanId === id)
    return {
      loanId: id,
      ref: loan.ref,
      title: doc?.title ?? loan.ref,
      businessName: businesses.get(loan.borrower.toLowerCase())?.name ?? '',
      grade: GRADES[loan.riskGrade - 1] ?? '',
      aprBps: loan.aprBps,
      tenorDays: loan.tenorDays,
      status: POSITION_STATUS[loan.status] ?? 'funded',
      loanStatus: loan.status,
      maturity: loan.maturity, // unix seconds, 0 until the business is paid
      dueDate: doc?.dueDate,
      token: token ?? null,
      symbol: `TFN${id}`,
      notes,
      principalUsd6: lent,
      expectedUsd6: expected,
      receivedUsd6: received.get(id) ?? 0n,
      claimableUsd6: claimable,
      ...(payout ? { payoutRef: payout.payoutRef } : {}),
    }
  })

  const sum = (xs: typeof positions, f: (p: (typeof positions)[number]) => bigint) => xs.reduce((t, p) => t + f(p), 0n)
  // Still working: the principal is out and the payout is to come (raising, funded, active or late).
  const open = positions.filter((p) => [1, 2, 3, 5].includes(p.loanStatus))
  return {
    lender: { ...publicLender(lender), verifiedOnchain, ...(identity ? { identity } : {}), ...identityOf(lender, verifiedOnchain) },
    ...(warning ? { warning } : {}),
    positions,
    deposits: state.intents
      .filter((i) => i.lenderId === lender.id)
      .map((i) => ({
        reference: i.reference,
        loanId: i.loanId,
        amountMinor: i.amountMinor,
        currency: i.currency,
        status: i.status,
        ...(i.fxRateE8 ? { fxRateE8: i.fxRateE8 } : {}),
        ...(i.stablecoinAmount ? { stablecoinAmount: i.stablecoinAmount } : {}),
        createdAt: i.createdAt,
        ...(i.status === 'awaiting_funds' ? { instructions: transferInstructions(i) } : {}),
      })),
    totals: {
      investedUsd6: sum(open, (p) => p.principalUsd6), // principal in active loans
      expectedUsd6: sum(open, (p) => p.expectedUsd6 - p.principalUsd6), // interest still to come
      receivedUsd6: sum(positions, (p) => p.receivedUsd6),
      claimableUsd6: sum(positions, (p) => p.claimableUsd6),
    },
  }
}

/** Every loan the market lists for a borrower wallet, read in one batch. */
async function loansOf(borrower: Address) {
  const count = Number(await chain.publicClient.readContract({ address: deployment.market, abi: marketAbi, functionName: 'loanCount' }))
  const loans = await Promise.all(Array.from({ length: count }, async (_, i) => ({ id: i + 1, ...(await chain.readLoan(BigInt(i + 1))) })))
  return loans.filter((l) => l.borrower.toLowerCase() === borrower.toLowerCase())
}
/** A document's face value in USD (6 decimals), at the rate the loan was listed with. */
const faceUsd6 = (l: { faceValueMinor: bigint; fxRateE8: bigint }) => (l.faceValueMinor * (l.fxRateE8 > 0n ? l.fxRateE8 : 100_000_000n)) / 10_000n

/** The business's own documents with their loans, and its overview: totals, the next item due, frozen or not. */
async function businessView(business: Business) {
  const own = state.documents.filter((d) => d.businessId === business.id)
  const [loans, frozen] = await Promise.all([
    loansOf(business.wallet),
    chain.publicClient.readContract({ address: deployment.market, abi: marketAbi, functionName: 'frozenBorrower', args: [business.wallet] }),
  ])
  const byHash = new Map<Hex, (typeof loans)[number]>()
  for (const l of loans) byHash.set(l.docHash, l) // the newest loan wins, as in loanFor
  const documents = own.map((doc) => {
    const { review: _r, ...d } = doc
    const docHash = docHashOf(doc)
    const loan = doc.status === 'confirmed' ? byHash.get(docHash) : undefined
    return {
      ...d,
      docHash,
      buyerLink: buyerLink(doc),
      review: reviewOf(doc),
      ...(loan ? { loan: { id: loan.id, status: loan.status, maturity: loan.maturity, target: loan.target, funded: loan.funded } } : {}),
    }
  })

  const OWED = [3, 5, 6] // paid out to the business, not yet repaid by the buyer: Disbursed, Late, Defaulted
  const total = (xs: typeof loans, f: (l: (typeof loans)[number]) => bigint) => xs.reduce((t, l) => t + f(l), 0n)
  const due = own
    .flatMap((doc) => {
      const loan = doc.status === 'confirmed' ? byHash.get(docHashOf(doc)) : undefined
      return loan && OWED.includes(loan.status) ? [{ doc, loan }] : []
    })
    .sort((a, b) => (a.loan.maturity === b.loan.maturity ? a.doc.dueDate.localeCompare(b.doc.dueDate) : a.loan.maturity < b.loan.maturity ? -1 : 1))[0]
  const overview = {
    advancedUsd6: total(loans.filter((l) => l.status >= 3), (l) => l.funded), // paid out to the business
    outstandingUsd6: total(loans.filter((l) => OWED.includes(l.status)), faceUsd6), // still owed by buyers
    repaidUsd6: total(loans.filter((l) => l.status === 4), faceUsd6), // paid by buyers
    inReview: documents.filter((d) => d.review?.status === 'in_review').length,
    frozen,
    ...(due
      ? {
          nextDue: {
            docNumber: due.doc.number,
            buyer: due.doc.buyer,
            dueDate: due.doc.dueDate,
            amountMinor: due.doc.amountMinor,
            currency: due.doc.currency,
            loanId: due.loan.id,
            maturity: due.loan.maturity,
            late: due.loan.status !== 3,
          },
        }
      : {}),
  }
  return { business: ownBusiness(business), documents, overview }
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

// The /api/state body: market reads (batched into Multicall3) plus the rails books.
/**
 * Serve the last good value at once and refresh it in the background, one refresh at a time.
 * Public RPCs throttle hard; nothing a person clicks should wait on them. The first call waits.
 */
function swr<T>(build: () => Promise<T>, ttlMs: number) {
  let value: T | undefined
  let at = 0
  let pending: Promise<T> | undefined
  const refresh = () =>
    (pending ??= build()
      .then((v) => ((value = v), (at = Date.now()), v))
      .finally(() => (pending = undefined)))
  return {
    get(): Promise<T> {
      if (value === undefined) return refresh()
      if (Date.now() - at > ttlMs) void refresh().catch((e: Error) => console.error('refresh', e.message.split('\n')[0]))
      return Promise.resolve(value)
    },
    stale() {
      at = 0
    },
  }
}

// The market's state from the chain: loans, the snapshot and the funding history.
const chainState = swr(async () => {
  const snap = await chain.marketSnapshot()
  const count = Number(snap.loanCount)
  const loans = await Promise.all(
    Array.from({ length: count }, async (_, i) => {
      const id = BigInt(i + 1)
      const [l, loanToken] = await Promise.all([chain.readLoan(id), chain.loanToken(i + 1).catch(() => undefined)])
      return { id: i + 1, ...l, loanToken: loanToken ?? null } // loanToken: the loan's ERC-3643 token (its notes)
    }),
  )
  const fundingEvents = await scanLogs('Funded|*', (fromBlock, toBlock) =>
    chain.publicClient.getContractEvents({ address: deployment.market, abi: marketAbi, eventName: 'Funded', fromBlock, toBlock }),
  ).catch(() => [])
  return { snapshot: snap, loans, fundings: fundingEvents.map((e) => ({ ...e.args, tx: e.transactionHash })) }
}, 3_000)

// Portfolios, one cache per investor.
const portfolios = new Map<string, ReturnType<typeof swr<unknown>>>()
const cachedPortfolio = (lender: Lender) => {
  let p = portfolios.get(lender.id)
  if (!p) portfolios.set(lender.id, (p = swr<unknown>(() => portfolioOf(lender), 4_000)))
  return p.get()
}

chainChanged = () => {
  chainState.stale()
  for (const p of portfolios.values()) p.stale()
}

/** /api/state: the chain part from the cache, everything the app keeps itself always current. */
async function cachedState() {
  const onchain = await chainState.get()
  const credited = state.intents.filter((i) => i.status === 'credited')
  const sum = (xs: Intent[]) => xs.reduce((t, i) => t + BigInt(i.stablecoinAmount ?? '0'), 0n)
  const books = {
    bankUsd6: (sum(credited) + state.ledgerAdjustments.reduce((t, a) => t + BigInt(a.usd6), 0n)).toString(),
    onrampUsd6: sum(credited.filter((i) => i.mintTx)).toString(),
  }
  return {
    ...onchain,
    books,
    businesses: state.businesses.map(publicBusiness),
    documents: state.documents.map(publicDocument),
    lenders: state.lenders.map(publicLender),
    intents: state.intents,
    payouts: state.payouts,
    bankCredits: state.bankCredits,
    listings: state.listings,
    ledgerAdjustments: state.ledgerAdjustments,
    queue: bridge.queueLength(),
  }
}

const server = Bun.serve({
  port: PORT,
  idleTimeout: 255, // some calls wait for a workflow run to finish
  routes: {
    '/': index,
    '/investor': index,
    '/investor/*': index,
    '/business': index,
    '/business/*': index,
    '/loans/*': index, // older links; the app sends them to /investor/loans/:id
    '/buyer/*': index,
    '/ops': index,

    // ---------------- registry, credit, sanctions (listing workflow) ----------------
    '/v1/registry/verify': {
      POST: async (req) => {
        if (!authed(req)) return unauthorized()
        const body = (await req.json()) as { docNumber: string; borrowerId: string }
        const doc = state.documents.find((d) => d.businessId === body.borrowerId && d.number === body.docNumber)
        if (!doc) return json({ valid: false, reason: 'document not found for this business' })
        return json({
          valid: true,
          status: doc.status,
          buyerConfirmed: doc.status === 'confirmed',
          disputed: doc.status === 'disputed',
          docType: doc.type,
          buyer: doc.buyer,
          buyerCountry: doc.buyerCountry,
          amountMinor: doc.amountMinor,
          currency: doc.currency,
          issuedAt: doc.issuedAt,
          dueInDays: Math.max(1, daysUntil(doc.dueDate)),
          docHash: docHashOf(doc),
        })
      },
    },
    '/v1/credit/:borrowerId': {
      GET: (req) => {
        if (!authed(req)) return unauthorized()
        const b = state.businesses.find((x) => x.id === req.params.borrowerId)
        if (!b) return json({ error: 'unknown business' }, 404)
        return json({ borrowerId: b.id, name: b.name, country: b.country, wallet: b.wallet, ...bureauFile(b.country, b.registrationNumber) })
      },
    },
    '/v1/sanctions/screen': {
      POST: async (req) => {
        if (!authed(req)) return unauthorized()
        const body = (await req.json()) as { name: string; country: string }
        const hit = /blocked|sanctioned/i.test(body.name)
        return json({ match: hit, lists: ['OFAC SDN', 'UN Consolidated', 'EU FSF'], screenedName: body.name })
      },
    },

    // ---------------- KYC + on-ramp (lender workflow) ----------------
    '/v1/kyc/:lenderId': {
      GET: (req) => {
        if (!authed(req)) return unauthorized()
        const l = state.lenders.find((x) => x.id === req.params.lenderId)
        if (!l) return json({ error: 'unknown lender' }, 404)
        return json({ lenderId: l.id, status: l.kycStatus, level: l.kycLevel, wallet: l.wallet, country: l.country })
      },
    },
    '/v1/onramp/deposits/:reference': {
      GET: (req) => {
        if (!authed(req)) return unauthorized()
        const i = state.intents.find((x) => x.reference === req.params.reference)
        if (!i) return json({ error: 'unknown reference' }, 404)
        const lender = state.lenders.find((l) => l.id === i.lenderId)
        if (!lender) return json({ error: 'unknown lender' }, 404)
        return json({
          reference: i.reference,
          status: i.status,
          lenderId: i.lenderId,
          wallet: lender.wallet,
          loanId: i.loanId,
          fiatAmountMinor: i.amountMinor,
          currency: i.currency,
          fxRateE8: i.fxRateE8 ?? '0',
          stablecoinAmount: i.stablecoinAmount ?? '0',
          mintTx: i.mintTx ?? '',
          destination: deployment.market,
        })
      },
    },
    // The on-ramp converts a received transfer and delivers the USDC to the market, only when the
    // lender workflow instructs it (Confidential HTTP). Idempotent by reference; refuses a rate below
    // the workflow's limit, which the workflow derives from Chainlink's EUR/USD feed.
    '/v1/onramp/conversions': {
      POST: async (req) => {
        if (!authed(req)) return unauthorized()
        const b = (await req.json()) as { reference: string; destination: string; minRateE8: string; idempotencyKey: string }
        const i = state.intents.find((x) => x.reference === b.reference)
        if (!i) return json({ error: 'unknown reference' }, 404)
        const done = () => json({ status: 'settled', fxRateE8: i.fxRateE8, stablecoinAmount: i.stablecoinAmount, mintTx: i.mintTx, destination: deployment.market, duplicate: true })
        if ((i.status === 'settled' || i.status === 'credited') && i.mintTx) return done()
        if (i.status !== 'received') return json({ error: `transfer is ${i.status}, not received` }, 409)
        if (String(b.destination).toLowerCase() !== deployment.market.toLowerCase()) return json({ error: 'unsupported destination' }, 400)
        if (converting.has(i.reference)) return json({ error: 'conversion in progress' }, 409)
        converting.add(i.reference)
        try {
          const rate = await ccyRateE8(i.currency)
          if (rate < BigInt(b.minRateE8 || '0')) {
            railsLog('on-ramp', `${i.reference}: rate ${(Number(rate) / 1e8).toFixed(4)} is below the instructed limit, not converted`)
            return json({ error: 'rate below the instructed limit' }, 409)
          }
          const usd = toUsd6(i.amountMinor, rate)
          railsLog('on-ramp', `${i.reference}: instructed to convert ${fiatText(i.amountMinor, i.currency)} at ${(Number(rate) / 1e8).toFixed(4)} (limit ${(Number(b.minRateE8) / 1e8).toFixed(4)})`)
          const mintTx = await chain.onRampMint(usd)
          Object.assign(i, { status: 'settled', fxRateE8: rate.toString(), stablecoinAmount: usd.toString(), mintTx, settledAt: nowIso() })
          persist()
          broadcast('rails', { kind: 'conversion', intent: i })
          railsLog('on-ramp', `${i.reference}: delivered ${(Number(usd) / 1e6).toFixed(2)} USDC to the market, tx ${mintTx}`)
          return json({ status: 'settled', fxRateE8: i.fxRateE8, stablecoinAmount: i.stablecoinAmount, mintTx, destination: deployment.market })
        } finally {
          converting.delete(i.reference)
        }
      },
    },
    '/v1/onramp/lenders': {
      GET: (req) => {
        if (!authed(req)) return unauthorized()
        const loanId = Number(new URL(req.url).searchParams.get('loanId'))
        const fiat = state.intents.filter((i) => i.loanId === loanId && i.status === 'credited')
        const ids = [...new Set(fiat.map((i) => i.lenderId))]
        return json({
          loanId,
          lenders: ids.flatMap((id) => {
            const l = state.lenders.find((x) => x.id === id)
            return l ? [{ lenderId: l.id, wallet: l.wallet, bankAccount: l.bankAccount ?? '' }] : []
          }),
        })
      },
    },

    // ---------------- repayment sources + payouts (settlement workflow) ----------------
    '/v1/bank/credits': {
      GET: (req) => {
        if (!authed(req)) return unauthorized()
        const reference = new URL(req.url).searchParams.get('reference')
        return json({ entries: state.bankCredits.filter((c) => c.reference === reference) })
      },
    },
    '/v1/psp/payments/:reference': {
      GET: (req) => {
        if (!authed(req)) return unauthorized()
        const p = state.pspPayments.find((x) => x.reference === req.params.reference)
        if (!p) return json({ error: 'unknown payment' }, 404)
        return json(p)
      },
    },
    '/v1/payouts': {
      POST: async (req) => {
        if (!authed(req)) return unauthorized()
        const body = (await req.json()) as Omit<Payout, 'payoutRef' | 'createdAt'>
        const existing = state.payouts.find((p) => p.idempotencyKey === body.idempotencyKey)
        if (existing) return json({ payoutRef: existing.payoutRef, status: 'sent', duplicate: true })
        const payout: Payout = {
          idempotencyKey: String(body.idempotencyKey),
          kind: body.kind === 'business' ? 'business' : 'lender',
          loanId: Number(body.loanId),
          beneficiaryId: String(body.beneficiaryId),
          amount: String(body.amount),
          payoutRef: `PO-${body.kind === 'business' ? 'B' : 'L'}-${String(state.payouts.length + 1).padStart(5, '0')}`,
          createdAt: nowIso(),
        }
        state.payouts.push(payout)
        railsLog('payouts', `${payout.payoutRef}: ${payout.kind === 'business' ? 'business' : 'lender'} payout of ${(Number(payout.amount) / 1e6).toFixed(2)} USD instructed by CRE, loan ${payout.loanId}`)
        persist()
        broadcast('rails', { kind: 'payout', payout })
        return json({ payoutRef: payout.payoutRef, status: 'sent', duplicate: false })
      },
    },

    // ---------------- operator books (monitor workflow) ----------------
    '/v1/ledger/summary': {
      GET: (req) => {
        if (!authed(req)) return unauthorized()
        // Bank books: deposits received and credited (plus any manual bookings).
        // On-ramp books: stablecoins minted for those deposits.
        const credited = state.intents.filter((i) => i.status === 'credited')
        const inFlightDeposits = state.intents.filter((i) => i.status === 'settled')
        const sum = (xs: Intent[]) => xs.reduce((s, i) => s + BigInt(i.stablecoinAmount ?? '0'), 0n)
        const bankUsd6 = sum(credited) + state.ledgerAdjustments.reduce((s, a) => s + BigInt(a.usd6), 0n)
        const onrampUsd6 = sum(credited.filter((i) => i.mintTx))
        return json({
          bankUsd6: bankUsd6.toString(),
          onrampUsd6: onrampUsd6.toString(),
          creditedDeposits: credited.length,
          inFlightDeposits: inFlightDeposits.length,
          inFlightUsd6: sum(inFlightDeposits).toString(),
        })
      },
    },

    // ---------------- app: config, state, runs ----------------
    '/api/config': {
      GET: async () =>
        json({
          deployment,
          deploymentName: DEPLOYMENT,
          // The browser gets a public endpoint; the server's own RPC_URL may carry a provider key.
          rpcUrl: process.env.PUBLIC_RPC_URL ?? RPC_URL,
          explorer: process.env.EXPLORER ?? null,
          chainId: deployment.chainId,
          builtinWallets: BUILTIN_WALLETS,
          // ERC-3643: the identity registry every loan token checks, and the claim issuer CRE writes KYC claims through.
          identityRegistry: deployment.identityRegistry ?? (await chain.identityRegistry().catch(() => null)),
          claimIssuer: deployment.claimIssuer ?? (await chain.claimIssuer().catch(() => null)),
        }),
    },
    '/api/state': { GET: async () => json(await cachedState()) },
    '/api/runs': { GET: () => json(state.runs.slice(0, 60)) },
    '/api/runs/:id': {
      GET: (req) => json(state.runs.find((r) => r.id === Number(req.params.id)) ?? fail(404, 'No run with that id.')),
    },

    // ---------------- businesses and their documents ----------------

    // A business signs up. The response carries the key this browser uses to stay signed in.
    '/api/businesses': {
      POST: async (req) => {
        const b = await body<{ name: string; country: string; registrationNumber: string; bankAccount: string; email: string }>(req)
        const name = text(b.name, 120) || fail(400, 'Enter the legal name of your business.')
        const country = countryCode(b.country) ?? fail(400, 'Choose the country where your business is registered.')
        const registrationNumber = text(b.registrationNumber, 40)
        if (!normalizeRegistration(registrationNumber)) fail(400, 'Enter your company registration number.')
        const bankAccount = text(b.bankAccount, 60) || fail(400, 'Enter the bank account where advances should be paid.')
        const email = text(b.email, 120).toLowerCase()
        if (!EMAIL.test(email)) fail(400, 'Enter a valid work email, for example finance@yourcompany.com.')

        const reg = normalizeRegistration(registrationNumber)
        if (state.businesses.some((x) => x.country === country && normalizeRegistration(x.registrationNumber) === reg)) {
          fail(409, 'A business with this registration number is already registered. Sign in with the work email on file instead.')
        }

        const id = `biz-${slug(name)}-${suffix()}`
        const business: Business = { id, name, country, registrationNumber, bankAccount, email, wallet: custodyWallet(id), sessions: [], createdAt: nowIso() }
        state.businesses.unshift(business)
        const key = issueSession(business)
        broadcast('rails', { kind: 'business', id })
        return json({ business: ownBusiness(business), key }, 201)
      },
    },

    // A registered business signs in again: country, registration number and the work email on file.
    '/api/business-sessions': {
      POST: async (req) => {
        const b = await body<{ country: string; registrationNumber: string; email: string }>(req)
        const country = countryCode(b.country) ?? fail(400, 'Choose the country where your business is registered.')
        const reg = normalizeRegistration(text(b.registrationNumber, 40))
        if (!reg) fail(400, 'Enter your company registration number.')
        const email = text(b.email, 120).toLowerCase()
        if (!EMAIL.test(email)) fail(400, 'Enter the work email you signed up with, for example finance@yourcompany.com.')
        const business = state.businesses.find((x) => x.country === country && normalizeRegistration(x.registrationNumber) === reg)
        if (!business || !sameHash(sha256(business.email), sha256(email))) {
          fail(401, 'No business matches this country, registration number and work email. Check them and try again.')
        }
        return json({ business: ownBusiness(business), key: issueSession(business, { unproven: true }) })
      },
    },

    // The business's own view (signed in): its documents with their buyer links, review status and
    // loan once listed, and the overview (advanced, owed by buyers, repaid, in review, next due).
    '/api/businesses/:id': {
      GET: async (req) => json(await businessView(signedIn(req, req.params.id))),
    },
    // Signing out: the key this browser holds stops working.
    '/api/businesses/:id/sign-out': {
      POST: (req) => {
        endSession(signedIn(req, req.params.id), req.headers.get('x-business-key'))
        return json({ ok: true })
      },
    },

    // A business enters a document for financing. The buyer confirms it through the buyer link.
    '/api/documents': {
      POST: async (req) => {
        const b = await body<{
          businessId: string
          type: DocType
          number: string
          buyer: string
          buyerEmail: string
          buyerCountry: string
          amountMinor: number
          currency: 'EUR' | 'USD'
          issuedAt: string
          dueDate: string
          description: string
          file: { name?: string; type?: string; base64?: string }
        }>(req)
        const business = signedIn(req, b.businessId)
        const type = DOC_TYPES.includes(b.type as DocType) ? (b.type as DocType) : fail(400, 'Choose a document type: invoice, bill of lading or equipment order.')
        const number = text(b.number, 64) || fail(400, 'Enter the document number.')
        const buyer = text(b.buyer, 120) || fail(400, "Enter the buyer's legal name.")
        const buyerEmail = text(b.buyerEmail, 120).toLowerCase()
        if (!EMAIL.test(buyerEmail)) fail(400, "Enter the buyer's email address, for example payables@buyer.com.")
        const buyerCountry = countryCode(b.buyerCountry) ?? fail(400, "Choose the buyer's country.")
        const amountMinor = Number(b.amountMinor)
        if (!Number.isInteger(amountMinor) || amountMinor < 100 || amountMinor > 500_000_000) {
          fail(400, 'Enter an amount between 1.00 and 5,000,000.00.')
        }
        const currency = b.currency === 'EUR' || b.currency === 'USD' ? b.currency : fail(400, 'Choose the currency: EUR or USD.')
        const issuedAt = isoDate(b.issuedAt) ?? fail(400, 'Enter the issue date.')
        const dueDate = isoDate(b.dueDate) ?? fail(400, 'Enter the due date.')
        if (dueDate <= issuedAt) fail(400, 'The due date must be after the issue date.')
        const days = daysUntil(dueDate)
        if (days < -1) fail(400, 'The due date has passed. Only documents that are still to be paid can be financed.')
        if (days > 366) fail(400, 'The due date must be within a year from today.')
        const description = text(b.description, 200) || fail(400, 'Describe what is being sold, for example "4 containers of washed Arabica".')
        if (description.length > 120) fail(400, 'Keep the description to 120 characters or fewer.')

        const num = normalizeRegistration(number)
        const duplicate = state.documents.find(
          (d) =>
            normalizeRegistration(d.number) === num &&
            (normalizeBuyer(d.buyer) === normalizeBuyer(buyer) || d.businessId === business.id),
        )
        if (duplicate) fail(409, 'This document is already registered.')

        let fileName: string | undefined
        let fileSha256: string | undefined
        let bytes: Buffer | undefined
        if (b.file) {
          const base64 = text(b.file.base64, 8 * 1024 * 1024).replace(/^data:[^,]*,/, '')
          bytes = Buffer.from(base64, 'base64')
          if (bytes.length === 0) fail(400, 'The attached file is empty. Attach the document as a PDF, PNG or JPG.')
          if (bytes.length > MAX_FILE_BYTES) fail(400, 'The attached file is larger than 5 MB. Attach a smaller file.')
          const kind = fileKind(bytes) ?? fail(400, 'Attach the document as a PDF, PNG or JPG file.')
          fileSha256 = createHash('sha256').update(bytes).digest('hex')
          const base = text(b.file.name, 200).split(/[\\/]/).pop()!.replace(/\.[^.]*$/, '')
          fileName = `${base.replace(/[^A-Za-z0-9._-]+/g, '_').slice(0, 80) || 'document'}.${kind.ext}`
        }

        const doc: FinDocument = {
          number,
          type,
          businessId: business.id,
          buyer,
          buyerEmail,
          buyerCountry,
          amountMinor,
          currency,
          issuedAt,
          dueDate,
          dueInDays: Math.max(1, days),
          title: TITLE_PREFIX[type] + description,
          ...(fileName ? { fileName, fileSha256 } : {}),
          status: 'awaiting_buyer',
          token: newToken(),
          createdAt: nowIso(),
        }
        // Written synchronously: nothing may run between the duplicate check above and the insert below.
        if (bytes) {
          mkdirSync(`${UPLOADS_DIR}/${business.id}`, { recursive: true })
          writeFileSync(uploadPath(doc), bytes)
        }
        state.documents.unshift(doc)
        persist()
        broadcast('rails', { kind: 'document', number: doc.number, status: doc.status })
        return json({ document: { ...doc, docHash: docHashOf(doc) }, buyerLink: buyerLink(doc) }, 201)
      },
    },

    // Start the review again when the last listing run did not finish (the workflow never decided).
    '/api/documents/review': {
      POST: async (req) => {
        const b = await body<{ businessId: string; number: string }>(req)
        const business = signedIn(req, b.businessId)
        const doc =
          state.documents.find((d) => d.businessId === business.id && d.number === b.number) ?? fail(404, 'We could not find that document. Refresh the page and try again.')
        if (doc.status === 'awaiting_buyer') fail(409, 'The buyer has not responded yet. The review starts when they do.')
        const review = reviewOf(doc)
        if (review?.status === 'in_review') fail(409, 'This document is being reviewed now.')
        if (review?.status !== 'failed') fail(409, 'This document has already been reviewed.')
        if (await loanFor(doc)) fail(409, 'This document is already listed.')
        return json({ ok: true, runId: submitListing(doc) })
      },
    },

    // ---------------- buyer portal ----------------
    '/api/buyer/:token': {
      GET: async (req) => {
        const doc = docByToken(req.params.token)
        const business = state.businesses.find((x) => x.id === doc.businessId)
        const loan = await loanFor(doc)
        const payment = loan ? state.pspPayments.find((p) => p.loanId === loan.id) : undefined
        // The buyer learns only whether the document is financed, never why a review said no.
        const review = loan ? undefined : reviewOf(doc)
        return json({
          document: publicDocument(doc),
          business: { name: business?.name ?? '', country: business?.country ?? '' },
          financing: loan ? 'financed' : review?.status === 'rejected' ? 'not_financed' : review ? 'in_review' : undefined,
          loan: loan && {
            id: loan.id,
            status: loan.status,
            maturity: loan.maturity,
            repaidAt: loan.repaidAt,
          },
          payment: payment && { amountMinor: payment.amountMinor, currency: payment.currency, capturedAt: payment.capturedAt },
          collection: loan && { ...COLLECTION[doc.currency], reference: doc.number },
        })
      },
    },
    '/api/buyer/:token/file': {
      GET: async (req) => {
        const doc = docByToken(req.params.token)
        if (!doc.fileName || !doc.fileSha256) fail(404, 'No file was attached to this document.')
        const file = Bun.file(uploadPath(doc))
        if (!(await file.exists())) fail(404, 'The attached file is no longer available. Ask your supplier to send it again.')
        const kind = FILE_KINDS.find((k) => doc.fileName!.endsWith(`.${k.ext}`))
        return new Response(file, {
          headers: { 'content-type': kind?.type ?? 'application/octet-stream', 'content-disposition': `inline; filename="${doc.fileName}"` },
        })
      },
    },

    // The buyer confirms the document: the listing workflow reviews and lists it.
    '/api/buyer/:token/confirm': {
      POST: async (req) => {
        const doc = docByToken(req.params.token)
        const b = await body<{ name: string }>(req, true)
        if (doc.status !== 'awaiting_buyer') {
          fail(409, doc.status === 'confirmed' ? 'This document was already confirmed.' : 'This document was already disputed.')
        }
        doc.status = 'confirmed'
        doc.respondedAt = nowIso()
        doc.respondedBy = text(b.name, 120) || doc.buyer
        return json({ ok: true, runId: submitListing(doc) })
      },
    },

    // The buyer disputes the document: the listing workflow records the rejection.
    '/api/buyer/:token/dispute': {
      POST: async (req) => {
        const doc = docByToken(req.params.token)
        const b = await body<{ reason: string; name: string }>(req, true)
        if (doc.status !== 'awaiting_buyer') {
          fail(409, doc.status === 'confirmed' ? 'This document was already confirmed.' : 'This document was already disputed.')
        }
        const reason = text(b.reason, 500) || fail(400, 'Tell your supplier why you are disputing this document.')
        doc.status = 'disputed'
        doc.respondedAt = nowIso()
        doc.respondedBy = text(b.name, 120) || doc.buyer
        doc.disputeReason = reason
        return json({ ok: true, runId: submitListing(doc) })
      },
    },

    // The buyer pays the full document amount, in its currency, to the collection account. The
    // payment is captured by the buyer's processor and lands in the collection bank; the lenders'
    // share (advance plus interest) is on-ramped into the market, and CRE confirms the payment from
    // both sources, repays the lenders and pays the balance to the business.
    '/api/buyer/:token/pay': {
      POST: async (req) => {
        const doc = docByToken(req.params.token)
        const noun = doc.type === 'invoice' ? 'invoice' : doc.type === 'bill_of_lading' ? 'bill of lading' : 'equipment order'
        const loan = (await loanFor(doc)) ?? fail(409, `This ${noun} has not been financed, so there is nothing to pay through Tradeflow.`)
        if (loan.status === 4) fail(409, `This ${noun} is already paid.`)
        if (loan.status !== 3 && loan.status !== 5) fail(409, `This ${noun} can be paid once your supplier has received the advance.`)
        const loanId = loan.id

        return exclusive(`pay-${loanId}`, 'Your payment is being confirmed. This page updates when it is done.', async () => {
          // A payment already captured is never taken twice: if its confirmation failed, notify again.
          const earlier = state.pspPayments.find((p) => p.loanId === loanId)
          if (earlier) {
            const input = { loanId, reference: earlier.reference }
            if (inFlight(WF.repayment.handler, JSON.stringify(input))) fail(409, 'Your payment is being confirmed. This page updates when it is done.')
            const run = await bridge.enqueue({ ...WF.repayment, httpPayload: input, loanId })
            return json({ reference: earlier.reference, amountMinor: earlier.amountMinor, currency: earlier.currency, runId: run.id, run })
          }

          const { amountMinor, currency } = doc
          const reference = `PAY-${loanId}-${Date.now().toString(36).toUpperCase()}`
          const payer = doc.buyer
          const psp: PspPayment = { reference, status: 'captured', amountMinor, currency, payer, capturedAt: nowIso(), loanId }
          const credit: BankCredit = { reference, amountMinor, currency, payer, valueDate: nowIso(), kind: 'repayment' }
          let mintTx: Hash
          try {
            mintTx = await chain.onRampMint(dueOf(loan)) // the lenders' share; the balance stays in fiat for the business
          } catch {
            fail(502, 'We could not take your payment just now. Nothing was charged. Try again in a moment.')
          }
          state.pspPayments.push(psp)
          state.bankCredits.push(credit)
          persist()
          broadcast('rails', { kind: 'repayment', reference, amountMinor, currency, mintTx })
          railsLog('payment processor', `${payer} paid ${fiatText(amountMinor, currency)}, reference ${reference}, captured`)
          railsLog('bank', `${fiatText(amountMinor, currency)} credited to the collection account; lenders' share on-ramped to the market, tx ${mintTx}`)
          const run = await bridge.enqueue({ ...WF.repayment, httpPayload: { loanId, reference }, loanId })
          return json({ reference, amountMinor, currency, mintTx, runId: run.id, run })
        })
      },
    },

    // ---------------- lenders ----------------

    // A lender with a browser wallet asks for a one-time message to sign, proving the wallet is theirs.
    '/api/lenders/challenge': {
      POST: async (req) => {
        const b = await body<{ wallet: string }>(req)
        const w = text(b.wallet)
        if (!isAddress(w, { strict: false })) fail(400, 'Connect a wallet to lend with USDC.')
        return json(challengeFor(getAddress(w)))
      },
    },

    // A lender signs up: the KYC provider decides, the lender workflow verifies the wallet onchain.
    // USDC lenders prove the wallet is theirs: a signed challenge (browser wallet) or the wallet key (built-in wallet).
    '/api/lenders': {
      POST: async (req) => {
        const b = await body<{
          name: string
          email: string
          country: string
          funding: 'fiat' | 'stablecoin'
          wallet: string
          bankAccount: string
          nonce: string
          signature: string
        }>(req)
        const name = text(b.name, 120) || fail(400, 'Enter your full name.')
        const email = text(b.email, 120).toLowerCase()
        if (!EMAIL.test(email)) fail(400, 'Enter a valid email address, for example ana@example.com.')
        const country = countryCode(b.country) ?? fail(400, 'Choose the country you live in.')
        const funding = b.funding === 'fiat' || b.funding === 'stablecoin' ? b.funding : fail(400, 'Choose how you will fund: bank transfer or USDC.')

        let wallet: Address | undefined
        let bankAccount: string | undefined
        let existing: Lender | undefined
        if (funding === 'stablecoin') {
          const w = text(b.wallet)
          if (!isAddress(w, { strict: false })) fail(400, 'Connect a wallet to lend with USDC.')
          wallet = getAddress(w)
          if (req.headers.get('x-wallet-key')) builtinFor(req, wallet)
          else if (!(await provesWallet(wallet, b.nonce, b.signature))) {
            fail(401, 'We could not confirm this wallet is yours. Sign the message in your wallet, then try again.')
          }
          existing = state.lenders.find((l) => l.wallet.toLowerCase() === wallet!.toLowerCase())
        } else {
          bankAccount = text(b.bankAccount, 60) || fail(400, 'Enter the bank account where repayments should be paid, for example your IBAN.')
          existing = state.lenders.find((l) => l.funding === 'fiat' && l.email === email)
        }
        if (existing) {
          // Signing back in: verify again only if the wallet is not verified onchain yet.
          const runId = (await isVerified(existing.wallet)) ? undefined : runKyc(existing)
          return json({ lender: publicLender(existing), runId, key: issueSession(existing, { unproven: funding === 'fiat' }) })
        }

        const id = `lender-${slug(name)}-${suffix()}`
        const decision = kycDecision(country, funding)
        const lender: Lender = {
          id,
          name,
          email,
          country,
          funding,
          wallet: wallet ?? custodyWallet(id),
          ...(bankAccount ? { bankAccount } : {}),
          kycStatus: decision.status,
          kycLevel: decision.level,
          sessions: [],
          createdAt: nowIso(),
        }
        state.lenders.unshift(lender)
        const key = issueSession(lender)
        broadcast('rails', { kind: 'lender', id })
        return json({ lender: publicLender(lender), runId: runKyc(lender), key }, 201)
      },
    },

    // An investor signs in again. Bank-transfer investors by the email they signed up with; USDC
    // investors by proving the wallet is theirs (a signed challenge, or the built-in wallet's key).
    '/api/investors/sign-in': {
      POST: async (req) => {
        const b = await body<{ email: string; wallet: string; nonce: string; signature: string }>(req)
        if (text(b.wallet)) {
          const w = text(b.wallet)
          if (!isAddress(w, { strict: false })) fail(400, 'Connect the wallet you invest with, then sign in.')
          const wallet = getAddress(w)
          if (req.headers.get('x-wallet-key')) builtinFor(req, wallet)
          else if (!(await provesWallet(wallet, b.nonce, b.signature))) {
            fail(401, 'We could not confirm this wallet is yours. Sign the message in your wallet, then try again.')
          }
          const lender =
            state.lenders.find((l) => l.funding === 'stablecoin' && l.wallet.toLowerCase() === wallet.toLowerCase()) ??
            fail(404, 'No investor account uses this wallet. Start investing to create one.')
          return json({ lender: publicLender(lender), key: issueSession(lender) })
        }
        const email = text(b.email, 120).toLowerCase()
        if (!EMAIL.test(email)) fail(400, 'Enter the email you signed up with, for example ana@example.com.')
        // Unknown emails and the emails of USDC investors get the same answer, so it never tells who invests in USDC.
        const lender =
          state.lenders.find((l) => l.funding === 'fiat' && sameHash(sha256(l.email), sha256(email))) ??
          fail(404, 'No bank-transfer investor uses that email. If you invest in USDC, sign in with your wallet. New to Tradeflow? Start investing to create an account.')
        return json({ lender: publicLender(lender), key: issueSession(lender, { unproven: true }) })
      },
    },
    // Signing out: the key this browser holds stops working.
    '/api/investors/:id/sign-out': {
      POST: (req) => {
        endSession(signedInInvestor(req, req.params.id), req.headers.get('x-investor-key'))
        return json({ ok: true })
      },
    },

    // The investor's own portfolio (signed in): positions, deposits, totals and identity status.
    '/api/investors/:id/portfolio': {
      GET: async (req) => json(await cachedPortfolio(signedInInvestor(req, req.params.id))),
    },
    '/api/lenders/:id/kyc': {
      POST: (req) => {
        const l = state.lenders.find((x) => x.id === req.params.id) ?? fail(404, 'We could not find that lender.')
        return json({ ok: true, runId: runKyc(l) })
      },
    },

    // A lender chooses "fund by bank transfer": the on-ramp issues payment instructions.
    '/api/onramp/intent': {
      POST: async (req) => {
        const b = await body<{ lenderId: string; loanId: number; amountMinor: number; currency: 'EUR' | 'USD' }>(req)
        const lender = state.lenders.find((l) => l.id === b.lenderId) ?? fail(404, 'We could not find your lender account. Verify your identity to lend, then try again.')
        if (lender.funding !== 'fiat') fail(400, 'This account lends with USDC. Use the USDC tab to fund.')
        if (lender.kycStatus !== 'approved') fail(403, 'Your identity was not verified, so you cannot fund this loan.')
        // Loan notes mint only to wallets in the ERC-3643 identity registry, so the KYC report must have landed first.
        if (!(await isVerified(lender.wallet))) {
          fail(
            409,
            inFlight(WF.kyc.handler, JSON.stringify({ lenderId: lender.id }))
              ? 'Your identity check is still running. Fund once it is done.'
              : 'Your identity is not verified yet. Verify your identity, then fund.',
          )
        }
        const currency = b.currency === 'EUR' || b.currency === 'USD' ? b.currency : fail(400, 'Choose the currency of your transfer: EUR or USD.')
        const amountMinor = Number(b.amountMinor)
        if (!Number.isInteger(amountMinor) || amountMinor < 100) fail(400, 'Enter an amount of at least 1.00.')
        const loanId = Number(b.loanId)
        const loan = Number.isInteger(loanId) && loanId > 0 ? await chain.readLoan(BigInt(loanId)) : undefined
        if (!loan || loan.status !== 1) return fail(409, 'This loan is not open for funding.')
        if (await chain.publicClient.readContract({ address: deployment.market, abi: marketAbi, functionName: 'fundingPaused' })) {
          fail(409, 'New funding is paused while the books are reconciled. Try again later.')
        }
        const rate = await ccyRateE8(currency)
        const remaining = loan.target - loan.funded
        if (toUsd6(amountMinor, rate) > remaining) {
          const maxMinor = (remaining * 100_000_000n) / rate / 10_000n
          fail(400, `This loan needs at most ${money(maxMinor, currency)} more. Enter that amount or less.`)
        }

        const reference = `TF-${Date.now().toString(36).toUpperCase()}`
        const intent: Intent = { lenderId: lender.id, loanId, amountMinor, currency, reference, createdAt: nowIso(), status: 'awaiting_funds' }
        state.intents.unshift(intent)
        persist()
        broadcast('rails', { kind: 'intent', intent })
        railsLog('bank', `transfer instructions issued to ${lender.name}: ${fiatText(amountMinor, currency)}, reference ${reference}`)
        return json({ intent, instructions: transferInstructions(intent) })
      },
    },

    // The lender's bank transfer lands. The on-ramp converts it at its quoted rate, mints
    // stablecoins into the market, and notifies CRE (fiat funding workflow).
    '/api/onramp/deposit-received': {
      POST: async (req) => {
        const { reference } = await body<{ reference: string }>(req)
        const i = state.intents.find((x) => x.reference === reference) ?? fail(404, 'We could not find a transfer with that reference.')
        const lender = state.lenders.find((l) => l.id === i.lenderId) ?? fail(404, 'We could not find the lender for this transfer.')
        // The status check and the mint must not interleave with another request for the same transfer.
        return exclusive(`deposit-${i.reference}`, 'This transfer is being received now. This page updates when it is done.', async () => {
          if (i.status !== 'awaiting_funds') fail(409, `This transfer was already received (${i.status}).`)
          // The collection bank records the arrival. Converting it is the lender workflow's call.
          Object.assign(i, { status: 'received', settledAt: nowIso() })
          state.bankCredits.push({ reference: i.reference, amountMinor: i.amountMinor, currency: i.currency, payer: lender.name, valueDate: nowIso(), kind: 'deposit' })
          persist()
          broadcast('rails', { kind: 'deposit', intent: i })
          railsLog('bank', `${fiatText(i.amountMinor, i.currency)} received from ${lender.name}, reference ${i.reference}; notifying CRE`)
          const run = await bridge.enqueue({ ...WF.fiatFunding, httpPayload: { reference: i.reference }, loanId: i.loanId })
          if (run.status === 'success') i.status = 'credited'
          persist()
          return json({ intent: i, runId: run.id, run })
        })
      },
    },

    // ---------------- wallets ----------------
    '/api/wallet/:address': {
      GET: async (req) => {
        const a = req.params.address
        if (!isAddress(a, { strict: false })) fail(400, 'That is not a wallet address.')
        return json(await chain.walletSnapshot(getAddress(a)))
      },
    },
    // A browser without a wallet extension gets its own built-in wallet. Only the wallet key
    // (shown once, kept by the browser) can ask it to sign.
    '/api/wallet/builtin': {
      POST: async () => {
        if (!BUILTIN_WALLETS) fail(404, 'This deployment has no built-in wallets. Install a browser wallet to continue.')
        const key = newSecret()
        const privateKey = generatePrivateKey()
        const { address } = privateKeyToAccount(privateKey)
        custody[builtinId(address)] = { address, privateKey, keyHash: sha256(key), createdAt: nowIso() }
        writeFileSync(CUSTODY_FILE, JSON.stringify(custody, null, 2), { mode: 0o600 })
        await topUpGas(address)
        return json({ address, key }, 201)
      },
    },
    '/api/wallet/builtin/:address': {
      GET: (req) => json({ address: builtinFor(req, req.params.address).address }),
    },
    '/api/wallet/send': {
      POST: async (req) => {
        const b = await body<{ from: string; to: string; data: string }>(req)
        const wallet = builtinFor(req, b.from)
        const call =
          allowedCall(b.to, b.data) ??
          fail(400, 'The built-in wallet only approves USDC for the market, gets USDC, funds loans and claims repayments.')
        return json(await sendBuiltin(wallet, call))
      },
    },
    '/api/tx/:hash': {
      GET: async (req) => {
        const hash = req.params.hash
        if (!/^0x[0-9a-fA-F]{64}$/.test(hash)) fail(400, 'That is not a transaction hash.')
        const receipt = await chain.publicClient.getTransactionReceipt({ hash: hash as Hash }).catch(() => undefined)
        return json({ status: receipt ? receipt.status : 'pending' })
      },
    },

    // ---------------- operations ----------------

    // Operator lifts the circuit breaker after investigating.
    '/api/ops/resume': {
      POST: async () => {
        const tx = await chain.send(chain.walletFor(OWNER_KEY), deployment.market, marketAbi, 'resumeFunding', [])
        return json({ ok: true, tx })
      },
    },

    // Run the monitor (cron workflow) on demand.
    '/api/monitor/run': {
      POST: async () => json(await bridge.enqueue({ ...WF.monitor })),
    },

    // The operator's books record a deposit that never reached the chain.
    '/api/ops/book-unmatched-deposit': {
      POST: async () => {
        state.ledgerAdjustments.push({ at: nowIso(), note: 'Deposit booked without a matching on-ramp mint', usd6: '2500000000' })
        persist()
        broadcast('rails', { kind: 'books' })
        return json({ ok: true })
      },
    },
    '/api/ops/correct-books': {
      POST: async () => {
        state.ledgerAdjustments = []
        persist()
        broadcast('rails', { kind: 'books' })
        return json({ ok: true })
      },
    },
  },
  fetch(req, server) {
    if (new URL(req.url).pathname === '/ws' && server.upgrade(req)) return
    return new Response('not found', { status: 404 })
  },
  error(e) {
    if (e instanceof ApiError) return json({ error: e.message }, e.status)
    console.error('api error', e.message.split('\n')[0])
    return json({ error: 'Something went wrong on our side. Try again in a moment.' }, 500)
  },
  websocket: {
    open: (ws) => void sockets.add(ws),
    close: (ws) => void sockets.delete(ws),
    message: () => {},
  },
  development: process.env.NODE_ENV !== 'production' ? { hmr: true, console: true } : false,
})

console.log(`Tradeflow rails on http://localhost:${server.port}  (deployment: ${DEPLOYMENT}, rpc: ${RPC_URL})`)
