// Tradeflow rails sandbox.
//
// Plays every off-chain party the CRE workflows talk to:
//   - document registry, credit bureau and sanctions screening (listing workflow, run in a TEE)
//   - KYC provider and the on-ramp/bank that receives lender deposits (lender workflow,
//     called through Confidential HTTP)
//   - the collection bank and the buyer's payment processor (two independent repayment sources)
//   - the payout provider (fiat out to businesses and fiat lenders)
//   - the operator's books (for the monitor's three-way reconciliation)
// It also runs the CRE workflows through the CLI simulator and serves the web app.

import { keccak256, toHex, parseAbiItem, encodeEventTopics, type Hash } from 'viem'
import { borrowers, documents, lenders } from './seed'
import { makeChain, marketAbi, erc20Abi, notesAbi, type Deployment } from './chain'
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
const API_KEY = process.env.RAILS_API_KEY ?? 'sandbox-key-local'
const OPERATOR_KEY = (process.env.ONRAMP_OPERATOR_KEY ?? KEYS.platform) as `0x${string}`
const DEMO_LENDER_KEY = (process.env.DEMO_LENDER_KEY ?? KEYS.ben) as `0x${string}`
const OWNER_KEY = (process.env.OWNER_KEY ?? KEYS.platform) as `0x${string}`
const CRE_BIN = process.env.CRE_BIN ?? `${process.env.HOME}/.cre/bin/cre`
const CRE_TARGET = process.env.CRE_TARGET ?? 'local'
const AUTO_RUN = process.env.AUTO_RUN !== '0'

const deployment: Deployment = await Bun.file(`${ROOT}contracts/deployments/${DEPLOYMENT}.json`).json()
const chain = makeChain(RPC_URL, deployment, OPERATOR_KEY)

// ---------------------------------------------------------------------------
// State (persisted to a JSON file so restarts keep the demo history)
// ---------------------------------------------------------------------------

type Intent = {
  reference: string
  lenderId: string
  loanId: number
  amountMinor: number // fiat, 2 decimals
  currency: 'EUR' | 'USD'
  createdAt: string
  status: 'awaiting_funds' | 'settled' | 'credited' | 'failed'
  fxRateE8?: string
  stablecoinAmount?: string // 6 decimals
  mintTx?: string
  settledAt?: string
}
type Payout = { idempotencyKey: string; payoutRef: string; kind: 'business' | 'lender'; loanId: number; beneficiaryId: string; amount: string; createdAt: string }
type BankCredit = { reference: string; amountMinor: number; currency: 'EUR' | 'USD'; payer: string; valueDate: string; kind: 'deposit' | 'repayment' }
type PspPayment = { reference: string; status: 'captured'; amountMinor: number; currency: 'EUR' | 'USD'; payer: string; capturedAt: string }
type Listing = { docNumber: string; borrowerId: string; submittedAt: string; runId?: number; tenorDays: number }

type State = {
  intents: Intent[]
  payouts: Payout[]
  bankCredits: BankCredit[]
  pspPayments: PspPayment[]
  listings: Listing[]
  ledgerAdjustments: { at: string; note: string; usd6: string }[]
  runs: WorkflowRun[]
}

const STATE_FILE = `${import.meta.dir}/data/state.${DEPLOYMENT}.json`
const state: State = (await Bun.file(STATE_FILE).exists())
  ? await Bun.file(STATE_FILE).json()
  : { intents: [], payouts: [], bankCredits: [], pspPayments: [], listings: [], ledgerAdjustments: [], runs: [] }
let saveTimer: ReturnType<typeof setTimeout> | undefined
function persist() {
  clearTimeout(saveTimer)
  saveTimer = setTimeout(() => Bun.write(STATE_FILE, JSON.stringify(state, null, 2)), 50)
}

// ---------------------------------------------------------------------------
// CRE bridge
// ---------------------------------------------------------------------------

const sockets = new Set<import('bun').ServerWebSocket<unknown>>()
function broadcast(type: string, data: unknown) {
  const msg = JSON.stringify({ type, data })
  for (const s of sockets) s.send(msg)
}

const bridge = makeBridge(
  {
    creBin: CRE_BIN,
    projectDir: `${ROOT}cre`,
    target: CRE_TARGET,
    broadcast: true,
    env: {
      RAILS_API_KEY_VAR: API_KEY,
      CRE_TARGET,
    },
    onUpdate: (run) => broadcast('run', run),
  },
  state.runs,
  persist,
)

const WF = {
  listing: { workflow: 'listing', handler: 'verify-and-list', triggerIndex: 0, trigger: 'http' as const },
  kyc: { workflow: 'lender', handler: 'verify-lender', triggerIndex: 0, trigger: 'http' as const },
  fiatFunding: { workflow: 'lender', handler: 'credit-fiat-deposit', triggerIndex: 1, trigger: 'http' as const },
  disburse: { workflow: 'settlement', handler: 'disburse-on-funded', triggerIndex: 0, trigger: 'evm-log' as const },
  repayment: { workflow: 'settlement', handler: 'confirm-repayment', triggerIndex: 1, trigger: 'http' as const },
  redeemFiat: { workflow: 'settlement', handler: 'redeem-fiat-lenders', triggerIndex: 2, trigger: 'evm-log' as const },
  monitor: { workflow: 'monitor', handler: 'watch-and-reconcile', triggerIndex: 0, trigger: 'cron' as const },
}

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
const refHash = (ref: string) => keccak256(toHex(ref))
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

// ---------------------------------------------------------------------------
// Event watcher: market events start the log-triggered settlement workflows
// ---------------------------------------------------------------------------

const topic = (sig: string) => keccak256(toHex(sig))
const FULLY_FUNDED = topic('LoanFullyFunded(uint256,address,uint256)')
const REPAID = topic('Repaid(uint256,uint256,bytes32)')
let lastBlock = await chain.publicClient.getBlockNumber()

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
// Server
// ---------------------------------------------------------------------------

const server = Bun.serve({
  port: PORT,
  idleTimeout: 120,
  routes: {
    '/': index,
    '/loans/*': index,
    '/ops': index,
    '/lend': index,
    '/business': index,

    // ---------------- registry, credit, sanctions (listing workflow) ----------------
    '/v1/registry/verify': {
      POST: async (req) => {
        if (!authed(req)) return unauthorized()
        const body = (await req.json()) as { docNumber: string; borrowerId: string }
        const doc = documents.find((d) => d.number === body.docNumber)
        if (!doc || doc.borrowerId !== body.borrowerId) {
          return json({ valid: false, reason: 'document not found for this business' })
        }
        return json({
          valid: true,
          buyerConfirmed: doc.buyerConfirmed,
          docType: doc.type,
          buyer: doc.buyer,
          buyerCountry: doc.buyerCountry,
          amountMinor: doc.amountMinor,
          currency: doc.currency,
          issuedAt: doc.issuedAt,
          dueInDays: doc.dueInDays,
          docHash: keccak256(toHex(`${doc.number}|${doc.borrowerId}|${doc.amountMinor}|${doc.currency}|${doc.buyer}`)),
        })
      },
    },
    '/v1/credit/:borrowerId': {
      GET: (req) => {
        if (!authed(req)) return unauthorized()
        const b = borrowers.find((x) => x.id === req.params.borrowerId)
        if (!b) return json({ error: 'unknown business' }, 404)
        return json({ borrowerId: b.id, name: b.name, country: b.country, wallet: b.wallet, ...b.credit })
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
        const l = lenders.find((x) => x.id === req.params.lenderId)
        if (!l) return json({ error: 'unknown lender' }, 404)
        return json({ lenderId: l.id, status: l.kycStatus, level: l.kycLevel, wallet: l.wallet, country: l.country })
      },
    },
    '/v1/onramp/deposits/:reference': {
      GET: (req) => {
        if (!authed(req)) return unauthorized()
        const i = state.intents.find((x) => x.reference === req.params.reference)
        if (!i) return json({ error: 'unknown reference' }, 404)
        const lender = lenders.find((l) => l.id === i.lenderId)!
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
    '/v1/onramp/lenders': {
      GET: (req) => {
        if (!authed(req)) return unauthorized()
        const loanId = Number(new URL(req.url).searchParams.get('loanId'))
        const fiat = state.intents.filter((i) => i.loanId === loanId && i.status === 'credited')
        const ids = [...new Set(fiat.map((i) => i.lenderId))]
        return json({
          loanId,
          lenders: ids.map((id) => {
            const l = lenders.find((x) => x.id === id)!
            return { lenderId: l.id, wallet: l.wallet, bankAccount: l.bankAccount ?? '' }
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
          ...body,
          payoutRef: `PO-${body.kind === 'business' ? 'B' : 'L'}-${String(state.payouts.length + 1).padStart(5, '0')}`,
          createdAt: nowIso(),
        }
        state.payouts.push(payout)
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
        const inFlight = state.intents.filter((i) => i.status === 'settled')
        const sum = (xs: Intent[]) => xs.reduce((s, i) => s + BigInt(i.stablecoinAmount ?? '0'), 0n)
        const bankUsd6 = sum(credited) + state.ledgerAdjustments.reduce((s, a) => s + BigInt(a.usd6), 0n)
        const onrampUsd6 = sum(credited.filter((i) => i.mintTx))
        return json({
          bankUsd6: bankUsd6.toString(),
          onrampUsd6: onrampUsd6.toString(),
          creditedDeposits: credited.length,
          inFlightDeposits: inFlight.length,
          inFlightUsd6: sum(inFlight).toString(),
        })
      },
    },

    // ---------------- app + demo controls ----------------
    '/api/config': {
      GET: () => json({ deployment, rpcUrl: RPC_URL, explorer: process.env.EXPLORER ?? null, demoLender: lenders.find((l) => l.id === 'lender-ben')!.wallet }),
    },
    '/api/seed': {
      GET: () => json({ borrowers, documents, lenders }),
    },
    '/api/state': {
      GET: async () => {
        const snap = await chain.marketSnapshot()
        const count = Number(snap.loanCount)
        const loans = await Promise.all(
          Array.from({ length: count }, async (_, i) => {
            const id = BigInt(i + 1)
            const l = await chain.readLoan(id)
            return { id: i + 1, ...l }
          }),
        )
        const fundingEvents = await chain.publicClient.getContractEvents({
          address: deployment.market,
          abi: marketAbi,
          eventName: 'Funded',
          fromBlock: 0n,
        }).catch(() => [])
        const credited = state.intents.filter((i) => i.status === 'credited')
        const sum = (xs: Intent[]) => xs.reduce((t, i) => t + BigInt(i.stablecoinAmount ?? '0'), 0n)
        const books = {
          bankUsd6: (sum(credited) + state.ledgerAdjustments.reduce((t, a) => t + BigInt(a.usd6), 0n)).toString(),
          onrampUsd6: sum(credited.filter((i) => i.mintTx)).toString(),
        }
        return json({
          snapshot: snap,
          books,
          loans,
          fundings: fundingEvents.map((e) => ({ ...e.args, tx: e.transactionHash })),
          intents: state.intents,
          payouts: state.payouts,
          bankCredits: state.bankCredits,
          listings: state.listings,
          ledgerAdjustments: state.ledgerAdjustments,
          queue: bridge.queueLength(),
        })
      },
    },
    '/api/runs': { GET: () => json(state.runs.slice(0, 60)) },

    // A business submits a document for financing: starts the listing workflow.
    '/api/business/submit': {
      POST: async (req) => {
        const body = (await req.json()) as { docNumber: string; tenorDays?: number }
        const doc = documents.find((d) => d.number === body.docNumber)
        if (!doc) return json({ error: 'unknown document' }, 404)
        const b = borrowers.find((x) => x.id === doc.borrowerId)!
        const listing: Listing = { docNumber: doc.number, borrowerId: b.id, submittedAt: nowIso(), tenorDays: body.tenorDays ?? doc.dueInDays }
        state.listings.unshift(listing)
        const run = bridge.enqueue({
          ...WF.listing,
          httpPayload: { borrowerId: b.id, docNumber: doc.number, tenorDays: listing.tenorDays },
        })
        listing.runId = (state.runs[0] as WorkflowRun).id
        persist()
        return json({ ok: true, listing, run: await Promise.race([run, Bun.sleep(50).then(() => null)]) })
      },
    },

    // A lender completes onboarding: starts the KYC workflow.
    '/api/lender/onboard': {
      POST: async (req) => {
        const body = (await req.json()) as { lenderId: string }
        const l = lenders.find((x) => x.id === body.lenderId)
        if (!l) return json({ error: 'unknown lender' }, 404)
        void bridge.enqueue({ ...WF.kyc, httpPayload: { lenderId: l.id } })
        return json({ ok: true })
      },
    },

    // A lender chooses "fund by bank transfer": the on-ramp issues payment instructions.
    '/api/onramp/intent': {
      POST: async (req) => {
        const body = (await req.json()) as { lenderId: string; loanId: number; amountMinor: number; currency: 'EUR' | 'USD' }
        const reference = `TF-${Date.now().toString(36).toUpperCase()}`
        const intent: Intent = { ...body, reference, createdAt: nowIso(), status: 'awaiting_funds' }
        state.intents.unshift(intent)
        persist()
        broadcast('rails', { kind: 'intent', intent })
        return json({
          intent,
          instructions: {
            beneficiary: 'Tradeflow Client Funds (sandbox)',
            iban: intent.currency === 'EUR' ? 'DE89 3704 0044 0532 0130 00' : 'US-ACH 021000021 / 9988776655',
            reference,
          },
        })
      },
    },

    // Sandbox: the lender's bank transfer lands. The on-ramp converts it at its quoted rate,
    // mints stablecoins into the market, and notifies CRE (fiat funding workflow).
    '/api/onramp/simulate-deposit': {
      POST: async (req) => {
        const { reference } = (await req.json()) as { reference: string }
        const i = state.intents.find((x) => x.reference === reference)
        if (!i) return json({ error: 'unknown reference' }, 404)
        if (i.status !== 'awaiting_funds') return json({ error: `deposit already ${i.status}` }, 409)
        const rate = await ccyRateE8(i.currency)
        const usd6 = toUsd6(i.amountMinor, rate)
        const mintTx = await chain.onRampMint(usd6)
        Object.assign(i, { status: 'settled', fxRateE8: rate.toString(), stablecoinAmount: usd6.toString(), mintTx, settledAt: nowIso() })
        const lender = lenders.find((l) => l.id === i.lenderId)!
        state.bankCredits.push({ reference, amountMinor: i.amountMinor, currency: i.currency, payer: lender.name, valueDate: nowIso(), kind: 'deposit' })
        persist()
        broadcast('rails', { kind: 'deposit', intent: i })
        const run = await bridge.enqueue({ ...WF.fiatFunding, httpPayload: { reference }, loanId: i.loanId })
        if (run.status === 'success') i.status = 'credited'
        persist()
        return json({ intent: i, run })
      },
    },

    // Sandbox: the buyer pays the invoice. The payment is captured by the buyer's processor,
    // lands in the collection bank, is on-ramped into the market, and CRE confirms it.
    '/api/buyer/pay': {
      POST: async (req) => {
        const { loanId } = (await req.json()) as { loanId: number }
        const loan = await chain.readLoan(BigInt(loanId))
        const interest = (loan.target * BigInt(loan.aprBps) * BigInt(loan.tenorDays)) / (10_000n * 365n)
        const dueUsd6 = loan.target + interest
        const amountMinor = Number(dueUsd6 / 10_000n)
        const reference = `PAY-${loanId}-${Date.now().toString(36).toUpperCase()}`
        const doc = documents.find((d) => d.number === loan.ref)
        const payer = doc?.buyer ?? 'Buyer'
        state.pspPayments.push({ reference, status: 'captured', amountMinor, currency: 'USD', payer, capturedAt: nowIso() })
        state.bankCredits.push({ reference, amountMinor, currency: 'USD', payer, valueDate: nowIso(), kind: 'repayment' })
        const mintTx = await chain.onRampMint(BigInt(amountMinor) * 10_000n)
        persist()
        broadcast('rails', { kind: 'repayment', reference, amountMinor, mintTx })
        const run = await bridge.enqueue({ ...WF.repayment, httpPayload: { loanId, reference }, loanId })
        return json({ reference, amountMinor, mintTx, run })
      },
    },

    // Demo wallet for the stablecoin lender (Ben): faucet, approve and fund in one click.
    '/api/demo-wallet/fund': {
      POST: async (req) => {
        const { loanId, amountUsd } = (await req.json()) as { loanId: number; amountUsd: number }
        const wallet = chain.walletFor(DEMO_LENDER_KEY)
        const me = wallet.account!.address
        const amount = BigInt(Math.round(amountUsd * 1e6))
        const bal = await chain.publicClient.readContract({ address: deployment.stablecoin, abi: erc20Abi, functionName: 'balanceOf', args: [me] })
        const txs: Hash[] = []
        if (bal < amount) txs.push(await chain.send(wallet, deployment.stablecoin, erc20Abi, 'drip', []))
        txs.push(await chain.send(wallet, deployment.stablecoin, erc20Abi, 'approve', [deployment.market, amount]))
        txs.push(await chain.send(wallet, deployment.market, marketAbi, 'fund', [BigInt(loanId), amount]))
        return json({ ok: true, txs })
      },
    },
    '/api/demo-wallet/claim': {
      POST: async (req) => {
        const { loanId } = (await req.json()) as { loanId: number }
        const wallet = chain.walletFor(DEMO_LENDER_KEY)
        const tx = await chain.send(wallet, deployment.market, marketAbi, 'claim', [BigInt(loanId)])
        return json({ ok: true, tx })
      },
    },
    '/api/demo-wallet': {
      GET: async () => {
        const wallet = chain.walletFor(DEMO_LENDER_KEY)
        const me = wallet.account!.address
        const [usdc, verified] = await Promise.all([
          chain.publicClient.readContract({ address: deployment.stablecoin, abi: erc20Abi, functionName: 'balanceOf', args: [me] }),
          chain.publicClient.readContract({ address: deployment.notes, abi: notesAbi, functionName: 'isVerifiedHolder', args: [me] }),
        ])
        return json({ address: me, usdc, verified })
      },
    },

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

    // Demo: an operator's books record a deposit that never reached the chain.
    '/api/demo/tamper': {
      POST: async () => {
        state.ledgerAdjustments.push({ at: nowIso(), note: 'Deposit booked without a matching on-ramp mint', usd6: '2500000000' })
        persist()
        broadcast('rails', { kind: 'tamper' })
        return json({ ok: true })
      },
    },
    '/api/demo/untamper': {
      POST: async () => {
        state.ledgerAdjustments = []
        persist()
        return json({ ok: true })
      },
    },
  },
  fetch(req, server) {
    if (new URL(req.url).pathname === '/ws' && server.upgrade(req)) return
    return new Response('not found', { status: 404 })
  },
  websocket: {
    open: (ws) => void sockets.add(ws),
    close: (ws) => void sockets.delete(ws),
    message: () => {},
  },
  development: process.env.NODE_ENV !== 'production' ? { hmr: true, console: true } : false,
})

console.log(`Tradeflow rails sandbox on http://localhost:${server.port}  (deployment: ${DEPLOYMENT}, rpc: ${RPC_URL})`)
