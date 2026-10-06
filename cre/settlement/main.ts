// Settlement workflow: money out to the business, money back from the buyer, and fiat
// redemptions for lenders who funded by bank transfer.
//
// Handler 0 (EVM log: LoanFullyFunded): instruct the payout provider to pay the business in
// fiat (idempotent per loan), then report Disbursed so the market releases the stablecoins to
// the off-ramp operator and starts the loan clock.
// Handler 1 (HTTP: buyer payment notice): confirm the repayment with TWO independent sources,
// the collection bank and the buyer's payment processor, which must agree on amount and
// currency on every node; check the on-ramped stablecoins are in the market; report Repaid.
// Handler 2 (EVM log: Repaid): pay each fiat lender's bank account and report FiatRedeemed,
// which burns their notes and moves their share to the off-ramp operator.

import {
  ConsensusAggregationByFields,
  EVMClient,
  HTTPCapability,
  HTTPClient,
  Runner,
  bytesToBase64,
  bytesToHex,
  getNetwork,
  handler,
  logTriggerConfig,
  identical,
  json,
  ok,
  type EVMLog,
  type HTTPPayload,
  type HTTPSendRequester,
  type NodeRuntime,
  type Runtime,
} from '@chainlink/cre-sdk'
import { decodeEventLog, encodeAbiParameters, keccak256, parseAbi, parseAbiParameters, toHex, type Address, type Hex } from 'viem'
import { z } from 'zod'
import { Action, baseConfig, bigintJson, decodeInput, marketAbi, notesAbi, read, refHash, writeAction } from './lib'

const configSchema = baseConfig.extend({
  authorizedKeys: z.array(z.string()),
  apiKeySecretId: z.string(),
  logConfidence: z.string(),
})
type Config = z.infer<typeof configSchema>

const events = parseAbi([
  'event LoanFullyFunded(uint256 indexed loanId, address indexed borrower, uint256 amount)',
  'event Repaid(uint256 indexed loanId, uint256 amount, bytes32 paymentRef)',
])

type Loan = { borrower: Address; ref: string; target: bigint; repaidAmount: bigint; status: number }

function decode(log: EVMLog) {
  const topics = log.topics.map((t) => bytesToHex(t)) as [Hex, ...Hex[]]
  return decodeEventLog({ abi: events, data: bytesToHex(log.data), topics })
}

/** POST to the payout provider from every node; nodes must agree on the payout reference. */
function postPayout(runtime: Runtime<Config>, body: Record<string, unknown>): string {
  const apiKey = runtime.getSecret({ id: runtime.config.apiKeySecretId }).result().value
  const fetchPayout = (sender: HTTPSendRequester, key: string): { payoutRef: string } => {
    const res = sender
      .sendRequest({
        url: `${runtime.config.railsUrl}/v1/payouts`,
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-api-key': key },
        body: bytesToBase64(new TextEncoder().encode(JSON.stringify(body))),
        cacheSettings: { store: true, maxAge: '60s' },
      })
      .result()
    if (!ok(res)) throw new Error(`payout HTTP ${res.statusCode}`)
    return { payoutRef: String((json(res) as { payoutRef: string }).payoutRef) }
  }
  return new HTTPClient()
    .sendRequest(runtime, fetchPayout, ConsensusAggregationByFields<{ payoutRef: string }>({ payoutRef: identical }))(apiKey)
    .result().payoutRef
}

const onFullyFunded = (runtime: Runtime<Config>, log: EVMLog): string => {
  const ev = decode(log)
  if (ev.eventName !== 'LoanFullyFunded') throw new Error('unexpected event')
  const loanId = ev.args.loanId as bigint
  const loan = read<Loan>(runtime, runtime.config.market, marketAbi, 'getLoan', [loanId])
  if (loan.status !== 2) return JSON.stringify({ skipped: true, reason: `loan ${loanId} status ${loan.status}` })

  const payoutRef = postPayout(runtime, {
    kind: 'business',
    loanId: Number(loanId),
    beneficiaryId: loan.borrower,
    amount: loan.target.toString(),
    idempotencyKey: `disburse-${loanId}`,
  })
  runtime.log(`fiat payout ${payoutRef} sent to ${loan.borrower} for loan ${loanId} (${loan.ref})`)
  const tx = writeAction(
    runtime,
    Action.Disbursed,
    encodeAbiParameters(parseAbiParameters('uint256 loanId, bytes32 payoutRef'), [loanId, refHash(`payout|${payoutRef}`)]),
  )
  return bigintJson({ disbursed: true, loanId, ref: loan.ref, amount: loan.target, payoutRef, tx })
}

type RepaymentCheck = { found: boolean; agree: boolean; amountMinor: string; currency: string; payer: string }

const onRepaymentNotice = (runtime: Runtime<Config>, payload: HTTPPayload): string => {
  const { loanId, reference } = decodeInput<{ loanId: number; reference: string }>(payload.input)
  const apiKey = runtime.getSecret({ id: runtime.config.apiKeySecretId }).result().value
  const base = runtime.config.railsUrl

  // Every node queries BOTH sources; the DON must reach identical conclusions.
  const check = runtime
    .runInNodeMode(
      (node: NodeRuntime<Config>, key: string): RepaymentCheck => {
        const http = new HTTPClient()
        const headers = { 'x-api-key': key }
        const bank = http.sendRequest(node, { url: `${base}/v1/bank/credits?reference=${reference}`, method: 'GET', headers }).result()
        const psp = http.sendRequest(node, { url: `${base}/v1/psp/payments/${reference}`, method: 'GET', headers }).result()
        if (!ok(bank) || !ok(psp)) return { found: false, agree: false, amountMinor: '0', currency: '', payer: '' }
        const entries = (json(bank) as { entries: { amountMinor: number; currency: string; kind: string }[] }).entries.filter(
          (e) => e.kind === 'repayment',
        )
        const p = json(psp) as { status: string; amountMinor: number; currency: string; payer: string }
        if (entries.length !== 1 || p.status !== 'captured') return { found: false, agree: false, amountMinor: '0', currency: '', payer: '' }
        const agree = entries[0].amountMinor === p.amountMinor && entries[0].currency === p.currency
        return { found: true, agree, amountMinor: String(p.amountMinor), currency: p.currency, payer: p.payer }
      },
      ConsensusAggregationByFields<RepaymentCheck>({ found: identical, agree: identical, amountMinor: identical, currency: identical, payer: identical }),
    )(apiKey)
    .result()

  if (!check.found) throw new Error(`payment ${reference} not found at both sources`)
  if (!check.agree) throw new Error(`bank and payment processor disagree on ${reference}`)
  if (check.currency !== 'USD') throw new Error(`unsupported repayment currency ${check.currency}`)

  const amount = BigInt(check.amountMinor) * 10_000n // cents -> 6 decimals
  const loan = read<Loan>(runtime, runtime.config.market, marketAbi, 'getLoan', [BigInt(loanId)])
  if (amount < loan.target) throw new Error(`repayment ${amount} is below principal ${loan.target}`)
  const unallocated = read<bigint>(runtime, runtime.config.market, marketAbi, 'unallocated')
  if (unallocated < amount) throw new Error(`repayment not yet on-ramped: ${unallocated} < ${amount}`)

  const tx = writeAction(
    runtime,
    Action.Repaid,
    encodeAbiParameters(parseAbiParameters('uint256 loanId, uint256 amount, bytes32 paymentRef'), [
      BigInt(loanId),
      amount,
      refHash(`payment|${reference}`),
    ]),
  )
  return bigintJson({ repaid: true, loanId, reference, payer: check.payer, amount, sources: ['collection bank', 'payment processor'], tx })
}

const onRepaid = (runtime: Runtime<Config>, log: EVMLog): string => {
  const ev = decode(log)
  if (ev.eventName !== 'Repaid') throw new Error('unexpected event')
  const loanId = ev.args.loanId as bigint
  const loan = read<Loan>(runtime, runtime.config.market, marketAbi, 'getLoan', [loanId])
  const apiKey = runtime.getSecret({ id: runtime.config.apiKeySecretId }).result().value

  const fetchLenders = (sender: HTTPSendRequester, key: string): { list: string } => {
    const res = sender
      .sendRequest({ url: `${runtime.config.railsUrl}/v1/onramp/lenders?loanId=${loanId}`, method: 'GET', headers: { 'x-api-key': key } })
      .result()
    if (!ok(res)) throw new Error(`lenders HTTP ${res.statusCode}`)
    const body = json(res) as { lenders: { lenderId: string; wallet: string }[] }
    return { list: body.lenders.map((l) => `${l.lenderId}:${l.wallet}`).sort().join(',') }
  }
  const list = new HTTPClient()
    .sendRequest(runtime, fetchLenders, ConsensusAggregationByFields<{ list: string }>({ list: identical }))(apiKey)
    .result().list
  const fiatLenders = list ? list.split(',').map((x) => ({ lenderId: x.split(':')[0], wallet: x.split(':')[1] as Address })) : []

  const redeemed: unknown[] = []
  for (const l of fiatLenders) {
    const balance = read<bigint>(runtime, runtime.config.notes, notesAbi, 'balanceOf', [l.wallet, loanId])
    if (balance === 0n) continue
    const payout = (balance * loan.repaidAmount) / loan.target
    const payoutRef = postPayout(runtime, {
      kind: 'lender',
      loanId: Number(loanId),
      beneficiaryId: l.lenderId,
      amount: payout.toString(),
      idempotencyKey: `redeem-${loanId}-${l.lenderId}`,
    })
    const tx = writeAction(
      runtime,
      Action.FiatRedeemed,
      encodeAbiParameters(parseAbiParameters('uint256 loanId, address lender, bytes32 payoutRef'), [loanId, l.wallet, refHash(`payout|${payoutRef}`)]),
    )
    redeemed.push({ lender: l.lenderId, payout, payoutRef, tx })
  }
  return bigintJson({ loanId, redeemed })
}

const initWorkflow = (config: Config) => {
  const network = getNetwork({ chainFamily: 'evm', chainSelectorName: config.chainSelectorName, isTestnet: true })
  if (!network) throw new Error(`unknown chain ${config.chainSelectorName}`)
  const evmClient = new EVMClient(network.chainSelector.selector)
  const topic = (sig: string) => keccak256(toHex(sig))
  const confidence = config.logConfidence as 'SAFE' | 'LATEST' | 'FINALIZED'
  const market = config.market as Hex
  return [
    handler(
      evmClient.logTrigger(logTriggerConfig({ addresses: [market], topics: [[topic('LoanFullyFunded(uint256,address,uint256)')]], confidence })),
      onFullyFunded,
    ),
    handler(new HTTPCapability().trigger({ authorizedKeys: config.authorizedKeys as any }), onRepaymentNotice),
    handler(
      evmClient.logTrigger(logTriggerConfig({ addresses: [market], topics: [[topic('Repaid(uint256,uint256,bytes32)')]], confidence })),
      onRepaid,
    ),
  ]
}

export async function main() {
  const runner = await Runner.newRunner<Config>({ configSchema })
  await runner.run(initWorkflow)
}
