// Listing workflow: verify a financing request and list it onchain.
//
// Trigger: HTTP (the business submits a document for financing).
// Runs inside a TEE (Confidential Workflow): the business's credit file, the document
// registry response and the sanctions result are fetched and scored in the enclave, so node
// operators never see the private financial data. Only derived values cross back to the DON:
// risk grade, APR, advance amount and a document hash.
// Then, on the DON: read Chainlink's EUR/USD Data Feed to price non-USD documents, build the
// ListLoan report and deliver it to TradeflowMarket through the CRE forwarder.

import {
  HTTPCapability,
  HTTPClient,
  Runner,
  bytesToBase64,
  handlerInTee,
  json,
  ok,
  type HTTPPayload,
  type TeeRuntime,
} from '@chainlink/cre-sdk'
import { encodeAbiParameters, parseAbiParameters, toHex, type Address, type Hex } from 'viem'
import { z } from 'zod'
import { Action, baseConfig, bigintJson, decodeInput, readEurUsd, toUsd6, writeAction } from './lib'

const configSchema = baseConfig.extend({
  authorizedKeys: z.array(z.string()),
  apiKeySecretId: z.string(),
  minScore: z.number(),
})
type Config = z.infer<typeof configSchema>

type Request = { borrowerId: string; docNumber: string; tenorDays: number }
type Credit = {
  borrowerId: string
  name: string
  country: string
  wallet: string
  yearsTrading: number
  annualRevenueUsd: number
  onTimeRate: number
  avgDaysLate: number
  openDebtUsd: number
  priorLoans: number
}
type Registry = {
  valid: boolean
  reason?: string
  buyerConfirmed?: boolean
  docType?: 'invoice' | 'bill_of_lading' | 'equipment' | 'working_capital'
  buyer?: string
  amountMinor?: number
  currency?: 'EUR' | 'USD'
  dueInDays?: number
  docHash?: Hex
}

const ASSET_TYPE: Record<string, number> = { invoice: 0, bill_of_lading: 1, equipment: 2, working_capital: 3 }

/** Credit scorecard, evaluated only inside the enclave. Returns grade 1 (A) .. 5 (E). */
function scorecard(c: Credit, minScore: number) {
  const years = Math.min(c.yearsTrading, 10)
  const debtRatio = c.annualRevenueUsd > 0 ? c.openDebtUsd / c.annualRevenueUsd : 1
  const score = Math.round(
    500 + years * 12 + c.onTimeRate * 250 - c.avgDaysLate * 6 - debtRatio * 150 + Math.min(c.priorLoans, 20) * 3,
  )
  const grade = score >= 820 ? 1 : score >= 770 ? 2 : score >= 720 ? 3 : score >= 670 ? 4 : 5
  const baseApr = [0, 900, 1200, 1500, 1900, 2600][grade]
  const advanceBps = [0, 9000, 8800, 8500, 8000, 0][grade]
  return { score, grade, baseApr, advanceBps, approved: score >= minScore && grade <= 4 }
}

const onSubmission = (runtime: TeeRuntime<Config>, payload: HTTPPayload): string => {
  const req = decodeInput<Request>(payload.input)
  const apiKey = runtime.getSecret({ id: runtime.config.apiKeySecretId }).result().value
  const http = new HTTPClient()
  const headers = { 'x-api-key': { values: [apiKey] }, 'content-type': { values: ['application/json'] } }
  const base = runtime.config.railsUrl

  // ---- Inside the enclave: private data ----
  const creditRes = http.sendRequest(runtime, { url: `${base}/v1/credit/${req.borrowerId}`, method: 'GET', multiHeaders: headers }).result()
  if (!ok(creditRes)) throw new Error(`credit bureau HTTP ${creditRes.statusCode}`)
  const credit = json(creditRes) as Credit

  const regRes = http
    .sendRequest(runtime, {
      url: `${base}/v1/registry/verify`,
      method: 'POST',
      multiHeaders: headers,
      body: bytesToBase64(new TextEncoder().encode(JSON.stringify({ docNumber: req.docNumber, borrowerId: req.borrowerId }))),
    })
    .result()
  if (!ok(regRes)) throw new Error(`registry HTTP ${regRes.statusCode}`)
  const reg = json(regRes) as Registry

  const sanRes = http
    .sendRequest(runtime, {
      url: `${base}/v1/sanctions/screen`,
      method: 'POST',
      multiHeaders: headers,
      body: bytesToBase64(new TextEncoder().encode(JSON.stringify({ name: credit.name, country: credit.country }))),
    })
    .result()
  if (!ok(sanRes)) throw new Error(`sanctions HTTP ${sanRes.statusCode}`)
  const sanctions = json(sanRes) as { match: boolean }

  const rejection = !reg.valid
    ? `document rejected: ${reg.reason ?? 'not found'}`
    : !reg.buyerConfirmed
      ? 'buyer has not confirmed the document'
      : sanctions.match
        ? 'sanctions screening match'
        : undefined
  const card = scorecard(credit, runtime.config.minScore)

  // ---- Cross back to the DON with derived values only ----
  const don = runtime.usingTheDons()
  if (rejection || !card.approved) {
    const reason = rejection ?? `credit grade below policy (grade ${card.grade})`
    don.log(`listing rejected for ${req.docNumber}: ${reason}`)
    return JSON.stringify({ listed: false, docNumber: req.docNumber, reason })
  }

  const currency = reg.currency!
  const fxRateE8 = currency === 'USD' ? 100_000_000n : readEurUsd(don)
  const faceValueMinor = BigInt(reg.amountMinor!)
  const faceUsd6 = toUsd6(faceValueMinor, fxRateE8)
  const advanceUsd6 = ((faceUsd6 * BigInt(card.advanceBps)) / 10_000n / 1_000_000n) * 1_000_000n // whole dollars
  const tenorDays = req.tenorDays > 0 ? req.tenorDays : reg.dueInDays!
  const aprBps = card.baseApr + (tenorDays > 120 ? 150 : 0)

  const listPayload = encodeAbiParameters(
    parseAbiParameters(
      'address borrower, uint8 assetType, uint8 riskGrade, bytes3 currency, uint32 aprBps, uint32 tenorDays, uint256 faceValueMinor, uint256 fxRateE8, uint256 target, bytes32 docHash, string ref',
    ),
    [
      credit.wallet as Address,
      ASSET_TYPE[reg.docType!] ?? 0,
      card.grade,
      toHex(currency, { size: 3 }),
      aprBps,
      tenorDays,
      faceValueMinor,
      fxRateE8,
      advanceUsd6,
      reg.docHash!,
      req.docNumber,
    ],
  )
  const tx = writeAction(don, Action.ListLoan, listPayload)
  return bigintJson({
    listed: true,
    docNumber: req.docNumber,
    grade: 'ABCDE'[card.grade - 1],
    aprBps,
    tenorDays,
    currency,
    fxRateE8,
    target: advanceUsd6,
    tx,
  })
}

const initWorkflow = (config: Config) => [
  handlerInTee(new HTTPCapability().trigger({ authorizedKeys: config.authorizedKeys as any }), onSubmission, [
    { tee: 'nitro', regions: ['us-west-2'] },
  ]),
]

export async function main() {
  const runner = await Runner.newRunner<Config>({ configSchema })
  await runner.run(initWorkflow)
}
