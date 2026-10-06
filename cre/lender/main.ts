// Lender workflow: KYC onboarding and crediting fiat deposits.
//
// Handler 0 (HTTP): a lender finished onboarding. CRE checks the KYC provider over
// Confidential HTTP (the provider credential is injected only inside the enclave) and adds the
// wallet to the notes allowlist, so loan notes can only be held by verified people.
//
// Handler 1 (HTTP): the on-ramp reports that a lender's bank transfer settled and was converted
// to stablecoins. CRE independently:
//   - fetches the deposit from the on-ramp and the lender's KYC file (Confidential HTTP)
//   - checks the on-ramp's FX rate against Chainlink's EUR/USD Data Feed (max deviation)
//   - recomputes the stablecoin amount from fiat x rate
//   - confirms onchain that the stablecoins actually reached the market, unallocated
// and only then credits the lender with loan notes.

import { ConfidentialHTTPClient, HTTPCapability, Runner, handler, json, ok, type HTTPPayload, type Runtime } from '@chainlink/cre-sdk'
import { encodeAbiParameters, parseAbiParameters, type Address } from 'viem'
import { z } from 'zod'
import { Action, baseConfig, bigintJson, decodeInput, marketAbi, read, readEurUsd, refHash, toUsd6, writeAction } from './lib'

const configSchema = baseConfig.extend({
  authorizedKeys: z.array(z.string()),
  apiKeySecretId: z.string(),
  secretOwner: z.string(),
  maxFxDeviationBps: z.number(),
})
type Config = z.infer<typeof configSchema>

type Kyc = { lenderId: string; status: string; level: string; wallet: string; country: string }
type Deposit = {
  reference: string
  status: string
  lenderId: string
  wallet: string
  loanId: number
  fiatAmountMinor: number
  currency: 'EUR' | 'USD'
  fxRateE8: string
  stablecoinAmount: string
  mintTx: string
  destination: string
}

/**
 * GET a rails endpoint over Confidential HTTP. The API key is a Vault DON secret injected into
 * the request only inside the enclave, and the request executes exactly once.
 */
function confidentialGet<T>(runtime: Runtime<Config>, path: string): T {
  const res = new ConfidentialHTTPClient()
    .sendRequest(runtime, {
      vaultDonSecrets: [{ key: runtime.config.apiKeySecretId, owner: runtime.config.secretOwner }],
      request: {
        url: `${runtime.config.railsUrl}${path}`,
        method: 'GET',
        multiHeaders: { 'x-api-key': { values: [`{{.${runtime.config.apiKeySecretId}}}`] } },
        encryptOutput: false,
      },
    })
    .result()
  if (!ok(res)) throw new Error(`${path} HTTP ${res.statusCode}`)
  return json(res) as T
}

const onVerifyLender = (runtime: Runtime<Config>, payload: HTTPPayload): string => {
  const { lenderId } = decodeInput<{ lenderId: string }>(payload.input)
  const kyc = confidentialGet<Kyc>(runtime, `/v1/kyc/${lenderId}`)
  runtime.log(`KYC file received: ${kyc.status}`)
  if (kyc.status !== 'approved') {
    runtime.log(`KYC not approved for ${lenderId}: ${kyc.status}`)
    return JSON.stringify({ verified: false, lenderId, status: kyc.status })
  }
  const kycRef = refHash(`kyc|${kyc.lenderId}|${kyc.level}`)
  const tx = writeAction(
    runtime,
    Action.VerifyLender,
    encodeAbiParameters(parseAbiParameters('address lender, bool verified, bytes32 kycRef'), [kyc.wallet as Address, true, kycRef]),
  )
  return JSON.stringify({ verified: true, lenderId, wallet: kyc.wallet, level: kyc.level, tx })
}

const onFiatDeposit = (runtime: Runtime<Config>, payload: HTTPPayload): string => {
  const { reference } = decodeInput<{ reference: string }>(payload.input)
  const dep = confidentialGet<Deposit>(runtime, `/v1/onramp/deposits/${reference}`)
  if (dep.status !== 'settled') throw new Error(`deposit ${reference} is ${dep.status}, not settled`)
  if (dep.destination.toLowerCase() !== runtime.config.market.toLowerCase()) throw new Error('deposit minted to the wrong destination')
  runtime.log('on-ramp: deposit settled and minted to the market')

  const kyc = confidentialGet<Kyc>(runtime, `/v1/kyc/${dep.lenderId}`)
  if (kyc.status !== 'approved') throw new Error(`lender ${dep.lenderId} is not KYC approved`)
  if (kyc.wallet.toLowerCase() !== dep.wallet.toLowerCase()) throw new Error('deposit wallet does not match KYC file')
  runtime.log('KYC file approved and matches the deposit wallet')

  // FX check against Chainlink's EUR/USD Data Feed.
  const providerRate = BigInt(dep.fxRateE8)
  let feedRate = 100_000_000n
  if (dep.currency === 'EUR') {
    feedRate = readEurUsd(runtime)
    const diff = providerRate > feedRate ? providerRate - feedRate : feedRate - providerRate
    const deviationBps = (diff * 10_000n) / feedRate
    if (deviationBps > BigInt(runtime.config.maxFxDeviationBps)) {
      throw new Error(`on-ramp FX ${providerRate} deviates ${deviationBps} bps from Chainlink ${feedRate}`)
    }
    runtime.log(`EUR/USD ${(Number(feedRate) / 1e8).toFixed(4)} from the data feed, on-ramp rate ${deviationBps} bps off (limit ${runtime.config.maxFxDeviationBps})`)
  } else if (providerRate !== 100_000_000n) {
    throw new Error('USD deposit quoted with a non-unit rate')
  }

  // Recompute the stablecoin amount and confirm it really reached the market.
  const expected = toUsd6(BigInt(dep.fiatAmountMinor), providerRate)
  const claimed = BigInt(dep.stablecoinAmount)
  if (claimed !== expected) throw new Error(`on-ramp minted ${claimed}, expected ${expected}`)
  const unallocated = read<bigint>(runtime, runtime.config.market, marketAbi, 'unallocated')
  if (unallocated < claimed) throw new Error(`only ${unallocated} unallocated in the market, need ${claimed}`)
  runtime.log('stablecoin amount recomputed and found in the market')

  const tx = writeAction(
    runtime,
    Action.FiatFunding,
    encodeAbiParameters(parseAbiParameters('uint256 loanId, address lender, uint256 amount, bytes32 depositRef'), [
      BigInt(dep.loanId),
      dep.wallet as Address,
      claimed,
      refHash(`deposit|${reference}`),
    ]),
  )
  return bigintJson({
    credited: true,
    reference,
    loanId: dep.loanId,
    lender: dep.lenderId,
    fiat: `${dep.fiatAmountMinor / 100} ${dep.currency}`,
    providerRate,
    chainlinkRate: feedRate,
    stablecoins: claimed,
    tx,
  })
}

const initWorkflow = (config: Config) => {
  const http = new HTTPCapability()
  return [
    handler(http.trigger({ authorizedKeys: config.authorizedKeys as any }), onVerifyLender),
    handler(http.trigger({ authorizedKeys: config.authorizedKeys as any }), onFiatDeposit),
  ]
}

export async function main() {
  const runner = await Runner.newRunner<Config>({ configSchema })
  await runner.run(initWorkflow)
}
