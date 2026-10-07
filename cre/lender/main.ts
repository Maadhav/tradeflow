// Lender workflow: KYC onboarding and crediting fiat deposits.
//
// Handler 0 (HTTP): a lender finished onboarding. CRE checks the KYC provider over
// Confidential HTTP (the provider credential is injected only inside the enclave) and reports the
// result to the market, which registers the wallet in the ERC-3643 identity registry: the lender
// gets an ONCHAINID identity holding a KYC claim issued by CreClaimIssuer (written only through
// these reports), with the ISO 3166 numeric code of the KYC country. Every loan's ERC-3643 token
// checks that registry, so loan notes can only be held by verified people.
//
// Handler 1 (HTTP): the on-ramp reports that a lender's bank transfer settled and was converted
// to stablecoins. CRE independently:
//   - fetches the deposit from the on-ramp and the lender's KYC file (Confidential HTTP)
//   - checks the on-ramp's FX rate against Chainlink's EUR/USD Data Feed (max deviation)
//   - recomputes the stablecoin amount from fiat x rate
//   - confirms onchain that the stablecoins actually reached the market, unallocated
//   - confirms the wallet is verified in the ERC-3643 identity registry
// and only then credits the lender with loan notes (the loan's ERC-3643 token, minted by the market).

import { ConfidentialHTTPClient, HTTPCapability, Runner, handler, json, ok, type HTTPPayload, type Runtime } from '@chainlink/cre-sdk'
import { encodeAbiParameters, parseAbiParameters, type Address } from 'viem'
import { z } from 'zod'
import {
  Action,
  baseConfig,
  bigintJson,
  decodeInput,
  isVerifiedInRegistry,
  loanTokenAbi,
  loanTokenOf,
  marketAbi,
  read,
  readEurUsd,
  refHash,
  toUsd6,
  tokenSymbol,
  writeAction,
} from './lib'

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

/**
 * ISO 3166-1 numeric code of each country a lender can be resident in (the KYC file carries the
 * alpha-2 code). The identity registry stores the numeric code; a country missing here is refused,
 * never registered as 0.
 */
const ISO_NUMERIC: Record<string, number> = {
  AE: 784, AR: 32, AT: 40, AU: 36, BD: 50, BE: 56, BR: 76, CA: 124, CH: 756, CI: 384,
  CL: 152, CN: 156, CO: 170, CR: 188, CU: 192, CZ: 203, DE: 276, DK: 208, EC: 218, EG: 818,
  ES: 724, ET: 231, FI: 246, FR: 250, GB: 826, GH: 288, GR: 300, HK: 344, HU: 348, ID: 360,
  IE: 372, IL: 376, IN: 356, IR: 364, IT: 380, JP: 392, KE: 404, KP: 408, KR: 410, LK: 144,
  MA: 504, MX: 484, MY: 458, NG: 566, NL: 528, NO: 578, NZ: 554, PA: 591, PE: 604, PH: 608,
  PK: 586, PL: 616, PT: 620, QA: 634, RO: 642, SA: 682, SE: 752, SG: 702, SY: 760, TH: 764,
  TR: 792, TW: 158, TZ: 834, UG: 800, US: 840, UY: 858, VN: 704, ZA: 710,
}

const onVerifyLender = (runtime: Runtime<Config>, payload: HTTPPayload): string => {
  const { lenderId } = decodeInput<{ lenderId: string }>(payload.input)
  const kyc = confidentialGet<Kyc>(runtime, `/v1/kyc/${lenderId}`)
  runtime.log(`KYC file received: ${kyc.status}`)
  if (kyc.status !== 'approved') {
    runtime.log(`KYC not approved for ${lenderId}: ${kyc.status}`)
    return JSON.stringify({ verified: false, lenderId, status: kyc.status })
  }
  const alpha2 = String(kyc.country ?? '').toUpperCase()
  const country = ISO_NUMERIC[alpha2]
  if (!country) {
    const reason = `KYC country ${alpha2 || '(none)'} has no ISO 3166 numeric code on file, so no identity claim can be issued`
    runtime.log(`identity not registered: ${reason}`)
    return JSON.stringify({ verified: false, lenderId, status: 'unsupported country', reason })
  }
  const wallet = kyc.wallet as Address

  // A wallet already verified in the registry needs no second identity.
  if (isVerifiedInRegistry(runtime, wallet)) {
    runtime.log('wallet already verified in the ERC-3643 identity registry, nothing to write')
    return JSON.stringify({ verified: true, lenderId, wallet, level: kyc.level, country, alreadyVerified: true })
  }

  const kycRef = refHash(`kyc|${kyc.lenderId}|${kyc.level}`)
  const tx = writeAction(
    runtime,
    Action.VerifyLender,
    encodeAbiParameters(parseAbiParameters('address lender, bool verified, bytes32 kycRef, uint16 country'), [wallet, true, kycRef, country]),
  )
  const registered = isVerifiedInRegistry(runtime, wallet)
  runtime.log(
    registered
      ? `KYC claim issued, wallet registered in the ERC-3643 identity registry (country ${country})`
      : 'report accepted, but the ERC-3643 identity registry does not show the wallet as verified yet',
  )
  return JSON.stringify({ verified: true, lenderId, wallet, level: kyc.level, country, identityVerified: registered, tx })
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

  // Loan notes are the loan's ERC-3643 token: only a wallet verified in the identity registry can receive them.
  const loanId = BigInt(dep.loanId)
  if (!isVerifiedInRegistry(runtime, dep.wallet as Address)) throw new Error('lender wallet is not verified in the ERC-3643 identity registry')
  const token = loanTokenOf(runtime, loanId)
  const before = read<bigint>(runtime, token, loanTokenAbi, 'balanceOf', [dep.wallet])

  const tx = writeAction(
    runtime,
    Action.FiatFunding,
    encodeAbiParameters(parseAbiParameters('uint256 loanId, address lender, uint256 amount, bytes32 depositRef'), [
      loanId,
      dep.wallet as Address,
      claimed,
      refHash(`deposit|${reference}`),
    ]),
  )
  const minted = read<bigint>(runtime, token, loanTokenAbi, 'balanceOf', [dep.wallet]) - before
  runtime.log(`loan notes minted: ${(Number(minted) / 1e6).toFixed(2)} ${tokenSymbol(loanId)} (ERC-3643) to the lender's wallet`)
  return bigintJson({
    credited: true,
    reference,
    loanId: dep.loanId,
    token,
    notesMinted: minted,
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
