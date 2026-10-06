// Shared helpers for the Tradeflow CRE workflows (copied into each workflow directory).

import {
  EVMClient,
  LATEST_BLOCK_NUMBER,
  TxStatus,
  bytesToHex,
  encodeCallMsg,
  getNetwork,
  prepareReportRequest,
  type Runtime,
} from '@chainlink/cre-sdk'
import {
  decodeFunctionResult,
  encodeAbiParameters,
  encodeFunctionData,
  keccak256,
  parseAbi,
  parseAbiParameters,
  toHex,
  zeroAddress,
  type Abi,
  type Address,
  type Hex,
} from 'viem'
import { z } from 'zod'

export const baseConfig = z.object({
  chainSelectorName: z.string(),
  market: z.string(),
  stablecoin: z.string(),
  notes: z.string(),
  eurUsdFeed: z.string(),
  railsUrl: z.string(),
  gasLimit: z.string(),
})
export type BaseConfig = z.infer<typeof baseConfig>

/** Report actions understood by TradeflowMarket._processReport. */
export const Action = {
  ListLoan: 1,
  VerifyLender: 2,
  FiatFunding: 3,
  Disbursed: 4,
  Repaid: 5,
  FiatRedeemed: 6,
  LoanStatus: 7,
  Reconciliation: 8,
} as const

export const Status = { None: 0, Listed: 1, Funded: 2, Disbursed: 3, Repaid: 4, Late: 5, Defaulted: 6 } as const

export const marketAbi = parseAbi([
  'function loanCount() view returns (uint256)',
  'function reserved() view returns (uint256)',
  'function totalFiatIn() view returns (uint256)',
  'function unallocated() view returns (uint256)',
  'function secondsPerDay() view returns (uint32)',
  'function loanStates(uint256 fromId, uint256 toId) view returns (uint8[] statuses, uint64[] maturities, uint256[] funded, uint256[] fiatFunded)',
  'function getLoan(uint256 loanId) view returns ((address borrower, uint8 assetType, uint8 riskGrade, bytes3 currency, uint8 status, uint32 aprBps, uint32 tenorDays, uint64 listedAt, uint64 fundedAt, uint64 disbursedAt, uint64 maturity, uint64 repaidAt, uint256 faceValueMinor, uint256 fxRateE8, uint256 target, uint256 funded, uint256 fiatFunded, uint256 repaidAmount, bytes32 docHash, string ref))',
])
export const erc20Abi = parseAbi(['function balanceOf(address) view returns (uint256)'])
export const notesAbi = parseAbi(['function balanceOf(address account, uint256 id) view returns (uint256)'])
export const feedAbi = parseAbi([
  'function latestRoundData() view returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound)',
])

export function evm(runtime: Runtime<BaseConfig>): EVMClient {
  const network = getNetwork({ chainFamily: 'evm', chainSelectorName: runtime.config.chainSelectorName, isTestnet: true })
  if (!network) throw new Error(`unknown chain selector name ${runtime.config.chainSelectorName}`)
  return new EVMClient(network.chainSelector.selector)
}

/** Read a view function at the latest block and decode the result. */
export function read<T>(runtime: Runtime<BaseConfig>, to: string, abi: Abi, functionName: string, args: unknown[] = []): T {
  const reply = evm(runtime)
    .callContract(runtime, {
      call: encodeCallMsg({
        from: zeroAddress,
        to: to as Address,
        data: encodeFunctionData({ abi, functionName, args } as any),
      }),
      blockNumber: LATEST_BLOCK_NUMBER,
    })
    .result()
  return decodeFunctionResult({ abi, functionName, data: bytesToHex(reply.data) } as any) as T
}

/** Chainlink Data Feed: EUR/USD with 8 decimals. Rejects unanswered or stale rounds. */
export function readEurUsd(runtime: Runtime<BaseConfig>, maxAgeSeconds = 2n * 86_400n): bigint {
  const [roundId, answer, , updatedAt, answeredInRound] = read<readonly [bigint, bigint, bigint, bigint, bigint]>(
    runtime,
    runtime.config.eurUsdFeed,
    feedAbi,
    'latestRoundData',
  )
  if (roundId === 0n || answeredInRound < roundId || answer <= 0n) throw new Error('EUR/USD round not answered')
  const now = BigInt(Math.floor(runtime.now().getTime() / 1000))
  if (updatedAt > now + 300n) throw new Error('EUR/USD round from the future')
  if (now - updatedAt > maxAgeSeconds) throw new Error('EUR/USD feed is stale')
  return answer
}

/** Encode (action, payload), sign it as a CRE report and deliver it to the market. */
export function writeAction(runtime: Runtime<BaseConfig>, action: number, payload: Hex): string {
  const encoded = encodeAbiParameters(parseAbiParameters('uint8 action, bytes payload'), [action, payload])
  const report = runtime.report(prepareReportRequest(encoded)).result()
  const reply = evm(runtime)
    .writeReport(runtime, {
      receiver: runtime.config.market,
      report,
      gasConfig: { gasLimit: runtime.config.gasLimit },
    })
    .result()
  if (reply.txStatus !== TxStatus.SUCCESS) {
    throw new Error(reply.errorMessage ?? `report write failed with status ${reply.txStatus}`)
  }
  if (!reply.txHash) throw new Error('report write succeeded without a transaction hash')
  const hash = bytesToHex(reply.txHash)
  // The forwarder transaction can succeed while the receiver reverts: treat that as a failure.
  // (EVM ReceiverContractExecutionStatus: 0 = SUCCESS, 1 = REVERTED)
  if ((reply.receiverContractExecutionStatus ?? 0) !== 0) {
    throw new Error(`market rejected the report (action ${action}), tx ${hash}`)
  }
  runtime.log(`report delivered: action=${action} tx=${hash}`)
  return hash
}

export const refHash = (ref: string): Hex => keccak256(toHex(ref))

/** HTTP trigger input is JSON bytes. */
export function decodeInput<T>(input: Uint8Array): T {
  return JSON.parse(new TextDecoder().decode(input)) as T
}

export const toUsd6 = (amountMinor: bigint, rateE8: bigint): bigint => (amountMinor * rateE8 * 10_000n) / 100_000_000n

export const bigintJson = (v: unknown) => JSON.stringify(v, (_, x) => (typeof x === 'bigint' ? x.toString() : x))
