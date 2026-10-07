// Monitor workflow: loan health and the three-way reconciliation circuit breaker.
//
// Trigger: cron.
// 1. Reads every loan's state and maturity onchain. A disbursed loan past maturity is marked
//    Late and its business is frozen (no new listings); a loan still unpaid after the grace
//    period is marked Defaulted. The market pauses a late or defaulted loan's ERC-3643 token, so
//    its notes stop moving until the loan is repaid.
// 2. Reconciles three independent records of fiat-funded money:
//      a. cash received, per the bank's books
//      b. stablecoins minted for those deposits, per the on-ramp's books
//      c. stablecoins credited to lenders as loan notes (ERC-3643 tokens), per the market contract
//    and checks the market is solvent (stablecoins held >= reserved obligations).
//    Any mismatch is reported onchain and the market pauses new funding until an operator
//    investigates.

import {
  ConsensusAggregationByFields,
  CronCapability,
  HTTPClient,
  Runner,
  handler,
  identical,
  json,
  ok,
  type HTTPSendRequester,
  type Runtime,
} from '@chainlink/cre-sdk'
import { encodeAbiParameters, keccak256, parseAbiParameters } from 'viem'
import { z } from 'zod'
import { Action, Status, baseConfig, bigintJson, erc20Abi, loanTokenAbi, loanTokenOf, marketAbi, read, tokenSymbol, writeAction } from './lib'

const configSchema = baseConfig.extend({
  schedule: z.string(),
  apiKeySecretId: z.string(),
  graceDays: z.number(),
})
type Config = z.infer<typeof configSchema>

type Books = { bankUsd6: string; onrampUsd6: string }

const onSchedule = (runtime: Runtime<Config>): string => {
  const market = runtime.config.market
  const now = BigInt(Math.floor(runtime.now().getTime() / 1000))
  const actions: unknown[] = []

  // ---- 1. Loan health ----
  const count = read<bigint>(runtime, market, marketAbi, 'loanCount')
  const secondsPerDay = BigInt(read<number>(runtime, market, marketAbi, 'secondsPerDay'))
  if (count > 0n) {
    const [statuses, maturities] = read<readonly [readonly number[], readonly bigint[], readonly bigint[], readonly bigint[]]>(
      runtime,
      market,
      marketAbi,
      'loanStates',
      [1n, count],
    )
    for (let i = 0; i < statuses.length; i++) {
      const loanId = BigInt(i + 1)
      const status = statuses[i]
      const maturity = maturities[i]
      const graceEnds = maturity + BigInt(runtime.config.graceDays) * secondsPerDay
      let next: number | undefined
      if (status === Status.Disbursed && maturity > 0n && now > maturity) next = Status.Late
      else if (status === Status.Late && now > graceEnds) next = Status.Defaulted
      if (next !== undefined) {
        const tx = writeAction(
          runtime,
          Action.LoanStatus,
          encodeAbiParameters(parseAbiParameters('uint256 loanId, uint8 newStatus, bool freezeBorrower'), [loanId, next, true]),
        )
        const tokenPaused = read<boolean>(runtime, loanTokenOf(runtime, loanId), loanTokenAbi, 'paused')
        runtime.log(
          `loan ${loanId} ${next === Status.Late ? 'is past maturity: marked late' : 'is past the grace period: marked defaulted'}, business frozen, ` +
            `ERC-3643 token ${tokenSymbol(loanId)} ${tokenPaused ? 'paused' : 'still transferable'}`,
        )
        actions.push({ loanId, status: next === Status.Late ? 'late' : 'defaulted', businessFrozen: true, tokenPaused, tx })
      }
    }
  }
  runtime.log(`loan health: ${count} loan${count === 1n ? '' : 's'} checked, ${actions.length} status change${actions.length === 1 ? '' : 's'}`)

  // ---- 2. Three-way reconciliation ----
  const apiKey = runtime.getSecret({ id: runtime.config.apiKeySecretId }).result().value
  const fetchBooks = (sender: HTTPSendRequester, key: string): Books => {
    const res = sender
      .sendRequest({ url: `${runtime.config.railsUrl}/v1/ledger/summary`, method: 'GET', headers: { 'x-api-key': key } })
      .result()
    if (!ok(res)) throw new Error(`ledger HTTP ${res.statusCode}`)
    const b = json(res) as Books
    return { bankUsd6: String(b.bankUsd6), onrampUsd6: String(b.onrampUsd6) }
  }
  const books = new HTTPClient()
    .sendRequest(runtime, fetchBooks, ConsensusAggregationByFields<Books>({ bankUsd6: identical, onrampUsd6: identical }))(apiKey)
    .result()

  // Three independent records of the same money must agree:
  //   bank books (cash received)  ==  on-ramp books (stablecoins minted)  ==  market (credited as notes)
  const cashAtBank = BigInt(books.bankUsd6)
  const stablecoinsMinted = BigInt(books.onrampUsd6)
  const creditedOnchain = read<bigint>(runtime, market, marketAbi, 'totalFiatIn')
  const reserved = read<bigint>(runtime, market, marketAbi, 'reserved')
  const held = read<bigint>(runtime, runtime.config.stablecoin, erc20Abi, 'balanceOf', [market])

  const bankMatchesOnramp = cashAtBank === stablecoinsMinted
  const onrampMatchesChain = stablecoinsMinted === creditedOnchain
  const solvent = held >= reserved
  const okAll = bankMatchesOnramp && onrampMatchesChain && solvent
  runtime.log(
    okAll
      ? 'reconciliation: bank books, on-ramp books and the market agree, market is solvent'
      : `reconciliation: mismatch (${[!bankMatchesOnramp && 'bank vs on-ramp', !onrampMatchesChain && 'on-ramp vs market', !solvent && 'solvency'].filter(Boolean).join(', ')}), pausing new funding`,
  )
  const snapshotHash = keccak256(
    encodeAbiParameters(parseAbiParameters('uint256,uint256,uint256,uint256,uint256,uint256'), [
      cashAtBank,
      stablecoinsMinted,
      creditedOnchain,
      held,
      reserved,
      now,
    ]),
  )
  const reconTx = writeAction(
    runtime,
    Action.Reconciliation,
    encodeAbiParameters(parseAbiParameters('bool ok, uint256 fiatReceived, uint256 stablecoinsHeld, uint256 notesOutstanding, bytes32 snapshotHash'), [
      okAll,
      cashAtBank,
      stablecoinsMinted,
      creditedOnchain,
      snapshotHash,
    ]),
  )

  return bigintJson({
    checkedAt: runtime.now().toISOString(),
    loans: count,
    statusChanges: actions,
    reconciliation: {
      ok: okAll,
      cashAtBank,
      stablecoinsMinted,
      creditedOnchain,
      stablecoinsHeld: held,
      reserved,
      checks: { bankMatchesOnramp, onrampMatchesChain, solvent },
      tx: reconTx,
    },
  })
}

const initWorkflow = (config: Config) => [handler(new CronCapability().trigger({ schedule: config.schedule }), onSchedule)]

export async function main() {
  const runner = await Runner.newRunner<Config>({ configSchema })
  await runner.run(initWorkflow)
}
