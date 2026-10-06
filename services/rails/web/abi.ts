// The contract calls a lender's wallet makes, built in the browser. Browser safe: viem only, no node imports.

import { encodeFunctionData, parseAbi, type Address, type Hex } from 'viem'

export const marketAbi = parseAbi([
  'function fund(uint256 loanId, uint256 amount)',
  'function claim(uint256 loanId)',
])

export const stablecoinAbi = parseAbi([
  'function approve(address spender, uint256 amount) returns (bool)',
  'function drip()',
])

export type Call = { to: Address; data: Hex }
type Contracts = { market: Address; stablecoin: Address }

/** Calldata for the four transactions the app asks a wallet to sign. */
export const calls = {
  approve: (c: Contracts, amount: bigint): Call => ({
    to: c.stablecoin,
    data: encodeFunctionData({ abi: stablecoinAbi, functionName: 'approve', args: [c.market, amount] }),
  }),
  drip: (c: Contracts): Call => ({
    to: c.stablecoin,
    data: encodeFunctionData({ abi: stablecoinAbi, functionName: 'drip' }),
  }),
  fund: (c: Contracts, loanId: number, amount: bigint): Call => ({
    to: c.market,
    data: encodeFunctionData({ abi: marketAbi, functionName: 'fund', args: [BigInt(loanId), amount] }),
  }),
  claim: (c: Contracts, loanId: number): Call => ({
    to: c.market,
    data: encodeFunctionData({ abi: marketAbi, functionName: 'claim', args: [BigInt(loanId)] }),
  }),
}
