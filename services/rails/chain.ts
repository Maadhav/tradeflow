// Chain access for the rails sandbox: reads market state, lets the on-ramp operator mint
// stablecoins when fiat arrives, and watches market events that start CRE log-triggered workflows.

import {
  createPublicClient,
  createWalletClient,
  http,
  parseAbi,
  type Address,
  type Hash,
  type Log,
} from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { sepolia } from 'viem/chains'

export const marketAbi = parseAbi([
  'function loanCount() view returns (uint256)',
  'function reserved() view returns (uint256)',
  'function totalFiatIn() view returns (uint256)',
  'function unallocated() view returns (uint256)',
  'function fundingPaused() view returns (bool)',
  'function secondsPerDay() view returns (uint32)',
  'function frozenBorrower(address) view returns (bool)',
  'function settlementAccount() view returns (address)',
  'function lastReconciliation() view returns (bool ok, uint64 at, uint256 fiatReceived, uint256 stablecoinsHeld, uint256 notesOutstanding, bytes32 snapshotHash)',
  'function fund(uint256 loanId, uint256 amount)',
  'function claim(uint256 loanId)',
  'function resumeFunding()',
  'function getLoan(uint256 loanId) view returns ((address borrower, uint8 assetType, uint8 riskGrade, bytes3 currency, uint8 status, uint32 aprBps, uint32 tenorDays, uint64 listedAt, uint64 fundedAt, uint64 disbursedAt, uint64 maturity, uint64 repaidAt, uint256 faceValueMinor, uint256 fxRateE8, uint256 target, uint256 funded, uint256 fiatFunded, uint256 repaidAmount, bytes32 docHash, string ref))',
  'event LoanListed(uint256 indexed loanId, address indexed borrower, string ref, uint256 target, uint32 aprBps, uint32 tenorDays, uint8 riskGrade, bytes32 docHash)',
  'event LenderVerified(address indexed lender, bool verified, bytes32 kycRef)',
  'event Funded(uint256 indexed loanId, address indexed lender, uint256 amount, bool viaFiat, bytes32 ref)',
  'event LoanFullyFunded(uint256 indexed loanId, address indexed borrower, uint256 amount)',
  'event Disbursed(uint256 indexed loanId, uint256 amount, bytes32 payoutRef, uint64 maturity)',
  'event Repaid(uint256 indexed loanId, uint256 amount, bytes32 paymentRef)',
  'event Claimed(uint256 indexed loanId, address indexed lender, uint256 notesBurned, uint256 payout)',
  'event FiatRedeemed(uint256 indexed loanId, address indexed lender, uint256 payout, bytes32 payoutRef)',
  'event StatusChanged(uint256 indexed loanId, uint8 status)',
  'event BorrowerFrozen(address indexed borrower, uint256 indexed loanId)',
  'event Reconciled(bool ok, uint256 fiatReceived, uint256 stablecoinsHeld, uint256 notesOutstanding, bytes32 snapshotHash)',
  'event FundingPaused(bool paused)',
])

export const erc20Abi = parseAbi([
  'function balanceOf(address) view returns (uint256)',
  'function mint(address to, uint256 amount)',
  'function approve(address spender, uint256 amount) returns (bool)',
  'function drip()',
])

export const notesAbi = parseAbi([
  'function balanceOf(address account, uint256 id) view returns (uint256)',
  'function totalSupply(uint256 id) view returns (uint256)',
  'function isVerifiedHolder(address) view returns (bool)',
])

export type Deployment = { market: Address; notes: Address; stablecoin: Address; forwarder: Address; chainId: number }

export function makeChain(rpcUrl: string, deployment: Deployment, operatorKey: `0x${string}`) {
  const chain = { ...sepolia, rpcUrls: { default: { http: [rpcUrl] } } }
  const publicClient = createPublicClient({ chain, transport: http(rpcUrl) })
  const operator = privateKeyToAccount(operatorKey)
  const operatorWallet = createWalletClient({ chain, transport: http(rpcUrl), account: operator })

  const walletFor = (key: `0x${string}`) =>
    createWalletClient({ chain, transport: http(rpcUrl), account: privateKeyToAccount(key) })

  async function send(wallet: ReturnType<typeof walletFor>, address: Address, abi: any, functionName: string, args: any[]) {
    const hash = await wallet.writeContract({ address, abi, functionName, args, chain, account: wallet.account! })
    const receipt = await publicClient.waitForTransactionReceipt({ hash })
    if (receipt.status !== 'success') throw new Error(`${functionName} reverted: ${hash}`)
    return hash as Hash
  }

  /** On-ramp operator mints stablecoins for a settled fiat deposit straight into the market. */
  async function onRampMint(amount: bigint): Promise<Hash> {
    return send(operatorWallet, deployment.stablecoin, erc20Abi, 'mint', [deployment.market, amount])
  }

  async function readLoan(id: bigint) {
    return publicClient.readContract({ address: deployment.market, abi: marketAbi, functionName: 'getLoan', args: [id] })
  }

  async function marketSnapshot() {
    const [loanCount, reserved, totalFiatIn, unallocated, fundingPaused, recon, held] = await Promise.all([
      publicClient.readContract({ address: deployment.market, abi: marketAbi, functionName: 'loanCount' }),
      publicClient.readContract({ address: deployment.market, abi: marketAbi, functionName: 'reserved' }),
      publicClient.readContract({ address: deployment.market, abi: marketAbi, functionName: 'totalFiatIn' }),
      publicClient.readContract({ address: deployment.market, abi: marketAbi, functionName: 'unallocated' }),
      publicClient.readContract({ address: deployment.market, abi: marketAbi, functionName: 'fundingPaused' }),
      publicClient.readContract({ address: deployment.market, abi: marketAbi, functionName: 'lastReconciliation' }),
      publicClient.readContract({ address: deployment.stablecoin, abi: erc20Abi, functionName: 'balanceOf', args: [deployment.market] }),
    ])
    return { loanCount, reserved, totalFiatIn, unallocated, fundingPaused, recon, held }
  }

  /** Index of a given event within a transaction receipt (for --evm-event-index). */
  async function eventIndexIn(txHash: Hash, eventTopic: `0x${string}`): Promise<number> {
    const receipt = await publicClient.getTransactionReceipt({ hash: txHash })
    const idx = receipt.logs.findIndex(
      (l) => l.address.toLowerCase() === deployment.market.toLowerCase() && l.topics[0] === eventTopic,
    )
    if (idx < 0) throw new Error(`event ${eventTopic} not found in ${txHash}`)
    return idx
  }

  return { chain, publicClient, operatorWallet, walletFor, send, onRampMint, readLoan, marketSnapshot, eventIndexIn }
}

export type ChainApi = ReturnType<typeof makeChain>
export type MarketLog = Log
