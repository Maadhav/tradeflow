// Chain access for the rails sandbox: reads market state, lets the on-ramp operator mint
// stablecoins when fiat arrives, signs for the built-in wallet, and watches market events that
// start CRE log-triggered workflows.
// Loan notes are ERC-3643 (T-REX) security tokens, one per loan, deployed by the market when the
// loan is listed (market.loanToken(id)). Holding them requires a wallet verified in the market's
// ERC-3643 identity registry (market.identityRegistry()), which CRE KYC reports write to.

import {
  createPublicClient,
  createWalletClient,
  http,
  parseAbi,
  type Address,
  type Hash,
  type Hex,
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
  'function usedRef(bytes32) view returns (bool)',
  'function getLoan(uint256 loanId) view returns ((address borrower, uint8 assetType, uint8 riskGrade, bytes3 currency, uint8 status, uint32 aprBps, uint32 tenorDays, uint64 listedAt, uint64 fundedAt, uint64 disbursedAt, uint64 maturity, uint64 repaidAt, uint256 faceValueMinor, uint256 fxRateE8, uint256 target, uint256 funded, uint256 fiatFunded, uint256 repaidAmount, bytes32 docHash, string ref))',
  'function loanToken(uint256 loanId) view returns (address)',
  'function identityRegistry() view returns (address)',
  'function claimIssuer() view returns (address)',
  'event LoanTokenDeployed(uint256 indexed loanId, address token)',
  'event IdentityRegistered(address indexed lender, address identity, uint16 country)',
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
  'function allowance(address owner, address spender) view returns (uint256)',
  'function mint(address to, uint256 amount)',
  'function approve(address spender, uint256 amount) returns (bool)',
  'function drip()',
])

/** A loan's ERC-3643 (T-REX) token: an ERC-20 with 6 decimals, "Tradeflow Loan Note <id>" (TFN<id>). */
export const loanTokenAbi = parseAbi([
  'function balanceOf(address) view returns (uint256)',
  'function totalSupply() view returns (uint256)',
  'function paused() view returns (bool)',
  'function name() view returns (string)',
  'function symbol() view returns (string)',
  'function decimals() view returns (uint8)',
])

/** The ERC-3643 identity registry every loan token checks before notes move. */
export const identityRegistryAbi = parseAbi(['function isVerified(address) view returns (bool)'])

/** The only calls the built-in wallet signs: approve and faucet on the stablecoin, fund and claim on the market. */
export const walletAbi = parseAbi([
  'function approve(address spender, uint256 amount) returns (bool)',
  'function drip()',
  'function fund(uint256 loanId, uint256 amount)',
  'function claim(uint256 loanId)',
])

/** Custom errors of the market, the loan tokens and the stablecoin, to explain a failing transaction. */
export const errorsAbi = parseAbi([
  'error BadStatus(uint256 loanId, uint8 status)',
  'error FundingIsPaused()',
  'error Frozen(address borrower)',
  'error NotVerified(address lender)',
  'error OverTarget(uint256 remaining)',
  'error NothingToClaim()',
  'error ZeroAmount()',
  'error UnverifiedHolder(address account)',
  'error SafeERC20FailedOperation(address token)',
  'error ERC20InsufficientBalance(address sender, uint256 balance, uint256 needed)',
  'error ERC20InsufficientAllowance(address spender, uint256 allowance, uint256 needed)',
  'error ERC20InvalidSpender(address spender)',
  'error DripCooldown(uint256 availableAt)',
  'error EnforcedPause()',
])

/** contracts/deployments/<name>.json */
export type Deployment = {
  chainId: number
  forwarder: Address
  market: Address
  stablecoin: Address
  identityRegistry?: Address
  claimIssuer?: Address
}

const ZERO = '0x0000000000000000000000000000000000000000'

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

  /** Sign and send raw calldata, wait for the receipt. */
  async function sendData(wallet: ReturnType<typeof walletFor>, to: Address, data: Hex) {
    const hash = await wallet.sendTransaction({ to, data, chain, account: wallet.account! })
    const receipt = await publicClient.waitForTransactionReceipt({ hash })
    return { hash, status: receipt.status }
  }

  // A loan's token and the identity registry never change once set, so each is read once.
  let registry: Promise<Address> | undefined
  function identityRegistry(): Promise<Address> {
    registry ??= publicClient.readContract({ address: deployment.market, abi: marketAbi, functionName: 'identityRegistry' }).catch((e) => {
      registry = undefined
      throw e
    })
    return registry
  }
  const tokens = new Map<number, Address>()
  /** The loan's ERC-3643 token, or undefined while the market has not deployed one. */
  async function loanToken(loanId: number): Promise<Address | undefined> {
    const known = tokens.get(loanId)
    if (known) return known
    const token = await publicClient.readContract({ address: deployment.market, abi: marketAbi, functionName: 'loanToken', args: [BigInt(loanId)] })
    if (token === ZERO) return undefined
    tokens.set(loanId, token)
    return token
  }

  /** CreClaimIssuer: the identity registry's trusted issuer of KYC claims, written only through CRE reports. */
  const claimIssuer = () => publicClient.readContract({ address: deployment.market, abi: marketAbi, functionName: 'claimIssuer' })

  /** True when the wallet is verified in the ERC-3643 identity registry (a valid KYC claim on its ONCHAINID). */
  async function isVerified(address: Address): Promise<boolean> {
    return publicClient.readContract({ address: await identityRegistry(), abi: identityRegistryAbi, functionName: 'isVerified', args: [address] })
  }

  /** Balances, allowance to the market, KYC flag and loan notes (balance of each loan's ERC-3643 token) of any address. */
  async function walletSnapshot(address: Address) {
    const [usdc, eth, allowance, verified, count] = await Promise.all([
      publicClient.readContract({ address: deployment.stablecoin, abi: erc20Abi, functionName: 'balanceOf', args: [address] }),
      publicClient.getBalance({ address }),
      publicClient.readContract({ address: deployment.stablecoin, abi: erc20Abi, functionName: 'allowance', args: [address, deployment.market] }),
      isVerified(address),
      publicClient.readContract({ address: deployment.market, abi: marketAbi, functionName: 'loanCount' }),
    ])
    const balances = await Promise.all(
      Array.from({ length: Number(count) }, async (_, i) => {
        const token = await loanToken(i + 1)
        return token ? publicClient.readContract({ address: token, abi: loanTokenAbi, functionName: 'balanceOf', args: [address] }) : 0n
      }),
    )
    const notes: Record<string, string> = {}
    balances.forEach((b, i) => {
      if (b > 0n) notes[String(i + 1)] = b.toString()
    })
    return { address, usdc, eth, allowance, verified, notes }
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

  return {
    chain,
    publicClient,
    operatorWallet,
    walletFor,
    send,
    sendData,
    walletSnapshot,
    onRampMint,
    readLoan,
    loanToken,
    identityRegistry,
    claimIssuer,
    isVerified,
    marketSnapshot,
    eventIndexIn,
  }
}

