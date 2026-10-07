// Exports the Sepolia workflow runs as judge-facing evidence:
//   evidence/README.md        the contracts (market, stablecoin, ERC-3643 identity registry, claim
//                             issuer and every loan's ERC-3643 token) and one row per run: workflow,
//                             trigger, capabilities, outcome, Sepolia tx
//   evidence/logs/<n>-<handler>.log   the full `cre workflow simulate --broadcast` output of each run
// Usage: bun scripts/export-evidence.ts
// Env: DEPLOYMENT (default sepolia), RPC_URL (default SEPOLIA_RPC or the public Sepolia node),
//      OUT_DIR (default evidence/, so a local run can be checked without touching the real evidence).

import { decodeFunctionResult, encodeFunctionData, parseAbi } from '../services/rails/node_modules/viem/_esm/index.js'

const ROOT = new URL('../', import.meta.url).pathname
const DEPLOYMENT = process.env.DEPLOYMENT ?? 'sepolia'
const RPC_URL = process.env.RPC_URL ?? process.env.SEPOLIA_RPC ?? 'https://ethereum-sepolia-rpc.publicnode.com'
const OUT_DIR = (process.env.OUT_DIR ?? `${ROOT}evidence`).replace(/\/$/, '')
const state = await Bun.file(`${ROOT}services/rails/data/state.${DEPLOYMENT}.json`).json()
const dep = await Bun.file(`${ROOT}contracts/deployments/${DEPLOYMENT}.json`).json()
const runs: any[] = [...state.runs].filter((r) => r.status === 'success').sort((a, b) => a.id - b.id)
const ETHERSCAN = 'https://sepolia.etherscan.io'

// ---- contracts: the market's ERC-3643 identity registry and each loan's token, read onchain ----
const ZERO = '0x0000000000000000000000000000000000000000'
const abi = parseAbi([
  'function loanCount() view returns (uint256)',
  'function loanToken(uint256 loanId) view returns (address)',
  'function identityRegistry() view returns (address)',
])
async function read<T>(to: string, functionName: string, args: unknown[] = []): Promise<T> {
  const res = await fetch(RPC_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'eth_call',
      params: [{ to, data: encodeFunctionData({ abi, functionName, args } as any) }, 'latest'],
    }),
  })
  const { result, error } = (await res.json()) as any
  if (error || !result || result === '0x') throw new Error(`${functionName} on ${to}: ${error?.message ?? 'no data'}`)
  return decodeFunctionResult({ abi, functionName, data: result } as any) as T
}
const registry: string | undefined = dep.identityRegistry ?? (await read<string>(dep.market, 'identityRegistry').catch(() => undefined))
const loanTokens: { loanId: number; token: string }[] = []
try {
  const count = Number(await read<bigint>(dep.market, 'loanCount'))
  for (let id = 1; id <= count; id++) {
    const token = await read<string>(dep.market, 'loanToken', [BigInt(id)])
    if (token !== ZERO) loanTokens.push({ loanId: id, token })
  }
} catch (e) {
  console.warn(`loan tokens not listed: ${(e as Error).message}`)
}
const link = (a: string) => `[\`${a}\`](${ETHERSCAN}/address/${a})`
const contractRows = [
  `| TradeflowMarket (CRE receiver, deploys one ERC-3643 token per loan) | ${link(dep.market)} |`,
  `| Test stablecoin (tUSDC) | ${link(dep.stablecoin)} |`,
  ...(registry ? [`| ERC-3643 identity registry (ONCHAINID identities of verified lenders) | ${link(registry)} |`] : []),
  ...(dep.claimIssuer ? [`| CreClaimIssuer (CRE as the trusted KYC claim issuer) | ${link(dep.claimIssuer)} |`] : []),
  ...loanTokens.map(({ loanId, token }) => `| Loan ${loanId} notes: ERC-3643 token TFN${loanId} | ${link(token)} |`),
]

const CAPS: Record<string, string> = {
  'verify-and-list': 'Confidential Workflow (TEE, `handlerInTee`), HTTP in enclave, EVM read (Chainlink EUR/USD Data Feed), EVM write (lists the loan and deploys its ERC-3643 token)',
  'verify-lender': 'Confidential HTTP (Vault DON secret), EVM read and write: the KYC claim on the lender\'s ONCHAINID, issued through CreClaimIssuer, registers the wallet in the ERC-3643 identity registry',
  'credit-fiat-deposit': 'Confidential HTTP, EVM read (Chainlink EUR/USD, market, ERC-3643 identity registry and loan token), EVM write (mints ERC-3643 loan notes)',
  'disburse-on-funded': 'EVM log trigger, HTTP POST with consensus, EVM read/write',
  'confirm-repayment': 'HTTP trigger, `runInNodeMode` over two sources with consensus, EVM read/write',
  'redeem-fiat-lenders': 'EVM log trigger, HTTP with consensus, EVM read (ERC-3643 loan token balances), EVM write (burns the notes)',
  'watch-and-reconcile': 'Cron trigger, EVM read, HTTP with consensus, EVM write (a late loan\'s ERC-3643 token is paused)',
}
const TRIGGER: Record<string, string> = { http: 'HTTP', 'evm-log': 'EVM log', cron: 'Cron' }

function outcome(r: any): string {
  const d = r.resultData ?? {}
  switch (r.handler) {
    case 'verify-and-list':
      return d.listed
        ? `Listed ${d.docNumber}: grade ${d.grade}, APR ${d.aprBps / 100}%, advance $${Number(d.target) / 1e6}${d.currency === 'EUR' ? `, EUR/USD ${Number(d.fxRateE8) / 1e8}` : ''}${d.loanId ? `; ERC-3643 token TFN${d.loanId} deployed` : ''}`
        : `Rejected ${d.docNumber}: ${d.reason}`
    case 'verify-lender':
      return d.verified
        ? `KYC verified: ${d.lenderId}${d.country ? `, registered in the ERC-3643 identity registry (country ${d.country})` : ''}`
        : `KYC not approved: ${d.lenderId}${d.reason ? ` (${d.reason})` : ''}`
    case 'credit-fiat-deposit':
      return `Credited $${Number(d.stablecoins) / 1e6} for ${d.fiat}; on-ramp ${Number(d.providerRate) / 1e8} vs Chainlink ${Number(d.chainlinkRate) / 1e8}`
    case 'disburse-on-funded':
      return `Paid $${Number(d.amount) / 1e6} to the business (${d.payoutRef}), loan ${d.loanId}`
    case 'confirm-repayment':
      return `Repayment $${Number(d.amount) / 1e6} from ${d.payer}, confirmed by ${d.sources?.join(' and ')}`
    case 'redeem-fiat-lenders':
      return (d.redeemed ?? []).map((x: any) => `${x.lender} paid $${Number(x.payout) / 1e6} (${x.payoutRef})`).join('; ') || 'no fiat lenders'
    case 'watch-and-reconcile': {
      const changes = (d.statusChanges ?? [])
        .map((c: any) => `loan ${c.loanId} ${c.status}, business frozen${c.tokenPaused ? `, ERC-3643 token TFN${c.loanId} paused` : ''}`)
        .join('; ')
      return `Reconciliation ${d.reconciliation?.ok ? 'passed' : 'FAILED (funding paused)'}${changes ? `; ${changes}` : ''}`
    }
  }
  return ''
}

function txs(r: any): string[] {
  const d = r.resultData ?? {}
  return [d.tx, d.reconciliation?.tx, ...(d.redeemed ?? []).map((x: any) => x.tx), ...(d.statusChanges ?? []).map((x: any) => x.tx)].filter(Boolean)
}

await Bun.$`mkdir -p ${OUT_DIR}/logs`
const rows: string[] = []
for (const r of runs) {
  const file = `logs/${String(r.id).padStart(2, '0')}-${r.handler}.log`
  await Bun.write(`${OUT_DIR}/${file}`, `${r.logs.join('\n')}\n`)
  const links = txs(r).map((h) => `[${h.slice(0, 10)}…](${ETHERSCAN}/tx/${h})`).join('<br>')
  rows.push(`| ${r.id} | \`${r.workflow}\` · ${r.handler} | ${TRIGGER[r.trigger] ?? r.trigger} | ${CAPS[r.handler] ?? ''} | ${outcome(r)} | ${links || '(no write: rejected)'} | [log](${file}) |`)
}

const md = `# Evidence: CRE workflow simulations on Ethereum Sepolia

Every run below is \`cre workflow simulate <workflow> --target sepolia --broadcast\` (CRE CLI v1.37),
executed by the app as the loan moved through its lifecycle. Each onchain write is a signed CRE report
delivered through the Sepolia **MockKeystoneForwarder** (\`${dep.forwarder}\`) to the market contract.

| Contract | Address |
|---|---|
${contractRows.join('\n')}

| # | Workflow · handler | Trigger | CRE capabilities used | Outcome | Sepolia transaction | Log |
|---|---|---|---|---|---|---|
${rows.join('\n')}

Generated by \`scripts/export-evidence.ts\` from the app's run history.
`
await Bun.write(`${OUT_DIR}/README.md`, md)
console.log(`wrote ${OUT_DIR}/README.md with ${runs.length} runs and ${contractRows.length} contracts`)
