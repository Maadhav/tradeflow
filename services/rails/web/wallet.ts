// Wallet connection for lenders who fund in USDC.
//
// On a public deployment the lender signs with their own browser wallet (EIP-1193, window.ethereum),
// and the app follows its account and network. On the local deployment (a forked chain no browser
// wallet can reach) each browser gets its own built-in wallet: a real account whose private key stays
// on the server, which signs only the calls a lender needs (approve, fund, claim and the USDC faucet)
// when the browser sends the wallet key it was given. That key is kept in this browser only.

import { getAddress, type Address, type Hash } from 'viem'
import type { Call } from './abi'

export type WalletKind = 'injected' | 'builtin'
export type WalletSession = { address: Address; kind: WalletKind }
export type TxStage = 'sign' | 'pending'

type Eip1193 = {
  request(args: { method: string; params?: unknown }): Promise<any>
  on?(event: string, fn: (...args: any[]) => void): void
  removeListener?(event: string, fn: (...args: any[]) => void): void
}
type Config = {
  deployment?: any
  deploymentName?: string
  network?: string
  rpcUrl?: string
  explorer?: string | null
  chainId?: number
  builtinWallets?: boolean
}

const SEPOLIA = '0xaa36a7'
const provider = (): Eip1193 | undefined => (typeof window === 'undefined' ? undefined : (window as any).ethereum)
const same = (a?: string | null, b?: string | null) => !!a && !!b && a.toLowerCase() === b.toLowerCase()

/** The local deployment runs against a forked chain that browser wallets cannot reach. */
export function isLocal(config: Config): boolean {
  const name = config.deploymentName ?? config.network ?? (typeof config.deployment === 'string' ? config.deployment : config.deployment?.name)
  if (typeof name === 'string') return name === 'local'
  if (config.rpcUrl) return /\/\/(127\.0\.0\.1|localhost|0\.0\.0\.0)[:/]/.test(config.rpcUrl)
  return !config.explorer
}

const prefersInjected = (config: Config) => !!provider() && !isLocal(config)

/** Which wallet Connect will use here: the browser's own, a built-in one, or none. */
export function walletKind(config: Config): WalletKind | null {
  if (prefersInjected(config)) return 'injected'
  return config.builtinWallets ? 'builtin' : null
}

// This browser's built-in wallet: its address and the key that lets it ask the server to sign.
const BUILTIN_KEY = 'tradeflow.builtin'
type Builtin = { address: Address; key: string }
export function savedBuiltin(): Builtin | null {
  try {
    const b = JSON.parse(window.localStorage.getItem(BUILTIN_KEY) ?? 'null')
    return b && /^0x[0-9a-fA-F]{40}$/.test(b.address) && typeof b.key === 'string' ? { address: getAddress(b.address), key: b.key } : null
  } catch {
    return null
  }
}
function saveBuiltin(b: Builtin | null) {
  try {
    if (b) window.localStorage.setItem(BUILTIN_KEY, JSON.stringify(b))
    else window.localStorage.removeItem(BUILTIN_KEY)
  } catch {}
}
/** Headers that let this browser use its built-in wallet. */
export function builtinHeaders(address: string): Record<string, string> {
  const b = savedBuiltin()
  return b && same(b.address, address) ? { 'x-wallet-key': b.key } : {}
}
const chainHex = (config: Config) => `0x${Number(config.chainId ?? config.deployment?.chainId ?? 11155111).toString(16)}`

async function ensureChain(eth: Eip1193, config: Config) {
  const want = chainHex(config)
  const have = String(await eth.request({ method: 'eth_chainId' })).toLowerCase()
  if (have === want) return
  try {
    await eth.request({ method: 'wallet_switchEthereumChain', params: [{ chainId: want }] })
  } catch (e: any) {
    const code = e?.code ?? e?.data?.originalError?.code
    if (code !== 4902 || want !== SEPOLIA) throw e
    await eth.request({
      method: 'wallet_addEthereumChain',
      params: [
        {
          chainId: SEPOLIA,
          chainName: 'Sepolia',
          nativeCurrency: { name: 'Sepolia Ether', symbol: 'ETH', decimals: 18 },
          rpcUrls: ['https://ethereum-sepolia-rpc.publicnode.com'],
          blockExplorerUrls: [config.explorer ?? 'https://sepolia.etherscan.io'],
        },
      ],
    })
  }
}

/** A message the lender can act on, from whatever the wallet threw. */
export function walletMessage(e: any, reverted?: string): string {
  if (e?.handled) return e.message
  const code = e?.code ?? e?.data?.originalError?.code
  const text = String(e?.shortMessage ?? e?.message ?? '')
  if (code === 4001 || /user (rejected|denied)/i.test(text)) return 'You declined the request in your wallet. Try again when you are ready.'
  if (code === -32002) return 'Your wallet already has a request open. Open your wallet to finish it.'
  if (code === 4902) return 'Your wallet could not switch to Sepolia. Add the Sepolia network in your wallet, then try again.'
  if (/insufficient funds/i.test(text)) return 'This wallet does not have enough ETH to pay the network fee. Add Sepolia ETH, then try again.'
  if (reverted && /revert/i.test(text)) return reverted
  return text || 'Your wallet returned an error. Try again.'
}

const handled = (message: string) => Object.assign(new Error(message), { handled: true })

async function call(path: string, body?: unknown, headers: Record<string, string> = {}) {
  let res: Response
  try {
    res = await fetch(
      path,
      body === undefined ? { headers } : { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) },
    )
  } catch {
    throw handled('Could not reach Tradeflow. Check your connection and try again.')
  }
  const data = await res.json().catch(() => ({}))
  if (!res.ok) throw Object.assign(handled(data.error ?? `Something went wrong (${res.status}). Try again.`), { status: res.status })
  return data
}

/** True when the server still knows this browser's built-in wallet (a reset deployment forgets it). */
async function builtinUsable(b: Builtin): Promise<boolean> {
  try {
    await call(`/api/wallet/builtin/${b.address}`, undefined, { 'x-wallet-key': b.key })
    return true
  } catch (e: any) {
    if (e?.status === 401 || e?.status === 404) saveBuiltin(null)
    return false
  }
}

/**
 * Connects a browser wallet when there is one (and the deployment is public). Otherwise connects
 * this browser's built-in wallet, creating it the first time (or when `fresh` asks for a new one).
 */
export async function connect(config: Config, opts: { fresh?: boolean } = {}): Promise<WalletSession> {
  const eth = provider()
  if (eth && prefersInjected(config)) {
    try {
      const accounts: string[] = await eth.request({ method: 'eth_requestAccounts' })
      if (!accounts?.[0]) throw handled('Your wallet did not share an account. Unlock it and try again.')
      await ensureChain(eth, config)
      return { address: getAddress(accounts[0]), kind: 'injected' }
    } catch (e) {
      throw handled(walletMessage(e))
    }
  }
  if (!config.builtinWallets) throw handled('No wallet found. Install a browser wallet to continue.')
  const saved = opts.fresh ? null : savedBuiltin()
  if (saved && (await builtinUsable(saved))) return { address: saved.address, kind: 'builtin' }
  const created = (await call('/api/wallet/builtin', {})) as { address: string; key: string }
  saveBuiltin({ address: getAddress(created.address), key: created.key })
  return { address: getAddress(created.address), kind: 'builtin' }
}

/** Checks a remembered wallet against this deployment without prompting. Null when it is no longer usable. */
export async function restore(saved: WalletSession, config: Config): Promise<WalletSession | null> {
  if (saved.kind === 'builtin') {
    const b = savedBuiltin()
    return config.builtinWallets && b && same(b.address, saved.address) && (await builtinUsable(b)) ? saved : null
  }
  const eth = provider()
  if (!eth || !prefersInjected(config)) return null
  try {
    const accounts: string[] = await eth.request({ method: 'eth_accounts' })
    const hit = accounts.find((a) => same(a, saved.address)) ?? accounts[0]
    return hit ? { address: getAddress(hit), kind: 'injected' } : null
  } catch {
    return null
  }
}

/** Follows the browser wallet's account and network. Returns an unsubscribe function. */
export function watch(config: Config, on: { account: (address: Address | null) => void; chain: (ok: boolean) => void }): () => void {
  const eth = provider()
  if (!eth?.on) return () => {}
  const want = chainHex(config)
  const accounts = (a: string[]) => on.account(a?.[0] ? getAddress(a[0]) : null)
  const chain = (id: string) => on.chain(String(id).toLowerCase() === want)
  eth.on('accountsChanged', accounts)
  eth.on('chainChanged', chain)
  eth.request({ method: 'eth_chainId' }).then(chain, () => {})
  return () => {
    eth.removeListener?.('accountsChanged', accounts)
    eth.removeListener?.('chainChanged', chain)
  }
}

export async function switchChain(config: Config) {
  const eth = provider()
  if (!eth) return
  try {
    await ensureChain(eth, config)
  } catch (e) {
    throw handled(walletMessage(e))
  }
}

/** Forgets the connection. Browser wallets that support it also drop the site's permission. */
export async function disconnect(session: WalletSession) {
  const eth = provider()
  if (session.kind !== 'injected' || !eth) return
  await eth.request({ method: 'wallet_revokePermissions', params: [{ eth_accounts: {} }] }).catch(() => {})
}

/**
 * Proves to Tradeflow that this wallet is the lender's: a browser wallet signs a one-time message
 * (free, no transaction); a built-in wallet sends its wallet key. Returns what to add to the sign-up.
 */
export async function proveWallet(
  session: WalletSession,
  onStage?: (stage: 'sign') => void,
): Promise<{ body: { nonce?: string; signature?: string }; headers: Record<string, string> }> {
  if (session.kind === 'builtin') return { body: {}, headers: builtinHeaders(session.address) }
  const eth = provider()
  if (!eth) throw handled('Your browser wallet is not available. Reconnect it and try again.')
  const { nonce, message } = (await call('/api/lenders/challenge', { wallet: session.address })) as { nonce: string; message: string }
  try {
    onStage?.('sign')
    const hex = `0x${Array.from(new TextEncoder().encode(message), (b) => b.toString(16).padStart(2, '0')).join('')}`
    const signature: string = await eth.request({ method: 'personal_sign', params: [hex, session.address] })
    return { body: { nonce, signature }, headers: {} }
  } catch (e) {
    throw handled(walletMessage(e))
  }
}

async function receipt(hash: Hash): Promise<'success' | 'reverted'> {
  for (let i = 0; i < 160; i++) {
    const r = await call(`/api/tx/${hash}`).catch(() => ({ status: 'pending' }))
    if (r.status === 'success' || r.status === 'reverted') return r.status
    await new Promise((ok) => setTimeout(ok, 1500))
  }
  throw handled('The transaction is still pending. Check the activity in your wallet, then refresh this page.')
}

/**
 * Sends one transaction from the connected wallet and waits for it to be mined.
 * `reverted` is the message shown when the chain rejects the call.
 */
export async function sendTx(
  session: WalletSession,
  config: Config,
  tx: Call,
  opts: { reverted: string; onStage?: (stage: TxStage, hash?: Hash) => void },
): Promise<Hash> {
  if (session.kind === 'builtin') {
    opts.onStage?.('pending')
    const r = await call('/api/wallet/send', { from: session.address, ...tx }, builtinHeaders(session.address))
    if (r.status !== 'success') throw handled(opts.reverted)
    return r.hash
  }
  const eth = provider()
  if (!eth) throw handled('Your browser wallet is not available. Reconnect it and try again.')
  try {
    await ensureChain(eth, config)
    opts.onStage?.('sign')
    const hash: Hash = await eth.request({ method: 'eth_sendTransaction', params: [{ from: session.address, to: tx.to, data: tx.data }] })
    opts.onStage?.('pending', hash)
    if ((await receipt(hash)) !== 'success') throw handled(opts.reverted)
    return hash
  } catch (e) {
    throw handled(walletMessage(e, opts.reverted))
  }
}
