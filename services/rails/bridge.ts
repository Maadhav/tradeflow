// CRE bridge: runs the Chainlink CRE workflows through the CRE CLI simulator with --broadcast,
// so every workflow run makes real calls to the rails APIs and writes real transactions through
// the CRE forwarder. Runs are queued one at a time and recorded for the activity feed. The CLI's
// output is streamed line by line into the run (and the server console) while it executes.

export type WorkflowRun = {
  id: number
  workflow: string
  handler: string
  trigger: string
  input: string
  status: 'queued' | 'running' | 'success' | 'failed'
  queuedAt: string
  startedAt?: string
  finishedAt?: string
  txHashes: string[]
  result?: string
  resultData?: Record<string, any>
  loanId?: number
  logs: string[]
}

export type RunRequest = {
  workflow: string
  handler: string
  triggerIndex: number
  trigger: 'http' | 'evm-log' | 'cron'
  httpPayload?: unknown
  evmTxHash?: string
  evmEventIndex?: number
  loanId?: number
}

type BridgeOptions = {
  creBin: string
  projectDir: string
  target: string
  envFile?: string // the CLI's secrets (--env); it wins over the process environment
  env: Record<string, string>
  broadcast: boolean
  onUpdate?: (run: WorkflowRun) => void
}

const MAX_LOG_LINES = 200
const UPDATE_EVERY_MS = 250 // live updates: at most ~4 per second while a run streams
const RUN_TIMEOUT_MS = 5 * 60_000
const RATE_LIMIT_RETRIES = 4
const stripAnsi = (s: string) => s.replace(/\x1b\[[0-9;?]*[A-Za-z]/g, '')

export function makeBridge(opts: BridgeOptions, runs: WorkflowRun[], persist: () => void) {
  let nextId = runs.reduce((m, r) => Math.max(m, r.id), 0) + 1
  const queue: { run: WorkflowRun; req: RunRequest; resolve: (r: WorkflowRun) => void }[] = []
  let busy = false

  /** Queue a run and return it straight away (it updates in place); `done` settles when it finishes. */
  function start(req: RunRequest): { run: WorkflowRun; done: Promise<WorkflowRun> } {
    const run: WorkflowRun = {
      id: nextId++,
      workflow: req.workflow,
      handler: req.handler,
      trigger: req.trigger,
      input: req.httpPayload ? JSON.stringify(req.httpPayload) : req.evmTxHash ? `tx ${req.evmTxHash} #${req.evmEventIndex ?? 0}` : 'schedule',
      status: 'queued',
      queuedAt: new Date().toISOString(),
      txHashes: [],
      logs: [],
      loanId: req.loanId,
    }
    runs.unshift(run)
    if (runs.length > 200) runs.length = 200
    persist()
    opts.onUpdate?.(run)
    const done = new Promise<WorkflowRun>((resolve) => {
      queue.push({ run, req, resolve })
      void pump()
    })
    return { run, done }
  }

  /** Queue a run and wait for it to finish. */
  const enqueue = (req: RunRequest): Promise<WorkflowRun> => start(req).done

  async function pump() {
    if (busy) return
    const job = queue.shift()
    if (!job) return
    busy = true
    try {
      // A public RPC can throttle the simulator (HTTP 429), and the CLI's credential check can time
      // out before the run starts. Retry such runs, but never one that already delivered a report,
      // so a retry cannot write twice.
      for (let attempt = 1; ; attempt++) {
        await execute(job.run, job.req)
        const throttled =
          job.run.status === 'failed' &&
          job.run.logs.some((l) => /429|Too Many Requests|rate limit|context deadline exceeded|Credential validation failed/i.test(l))
        const authTimeout = job.run.status === 'failed' && job.run.logs.some((l) => /Credential validation failed/i.test(l))
        const delivered = job.run.logs.some((l) => /report delivered/i.test(l))
        if (!(throttled || authTimeout) || delivered || attempt >= RATE_LIMIT_RETRIES) break
        const why = throttled ? 'rate limited by the RPC' : 'the CLI could not validate its credentials in time'
        console.log(`[run ${job.run.id} ${job.run.workflow}/${job.run.handler}] ${why}, retrying (${attempt + 1} of ${RATE_LIMIT_RETRIES})`)
        await new Promise((r) => setTimeout(r, 6_000 * attempt))
        job.run.logs = []
      }
    } catch (e) {
      job.run.status = 'failed'
      job.run.logs.push(`could not run the workflow: ${(e as Error).message}`)
      job.run.finishedAt = new Date().toISOString()
    } finally {
      busy = false
      job.resolve(job.run)
      persist()
      opts.onUpdate?.(job.run)
      void pump()
    }
  }

  async function execute(run: WorkflowRun, req: RunRequest) {
    run.status = 'running'
    run.startedAt = new Date().toISOString()
    opts.onUpdate?.(run)
    const args = [
      'workflow', 'simulate', req.workflow,
      '--target', opts.target,
      '--non-interactive',
      '--trigger-index', String(req.triggerIndex),
    ]
    if (req.httpPayload !== undefined) args.push('--http-payload', JSON.stringify(req.httpPayload))
    if (req.evmTxHash) args.push('--evm-tx-hash', req.evmTxHash, '--evm-event-index', String(req.evmEventIndex ?? 0))
    if (opts.broadcast) args.push('--broadcast')
    if (opts.envFile) args.push('--env', opts.envFile)

    const proc = Bun.spawn([opts.creBin, ...args], {
      cwd: opts.projectDir,
      env: { ...process.env, ...opts.env },
      stdout: 'pipe',
      stderr: 'pipe',
    })
    const killer = setTimeout(() => proc.kill(), RUN_TIMEOUT_MS)

    // Live output: each line lands in run.logs and the server console as it arrives.
    const prefix = `[run ${run.id} ${run.workflow}/${run.handler}]`
    let lastUpdate = 0
    let pending: ReturnType<typeof setTimeout> | undefined
    const update = () => {
      const wait = UPDATE_EVERY_MS - (Date.now() - lastUpdate)
      if (wait <= 0) {
        lastUpdate = Date.now()
        opts.onUpdate?.(run)
      } else if (!pending) {
        pending = setTimeout(() => {
          pending = undefined
          lastUpdate = Date.now()
          opts.onUpdate?.(run)
        }, wait)
      }
    }
    const onLine = (raw: string, sink: string[]) => {
      const line = stripAnsi(raw).replace(/\r/g, '').trimEnd()
      if (line.trim().length === 0) return
      sink.push(line)
      run.logs.push(line)
      if (run.logs.length > MAX_LOG_LINES) run.logs.splice(0, run.logs.length - MAX_LOG_LINES)
      console.log(`${prefix} ${line}`)
      update()
    }
    const read = async (stream: ReadableStream<Uint8Array>, sink: string[]) => {
      const decoder = new TextDecoder()
      let text = ''
      let buf = ''
      const reader = stream.getReader()
      for (;;) {
        const { value, done } = await reader.read()
        if (done) break
        const part = decoder.decode(value, { stream: true })
        text += part
        buf += part
        let nl: number
        while ((nl = buf.indexOf('\n')) >= 0) {
          onLine(buf.slice(0, nl), sink)
          buf = buf.slice(nl + 1)
        }
      }
      const rest = decoder.decode()
      text += rest
      buf += rest
      if (buf) onLine(buf, sink)
      return text
    }

    const outLines: string[] = []
    const errLines: string[] = []
    const [out, err] = await Promise.all([read(proc.stdout, outLines), read(proc.stderr, errLines)])
    const code = await proc.exited
    clearTimeout(killer)
    clearTimeout(pending)

    // Result parsing and status: stdout then stderr, as the CLI prints them.
    const lines = [...outLines, ...errLines]
    const text = `${out}\n${err}`
    run.txHashes = [...new Set([...text.matchAll(/0x[0-9a-fA-F]{64}/g)].map((m) => m[0]))].filter(
      (h) => h !== req.evmTxHash,
    )
    const at = lines.findIndex((l) => l.includes('Workflow Simulation Result'))
    if (at >= 0 && lines[at + 1]) {
      run.result = lines[at + 1]
      try {
        let v: unknown = JSON.parse(lines[at + 1])
        if (typeof v === 'string') v = JSON.parse(v)
        run.resultData = v as Record<string, any>
        const id = Number((v as any)?.loanId)
        if (Number.isFinite(id) && id > 0) run.loanId = id
      } catch {}
    }
    run.status = code === 0 && !/✗|error|failed/i.test(lines.slice(-5).join(' ')) ? 'success' : 'failed'
    run.finishedAt = new Date().toISOString()
    console.log(`${prefix} ${run.status}${code === 0 ? '' : ` (exit ${code})`}`)
  }

  return { start, enqueue, queueLength: () => queue.length + (busy ? 1 : 0) }
}

export type Bridge = ReturnType<typeof makeBridge>
