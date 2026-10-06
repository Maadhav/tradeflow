// CRE bridge: runs the Chainlink CRE workflows through the CRE CLI simulator with --broadcast,
// so every workflow run makes real calls to the rails APIs and writes real transactions through
// the CRE forwarder. Runs are queued one at a time and recorded for the activity feed.

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
  env: Record<string, string>
  broadcast: boolean
  onUpdate?: (run: WorkflowRun) => void
}

export function makeBridge(opts: BridgeOptions, runs: WorkflowRun[], persist: () => void) {
  let nextId = runs.reduce((m, r) => Math.max(m, r.id), 0) + 1
  const queue: { run: WorkflowRun; req: RunRequest; resolve: (r: WorkflowRun) => void }[] = []
  let busy = false

  function enqueue(req: RunRequest): Promise<WorkflowRun> {
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
    return new Promise((resolve) => {
      queue.push({ run, req, resolve })
      void pump()
    })
  }

  async function pump() {
    if (busy) return
    const job = queue.shift()
    if (!job) return
    busy = true
    try {
      await execute(job.run, job.req)
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

    const proc = Bun.spawn([opts.creBin, ...args], {
      cwd: opts.projectDir,
      env: { ...process.env, ...opts.env },
      stdout: 'pipe',
      stderr: 'pipe',
    })
    const [out, err] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text()])
    const code = await proc.exited
    const text = `${out}\n${err}`
    run.logs = text
      .split('\n')
      .map((l) => l.replace(/\x1b\[[0-9;]*m/g, '').trimEnd())
      .filter((l) => l.trim().length > 0)
      .slice(-120)
    run.txHashes = [...new Set([...text.matchAll(/0x[0-9a-fA-F]{64}/g)].map((m) => m[0]))].filter(
      (h) => h !== req.evmTxHash,
    )
    const at = run.logs.findIndex((l) => l.includes('Workflow Simulation Result'))
    if (at >= 0 && run.logs[at + 1]) {
      run.result = run.logs[at + 1]
      try {
        let v: unknown = JSON.parse(run.logs[at + 1])
        if (typeof v === 'string') v = JSON.parse(v)
        run.resultData = v as Record<string, any>
        const id = Number((v as any)?.loanId)
        if (Number.isFinite(id) && id > 0) run.loanId = id
      } catch {}
    }
    run.status = code === 0 && !/✗|error|failed/i.test(run.logs.slice(-5).join(' ')) ? 'success' : 'failed'
    run.finishedAt = new Date().toISOString()
  }

  return { enqueue, queueLength: () => queue.length + (busy ? 1 : 0) }
}

export type Bridge = ReturnType<typeof makeBridge>
