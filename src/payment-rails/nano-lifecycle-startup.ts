// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Nano lifecycle startup (Day 268): installs the in-process runner the send route schedules on,
 * runs one recovery pass at startup and then one per interval, and reports its state.
 *
 * Recovery never builds a second block for an operation and never publishes while paused, because
 * every step goes through runOp and commitAttempt. An empty wallet_ops table makes no node calls.
 *
 * State is reported, not hidden. GET /healthz/nano-lifecycle answers 503 while the first pass has
 * not finished, when a pass threw or hit an integrity fault, and when the wallet-to-account mapping
 * is unsafe, and while any released payment has been contradicted (see below). /healthz itself stays 200 on purpose: the gateway serves much more than Nano, and this
 * service has a volume, so Railway cannot overlap deployments, and a failing /healthz during a
 * Nano node outage would take the whole gateway down on deploy.
 *
 * Each pass also runs watchFinalized: a failed_final payment whose own block later shows confirmed
 * freezes its wallet and holds its chain. Until an operator records the contradiction as resolved
 * (resolveContradictedRelease, after reconciling the affected budgets), the state is blocked, so no
 * new send is reserved anywhere. Unfreezing the wallet alone does not clear it. The release was made
 * on the configured node's evidence, and a contradiction means that evidence was wrong. A blocked
 * pass still reconciles and watches: only new sends stop.
 */
import type Database from 'better-sqlite3'
import { getMasterSeed, deriveAccount, deriveAddress } from './wallet-crypto.js'
import { walletAccountProblems, type WalletOp } from './wallet-ops.js'
import type { Signer } from './nano-publish.js'
import { inProcessRunner, lifecycleTick, setOpRunner, watchFinalized, type RunContext, type RunResult } from './wallet-reconcile.js'

export type LifecycleState = 'starting' | 'ok' | 'degraded' | 'blocked'

export interface LifecycleStatus {
  state: LifecycleState
  pending: number
  last_tick_at: number | null
  last_error: string | null
  integrity_faults: number
  unsafe_mapping: string[]
  /** failed_final payments whose own block later confirmed, not yet recorded as resolved by an operator. */
  contradicted: number
  /** Conflict incidents (a signed block of the account on our previous) not yet resolved by an operator. */
  incidents: number
  /** Node faults (a reported block that is not a signed block of the account) not yet resolved. */
  node_faults: number
}

/** How long after a release watchFinalized keeps checking it, by default. */
export const DEFAULT_FINAL_WATCH_MS = 7 * 24 * 3600_000

export interface LifecycleHandle {
  status(): LifecycleStatus
  tickNow(): Promise<RunResult[]>
  stop(): void
}

/** The production signer: the key for an operation's wallet index, checked against its account. */
export function seedSigner(db: Database.Database): (op: WalletOp) => Signer {
  return (op) => {
    const w = db.prepare(`SELECT wallet_index, nano_address FROM agent_wallets WHERE id = ?`).get(op.wallet_id) as any
    if (!w || w.nano_address !== op.nano_account) throw new Error('signer: wallet row does not match the operation account')
    const acct = deriveAccount(getMasterSeed(), w.wallet_index) // throws while NANO_WALLETS_PAUSED=1
    if (acct.address !== op.nano_account) throw new Error('signer: derived key does not match the operation account')
    return { address: acct.address, privateKey: acct.privateKey }
  }
}

/** The gateway's own account (seed index 0), or null when the seed cannot be read (for example, paused). */
export function gatewayAddressOrNull(): string | null {
  try { return deriveAddress(getMasterSeed(), 0).address } catch { return null }
}

export function startNanoLifecycle(db: Database.Database, opts: {
  ctx: RunContext
  tickMs: number
  gatewayAddress: string | null
  /** How long after a release to keep checking it for contradiction. Default DEFAULT_FINAL_WATCH_MS. */
  finalWatchMs?: number
}): LifecycleHandle {
  const status: LifecycleStatus = {
    state: 'starting', pending: 0, last_tick_at: null, last_error: null, integrity_faults: 0, unsafe_mapping: [], contradicted: 0, incidents: 0, node_faults: 0,
  }
  const watchMs = opts.finalWatchMs ?? DEFAULT_FINAL_WATCH_MS
  // New sends are reserved only while the lifecycle reports ok: not while the first pass is still
  // running, and not while it is degraded or blocked (activation gate 2).
  setOpRunner({ ...inProcessRunner(db, opts.ctx), readiness: () => status.state === 'ok' ? null : `lifecycle_${status.state}` })

  let running: Promise<RunResult[]> | null = null
  const tick = (): Promise<RunResult[]> => {
    if (running) return running
    running = (async () => {
      const unsafe = walletAccountProblems(db, opts.gatewayAddress)
      let results: RunResult[] = []
      let error: string | null = null
      try {
        results = await lifecycleTick(db, opts.ctx)
      } catch (e: any) {
        error = String(e?.message ?? e)
      }
      try {
        await watchFinalized(db, opts.ctx.node, opts.ctx.now(), watchMs, opts.ctx.reconcile.source)
      } catch (e: any) {
        error = error ?? `watchFinalized: ${String(e?.message ?? e)}`
      }
      const contradicted = (db.prepare(`SELECT COUNT(*) AS c FROM wallet_ops WHERE status = 'failed_final'
        AND json_extract(resolution, '$.contradicted') IS NOT NULL AND json_extract(resolution, '$.contradicted.resolved') IS NULL`).get() as any).c
      const faults = results.filter(r => r.step === 'integrity_fault').length
      const frontierFaults = results.filter(r => r.step === 'prepare_failed' && /^frontier_/.test(r.detail ?? '')).length
      const count = (sql: string) => (db.prepare(sql).get() as any).c as number
      const incidents = count(`SELECT COUNT(*) AS c FROM wallet_ops WHERE json_extract(resolution, '$.incident') IS NOT NULL
        AND json_extract(resolution, '$.incident.resolved') IS NULL`)
      // Counted whatever the payment's status: a node fault stays until an operator records it,
      // even when the payment later confirms.
      const nodeFaults = count(`SELECT COUNT(*) AS c FROM wallet_ops
        WHERE json_extract(resolution, '$.node_fault') IS NOT NULL AND json_extract(resolution, '$.node_fault.resolved') IS NULL`)
      const failed = results.filter(r => r.step === 'error')
      if (!error && failed.length) error = failed[0].detail ?? 'operation error'
      status.pending = (db.prepare(`SELECT COUNT(*) AS c FROM wallet_ops WHERE status IN ('reserved', 'prepared', 'admitted')`).get() as any).c
      status.last_tick_at = opts.ctx.now()
      status.last_error = error
      status.integrity_faults = faults
      status.unsafe_mapping = unsafe
      status.contradicted = contradicted
      status.incidents = incidents
      status.node_faults = nodeFaults
      status.state = (unsafe.length || contradicted || incidents) ? 'blocked'
        : (error || faults || nodeFaults || frontierFaults) ? 'degraded' : 'ok'
      if (status.state !== 'ok') {
        const why = incidents ? `${incidents} unresolved conflict incident(s)`
          : contradicted ? `${contradicted} unresolved contradicted release(s)`
          : nodeFaults ? `${nodeFaults} unresolved node fault(s)`
          : frontierFaults ? `${frontierFaults} send(s) waiting on the frontier record`
          : error ?? (faults ? `${faults} integrity fault(s)` : unsafe.join('; '))
        console.error(`[nano-lifecycle] ${status.state}: ${why}`)
      }
      return results
    })().finally(() => { running = null })
    return running
  }

  void tick()
  const timer = setInterval(() => { void tick() }, opts.tickMs)
  timer.unref?.()
  return {
    status: () => ({ ...status, unsafe_mapping: [...status.unsafe_mapping] }),
    tickNow: tick,
    stop: () => { clearInterval(timer); setOpRunner(null) },
  }
}

/**
 * HTTP status and body for GET /healthz/nano-lifecycle. The endpoint has no auth, so the body is the
 * state word only: no counts, wallet identifiers, block data or error text. Details go to the logs.
 */
export function lifecycleHealth(handle: LifecycleHandle | null): { code: number; body: { state: string } } {
  if (!handle) return { code: 200, body: { state: 'disabled' } }
  const s = handle.status()
  return { code: s.state === 'ok' ? 200 : 503, body: { state: s.state } }
}
