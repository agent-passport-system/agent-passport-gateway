// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Chain spend (Day 268): a spend counts against every bounded delegation on the
// acting delegation's bound chain, not only against the acting delegation.
//
// Before this module, /evaluate and the Nano wallet send checked and debited
// spend_used on the selected inbound row only. A root granting B $100, with B
// granting C $30, let C spend $30 and then B spend $100: $130 under a $100 grant.
// Two children of one parent could each spend the parent's whole budget.
//
// The rule now matches the SDK's draft-03 budget ledger (the cumulative limit of a
// delegation applies to its whole subtree): every row on the chain, from the acting
// delegation up to the terminal grant, must have room for the cost, and on permit
// every row on the chain is debited. Both run inside the caller's IMMEDIATE
// transaction, so concurrent spends serialize on the database write lock.
// ══════════════════════════════════════════════════════════════════
import type Database from 'better-sqlite3'

/** Same ceiling as checkBoundAuthorityChain in enforce.ts. Kept here rather than imported
 *  so this module does not import enforce.ts, which imports it. */
const MAX_CHAIN_HOPS = 64

export interface ChainSpendRow {
  id: string
  spend_limit: number | null
  spend_used: number | null
}

/**
 * The acting delegation and its ancestors, nearest first, following parent_delegation_id.
 * Returns null when the walk cannot complete (missing row, other tenant, cycle, too many
 * hops). Callers treat null as a denial: a chain whose budgets cannot be read is not a
 * chain whose budgets have room.
 */
export function boundChainSpendRows(
  db: Database.Database,
  tenantId: string,
  startDelegationId: string,
): ChainSpendRow[] | null {
  const rows: ChainSpendRow[] = []
  const seen = new Set<string>()
  let currentId: string | null = startDelegationId
  while (currentId) {
    if (rows.length >= MAX_CHAIN_HOPS || seen.has(currentId)) return null
    seen.add(currentId)
    const row = db.prepare(
      `SELECT id, tenant_id, spend_limit, spend_used, parent_delegation_id FROM delegations WHERE id = ?`,
    ).get(currentId) as any
    if (!row || row.tenant_id !== tenantId) return null
    rows.push({ id: row.id, spend_limit: row.spend_limit ?? null, spend_used: row.spend_used ?? null })
    currentId = row.parent_delegation_id ?? null
  }
  return rows
}

/**
 * The first ancestor (hop 2 or above, the acting row is hop 1) whose remaining budget is
 * smaller than cost, or null when every bounded ancestor has room. The acting row itself
 * is left to the caller's existing check so its denial text is unchanged.
 * `round` lets a caller apply the same rounding it already uses for the acting row.
 */
export function ancestorSpendViolation(
  rows: readonly ChainSpendRow[],
  cost: number,
  round: (n: number) => number = n => n,
): { hop: number; remaining: number } | null {
  for (let i = 1; i < rows.length; i++) {
    const r = rows[i]
    if (r.spend_limit == null) continue
    const remaining = round(r.spend_limit - (r.spend_used || 0))
    if (round(cost) > remaining) return { hop: i + 1, remaining }
  }
  return null
}

/** Add (or, with a negative sign, reverse) a spend on every row of the chain. */
export function applyChainSpend(
  db: Database.Database,
  rows: readonly ChainSpendRow[],
  amount: number,
  amountCents: number,
): void {
  const stmt = db.prepare(
    `UPDATE delegations
     SET spend_used = spend_used + ?,
         spend_used_cents = COALESCE(spend_used_cents, 0) + ?
     WHERE id = ?`,
  )
  for (const r of rows) stmt.run(amount, amountCents, r.id)
}

// ══════════════════════════════════════════════════════════════════
// Upgrade hold (0.4.3): spending under chains whose counters predate this module.
//
// Before 0.4.3 a delegation's spend_used held only its own direct spending. After the
// upgrade, a parent's counter does not include what its children spent earlier, so a
// parent with $100 whose child spent $20 would read $100 remaining instead of $80. This
// holds every delegation whose counter cannot be trusted, and every spend whose chain
// touches a held delegation is refused until an operator reconciles it.
//
// Held at upgrade, in one transaction gated on a schema_migrations marker:
//   - every ancestor, through parent_delegation_id, of a delegation that had spent
//   - every legacy sub-delegation with no parent_delegation_id whose grantor itself held
//     an inbound delegation in the same tenant (rows from before 0.4.1, when chains were
//     not bound), together with that grantor's inbound delegation and its ancestors.
//     The chain walk cannot see these links, so their spending would stay uncounted.
// Each hold records the delegation's direct spend_used at upgrade time as evidence.
// Rows created after the upgrade are never held. A fresh database gets the marker and
// no holds.
//
// Releasing a hold is an operator decision: either revoke the chain and grant new
// delegations, or reconcile the counters from the recorded direct spending and delete
// the hold rows. Nothing here caps or rewrites a counter.
// ══════════════════════════════════════════════════════════════════

export const CHAIN_SPEND_HOLD_MIGRATION_ID = 'chain_spend_upgrade_hold_v1'

export function ensureChainSpendHoldTable(db: Database.Database): void {
  db.exec(`CREATE TABLE IF NOT EXISTS chain_spend_holds (
    delegation_id      TEXT PRIMARY KEY,
    tenant_id          TEXT NOT NULL,
    reason             TEXT NOT NULL,
    direct_spend_used  REAL,
    created_at         TEXT NOT NULL
  )`)
}

/** Compute and record the upgrade holds once. Returns how many delegations were held, or
 *  'already' when the marker was present. Runs inside initDB, before the server listens.
 *  The holds and the marker commit in one IMMEDIATE transaction: an interrupted run leaves
 *  neither, and the next boot runs it again. An error is not caught here, so a failed
 *  migration stops the boot instead of serving on unheld counters. */
export function runChainSpendUpgradeHold(db: Database.Database, opts: { maxAttempts?: number } = {}): number | 'already' {
  ensureChainSpendHoldTable(db)
  const done = () => db.prepare(`SELECT 1 FROM schema_migrations WHERE id = ? AND status = 'complete'`).get(CHAIN_SPEND_HOLD_MIGRATION_ID)
  if (done()) return 'already'
  const txn = db.transaction((): number | 'already' => {
    if (done()) return 'already'
    const rows = db.prepare(
      `SELECT id, tenant_id, parent_agent_id, child_agent_id, parent_delegation_id, spend_used FROM delegations`,
    ).all() as any[]
    const byId = new Map<string, any>(rows.map(r => [r.id, r]))
    const holds = new Map<string, { tenant: string; reason: string; spent: number | null }>()
    const hold = (id: string, reason: string) => {
      const r = byId.get(id)
      if (r && !holds.has(id)) holds.set(id, { tenant: r.tenant_id, reason, spent: r.spend_used ?? null })
    }
    const holdAncestors = (startParentId: string | null, reason: string) => {
      const seen = new Set<string>()
      let id = startParentId
      while (id && !seen.has(id) && seen.size < MAX_CHAIN_HOPS) {
        seen.add(id)
        hold(id, reason)
        id = byId.get(id)?.parent_delegation_id ?? null
      }
    }
    for (const r of rows) {
      if (r.parent_delegation_id && (r.spend_used || 0) > 0) holdAncestors(r.parent_delegation_id, 'descendant_spent_before_upgrade')
    }
    const inboundOf = new Map<string, any[]>()
    for (const p of rows) {
      const k = `${p.tenant_id}\u0000${p.child_agent_id}`
      const list = inboundOf.get(k)
      if (list) list.push(p)
      else inboundOf.set(k, [p])
    }
    for (const r of rows) {
      if (r.parent_delegation_id) continue
      const inbound = (inboundOf.get(`${r.tenant_id}\u0000${r.parent_agent_id}`) ?? []).filter(p => p.id !== r.id)
      if (inbound.length === 0) continue
      hold(r.id, 'unbound_legacy_subdelegation')
      for (const p of inbound) {
        hold(p.id, 'unbound_legacy_descendant')
        holdAncestors(p.parent_delegation_id, 'unbound_legacy_descendant')
      }
    }
    const now = new Date().toISOString()
    const ins = db.prepare(`INSERT OR IGNORE INTO chain_spend_holds (delegation_id, tenant_id, reason, direct_spend_used, created_at) VALUES (?, ?, ?, ?, ?)`)
    for (const [id, h] of holds) ins.run(id, h.tenant, h.reason, h.spent, now)
    db.prepare(
      `INSERT INTO schema_migrations (id, status, applied_at) VALUES (?, 'complete', ?)
       ON CONFLICT(id) DO UPDATE SET status = 'complete', applied_at = excluded.applied_at`,
    ).run(CHAIN_SPEND_HOLD_MIGRATION_ID, now)
    return holds.size
  })
  // Same bounded retry as runIsRootOriginBackfill: a concurrent boot holding the write lock
  // longer than busy_timeout surfaces SQLITE_BUSY, and the winner's marker answers it.
  const maxAttempts = Math.max(1, opts.maxAttempts ?? 12)
  for (let attempt = 1; ; attempt++) {
    if (done()) return 'already'
    try {
      return txn.immediate()
    } catch (e: any) {
      const busy = e && (e.code === 'SQLITE_BUSY' || /database is locked|SQLITE_BUSY/i.test(String(e.message || '')))
      if (busy && attempt < maxAttempts) continue
      throw e
    }
  }
}

/** The first held delegation on the chain, or null. */
export function chainSpendHold(
  db: Database.Database,
  rows: readonly ChainSpendRow[],
): { delegation_id: string; reason: string } | null {
  const stmt = db.prepare(`SELECT delegation_id, reason FROM chain_spend_holds WHERE delegation_id = ?`)
  for (const r of rows) {
    const h = stmt.get(r.id) as any
    if (h) return { delegation_id: h.delegation_id, reason: h.reason }
  }
  return null
}
