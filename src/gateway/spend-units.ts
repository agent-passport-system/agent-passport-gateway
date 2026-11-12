// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Day 268: explicit spending units on delegations.
//
// Before this, a delegation's budget was one REAL column with no unit. The grant path wrote
// USD into it and the Nano wallet route added XNO to the same column. A unit-declared
// delegation now carries:
//   spend_unit         'iso4217:USD:minor' (cents) or 'nano:XNO:raw' (1 XNO = 10^30 raw)
//   spend_limit_minor  canonical decimal integer string, or NULL for no limit in that unit
//   spend_used_minor   canonical decimal integer string
// Amounts are compared and added as BigInt, because raw XNO amounts exceed both JavaScript's
// safe integer range and SQLite's 64-bit INTEGER.
//
// Legacy rows (spend_unit NULL) keep their REAL columns and their /evaluate behavior exactly as
// before. A unit-declared row stores spend_limit = 0 in the REAL column, so every code path
// that reads only the REAL columns sees a zero budget and refuses to spend, instead of
// reading an absent limit as no limit. Only the unit-aware paths read the minor columns.
//
// Ambiguity is refused, never guessed:
//   - a unit-declared grant under a legacy BOUNDED parent is refused: the parent's REAL budget
//     has no proven unit, so it cannot bound the child.
//   - a legacy (unit-less) grant under a unit-declared parent is refused: it would escape the
//     parent's budget.
//   - a unit-aware spend through any legacy bounded row on its chain is refused.
// Nothing converts between units.
// ══════════════════════════════════════════════════════════════════
import type Database from 'better-sqlite3'

export const SPEND_UNITS = ['iso4217:USD:minor', 'nano:XNO:raw'] as const
export type SpendUnit = typeof SPEND_UNITS[number]
export const XNO_RAW: SpendUnit = 'nano:XNO:raw'

const CANONICAL = /^(0|[1-9][0-9]*)$/

export const isSpendUnit = (u: unknown): u is SpendUnit => typeof u === 'string' && (SPEND_UNITS as readonly string[]).includes(u)

/** BigInt for a canonical unsigned decimal integer string, otherwise null. */
export function parseMinor(s: unknown): bigint | null {
  return typeof s === 'string' && CANONICAL.test(s) ? BigInt(s) : null
}

const XNO_DECIMAL = /^(0|[1-9][0-9]*)(\.[0-9]{1,30})?$/
const RAW_PER_XNO = 10n ** 30n

/** Raw XNO for an exact decimal XNO string, without floating point. null for anything else,
 *  including JSON numbers, exponents, signs and more than 30 decimals. */
export function exactXnoToRaw(xno: unknown): string | null {
  if (typeof xno !== 'string' || !XNO_DECIMAL.test(xno)) return null
  const [whole, frac = ''] = xno.split('.')
  return (BigInt(whole) * RAW_PER_XNO + BigInt(frac.padEnd(30, '0'))).toString()
}

/** Exact XNO decimal string for a canonical raw amount (display only). */
export function rawToExactXno(raw: string): string {
  const r = BigInt(raw)
  const whole = r / RAW_PER_XNO
  const frac = (r % RAW_PER_XNO).toString().padStart(30, '0').replace(/0+$/, '')
  return frac ? `${whole}.${frac}` : whole.toString()
}

/**
 * The send amount from a request body. Accepts amount_raw, a canonical decimal integer string
 * of raw XNO, or amount_xno, an exact decimal string. Refuses JSON numbers: JSON.parse has
 * already rounded them, so 1 XNO and 1 XNO plus 1 raw arrive as the same value. The raw string
 * returned is the one amount used for the budget check, the debit and the wallet executor.
 */
export function parseSendAmount(body: { amount_raw?: unknown; amount_xno?: unknown }): { raw: string } | { error: string } {
  const hasRaw = body.amount_raw !== undefined && body.amount_raw !== null
  const hasXno = body.amount_xno !== undefined && body.amount_xno !== null
  if (hasRaw && hasXno) return { error: 'Send either amount_raw or amount_xno, not both' }
  if (hasRaw) {
    const v = parseMinor(body.amount_raw)
    if (v === null || v === 0n) return { error: 'amount_raw must be a canonical positive decimal integer string of raw XNO' }
    return { raw: v.toString() }
  }
  if (hasXno) {
    if (typeof body.amount_xno === 'number') {
      return { error: 'amount_xno must be a decimal string, for example "0.1". A JSON number loses precision. Or send amount_raw.' }
    }
    const raw = exactXnoToRaw(body.amount_xno)
    if (raw === null || raw === '0') return { error: 'amount_xno must be a positive decimal string with at most 30 decimals' }
    return { raw }
  }
  return { error: 'Required: amount_raw or amount_xno' }
}

/** The unit fields of one delegation row. */
export interface UnitRow {
  id: string
  spend_unit: string | null
  spend_limit: number | null
  spend_limit_minor: string | null
  spend_used_minor: string | null
}

/** A legacy row has no declared unit. Bounded means it carries a REAL limit. */
const legacyBounded = (r: UnitRow) => r.spend_unit == null && r.spend_limit != null

/**
 * Narrowing for the unit fields of a new grant. parent is the grantor's inbound delegation, or
 * null for a designated root. Returns null when allowed, otherwise the refusal reason.
 */
export function unitNarrowingViolation(
  parent: UnitRow | null,
  child: { spend_unit: string | null; spend_limit_minor: string | null },
): string | null {
  if (child.spend_unit != null && !isSpendUnit(child.spend_unit)) return 'spend_unit_unknown'
  if (child.spend_unit != null && child.spend_limit_minor != null && parseMinor(child.spend_limit_minor) === null) {
    return 'spend_limit_minor_not_canonical'
  }
  if (!parent) return null
  if (parent.spend_unit == null) {
    if (child.spend_unit == null) return null // legacy under legacy: unchanged rules apply
    return legacyBounded(parent) ? 'parent_budget_unit_unproven' : null
  }
  // parent is unit-declared
  if (child.spend_unit == null) return 'spend_unit_required_under_unit_parent'
  if (child.spend_unit !== parent.spend_unit) return 'spend_unit_mismatch'
  const pLimit = parent.spend_limit_minor == null ? null : parseMinor(parent.spend_limit_minor)
  if (parent.spend_limit_minor != null && pLimit === null) return 'parent_budget_corrupt'
  if (pLimit === null) return null // parent unbounded in this unit
  if (child.spend_limit_minor == null) return 'child_unbounded_under_bounded_parent'
  const pUsed = parseMinor(parent.spend_used_minor ?? '0')
  if (pUsed === null) return 'parent_budget_corrupt'
  return parseMinor(child.spend_limit_minor)! > pLimit - pUsed ? 'spend_limit_exceeds_parent_remaining' : null
}

/** The bound chain from a delegation up to its root, leaf first, with unit fields. */
export function unitChainRows(db: Database.Database, tenantId: string, delegationId: string): UnitRow[] | null {
  const rows: UnitRow[] = []
  const seen = new Set<string>()
  let id: string | null = delegationId
  while (id) {
    if (seen.has(id)) return null // a cycle is corrupt state
    seen.add(id)
    const r = db.prepare(
      `SELECT id, tenant_id, spend_unit, spend_limit, spend_limit_minor, spend_used_minor, parent_delegation_id
         FROM delegations WHERE id = ?`,
    ).get(id) as any
    if (!r || r.tenant_id !== tenantId) return null
    rows.push({ id: r.id, spend_unit: r.spend_unit ?? null, spend_limit: r.spend_limit ?? null,
      spend_limit_minor: r.spend_limit_minor ?? null, spend_used_minor: r.spend_used_minor ?? null })
    id = r.parent_delegation_id ?? null
  }
  return rows
}

/**
 * Whether `amount` in `unit` fits every row of the chain (leaf first). The leaf must be
 * declared in `unit` and bounded. Every other row must be declared in `unit` or be a legacy
 * row with no limit. Returns null when it fits, otherwise the refusal reason.
 */
export function unitSpendViolation(rows: readonly UnitRow[], unit: SpendUnit, amount: bigint): string | null {
  if (amount <= 0n) return 'amount_not_positive'
  const leaf = rows[0]
  if (!leaf || leaf.spend_unit !== unit) return 'unit_not_delegated'
  if (leaf.spend_limit_minor == null) return 'spend_unbounded_refused'
  for (const r of rows) {
    if (r.spend_unit == null) {
      if (legacyBounded(r)) return 'unit_not_delegated'
      continue
    }
    if (r.spend_unit !== unit) return 'unit_not_delegated'
    if (r.spend_limit_minor == null) continue
    const limit = parseMinor(r.spend_limit_minor)
    const used = parseMinor(r.spend_used_minor ?? '0')
    if (limit === null || used === null) return 'budget_corrupt'
    if (amount > limit - used) return 'budget_exceeded'
  }
  return null
}

/**
 * Add `delta` (negative to reverse) to spend_used_minor on every unit-declared row of the chain.
 * Call inside the same transaction as unitSpendViolation. Throws on a result below zero.
 */
export function applyUnitSpend(db: Database.Database, rows: readonly UnitRow[], delta: bigint): void {
  const upd = db.prepare(`UPDATE delegations SET spend_used_minor = ? WHERE id = ?`)
  for (const r of rows) {
    if (r.spend_unit == null) continue
    const cur = db.prepare(`SELECT spend_used_minor FROM delegations WHERE id = ?`).get(r.id) as any
    const used = parseMinor(cur?.spend_used_minor ?? '0')
    if (used === null) throw new Error(`spend_used_minor is not canonical on delegation ${r.id}`)
    const next = used + delta
    if (next < 0n) throw new Error(`spend_used_minor would go below zero on delegation ${r.id}`)
    upd.run(next.toString(), r.id)
  }
}
