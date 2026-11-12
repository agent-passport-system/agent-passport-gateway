// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// buildAgentTrustProfile — shared profile builder
// ══════════════════════════════════════════════════════════════════
//
// Both /api/v1/public/trust/:agentId and /api/v1/public/trust/by-wallet/:address
// return the same envelope shape. Extracted into a single function so the
// two routes cannot drift in behavior, and so the wallet→agent reverse
// lookup composes cleanly with the existing endpoint.
//
// Inputs: a fully fetched agent row (already validated to exist) plus
// optional context (walletParam for the deprecated query-string mode,
// matchedWalletEntry for the by-wallet route, window_days for trust
// decay). Returns the public-facing profile JSON.
// ══════════════════════════════════════════════════════════════════

import type Database from 'better-sqlite3'

export interface AgentRow {
  id: string
  tenant_id: string
  agent_id: string
  public_key: string
  did: string | null
  status: string
  created_at: string
  metadata: string | null
  [key: string]: any
}

export interface BuildTrustProfileOpts {
  db: Database.Database
  agent: AgentRow
  agentId: string
  /** Optional wallet address surfaced via deprecated query-string mode. */
  walletParam?: string
  /** Optional chain hint for walletParam. */
  chainParam?: string
  /** Optional matched wallet entry from the reverse-index lookup. Surfaced
   *  on by-wallet responses so callers see which entry resolved. */
  matchedWalletEntry?: { chain: string; address: string; bound_at: string; binding_sig: string }
  /** Optional trust window for per-task-class breakdown. */
  windowDays?: number
  /** Continuity score helper (server.ts owns the implementation). */
  computeContinuityScore: (db: Database.Database, tenantId: string, agentId: string, ageDays: number) => {
    score: number
    context_break: boolean
    signals: any
  }
}

export interface TrustProfile {
  agent_id: string
  grade: number
  grade_label: string
  trust: string
  age_days: number
  risk_level: string
  has_delegation: boolean
  has_wallet: boolean
  wallet_ref: Array<{ chain: string; address: string; bound_at: string; binding_sig: string }>
  matched_wallet?: { chain: string; address: string; bound_at: string; binding_sig: string }
  key_rotation: any | null
  active_constraints: {
    scopes: string[]; spend_limit: number | null; spend_used: number
    /** Day 268: a unit-declared budget. null on a legacy row. */
    spend_unit: string | null; spend_limit_minor: string | null; spend_used_minor: string | null
  } | null
  grade_computed_at: string
  last_activity_at: string
  attestation_bundle_hash: string | null
  context_continuity: { score: number; context_break: boolean; signals: any }
  did_binding: 'bound' | 'unverified' | 'none'
  did_method: string | null
  trust_reliability: 'high' | 'low'
  wallet_address: string | null
  wallet_chain: string | null
  found: true
  queried_at: string
  // Optional add-ons
  trust_by_task_class?: Record<string, { evaluations: number; trust_score: number }>
  // Internal: tenantId surfaced for downstream consumers (signal projection,
  // cache namespacing). Not part of the wire contract — strip if filtering.
  _tenant_id?: string
  _grade_for_signal?: number
  _delegation_for_signal?: any
}

const GRADE_LABELS: Record<number, string> = { 0: 'unknown', 1: 'registered', 2: 'endorsed', 3: 'established' }
const TRUST_LABELS: Record<number, string> = { 0: 'unknown', 1: 'registered', 2: 'endorsed', 3: 'established' }

export function buildAgentTrustProfile(opts: BuildTrustProfileOpts): TrustProfile {
  const { db, agent, agentId } = opts
  const tenantId = agent.tenant_id

  // Delegation
  const delegation = db.prepare(
    `SELECT scope, spend_limit, spend_used, spend_unit, spend_limit_minor, spend_used_minor FROM delegations WHERE tenant_id = ? AND child_agent_id = ? AND status = 'active' ORDER BY created_at DESC LIMIT 1`
  ).get(tenantId, agentId) as any

  // Wallet (Nano)
  const wallet = db.prepare(
    `SELECT status FROM agent_wallets WHERE tenant_id = ? AND agent_id = ? LIMIT 1`
  ).get(tenantId, agentId) as any

  // Dossier grade (if exists)
  const dossier = db.prepare(
    `SELECT passport_grade, attestation_bundle_hash, created_at FROM issuance_dossiers WHERE tenant_id = ? AND passport_id = ? ORDER BY created_at DESC LIMIT 1`
  ).get(tenantId, agentId) as any

  // Grade: dossier if exists, else heuristic
  let grade = 0
  if (dossier) {
    grade = dossier.passport_grade
  } else {
    const evalCount = (db.prepare(
      `SELECT COUNT(*) as c FROM policy_evaluations WHERE tenant_id = ? AND agent_id = ?`
    ).get(tenantId, agentId) as any).c
    const receiptCount = (db.prepare(
      `SELECT COUNT(*) as c FROM receipts WHERE tenant_id = ? AND agent_id = ?`
    ).get(tenantId, agentId) as any).c
    if (agent.status === 'active') grade = 1
    if (delegation) grade = 2
    if (delegation && evalCount >= 10 && receiptCount >= 5) grade = 3
  }

  // Risk — simple denial rate only (no internal metrics). Verdicts are stored lowercase
  // ('permit' / 'deny') by the evaluate path, so this MUST match 'deny'. It previously queried
  // 'DENY', so deniedCount was always 0 and every agent graded low-risk regardless of denials.
  const deniedCount = (db.prepare(
    `SELECT COUNT(*) as c FROM policy_evaluations WHERE tenant_id = ? AND agent_id = ? AND verdict = 'deny'`
  ).get(tenantId, agentId) as any).c
  const evalTotal = (db.prepare(
    `SELECT COUNT(*) as c FROM policy_evaluations WHERE tenant_id = ? AND agent_id = ?`
  ).get(tenantId, agentId) as any).c
  const denialRate = evalTotal > 0 ? Math.round((deniedCount / evalTotal) * 100) / 100 : 0
  const riskLevel = denialRate > 0.3 ? 'high' : denialRate > 0.1 ? 'medium' : 'low'

  const ageDays = Math.floor((Date.now() - new Date(agent.created_at).getTime()) / (1000 * 60 * 60 * 24))

  const continuity = opts.computeContinuityScore(db, tenantId, agentId, ageDays)

  // Freshness signals
  const lastEval = db.prepare(
    `SELECT created_at FROM policy_evaluations WHERE tenant_id = ? AND agent_id = ? ORDER BY created_at DESC LIMIT 1`
  ).get(tenantId, agentId) as any
  const lastActivityAt = lastEval ? lastEval.created_at : agent.created_at
  const gradeComputedAt = dossier ? dossier.created_at : agent.created_at

  // Key rotation
  const latestRotation = db.prepare(
    `SELECT * FROM key_rotations WHERE tenant_id = ? AND agent_id = ? ORDER BY created_at DESC LIMIT 1`
  ).get(tenantId, agentId) as any

  if (latestRotation && latestRotation.state === 'announced' && latestRotation.mode === 'planned') {
    const activationTime = new Date(latestRotation.activation_time)
    if (new Date() >= activationTime) {
      db.prepare(`UPDATE key_rotations SET state = 'activated', completed_at = datetime('now') WHERE id = ?`)
        .run(latestRotation.id)
      db.prepare(`UPDATE agents SET public_key = ? WHERE tenant_id = ? AND agent_id = ?`)
        .run(latestRotation.new_key, tenantId, agentId)
      latestRotation.state = 'activated'
    }
  }

  const keyRotation = latestRotation ? {
    mode: latestRotation.mode,
    state: latestRotation.state,
    old_key: latestRotation.old_key,
    new_key: latestRotation.new_key,
    activation_time: latestRotation.activation_time,
    retired_keys: latestRotation.state === 'activated' ? [latestRotation.old_key] : [],
  } : null

  // wallet_ref: agent-native (structural) wallet binding from the SDK's
  // BoundWallet primitive.
  let walletRef: Array<{ chain: string; address: string; bound_at: string; binding_sig: string }> = []
  try {
    if (agent.metadata) {
      const meta = typeof agent.metadata === 'string' ? JSON.parse(agent.metadata) : agent.metadata
      const bw = meta?.bound_wallets
      if (Array.isArray(bw)) {
        walletRef = bw
          .filter((w: any) => w && typeof w.chain === 'string' && typeof w.address === 'string')
          .map((w: any) => ({
            chain: w.chain,
            address: w.address,
            bound_at: w.bound_at || '',
            binding_sig: w.binding_signature || w.binding_sig || '',
          }))
      }
    }
  } catch { /* metadata parse failure — leave walletRef empty */ }

  const profile: TrustProfile = {
    agent_id: agentId,
    grade,
    grade_label: GRADE_LABELS[grade] || 'unknown',
    trust: TRUST_LABELS[grade] || 'unknown',
    age_days: ageDays,
    risk_level: riskLevel,
    has_delegation: !!delegation,
    has_wallet: !!wallet,
    wallet_ref: walletRef,
    ...(opts.matchedWalletEntry ? { matched_wallet: opts.matchedWalletEntry } : {}),
    key_rotation: keyRotation,
    active_constraints: delegation ? {
      scopes: delegation.scope ? delegation.scope.split(',').map((s: string) => s.trim()) : [],
      // `?? null`, not `|| null`: a zero limit is a zero budget, never reported as no limit.
      spend_limit: delegation.spend_limit ?? null,
      spend_used: delegation.spend_used || 0,
      // Day 268: a unit-declared budget, exactly. null on a legacy row, whose REAL limit is USD.
      spend_unit: delegation.spend_unit ?? null,
      spend_limit_minor: delegation.spend_limit_minor ?? null,
      spend_used_minor: delegation.spend_used_minor ?? null,
    } : null,
    grade_computed_at: gradeComputedAt,
    last_activity_at: lastActivityAt,
    attestation_bundle_hash: dossier ? dossier.attestation_bundle_hash : null,
    context_continuity: {
      score: continuity.score,
      context_break: continuity.context_break,
      signals: continuity.signals,
    },
    did_binding: agent.public_key && /^[0-9a-fA-F]{64}$/.test(agent.public_key) ? 'bound'
      : agent.public_key ? 'unverified' : 'none',
    did_method: agent.did ? (agent.did.split(':')[1] || null) : null,
    trust_reliability: agent.public_key && /^[0-9a-fA-F]{64}$/.test(agent.public_key) ? 'high' : 'low',
    wallet_address: opts.walletParam || (opts.matchedWalletEntry?.address ?? null),
    wallet_chain: opts.walletParam ? (opts.chainParam || 'nano') : (opts.matchedWalletEntry?.chain ?? null),
    found: true,
    queried_at: new Date().toISOString(),
    _tenant_id: tenantId,
    _grade_for_signal: grade,
    _delegation_for_signal: delegation,
  }

  // Per-task-class trust breakdown
  try {
    const windowDays = opts.windowDays ?? 0
    const timeFilter = windowDays > 0 ? ` AND created_at > datetime('now', '-${windowDays} days')` : ''
    const classRows = db.prepare(
      `SELECT task_class, COUNT(*) as evals, SUM(CASE WHEN verdict = 'permit' THEN 1 ELSE 0 END) as permits
       FROM policy_evaluations WHERE tenant_id = ? AND agent_id = ? AND task_class != ''${timeFilter} GROUP BY task_class`
    ).all(tenantId, agentId) as any[]
    if (classRows.length > 0) {
      profile.trust_by_task_class = Object.fromEntries(
        classRows.map((r: any) => [r.task_class, { evaluations: r.evals, trust_score: r.evals > 0 ? Math.round((r.permits / r.evals) * 100) / 100 : 0 }])
      )
    }
  } catch { /* task_class column may not exist yet */ }

  return profile
}

/** Strip private underscore-prefixed fields before sending over the wire. */
/**
 * The spend constraints carried in the signed governance_attestation claim, shaped to the
 * governance-attestation schema (draft v0.1, active_constraints: scopes, spend_limit, spend_used,
 * optional spend_currency, no other properties).
 *
 * - A legacy row has no stored unit. Its REAL counters may hold USD from the grant path or XNO from
 *   the old Nano send path, so no currency is asserted: spend_currency is omitted. 0.4.3 and earlier
 *   labelled every row XNO.
 * - A unit-declared row cannot be stated exactly in that schema: its exact budget is a decimal
 *   string in minor units, and its REAL columns hold a zero sentinel that would read as a zero
 *   budget. The attestation is refused for it until the schema carries units.
 * - With no active delegation, the claim is empty scopes, no limit, nothing spent, as before.
 */
export function attestationSpendConstraints(delegation: any):
  | { ok: true; constraints: { scopes: string[]; spend_limit: number | null; spend_used: number } }
  | { ok: false; reason: string } {
  if (!delegation) return { ok: true, constraints: { scopes: [], spend_limit: null, spend_used: 0 } }
  if (delegation.spend_unit != null) {
    return { ok: false, reason: `the delegation's budget is declared in ${delegation.spend_unit}, which governance_attestation draft v0.1 cannot state exactly` }
  }
  return {
    ok: true,
    constraints: {
      scopes: delegation.scope ? String(delegation.scope).split(',').map((s: string) => s.trim()) : [],
      spend_limit: delegation.spend_limit ?? null,
      spend_used: delegation.spend_used ?? 0,
    },
  }
}

export function publicizeProfile(profile: TrustProfile): Record<string, any> {
  const out: Record<string, any> = {}
  for (const [k, v] of Object.entries(profile)) {
    if (!k.startsWith('_')) out[k] = v
  }
  return out
}
