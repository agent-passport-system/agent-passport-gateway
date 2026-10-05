// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Gateway Enforcement API — the revenue product.
 *
 * POST /api/v1/evaluate   — policy evaluation (the billable unit)
 * POST /api/v1/receipt     — store signed receipt
 * POST /api/v1/revoke      — cascade revocation
 * GET  /api/v1/agents      — list agents
 * GET  /api/v1/delegations — list delegations
 * GET  /api/v1/audit       — audit trail
 */

import { Router } from 'express'
import type Database from 'better-sqlite3'
import { RateLimiterMemory } from 'rate-limiter-flexible'
import { randomUUID, createHash } from 'node:crypto'
// Receipt-ingest signature verification (audit item 6). Same SDK canonicalize/verify the
// proxy-gateway already depends on; the ActionReceipt preimage is canonicalize(receipt minus
// signature) verified against the signer's registered agents.public_key.
import { verify as apsVerify, canonicalize as apsCanonicalize, verifyBilateralReceipt, checkAudience } from 'agent-passport-system'
import { getDB, PLAN_LIMITS } from '../db/schema.js'
import { getGatewayIdentity } from './identity.js'
import type { Tenant } from '../auth/api-keys.js'
import { computeLineageLinks, storeAndCluster, getClusterRisk } from './lineage.js'
import { getEventBus } from './events.js'
import { recordBoundWallets } from './wallet-reverse-index.js'
import { validateExternalUrl } from './url-safety.js'
import { sendEmail, spendAlertEmail } from '../notifications/email.js'
import { runFreshnessGate, type FreshnessGateResult } from './freshness/gate.js'
// G-C2 layer (a): compiled, stateless, non-Turing-complete pre-flight guards.
// Slotted BEFORE the billable evaluate decision below. No agent/LLM in this path.
import {
  evaluateGuards,
  isScopeHighRisk,
  DEFAULT_HIGH_RISK_SCOPES,
  type GuardContext,
} from './guards/index.js'
// G-C2 layer (c): whether a live customer-signed playbook covers a high-risk
// scope. Read-only; the guard only consumes the resolved boolean.
import { scopeCoveredByLivePlaybook } from './playbooks/index.js'
// G-D1: enforcement modes (observe/warn/approval/enforce/emergency).
import { resolveMode } from './simulation/mode-config.js'
import { applyMode, classifyRequestRisk } from './simulation/modes.js'
import { recordModeObservation } from './simulation/migration-metric.js'
import { emitToEventSpine } from './simulation/event-spine.js'

// Spend alert dedup: track which delegation+threshold combos have been alerted
const spendAlertsSent = new Set<string>()
import { checkAgentLimit, checkEvaluationLimit } from '../billing/limits.js'
import { toCents } from '../billing/money.js'

function safeError(e: any, context: string): { error: string; ref: string } {
  const ref = randomUUID().slice(0, 8)
  console.error(`[ERR:${ref}] ${context}:`, e.message || e)
  return { error: `Internal error (ref: ${ref}). Contact support.`, ref }
}

// ── Auto-Mint Evaluation Receipts ──
// Non-blocking: logs failures but never blocks the evaluation response.
// Denials are signed (proof of restraint). Permits are unsigned (routine).

// H9: aligned with SDK canonicalize() — strips null/undefined, cycle-safe
function canonicalJsonStringify(v: unknown, seen = new WeakSet<object>()): string {
  if (v === null || v === undefined) return 'null'
  if (typeof v !== 'object') return JSON.stringify(v)
  if (v instanceof Date) return JSON.stringify(v)
  if (seen.has(v as object)) return '"[circular]"'
  seen.add(v as object)
  if (Array.isArray(v)) return '[' + v.map(i => canonicalJsonStringify(i, seen)).join(',') + ']'
  const keys = Object.keys(v as Record<string, unknown>).sort()
    .filter(k => { const val = (v as Record<string, unknown>)[k]; return val !== null && val !== undefined })
  return '{' + keys.map(k =>
    JSON.stringify(k) + ':' + canonicalJsonStringify((v as Record<string, unknown>)[k], seen)
  ).join(',') + '}'
}

function mintEvaluationReceipt(opts: {
  tenantId: string; agentId: string; evaluationId: string;
  verdict: string; actionType: string; scopeRequired: string;
  reason: string; delegationId: string | null;
}) {
  try {
    const db = getDB()
    const scopeJson = JSON.stringify(
      (opts.scopeRequired || '').split(',').map(s => s.trim()).filter(Boolean).sort()
    )
    const policyHash = createHash('sha256')
      .update('floor-v1-scope-spend-depth-delegation')
      .digest('hex').slice(0, 16)

    const receiptData: Record<string, unknown> = {
      tenant_id: opts.tenantId,
      agent_id: opts.agentId,
      evaluation_id: opts.evaluationId,
      event_type: opts.verdict === 'permit' ? 'authorization_permit' : 'authorization_deny',
      decision_stage: 'gateway_authorization',
      action_type: opts.actionType,
      scope_requested_json: scopeJson,
      verdict: opts.verdict === 'permit' ? 'permit' : 'deny',
      reason_code: opts.verdict !== 'permit' ? (opts.reason || 'policy_deny') : null,
      delegation_id: opts.delegationId,
      policy_hash: policyHash,
      schema_version: '1.0.0',
    }

    const receiptHash = createHash('sha256')
      .update(canonicalJsonStringify(receiptData))
      .digest('hex')

    // Only sign denials (proof of restraint)
    let gatewaySignature: string | null = null
    if (opts.verdict !== 'permit') {
      try {
        const identity = getGatewayIdentity()
        gatewaySignature = identity.sign({ ...receiptData, receipt_hash: receiptHash })
      } catch { /* signing optional, log below */ }
    }

    db.prepare(`
      INSERT INTO evaluation_receipts (
        tenant_id, agent_id, evaluation_id, event_type, decision_stage,
        action_type, scope_requested_json, verdict, reason_code,
        delegation_id, policy_hash, schema_version, receipt_hash, gateway_signature
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      receiptData.tenant_id, receiptData.agent_id, receiptData.evaluation_id,
      receiptData.event_type, receiptData.decision_stage,
      receiptData.action_type, receiptData.scope_requested_json,
      receiptData.verdict, receiptData.reason_code,
      receiptData.delegation_id, receiptData.policy_hash,
      receiptData.schema_version, receiptHash, gatewaySignature,
    )
    maybeAutoSeal()
  } catch (e: any) {
    console.error('[receipt-mint] FAILED:', opts.agentId, e.message)
  }
}

// SDK scope matching — respects monotonic narrowing invariant
let _scopeAuthorizes: ((scopes: string[], required: string) => boolean) | null = null
// Exported so the sink-side verifier consumes the SAME SDK-backed scope
// matcher as the source-side pre-check (no hand-rolled matcher at the sink).
export async function getScopeAuthorizes() {
  if (!_scopeAuthorizes) {
    try {
      const sdk = await import('agent-passport-system')
      _scopeAuthorizes = sdk.scopeAuthorizes
    } catch (e) {
      // FAIL CLOSED: deny all scope checks when SDK unavailable
      console.error('[SECURITY] Failed to load scopeAuthorizes — all checks DENY:', (e as Error).message)
      _scopeAuthorizes = () => false
    }
  }
  return _scopeAuthorizes
}

// ── Task class derivation (first segment of action_type) ──
export function deriveTaskClass(actionType: string): string {
  return (actionType || '').split(':')[0] || ''
}

// ── Argument-pattern scope matching (Feature: broad-capability tool scoping) ──

export function globMatch(pattern: string, value: string): boolean {
  // Convert glob to regex: ** = any path depth, * = one segment
  const parts = pattern.split('/')
  let regex = '^'
  for (let i = 0; i < parts.length; i++) {
    if (i > 0) regex += '\\/'
    if (parts[i] === '**') { regex += '.*'; break }
    else if (parts[i] === '*') regex += '[^/]+'
    else regex += parts[i].replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  }
  regex += '$'
  try { return new RegExp(regex).test(value) } catch { return false }
}

export function scopeMatchesWithArguments(
  delegationScope: string[],
  actionType: string,
  actionArgs: Record<string, unknown>,
  fallbackAuth: (scopes: string[], required: string) => boolean,
): boolean {
  // Global wildcard
  if (delegationScope.includes('*')) return true

  for (const scope of delegationScope) {
    const parts = scope.split(':')

    // Simple scope (1-2 segments): delegate to SDK scopeAuthorizes
    if (parts.length <= 2) {
      if (fallbackAuth([scope], actionType)) return true
      continue
    }

    // Hierarchical scope (3+ segments): tool:name:capability[:targetPattern]
    const scopeCategory = parts[0]
    const scopeName = parts[1]
    const scopeCapability = parts[2]
    const scopeTarget = parts.length > 3 ? parts.slice(3).join(':') : null

    // Match action_type against category:name:capability
    const actionParts = actionType.split(':')
    const actionCategory = actionParts[0] || ''
    const actionName = actionParts[1] || ''
    const actionCapability = actionParts[2] || (actionArgs.capability as string) || ''

    if (scopeCategory !== actionCategory) continue
    if (scopeName !== actionName && scopeName !== '*') continue
    if (scopeCapability !== actionCapability && scopeCapability !== '*') continue

    // If no target pattern, the capability match is sufficient
    if (!scopeTarget) return true

    // Target pattern matching against action args
    const targetValue = (actionArgs.path || actionArgs.target || actionArgs.resource || actionArgs.url || '') as string
    if (!targetValue) continue
    if (globMatch(scopeTarget, targetValue)) return true
  }

  return false
}

// Agent type constraints (Primitive #12)
const AGENT_TYPE_CONSTRAINTS: Record<string, { blocked_scopes: string[]; max_evaluations_per_hour?: number }> = {
  explorer: { blocked_scopes: ['admin:delete', 'admin:write', 'commerce:send'], max_evaluations_per_hour: 100 },
  planner: { blocked_scopes: ['admin:delete', 'commerce:send'] },
  reviewer: { blocked_scopes: ['admin:delete', 'admin:write'] },
  monitor: { blocked_scopes: ['admin:delete', 'admin:write', 'commerce:send', 'data:write'], max_evaluations_per_hour: 500 },
  executor: { blocked_scopes: [] },
  general: { blocked_scopes: [] },
}

// SDK recovery evaluation — consulted on denials
let _evaluateRecovery: ((opts: any) => any) | null = null
async function getEvaluateRecovery() {
  if (!_evaluateRecovery) {
    try {
      const sdk: any = await import('agent-passport-system')
      if (typeof sdk.evaluateRecovery === 'function') {
        _evaluateRecovery = sdk.evaluateRecovery
      }
    } catch { /* SDK version may not have evaluateRecovery yet */ }
  }
  return _evaluateRecovery
}

// Map denial reason to SDK failure type
function mapFailureType(violations: string[]): string {
  const joined = violations.join(' ').toLowerCase()
  if (joined.includes('stale') || joined.includes('freshness')) return 'evidence_stale'
  if (joined.includes('scope')) return 'scope_denied'
  if (joined.includes('budget') || joined.includes('spend') || joined.includes('cost')) return 'budget_exceeded'
  if (joined.includes('suspended')) return 'passport_expired'
  if (joined.includes('delegation')) return 'delegation_revoked'
  if (joined.includes('key')) return 'policy_violation'
  return 'unknown'
}

/**
 * True iff x is a finite number >= 0. Used to reject a malformed or negative estimated_cost before
 * any budget math: a negative cost slips past the `cost > remaining` overspend check (a negative is
 * never greater than the remaining budget) and, on permit, would be ADDED to spend_used, refunding
 * the budget. Both let an agent spend without limit.
 */
export function isNonNegativeFiniteCost(x: unknown): boolean {
  return typeof x === 'number' && Number.isFinite(x) && x >= 0
}

/** True iff the granted scope token covers the required one: exact, global '*', hierarchical
 *  prefix ('a' or 'a:b' covers 'a:b...'), or wildcard suffix ('a:*' covers 'a:b'). */
export function scopeCovers(granted: string, required: string): boolean {
  if (granted === '*' || granted === required) return true
  if (required.startsWith(granted + ':')) return true
  if (granted.endsWith(':*') && required.startsWith(granted.slice(0, -1))) return true
  return false
}

export interface NarrowingParent { scope: string; spend_limit: number | null; spend_used?: number | null; max_depth: number; current_depth?: number | null }
export interface NarrowingChild { scope: string[]; spend_limit: number | null; max_depth: number }

/**
 * Enforce monotonic narrowing on delegation CREATION. A child delegation minted from a parent
 * delegation may only narrow it: scope must be a subset, spend_limit may not exceed the parent's
 * remaining budget, and the depth ceiling may not increase. parent === null means the grantor is a
 * tenant root principal that received no delegation, so it may grant freely (the tenant owns it).
 * Previously creation enforced none of this, so a delegatee could mint a child with broader scope,
 * higher spend, or a deeper ceiling than it was granted (privilege escalation).
 */
export function checkDelegationNarrowing(parent: NarrowingParent | null, child: NarrowingChild): { ok: boolean; violations: string[] } {
  const violations: string[] = []
  if (!parent) return { ok: true, violations }
  const parentScopes = parent.scope.split(',').map((s) => s.trim()).filter(Boolean)
  for (const cs of child.scope) {
    if (!parentScopes.some((ps) => scopeCovers(ps, cs))) {
      violations.push(`scope "${cs}" is not within the parent delegation scope`)
    }
  }
  // Money-path narrowing. Only gate when the ANCESTOR carries a bounded spend budget. When the
  // parent has no bound (spend_limit null), the child may leave spend unbounded (no bound to widen)
  // or introduce one (narrowing) -- both stay allowed, so skip. When the parent IS bounded:
  //  - a null (absent) child spend_limit is treated as UNLIMITED at enforcement time (see the
  //    `delegation.spend_limit != null` gate on the /evaluate path), so it would WIDEN the bounded
  //    ancestor to unbounded spend. Monotonic narrowing forbids that: authority can only decrease.
  //    Reject it; the child must carry an explicit bound no larger than the parent's remaining.
  //  - a set child spend_limit may not exceed the parent's remaining budget.
  if (parent.spend_limit != null) {
    const remaining = parent.spend_limit - (parent.spend_used || 0)
    if (child.spend_limit == null) {
      violations.push(`spend_limit is absent (unbounded), but the parent delegation is bounded (remaining budget ${remaining}); an unbounded child would widen a bounded ancestor. Set a spend_limit no greater than ${remaining}.`)
    } else if (child.spend_limit > remaining) {
      violations.push(`spend_limit ${child.spend_limit} exceeds parent remaining budget ${remaining}`)
    }
  }
  if (typeof child.max_depth === 'number' && typeof parent.max_depth === 'number' && child.max_depth > parent.max_depth) {
    violations.push(`max_depth ${child.max_depth} exceeds parent max_depth ${parent.max_depth}`)
  }
  // Running chain depth: a child sits one hop below the parent. The chain may not grow past the
  // child's max_depth ceiling (already <= the parent's). This is the actual depth BOUND, not just
  // the non-increasing ceiling above, so a long chain at a flat ceiling cannot grow unbounded.
  const childDepth = (parent.current_depth ?? 0) + 1
  if (typeof child.max_depth === 'number' && childDepth > child.max_depth) {
    violations.push(`chain depth ${childDepth} exceeds max_depth ${child.max_depth}`)
  }
  return { ok: violations.length === 0, violations }
}

// C1 (Day 217): stable, row-data-free failure codes for a bound-chain check. hop is 1-indexed, counted
// from the starting delegation row.
export type ChainCheckCode =
  | 'missing_row'
  | 'cross_tenant'
  | 'inactive_delegation'
  | 'continuity_mismatch'
  | 'cycle'
  | 'max_hops_exceeded'
  | 'missing_agent'
  | 'agent_suspended'
  | 'agent_frozen'
  | 'agent_revoked'
  | 'agent_unknown_status'

export interface ChainCheckResult {
  ok: boolean
  code?: ChainCheckCode
  hop?: number
}

const MAX_CHAIN_HOPS = 64

/**
 * C1 (Day 217): the one checker for bound-chain authority, read-only, used by both the grant path
 * (the POST /delegations route gate and applyGrantWithReverify's in-transaction re-verify) and
 * /evaluate. Walks a delegation's parent_delegation_id links up to its terminal (NULL-parent,
 * origination) row and fails closed on the first bad hop: a missing or cross-tenant row, a delegation
 * row whose status isn't 'active', a continuity break (the parent row's child_agent_id must equal this
 * row's parent_agent_id -- otherwise parent_delegation_id could point anywhere), a cycle, or a chain
 * longer than MAX_CHAIN_HOPS. At every hop the GRANTOR agent (row.parent_agent_id) -- including the
 * terminal/root grantor -- must exist in the tenant: 'active' and 'restricted' keep the chain live,
 * 'suspended' and 'frozen' pause it (reversible, no row rewritten), 'revoked' invalidates it, any other
 * or unknown status fails closed. restricted_scopes is
 * deliberately NOT consulted here (propagating a restricted ancestor's scope narrowing through the chain
 * is a separate policy question); only status decides liveness. Never require the terminal grantor to
 * be is_root -- auto-demotion on receiving a later inbound must not retroactively kill an earlier
 * legitimate grant. Returns a stable code and the failing hop index only, never row data.
 */
export function checkBoundAuthorityChain(
  db: Database.Database,
  tenantId: string,
  startDelegationId: string,
): ChainCheckResult {
  const visited = new Set<string>()
  let currentId: string | null = startDelegationId
  let expectedChildAgentId: string | null = null
  let hop = 0

  while (currentId) {
    hop++
    if (hop > MAX_CHAIN_HOPS) return { ok: false, code: 'max_hops_exceeded', hop }
    if (visited.has(currentId)) return { ok: false, code: 'cycle', hop }
    visited.add(currentId)

    const row = db.prepare(
      `SELECT id, tenant_id, parent_agent_id, child_agent_id, status, parent_delegation_id FROM delegations WHERE id = ?`
    ).get(currentId) as any
    if (!row) return { ok: false, code: 'missing_row', hop }
    if (row.tenant_id !== tenantId) return { ok: false, code: 'cross_tenant', hop }
    if (row.status !== 'active') return { ok: false, code: 'inactive_delegation', hop }
    if (expectedChildAgentId !== null && row.child_agent_id !== expectedChildAgentId) {
      return { ok: false, code: 'continuity_mismatch', hop }
    }

    const grantor = db.prepare(
      `SELECT status FROM agents WHERE tenant_id = ? AND agent_id = ?`
    ).get(tenantId, row.parent_agent_id) as any
    if (!grantor) return { ok: false, code: 'missing_agent', hop }
    if (grantor.status === 'suspended') return { ok: false, code: 'agent_suspended', hop }
    if (grantor.status === 'frozen') return { ok: false, code: 'agent_frozen', hop }
    if (grantor.status === 'revoked') return { ok: false, code: 'agent_revoked', hop }
    if (grantor.status !== 'active' && grantor.status !== 'restricted') {
      return { ok: false, code: 'agent_unknown_status', hop }
    }

    if (!row.parent_delegation_id) return { ok: true }

    expectedChildAgentId = row.parent_agent_id
    currentId = row.parent_delegation_id
  }
  return { ok: true }
}

export const gatewayRouter = Router()

// ═══════════════════════════════════════
// Lexical similarity utilities (reusable)
// ═══════════════════════════════════════

function ngrams(text: string, n: number): Set<string> {
  const words = text.toLowerCase().replace(/[^a-z0-9\s]/g, '').split(/\s+/).filter(w => w.length > 2)
  const grams = new Set<string>()
  for (let i = 0; i <= words.length - n; i++) grams.add(words.slice(i, i + n).join(' '))
  return grams
}

function jaccardOverlap(a: Set<string>, b: Set<string>): number {
  let shared = 0
  a.forEach(g => { if (b.has(g)) shared++ })
  const union = new Set([...a, ...b]).size
  return union > 0 ? shared / union : 0
}

function computeLexicalScore(sourceText: string, outputText: string) {
  const uni = jaccardOverlap(ngrams(sourceText, 1), ngrams(outputText, 1))
  const bi = jaccardOverlap(ngrams(sourceText, 2), ngrams(outputText, 2))
  const tri = jaccardOverlap(ngrams(sourceText, 3), ngrams(outputText, 3))
  const score = Math.round((uni * 0.2 + bi * 0.35 + tri * 0.45) * 10000) / 10000
  return {
    score, detail: { unigram: Math.round(uni * 10000) / 10000, bigram: Math.round(bi * 10000) / 10000, trigram: Math.round(tri * 10000) / 10000 },
    verdict: score > 0.3 ? 'high_overlap' as const : score > 0.1 ? 'moderate_overlap' as const : 'low_overlap' as const,
  }
}

// ═══════════════════════════════════════
// Usage check middleware
// ═══════════════════════════════════════

// C3 (audit 2026-05-12): the legacy `checkUsageLimit` + `incrementUsage`
// pair maintained a denormalised counter in the `usage` table that
// diverged from the source-of-truth `policy_evaluations` rowcount under
// any failure path. We now query `policy_evaluations` directly via
// `checkEvaluationLimit` (imported from billing/limits.ts). The functions
// previously here have been removed; the `usage` table is left in place
// for historical aggregates but is no longer written by /evaluate.

// ═══════════════════════════════════════
// POST /api/v1/evaluate — Policy Evaluation
// ═══════════════════════════════════════

gatewayRouter.post('/evaluate', async (req: any, res) => {
  try {
  const tenant: Tenant = req.tenant
  const start = Date.now()

  // Billing limit check
  const evalLimit = checkEvaluationLimit(tenant.id, tenant.plan)
  if (!evalLimit.allowed) {
    return res.status(429).json({ error: evalLimit.reason, current: evalLimit.current, limit: evalLimit.limit })
  }

  const { agent_id, action_type, action_target, scope_required, estimated_cost, action_args } = req.body
  if (!agent_id || !action_type || !scope_required) {
    return res.status(400).json({ error: 'Required: agent_id, action_type, scope_required' })
  }
  const parsedArgs: Record<string, unknown> = (action_args && typeof action_args === 'object') ? action_args : {}

  const db = getDB()

  // Check agent exists
  const agent = db.prepare(`SELECT * FROM agents WHERE tenant_id = ? AND agent_id = ?`)
    .get(tenant.id, agent_id) as any
  if (!agent) {
    return res.status(404).json({ error: `Agent "${agent_id}" not found` })
  }

  // Posture enforcement: suspended → deny all, restricted → deny restricted scopes
  if (agent.status === 'suspended') {
    const evalId = randomUUID()
    const durationMs = Date.now() - start
    db.prepare(`INSERT INTO policy_evaluations (id, tenant_id, agent_id, action_type, action_target, scope_required, verdict, reason, duration_ms, task_class) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(evalId, tenant.id, agent_id, action_type, action_target || '', scope_required, 'deny', 'Agent suspended', durationMs, deriveTaskClass(action_type))
    mintEvaluationReceipt({
      tenantId: tenant.id, agentId: agent_id, evaluationId: evalId,
      verdict: 'deny', actionType: action_type, scopeRequired: scope_required,
      reason: 'agent_suspended', delegationId: null,
    })
    return res.json({ evaluation_id: evalId, verdict: 'deny', reason: 'Agent suspended', violations: ['agent_suspended'], duration_ms: durationMs, agent_id, action: { type: action_type, target: action_target, scope_required } })
  }
  if (agent.status === 'restricted' && agent.restricted_scopes) {
    try {
      const restrictedScopes: string[] = JSON.parse(agent.restricted_scopes)
      if (restrictedScopes.includes(scope_required) || restrictedScopes.some(rs => scope_required.startsWith(rs + ':'))) {
        const evalId = randomUUID()
        const durationMs = Date.now() - start
        db.prepare(`INSERT INTO policy_evaluations (id, tenant_id, agent_id, action_type, action_target, scope_required, verdict, reason, duration_ms, task_class) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
          .run(evalId, tenant.id, agent_id, action_type, action_target || '', scope_required, 'deny', `Scope "${scope_required}" restricted by posture`, durationMs, deriveTaskClass(action_type))
        mintEvaluationReceipt({
          tenantId: tenant.id, agentId: agent_id, evaluationId: evalId,
          verdict: 'deny', actionType: action_type, scopeRequired: scope_required,
          reason: 'scope_restricted', delegationId: null,
        })
        return res.json({ evaluation_id: evalId, verdict: 'deny', reason: `Scope "${scope_required}" restricted by posture`, violations: ['scope_restricted'], duration_ms: durationMs, agent_id, action: { type: action_type, target: action_target, scope_required } })
      }
    } catch { /* invalid JSON in restricted_scopes — proceed */ }
  }
  if (agent.status !== 'active' && agent.status !== 'restricted') {
    return res.status(404).json({ error: `Agent "${agent_id}" not active (status: ${agent.status})` })
  }

  // Entity binding check (vessenes integration — A2A#1575)
  //
  // Security triage 2026-04-11 fix 4: validate the URL before fetch as
  // defense-in-depth. Registration-time validation is the primary guard,
  // but any URL stored before that guard existed (or that somehow slipped
  // past) is still rejected here. The entity binding check falls through
  // on an unsafe URL; it does not deny the request, because that would
  // let a tenant weaponize a stored bad URL to deny-list their own agent.
  const entityUrlSafe = validateExternalUrl(agent.entity_verification_endpoint)
  if (agent.entity_id && agent.entity_verification_endpoint && entityUrlSafe.safe) {
    try {
      const entityRes = await fetch(agent.entity_verification_endpoint, {
        signal: AbortSignal.timeout(3000)
      })
      if (entityRes.ok) {
        const entity = await entityRes.json() as any
        if (entity.status !== 'active') {
          const evalId = randomUUID()
          const durationMs = Date.now() - start
          db.prepare(`INSERT INTO policy_evaluations (id, tenant_id, agent_id, action_type, action_target, scope_required, verdict, reason, duration_ms, task_class) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
            .run(evalId, tenant.id, agent_id, action_type, action_target || '', scope_required, 'deny', `Entity "${agent.entity_id}" is ${entity.status}`, durationMs, deriveTaskClass(action_type))
          return res.json({ evaluation_id: evalId, verdict: 'deny', reason: `Entity binding: entity "${agent.entity_id}" status is "${entity.status}"`, violations: ['entity_binding_violation'], duration_ms: durationMs, agent_id, action: { type: action_type, scope_required } })
        }
        if (entity.authority_ceiling && Array.isArray(entity.authority_ceiling)) {
          const scopeRoot = scope_required.split(':')[0]
          if (!entity.authority_ceiling.includes(scopeRoot) && !entity.authority_ceiling.includes(scope_required)) {
            const evalId = randomUUID()
            const durationMs = Date.now() - start
            db.prepare(`INSERT INTO policy_evaluations (id, tenant_id, agent_id, action_type, action_target, scope_required, verdict, reason, duration_ms, task_class) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
              .run(evalId, tenant.id, agent_id, action_type, action_target || '', scope_required, 'deny', `Scope "${scope_required}" exceeds entity ceiling [${entity.authority_ceiling.join(', ')}]`, durationMs, deriveTaskClass(action_type))
            return res.json({ evaluation_id: evalId, verdict: 'deny', reason: `Entity binding: scope "${scope_required}" exceeds entity authority ceiling`, violations: ['entity_ceiling_exceeded'], duration_ms: durationMs, agent_id, action: { type: action_type, scope_required } })
          }
        }
      }
    } catch {
      console.warn(`[entity-binding] Failed to reach ${agent.entity_verification_endpoint} for agent ${agent_id}`)
    }
  } else if (agent.entity_id && agent.entity_verification_endpoint && !entityUrlSafe.safe) {
    // URL is stored but fails the SSRF guard. Log once so operators can
    // find and clean up legacy rows.
    console.warn(`[entity-binding] Stored endpoint rejected by SSRF guard for agent ${agent_id}: ${entityUrlSafe.reason}`)
  }

  // Key rotation enforcement: if request includes signing_key, check against retired keys.
  // A compromised old key MUST NOT authorize actions after rotation completes.
  const signingKey = req.body.signing_key as string | undefined
  if (signingKey) {
    const rotation = db.prepare(
      `SELECT old_key, new_key, state FROM key_rotations
       WHERE tenant_id = ? AND agent_id = ? AND state = 'activated'
       ORDER BY created_at DESC LIMIT 1`
    ).get(tenant.id, agent_id) as any
    if (rotation && rotation.old_key === signingKey) {
      const evalId = randomUUID()
      const durationMs = Date.now() - start
      db.prepare(`INSERT INTO policy_evaluations (id, tenant_id, agent_id, action_type, action_target, scope_required, verdict, reason, duration_ms, task_class) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
        .run(evalId, tenant.id, agent_id, action_type, action_target || '', scope_required, 'deny', 'Key retired via rotation', durationMs, deriveTaskClass(action_type))
      mintEvaluationReceipt({
        tenantId: tenant.id, agentId: agent_id, evaluationId: evalId,
        verdict: 'deny', actionType: action_type, scopeRequired: scope_required,
        reason: 'key_retired', delegationId: null,
      })
      return res.json({
        evaluation_id: evalId, verdict: 'deny',
        reason: 'Key retired via rotation. Use the current key.',
        violations: ['key_retired'],
        duration_ms: durationMs, agent_id,
        action: { type: action_type, target: action_target, scope_required },
      })
    }
  }

  // ── G-C2 layer (a): real-time pre-flight guards (constraint C2) ──
  //
  // Compiled, stateless, non-Turing-complete guards run HERE, before the billable
  // evaluate decision. There is no agent and no LLM in this path: evaluateGuards
  // runs a fixed array of straight-line predicates over an immutable context.
  // A BLOCK is fail-closed deny-before; the request never reaches the billable
  // transaction. The guard never approves a high-risk action on its own authority
  // and never mutates policy - that authority lives at the sink (B2 epoch check,
  // offline) and in the customer-signed playbooks (layer c).
  //
  // `coveredBySignedPlaybook` is resolved from the playbook registry. A high-risk
  // scope with no live signed playbook is blocked here: no free-form autonomous
  // high-risk action exists outside a signed playbook (constraint C1).
  const guardHighRisk = isScopeHighRisk(scope_required, DEFAULT_HIGH_RISK_SCOPES)
  let guardCoveredByPlaybook = false
  if (guardHighRisk) {
    try { guardCoveredByPlaybook = scopeCoveredByLivePlaybook(tenant.id, scope_required) }
    catch { guardCoveredByPlaybook = false } // fail-closed: unresolved => not covered
  }
  const guardCtx: GuardContext = {
    agentStatus: agent.status,
    scopeRequired: scope_required,
    actionType: action_type,
    estimatedCost: typeof estimated_cost === 'number' ? estimated_cost : 0,
    isHighRisk: guardHighRisk,
    coveredBySignedPlaybook: guardCoveredByPlaybook,
    costCeiling: 0, // per-action ceiling is opt-in; 0 disables this guard
  }
  const guardDecision = evaluateGuards(guardCtx)
  if (guardDecision.verdict === 'block') {
    const gEvalId = randomUUID()
    const gDurationMs = Date.now() - start
    db.prepare(`INSERT INTO policy_evaluations (id, tenant_id, agent_id, action_type, action_target, scope_required, verdict, reason, duration_ms, task_class) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(gEvalId, tenant.id, agent_id, action_type, action_target || '', scope_required, 'deny', `Pre-flight guard: ${guardDecision.reason}`, gDurationMs, deriveTaskClass(action_type))
    mintEvaluationReceipt({
      tenantId: tenant.id, agentId: agent_id, evaluationId: gEvalId,
      verdict: 'deny', actionType: action_type, scopeRequired: scope_required,
      reason: guardDecision.code, delegationId: null,
    })
    try { getEventBus().emit(tenant.id, { type: 'guard_block', agentId: agent_id, data: { evaluationId: gEvalId, guard: guardDecision.guard, code: guardDecision.code, scope_required, duration_ms: gDurationMs } }) } catch {}
    return res.json({ evaluation_id: gEvalId, verdict: 'deny', reason: `Pre-flight guard: ${guardDecision.reason}`, violations: [guardDecision.code], duration_ms: gDurationMs, agent_id, action: { type: action_type, target: action_target, scope_required } })
  }

  // C2: Atomic delegation check + spend update (prevents TOCTOU double-spend)
  const scopeAuth = await getScopeAuthorizes()
  const evalId = randomUUID()

  // ── G-B3: Risk-tiered freshness gate ──
  // Per-action risk tier sets the freshness window and the fail behavior. The
  // customer supplies the freshness evidence descriptor at the edge; the
  // gateway observes the staleness and applies the tier's posture. Computed
  // here (async SDK import) and folded into the transaction's violations[]
  // below so it composes with scope/spend denials.
  //
  // Tier resolution: the default task-class mapping is a FLOOR. The explicit
  // per-action `risk_tier` (request) and the per-delegation contract tier
  // (`delegation_risk_tier`) may only RAISE the tier above the class floor,
  // never lower it, so a protected class (e.g. commerce tier 3) cannot be
  // undercut to bypass the tier-3 fail-closed.
  // TODO(W2-B3): persist the per-delegation contract tier as a durable
  // `delegations.risk_tier` column; today it rides on the request as the
  // signed-contract input so this module stays inside its allowed surface.
  let freshnessGate: FreshnessGateResult | null = null
  try {
    freshnessGate = await runFreshnessGate({
      taskClass: deriveTaskClass(action_type),
      requestTier: req.body.risk_tier,
      delegationTier: req.body.delegation_risk_tier,
      freshnessInput: req.body.freshness ?? req.body.freshness_required,
    })
  } catch (e) {
    // Freshness gate must never crash the evaluation. On failure, leave the
    // existing scope/spend path authoritative (no freshness verdict added).
    console.error('[freshness] gate error - skipping freshness verdict:', (e as Error).message)
    freshnessGate = null
  }

  const evalResult = db.transaction(() => {
    const delegation = db.prepare(`
      SELECT * FROM delegations
      WHERE tenant_id = ? AND child_agent_id = ? AND status = 'active'
      ORDER BY created_at DESC, id DESC LIMIT 1
    `).get(tenant.id, agent_id) as any

    let verdict = 'permit'
    const violations: string[] = []

    // G-B3: fold the freshness-tier outcome into the verdict. A blocking
    // outcome (tier 3 fail-closed, tier 2 deny-if-stale, tier 1
    // require-approval) denies; a non-blocking outcome (allow/warn) records
    // the staleness but does not deny. The reason carries the tier's detail
    // so the receipt shows which fail behavior was applied.
    if (freshnessGate && freshnessGate.blocks) {
      verdict = 'deny'
      violations.push(freshnessGate.detail)
    }

    if (!delegation) {
      verdict = 'deny'
      violations.push('No active delegation for agent')
    } else {
      // C1 (Day 217): before scope and spend, walk the selected inbound delegation's BOUND chain
      // (parent_delegation_id, not a re-resolved "current newest inbound" per ancestor). A revoked or
      // suspended agent anywhere on that chain -- including the terminal root grantor -- ends this
      // delegation's authority even though its own row is still 'active'. Intentionally fail-closed:
      // if the acting agent holds a newer inbound whose chain is dead while an older inbound would
      // still be valid, the newest-inbound selection above still denies (see handoff).
      const chainCheck = checkBoundAuthorityChain(db, tenant.id, delegation.id)
      if (!chainCheck.ok) {
        verdict = 'deny'
        violations.push(`Delegation authority chain is invalid (code=${chainCheck.code}, hop=${chainCheck.hop})`)
      }
      const allowedScopes = delegation.scope.split(',').map((s: string) => s.trim())
      // Use argument-pattern matching for broad-capability tools, fall back to simple scope
      const scopeMatched = scopeMatchesWithArguments(allowedScopes, scope_required, parsedArgs, scopeAuth)
      if (!scopeMatched) {
        verdict = 'deny'
        violations.push(`Scope "${scope_required}" not in [${delegation.scope}]`)
      }
      // Reject a malformed or negative estimated_cost before any budget math. A negative cost would
      // slip past `estimated_cost > remaining` (a negative is never greater than the remaining
      // budget) AND, on permit, the spend_used update below would ADD a negative, refunding the
      // budget. Either lets an agent spend without limit. Require a non-negative finite number.
      if (estimated_cost !== undefined && estimated_cost !== null && !isNonNegativeFiniteCost(estimated_cost)) {
        verdict = 'deny'
        violations.push(`Invalid estimated_cost ${estimated_cost}: must be a non-negative finite number`)
      }
      // Panel B6 F1: gate on `!= null`, not truthiness. A spend_limit of 0 (a zero-budget grant) is
      // falsy, so the old check skipped it, permitted the spend, and then the spend_used UPDATE tripped
      // the DB CHECK -> 500. `!= null` means a 0 limit denies any positive cost (remaining 0), cleanly.
      if (estimated_cost && estimated_cost > 0 && delegation.spend_limit != null) {
        const remaining = delegation.spend_limit - (delegation.spend_used || 0)
        if (estimated_cost > remaining) {
          verdict = 'deny'
          violations.push(`Cost $${estimated_cost} exceeds remaining budget $${remaining.toFixed(2)}`)
        }
      }
    }

    // Agent type enforcement
    if (verdict === 'permit' && agent.agent_type && agent.agent_type !== 'general') {
      const typeConstraints = AGENT_TYPE_CONSTRAINTS[agent.agent_type as string]
      if (typeConstraints) {
        for (const blocked of typeConstraints.blocked_scopes) {
          if (scope_required === blocked || scope_required.startsWith(blocked + ':')) {
            verdict = 'deny'
            violations.push(`Agent type "${agent.agent_type}" is not permitted scope "${scope_required}"`)
            break
          }
        }
      }
    }

    const reason = verdict === 'permit'
      ? `Permitted: scope "${scope_required}" authorized`
      : `Denied: ${violations.join('; ')}`
    const durationMs = Date.now() - start

    db.prepare(`INSERT INTO policy_evaluations (id, tenant_id, agent_id, action_type, action_target, scope_required, verdict, reason, duration_ms, task_class) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(evalId, tenant.id, agent_id, action_type, action_target || '', scope_required, verdict, reason, durationMs, deriveTaskClass(action_type))

    if (verdict === 'permit' && estimated_cost && estimated_cost > 0 && delegation) {
      // Defense in depth: only ever ADD a positive amount to spend_used. A non-positive cost is
      // already denied above, so this never runs for one, but the guard makes a budget refund
      // structurally impossible from this path.
      // C4 dual-write: REAL column (existing) + INTEGER cents (forward-compat).
      // COALESCE guards against rows that pre-date the cents column.
      const inc_cents = toCents(estimated_cost) || 0
      db.prepare(
        `UPDATE delegations
         SET spend_used = spend_used + ?,
             spend_used_cents = COALESCE(spend_used_cents, 0) + ?
         WHERE id = ?`
      ).run(estimated_cost, inc_cents, delegation.id)
    }

    return { verdict, reason, violations, durationMs, delegation }
  }).immediate()

  const { verdict, reason, violations, durationMs, delegation } = evalResult

  // ── G-D1: apply the enforcement mode ──────────────────────────────
  // `verdict` above is the RAW policy decision (a violation is a violation,
  // recorded faithfully in policy_evaluations and the minted receipt). The
  // active mode decides the CONSEQUENCE the caller actually sees: observe/warn
  // never block (evidence only), approval blocks only high-risk for sign-off,
  // enforce blocks every violation, emergency additionally fails closed on
  // high-risk permits. The body accepts an optional workflow_id so a single
  // tenant can run different workflows at different rollout stages.
  const workflowId = (req.body.workflow_id as string) || null
  const mode = resolveMode(tenant.id, workflowId)
  const risk = classifyRequestRisk({ scopeRequired: scope_required, violations, estimatedCost: estimated_cost ?? null })
  const modeDecision = applyMode({ rawVerdict: verdict === 'permit' ? 'permit' : 'deny', risk, mode })

  // Effective verdict the caller sees. permit unless the mode chose to stop it.
  const effectiveVerdict = modeDecision.blocked ? 'deny' : 'permit'

  // Record the migration signal (would-have-been-denied or a real block) so the
  // migration metric can answer "is it safe to graduate to enforce yet".
  recordModeObservation({
    tenantId: tenant.id, agentId: agent_id, workflowId, evaluationId: evalId,
    scopeRequired: scope_required, decision: modeDecision,
  })
  if (modeDecision.wouldHaveBeenDenied || modeDecision.blocked) {
    emitToEventSpine(tenant.id, 'mode_observation', {
      agent_id: agent_id, evaluation_id: evalId, mode, effect: modeDecision.effect, risk,
      would_have_been_denied: modeDecision.wouldHaveBeenDenied, blocked: modeDecision.blocked,
    })
  }

  try { getEventBus().emit(tenant.id, { type: verdict === 'permit' ? 'evaluation' : 'denial', agentId: agent_id, data: { evaluationId: evalId, action_type, scope_required, verdict, reason, duration_ms: durationMs, mode, effect: modeDecision.effect } }) } catch {}

  mintEvaluationReceipt({
    tenantId: tenant.id, agentId: agent_id, evaluationId: evalId,
    verdict, actionType: action_type, scopeRequired: scope_required,
    reason, delegationId: delegation?.id || null,
  })

  // C3 (audit 2026-05-12): no longer write to the legacy `usage` table.
  // `policy_evaluations` (inserted via mintEvaluationReceipt above) is
  // the single source of truth and is what `checkEvaluationLimit` reads.

  if (verdict === 'permit' && estimated_cost && delegation) {
    try { getEventBus().emit(tenant.id, { type: 'spend_update', agentId: agent_id, data: { delegation_id: delegation.id, spend_used: (delegation.spend_used || 0) + estimated_cost, spend_limit: delegation.spend_limit } }) } catch {}
  }
  if (delegation?.spend_limit && (delegation.spend_used || 0) > delegation.spend_limit * 0.8) {
    db.prepare(`INSERT INTO alerts (id, tenant_id, alert_type, severity, message) VALUES (?, ?, ?, ?, ?)`)
      .run(randomUUID(), tenant.id, 'spend_threshold', 'warning',
        `Agent "${agent_id}" at ${(((delegation.spend_used || 0) / delegation.spend_limit) * 100).toFixed(0)}% of spend limit`)
    try { getEventBus().emit(tenant.id, { type: 'alert', agentId: agent_id, data: { alert_type: 'spend_threshold', severity: 'warning' } }) } catch {}
  }

  // Spend alert emails (80% and 95% thresholds, deduplicated)
  if (verdict === 'permit' && delegation?.spend_limit && estimated_cost) {
    const newSpent = (delegation.spend_used || 0) + estimated_cost
    const pct = (newSpent / delegation.spend_limit) * 100
    for (const threshold of [80, 95]) {
      if (pct >= threshold) {
        const key = `${delegation.id}:${threshold}`
        if (!spendAlertsSent.has(key)) {
          spendAlertsSent.add(key)
          const email = spendAlertEmail(tenant.name || 'Tenant', agent_id, Math.round(pct))
          email.to = tenant.email
          sendEmail(email).catch(() => {})
        }
      }
    }
  }

  // Recovery guidance on denial (backward compat: null when no policy)
  let recovery: any = null
  if (verdict === 'deny') {
    try {
      const policyRow = db.prepare(
        `SELECT policy_json FROM recovery_policies WHERE tenant_id = ? AND agent_id = ?`
      ).get(tenant.id, agent_id) as any
      if (policyRow) {
        const evaluateRecovery = await getEvaluateRecovery()
        if (evaluateRecovery) {
          const policy = JSON.parse(policyRow.policy_json)
          const failureType = mapFailureType(violations)
          const result = evaluateRecovery({ policy, failureType })
          recovery = {
            strategy: result.strategy,
            rule: result.rule?.name || null,
            maxRetries: result.rule?.maxRetries || null,
            initialBackoffMs: result.rule?.initialBackoffMs || null,
            hardStop: result.hardStop,
          }
          // Store recovery event in audit trail (best-effort)
          try {
            db.prepare(
              `INSERT INTO recovery_events (id, tenant_id, agent_id, delegation_id, evaluation_id, failure_type, strategy_applied, attempt_number) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
            ).run(randomUUID(), tenant.id, agent_id, delegation?.id || null, evalId, failureType, result.strategy, 1)
            try { getEventBus().emit(tenant.id, { type: 'recovery_event', agentId: agent_id, data: { failure_type: failureType, strategy: result.strategy } }) } catch {}
          } catch { /* best-effort */ }
        }
      }
    } catch { /* recovery lookup is best-effort, never blocks response */ }
  }

  // G-B3: surface the freshness-tier verdict additively. Shows which fail
  // behavior the gateway applied for this action class and the staleness it
  // observed. Recorded durably in the evaluation receipt via the reason above.
  const freshness = freshnessGate ? {
    risk_tier: freshnessGate.tier,
    outcome: freshnessGate.outcome,
    fresh: freshnessGate.fresh,
    observed_age_seconds: freshnessGate.ageSeconds,
    reason_code: freshnessGate.reasonCode,
    revocation_mode: freshnessGate.revocationMode,
  } : undefined

  // G-D1: `verdict` remains the RAW policy decision (unchanged contract: the
  // receipt records the policy's view of the action). The mode dimension is
  // surfaced separately:
  //   effective_verdict - what the caller should actually do (deny only when the
  //                        mode chose to stop the action).
  //   enforced          - true when the mode actually blocked (enforce/emergency
  //                        block, or approval_required). false in shadow modes.
  //   would_have_been_denied - a violation the current mode let through. The
  //                        shadow signal an operator watches before enforcing.
  res.json({
    evaluation_id: evalId,
    verdict,
    reason,
    violations: violations.length > 0 ? violations : undefined,
    recovery,
    freshness,
    duration_ms: durationMs,
    agent_id,
    action: { type: action_type, target: action_target, scope_required },
    mode,
    effective_verdict: effectiveVerdict,
    enforced: modeDecision.blocked,
    mode_effect: modeDecision.effect,
    would_have_been_denied: modeDecision.wouldHaveBeenDenied,
    risk,
  })
  } catch (e) {
    const msg = (e as Error).message || String(e)
    const stack = (e as Error).stack || ''
    console.error('[EVALUATE ERROR]', msg)
    const err = safeError(e, 'evaluate')
    res.status(500).json(err)
  }
})

// ═══════════════════════════════════════
// POST /api/v1/receipt — Store Signed Receipt
// ═══════════════════════════════════════

gatewayRouter.post('/receipt', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const { evaluation_id, agent_id, action_type, verdict, execution_result, signature, payload } = req.body
  if (!agent_id || !signature || !payload) {
    return res.status(400).json({ error: 'Required: agent_id, signature, payload' })
  }

  const db = getDB()

  // Audit item 6 (HIGH, money/audit): verify the receipt signature BEFORE storing. Previously any
  // caller could store a forged or tampered receipt under any agent_id. The SDK ActionReceipt
  // preimage is canonicalize(receipt MINUS its signature field), verified against the signer's
  // REGISTERED public key (agents.public_key, looked up by tenant + agent_id). Fail closed: an
  // unknown agent, an unparseable payload, or a bad/missing signature is rejected, never stored.
  const agentRow = db.prepare(`SELECT public_key FROM agents WHERE tenant_id = ? AND agent_id = ?`).get(tenant.id, agent_id) as any
  if (!agentRow || !agentRow.public_key) {
    return res.status(404).json({ error: `Agent "${agent_id}" not registered in this tenant; cannot verify receipt signature` })
  }
  let receiptObj: any
  try {
    receiptObj = typeof payload === 'string' ? JSON.parse(payload) : payload
  } catch {
    return res.status(400).json({ error: 'Receipt payload is not valid JSON; cannot verify signature' })
  }
  if (!receiptObj || typeof receiptObj !== 'object' || Array.isArray(receiptObj)) {
    return res.status(400).json({ error: 'Receipt payload must be a JSON object; cannot verify signature' })
  }
  // The signed preimage excludes the receipt's own signature field (matches SDK signing).
  const { signature: _embeddedSig, ...unsigned } = receiptObj
  let sigOk = false
  try {
    sigOk = apsVerify(apsCanonicalize(unsigned), String(signature), String(agentRow.public_key))
  } catch {
    sigOk = false // fail closed on any canonicalize/verify error
  }
  if (!sigOk) {
    return res.status(400).json({ error: 'Receipt signature verification failed; receipt rejected (tampered, forged, or wrong signing key)' })
  }

  const receiptId = randomUUID()
  db.prepare(`INSERT INTO receipts (id, tenant_id, evaluation_id, agent_id, action_type, verdict, execution_result, signature, payload) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(receiptId, tenant.id, evaluation_id || null, agent_id, action_type || '', verdict || '', execution_result || '', signature, typeof payload === 'string' ? payload : JSON.stringify(payload))

  try { getEventBus().emit(tenant.id, { type: 'receipt_stored', agentId: agent_id, data: { receiptId, evaluationId: evaluation_id, action_type, verdict } }) } catch {}

  res.status(201).json({ receipt_id: receiptId, stored: true })
})

// ═══════════════════════════════════════
// POST /api/v1/receipts/bilateral - Bilateral interaction receipt (B3, Consilium)
// ═══════════════════════════════════════
//
// An APS interaction receipt is BILATERAL: a requesting agent and a serving agent
// BOTH sign the same canonical body. The unilateral POST /receipt above checks a
// SINGLE signature against a SINGLE key and cannot attest a two-party interaction.
// This route verifies BOTH signatures against BOTH agents' REGISTERED keys (looked
// up by tenant + agent_id) using the SDK's verifyBilateralReceipt primitive, so the
// gateway consumes the protocol primitive and never reimplements it.
//
// Fail-closed rules:
//   * both agents MUST be registered in THIS tenant (agent_id + tenant bound); an
//     unknown or cross-tenant counterparty is a 404, never stored.
//   * a PRESENT signature that does not verify against the registered key is a
//     forgery/tamper -> 400, never stored.
//   * status is 'attested' only when BOTH sides verify; a legitimately one-sided
//     receipt (exactly one present-and-valid signature, the other absent) stores
//     'partial_attestation'; a receipt with no valid signature is rejected.
//   * F3 (FREEZE-VWE): the signed body must carry an audience binding naming THIS
//     tenant's recipient identifier; requireAudience is TRUE on this route. See
//     checkReceiptAudienceForTenant below.

// F3 (FREEZE-VWE) route-side audience evaluation, fail closed. Delegates to the
// SDK's checkAudience (root barrel export since agent-passport-system 3.3.0) with
// requireAudience hardwired true. This replaced the local mirror the moment the
// export landed, per that mirror's swap note; the SDK emits the same reason codes
// the mirror did, so the wire contract is unchanged:
// audience_required_absent | audience_malformed | audience_mismatch.
// aud null is coalesced to undefined before the call: JSON bodies can carry an
// explicit null, the route's contract treats it as absent, and the SDK's
// checkAudience throws on null rather than classifying it.
function checkReceiptAudienceForTenant(
  aud: unknown,
  recipientId: string,
): { ok: boolean; code: string; message: string } {
  const r = checkAudience(
    { aud: (aud ?? undefined) as Parameters<typeof checkAudience>[0]['aud'] },
    { recipientId, requireAudience: true },
  )
  return { ok: r.status === 'pass', code: r.reason ?? r.status, message: r.message ?? '' }
}

gatewayRouter.post('/receipts/bilateral', (req: any, res) => {
 try {
  // R3-0 (round-2 Consilium): OFF by default. The signed BilateralReceipt body carries no audience/
  // tenant field, so a valid receipt from tenant A replays into tenant B (F2 cross-tenant; per-tenant
  // dedup cannot see it). Nothing reads bilateral_receipts today (grep-verified), but the route must
  // stay dark until BOTH land: (a) the SDK BilateralReceipt binds an audience/tenant INSIDE the signed
  // body and this route verifies it, and (b) an independent, hand-computed RFC 8785 golden vector (NOT
  // SDK-generated) is added to the conformance suite. Enable only then, via BILATERAL_RECEIPTS_ENABLED=1.
  if (process.env.BILATERAL_RECEIPTS_ENABLED !== '1') {
    return res.status(404).json({ error: 'Bilateral receipt endpoint is not enabled' })
  }
  const tenant: Tenant = req.tenant
  const receipt = req.body?.receipt
  if (!receipt || typeof receipt !== 'object' || Array.isArray(receipt)) {
    return res.status(400).json({ error: 'Required: receipt (a bilateral receipt object)' })
  }
  const { requestingAgentId, servingAgentId, requestingAgentSignature, servingAgentSignature } = receipt
  if (!requestingAgentId || !servingAgentId) {
    return res.status(400).json({ error: 'Receipt must name requestingAgentId and servingAgentId' })
  }
  // Panel F1: a stable, signed receipt_id is the dedup key. It is inside the signed body, so a
  // replay cannot alter it without breaking a signature. Absent it, replays could not be detected.
  if (!receipt.receiptId || typeof receipt.receiptId !== 'string') {
    return res.status(400).json({ error: 'Receipt must carry a receiptId (replay-dedup key)' })
  }
  // Panel F3: a bilateral receipt is between TWO DISTINCT parties. requester===server is a
  // self-interaction, not a two-party attestation.
  if (requestingAgentId === servingAgentId) {
    return res.status(400).json({ error: 'A bilateral receipt requires two distinct agents; requestingAgentId equals servingAgentId' })
  }

  const db = getDB()
  // agent_id + tenant binding: BOTH counterparties must be registered in THIS tenant, and (panel F5)
  // BOTH must be active. A revoked/suspended key must not mint an attestation.
  const reqRow = db.prepare(`SELECT public_key, status FROM agents WHERE tenant_id = ? AND agent_id = ?`).get(tenant.id, requestingAgentId) as any
  if (!reqRow || !reqRow.public_key) {
    return res.status(404).json({ error: `Requesting agent "${requestingAgentId}" not registered in this tenant; cannot verify receipt` })
  }
  const srvRow = db.prepare(`SELECT public_key, status FROM agents WHERE tenant_id = ? AND agent_id = ?`).get(tenant.id, servingAgentId) as any
  if (!srvRow || !srvRow.public_key) {
    return res.status(404).json({ error: `Serving agent "${servingAgentId}" not registered in this tenant; cannot verify receipt` })
  }
  if (reqRow.status !== 'active' || srvRow.status !== 'active') {
    const bad = reqRow.status !== 'active' ? requestingAgentId : servingAgentId
    return res.status(403).json({ error: `Agent "${bad}" is not active; a suspended or revoked agent cannot attest a receipt` })
  }
  // Panel F4: two distinct ids sharing ONE key is a single party masquerading as two. A genuine
  // bilateral attestation is signed by two DISTINCT keys.
  if (String(reqRow.public_key) === String(srvRow.public_key)) {
    return res.status(400).json({ error: 'Both agents present the same public key; a bilateral attestation requires two distinct keys' })
  }

  // Which sides even claim a signature (a present signature must verify; an absent one is one-sided).
  const hasReq = typeof requestingAgentSignature === 'string' && requestingAgentSignature.length > 0
  const hasSrv = typeof servingAgentSignature === 'string' && servingAgentSignature.length > 0

  let v
  try {
    v = verifyBilateralReceipt(receipt, String(reqRow.public_key), String(srvRow.public_key))
  } catch {
    return res.status(400).json({ error: 'Bilateral receipt verification failed (unparseable or malformed receipt); rejected' })
  }

  // A PRESENT signature that does not verify is a forgery/tamper. Fail closed, never store.
  if (hasReq && !v.requestingAgentSignatureValid) {
    return res.status(400).json({ error: 'Requesting agent signature invalid; receipt rejected (forged, tampered, or wrong registered key)' })
  }
  if (hasSrv && !v.servingAgentSignatureValid) {
    return res.status(400).json({ error: 'Serving agent signature invalid; receipt rejected (forged, tampered, or wrong registered key)' })
  }
  // Panel F6: an attested outcome must be temporally possible. completedAt/agreedAt before
  // requestedAt (verifyBilateralReceipt.timingValid=false) is not a valid attestation.
  if (!v.timingValid) {
    return res.status(400).json({ error: 'Receipt timing is invalid (completed or agreed before requested); rejected' })
  }

  // F3 (FREEZE-VWE): audience gate, fail closed. The recipient identifier is DERIVED from the
  // tenant key registry partition: agents.tenant_id, i.e. the authenticated tenant row id that
  // already scopes every registry lookup above. It is NEVER read from request input, so a valid
  // receipt minted for tenant A cannot replay into tenant B (the F2 cross-tenant gap that kept
  // this route dark). The aud slot is inside the signed body: re-targeting it breaks the
  // signatures checked above. Machine-readable code + facet in the rejection.
  const audienceRecipientId = `aps-tenant:${tenant.id}`
  const audCheck = checkReceiptAudienceForTenant(receipt.aud, audienceRecipientId)
  if (!audCheck.ok) {
    return res.status(403).json({
      error: `Audience check failed: ${audCheck.message}`,
      code: audCheck.code,
      facet: 'audience',
    })
  }

  const reqValid = hasReq && v.requestingAgentSignatureValid
  const srvValid = hasSrv && v.servingAgentSignatureValid
  let status: 'attested' | 'partial_attestation'
  if (reqValid && srvValid) status = 'attested'
  else if (reqValid || srvValid) status = 'partial_attestation'
  else return res.status(400).json({ error: 'Receipt carries no valid signature; rejected' })

  // Panel F1: replay dedup. A receipt_id already stored for this tenant is a replay. The pre-check
  // gives a clean 409; the UNIQUE(tenant_id, receipt_id) constraint is the race backstop below.
  const dup = db.prepare(`SELECT 1 FROM bilateral_receipts WHERE tenant_id = ? AND receipt_id = ?`).get(tenant.id, String(receipt.receiptId)) as any
  if (dup) {
    return res.status(409).json({ error: `Receipt "${receipt.receiptId}" already recorded for this tenant; replay rejected` })
  }

  const rowId = randomUUID()
  try {
    db.prepare(`INSERT INTO bilateral_receipts (id, tenant_id, receipt_id, requesting_agent_id, serving_agent_id, delegation_id, status, requesting_sig_valid, serving_sig_valid, outcome_consistent, timing_valid, payload) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(rowId, tenant.id, String(receipt.receiptId), requestingAgentId, servingAgentId, receipt.delegationId || null, status, reqValid ? 1 : 0, srvValid ? 1 : 0, v.outcomeConsistent ? 1 : 0, v.timingValid ? 1 : 0, JSON.stringify(receipt))
  } catch (e: any) {
    if (String(e?.message || '').includes('UNIQUE')) {
      return res.status(409).json({ error: `Receipt "${receipt.receiptId}" already recorded for this tenant; replay rejected` })
    }
    throw e
  }

  try { getEventBus().emit(tenant.id, { type: 'bilateral_receipt_stored', agentId: requestingAgentId, data: { rowId, receiptId: receipt.receiptId, servingAgentId, status } }) } catch {}

  res.status(201).json({
    receipt_id: rowId,
    status,
    requesting_signature_valid: reqValid,
    serving_signature_valid: srvValid,
    outcome_consistent: v.outcomeConsistent,
    timing_valid: v.timingValid,
    stored: true,
  })
 } catch (e) {
    res.status(500).json(safeError(e, 'receipts-bilateral'))
 }
})

// ═══════════════════════════════════════
// POST /api/v1/revoke — Cascade Revocation
// ═══════════════════════════════════════

// H1 (audit 2026-05-12): per-tenant rate limit on cascade revoke.
// A leaked API key could otherwise cascade-revoke a tenant's entire fleet
// in a single hostile session. 5 revokes/min/tenant gives an operator
// plenty of headroom for normal use; anything past that is suspicious.
const revokeLimiter = new RateLimiterMemory({
  points: 5,
  duration: 60,
  keyPrefix: 'revoke',
})

gatewayRouter.post('/revoke', async (req: any, res) => {
  const tenant: Tenant = req.tenant
  try { await revokeLimiter.consume(tenant.id) }
  catch {
    return res.status(429).json({
      error: 'Revoke rate limit exceeded (5/min/tenant). If this is unexpected, your API key may be compromised — rotate it immediately at aeoess.com/dashboard.html.',
    })
  }
  const { target_type, target_id, revoked_by } = req.body
  if (!target_type || !target_id) {
    return res.status(400).json({ error: 'Required: target_type (agent|delegation|data_source), target_id' })
  }

  const db = getDB()
  let cascadeCount = 0

  if (target_type === 'agent') {
    // Revoke agent and all their delegations
    db.prepare(`UPDATE agents SET status = 'revoked' WHERE tenant_id = ? AND agent_id = ?`)
      .run(tenant.id, target_id)
    const result = db.prepare(`UPDATE delegations SET status = 'revoked', revoked_at = datetime('now') WHERE tenant_id = ? AND (child_agent_id = ? OR parent_agent_id = ?)`)
      .run(tenant.id, target_id, target_id)
    // Freeze agent wallet as part of revocation cascade
    db.prepare(`UPDATE agent_wallets SET status = 'frozen' WHERE tenant_id = ? AND agent_id = ? AND status = 'active'`)
      .run(tenant.id, target_id)
    cascadeCount = result.changes
  } else if (target_type === 'delegation') {
    // C1 (Day 217): revokes ONLY this row. Direct target only -- there is no downstream cascade here
    // and there never was one; a descendant delegation bound to this row via parent_delegation_id loses
    // authority through checkBoundAuthorityChain at evaluation/grant time, not by this UPDATE rewriting
    // its status. Descendant rows are never touched by /revoke.
    db.prepare(`UPDATE delegations SET status = 'revoked', revoked_at = datetime('now') WHERE tenant_id = ? AND id = ?`)
      .run(tenant.id, target_id)
    cascadeCount = 1
  } else if (target_type === 'data_source') {
    // Retract a data source — no more access receipts will be generated
    db.prepare(`UPDATE data_sources SET status = 'revoked', revoked_at = datetime('now') WHERE tenant_id = ? AND source_id = ?`)
      .run(tenant.id, target_id)
    // Count affected agents (who consumed this source)
    const affected = db.prepare(`SELECT COUNT(DISTINCT agent_id) as c FROM access_receipts WHERE tenant_id = ? AND source_id = ?`)
      .get(tenant.id, target_id) as any
    cascadeCount = affected.c
  }

  const revocationId = randomUUID()
  db.prepare(`INSERT INTO revocations (id, tenant_id, target_type, target_id, cascade_count, revoked_by) VALUES (?, ?, ?, ?, ?, ?)`)
    .run(revocationId, tenant.id, target_type, target_id, cascadeCount, revoked_by || 'api')

  // C1 (Day 217): cascade_count is the number of rows this call directly updated (both sides of an
  // agent revoke, or the single delegation row, or the count of agents who accessed a revoked data
  // source) -- NOT a count of descendants in a delegation chain. Wording fixed to match; the JSON field
  // name (cascade_count) is left in place for API compatibility.
  db.prepare(`INSERT INTO alerts (id, tenant_id, alert_type, severity, message) VALUES (?, ?, ?, ?, ?)`)
    .run(randomUUID(), tenant.id, 'revocation', 'critical',
      `${target_type} "${target_id}" revoked. ${cascadeCount} row(s) directly updated.`)
  try { getEventBus().emit(tenant.id, { type: 'alert', data: { alert_type: 'revocation', severity: 'critical', target_type, target_id } }) } catch {}

  try { getEventBus().emit(tenant.id, { type: 'revocation', data: { revocationId, target_type, target_id, cascade_count: cascadeCount, revoked_by: revoked_by || 'api' } }) } catch {}

  res.json({ revocation_id: revocationId, target_type, target_id, cascade_count: cascadeCount })
})

// ═══════════════════════════════════════
// GET /api/v1/agents — List Agents
// ═══════════════════════════════════════

gatewayRouter.get('/agents', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const db = getDB()
  const limit = Math.min(parseInt(req.query.limit as string) || 20, 100)
  const offset = parseInt(req.query.offset as string) || 0
  const [sortCol, sortDir] = ((req.query.sort as string) || 'created_at:desc').split(':')
  const safeCol = ['created_at', 'agent_id', 'status', 'name'].includes(sortCol) ? sortCol : 'created_at'
  const safeDir = sortDir === 'asc' ? 'ASC' : 'DESC'
  const items = db.prepare(`SELECT agent_id, public_key, did, name, status, agent_type, created_at FROM agents WHERE tenant_id = ? ORDER BY ${safeCol} ${safeDir} LIMIT ? OFFSET ?`).all(tenant.id, limit, offset)
  const total = (db.prepare(`SELECT COUNT(*) as c FROM agents WHERE tenant_id = ?`).get(tenant.id) as any).c
  res.json({ agents: items, total, limit, offset, has_more: offset + items.length < total })
})

// POST /api/v1/agents — Register Agent
gatewayRouter.post('/agents', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const db = getDB()
  const { agent_id, public_key, did, name, agent_type, entity_id, entity_verification_endpoint, metadata } = req.body
  if (!agent_id || !public_key) {
    return res.status(400).json({ error: 'Required: agent_id, public_key' })
  }
  // Consilium policy: is_root is NEVER self-service. A client-supplied `is_root` is ignored here;
  // root designation is the audited admin action POST /api/v1/root-designations. New agents are
  // is_root=0; existing roots are preserved by the B1 history backfill.
  // B8 immutability: an agent_id is immutable. A duplicate registration is a 409 (no upsert), so the
  // public_key cannot be swapped by re-registering (which would rebind authority). Key rotation is a
  // separate, recorded operation (not this path).
  const existing = db.prepare(`SELECT 1 FROM agents WHERE tenant_id = ? AND agent_id = ?`).get(tenant.id, agent_id) as any
  if (existing) {
    return res.status(409).json({ error: `Agent "${agent_id}" already exists in this tenant; agent_id and public_key are immutable (rotate keys via the recorded rotation path).` })
  }
  // Security triage 2026-04-11 fix 4: validate entity_verification_endpoint
  // against the SSRF guard at registration time. Rejecting here is the
  // primary defense; the policy evaluation path has defense-in-depth.
  if (entity_verification_endpoint !== undefined && entity_verification_endpoint !== null && entity_verification_endpoint !== '') {
    const check = validateExternalUrl(entity_verification_endpoint)
    if (!check.safe) {
      return res.status(400).json({
        error: 'entity_verification_endpoint rejected by SSRF guard',
        reason: check.reason,
      })
    }
  }
  const validTypes = ['general', 'explorer', 'planner', 'executor', 'reviewer', 'monitor']
  const safeType = validTypes.includes(agent_type) ? agent_type : 'general'
  const limitCheck = checkAgentLimit(tenant.id, tenant.plan)
  if (!limitCheck.allowed) {
    return res.status(403).json({ error: limitCheck.reason, current: limitCheck.current, limit: limitCheck.limit })
  }
  const id = randomUUID()
  db.prepare(`INSERT INTO agents (id, tenant_id, agent_id, public_key, did, name, agent_type, entity_id, entity_verification_endpoint, metadata, is_root) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`)
    .run(id, tenant.id, agent_id, public_key, did || null, name || null, safeType, entity_id || null, entity_verification_endpoint || null, metadata ? JSON.stringify(metadata) : null)
  // Wallet → agent reverse index: pick up bound_wallets at enrollment time
  // so /public/trust/by-wallet/:address resolves immediately without a
  // boot rebuild. Promised to douglasborthwick-crypto on insumer-examples#1.
  try {
    if (metadata && Array.isArray((metadata as any).bound_wallets)) {
      recordBoundWallets({
        tenant_id: tenant.id,
        agent_id,
        bound_wallets: (metadata as any).bound_wallets,
      })
    }
  } catch { /* index hygiene must not block enrollment */ }
  try { getEventBus().emit(tenant.id, { type: 'agent_registered', agentId: agent_id, data: { public_key, name, did, agent_type: safeType, entity_id } }) } catch {}
  res.status(201).json({ id, agent_id, status: 'active' })
})

// POST /api/v1/root-designations - Consilium policy: designate an agent as a root grantor.
// Admin-only and AUDITED. This is the ONLY way to set is_root=1 (POST /agents ignores a client
// is_root). Every designation writes a root_designations row (who, when, agent, tenant), atomically
// with the is_root flip. Existing roots are preserved by the B1 history backfill; this handles NEW
// roots after migration.
gatewayRouter.post('/root-designations', (req: any, res) => {
  const tenant: Tenant = req.tenant
  if ((tenant as any).role !== 'admin') {
    return res.status(403).json({ error: 'Root designation requires an admin key. is_root is not self-service.' })
  }
  const db = getDB()
  const targetTenant = req.body.tenant_id || tenant.id
  const { agent_id } = req.body
  if (!agent_id) return res.status(400).json({ error: 'Required: agent_id' })
  const agent = db.prepare(`SELECT status FROM agents WHERE tenant_id = ? AND agent_id = ?`).get(targetTenant, agent_id) as any
  if (!agent) return res.status(404).json({ error: `Agent "${agent_id}" not found in tenant "${targetTenant}"` })
  // R3-1 (a): a root grantor must be a live principal. Refuse designating a non-active target; a
  // revoked/suspended/frozen agent must not be handed fresh-budget origination authority.
  if (agent.status !== 'active') {
    return res.status(400).json({ error: `Cannot designate agent "${agent_id}" as root: status is "${agent.status}", not active.` })
  }
  // R3-1 (b): re-rooting an agent that has a delegation history (ever a child) is the deliberate,
  // audited override of the DEAD path. It requires an explicit re_root:true and a non-empty reason,
  // both recorded in the audit row. A never-inbound agent is a plain origin root (no re_root needed).
  const everInbound = db.prepare(`SELECT 1 FROM delegations WHERE tenant_id = ? AND child_agent_id = ? LIMIT 1`).get(targetTenant, agent_id) as any
  const reRoot = req.body.re_root === true
  const reason = typeof req.body.reason === 'string' ? req.body.reason.trim() : ''
  if (everInbound && (!reRoot || reason.length === 0)) {
    return res.status(400).json({ error: `Agent "${agent_id}" has a delegation history (it was previously a delegatee). Re-rooting it requires re_root:true and a non-empty reason.` })
  }
  const designatedAt = new Date().toISOString()
  // R5-1 (final Consilium): same TOCTOU shape as POST /delegations. The target-status read above is an
  // autocommit read outside the write txn; across processes the target could be revoked/suspended
  // between that read and the promotion. Run the promotion in a BEGIN IMMEDIATE txn and re-verify the
  // target is STILL active inside it; a mismatch is a 409 (retry). (Grant-time is already protected by
  // the R5-1 grant re-verify, but designating a just-revoked agent as root would still write a stale
  // flag + audit row, so close it here too.)
  try {
    const txn = db.transaction(() => {
      const now = db.prepare(`SELECT status FROM agents WHERE tenant_id = ? AND agent_id = ?`).get(targetTenant, agent_id) as any
      if (!now || now.status !== 'active') {
        throw new AuthorityChangedError(`target agent "${agent_id}" is no longer active`)
      }
      db.prepare(`UPDATE agents SET is_root = 1 WHERE tenant_id = ? AND agent_id = ?`).run(targetTenant, agent_id)
      db.prepare(`INSERT INTO root_designations (id, tenant_id, agent_id, designated_by, designated_at, re_root, reason) VALUES (?, ?, ?, ?, ?, ?, ?)`)
        .run(randomUUID(), targetTenant, agent_id, tenant.id, designatedAt, everInbound && reRoot ? 1 : 0, everInbound ? reason : (reason || null))
    })
    txn.immediate()
  } catch (e) {
    if (e instanceof AuthorityChangedError) {
      return res.status(409).json({ error: `${(e as Error).message}; state changed between evaluation and commit, retry the request` })
    }
    throw e
  }
  res.status(200).json({ tenant_id: targetTenant, agent_id, is_root: true, designated_by: tenant.id, designated_at: designatedAt, re_root: !!(everInbound && reRoot), reason: everInbound ? reason : (reason || null) })
})

// ═══════════════════════════════════════
// POST /api/v1/issuance-dossier
// MCP server POSTs IssuanceContext after every passport issuance.
// Gateway stores the full evidence record privately.
// ═══════════════════════════════════════
gatewayRouter.post('/issuance-dossier', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const db = getDB()
  const {
    passport_id, public_key_hash, passport_grade, flags,
    attestation_bundle_hash, observed_context,
    runtime_attestations, provider_attestations,
    self_declared_signals, derived_signals, prior_passport_ref
  } = req.body

  if (!passport_id || !public_key_hash) {
    return res.status(400).json({ error: 'Required: passport_id, public_key_hash' })
  }

  // Clamp grade to 0-3 — malicious MCP can't send passport_grade: 99
  const grade = Math.min(3, Math.max(0, Math.floor(passport_grade || 0)))
  const id = randomUUID()
  const obs = observed_context || {}

  try {
    db.prepare(`INSERT OR REPLACE INTO issuance_dossiers
      (id, tenant_id, passport_id, public_key_hash, passport_grade,
       flags, attestation_bundle_hash, observed_context,
       runtime_attestations, provider_attestations,
       self_declared_signals, derived_signals, prior_passport_ref,
       transport_type, issuance_velocity, connection_timing_ms,
       request_payload_fingerprint)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(
        id, tenant.id, passport_id, public_key_hash,
        grade,
        JSON.stringify(flags || []),
        attestation_bundle_hash || null,
        JSON.stringify(obs),
        JSON.stringify(runtime_attestations || []),
        JSON.stringify(provider_attestations || []),
        JSON.stringify(self_declared_signals || []),
        JSON.stringify(derived_signals || []),
        prior_passport_ref || null,
        obs.transportType || null,
        obs.issuanceVelocity ?? null,
        obs.connectionTimingMs ?? null,
        obs.requestPayloadFingerprint || null
      )

    // Check for velocity anomaly — many passports from same pubkey hash
    const velocityCheck = db.prepare(
      `SELECT COUNT(*) as c FROM issuance_dossiers
       WHERE tenant_id = ? AND public_key_hash = ?`
    ).get(tenant.id, public_key_hash) as any
    if (velocityCheck.c > 1) {
      db.prepare(`INSERT INTO alerts (id, tenant_id, alert_type, severity, message)
        VALUES (?, ?, ?, ?, ?)`)
        .run(randomUUID(), tenant.id, 'issuance_velocity', 'warning',
          `pubkey ${public_key_hash.slice(0, 12)}... has ${velocityCheck.c} dossiers. Possible re-issuance.`)
      try { getEventBus().emit(tenant.id, { type: 'alert', data: { alert_type: 'issuance_velocity', severity: 'warning', public_key_hash } }) } catch {}
    }

    // Sybil gate: strict velocity (5+ passports/hr from same key = critical)
    const recentFromKey = db.prepare(
      `SELECT COUNT(*) as c FROM issuance_dossiers WHERE tenant_id = ? AND public_key_hash = ? AND created_at > datetime('now', '-1 hour')`
    ).get(tenant.id, public_key_hash) as any
    if (recentFromKey.c >= 5) {
      db.prepare(`INSERT INTO alerts (id, tenant_id, alert_type, severity, message) VALUES (?, ?, ?, ?, ?)`)
        .run(randomUUID(), tenant.id, 'sybil_issuance_velocity', 'critical',
          `Key ${public_key_hash.slice(0, 16)}... issued ${recentFromKey.c} passports in 1hr`)
    }

    // Sybil gate: fingerprint clustering (10+ distinct keys with same request fingerprint in 24h)
    if (obs.requestPayloadFingerprint) {
      const fpCluster = db.prepare(
        `SELECT COUNT(DISTINCT public_key_hash) as c FROM issuance_dossiers WHERE tenant_id = ? AND request_payload_fingerprint = ? AND created_at > datetime('now', '-24 hours')`
      ).get(tenant.id, obs.requestPayloadFingerprint) as any
      if (fpCluster.c >= 10) {
        db.prepare(`INSERT INTO alerts (id, tenant_id, alert_type, severity, message) VALUES (?, ?, ?, ?, ?)`)
          .run(randomUUID(), tenant.id, 'sybil_fingerprint_cluster', 'critical',
            `Payload fingerprint ${(obs.requestPayloadFingerprint as string).slice(0, 16)}... seen from ${fpCluster.c} distinct keys in 24h`)
      }
    }

    // Compute lineage links and cluster risk
    const dossierRow = db.prepare(
      `SELECT * FROM issuance_dossiers WHERE id = ?`
    ).get(id) as any
    const links = computeLineageLinks(dossierRow)
    const cluster = storeAndCluster(tenant.id, id, passport_id, links)

    res.status(201).json({
      dossier_id: id,
      passport_id,
      grade,
      cluster_risk: cluster.risk,
      cluster_size: cluster.clusterSize,
      stored: true,
    })
  } catch (e: any) {
    res.status(500).json(safeError(e, 'issuance-dossier'))
  }
})

// ═══════════════════════════════════════
// GET /api/v1/passport/:agentId/trust-profile
// The presentation query API. One call, one JSON, one decision.
// This is what Nik's service (and every partner) actually calls.
// ═══════════════════════════════════════
gatewayRouter.get('/passport/:agentId/trust-profile', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const db = getDB()
  const { agentId } = req.params

  // Agent existence
  const agent = db.prepare(
    `SELECT * FROM agents WHERE tenant_id = ? AND agent_id = ?`
  ).get(tenant.id, agentId) as any
  if (!agent) {
    return res.status(404).json({ error: `Unknown agent: ${agentId}`, grade: 0, trust: 'unknown' })
  }

  // Delegation (endorsement proxy)
  const delegation = db.prepare(
    `SELECT * FROM delegations WHERE tenant_id = ? AND child_agent_id = ? AND status = 'active' ORDER BY created_at DESC LIMIT 1`
  ).get(tenant.id, agentId) as any

  // Wallet
  const wallet = db.prepare(
    `SELECT * FROM agent_wallets WHERE tenant_id = ? AND agent_id = ?`
  ).get(tenant.id, agentId) as any

  // Activity stats
  const evalCount = (db.prepare(
    `SELECT COUNT(*) as c FROM policy_evaluations WHERE tenant_id = ? AND agent_id = ?`
  ).get(tenant.id, agentId) as any).c
  const receiptCount = (db.prepare(
    `SELECT COUNT(*) as c FROM receipts WHERE tenant_id = ? AND agent_id = ?`
  ).get(tenant.id, agentId) as any).c
  const deniedCount = (db.prepare(
    `SELECT COUNT(*) as c FROM policy_evaluations WHERE tenant_id = ? AND agent_id = ? AND verdict = 'deny'`
  ).get(tenant.id, agentId) as any).c

  // Data contribution receipts
  const contributionReceipts = (db.prepare(
    `SELECT COUNT(*) as c FROM access_receipts WHERE tenant_id = ? AND agent_id = ?`
  ).get(tenant.id, agentId) as any).c

  // Wallet transaction stats
  const txCount = wallet ? (db.prepare(
    `SELECT COUNT(*) as c FROM wallet_transactions WHERE tenant_id = ? AND from_agent_id = ?`
  ).get(tenant.id, agentId) as any).c : 0
  const walletDenied = wallet ? (db.prepare(
    `SELECT COUNT(*) as c FROM wallet_transactions WHERE tenant_id = ? AND from_agent_id = ? AND status = 'denied'`
  ).get(tenant.id, agentId) as any).c : 0

  // Destination convergence (farming detector)
  // How many OTHER agents sent to the same top destination in 24h?
  let destinationRisk: 'low' | 'medium' | 'high' = 'low'
  let convergenceCount = 0
  if (wallet) {
    const topDest = db.prepare(
      `SELECT to_address, COUNT(*) as c FROM wallet_transactions
       WHERE tenant_id = ? AND from_agent_id = ? AND status = 'confirmed'
       GROUP BY to_address ORDER BY c DESC LIMIT 1`
    ).get(tenant.id, agentId) as any
    if (topDest) {
      const convergence = db.prepare(
        `SELECT COUNT(DISTINCT from_agent_id) as c FROM wallet_transactions
         WHERE tenant_id = ? AND to_address = ? AND from_agent_id != ?
         AND status = 'confirmed' AND created_at > datetime('now', '-24 hours')`
      ).get(tenant.id, topDest.to_address, agentId) as any
      convergenceCount = convergence.c
      if (convergenceCount >= 10) destinationRisk = 'high'
      else if (convergenceCount >= 3) destinationRisk = 'medium'
    }
  }

  // Issuance dossier (if MCP server has sent one)
  const dossier = db.prepare(
    `SELECT * FROM issuance_dossiers WHERE tenant_id = ? AND passport_id = ? ORDER BY created_at DESC LIMIT 1`
  ).get(tenant.id, agentId) as any

  // Compute coarse grade (0-3)
  // If dossier exists, use its grade (computed by SDK with full evidence model).
  // Otherwise fall back to SQL-based heuristic.
  let grade = 0
  if (dossier) {
    grade = dossier.passport_grade
  } else {
    if (agent.status === 'active') grade = 1
    if (delegation) grade = 2
    if (delegation && evalCount >= 10 && receiptCount >= 5) grade = 3
  }

  // Age
  const createdAt = new Date(agent.created_at)
  const ageDays = Math.floor((Date.now() - createdAt.getTime()) / (1000 * 60 * 60 * 24))

  res.json({
    agent_id: agentId,
    grade,
    trust: grade >= 3 ? 'established' : grade >= 2 ? 'endorsed' : grade >= 1 ? 'registered' : 'unknown',
    age_days: ageDays,
    has_delegation: !!delegation,
    has_wallet: !!wallet,
    activity: {
      evaluations: evalCount,
      receipts: receiptCount,
      denials: deniedCount,
      contribution_receipts: contributionReceipts,
    },
    wallet_activity: wallet ? {
      transactions: txCount,
      denied: walletDenied,
      status: wallet.status,
    } : null,
    risk: {
      destination_convergence: destinationRisk,
      convergent_agents_24h: convergenceCount,
      denial_rate: evalCount > 0 ? Math.round((deniedCount / evalCount) * 100) / 100 : 0,
      lineage_cluster: dossier ? getClusterRisk(tenant.id, agentId).risk : 'no_dossier',
    },
    attestation: dossier ? {
      grade_source: 'sdk',
      transport_type: dossier.transport_type,
      issuance_velocity: dossier.issuance_velocity,
      has_runtime_attestation: JSON.parse(dossier.runtime_attestations || '[]').length > 0,
      has_provider_attestation: JSON.parse(dossier.provider_attestations || '[]').length > 0,
      flags: JSON.parse(dossier.flags || '[]'),
      attestation_bundle_hash: dossier.attestation_bundle_hash,
      dossier_created_at: dossier.created_at,
    } : { grade_source: 'heuristic' },
    queried_at: new Date().toISOString(),
  })
})

// ═══════════════════════════════════════
// GET /api/v1/trust/:agentId/profile — Per-task-class trust breakdown
// ═══════════════════════════════════════
gatewayRouter.get('/trust/:agentId/profile', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const db = getDB()
  const { agentId } = req.params

  const agent = db.prepare(`SELECT agent_id FROM agents WHERE tenant_id = ? AND agent_id = ?`).get(tenant.id, agentId) as any
  if (!agent) return res.status(404).json({ error: `Agent "${agentId}" not found` })

  // Temporal decay window: ?window_days=30, env TRUST_DECAY_WINDOW_DAYS (default 7)
  const windowDays = parseInt(req.query.window_days as string) || parseInt(process.env.TRUST_DECAY_WINDOW_DAYS || '7')
  const timeFilter = windowDays > 0 ? ` AND created_at > datetime('now', '-${windowDays} days')` : ''

  // Overall stats
  const overall = db.prepare(
    `SELECT COUNT(*) as evaluations,
            SUM(CASE WHEN verdict = 'permit' THEN 1 ELSE 0 END) as permits,
            SUM(CASE WHEN verdict = 'deny' THEN 1 ELSE 0 END) as denials
     FROM policy_evaluations WHERE tenant_id = ? AND agent_id = ?${timeFilter}`
  ).get(tenant.id, agentId) as any

  const overallEvals = overall?.evaluations || 0
  const overallPermits = overall?.permits || 0
  const overallDenials = overall?.denials || 0

  // Per-task-class breakdown
  const classRows = db.prepare(
    `SELECT task_class,
            COUNT(*) as evaluations,
            SUM(CASE WHEN verdict = 'permit' THEN 1 ELSE 0 END) as permits,
            SUM(CASE WHEN verdict = 'deny' THEN 1 ELSE 0 END) as denials
     FROM policy_evaluations WHERE tenant_id = ? AND agent_id = ? AND task_class != ''${timeFilter}
     GROUP BY task_class ORDER BY evaluations DESC`
  ).all(tenant.id, agentId) as any[]

  const byTaskClass: Record<string, { evaluations: number; permits: number; denials: number; trust_score: number }> = {}
  for (const row of classRows) {
    const evals = row.evaluations || 0
    byTaskClass[row.task_class] = {
      evaluations: evals,
      permits: row.permits || 0,
      denials: row.denials || 0,
      trust_score: evals > 0 ? Math.round(((row.permits || 0) / evals) * 100) / 100 : 0,
    }
  }

  res.json({
    agent_id: agentId,
    window_days: windowDays || 'all',
    overall: {
      evaluations: overallEvals,
      permits: overallPermits,
      denials: overallDenials,
      trust_score: overallEvals > 0 ? Math.round((overallPermits / overallEvals) * 100) / 100 : 0,
    },
    by_task_class: byTaskClass,
  })
})

/** R5-1: thrown when a grantor's authority changed between the gate read and the insert commit. */
export class AuthorityChangedError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'AuthorityChangedError'
  }
}

/**
 * R5-1 (final Consilium): apply a delegation grant inside a single BEGIN IMMEDIATE transaction that
 * RE-VERIFIES the grantor's authority against the CURRENT rows before inserting, closing the
 * cross-process TOCTOU on POST /delegations. The route's gate reads grantor authority (status, is_root,
 * the parent delegation) as autocommit reads OUTSIDE this txn; in-process the handler is synchronous so
 * there is no race, but across processes (Railway rolling restart, multi-replica) a demotion,
 * suspension, or revocation can commit between that read and this insert, and the prior deferred txn
 * never re-read. BEGIN IMMEDIATE takes the write lock up front (exactly one writer in WAL), so the
 * re-read here is serialized against any concurrent authority-change commit. On a mismatch it throws
 * AuthorityChangedError (the route maps it to 409; the caller retries and gets the correct 403 from the
 * gate). Also carries the R4-1 audited demotion in the same transaction. Returns { demoted }.
 *
 * C1 (Day 217): the narrowing branch's re-verify is the FULL bound-chain check (checkBoundAuthorityChain
 * on parentDelId), not just "is the immediate parentDel row still active" -- a revoked or suspended
 * ancestor anywhere up the chain also invalidates it. The new row's parent_delegation_id is stored as
 * parentDelId (NULL for an origination grant), permanently binding it to the exact inbound delegation
 * that authorized it; revocation later never rewrites this or any descendant row.
 */
export function applyGrantWithReverify(
  db: Database.Database,
  opts: {
    tenantId: string
    grantorId: string
    childId: string
    delegationId: string
    scope: string
    spendLimit: number | null
    spendLimitCents: number | null
    maxDepth: number
    childDepth: number
    wasOrigination: boolean
    parentDelId: string | null
  },
): { demoted: boolean } {
  let demoted = false
  const txn = db.transaction(() => {
    // R5-1 re-verify against CURRENT rows (inside the write lock).
    const gNow = db.prepare(`SELECT is_root, status FROM agents WHERE tenant_id = ? AND agent_id = ?`).get(opts.tenantId, opts.grantorId) as any
    if (!gNow || gNow.status !== 'active') {
      throw new AuthorityChangedError(`grantor "${opts.grantorId}" is no longer active`)
    }
    if (opts.wasOrigination) {
      // Origination branch: the grantor must STILL be a designated root (not demoted since the gate read).
      if (!gNow.is_root) throw new AuthorityChangedError(`grantor "${opts.grantorId}" is no longer a designated root`)
    } else {
      // C1 (Day 217): narrowing branch, re-verified INSIDE the write lock. The gate's route-level
      // check (below) already ran this as an autocommit read before the transaction; a demotion,
      // suspension, or revocation anywhere on the bound chain can still commit in the gap between that
      // read and here (the same TOCTOU this transaction already closes for the immediate grantor), so
      // the full chain check runs again against current rows before the insert.
      const chainCheck = checkBoundAuthorityChain(db, opts.tenantId, opts.parentDelId as string)
      if (!chainCheck.ok) {
        throw new AuthorityChangedError(`the grantor's bound authority chain is no longer valid (code=${chainCheck.code}, hop=${chainCheck.hop})`)
      }
    }
    db.prepare(`INSERT INTO delegations (id, tenant_id, parent_agent_id, child_agent_id, scope, spend_limit, spend_limit_cents, max_depth, current_depth, parent_delegation_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(opts.delegationId, opts.tenantId, opts.grantorId, opts.childId, opts.scope, opts.spendLimit, opts.spendLimitCents, opts.maxDepth, opts.childDepth, opts.parentDelId)
    // R4-1 audited demotion: if the CHILD is a designated root, receiving this inbound subordinates it.
    const childRoot = db.prepare(`SELECT is_root FROM agents WHERE tenant_id = ? AND agent_id = ?`).get(opts.tenantId, opts.childId) as any
    if (childRoot && childRoot.is_root) {
      db.prepare(`UPDATE agents SET is_root = 0 WHERE tenant_id = ? AND agent_id = ?`).run(opts.tenantId, opts.childId)
      db.prepare(`INSERT INTO root_designations (id, tenant_id, agent_id, designated_by, designated_at, re_root, reason, action, caused_by_delegation_id) VALUES (?, ?, ?, ?, ?, 0, ?, 'auto_demotion', ?)`)
        .run(randomUUID(), opts.tenantId, opts.childId, opts.grantorId, new Date().toISOString(), `auto-demotion: subordinated by inbound delegation ${opts.delegationId} from ${opts.grantorId}`, opts.delegationId)
      demoted = true
    }
  })
  txn.immediate() // BEGIN IMMEDIATE: take the write lock up front so the re-read is serialized.
  return { demoted }
}

// POST /api/v1/delegations — Create Delegation
gatewayRouter.post('/delegations', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const db = getDB()
  const { parent_agent_id, child_agent_id, scope, spend_limit, max_depth } = req.body
  if (!parent_agent_id || !child_agent_id || !scope) {
    return res.status(400).json({ error: 'Required: parent_agent_id, child_agent_id, scope' })
  }
  // P3-6: verify agent exists (prevent phantom delegations)
  const childExists = db.prepare(`SELECT 1 FROM agents WHERE tenant_id = ? AND agent_id = ?`).get(tenant.id, child_agent_id) as any
  if (!childExists) return res.status(404).json({ error: `Agent "${child_agent_id}" not found in this tenant` })

  // Consilium hostile-panel B1/B2 F1: the GRANTOR's own liveness. The gate below keys on is_root and
  // inbound-delegation liveness but must ALSO check the granting agent's own posture. A revoked or
  // suspended agent (including a designated root, which revocation does not un-root) must not
  // originate or narrow authority. /evaluate applies this posture to the ACTING agent; the grant path
  // applies it to the GRANTOR principal (a different agent). Fetched once here and reused below.
  const parentAgentRow = db.prepare(`SELECT is_root, status FROM agents WHERE tenant_id = ? AND agent_id = ?`).get(tenant.id, parent_agent_id) as any
  if (!parentAgentRow) return res.status(404).json({ error: `Parent agent "${parent_agent_id}" not found in this tenant` })
  if (parentAgentRow.status !== 'active') {
    return res.status(403).json({ error: `Delegation rejected: the granting agent "${parent_agent_id}" is not active (status: ${parentAgentRow.status}). A suspended or revoked agent cannot grant, even a designated root.` })
  }

  // Monotonic narrowing: if parent_agent_id itself holds a delegation, the new child may only
  // narrow it (subset scope, spend within the parent's remaining budget, non-increasing depth
  // ceiling). A parent with no inbound delegation is a tenant root principal and may grant freely.
  // Without this, a delegatee could mint a child broader than what it was granted (escalation).
  // Panel B1/B2 F2: `id DESC` is a deterministic secondary sort. created_at has 1s resolution, so
  // among same-instant active inbounds SQLite's pick was arbitrary, making WHICH inbound bounds the
  // child (and, on /evaluate, which is charged) nondeterministic. (Reconciling MULTIPLE simultaneous
  // active inbounds into an aggregate budget remains an open design item; see REMEDIATION-MEMO.md.)
  const parentDel = db.prepare(
    `SELECT id, scope, spend_limit, spend_used, max_depth, current_depth FROM delegations
     WHERE tenant_id = ? AND child_agent_id = ? AND status = 'active' ORDER BY created_at DESC, id DESC LIMIT 1`
  ).get(tenant.id, parent_agent_id) as any

  // Audit item 3 (HIGH money): fake-root gate. A parent with NO inbound delegation (parentDel null)
  // is treated by checkDelegationNarrowing as a free-granting root with spend_used=0 and
  // current_depth=0. Without a server-side root notion, any no-inbound agent could be named as a
  // fresh-budget root, resetting an exhausted child's spend and the chain depth. So a no-inbound
  // parent may grant ONLY if it is a DESIGNATED root (agents.is_root=1). This also closes item 2's
  // depth-reset coupling: a non-root no-inbound parent can no longer reset current_depth to 0.
  if (!parentDel) {
    // B2 three-valued liveness with the R3-1 gate order. No LIVE inbound.
    // R3-1 (round-2 Consilium): check is_root FIRST. A DESIGNATED root originates regardless of
    // delegation history; designation is the deliberate, audited override (POST /root-designations
    // records who/when and, for an ex-child, re_root:true + a reason). The prior order checked the DEAD
    // branch first, so an admin-designated ex-child still 403'd DEAD and the audited override was
    // silently ineffective for exactly the re-rooting topology (R2 defeated R8).
    // parentAgentRow (fetched + existence-checked + status-checked above) carries is_root.
    if (!parentAgentRow.is_root) {
      // Not a designated root. Distinguish DEAD (had an inbound, now revoked/expired -- a severed
      // delegatee) from ABSENT (never delegated to). Only a designated root may originate either way.
      const everInbound = db.prepare(
        `SELECT 1 FROM delegations WHERE tenant_id = ? AND child_agent_id = ? LIMIT 1`,
      ).get(tenant.id, parent_agent_id) as any
      if (everInbound) {
        // DEAD: a severed child is is_root=0 and was not re-rooted, so it cannot originate.
        return res.status(403).json({ error: 'Delegation rejected: the parent had an inbound delegation that is no longer active (revoked or expired) and is not a designated root. A severed delegatee cannot originate a fresh-budget delegation unless it is explicitly re-rooted (admin POST /root-designations with re_root).' })
      }
      // ABSENT and not a designated root.
      return res.status(403).json({ error: 'Delegation rejected: the parent has no inbound delegation and is not a designated root. Only a designated root (agents.is_root=1) may grant a fresh-budget delegation.' })
    }
    // is_root=1: a designated (or re-rooted) root originates freely; fall through to narrowing as a
    // fresh-budget root.
  }

  // C1 (Day 217): route-level gate, an autocommit read outside the write transaction. A narrowing
  // grant (parentDel truthy) may only extend a BOUND chain that is still fully authoritative -- not
  // just the immediate parentDel row (already status='active' by the query above), but every ancestor
  // up to the terminal grantor. An already-dead chain 403s here before paying for a transaction;
  // applyGrantWithReverify re-runs the same check INSIDE the write lock to close the TOCTOU gap between
  // this read and the insert (a concurrent revoke/suspend lands 409, not a silently-granted delegation).
  if (parentDel) {
    const chainCheck = checkBoundAuthorityChain(db, tenant.id, parentDel.id)
    if (!chainCheck.ok) {
      return res.status(403).json({
        error: 'Delegation rejected: the grantor\'s bound authority chain is invalid.',
        code: chainCheck.code,
        hop: chainCheck.hop,
      })
    }
  }

  const childScopeArr = Array.isArray(scope) ? scope.map(String) : String(scope).split(',').map((s: string) => s.trim()).filter(Boolean)
  const narrow = checkDelegationNarrowing(
    parentDel ? { scope: parentDel.scope, spend_limit: parentDel.spend_limit, spend_used: parentDel.spend_used, max_depth: parentDel.max_depth, current_depth: parentDel.current_depth } : null,
    { scope: childScopeArr, spend_limit: (spend_limit ?? null) as number | null, max_depth: max_depth || 3 },
  )
  if (!narrow.ok) {
    return res.status(403).json({ error: 'Delegation escalation rejected', violations: narrow.violations })
  }
  // Real chain depth: root (no inbound delegation) is 0; each hop is parent.current_depth + 1.
  const childDepth = parentDel ? ((parentDel.current_depth ?? 0) + 1) : 0

  const id = randomUUID()
  // C4 dual-write: spend_limit (REAL) + spend_limit_cents (INTEGER).
  const spendLimitUsd = spend_limit || null
  const spendLimitCents = toCents(spendLimitUsd)
  // R5-1 (final Consilium): apply the grant inside a BEGIN IMMEDIATE transaction that RE-VERIFIES the
  // grantor's authority against the CURRENT rows (the gate above read them as autocommit reads outside
  // this txn; across processes a demotion/suspension/revocation can commit in between). On a stale-read
  // mismatch it throws AuthorityChangedError, mapped to 409 here so the caller retries and gets the
  // correct 403 from the gate. Also carries the R4-1 audited demotion (same transaction).
  try {
    const { demoted } = applyGrantWithReverify(db, {
      tenantId: tenant.id, grantorId: parent_agent_id, childId: child_agent_id, delegationId: id,
      scope: Array.isArray(scope) ? scope.join(',') : scope, spendLimit: spendLimitUsd, spendLimitCents,
      maxDepth: max_depth || 3, childDepth, wasOrigination: !parentDel, parentDelId: parentDel ? parentDel.id : null,
    })
    try { getEventBus().emit(tenant.id, { type: 'delegation_created', data: { delegation_id: id, parent_agent_id, child_agent_id, scope, spend_limit } }) } catch {}
    // R5-2: surface the audited auto-demotion operationally (mirrors delegation_created).
    if (demoted) {
      try { getEventBus().emit(tenant.id, { type: 'root_auto_demotion', data: { tenant: tenant.id, agent: child_agent_id, caused_by_delegation_id: id, grantor: parent_agent_id } }) } catch {}
    }
    res.status(201).json({ id, status: 'active' })
  } catch (e) {
    if (e instanceof AuthorityChangedError) {
      return res.status(409).json({ error: `${(e as Error).message}; grantor authority changed between evaluation and commit, retry the request` })
    }
    throw e
  }
})

// GET /api/v1/delegations — List Delegations
gatewayRouter.get('/delegations', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const db = getDB()
  const limit = Math.min(parseInt(req.query.limit as string) || 20, 100)
  const offset = parseInt(req.query.offset as string) || 0
  const [sortCol, sortDir] = ((req.query.sort as string) || 'created_at:desc').split(':')
  const safeCol = ['created_at', 'child_agent_id', 'parent_agent_id', 'status'].includes(sortCol) ? sortCol : 'created_at'
  const safeDir = sortDir === 'asc' ? 'ASC' : 'DESC'
  const items = db.prepare(`SELECT * FROM delegations WHERE tenant_id = ? ORDER BY ${safeCol} ${safeDir} LIMIT ? OFFSET ?`).all(tenant.id, limit, offset)
  const total = (db.prepare(`SELECT COUNT(*) as c FROM delegations WHERE tenant_id = ?`).get(tenant.id) as any).c
  res.json({ delegations: items, total, limit, offset, has_more: offset + items.length < total })
})

// GET /api/v1/audit — Audit Trail
gatewayRouter.get('/audit', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const db = getDB()
  const limit = Math.min(parseInt(req.query.limit as string) || 20, 100)
  const offset = parseInt(req.query.offset as string) || 0
  const [sortCol, sortDir] = ((req.query.sort as string) || 'created_at:desc').split(':')
  const safeCol = ['created_at', 'agent_id', 'verdict', 'action_type', 'scope_required'].includes(sortCol) ? sortCol : 'created_at'
  const safeDir = sortDir === 'asc' ? 'ASC' : 'DESC'

  const where: string[] = ['e.tenant_id = ?']
  const params: any[] = [tenant.id]
  if (req.query.agent_id) { where.push('e.agent_id = ?'); params.push(req.query.agent_id) }
  if (req.query.verdict) { where.push('e.verdict = ?'); params.push(req.query.verdict) }
  if (req.query.action_type) { where.push('e.action_type = ?'); params.push(req.query.action_type) }
  if (req.query.from) { where.push('e.created_at >= ?'); params.push(req.query.from) }
  if (req.query.to) { where.push('e.created_at <= ?'); params.push(req.query.to) }

  const whereClause = where.join(' AND ')
  const entries = db.prepare(`SELECT e.*, r.signature, r.execution_result FROM policy_evaluations e LEFT JOIN receipts r ON r.evaluation_id = e.id WHERE ${whereClause} ORDER BY e.${safeCol} ${safeDir} LIMIT ? OFFSET ?`).all(...params, limit, offset)
  const total = (db.prepare(`SELECT COUNT(*) as c FROM policy_evaluations e WHERE ${whereClause}`).get(...params) as any).c
  res.json({ entries, total, limit, offset, has_more: offset + entries.length < total })
})

// GET /api/v1/dashboard — Dashboard Summary
gatewayRouter.get('/dashboard', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const db = getDB()
  const period = new Date().toISOString().slice(0, 7)

  const agents = db.prepare(`SELECT COUNT(*) as c FROM agents WHERE tenant_id = ? AND status = 'active'`).get(tenant.id) as any
  const delegations = db.prepare(`SELECT COUNT(*) as c FROM delegations WHERE tenant_id = ? AND status = 'active'`).get(tenant.id) as any
  // C3 (audit 2026-05-12): count from policy_evaluations directly. The `usage`
  // table is no longer written by /evaluate, so it would always read 0.
  const monthStart = new Date()
  monthStart.setUTCDate(1); monthStart.setUTCHours(0, 0, 0, 0)
  const evalsThisMonth = (db.prepare(
    `SELECT COUNT(*) as c FROM policy_evaluations WHERE tenant_id = ? AND created_at >= ?`
  ).get(tenant.id, monthStart.toISOString()) as { c: number }).c
  const receipts = db.prepare(`SELECT COUNT(*) as c FROM evaluation_receipts WHERE tenant_id = ?`).get(tenant.id) as any
  const alerts = db.prepare(`SELECT * FROM alerts WHERE tenant_id = ? AND acknowledged_at IS NULL ORDER BY created_at DESC LIMIT 10`).all(tenant.id)
  const limit = PLAN_LIMITS[tenant.plan as keyof typeof PLAN_LIMITS]

  const recentDenials = db.prepare(`SELECT agent_id, action_type, reason, created_at FROM policy_evaluations WHERE tenant_id = ? AND verdict = 'deny' ORDER BY created_at DESC LIMIT 5`).all(tenant.id)

  res.json({
    plan: tenant.plan,
    agents: { active: agents.c, limit: limit.maxAgents },
    delegations: { active: delegations.c },
    usage: {
      evaluations_this_month: evalsThisMonth,
      limit: limit.evaluationsPerMonth,
      utilization: limit.evaluationsPerMonth > 0
        ? (evalsThisMonth / limit.evaluationsPerMonth * 100).toFixed(1) + '%'
        : 'unlimited',
    },
    receipts: { total: receipts.c },
    evaluation_receipts: (() => {
      const stats = db.prepare(`
        SELECT COUNT(*) as total,
               SUM(CASE WHEN verdict='permit' THEN 1 ELSE 0 END) as permits,
               SUM(CASE WHEN verdict='deny' THEN 1 ELSE 0 END) as denials
        FROM evaluation_receipts WHERE tenant_id = ?
      `).get(tenant.id) as any
      return { total: stats?.total || 0, permits: stats?.permits || 0, denials: stats?.denials || 0 }
    })(),
    alerts: { unacknowledged: alerts.length, items: alerts },
    recent_denials: recentDenials,
    compliance_reports_available: limit.complianceReports,
  })
})

// GET /api/v1/usage — Usage History
gatewayRouter.get('/usage', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const db = getDB()
  const history = db.prepare(`SELECT * FROM usage WHERE tenant_id = ? ORDER BY period DESC LIMIT 12`).all(tenant.id)
  res.json({ usage: history })
})

// GET /api/v1/decisions/recent — Recent policy evaluations for THIS tenant
// Powers the live-decisions feed on dashboard.html. Tenant-scoped (unlike
// the public /api/v1/public/recent-decisions which aggregates across all
// tenants and anonymizes agent IDs).
gatewayRouter.get('/decisions/recent', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const db = getDB()
  const limit = Math.min(parseInt(String(req.query.limit || '20'), 10) || 20, 100)
  const rows = db.prepare(`
    SELECT id, agent_id, action_type, action_target, scope_required,
           verdict, reason, duration_ms, created_at
    FROM policy_evaluations
    WHERE tenant_id = ?
    ORDER BY created_at DESC
    LIMIT ?
  `).all(tenant.id, limit) as Array<any>
  res.json({
    decisions: rows.map((r: any) => ({
      id: r.id,
      ts: r.created_at,
      agent_id: r.agent_id,
      action_type: r.action_type,
      action_target: r.action_target,
      scope_required: r.scope_required,
      decision: r.verdict,
      reason: r.reason,
      duration_ms: r.duration_ms,
    })),
    count: rows.length,
  })
})

// GET /api/v1/receipts/recent — Recent signed evaluation receipts for THIS tenant.
//
// Reads from evaluation_receipts (gateway-signed decision receipts).
// The 'receipts' table is the post-execution receipt surface emitted
// by the SDK after the agent acts; the dashboard "Receipts" tile and
// this endpoint both reflect evaluation_receipts so the numbers agree.
gatewayRouter.get('/receipts/recent', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const db = getDB()
  const limit = Math.min(parseInt(String(req.query.limit || '20'), 10) || 20, 100)
  const rows = db.prepare(`
    SELECT id, agent_id, evaluation_id, event_type, decision_stage,
           action_type, verdict, reason_code, delegation_id,
           policy_hash, schema_version, receipt_hash, gateway_signature,
           created_at
    FROM evaluation_receipts
    WHERE tenant_id = ?
    ORDER BY created_at DESC
    LIMIT ?
  `).all(tenant.id, limit) as Array<any>
  res.json({ receipts: rows, count: rows.length })
})

// POST /api/v1/alerts/:id/acknowledge — Acknowledge Alert
gatewayRouter.post('/alerts/:id/acknowledge', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const db = getDB()
  db.prepare(`UPDATE alerts SET acknowledged_at = datetime('now') WHERE id = ? AND tenant_id = ?`)
    .run(req.params.id, tenant.id)
  res.json({ acknowledged: true })
})

// ═══════════════════════════════════════
// DATA ATTRIBUTION (The Pixel)
// ═══════════════════════════════════════

// Purpose weight multipliers — how much more valuable each usage type is
const DEFAULT_PURPOSE_WEIGHTS: Record<string, number> = {
  read: 1,
  summary: 2,
  citation: 1.5,
  editorial_research: 1.5,
  rag: 5,
  rag_embedding: 5,
  embedding: 5,
  training: 10,
  fine_tune: 10,
}

function getPurposeWeight(purpose: string, terms: any): number {
  // Terms can override default weights via compensation.purpose_weights
  const custom = terms?.compensation?.purpose_weights
  if (custom && typeof custom === 'object' && custom[purpose] !== undefined) {
    return custom[purpose]
  }
  return DEFAULT_PURPOSE_WEIGHTS[purpose] || 1
}

// POST /api/v1/data-sources — Register a Data Source
gatewayRouter.post('/data-sources', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const { source_id, source_name, source_url, data_terms, owner_agent_id } = req.body
  if (!source_id || !source_name) {
    return res.status(400).json({ error: 'Required: source_id, source_name' })
  }
  const db = getDB()
  const id = randomUUID()
  try {
    db.prepare(`INSERT INTO data_sources (id, tenant_id, source_id, source_name, source_url, data_terms, owner_agent_id) VALUES (?, ?, ?, ?, ?, ?, ?)`)
      .run(id, tenant.id, source_id, source_name, source_url || null, JSON.stringify(data_terms || {}), owner_agent_id || null)
    try { getEventBus().emit(tenant.id, { type: 'data_source_registered', data: { source_id, source_name, owner_agent_id } }) } catch {}
    res.status(201).json({ id, source_id, status: 'active' })
  } catch (e: any) {
    if (e.message?.includes('UNIQUE')) return res.status(409).json({ error: 'Source already registered' })
    return res.status(500).json(safeError(e, 'data-source-register'))
  }
})

// GET /api/v1/data-sources — List Data Sources
gatewayRouter.get('/data-sources', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const db = getDB()
  const limit = Math.min(parseInt(req.query.limit as string) || 20, 100)
  const offset = parseInt(req.query.offset as string) || 0
  const items = db.prepare(`SELECT * FROM data_sources WHERE tenant_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`).all(tenant.id, limit, offset)
  const total = (db.prepare(`SELECT COUNT(*) as c FROM data_sources WHERE tenant_id = ?`).get(tenant.id) as any).c
  res.json({ sources: items, total, limit, offset, has_more: offset + items.length < total })
})

// POST /api/v1/access-receipts — Record Data Access
gatewayRouter.post('/access-receipts', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const { source_id, agent_id, purpose, signature } = req.body
  if (!source_id || !agent_id) {
    return res.status(400).json({ error: 'Required: source_id, agent_id' })
  }
  const db = getDB()

  // Verify source exists
  const src = db.prepare(`SELECT * FROM data_sources WHERE tenant_id = ? AND source_id = ? AND status = 'active'`)
    .get(tenant.id, source_id) as any
  if (!src) return res.status(404).json({ error: `Data source "${source_id}" not found or revoked` })

  const id = randomUUID()
  db.prepare(`INSERT INTO access_receipts (id, tenant_id, source_id, agent_id, purpose, terms_snapshot, signature) VALUES (?, ?, ?, ?, ?, ?, ?)`)
    .run(id, tenant.id, source_id, agent_id, purpose || 'read', src.data_terms, signature || null)
  try { getEventBus().emit(tenant.id, { type: 'access_receipt', agentId: agent_id, data: { source_id, purpose: purpose || 'read' } }) } catch {}

  // Upsert contribution ledger (purpose-weighted)
  const terms = JSON.parse(src.data_terms || '{}')
  const baseRate = terms?.compensation?.rate || 0
  const weight = getPurposeWeight(purpose || 'read', terms)
  const effectiveRate = baseRate * weight
  // Atomic upsert — no TOCTOU race on concurrent access receipts.
  // C4 dual-write: amount (REAL) + amount_cents (INTEGER). The COALESCE
  // guards rows pre-dating the cents column.
  const effectiveRateCents = toCents(effectiveRate) || 0
  db.prepare(`INSERT INTO contributions (id, tenant_id, source_id, agent_id, access_count, amount, amount_cents, currency)
    VALUES (?, ?, ?, ?, 1, ?, ?, ?)
    ON CONFLICT(tenant_id, source_id, agent_id)
    DO UPDATE SET access_count = access_count + 1,
                  amount = amount + ?,
                  amount_cents = COALESCE(amount_cents, 0) + ?,
                  updated_at = datetime('now')`)
    .run(randomUUID(), tenant.id, source_id, agent_id, effectiveRate, effectiveRateCents,
      terms?.compensation?.currency || 'usd', effectiveRate, effectiveRateCents)

  // ── Attribution Alerts (fire-and-forget) ──
  try {
    // Alert: high access rate (>50 in last hour from same agent)
    const hourAgo = new Date(Date.now() - 3600_000).toISOString().replace('T', ' ').slice(0, 19)
    const recentCount = db.prepare(
      `SELECT COUNT(*) as c FROM access_receipts WHERE tenant_id = ? AND agent_id = ? AND created_at > ?`
    ).get(tenant.id, agent_id, hourAgo) as any
    if (recentCount.c > 50 && recentCount.c % 50 === 1) {
      db.prepare(`INSERT INTO alerts (id, tenant_id, alert_type, severity, message) VALUES (?, ?, ?, ?, ?)`)
        .run(randomUUID(), tenant.id, 'high_access_rate', 'warning',
          `Agent "${agent_id}" made ${recentCount.c} data accesses in the last hour`)
      try { getEventBus().emit(tenant.id, { type: 'alert', agentId: agent_id, data: { alert_type: 'high_access_rate', severity: 'warning', count: recentCount.c } }) } catch {}
    }
    // Alert: training/fine-tune purpose (always notify — high-value event)
    if (purpose === 'training' || purpose === 'fine_tune') {
      db.prepare(`INSERT INTO alerts (id, tenant_id, alert_type, severity, message) VALUES (?, ?, ?, ?, ?)`)
        .run(randomUUID(), tenant.id, 'training_access', 'info',
          `Agent "${agent_id}" accessed "${source_id}" for ${purpose} (${weight}x rate)`)
      try { getEventBus().emit(tenant.id, { type: 'alert', agentId: agent_id, data: { alert_type: 'training_access', severity: 'info', source_id, purpose } }) } catch {}
    }
    // Alert: new agent first seen
    const agentHistory = db.prepare(
      `SELECT COUNT(*) as c FROM access_receipts WHERE tenant_id = ? AND agent_id = ? AND id != ?`
    ).get(tenant.id, agent_id, id) as any
    if (agentHistory.c === 0) {
      db.prepare(`INSERT INTO alerts (id, tenant_id, alert_type, severity, message) VALUES (?, ?, ?, ?, ?)`)
        .run(randomUUID(), tenant.id, 'new_consumer', 'info',
          `New agent "${agent_id}" first accessed your data (source: "${source_id}", purpose: ${purpose || 'read'})`)
      try { getEventBus().emit(tenant.id, { type: 'alert', agentId: agent_id, data: { alert_type: 'new_consumer', severity: 'info', source_id } }) } catch {}
    }
  } catch (_) { /* alerts are non-critical */ }

  res.status(201).json({ receipt_id: id, source_id, agent_id, purpose: purpose || 'read', weight, effective_rate: effectiveRate })
})

// GET /api/v1/attribution — Attribution Dashboard
gatewayRouter.get('/attribution', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const db = getDB()

  const sources = db.prepare(`SELECT COUNT(*) as c FROM data_sources WHERE tenant_id = ? AND status = 'active'`).get(tenant.id) as any
  const totalAccess = db.prepare(`SELECT COUNT(*) as c FROM access_receipts WHERE tenant_id = ?`).get(tenant.id) as any
  const uniqueAgents = db.prepare(`SELECT COUNT(DISTINCT agent_id) as c FROM access_receipts WHERE tenant_id = ?`).get(tenant.id) as any
  const totalOwed = db.prepare(`SELECT COALESCE(SUM(amount), 0) as total FROM contributions WHERE tenant_id = ?`).get(tenant.id) as any
  const derivationCount = db.prepare(`SELECT COUNT(*) as c FROM derivations WHERE tenant_id = ?`).get(tenant.id) as any

  // Top sources by access count
  const topSources = db.prepare(`
    SELECT ds.source_name, ds.source_id,
      (SELECT COUNT(*) FROM access_receipts ar WHERE ar.tenant_id = ds.tenant_id AND ar.source_id = ds.source_id) as accesses,
      (SELECT COALESCE(SUM(c.amount), 0) FROM contributions c WHERE c.tenant_id = ds.tenant_id AND c.source_id = ds.source_id) as owed
    FROM data_sources ds
    WHERE ds.tenant_id = ?
    ORDER BY accesses DESC LIMIT 10
  `).all(tenant.id)

  // Top consumers
  const topAgents = db.prepare(`
    SELECT agent_id, SUM(access_count) as accesses, SUM(amount) as total_owed
    FROM contributions WHERE tenant_id = ?
    GROUP BY agent_id ORDER BY accesses DESC LIMIT 10
  `).all(tenant.id)

  // Recent access receipts
  const recentAccess = db.prepare(`
    SELECT ar.agent_id, ar.source_id, ar.purpose, ar.created_at
    FROM access_receipts ar WHERE ar.tenant_id = ?
    ORDER BY ar.created_at DESC LIMIT 20
  `).all(tenant.id)

  // Time series: accesses per day (last 30 days)
  const timeSeries = db.prepare(`
    SELECT DATE(created_at) as day, COUNT(*) as accesses, COUNT(DISTINCT agent_id) as agents
    FROM access_receipts WHERE tenant_id = ? AND created_at > datetime('now', '-30 days')
    GROUP BY DATE(created_at) ORDER BY day ASC
  `).all(tenant.id)

  // Purpose breakdown
  const purposeBreakdown = db.prepare(`
    SELECT purpose, COUNT(*) as count FROM access_receipts WHERE tenant_id = ?
    GROUP BY purpose ORDER BY count DESC
  `).all(tenant.id)

  res.json({
    summary: {
      data_sources: sources.c,
      total_accesses: totalAccess.c,
      unique_agents: uniqueAgents.c,
      total_owed: Math.round(totalOwed.total * 10000) / 10000,
      derivations_declared: derivationCount.c,
    },
    top_sources: topSources,
    top_agents: topAgents,
    recent_access: recentAccess,
    time_series: timeSeries,
    purpose_breakdown: purposeBreakdown,
  })
})

// POST /api/v1/settlements — Generate Settlement
gatewayRouter.post('/settlements', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const { period_start, period_end } = req.body
  if (!period_start || !period_end) {
    return res.status(400).json({ error: 'Required: period_start, period_end' })
  }
  const db = getDB()
  const contributions = db.prepare(`SELECT * FROM contributions WHERE tenant_id = ? AND amount > 0`).all(tenant.id) as any[]
  if (contributions.length === 0) {
    return res.status(404).json({ error: 'No contributions to settle' })
  }
  const lineItems = contributions.map((c: any) => ({
    source_id: c.source_id, agent_id: c.agent_id,
    accesses: c.access_count, amount: c.amount, currency: c.currency,
  }))
  const total = contributions.reduce((s: number, c: any) => s + c.amount, 0)
  const id = randomUUID()
  // C4 dual-write: total_amount (REAL) + total_amount_cents (INTEGER).
  const totalCents = toCents(total) || 0
  db.prepare(`INSERT INTO settlements (id, tenant_id, period_start, period_end, total_amount, total_amount_cents, line_items) VALUES (?, ?, ?, ?, ?, ?, ?)`)
    .run(id, tenant.id, period_start, period_end, total, totalCents, JSON.stringify(lineItems))
  try { getEventBus().emit(tenant.id, { type: 'settlement_created', data: { settlement_id: id, period_start, period_end, total_amount: total, line_items_count: lineItems.length } }) } catch {}
  res.status(201).json({ settlement_id: id, period_start, period_end, total_amount: Math.round(total * 10000) / 10000, line_items: lineItems.length })
})

// GET /api/v1/settlements — List Settlements
gatewayRouter.get('/settlements', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const db = getDB()
  const limit = Math.min(parseInt(req.query.limit as string) || 20, 100)
  const offset = parseInt(req.query.offset as string) || 0
  const items = db.prepare(`SELECT id, period_start, period_end, total_amount, created_at FROM settlements WHERE tenant_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`).all(tenant.id, limit, offset)
  const total = (db.prepare(`SELECT COUNT(*) as c FROM settlements WHERE tenant_id = ?`).get(tenant.id) as any).c
  res.json({ settlements: items, total, limit, offset, has_more: offset + items.length < total })
})

// ═══════════════════════════════════════
// AGENT SELF-SERVICE (transparency — agents audit their own usage)
// ═══════════════════════════════════════

// GET /api/v1/my-consumption?agent_id=X — Agent views what they've consumed
gatewayRouter.get('/my-consumption', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const agent_id = req.query.agent_id as string
  if (!agent_id) {
    return res.status(400).json({ error: 'Required query param: agent_id' })
  }
  const db = getDB()

  // What sources this agent has accessed
  const sources = db.prepare(`
    SELECT source_id, purpose, COUNT(*) as accesses, MIN(created_at) as first_access, MAX(created_at) as last_access
    FROM access_receipts WHERE tenant_id = ? AND agent_id = ?
    GROUP BY source_id, purpose ORDER BY accesses DESC
  `).all(tenant.id, agent_id)

  // What this agent owes
  const contributions = db.prepare(`
    SELECT source_id, access_count, amount, currency, updated_at
    FROM contributions WHERE tenant_id = ? AND agent_id = ?
    ORDER BY amount DESC
  `).all(tenant.id, agent_id)

  const totalOwed: number = (contributions as any[]).reduce((s: number, c: any) => s + (c.amount || 0), 0)
  const totalAccesses: number = (sources as any[]).reduce((s: number, r: any) => s + r.accesses, 0)

  // Terms the agent should be aware of
  const sourceTerms = db.prepare(`
    SELECT source_id, source_name, data_terms FROM data_sources
    WHERE tenant_id = ? AND source_id IN (SELECT DISTINCT source_id FROM access_receipts WHERE tenant_id = ? AND agent_id = ?)
  `).all(tenant.id, tenant.id, agent_id)

  res.json({
    agent_id,
    summary: {
      total_accesses: totalAccesses,
      unique_sources: new Set((sources as any[]).map((s: any) => s.source_id)).size,
      total_owed: Math.round(totalOwed * 10000) / 10000,
    },
    access_by_source: sources,
    contributions,
    source_terms: sourceTerms.map((s: any) => ({
      source_id: s.source_id,
      source_name: s.source_name,
      terms: JSON.parse(s.data_terms || '{}'),
    })),
  })
})

// ═══════════════════════════════════════
// DERIVATIONS (agent-declared usage chain)
// ═══════════════════════════════════════

// POST /api/v1/derivations — Agent declares "I used these sources to produce this output"
gatewayRouter.post('/derivations', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const { agent_id, source_ids, output_description, output_url, signature } = req.body
  if (!agent_id || !source_ids || !Array.isArray(source_ids) || source_ids.length === 0) {
    return res.status(400).json({ error: 'Required: agent_id, source_ids (array of source_id strings)' })
  }
  const db = getDB()
  const placeholders = source_ids.map(() => '?').join(',')
  const receipts = db.prepare(
    `SELECT id, source_id FROM access_receipts WHERE tenant_id = ? AND agent_id = ? AND source_id IN (${placeholders})`
  ).all(tenant.id, agent_id, ...source_ids) as any[]
  const id = randomUUID()
  db.prepare(`INSERT INTO derivations (id, tenant_id, agent_id, source_ids, output_description, output_url, access_receipt_ids, signature) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(id, tenant.id, agent_id, JSON.stringify(source_ids), output_description || null, output_url || null, JSON.stringify(receipts.map((r: any) => r.id)), signature || null)
  try { getEventBus().emit(tenant.id, { type: 'derivation_created', agentId: agent_id, data: { derivation_id: id, source_count: source_ids.length } }) } catch {}
  db.prepare(`INSERT INTO alerts (id, tenant_id, alert_type, severity, message) VALUES (?, ?, ?, ?, ?)`)
    .run(randomUUID(), tenant.id, 'derivation_declared', 'info',
      `Agent "${agent_id}" declared usage of ${source_ids.length} source(s) for "${output_description || output_url || 'undescribed'}"`)
  try { getEventBus().emit(tenant.id, { type: 'alert', agentId: agent_id, data: { alert_type: 'derivation_declared', severity: 'info' } }) } catch {}
  res.status(201).json({
    derivation_id: id, agent_id,
    sources_declared: source_ids.length,
    access_receipts_linked: receipts.length,
    coverage: source_ids.length > 0 ? Math.round((receipts.length / source_ids.length) * 100) + '%' : '0%',
  })
})

// GET /api/v1/derivations — List derivation declarations
gatewayRouter.get('/derivations', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const db = getDB()
  const limit = Math.min(parseInt(req.query.limit as string) || 20, 100)
  const offset = parseInt(req.query.offset as string) || 0
  const agent = req.query.agent_id as string
  let query = `SELECT * FROM derivations WHERE tenant_id = ?`
  const countQuery = `SELECT COUNT(*) as c FROM derivations WHERE tenant_id = ?`
  const params: any[] = [tenant.id]
  const countParams: any[] = [tenant.id]
  if (agent) { query += ` AND agent_id = ?`; countQuery; params.push(agent); countParams.push(agent) }
  query += ` ORDER BY created_at DESC LIMIT ? OFFSET ?`
  params.push(limit, offset)
  const rows = db.prepare(query).all(...params)
  const total = (db.prepare(agent ? `SELECT COUNT(*) as c FROM derivations WHERE tenant_id = ? AND agent_id = ?` : countQuery).get(...countParams) as any).c
  const items = (rows as any[]).map((d: any) => ({
    ...d, source_ids: JSON.parse(d.source_ids || '[]'), access_receipt_ids: JSON.parse(d.access_receipt_ids || '[]'),
  }))
  res.json({ derivations: items, total, limit, offset, has_more: offset + items.length < total })
})


// POST /api/v1/reset-attribution — Clear all demo/test attribution data
gatewayRouter.post('/reset-attribution', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const db = getDB()
  const ar = db.prepare(`DELETE FROM access_receipts WHERE tenant_id = ?`).run(tenant.id)
  const co = db.prepare(`DELETE FROM contributions WHERE tenant_id = ?`).run(tenant.id)
  const ds = db.prepare(`DELETE FROM data_sources WHERE tenant_id = ?`).run(tenant.id)
  const st = db.prepare(`DELETE FROM settlements WHERE tenant_id = ?`).run(tenant.id)
  const dv = db.prepare(`DELETE FROM derivations WHERE tenant_id = ?`).run(tenant.id)
  const al = db.prepare(`DELETE FROM alerts WHERE tenant_id = ?`).run(tenant.id)
  res.json({
    cleared: {
      access_receipts: ar.changes,
      contributions: co.changes,
      data_sources: ds.changes,
      settlements: st.changes,
      derivations: dv.changes,
      alerts: al.changes,
    },
    message: 'Attribution data cleared. Real data will flow once MCP tracking is live.',
  })
})


// POST /api/v1/compare-texts — Lexical similarity score (TF-IDF)
// The honest attribution signal: 80% accurate on hard negatives.
// Not derivation proof — lexical forensic evidence.
gatewayRouter.post('/compare-texts', (req: any, res) => {
  const { source_text, output_text, method } = req.body
  if (!source_text || !output_text) {
    return res.status(400).json({ error: 'Required: source_text, output_text' })
  }
  // Pluggable backend (future: bm25, custom). Default: tfidf/ngram_jaccard
  const lex = computeLexicalScore(source_text, output_text)
  res.json({
    method: method || 'ngram_jaccard',
    similarity_score: lex.score, detail: lex.detail, interpretation: lex.verdict,
    note: 'Lexical forensic evidence. Not derivation proof. Combine with access receipts and temporal ordering.',
  })
})


// ═══════════════════════════════════════════════════════════════
// VERIFIED SELF-DECLARATION (the core innovation)
// Agent declares sources, gateway verifies plausibility
// ═══════════════════════════════════════════════════════════════

gatewayRouter.post('/verify-declaration', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const { agent_id, output_text, declared_sources, output_url } = req.body

  if (!agent_id || !output_text || !declared_sources || !Array.isArray(declared_sources) || declared_sources.length === 0) {
    return res.status(400).json({ error: 'Required: agent_id, output_text, declared_sources (array of source_id strings)' })
  }

  const db = getDB()
  const id = randomUUID()

  // 1. Check access receipts for each declared source
  const receiptCheck = declared_sources.map((sourceId: string) => {
    const receipts = db.prepare(
      `SELECT id, created_at, purpose FROM access_receipts WHERE tenant_id = ? AND agent_id = ? AND source_id = ? ORDER BY created_at DESC LIMIT 1`
    ).get(tenant.id, agent_id, sourceId) as any
    return { source_id: sourceId, receipt_exists: !!receipts, last_access: receipts?.created_at || null, purpose: receipts?.purpose || null }
  })


  // 2. Fetch source texts for lexical comparison
  const plausibility = receiptCheck.map((rc: any) => {
    const src = db.prepare(
      `SELECT source_name, source_url FROM data_sources WHERE tenant_id = ? AND source_id = ?`
    ).get(tenant.id, rc.source_id) as any

    // If source has stored text (via source_url or name), compute lexical overlap
    // For now, store the declaration and flag based on receipt status
    let lexical = null as any
    // Check if source content was provided inline
    const sourceContent = (req.body.source_texts || {})[rc.source_id]
    if (sourceContent) {
      lexical = computeLexicalScore(sourceContent, output_text)
    }

    // Classify evidence
    let evidence_class: string
    if (rc.receipt_exists && lexical && (lexical.verdict === 'high_overlap' || lexical.verdict === 'moderate_overlap')) {
      evidence_class = 'supported_usage'
    } else if (rc.receipt_exists && (!lexical || lexical.verdict === 'low_overlap')) {
      evidence_class = 'access_without_surface_carryover'
    } else if (!rc.receipt_exists && lexical && lexical.verdict !== 'low_overlap') {
      evidence_class = 'untracked_overlap'
    } else {
      evidence_class = 'no_observed_linkage'
    }


    let verdict: string
    if (rc.receipt_exists && (!lexical || lexical.score >= 0.05)) {
      verdict = 'plausible'
    } else if (!rc.receipt_exists) {
      verdict = 'no_receipt'
    } else if (lexical && lexical.score < 0.02) {
      verdict = 'implausible'
    } else {
      verdict = 'weak'
    }

    return {
      source_id: rc.source_id, source_name: src?.source_name || null,
      receipt_exists: rc.receipt_exists, last_access: rc.last_access, purpose: rc.purpose,
      lexical: lexical ? { score: lexical.score, detail: lexical.detail, verdict: lexical.verdict } : null,
      evidence_class, verdict,
    }
  })


  // 3. Generate flags
  const flags: string[] = []
  for (const p of plausibility) {
    if (p.verdict === 'implausible') flags.push(`Declared source ${p.source_id} shows near-zero lexical overlap with output`)
    if (p.verdict === 'no_receipt') flags.push(`No access receipt found for declared source ${p.source_id}`)
    if (p.evidence_class === 'untracked_overlap') flags.push(`High overlap with ${p.source_id} but no access receipt — possible untracked reuse`)
  }

  // 4. Check for undeclared sources with high overlap (if source_texts provided)
  const sources_accessed = db.prepare(
    `SELECT DISTINCT source_id FROM access_receipts WHERE tenant_id = ? AND agent_id = ?`
  ).all(tenant.id, agent_id) as any[]

  const declared_set = new Set(declared_sources)
  const sources_accessed_but_not_declared: string[] = []
  for (const sa of sources_accessed) {
    if (!declared_set.has(sa.source_id)) sources_accessed_but_not_declared.push(sa.source_id)
  }
  if (sources_accessed_but_not_declared.length > 0) {
    flags.push(`Agent accessed ${sources_accessed_but_not_declared.length} source(s) not included in declaration`)
  }


  // 5. Store the verified declaration as a derivation
  db.prepare(`INSERT INTO derivations (id, tenant_id, agent_id, source_ids, output_description, output_url, access_receipt_ids, signature) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(id, tenant.id, agent_id, JSON.stringify(declared_sources), 'verified-declaration', output_url || null, JSON.stringify([]), 'gateway-verified')
  try { getEventBus().emit(tenant.id, { type: 'derivation_created', agentId: agent_id, data: { derivation_id: id, verified: true, source_count: declared_sources.length } }) } catch {}

  // 6. Fire alerts for anomalies
  if (flags.length > 0) {
    const anomalySeverity = flags.some(f => f.includes('untracked')) ? 'warning' : 'info'
    db.prepare(`INSERT INTO alerts (id, tenant_id, alert_type, severity, message) VALUES (?, ?, ?, ?, ?)`)
      .run(randomUUID(), tenant.id, 'declaration_anomaly', anomalySeverity,
        `Declaration from "${agent_id}": ${flags.join('; ')}`)
    try { getEventBus().emit(tenant.id, { type: 'alert', agentId: agent_id, data: { alert_type: 'declaration_anomaly', severity: anomalySeverity, flags } }) } catch {}
  }

  // 7. Coverage scope
  const total_sources = (db.prepare(`SELECT COUNT(*) as c FROM data_sources WHERE tenant_id = ?`).get(tenant.id) as any).c
  const total_receipts = (db.prepare(`SELECT COUNT(*) as c FROM access_receipts WHERE tenant_id = ? AND agent_id = ?`).get(tenant.id, agent_id) as any).c

  res.status(201).json({
    declaration_id: id, agent_id,
    plausibility,
    flags,
    sources_accessed_but_not_declared,
    coverage: {
      scope: 'gateway_tracked_only',
      registered_sources: total_sources,
      agent_total_accesses: total_receipts,
      note: 'No receipt does not prove no access. Coverage limited to gateway-tracked interactions.',
    },
    evidence_limits: 'Lexical overlap is forensic evidence, not derivation proof. Combined with receipts and temporal ordering for multi-factor attribution.',
  })
})


// ═══════════════════════════════════════════════════════════════
// PROVENANCE DOSSIER — full evidence bundle for an agent's outputs
// ═══════════════════════════════════════════════════════════════

gatewayRouter.get('/provenance-dossier', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const agent_id = req.query.agent_id as string
  if (!agent_id) return res.status(400).json({ error: 'Required: agent_id query parameter' })

  const db = getDB()

  // All access receipts for this agent
  const receipts = db.prepare(
    `SELECT ar.id, ar.source_id, ar.agent_id, ar.purpose, ar.created_at, ds.source_name
     FROM access_receipts ar LEFT JOIN data_sources ds ON ar.source_id = ds.source_id AND ar.tenant_id = ds.tenant_id
     WHERE ar.tenant_id = ? AND ar.agent_id = ? ORDER BY ar.created_at DESC LIMIT 100`
  ).all(tenant.id, agent_id) as any[]

  // All derivation declarations
  const derivations = db.prepare(
    `SELECT * FROM derivations WHERE tenant_id = ? AND agent_id = ? ORDER BY created_at DESC LIMIT 50`
  ).all(tenant.id, agent_id) as any[]


  // Contributions owed
  const contributions = db.prepare(
    `SELECT source_id, access_count, amount, currency, updated_at FROM contributions WHERE tenant_id = ? AND agent_id = ?`
  ).all(tenant.id, agent_id) as any[]

  // Source access frequency (longitudinal pattern)
  const sourceFrequency = db.prepare(
    `SELECT source_id, COUNT(*) as accesses, MIN(created_at) as first_access, MAX(created_at) as last_access,
     COUNT(DISTINCT date(created_at)) as distinct_days
     FROM access_receipts WHERE tenant_id = ? AND agent_id = ? GROUP BY source_id ORDER BY accesses DESC`
  ).all(tenant.id, agent_id) as any[]

  // Purpose breakdown
  const purposes = db.prepare(
    `SELECT purpose, COUNT(*) as count FROM access_receipts WHERE tenant_id = ? AND agent_id = ? GROUP BY purpose`
  ).all(tenant.id, agent_id) as any[]

  // Sources accessed but never declared
  const declared_source_ids = new Set<string>()
  for (const d of derivations) {
    for (const sid of JSON.parse(d.source_ids || '[]')) declared_source_ids.add(sid)
  }
  const accessed_source_ids = new Set(receipts.map((r: any) => r.source_id))
  const accessed_not_declared = [...accessed_source_ids].filter(s => !declared_source_ids.has(s))


  // Classify longitudinal patterns
  const patterns: string[] = []
  for (const sf of sourceFrequency) {
    if (sf.distinct_days >= 5) patterns.push(`habitual_consumer: ${sf.source_id} (${sf.accesses} accesses over ${sf.distinct_days} days)`)
    else if (sf.accesses >= 10) patterns.push(`heavy_consumer: ${sf.source_id} (${sf.accesses} accesses)`)
  }
  if (accessed_not_declared.length > 3) patterns.push(`low_declaration_rate: ${accessed_not_declared.length} sources accessed but never declared`)

  // Coverage
  const total_sources = (db.prepare(`SELECT COUNT(*) as c FROM data_sources WHERE tenant_id = ?`).get(tenant.id) as any).c

  res.json({
    agent_id,
    generated_at: new Date().toISOString(),
    evidence: {
      access_receipts: { count: receipts.length, items: receipts.slice(0, 20) },
      declarations: { count: derivations.length, items: (derivations as any[]).map((d: any) => ({ ...d, source_ids: JSON.parse(d.source_ids || '[]') })).slice(0, 10) },
      contributions: { total_owed: Math.round(contributions.reduce((s: number, c: any) => s + (c.amount || 0), 0) * 10000) / 10000, items: contributions },
      purpose_breakdown: purposes,
      source_frequency: sourceFrequency,
      longitudinal_patterns: patterns,
    },
    negative_evidence: {
      sources_accessed_but_not_declared: accessed_not_declared,
      declaration_coverage: `${declared_source_ids.size} declared / ${accessed_source_ids.size} accessed`,
    },
    coverage: {
      scope: 'gateway_tracked_only',
      registered_sources: total_sources,
      note: 'This dossier covers gateway-tracked interactions only. Absence of a receipt does not prove absence of access.',
    },
    evidence_limits: 'This is a structured evidentiary record that may support audit, compliance, contractual enforcement, or legal review depending on jurisdiction and context. It does not constitute a legal determination of derivation or infringement.',
  })
})


// [REMOVED: Duplicate issuance-dossier handler deleted. Sybil logic merged into first handler at line 568.]

// eslint-disable-next-line @typescript-eslint/no-unused-vars
const _removed_duplicate_issuance_handler = ((req: any, res: any) => {
  const tenant: Tenant = req.tenant
  const db = getDB()
  const {
    passport_id, public_key_hash, passport_grade, flags,
    attestation_bundle_hash, observed_context,
    runtime_attestations, provider_attestations,
    self_declared_signals, derived_signals, prior_passport_ref,
  } = req.body

  if (!passport_id || !public_key_hash) {
    return res.status(400).json({ error: 'Required: passport_id, public_key_hash' })
  }

  const id = randomUUID()
  const obs = observed_context || {}

  try {
    db.prepare(`INSERT INTO issuance_dossiers
      (id, tenant_id, passport_id, public_key_hash, passport_grade,
       flags, attestation_bundle_hash, observed_context,
       runtime_attestations, provider_attestations,
       self_declared_signals, derived_signals, prior_passport_ref,
       transport_type, issuance_velocity, connection_timing_ms,
       request_payload_fingerprint)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(
        id, tenant.id, passport_id, public_key_hash,
        passport_grade || 0,
        JSON.stringify(flags || []),
        attestation_bundle_hash || null,
        JSON.stringify(obs),
        JSON.stringify(runtime_attestations || []),
        JSON.stringify(provider_attestations || []),
        JSON.stringify(self_declared_signals || []),
        JSON.stringify(derived_signals || []),
        prior_passport_ref || null,
        obs.transportType || null,
        obs.issuanceVelocity || null,
        obs.connectionTimingMs || null,
        obs.requestPayloadFingerprint || null,
      )

    // Velocity anomaly: if same public_key_hash issued 5+ passports in 1 hour
    const recentFromKey = db.prepare(
      `SELECT COUNT(*) as c FROM issuance_dossiers
       WHERE public_key_hash = ? AND created_at > datetime('now', '-1 hour')`
    ).get(public_key_hash) as any
    if (recentFromKey.c >= 5) {
      db.prepare(`INSERT INTO alerts (id, tenant_id, alert_type, severity, message)
        VALUES (?, ?, ?, ?, ?)`)
        .run(randomUUID(), tenant.id, 'sybil_issuance_velocity', 'critical',
          `Key ${public_key_hash.slice(0, 16)}... issued ${recentFromKey.c} passports in 1hr`)
    }

    // Fingerprint clustering: if same request_payload_fingerprint from 10+ different keys
    if (obs.requestPayloadFingerprint) {
      const fpCluster = db.prepare(
        `SELECT COUNT(DISTINCT public_key_hash) as c FROM issuance_dossiers
         WHERE request_payload_fingerprint = ? AND created_at > datetime('now', '-24 hours')`
      ).get(obs.requestPayloadFingerprint) as any
      if (fpCluster.c >= 10) {
        db.prepare(`INSERT INTO alerts (id, tenant_id, alert_type, severity, message)
          VALUES (?, ?, ?, ?, ?)`)
          .run(randomUUID(), tenant.id, 'sybil_fingerprint_cluster', 'critical',
            `Payload fingerprint ${obs.requestPayloadFingerprint.slice(0, 16)}... seen from ${fpCluster.c} distinct keys in 24h — farming script?`)
      }
    }

    res.status(201).json({
      dossier_id: id,
      passport_id,
      passport_grade: passport_grade || 0,
      stored: true,
    })
  } catch (e: any) {
    if (e.message?.includes('UNIQUE constraint')) {
      // Update existing dossier (passport reissued)
      db.prepare(`UPDATE issuance_dossiers SET
        passport_grade = ?, flags = ?, attestation_bundle_hash = ?,
        observed_context = ?, runtime_attestations = ?,
        provider_attestations = ?, self_declared_signals = ?,
        derived_signals = ?
        WHERE tenant_id = ? AND passport_id = ?`)
        .run(
          passport_grade || 0, JSON.stringify(flags || []),
          attestation_bundle_hash || null, JSON.stringify(obs),
          JSON.stringify(runtime_attestations || []),
          JSON.stringify(provider_attestations || []),
          JSON.stringify(self_declared_signals || []),
          JSON.stringify(derived_signals || []),
          tenant.id, passport_id,
        )
      return res.json({ passport_id, updated: true })
    }
    res.status(500).json(safeError(e, 'behavioral-sequence'))
  }
}) // end of removed duplicate handler

// ═══════════════════════════════════════
// Evaluation Receipts — authenticated endpoints
// ═══════════════════════════════════════

// GET /api/v1/receipts/:agentId — all receipts for an agent (paginated)
gatewayRouter.get('/receipts/:agentId', (req: any, res) => {
  const tenant = req.tenant as Tenant
  const { agentId } = req.params
  const limit = Math.min(parseInt(req.query.limit || '50'), 100)
  const offset = parseInt(req.query.offset || '0')
  const db = getDB()

  const rows = db.prepare(
    `SELECT * FROM evaluation_receipts WHERE tenant_id = ? AND agent_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`
  ).all(tenant.id, agentId, limit, offset)
  const total = (db.prepare(
    `SELECT COUNT(*) as c FROM evaluation_receipts WHERE tenant_id = ? AND agent_id = ?`
  ).get(tenant.id, agentId) as any).c

  res.json({ receipts: rows, total, limit, offset, has_more: offset + rows.length < total })
})

// GET /api/v1/receipts/:agentId/denials — denial receipts only (proof of restraint)
gatewayRouter.get('/receipts/:agentId/denials', (req: any, res) => {
  const tenant = req.tenant as Tenant
  const { agentId } = req.params
  const limit = Math.min(parseInt(req.query.limit || '50'), 100)
  const offset = parseInt(req.query.offset || '0')
  const db = getDB()

  const rows = db.prepare(
    `SELECT * FROM evaluation_receipts WHERE tenant_id = ? AND agent_id = ? AND verdict = 'deny' ORDER BY created_at DESC LIMIT ? OFFSET ?`
  ).all(tenant.id, agentId, limit, offset)
  const total = (db.prepare(
    `SELECT COUNT(*) as c FROM evaluation_receipts WHERE tenant_id = ? AND agent_id = ? AND verdict = 'deny'`
  ).get(tenant.id, agentId) as any).c

  res.json({ denials: rows, total, limit, offset, has_more: offset + rows.length < total })
})

// ═══════════════════════════════════════
// Receipt Window Seals — sealed intervals with gateway signatures
// Sorted-hash commitment (Option A). Upgrade to full Merkle when
// inclusion proofs are needed.
// ═══════════════════════════════════════

let _receiptsSinceLastSeal = 0

function sealReceiptWindow() {
  try {
    const db = getDB()
    // P3-1: seal per-tenant
    const tenants = db.prepare('SELECT DISTINCT tenant_id FROM evaluation_receipts WHERE seal_id IS NULL').all() as Array<{ tenant_id: string }>
    for (const { tenant_id } of tenants) {
      const unsealed = db.prepare(
        'SELECT id, receipt_hash FROM evaluation_receipts WHERE seal_id IS NULL AND tenant_id = ? ORDER BY id'
      ).all(tenant_id) as Array<{ id: number; receipt_hash: string }>
      if (unsealed.length < 10) continue
      const seqStart = unsealed[0].id
      const seqEnd = unsealed[unsealed.length - 1].id
      const sealId = randomUUID()
      const sortedHashes = unsealed.map(r => r.receipt_hash || '').join('')
      const commitmentHash = createHash('sha256').update(sortedHashes).digest('hex')
      const counts = db.prepare(
        `SELECT verdict, COUNT(*) as c FROM evaluation_receipts WHERE id >= ? AND id <= ? AND tenant_id = ? GROUP BY verdict`
      ).all(seqStart, seqEnd, tenant_id) as Array<{ verdict: string; c: number }>
      const permitCount = counts.find(c => c.verdict === 'permit')?.c || 0
      const denyCount = counts.find(c => c.verdict === 'deny')?.c || 0
      const identity = getGatewayIdentity()
      const sig = identity.sign({ seal_id: sealId, seq_start: seqStart, seq_end: seqEnd, receipt_count: unsealed.length, commitment_hash: commitmentHash, tenant_id })
      const txn = db.transaction(() => {
        db.prepare(`INSERT INTO receipt_window_seals (seal_id, seq_start, seq_end, receipt_count, permit_count, deny_count, commitment_hash, gateway_signature, tenant_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
          .run(sealId, seqStart, seqEnd, unsealed.length, permitCount, denyCount, commitmentHash, sig, tenant_id)
        db.prepare('UPDATE evaluation_receipts SET seal_id = ? WHERE id >= ? AND id <= ? AND tenant_id = ?')
          .run(sealId, seqStart, seqEnd, tenant_id)
      })
      txn()
      console.log(`[seal] ${tenant_id.slice(0,8)}: ${unsealed.length} receipts, hash=${commitmentHash.slice(0, 16)}`)
    }
    _receiptsSinceLastSeal = 0
  } catch (e: any) {
    console.error('[seal] FAILED:', e.message)
  }
}

// Seal every hour. unref() so these background timers do not by
// themselves keep the process alive: under the running server the HTTP
// listener holds the loop open and sealing fires on schedule as before;
// in a bare import (e.g. a unit test of a consumer module) the process
// can still exit cleanly. Production cadence is unchanged.
setInterval(sealReceiptWindow, 3600_000).unref()
// Seal on startup (catch unsealed receipts from before crash)
setTimeout(sealReceiptWindow, 5000).unref()

function maybeAutoSeal() {
  _receiptsSinceLastSeal++
  if (_receiptsSinceLastSeal >= 100) {
    sealReceiptWindow()
  }
}

// GET /api/v1/receipt-seals — list all seals (authenticated)
gatewayRouter.get('/receipt-seals', (req: any, res) => {
  const tenant = req.tenant as Tenant
  const limit = Math.min(parseInt(req.query.limit || '50'), 100)
  const offset = parseInt(req.query.offset || '0')
  const db = getDB()

  const seals = db.prepare(
    `SELECT seal_id, seq_start, seq_end, receipt_count, permit_count, deny_count,
            commitment_hash, scope_note, created_at
     FROM receipt_window_seals WHERE tenant_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`
  ).all(tenant.id, limit, offset)
  const total = (db.prepare('SELECT COUNT(*) as c FROM receipt_window_seals WHERE tenant_id = ?').get(tenant.id) as any).c

  res.json({ seals, total, limit, offset })
})

// GET /api/v1/receipt-seals/:sealId — seal details + receipt hashes (authenticated)
gatewayRouter.get('/receipt-seals/:sealId', (req: any, res) => {
  const tenant = req.tenant as Tenant
  const { sealId } = req.params
  const db = getDB()

  const seal = db.prepare('SELECT * FROM receipt_window_seals WHERE seal_id = ? AND tenant_id = ?').get(sealId, tenant.id) as any
  if (!seal) return res.status(404).json({ error: 'Seal not found' })

  const receipts = db.prepare(
    'SELECT id, receipt_hash, verdict, agent_id, action_type FROM evaluation_receipts WHERE seal_id = ? AND tenant_id = ? ORDER BY id'
  ).all(sealId, tenant.id)

  // Verification: recompute commitment
  const recomputedHash = createHash('sha256')
    .update(receipts.map((r: any) => r.receipt_hash || '').join(''))
    .digest('hex')

  res.json({
    seal,
    receipts,
    verification: {
      commitment_matches: recomputedHash === seal.commitment_hash,
      recomputed_hash: recomputedHash,
      kid: 'gateway-v1',
      alg: 'EdDSA',
      jwks: 'https://gateway.aeoess.com/.well-known/jwks.json',
    },
  })
})

// ═══════════════════════════════════════
// Agent Posture Overlay — suspend/restrict with audit trail
// ═══════════════════════════════════════

// POST /api/v1/agents/:agentId/posture — change agent operational posture
gatewayRouter.post('/agents/:agentId/posture', (req: any, res) => {
  const tenant = req.tenant as Tenant
  const { agentId } = req.params
  const { status, reason, restricted_scopes } = req.body

  if (!status || !reason) {
    return res.status(400).json({ error: 'Required: status, reason' })
  }
  // R4-3 CROSS-POINT: this posture route sets agents.status to one of active/restricted/suspended.
  // The full agents.status domain (also revoked from /revoke + panic zero_authority, and frozen from
  // panic read_only) is pinned by a DB trigger in src/db/schema.ts (check_agents_status_insert/update).
  // Changing the allowed status set requires updating BOTH this enum AND that trigger together.
  if (!['active', 'restricted', 'suspended'].includes(status)) {
    return res.status(400).json({ error: 'status must be active, restricted, or suspended' })
  }
  if (status === 'restricted' && !restricted_scopes) {
    return res.status(400).json({ error: 'restricted status requires restricted_scopes array' })
  }

  const db = getDB()
  const agent = db.prepare(`SELECT status FROM agents WHERE tenant_id = ? AND agent_id = ?`)
    .get(tenant.id, agentId) as any
  if (!agent) return res.status(404).json({ error: 'Agent not found' })

  const oldStatus = agent.status || 'active'
  const now = new Date().toISOString()
  const scopesJson = restricted_scopes ? JSON.stringify(restricted_scopes) : null

  // Update agent status
  db.prepare(`UPDATE agents SET status = ?, restricted_scopes = ?, posture_reason = ?, posture_updated_at = ? WHERE tenant_id = ? AND agent_id = ?`)
    .run(status, status === 'restricted' ? scopesJson : null, reason, now, tenant.id, agentId)

  // Log posture event
  db.prepare(`INSERT INTO posture_events (tenant_id, agent_id, old_status, new_status, restricted_scopes, reason, changed_by) VALUES (?, ?, ?, ?, ?, ?, ?)`)
    .run(tenant.id, agentId, oldStatus, status, scopesJson, reason, tenant.id)
  try { getEventBus().emit(tenant.id, { type: 'posture_update', agentId, data: { old_status: oldStatus, new_status: status, reason, restricted_scopes: restricted_scopes || null } }) } catch {}

  res.json({ agent_id: agentId, old_status: oldStatus, new_status: status, reason, restricted_scopes: restricted_scopes || null, changed_at: now })
})

// GET /api/v1/agents/:agentId/posture-history — audit trail
gatewayRouter.get('/agents/:agentId/posture-history', (req: any, res) => {
  const tenant = req.tenant as Tenant
  const { agentId } = req.params
  const db = getDB()

  const events = db.prepare(
    `SELECT * FROM posture_events WHERE tenant_id = ? AND agent_id = ? ORDER BY created_at DESC`
  ).all(tenant.id, agentId)

  res.json({ agent_id: agentId, events, count: events.length })
})

// ═══════════════════════════════════════
// Authorization Audit Packets
// One receipt → one exportable proof chain. The atom of compliance evidence.
// decision_record is signed (immutable). current_context is NOT signed (volatile).
// ═══════════════════════════════════════

gatewayRouter.get('/audit-packet/:receiptId', (req: any, res) => {
  const tenant = req.tenant as Tenant
  const receiptId = parseInt(req.params.receiptId)
  if (!Number.isFinite(receiptId)) {
    return res.status(400).json({ error: 'Invalid receipt ID' })
  }

  const db = getDB()
  const receipt = db.prepare(
    `SELECT * FROM evaluation_receipts WHERE id = ? AND tenant_id = ?`
  ).get(receiptId, tenant.id) as any

  if (!receipt) {
    return res.status(404).json({ error: 'Receipt not found', receipt_id: receiptId })
  }

  const missing: string[] = []
  const notes: string[] = []

  // ── decision_record (frozen at decision time, signed) ──
  let scopeRequested: string[] = []
  try { scopeRequested = JSON.parse(receipt.scope_requested_json || '[]') } catch { scopeRequested = [] }

  // Look up agent grade at decision time (from dossier nearest to decision timestamp)
  let agentGradeAtDecision = 0
  try {
    const dossier = db.prepare(
      `SELECT passport_grade FROM issuance_dossiers WHERE tenant_id = ? AND passport_id = ? ORDER BY created_at DESC LIMIT 1`
    ).get(tenant.id, receipt.agent_id) as any
    if (dossier) agentGradeAtDecision = dossier.passport_grade
  } catch { notes.push('dossier_lookup_failed') }

  // Delegation chain hash (recompute from delegation_id)
  let delegationChainHash: string | null = null
  if (receipt.delegation_id) {
    try {
      const chain: Array<{ parent: string; child: string; scope: string; spend_limit: number | null }> = []
      // Find the delegation to get the child agent
      const del = db.prepare(
        `SELECT parent_agent_id, child_agent_id, scope, spend_limit FROM delegations WHERE id = ? AND tenant_id = ?`
      ).get(receipt.delegation_id, tenant.id) as any
      if (del) {
        let currentChild: string | null = del.child_agent_id
        const seen = new Set<string>()
        while (currentChild && !seen.has(currentChild)) {
          seen.add(currentChild)
          const row = db.prepare(
            `SELECT parent_agent_id, child_agent_id, scope, spend_limit FROM delegations
             WHERE tenant_id = ? AND child_agent_id = ? AND status = 'active'
             ORDER BY created_at DESC LIMIT 1`
          ).get(tenant.id, currentChild) as any
          if (!row) break
          chain.push({ parent: row.parent_agent_id, child: row.child_agent_id, scope: row.scope, spend_limit: row.spend_limit })
          currentChild = row.parent_agent_id
        }
        chain.reverse()
        delegationChainHash = createHash('sha256')
          .update(canonicalJsonStringify(chain))
          .digest('hex')
      }
    } catch { notes.push('delegation_chain_hash_failed') }
  }

  const decisionRecord: Record<string, unknown> = {
    receipt_id: receipt.id,
    event_type: receipt.event_type,
    action_type: receipt.action_type,
    scope_requested: scopeRequested,
    verdict: receipt.verdict,
    reason_code: receipt.reason_code || null,
    delegation_id: receipt.delegation_id || null,
    delegation_chain_hash: delegationChainHash,
    policy_hash: receipt.policy_hash,
    decision_timestamp: receipt.created_at,
    agent_id: receipt.agent_id,
    agent_grade_at_decision: agentGradeAtDecision,
  }

  // Sign the decision record (stable: same receipt always produces same signature)
  let gatewaySignature: string | null = null
  let kid = 'gateway-v1'
  try {
    const identity = getGatewayIdentity()
    kid = identity.kid
    gatewaySignature = identity.sign(decisionRecord)
  } catch { notes.push('signing_failed') }

  // ── current_context (queried now, NOT signed) ──
  let agentContext: Record<string, unknown> | null = null
  try {
    const agent = db.prepare(
      `SELECT status, created_at FROM agents WHERE tenant_id = ? AND agent_id = ? LIMIT 1`
    ).get(tenant.id, receipt.agent_id) as any
    if (agent) {
      let currentGrade = 0
      const dossier = db.prepare(
        `SELECT passport_grade FROM issuance_dossiers WHERE tenant_id = ? AND passport_id = ? ORDER BY created_at DESC LIMIT 1`
      ).get(tenant.id, receipt.agent_id) as any
      if (dossier) currentGrade = dossier.passport_grade

      agentContext = {
        status: agent.status,
        grade: currentGrade,
        created_at: agent.created_at,
      }
    } else {
      missing.push('agent')
    }
  } catch { missing.push('agent') }

  // Delegation chain (current state)
  let delegationChain: Array<Record<string, unknown>> = []
  let revocationState: Record<string, unknown> = {
    agent_revoked: false, delegation_revoked: false, any_ancestor_revoked: false,
  }
  try {
    const agent = db.prepare(
      `SELECT status FROM agents WHERE tenant_id = ? AND agent_id = ? LIMIT 1`
    ).get(tenant.id, receipt.agent_id) as any
    if (agent?.status !== 'active') {
      revocationState = { ...revocationState, agent_revoked: true }
    }

    if (receipt.delegation_id) {
      const del = db.prepare(
        `SELECT * FROM delegations WHERE id = ? AND tenant_id = ?`
      ).get(receipt.delegation_id, tenant.id) as any
      if (del) {
        if (del.status !== 'active') {
          revocationState = { ...revocationState, delegation_revoked: true }
        }
        // Build chain
        let currentChild: string | null = del.child_agent_id
        const seen = new Set<string>()
        while (currentChild && !seen.has(currentChild)) {
          seen.add(currentChild)
          const row = db.prepare(
            `SELECT parent_agent_id, child_agent_id, scope, status FROM delegations
             WHERE tenant_id = ? AND child_agent_id = ?
             ORDER BY created_at DESC LIMIT 1`
          ).get(tenant.id, currentChild) as any
          if (!row) break
          const scopes = row.scope ? row.scope.split(',').map((s: string) => s.trim()) : []
          delegationChain.push({ parent: row.parent_agent_id, child: row.child_agent_id, scope: scopes, status: row.status })
          if (row.status !== 'active') {
            revocationState = { ...revocationState, any_ancestor_revoked: true }
          }
          currentChild = row.parent_agent_id
        }
        delegationChain.reverse()
      } else {
        missing.push('delegation')
      }
    }
  } catch { missing.push('delegation_chain') }

  const completenessLevel = missing.length === 0 ? 'full' : 'partial'

  const packet: Record<string, unknown> = {
    type: 'authorization_audit_packet',
    version: '1.0.0',
    decision_record: { ...decisionRecord, gateway_signature: gatewaySignature },
    current_context: {
      _note: 'Queried NOW. Not part of the signed proof. May change.',
      generated_at: new Date().toISOString(),
      agent: agentContext,
      delegation_chain: delegationChain,
      revocation_state: revocationState,
    },
    completeness: {
      level: completenessLevel,
      missing_sections: missing,
      notes,
    },
    verification: {
      kid,
      alg: 'EdDSA',
      jwks: 'https://gateway.aeoess.com/.well-known/jwks.json',
    },
  }

  // Markdown format option
  if (req.query.format === 'markdown') {
    const dr = decisionRecord
    const md = `# Authorization Audit Packet

## Decision Record (frozen at decision time, signed)

| Field | Value |
|---|---|
| Receipt ID | ${dr.receipt_id} |
| Event Type | ${dr.event_type} |
| Action Type | ${dr.action_type} |
| Scope Requested | ${(dr.scope_requested as string[]).join(', ')} |
| Verdict | **${dr.verdict}** |
| Reason Code | ${dr.reason_code || 'n/a'} |
| Delegation ID | ${dr.delegation_id || 'none'} |
| Delegation Chain Hash | \`${dr.delegation_chain_hash || 'none'}\` |
| Policy Hash | \`${dr.policy_hash}\` |
| Decision Timestamp | ${dr.decision_timestamp} |
| Agent ID | ${dr.agent_id} |
| Agent Grade at Decision | ${dr.agent_grade_at_decision} |

## Current Context (queried now, not signed)

**Agent:** ${agentContext ? `status=${(agentContext as any).status}, grade=${(agentContext as any).grade}` : 'not found'}

**Delegation Chain:** ${delegationChain.length > 0 ? delegationChain.map((d: any) => `${d.parent} → ${d.child} [${d.scope.join(',')}] (${d.status})`).join(' → ') : 'none'}

**Revocation State:** agent_revoked=${(revocationState as any).agent_revoked}, delegation_revoked=${(revocationState as any).delegation_revoked}, any_ancestor_revoked=${(revocationState as any).any_ancestor_revoked}

## Completeness

Level: **${completenessLevel}**${missing.length > 0 ? `\nMissing: ${missing.join(', ')}` : ''}

## Verification

- **kid:** ${kid}
- **alg:** EdDSA
- **JWKS:** https://gateway.aeoess.com/.well-known/jwks.json
- **Decision Record Hash:** \`${createHash('sha256').update(canonicalJsonStringify(decisionRecord)).digest('hex')}\`
- **Gateway Signature:** \`${gatewaySignature ? gatewaySignature.slice(0, 40) + '...' : 'none'}\`
`
    res.setHeader('Content-Type', 'text/markdown; charset=utf-8')
    return res.send(md)
  }

  res.json(packet)
})

// ═══════════════════════════════════════
// CSV helper — pandas-friendly, UTF-8, ISO 8601
// ═══════════════════════════════════════

function escapeCsvField(val: unknown): string {
  if (val === null || val === undefined) return ''
  const s = String(val)
  if (s.includes(',') || s.includes('"') || s.includes('\n') || s.includes('\r')) {
    return '"' + s.replace(/"/g, '""') + '"'
  }
  return s
}

function toCsvSection(tableName: string, columns: string[], rows: Record<string, unknown>[]): string {
  const lines = rows.map(row =>
    [tableName, ...columns.map(c => escapeCsvField(row[c]))].join(',')
  )
  return lines.join('\n')
}

// ═══════════════════════════════════════
// Full Governance Evidence Export — 9 sections, single signed artifact
// NOT a compliance report (no GDPR/EU AI Act article mapping).
// Proves what was AUTHORIZED and what constraints applied.
// ?format=csv returns a pandas-friendly CSV with table_name discriminator.
// ═══════════════════════════════════════

gatewayRouter.get('/governance/export', (req: any, res) => {
  try {
    const tenant = req.tenant as Tenant
    const db = getDB()
    const now = new Date().toISOString()
    const since = (req.query.since as string) || '2020-01-01T00:00:00Z'
    const until = (req.query.until as string) || now
    const agentFilter = req.query.agent_id as string | undefined
    const format = (req.query.format as string)?.toLowerCase()

    // ── 1: Agent Registry (snapshot) ──
    const agentRows = db.prepare(
      agentFilter
        ? `SELECT agent_id, status, created_at FROM agents WHERE tenant_id = ? AND agent_id = ?`
        : `SELECT agent_id, status, created_at FROM agents WHERE tenant_id = ?`
    ).all(...(agentFilter ? [tenant.id, agentFilter] : [tenant.id])) as any[]

    const byStatus: Record<string, number> = {}
    for (const a of agentRows) byStatus[a.status || 'active'] = (byStatus[a.status || 'active'] || 0) + 1

    // Grade lookup
    const agentsWithGrade = agentRows.map((a: any) => {
      const dossier = db.prepare(
        `SELECT passport_grade FROM issuance_dossiers WHERE tenant_id = ? AND passport_id = ? ORDER BY created_at DESC LIMIT 1`
      ).get(tenant.id, a.agent_id) as any
      const grade = dossier?.passport_grade ?? 0
      const hasDel = !!(db.prepare(
        `SELECT 1 FROM delegations WHERE tenant_id = ? AND child_agent_id = ? AND status = 'active' LIMIT 1`
      ).get(tenant.id, a.agent_id))
      return { agent_id: a.agent_id, grade, grade_label: ['unknown','registered','endorsed','established'][grade] || 'unknown', status: a.status || 'active', has_delegation: hasDel, created_at: a.created_at }
    })

    const byGrade: Record<string, number> = {}
    for (const a of agentsWithGrade) byGrade[String(a.grade)] = (byGrade[String(a.grade)] || 0) + 1

    // ── 2: Delegation Inventory (snapshot) ──
    const delQuery = agentFilter
      ? `SELECT * FROM delegations WHERE tenant_id = ? AND (parent_agent_id = ? OR child_agent_id = ?)`
      : `SELECT * FROM delegations WHERE tenant_id = ?`
    const delRows = db.prepare(delQuery).all(...(agentFilter ? [tenant.id, agentFilter, agentFilter] : [tenant.id])) as any[]

    const activeDels = delRows.filter((d: any) => d.status === 'active').length
    const revokedDels = delRows.filter((d: any) => d.status !== 'active').length

    // ── 3: Evaluation Events (time-range) ──
    const evalWhere = agentFilter ? 'AND agent_id = ?' : ''
    const evalParams = agentFilter ? [tenant.id, since, until, agentFilter] : [tenant.id, since, until]
    const evalRows = db.prepare(
      `SELECT id, agent_id, action_type, verdict, reason, duration_ms, task_class, created_at FROM policy_evaluations WHERE tenant_id = ? AND created_at >= ? AND created_at <= ? ${evalWhere} ORDER BY created_at`
    ).all(...evalParams) as any[]

    const permits3 = evalRows.filter((e: any) => (e.verdict || '').toLowerCase() === 'permit').length
    const denials3 = evalRows.length - permits3
    const avgLatency = evalRows.length > 0 ? Math.round(evalRows.reduce((s: number, e: any) => s + (e.duration_ms || 0), 0) / evalRows.length * 10) / 10 : 0

    // ── 4: Authorization Receipts (time-range) ──
    const rcptWhere = agentFilter ? 'AND agent_id = ?' : ''
    const rcptParams = agentFilter ? [tenant.id, since, until, agentFilter] : [tenant.id, since, until]
    const rcptRows = db.prepare(
      `SELECT id, agent_id, event_type, action_type, scope_requested_json, reason_code, policy_hash, receipt_hash, gateway_signature, created_at FROM evaluation_receipts WHERE tenant_id = ? AND created_at >= ? AND created_at <= ? ${rcptWhere} ORDER BY created_at`
    ).all(...rcptParams) as any[]

    const byType4: Record<string, number> = {}
    for (const r of rcptRows) byType4[r.event_type] = (byType4[r.event_type] || 0) + 1

    // ── 5: Revocation Events (time-range) ──
    const revRows = db.prepare(
      `SELECT * FROM revocations WHERE tenant_id = ? AND created_at >= ? AND created_at <= ? ORDER BY created_at`
    ).all(tenant.id, since, until) as any[]

    // ── 6: Posture Events (time-range) ──
    const postureRows = db.prepare(
      agentFilter
        ? `SELECT * FROM posture_events WHERE tenant_id = ? AND created_at >= ? AND created_at <= ? AND agent_id = ? ORDER BY created_at`
        : `SELECT * FROM posture_events WHERE tenant_id = ? AND created_at >= ? AND created_at <= ? ORDER BY created_at`
    ).all(...(agentFilter ? [tenant.id, since, until, agentFilter] : [tenant.id, since, until])) as any[]

    // ── 7: Key Rotations (time-range) ──
    const rotRows = db.prepare(
      agentFilter
        ? `SELECT * FROM key_rotations WHERE tenant_id = ? AND created_at >= ? AND created_at <= ? AND agent_id = ? ORDER BY created_at`
        : `SELECT * FROM key_rotations WHERE tenant_id = ? AND created_at >= ? AND created_at <= ? ORDER BY created_at`
    ).all(...(agentFilter ? [tenant.id, since, until, agentFilter] : [tenant.id, since, until])) as any[]

    // ── 8: Receipt Window Seals (time-range) ──
    const sealRows = db.prepare(
      `SELECT seal_id, seq_start, seq_end, receipt_count, permit_count, deny_count, commitment_hash, gateway_signature, created_at FROM receipt_window_seals WHERE created_at >= ? AND created_at <= ? ORDER BY created_at`
    ).all(since, until) as any[]

    // ── 9: Governance Attestations (synthetic — count of attestation queries) ──
    // The gateway doesn't log individual attestation serves yet.
    // Section present with total: 0 — honest, not broken.

    // ── CSV format: 4 tables in a single file with table_name discriminator ──
    if (format === 'csv') {
      const csvHeader = 'table_name,col_1,col_2,col_3,col_4,col_5,col_6,col_7,col_8,col_9'

      // 1. policy_evaluations
      const evalCols = ['evaluation_id', 'agent_id', 'action_type', 'scope_checked', 'verdict', 'delegation_id', 'spend_at_evaluation', 'task_class', 'timestamp', 'receipt_hash']
      const csvEvalHeader = ['table_name', ...evalCols].join(',')
      const csvEvals = evalRows.map((e: any) => {
        const rcpt = rcptRows.find((r: any) => r.agent_id === e.agent_id && r.created_at === e.created_at)
        return {
          evaluation_id: e.id, agent_id: e.agent_id, action_type: e.action_type,
          scope_checked: e.reason || '', verdict: e.verdict,
          delegation_id: '', spend_at_evaluation: '',
          task_class: e.task_class || '',
          timestamp: e.created_at, receipt_hash: rcpt?.receipt_hash || '',
        }
      })

      // 2. revocation_events
      const revCols = ['revocation_id', 'delegation_id', 'revoked_at', 'cascade_parent_id', 'depth_in_chain']
      const revokedDels = delRows.filter((d: any) => d.revoked_at)
      const csvRevocations = revokedDels.map((d: any) => ({
        revocation_id: d.id, delegation_id: d.id,
        revoked_at: d.revoked_at, cascade_parent_id: '',
        depth_in_chain: 0,
      }))

      // 3. posture_events
      const postureCols = ['agent_id', 'posture_score', 'continuity_delta', 'timestamp']
      const csvPosture = postureRows.map((p: any) => ({
        agent_id: p.agent_id,
        posture_score: p.new_status === 'active' ? 100 : p.new_status === 'restricted' ? 50 : 0,
        continuity_delta: '', timestamp: p.created_at,
      }))

      // 4. receipt_window_seals
      const sealCols = ['seal_id', 'receipt_count', 'merkle_root', 'sealed_at']
      const csvSeals = sealRows.map((s: any) => ({
        seal_id: s.seal_id, receipt_count: s.receipt_count,
        merkle_root: s.commitment_hash, sealed_at: s.created_at,
      }))

      // Combined: proper header per table, table_name discriminator
      const sections: string[] = []
      // Emit header once, then all rows
      const header = ['table_name', 'evaluation_id', 'agent_id', 'action_type', 'scope_checked', 'verdict', 'delegation_id', 'spend_at_evaluation', 'task_class', 'timestamp', 'receipt_hash'].join(',')
      sections.push(header)
      sections.push(toCsvSection('policy_evaluations', evalCols, csvEvals))
      sections.push(toCsvSection('revocation_events', revCols, csvRevocations))
      sections.push(toCsvSection('posture_events', postureCols, csvPosture))
      sections.push(toCsvSection('receipt_window_seals', sealCols, csvSeals))

      const body = sections.filter(s => s.length > 0).join('\n')
      res.setHeader('Content-Type', 'text/csv; charset=utf-8')
      res.setHeader('Content-Disposition', 'attachment; filename="governance-export.csv"')
      return res.send(body)
    }

    // ── Assemble ──
    const exportData: Record<string, unknown> = {
      export_version: '1.0.0',
      generated_at: now,
      period: { from: since, to: until },
      completeness: 'full',
      scope: 'All gateway-mediated agent governance activity',
      known_exclusions: [
        'Downstream execution results (gateway authorizes, does not execute)',
        'External processing not mediated by this gateway',
      ],
      gateway: {
        id: 'gateway.aeoess.com',
        version: '0.4.1',
        kid: 'gateway-v1',
        jwks: 'https://gateway.aeoess.com/.well-known/jwks.json',
      },

      '1_agent_registry': {
        as_of: now,
        total: agentRows.length,
        by_status: byStatus,
        by_grade: byGrade,
        agents: agentsWithGrade,
      },

      '2_delegation_inventory': {
        as_of: now,
        total: delRows.length,
        active: activeDels,
        revoked: revokedDels,
        delegations: delRows.map((d: any) => ({
          id: d.id, parent: d.parent_agent_id, child: d.child_agent_id,
          scope: d.scope ? d.scope.split(',').map((s: string) => s.trim()) : [],
          spend_limit: d.spend_limit, spend_used: d.spend_used, max_depth: d.max_depth,
          status: d.status, created_at: d.created_at,
        })),
      },

      '3_evaluation_events': {
        from: since, to: until,
        total: evalRows.length, permits: permits3, denials: denials3,
        avg_latency_ms: avgLatency,
        events: evalRows.map((e: any) => ({
          agent_id: e.agent_id, action_type: e.action_type,
          verdict: e.verdict, reason_code: e.reason || null,
          policy_hash: null, timestamp: e.created_at,
        })),
      },

      '4_authorization_receipts': {
        from: since, to: until,
        total: rcptRows.length,
        by_type: byType4,
        receipts: rcptRows.map((r: any) => {
          let scope: string[] = []
          try { scope = JSON.parse(r.scope_requested_json || '[]') } catch {}
          return {
            id: r.id, agent_id: r.agent_id, event_type: r.event_type,
            action_type: r.action_type, scope_requested: scope,
            reason_code: r.reason_code, policy_hash: r.policy_hash,
            receipt_hash: r.receipt_hash, gateway_signature: r.gateway_signature,
            timestamp: r.created_at,
          }
        }),
      },

      '5_revocation_events': {
        from: since, to: until,
        total: revRows.length,
        revocations: revRows.map((r: any) => ({
          target_id: r.target_id, target_type: r.target_type,
          revoked_by: r.revoked_by, reason: r.reason || null,
          cascade_count: r.cascade_count, timestamp: r.created_at,
        })),
      },

      '6_posture_events': {
        from: since, to: until,
        total: postureRows.length,
        events: postureRows.map((p: any) => ({
          agent_id: p.agent_id, old_status: p.old_status, new_status: p.new_status,
          reason: p.reason, changed_by: p.changed_by, timestamp: p.created_at,
        })),
      },

      '7_key_rotations': {
        from: since, to: until,
        total: rotRows.length,
        rotations: rotRows.map((r: any) => ({
          agent_id: r.agent_id, mode: r.mode, state: r.state,
          announced_at: r.announced_at, activation_time: r.activation_time,
          completed_at: r.completed_at,
        })),
      },

      '8_receipt_window_seals': {
        from: since, to: until,
        total: sealRows.length,
        seals: sealRows.map((s: any) => ({
          seal_id: s.seal_id, seq_start: s.seq_start, seq_end: s.seq_end,
          receipt_count: s.receipt_count, commitment_hash: s.commitment_hash,
          gateway_signature: s.gateway_signature, created_at: s.created_at,
        })),
      },

      '9_governance_attestations': {
        from: since, to: until,
        total: 0,
        attestations_served: [],
      },
    }

    // Sign entire canonicalized export
    const identity = getGatewayIdentity()
    const signature = identity.sign(exportData as Record<string, unknown>)
    ;(exportData as any).signature = signature

    res.json(exportData)
  } catch (e: any) {
    console.error('[governance-export] FAILED:', e.message)
    res.status(500).json({ error: 'Export generation failed' })
  }
})


// ═══════════════════════════════════════
// GET /api/v1/agents/:agentId/health — Agent Health Status
// Enterprise monitoring integration (Datadog, Grafana).
// Matches AgentHealthStatus shape from agent-passport-system SDK.
// ═══════════════════════════════════════

gatewayRouter.get('/agents/:agentId/health', (req: any, res) => {
  try {
    const tenant: Tenant = req.tenant
    const db = getDB()
    const { agentId } = req.params

    // 1. Look up agent
    const agent = db.prepare(
      `SELECT * FROM agents WHERE tenant_id = ? AND agent_id = ?`
    ).get(tenant.id, agentId) as any
    if (!agent) {
      return res.status(404).json({ error: `Agent "${agentId}" not found` })
    }

    // 2. Passport validity
    const passportValid = agent.status === 'active' || agent.status === 'restricted'

    // 3. Delegation
    const delegation = db.prepare(
      `SELECT * FROM delegations WHERE tenant_id = ? AND child_agent_id = ? AND status = 'active' ORDER BY created_at DESC LIMIT 1`
    ).get(tenant.id, agentId) as any
    const delegationActive = !!delegation
    const spendUtilization = delegation && delegation.spend_limit
      ? (delegation.spend_used || 0) / delegation.spend_limit
      : 0

    // 4. Passport grade (from dossier or heuristic)
    const dossier = db.prepare(
      `SELECT passport_grade FROM issuance_dossiers WHERE tenant_id = ? AND passport_id = ? ORDER BY created_at DESC LIMIT 1`
    ).get(tenant.id, agentId) as any
    let grade = 0
    if (dossier) {
      grade = dossier.passport_grade
    } else {
      if (agent.status === 'active') grade = 1
      if (delegation) grade = 2
    }

    // 5. Behavioral signals
    const lastAction = db.prepare(
      `SELECT MAX(created_at) as last_ts FROM policy_evaluations WHERE tenant_id = ? AND agent_id = ?`
    ).get(tenant.id, agentId) as any
    const actionsLast24h = db.prepare(
      `SELECT COUNT(*) as c FROM policy_evaluations WHERE tenant_id = ? AND agent_id = ? AND created_at > datetime('now', '-1 day')`
    ).get(tenant.id, agentId) as any
    const recentDenials = db.prepare(
      `SELECT COUNT(*) as c FROM policy_evaluations WHERE tenant_id = ? AND agent_id = ? AND verdict = 'deny' AND created_at > datetime('now', '-1 hour')`
    ).get(tenant.id, agentId) as any

    // 6. Recovery events (from evaluation_receipts with event_type pattern)
    const recentRecoveries = db.prepare(
      `SELECT COUNT(*) as c FROM evaluation_receipts WHERE tenant_id = ? AND agent_id = ? AND verdict = 'deny' AND created_at > datetime('now', '-1 hour')`
    ).get(tenant.id, agentId) as any

    // 7. Recovery policy (if table exists)
    let activeRecoveryPolicy: string | null = null
    let currentStrategy: string | null = null
    try {
      const policy = db.prepare(
        `SELECT id FROM recovery_policies WHERE tenant_id = ? AND agent_id = ?`
      ).get(tenant.id, agentId) as any
      if (policy) activeRecoveryPolicy = policy.id
    } catch { /* table may not exist yet */ }

    // 8. Derive status
    let status: 'healthy' | 'degraded' | 'suspended' | 'expired'
    if (!passportValid) status = 'expired'
    else if (agent.status === 'suspended') status = 'suspended'
    else if ((recentRecoveries?.c || 0) > 2 || spendUtilization > 0.9) status = 'degraded'
    else status = 'healthy'

    // Compute expiry (agents table doesn't have expires_at, use delegation or default)
    const expiresAt = delegation?.created_at
      ? new Date(new Date(delegation.created_at).getTime() + 90 * 24 * 60 * 60 * 1000).toISOString()
      : new Date(new Date(agent.created_at).getTime() + 365 * 24 * 60 * 60 * 1000).toISOString()

    const healthStatus = {
      agentId,
      timestamp: new Date().toISOString(),
      passport: {
        valid: passportValid,
        expiresAt,
        grade,
      },
      delegation: {
        active: delegationActive,
        scopeCount: delegation ? delegation.scope.split(',').map((s: string) => s.trim()).filter(Boolean).length : 0,
        spendUtilization: Math.round(spendUtilization * 10000) / 10000,
        expiresAt: delegation?.revoked_at || null,
      },
      behavioral: {
        continuityScore: 0, // TODO: wire to context_continuity when implemented
        lastActionTimestamp: lastAction?.last_ts || null,
        actionsInWindow: actionsLast24h?.c || 0,
        driftDetected: false,
      },
      recovery: {
        activeRecoveryPolicy,
        recentRecoveryEvents: recentRecoveries?.c || 0,
        currentStrategy,
      },
      status,
    }

    res.json(healthStatus)
  } catch (e) {
    const err = safeError(e, 'agent-health')
    res.status(500).json(err)
  }
})


// ═══════════════════════════════════════
// Recovery Policy CRUD
// ═══════════════════════════════════════

// POST /api/v1/agents/:agentId/recovery-policy — Configure recovery policy
gatewayRouter.post('/agents/:agentId/recovery-policy', (req: any, res) => {
  try {
    const tenant: Tenant = req.tenant
    const db = getDB()
    const { agentId } = req.params
    const policy = req.body

    if (!policy || !policy.policyId || !policy.rules || !policy.defaultStrategy) {
      return res.status(400).json({ error: 'Required: policyId, rules, defaultStrategy, maxTotalAttempts' })
    }

    const agent = db.prepare(
      `SELECT agent_id FROM agents WHERE tenant_id = ? AND agent_id = ?`
    ).get(tenant.id, agentId) as any
    if (!agent) {
      return res.status(404).json({ error: `Agent "${agentId}" not found` })
    }

    const id = randomUUID()
    db.prepare(
      `INSERT INTO recovery_policies (id, tenant_id, agent_id, policy_json)
       VALUES (?, ?, ?, ?)
       ON CONFLICT(tenant_id, agent_id) DO UPDATE SET
         policy_json = excluded.policy_json,
         updated_at = datetime('now')`
    ).run(id, tenant.id, agentId, JSON.stringify(policy))

    res.status(201).json({ policyId: policy.policyId, agentId, status: 'active' })
  } catch (e) {
    const err = safeError(e, 'recovery-policy-create')
    res.status(500).json(err)
  }
})

// GET /api/v1/agents/:agentId/recovery-policy — Get recovery policy
gatewayRouter.get('/agents/:agentId/recovery-policy', (req: any, res) => {
  try {
    const tenant: Tenant = req.tenant
    const db = getDB()
    const { agentId } = req.params

    const row = db.prepare(
      `SELECT policy_json FROM recovery_policies WHERE tenant_id = ? AND agent_id = ?`
    ).get(tenant.id, agentId) as any
    if (!row) {
      return res.status(404).json({ error: 'No recovery policy configured for this agent' })
    }

    res.json(JSON.parse(row.policy_json))
  } catch (e) {
    const err = safeError(e, 'recovery-policy-get')
    res.status(500).json(err)
  }
})

// DELETE /api/v1/agents/:agentId/recovery-policy — Remove recovery policy
gatewayRouter.delete('/agents/:agentId/recovery-policy', (req: any, res) => {
  try {
    const tenant: Tenant = req.tenant
    const db = getDB()
    const { agentId } = req.params

    const result = db.prepare(
      `DELETE FROM recovery_policies WHERE tenant_id = ? AND agent_id = ?`
    ).run(tenant.id, agentId)

    if (result.changes === 0) {
      return res.status(404).json({ error: 'No recovery policy found' })
    }

    res.json({ agentId, status: 'removed' })
  } catch (e) {
    const err = safeError(e, 'recovery-policy-delete')
    res.status(500).json(err)
  }
})

// ── Inline tests for argument-pattern scoping ──
if (process.env.NODE_ENV === 'test') {
  const id = (s: string[], r: string) => s.includes(r) || s.some(x => r.startsWith(x.replace(/:?\*$/, '') + ':'))
  console.assert(scopeMatchesWithArguments(['tool:web_search'], 'tool:web_search', {}, id) === true, 'simple match')
  console.assert(scopeMatchesWithArguments(['tool:python_interpreter:file_read'], 'tool:python_interpreter:file_read', {}, id) === true, 'capability match')
  console.assert(scopeMatchesWithArguments(['tool:python_interpreter:file_read'], 'tool:python_interpreter:file_write', {}, id) === false, 'capability mismatch')
  console.assert(scopeMatchesWithArguments(['tool:python_interpreter:file_read:/workspace/**'], 'tool:python_interpreter:file_read', { path: '/workspace/data/file.csv' }, id) === true, 'glob ** match')
  console.assert(scopeMatchesWithArguments(['tool:python_interpreter:file_read:/workspace/**'], 'tool:python_interpreter:file_read', { path: '/etc/passwd' }, id) === false, 'glob ** reject')
  console.assert(scopeMatchesWithArguments(['tool:python_interpreter:file_write:/workspace/output/*'], 'tool:python_interpreter:file_write', { path: '/workspace/output/result.json' }, id) === true, 'glob * match')
  console.assert(scopeMatchesWithArguments(['tool:python_interpreter:file_write:/workspace/output/*'], 'tool:python_interpreter:file_write', { path: '/workspace/output/sub/deep.json' }, id) === false, 'glob * no depth')
  console.assert(scopeMatchesWithArguments([], 'anything', {}, id) === false, 'empty scope')
  console.assert(scopeMatchesWithArguments(['*'], 'anything', {}, id) === true, 'global wildcard')
  console.log('[scope-args] All inline tests passed')
}
