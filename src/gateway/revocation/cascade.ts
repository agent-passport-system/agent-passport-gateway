// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Cascade preview: blast-radius before a revoke.
 *
 * Before an operator commits a revoke, compute who and what it would touch, so
 * the choice is informed: revoke-now, schedule, freeze-first, or approval-only.
 *
 * Three blast-radius arms, each from a distinct, already-built source:
 *
 *  1. Delegation tree (forward descendants). The gateway is the store of record
 *     for the delegation graph (the SDK's cascade/getDescendants are MOVED
 *     no-ops in alpha.3). We walk the `delegations` table by parent_agent_id to
 *     find children, recursively, with a cycle guard. This is the reverse of
 *     the ancestor walk in enforce.ts, lifted into a shared descendant walk.
 *
 *  2. Entity cluster (lineage). getClusterRisk widens the radius to co-clustered
 *     passports (same owner / runtime), so a revoke that should also catch
 *     Sybil siblings is surfaced.
 *
 *  3. Data derivation (SDK). When the caller supplies a derivation receipt
 *     store and signer, evaluateRevocationImpact (SDK) lists every downstream
 *     artifact and its obligation. The gateway does not reimplement this; it
 *     consumes the SDK primitive. Without a store, this arm falls back to the
 *     access-receipt consumer count (the prior gateway behavior).
 *
 * Preview is read-only. It changes nothing; it returns a CascadeRevocationResult
 * shaped summary plus the recommended action options.
 */

import { getDB } from '../../db/schema.js'
import { getClusterRisk, type ClusterRisk } from '../lineage.js'
import { evaluateRevocationImpact } from 'agent-passport-system'

export type RevokeTargetType = 'agent' | 'delegation' | 'data_source'
export type CascadeAction = 'revoke_now' | 'schedule' | 'freeze_first' | 'approval_only'

export interface DelegationNode {
  delegationId: string
  parent: string
  child: string
  scope: string[]
  status: string
  depth: number
}

export interface CascadePreview {
  tenantId: string
  targetType: RevokeTargetType
  targetId: string
  /** Forward delegation-tree descendants that would be reached. */
  affectedDelegations: DelegationNode[]
  /** Distinct agents in the blast radius (target + descendants + cluster). */
  affectedAgents: string[]
  /** Entity-cluster widening from lineage (co-owner / co-runtime passports). */
  cluster: ClusterRisk
  /** Active delegations among the affected set (live authority that would drop). */
  activeWorkflows: number
  /** Pending approvals that reference the target (best-effort, table-guarded). */
  pendingApprovals: number
  /** Production processes: active wallets in the radius that move value. */
  productionProcesses: number
  /** Data-derivation obligations, if the SDK arm ran; else a fallback count. */
  dataObligations: {
    source: 'sdk' | 'access_receipt_fallback'
    totalAffected: number
    obligationId?: string
  } | null
  /** Total items the revoke would touch (CascadeRevocationResult.totalRevoked). */
  totalRevoked: number
  /** Deepest delegation chain reached (CascadeRevocationResult.chainDepth). */
  chainDepth: number
  /** Recommended action options for the operator. */
  recommendedActions: CascadeAction[]
  generatedAt: string
}

/** Optional data-derivation context. When present, the SDK arm runs. */
export interface DerivationContext {
  // Loosely typed to avoid importing the SDK's unexported receipt type; the
  // SDK function validates the store shape itself.
  receiptStore: Map<string, any>
  privateKey: string
}

const MAX_DEPTH = 32

/**
 * Walk the delegation tree forward from a root agent, collecting descendants.
 * Cycle-guarded by a seen-set on (parent->child) edges and a depth cap.
 */
export function walkDescendants(tenantId: string, rootAgentId: string): DelegationNode[] {
  const db = getDB()
  const out: DelegationNode[] = []
  const seenEdges = new Set<string>()
  const queue: Array<{ agentId: string; depth: number }> = [{ agentId: rootAgentId, depth: 0 }]
  const seenAgents = new Set<string>([rootAgentId])

  while (queue.length > 0) {
    const { agentId, depth } = queue.shift()!
    if (depth >= MAX_DEPTH) continue

    const rows = db.prepare(
      `SELECT id, parent_agent_id, child_agent_id, scope, status
         FROM delegations
        WHERE tenant_id = ? AND parent_agent_id = ?`,
    ).all(tenantId, agentId) as any[]

    for (const row of rows) {
      const edgeKey = `${row.parent_agent_id}->${row.child_agent_id}:${row.id}`
      if (seenEdges.has(edgeKey)) continue
      seenEdges.add(edgeKey)

      const scopes = row.scope ? String(row.scope).split(',').map((s: string) => s.trim()).filter(Boolean) : []
      out.push({
        delegationId: row.id,
        parent: row.parent_agent_id,
        child: row.child_agent_id,
        scope: scopes,
        status: row.status,
        depth: depth + 1,
      })

      if (!seenAgents.has(row.child_agent_id)) {
        seenAgents.add(row.child_agent_id)
        queue.push({ agentId: row.child_agent_id, depth: depth + 1 })
      }
    }
  }

  return out
}

function countPendingApprovals(tenantId: string, targetId: string): number {
  const db = getDB()
  // The approval tables self-create on first use of the approval router; guard
  // with a table-existence check so preview never throws before that.
  const tbl = db.prepare(
    `SELECT name FROM sqlite_master WHERE type='table' AND name='approval_requests'`,
  ).get() as { name?: string } | undefined
  if (!tbl?.name) return 0
  // approval_requests links to the agent through agent_id (store.ts); there is
  // no target column. No catch here: a query error used to be swallowed into 0,
  // which hid a reference to a column that never existed.
  // Expiry is swept lazily by the approval router, so a past-due row can still
  // read 'pending'; it is not counted.
  const row = db.prepare(
    `SELECT COUNT(*) AS c FROM approval_requests
      WHERE tenant_id = ? AND status = 'pending' AND agent_id = ? AND expires_at > ?`,
  ).get(tenantId, targetId, new Date().toISOString()) as { c: number }
  return row.c
}

/**
 * Build a cascade preview for a prospective revoke. Pure read; mutates nothing.
 */
export function previewCascade(opts: {
  tenantId: string
  targetType: RevokeTargetType
  targetId: string
  derivation?: DerivationContext
}): CascadePreview {
  const { tenantId, targetType, targetId } = opts
  const db = getDB()

  let affectedDelegations: DelegationNode[] = []
  let affectedAgents: string[] = []
  let cluster: ClusterRisk = { clusterId: null, clusterSize: 1, risk: 'low', matchedLinks: [] }
  let dataObligations: CascadePreview['dataObligations'] = null

  if (targetType === 'agent') {
    affectedDelegations = walkDescendants(tenantId, targetId)
    const agentSet = new Set<string>([targetId])
    for (const d of affectedDelegations) agentSet.add(d.child)

    // Arm 2: lineage entity-cluster widening.
    try {
      cluster = getClusterRisk(tenantId, targetId)
    } catch { /* lineage optional; default low cluster */ }

    affectedAgents = [...agentSet]
  } else if (targetType === 'delegation') {
    const del = db.prepare(
      `SELECT id, parent_agent_id, child_agent_id, scope, status FROM delegations WHERE tenant_id = ? AND id = ?`,
    ).get(tenantId, targetId) as any
    if (del) {
      const scopes = del.scope ? String(del.scope).split(',').map((s: string) => s.trim()).filter(Boolean) : []
      affectedDelegations = [
        { delegationId: del.id, parent: del.parent_agent_id, child: del.child_agent_id, scope: scopes, status: del.status, depth: 1 },
        // Forward descendants under the delegation's child.
        ...walkDescendants(tenantId, del.child_agent_id),
      ]
      const agentSet = new Set<string>([del.child_agent_id])
      for (const d of affectedDelegations) agentSet.add(d.child)
      affectedAgents = [...agentSet]
    }
  } else if (targetType === 'data_source') {
    // Arm 3: data-derivation blast-radius. Prefer the SDK primitive; fall back
    // to the access-receipt consumer count when no derivation store is supplied.
    if (opts.derivation) {
      try {
        const obligation = evaluateRevocationImpact({
          sourceId: targetId,
          receiptStore: opts.derivation.receiptStore,
          privateKey: opts.derivation.privateKey,
        })
        dataObligations = {
          source: 'sdk',
          totalAffected: obligation.totalAffected,
          obligationId: obligation.obligationId,
        }
      } catch {
        dataObligations = dataSourceFallback(tenantId, targetId)
      }
    } else {
      dataObligations = dataSourceFallback(tenantId, targetId)
    }
    const consumers = db.prepare(
      `SELECT DISTINCT agent_id FROM access_receipts WHERE tenant_id = ? AND source_id = ?`,
    ).all(tenantId, targetId) as any[]
    affectedAgents = consumers.map((c) => c.agent_id)
  }

  // Active workflows: live (active-status) delegations in the radius.
  const activeWorkflows = affectedDelegations.filter((d) => d.status === 'active').length

  // Production processes: active wallets among affected agents (value movers).
  let productionProcesses = 0
  if (affectedAgents.length > 0) {
    const placeholders = affectedAgents.map(() => '?').join(',')
    const row = db.prepare(
      `SELECT COUNT(*) AS c FROM agent_wallets
        WHERE tenant_id = ? AND status = 'active' AND agent_id IN (${placeholders})`,
    ).get(tenantId, ...affectedAgents) as { c: number }
    productionProcesses = row.c
  }

  const pendingApprovals = countPendingApprovals(tenantId, targetId)

  const chainDepth = affectedDelegations.reduce((max, d) => Math.max(max, d.depth), 0)
  // totalRevoked: target itself + every reached delegation + data-affected items.
  const dataCount = dataObligations?.totalAffected ?? 0
  const totalRevoked = 1 + affectedDelegations.length + dataCount

  const recommendedActions = recommend({
    cluster,
    activeWorkflows,
    pendingApprovals,
    productionProcesses,
    totalRevoked,
  })

  return {
    tenantId,
    targetType,
    targetId,
    affectedDelegations,
    affectedAgents,
    cluster,
    activeWorkflows,
    pendingApprovals,
    productionProcesses,
    dataObligations,
    totalRevoked,
    chainDepth,
    recommendedActions,
    generatedAt: new Date().toISOString(),
  }
}

function dataSourceFallback(tenantId: string, sourceId: string): NonNullable<CascadePreview['dataObligations']> {
  const db = getDB()
  const row = db.prepare(
    `SELECT COUNT(DISTINCT agent_id) AS c FROM access_receipts WHERE tenant_id = ? AND source_id = ?`,
  ).get(tenantId, sourceId) as { c: number }
  return { source: 'access_receipt_fallback', totalAffected: row.c }
}

/**
 * Map blast-radius signals to recommended action options. revoke_now is always
 * available; the larger or riskier the radius, the more the recommendation
 * leans toward freeze_first (stop cheaply) and approval_only (quorum gate).
 */
function recommend(signals: {
  cluster: ClusterRisk
  activeWorkflows: number
  pendingApprovals: number
  productionProcesses: number
  totalRevoked: number
}): CascadeAction[] {
  const actions = new Set<CascadeAction>(['revoke_now'])

  // Live authority or value movers in the radius: stopping cheaply first is wise.
  if (signals.activeWorkflows > 0 || signals.productionProcesses > 0) {
    actions.add('freeze_first')
  }
  // Pending approvals tied to the target: let them drain or be scheduled.
  if (signals.pendingApprovals > 0) {
    actions.add('schedule')
  }
  // Wide or high-risk cluster: gate behind quorum approval before a broad revoke.
  if (signals.cluster.risk === 'high' || signals.cluster.clusterSize > 3 || signals.totalRevoked > 10) {
    actions.add('approval_only')
    actions.add('freeze_first')
  }

  return [...actions]
}
