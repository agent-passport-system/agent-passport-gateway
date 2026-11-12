// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// delegation_chain_hash, computed one way for every surface that emits it.
//
// The signed governance_attestation (server.ts) and the decision record (enforce.ts) both carry
// delegation_chain_hash. They used two different canonicalizers: the attestation kept null-valued
// keys and the decision record dropped them, so any chain with a link that has no spend limit got
// two different hashes for the same chain. This module is the single implementation. It follows
// the SDK canonicalize() (aps-canonical-json): sorted object keys, null and undefined object values
// omitted, array elements kept as they are. Spec: governance-attestation-schema.md §2.3 (erratum 1).

import { createHash } from 'node:crypto'
import type Database from 'better-sqlite3'

export interface ChainLink { parent: string; child: string; scope: string; spend_limit: number | null }

export function canonicalChainJson(v: unknown): string {
  if (v === null || v === undefined) return 'null'
  if (typeof v !== 'object') return JSON.stringify(v)
  if (Array.isArray(v)) return '[' + v.map(canonicalChainJson).join(',') + ']'
  const obj = v as Record<string, unknown>
  const keys = Object.keys(obj).sort().filter((k) => obj[k] !== null && obj[k] !== undefined)
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalChainJson(obj[k])).join(',') + '}'
}

export function chainHash(chain: ChainLink[]): string {
  return createHash('sha256').update(canonicalChainJson(chain)).digest('hex')
}

/** The active delegation chain for an agent, root first. Empty when the agent holds no active delegation. */
export function resolveDelegationChain(db: Database.Database, tenantId: string, agentId: string): ChainLink[] {
  const chain: ChainLink[] = []
  let currentChild: string | null = agentId
  const seen = new Set<string>()
  const stmt = db.prepare(
    `SELECT parent_agent_id, child_agent_id, scope, spend_limit FROM delegations
     WHERE tenant_id = ? AND child_agent_id = ? AND status = 'active'
     ORDER BY created_at DESC LIMIT 1`,
  )
  while (currentChild && !seen.has(currentChild)) {
    seen.add(currentChild)
    const row = stmt.get(tenantId, currentChild) as
      | { parent_agent_id: string; child_agent_id: string; scope: string; spend_limit: number | null }
      | undefined
    if (!row) break
    chain.push({ parent: row.parent_agent_id, child: row.child_agent_id, scope: row.scope, spend_limit: row.spend_limit })
    currentChild = row.parent_agent_id
  }
  return chain.reverse()
}

export function computeDelegationChainHash(db: Database.Database, tenantId: string, agentId: string): string {
  return chainHash(resolveDelegationChain(db, tenantId, agentId))
}
