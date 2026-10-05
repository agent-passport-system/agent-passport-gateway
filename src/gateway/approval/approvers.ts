// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * G-C3 Scoped Human Approval - approver registry.
 *
 * The approver principal, its signing key and its granted authority come
 * from here, never from a /sign request body. A tenant API key proves only
 * "this is tenant X"; it does not prove which human approved. The registry
 * binds approver_id -> (Ed25519 public key, authority globs, principal_id),
 * and /sign accepts a signature only if it verifies under the registered key.
 *
 * principal_id is the owner relationship: the person or entity the approver
 * acts for. Separation of powers compares it (and approver_id) against the
 * agent owner, so an approver registered under the owner's principal is the
 * owner, whatever approver_id it uses.
 *
 * DESIGN DECISION (open, for Tima): there is deliberately no tenant-facing
 * route that writes this table. If the tenant API key could register
 * approvers, the requester could register its own keypair as an "outside"
 * approver and the P4 alias attack would come back one step removed.
 * Provisioning is operator-side (registerApprover called from an operator
 * path). Until a provisioning path is chosen, /sign fails closed with
 * approver_not_registered for every approver.
 */

import { getDB } from '../../db/schema.js'
import { initApprovalTables } from './store.js'

export interface ApproverRecord {
  tenant_id: string
  approver_id: string
  public_key: string
  authority: string[]
  principal_id: string
  key_class: string
  office_id: string | null
  status: 'active' | 'revoked'
  registered_by: string
  created_at: string
  revoked_at: string | null
}

const HEX64 = /^[0-9a-f]{64}$/

export function registerApprover(opts: {
  tenantId: string
  approverId: string
  publicKey: string
  authority: string[]
  principalId: string
  keyClass?: string
  officeId?: string | null
  registeredBy: string
}): ApproverRecord {
  initApprovalTables()
  const pub = String(opts.publicKey || '').toLowerCase()
  if (!HEX64.test(pub)) throw new Error('publicKey must be a 32-byte Ed25519 key as 64 hex chars')
  if (!opts.approverId) throw new Error('approverId required')
  if (!opts.principalId) throw new Error('principalId required')
  if (!opts.registeredBy) throw new Error('registeredBy required')
  if (!Array.isArray(opts.authority) || opts.authority.length === 0) {
    throw new Error('authority must be a non-empty list of action-class patterns')
  }
  getDB().prepare(`
    INSERT INTO approval_approvers (
      tenant_id, approver_id, public_key, authority, principal_id,
      key_class, office_id, status, registered_by, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)
  `).run(
    opts.tenantId, opts.approverId, pub, JSON.stringify(opts.authority.map(String)),
    opts.principalId, opts.keyClass || 'approver', opts.officeId ?? null,
    opts.registeredBy, new Date().toISOString(),
  )
  return getActiveApprover(opts.tenantId, opts.approverId)!
}

export function revokeApprover(tenantId: string, approverId: string): boolean {
  initApprovalTables()
  const r = getDB().prepare(`
    UPDATE approval_approvers SET status = 'revoked', revoked_at = ?
    WHERE tenant_id = ? AND approver_id = ? AND status = 'active'
  `).run(new Date().toISOString(), tenantId, approverId)
  return r.changes > 0
}

/** Active registry entry for (tenant, approver_id), or undefined. */
export function getActiveApprover(tenantId: string, approverId: string): ApproverRecord | undefined {
  initApprovalTables()
  const row = getDB().prepare(
    `SELECT * FROM approval_approvers WHERE tenant_id = ? AND approver_id = ? AND status = 'active'`
  ).get(tenantId, approverId) as (Omit<ApproverRecord, 'authority'> & { authority: string }) | undefined
  if (!row) return undefined
  let authority: string[] = []
  try { const v = JSON.parse(row.authority); authority = Array.isArray(v) ? v.map(String) : [] } catch { authority = [] }
  return { ...row, authority }
}
