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
 * acts for. The independence check in /sign compares it (and approver_id)
 * against registered identities on the owner side, so an approver
 * registered under the owner's principal is the owner, whatever
 * approver_id it uses. That check compares registered ids and keys; it
 * does not prove that separate humans hold the keys.
 *
 * Who writes this table: the tenant admin. The gateway authenticates the
 * tenant and isolates tenants; it never decides who inside a tenant may
 * approve. The HTTP routes (approvers-router.ts) accept only an unexpired
 * tenant_admin key of the same tenant; a runtime key gets 403, so a leaked
 * runtime key cannot register its own keypair as an approver. There is no
 * update route: authority is set once at registration and cannot be
 * widened, only revoked.
 *
 * Authority ceiling (validateAuthority): at most MAX_AUTHORITY_ENTRIES
 * entries, each in the action-class grammar approverHoldsAuthority
 * (policy.ts) matches on:
 *   <class>      exact action class, segments joined by ':'  (payments:refund)
 *   <head>       a head segment alone, covers <head>:*        (payments)
 *   <head>:*     head glob                                    (payments:*)
 * where a segment is [a-z0-9][a-z0-9_.-]*. A bare '*', or any other
 * wildcard ('*:*', ':*', 'payments:refund:*'), is refused.
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

/** Most authority entries one approver can hold. */
export const MAX_AUTHORITY_ENTRIES = 32

const SEGMENT = '[a-z0-9][a-z0-9_.-]*'
const AUTHORITY_CLASS = new RegExp(`^${SEGMENT}(?::${SEGMENT})*$`)
const AUTHORITY_HEAD_GLOB = new RegExp(`^${SEGMENT}:\\*$`)

export class AuthorityError extends Error {
  constructor(message: string, readonly code: 'authority_invalid' | 'authority_wildcard' | 'authority_too_many') {
    super(message)
  }
}

/**
 * Validate and normalize (trim, lower-case) an approver authority list.
 * Throws AuthorityError on: not a non-empty array, more than
 * MAX_AUTHORITY_ENTRIES entries, a bare '*' or root wildcard, or an entry
 * outside the grammar in the header comment.
 */
export function validateAuthority(authority: unknown): string[] {
  if (!Array.isArray(authority) || authority.length === 0) {
    throw new AuthorityError('authority must be a non-empty list of action-class entries', 'authority_invalid')
  }
  if (authority.length > MAX_AUTHORITY_ENTRIES) {
    throw new AuthorityError(`authority may hold at most ${MAX_AUTHORITY_ENTRIES} entries`, 'authority_too_many')
  }
  return authority.map((raw) => {
    if (typeof raw !== 'string') {
      throw new AuthorityError('authority entries must be strings', 'authority_invalid')
    }
    const e = raw.trim().toLowerCase()
    if (AUTHORITY_HEAD_GLOB.test(e)) return e
    if (e.includes('*')) {
      throw new AuthorityError(`wildcard authority "${raw}" is not grantable; list action classes or <head>:* explicitly`, 'authority_wildcard')
    }
    if (!AUTHORITY_CLASS.test(e)) {
      throw new AuthorityError(`authority entry "${raw}" is not an action class, a head segment or <head>:*`, 'authority_invalid')
    }
    return e
  })
}

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
  const authority = validateAuthority(opts.authority)
  getDB().prepare(`
    INSERT INTO approval_approvers (
      tenant_id, approver_id, public_key, authority, principal_id,
      key_class, office_id, status, registered_by, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)
  `).run(
    opts.tenantId, opts.approverId, pub, JSON.stringify(authority),
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

/** Every registry entry of one tenant, active and revoked. */
export function listApprovers(tenantId: string): ApproverRecord[] {
  initApprovalTables()
  const rows = getDB().prepare(
    `SELECT * FROM approval_approvers WHERE tenant_id = ? ORDER BY created_at ASC`
  ).all(tenantId) as Array<Omit<ApproverRecord, 'authority'> & { authority: string }>
  return rows.map(parseRow)
}

function parseRow(row: Omit<ApproverRecord, 'authority'> & { authority: string }): ApproverRecord {
  let authority: string[] = []
  try { const v = JSON.parse(row.authority); authority = Array.isArray(v) ? v.map(String) : [] } catch { authority = [] }
  return { ...row, authority }
}

/** Active registry entry for (tenant, approver_id), or undefined. */
export function getActiveApprover(tenantId: string, approverId: string): ApproverRecord | undefined {
  initApprovalTables()
  const row = getDB().prepare(
    `SELECT * FROM approval_approvers WHERE tenant_id = ? AND approver_id = ? AND status = 'active'`
  ).get(tenantId, approverId) as (Omit<ApproverRecord, 'authority'> & { authority: string }) | undefined
  if (!row) return undefined
  return parseRow(row)
}
