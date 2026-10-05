// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * G-C3 Scoped Human Approval - approver management routes.
 *
 *   POST /approvers                       - register an approver
 *   GET  /approvers                       - list the tenant's approvers
 *   POST /approvers/:approver_id/revoke   - revoke an approver
 *
 * Every route needs an unexpired tenant_admin key (requireTenantAdmin; the
 * expiry is enforced in authenticateKey). A runtime key gets 403
 * tenant_admin_required. Reads and writes are scoped to req.tenant.id, so
 * the admin of tenant A cannot see or change tenant B's approvers.
 *
 * There is no update route. Authority is validated against the ceiling in
 * approvers.ts (validateAuthority) at registration and cannot be widened
 * afterwards, only revoked.
 */

import { Router } from 'express'
import { requireTenantAdmin, type Tenant } from '../../auth/api-keys.js'
import {
  registerApprover, revokeApprover, listApprovers, getActiveApprover,
  AuthorityError, type ApproverRecord,
} from './approvers.js'

export const approverAdminRouter = Router()

// Path-scoped so the check never runs for other /api/v1 routes.
approverAdminRouter.use('/approvers', requireTenantAdmin)

const MAX_ID_LEN = 128

function idField(v: unknown): string | null {
  return typeof v === 'string' && v.trim().length > 0 && v.length <= MAX_ID_LEN ? v.trim() : null
}

function view(a: ApproverRecord) {
  return {
    approver_id: a.approver_id, public_key: a.public_key, authority: a.authority,
    principal_id: a.principal_id, office_id: a.office_id, status: a.status,
    registered_by: a.registered_by, created_at: a.created_at, revoked_at: a.revoked_at,
  }
}

approverAdminRouter.post('/approvers', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const { approver_id, public_key, authority, principal_id, office_id } = req.body || {}
  const approverId = idField(approver_id)
  const principalId = idField(principal_id)
  if (!approverId || !principalId || typeof public_key !== 'string') {
    return res.status(400).json({
      error: 'Required: approver_id, public_key, authority, principal_id', code: 'invalid_approver',
    })
  }
  if (office_id !== undefined && office_id !== null && !idField(office_id)) {
    return res.status(400).json({ error: 'office_id must be a non-empty string', code: 'invalid_approver' })
  }
  try {
    const rec = registerApprover({
      tenantId: tenant.id, approverId, publicKey: public_key, authority, principalId,
      officeId: office_id ?? null, registeredBy: `tenant_admin:${tenant.key_id ?? 'unknown'}`,
    })
    return res.status(201).json(view(rec))
  } catch (e: any) {
    if (e instanceof AuthorityError) {
      return res.status(400).json({ error: e.message, code: e.code })
    }
    const msg = String(e?.message || '')
    if (msg.includes('UNIQUE') || msg.includes('PRIMARY')) {
      return res.status(409).json({
        error: 'approver_id or public_key is already registered for this tenant', code: 'approver_exists',
      })
    }
    return res.status(400).json({ error: msg || 'Invalid approver', code: 'invalid_approver' })
  }
})

approverAdminRouter.get('/approvers', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const approvers = listApprovers(tenant.id).map(view)
  res.json({ approvers, total: approvers.length })
})

approverAdminRouter.post('/approvers/:approver_id/revoke', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const id = String(req.params.approver_id)
  if (!getActiveApprover(tenant.id, id)) {
    return res.status(404).json({ error: 'No active approver with this id for the tenant' })
  }
  revokeApprover(tenant.id, id)
  res.json({ approver_id: id, status: 'revoked' })
})
