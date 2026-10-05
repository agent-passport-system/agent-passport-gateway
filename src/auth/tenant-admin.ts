// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Tenant administration credential (api_keys.key_class = 'tenant_admin').
 *
 * The tenant admin is the trust root for who inside a tenant may approve:
 * the gateway authenticates the tenant and keeps tenants apart, and the
 * tenant admin registers the tenant's approvers (/api/v1/approvers). The
 * gateway never decides that on its own.
 *
 * Lifecycle:
 *   - issued only by POST /auth/tenant-admin/issue, which needs the account
 *     owner's email and password. Ordinary login, signup, GitHub OAuth and
 *     runtime rotate/regenerate never mint one, and no API key can.
 *   - expires TENANT_ADMIN_TTL_MS after issuance. authenticateKey refuses
 *     it after that. Nothing extends expires_at; a new one needs the
 *     password again.
 *   - runtime rotate/regenerate (rotateRuntimeKeys) revoke and mint runtime
 *     keys only and leave tenant_admin keys alone.
 *   - password reset revokes every key of the tenant, tenant_admin included
 *     (revokeAllApiKeysForTenant in email-password.ts).
 */

import { Router } from 'express'
import { createHash, randomBytes, randomUUID } from 'node:crypto'
import { RateLimiterMemory } from 'rate-limiter-flexible'
import { getDB } from '../db/schema.js'
import {
  isValidEmail, normalizeEmail, findTenantByEmail, verifyPassword, burnTime,
} from './email-password.js'

/** Fixed lifetime of a tenant_admin key. The codebase has no session TTL
 *  convention for API keys, so this is the 15-minute default. */
export const TENANT_ADMIN_TTL_MS = 15 * 60 * 1000

function newRawKey(): { rawKey: string; keyHash: string; keyPrefix: string } {
  const rawKey = `aps_live_${randomBytes(32).toString('hex')}`
  return {
    rawKey,
    keyHash: createHash('sha256').update(rawKey).digest('hex'),
    keyPrefix: rawKey.slice(0, 12),
  }
}

/**
 * Mint a tenant_admin key that expires TENANT_ADMIN_TTL_MS from now.
 * Callers must have checked the account password first; the only one is
 * the issuance route below.
 */
export function issueTenantAdminKey(tenantId: string, nowMs = Date.now()): {
  apiKey: string; keyId: string; expiresAt: string
} {
  const { rawKey, keyHash, keyPrefix } = newRawKey()
  const keyId = randomUUID()
  const expiresAt = new Date(nowMs + TENANT_ADMIN_TTL_MS).toISOString()
  getDB().prepare(`
    INSERT INTO api_keys (id, tenant_id, key_hash, key_prefix, name, key_class, expires_at)
    VALUES (?, ?, ?, ?, ?, 'tenant_admin', ?)
  `).run(keyId, tenantId, keyHash, keyPrefix, `tenant-admin-${nowMs}`, expiresAt)
  return { apiKey: rawKey, keyId, expiresAt }
}

/**
 * Runtime key rotation: revoke every active runtime key of the tenant and
 * mint one new runtime key. tenant_admin keys are neither revoked nor
 * minted here. Used by /api/v1/account/rotate-key and regenerate-key.
 */
export function rotateRuntimeKeys(tenantId: string, name: string): {
  apiKey: string; keyPrefix: string; revoked: number
} {
  const db = getDB()
  const { rawKey, keyHash, keyPrefix } = newRawKey()
  const revoked = db.transaction(() => {
    const r = db.prepare(`
      UPDATE api_keys SET revoked_at = datetime('now')
      WHERE tenant_id = ? AND revoked_at IS NULL AND key_class = 'runtime'
    `).run(tenantId)
    db.prepare(`
      INSERT INTO api_keys (id, tenant_id, key_hash, key_prefix, name, key_class)
      VALUES (?, ?, ?, ?, ?, 'runtime')
    `).run(randomUUID(), tenantId, keyHash, keyPrefix, name)
    return r.changes
  })()
  return { apiKey: rawKey, keyPrefix, revoked }
}

// Same budget as POST /auth/email/login: 10 attempts per 15 min per IP.
const tenantAdminIssueLimiter = new RateLimiterMemory({
  points: 10,
  duration: 900,
  keyPrefix: 'tenant_admin_issue',
})

export const tenantAdminRouter = Router()

// POST /auth/tenant-admin/issue — explicit admin-issuance action.
// Body: { email, password } of the account owner. Not authenticated by an
// API key on purpose: a runtime key (or an expiring admin key) cannot mint
// or renew an admin key. Failure answers match POST /auth/email/login.
tenantAdminRouter.post('/auth/tenant-admin/issue', async (req, res) => {
  try {
    await tenantAdminIssueLimiter.consume(req.ip || 'unknown')
  } catch {
    return res.status(429).json({ error: 'Too many attempts, try again later.' })
  }

  const { email: rawEmail, password } = req.body || {}
  if (!rawEmail || typeof rawEmail !== 'string' || !isValidEmail(rawEmail)
      || typeof password !== 'string' || password.length === 0) {
    await burnTime()
    return res.status(401).json({ error: 'Invalid email or password' })
  }

  const tenant = findTenantByEmail(normalizeEmail(rawEmail))
  if (!tenant || !tenant.password_hash) {
    await burnTime()
    return res.status(401).json({ error: 'Invalid email or password' })
  }
  if (!(await verifyPassword(password, tenant.password_hash))) {
    return res.status(401).json({ error: 'Invalid email or password' })
  }
  if (tenant.status !== 'active') {
    return res.status(403).json({ error: 'Account is not active. Contact signal@aeoess.com' })
  }

  const issued = issueTenantAdminKey(tenant.id)
  return res.status(201).json({
    message: 'Tenant admin key issued. It expires at expires_at and cannot be renewed; issue a new one with the password.',
    tenant_id: tenant.id,
    api_key: issued.apiKey,
    key_class: 'tenant_admin',
    expires_at: issued.expiresAt,
    ttl_seconds: TENANT_ADMIN_TTL_MS / 1000,
  })
})
