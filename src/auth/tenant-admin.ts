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
 *   - issued only by POST /auth/tenant-admin/issue (auth-router.ts), which
 *     needs the account owner's email and password. Ordinary login, signup, GitHub OAuth and
 *     runtime rotate/regenerate never mint one, and no API key can.
 *   - expires TENANT_ADMIN_TTL_MS after issuance. authenticateKey refuses
 *     it after that. Nothing extends expires_at; a new one needs the
 *     password again.
 *   - an admin row without a valid expiry is refused at authentication.
 *   - authenticates only on approver register/list/revoke and GET
 *     /api/v1/account (TENANT_ADMIN_ROUTES in api-keys.ts). Every other
 *     route, approval open/sign/decide and runtime rotate/regenerate
 *     included, answers 403 tenant_admin_scope, so an admin key cannot mint
 *     a runtime key.
 *   - runtime rotate/regenerate (rotateRuntimeKeys) revoke and mint runtime
 *     keys only and leave tenant_admin keys alone.
 *   - password reset revokes every key of the tenant, tenant_admin included
 *     (revokeAllApiKeysForTenant in email-password.ts).
 */

import { createHash, randomBytes, randomUUID } from 'node:crypto'
import { getDB } from '../db/schema.js'

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
 * the issuance route in auth-router.ts.
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
