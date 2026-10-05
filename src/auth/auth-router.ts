// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Credential and account routes: password login, tenant_admin issuance,
 * password reset, account read, and runtime key rotate/regenerate.
 *
 *   POST /auth/email/login                - password → new runtime key
 *   POST /auth/tenant-admin/issue         - password → tenant_admin key (15 min)
 *   POST /auth/email/forgot               - send a reset link (always 200)
 *   POST /auth/email/reset                - reset token → new password, revoke every key
 *   GET  /api/v1/account                  - account summary (authMiddleware)
 *   POST /api/v1/account/rotate-key       - runtime keys only (authMiddleware)
 *   POST /api/v1/account/regenerate-key   - runtime keys only (authMiddleware)
 *
 * Moved out of server.ts so tests can mount the same handlers over HTTP.
 * server.ts mounts one instance at the same paths. The mailer is a
 * parameter so tests can count what is sent; production passes nothing and
 * gets sendEmail from notifications/email.ts.
 *
 * Rate limiters are per router instance. server.ts creates one instance, so
 * the budgets are the same as when these handlers lived in server.ts.
 */

import { Router } from 'express'
import { RateLimiterMemory } from 'rate-limiter-flexible'
import { getDB, PLAN_LIMITS } from '../db/schema.js'
import { authMiddleware } from './api-keys.js'
import {
  validatePassword, isValidEmail, normalizeEmail,
  hashPassword, verifyPassword, burnTime,
  findTenantByEmail, setTenantPassword,
  issueApiKey, revokeAllApiKeysForTenant,
  createPasswordResetToken, consumePasswordResetToken,
} from './email-password.js'
import { issueTenantAdminKey, rotateRuntimeKeys, TENANT_ADMIN_TTL_MS } from './tenant-admin.js'
import { getEventBus } from '../gateway/events.js'
import {
  sendEmail as defaultSendEmail, passwordResetEmail, passwordChangedEmail,
  tenantAdminIssuedEmail, type EmailOptions,
} from '../notifications/email.js'

export interface AuthRouterOptions {
  /** Defaults to notifications/email.ts sendEmail. */
  sendEmail?: (opts: EmailOptions) => Promise<unknown>
  /** Origin of the portal that hosts the reset page. */
  appOrigin?: string
}

export function createAuthRouter(opts: AuthRouterOptions = {}): Router {
  const sendEmail = opts.sendEmail ?? defaultSendEmail
  const APP_ORIGIN = opts.appOrigin ?? (process.env.APP_ORIGIN || 'https://aeoess.com')
  const router = Router()

  const emailAuthLoginLimiter = new RateLimiterMemory({
    points: 10,
    duration: 900, // 10 attempts per 15 min per IP
    keyPrefix: 'email_auth_login',
  })

  // Same budget as POST /auth/email/login: 10 attempts per 15 min per IP.
  const tenantAdminIssueLimiter = new RateLimiterMemory({
    points: 10,
    duration: 900,
    keyPrefix: 'tenant_admin_issue',
  })

  const emailAuthForgotLimiter = new RateLimiterMemory({
    points: 5,
    duration: 3600,
    keyPrefix: 'email_auth_forgot',
  })

  const emailAuthResetLimiter = new RateLimiterMemory({
    points: 10,
    duration: 3600,
    keyPrefix: 'email_auth_reset',
  })

  // POST /auth/email/login — verify password, issue new runtime API key.
  // Never a tenant_admin key: that has its own explicit issuance action,
  // POST /auth/tenant-admin/issue below.
  router.post('/auth/email/login', async (req, res) => {
    try {
      await emailAuthLoginLimiter.consume(req.ip || 'unknown')
    } catch {
      return res.status(429).json({ error: 'Too many login attempts, try again later.' })
    }

    const { email: rawEmail, password } = req.body || {}
    if (!rawEmail || typeof rawEmail !== 'string' || !isValidEmail(rawEmail)) {
      // Don't leak whether the email is valid-format; still burn time.
      await burnTime()
      return res.status(401).json({ error: 'Invalid email or password' })
    }
    if (typeof password !== 'string' || password.length === 0) {
      await burnTime()
      return res.status(401).json({ error: 'Invalid email or password' })
    }

    const email = normalizeEmail(rawEmail)
    const tenant = findTenantByEmail(email)

    // Constant-time on unknown-email path: still run a bcrypt compare so
    // attackers can't distinguish "no such user" from "wrong password" by
    // response timing.
    if (!tenant || !tenant.password_hash) {
      await burnTime()
      return res.status(401).json({ error: 'Invalid email or password' })
    }

    const ok = await verifyPassword(password, tenant.password_hash)
    if (!ok) {
      return res.status(401).json({ error: 'Invalid email or password' })
    }

    if (tenant.status !== 'active') {
      return res.status(403).json({ error: 'Account is not active. Contact signal@aeoess.com' })
    }

    // Issue a fresh API key for this sign-in. Mirrors github-oauth pattern.
    const apiKey = issueApiKey(tenant.id, `email-login-${Date.now()}`)

    return res.status(200).json({
      message: 'Signed in. Save your API key — it will not be shown again.',
      tenant_id: tenant.id,
      plan: tenant.plan,
      api_key: apiKey,
      key_class: 'runtime',
      email_verified: tenant.email_verified === 1,
    })
  })

  // POST /auth/tenant-admin/issue — explicit admin-issuance action.
  // Body: { email, password } of the account owner. Not authenticated by an
  // API key on purpose: a runtime key (or an expiring admin key) cannot mint
  // or renew an admin key. Failure answers match POST /auth/email/login.
  // A successful issuance sends one security notice to the account address.
  router.post('/auth/tenant-admin/issue', async (req, res) => {
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

    const issuedAt = Date.now()
    const issued = issueTenantAdminKey(tenant.id, issuedAt)

    // Security notice to the stored account address, sent only after the
    // key exists. Best-effort like regenerate-key: a mail failure does not
    // undo the issuance. The notice never carries the key.
    try {
      sendEmail({
        ...tenantAdminIssuedEmail(tenant.name || tenant.email, tenant.email,
          new Date(issuedAt).toISOString(), issued.expiresAt),
        to: tenant.email,
      }).catch(() => {})
    } catch {}

    return res.status(201).json({
      message: 'Tenant admin key issued. It expires at expires_at and cannot be renewed; issue a new one with the password.',
      tenant_id: tenant.id,
      api_key: issued.apiKey,
      key_class: 'tenant_admin',
      expires_at: issued.expiresAt,
      ttl_seconds: TENANT_ADMIN_TTL_MS / 1000,
    })
  })

  // POST /auth/email/forgot — send password reset link (always 200)
  router.post('/auth/email/forgot', async (req, res) => {
    try {
      await emailAuthForgotLimiter.consume(req.ip || 'unknown')
    } catch {
      // Even on rate-limit, return generic 200 to prevent timing/enumeration.
      return res.status(200).json({ message: 'If that email is on file, a reset link has been sent.' })
    }

    const { email: rawEmail } = req.body || {}
    // Generic 200 regardless — never reveals whether the email exists.
    const genericResponse = { message: 'If that email is on file, a reset link has been sent.' }

    if (!rawEmail || typeof rawEmail !== 'string' || !isValidEmail(rawEmail)) {
      return res.status(200).json(genericResponse)
    }

    const email = normalizeEmail(rawEmail)
    const tenant = findTenantByEmail(email)
    if (!tenant) {
      return res.status(200).json(genericResponse)
    }

    try {
      const resetToken = createPasswordResetToken(tenant.id)
      const resetUrl = `${APP_ORIGIN}/portal.html?reset_token=${encodeURIComponent(resetToken)}`
      sendEmail({ ...passwordResetEmail(tenant.name, email, resetUrl), to: email }).catch(() => {})
    } catch (e) {
      console.error('[email-auth/forgot] reset token error', e)
      // Still return 200 to prevent enumeration.
    }

    return res.status(200).json(genericResponse)
  })

  // POST /auth/email/reset — consume reset token, set new password
  router.post('/auth/email/reset', async (req, res) => {
    try {
      await emailAuthResetLimiter.consume(req.ip || 'unknown')
    } catch {
      return res.status(429).json({ error: 'Too many reset attempts, try again later.' })
    }

    const { token, password } = req.body || {}
    if (!token || typeof token !== 'string') {
      return res.status(400).json({ error: 'Reset token required' })
    }
    const passwordCheck = validatePassword(password)
    if (!passwordCheck.ok) {
      return res.status(400).json({ error: passwordCheck.reason })
    }

    const consumed = consumePasswordResetToken(token)
    if (!consumed.ok || !consumed.tenantId) {
      return res.status(400).json({ error: consumed.reason || 'Invalid reset token' })
    }

    try {
      const hash = await hashPassword(password)
      setTenantPassword(consumed.tenantId, hash)
    } catch (e: any) {
      console.error('[email-auth/reset] hash error', e)
      return res.status(500).json({ error: 'Could not update password, try again' })
    }

    // Defence-in-depth: revoke ALL existing keys. User signs in fresh.
    const revokedCount = revokeAllApiKeysForTenant(consumed.tenantId)

    // Notify the user that the password changed (best-effort).
    try {
      const db = getDB()
      const row = db.prepare(`SELECT name, email FROM tenants WHERE id = ?`).get(consumed.tenantId) as any
      if (row?.email) {
        sendEmail({ ...passwordChangedEmail(row.name || row.email, row.email), to: row.email }).catch(() => {})
      }
    } catch (e) {
      console.error('[email-auth/reset] notify email failed', e)
    }

    return res.status(200).json({
      message: 'Password updated. Sign in to issue a new API key.',
      api_keys_revoked: revokedCount,
    })
  })

  // GET /api/v1/account — account summary. Lists API keys by prefix, class
  // and expiry, never secrets. Read-only, and one of the routes a
  // tenant_admin key may call (TENANT_ADMIN_ROUTES).
  router.get('/api/v1/account', authMiddleware, (req: any, res) => {
    const tenant = req.tenant
    const db = getDB()

    // Agent count
    const agentCount = db.prepare(
      `SELECT COUNT(*) as c FROM agents WHERE tenant_id = ? AND status = 'active'`
    ).get(tenant.id) as { c: number }

    // Delegation count
    const delegationCount = db.prepare(
      `SELECT COUNT(*) as c FROM delegations WHERE tenant_id = ? AND status = 'active'`
    ).get(tenant.id) as { c: number }

    // Evaluations this month
    const monthStart = new Date()
    monthStart.setDate(1)
    monthStart.setHours(0, 0, 0, 0)
    const evalsThisMonth = db.prepare(
      `SELECT COUNT(*) as c FROM policy_evaluations
       WHERE tenant_id = ? AND created_at >= ?`
    ).get(tenant.id, monthStart.toISOString()) as { c: number }

    // Receipts stored (evaluation_receipts = gateway auto-minted, receipts = agent-submitted)
    const evalReceiptCount = db.prepare(
      `SELECT COUNT(*) as c FROM evaluation_receipts WHERE tenant_id = ?`
    ).get(tenant.id) as { c: number }
    const agentReceiptCount = db.prepare(
      `SELECT COUNT(*) as c FROM receipts WHERE tenant_id = ?`
    ).get(tenant.id) as { c: number }

    // API keys (prefix only, no hashes)
    const keys = db.prepare(
      `SELECT id, key_prefix, name, key_class, created_at, last_used_at, revoked_at, expires_at
       FROM api_keys WHERE tenant_id = ?`
    ).all(tenant.id) as any[]

    // Plan limits
    const limits = PLAN_LIMITS[tenant.plan as keyof typeof PLAN_LIMITS] || PLAN_LIMITS.free

    res.json({
      tenant_id: tenant.id,
      name: tenant.name,
      email: tenant.email,
      plan: tenant.plan,
      status: tenant.status,
      usage: {
        agents: agentCount.c,
        delegations: delegationCount.c,
        evaluations_this_month: evalsThisMonth.c,
        receipts: evalReceiptCount.c + agentReceiptCount.c,
      },
      limits: {
        max_agents: limits.maxAgents,
        evaluations_per_month: limits.evaluationsPerMonth,
        compliance_reports: limits.complianceReports,
        sla: limits.sla,
      },
      api_keys: keys.map((k: any) => ({
        id: k.id,
        prefix: k.key_prefix,
        name: k.name,
        key_class: k.key_class === 'tenant_admin' ? 'tenant_admin' : 'runtime',
        created_at: k.created_at,
        last_used_at: k.last_used_at,
        expires_at: k.expires_at ?? null,
        // Same rule as authenticateKey: an admin key without a valid
        // future expiry is inactive.
        active: !k.revoked_at && (k.key_class === 'tenant_admin'
          ? Date.parse(k.expires_at ?? '') > Date.now()
          : !(k.expires_at && k.expires_at <= new Date().toISOString())),
      })),
    })
  })

  // Rotate API key — revokes the tenant's runtime keys, issues a new runtime
  // key. tenant_admin keys are not revoked, minted or listed here (they
  // expire on their own; password reset revokes them). A tenant_admin key
  // cannot call this or regenerate-key: authMiddleware refuses it outside
  // TENANT_ADMIN_ROUTES (api-keys.ts), so an admin key never mints a
  // runtime key that would outlive it.
  router.post('/api/v1/account/rotate-key', authMiddleware, (req: any, res) => {
    const tenant = req.tenant
    const { apiKey: rawKey, keyPrefix } = rotateRuntimeKeys(tenant.id, 'rotated')
    try { getEventBus().emit(tenant.id, { type: 'key_rotated', data: { key_prefix: keyPrefix } }) } catch {}

    res.json({
      message: 'API key rotated. Save this key — it will not be shown again.',
      api_key: rawKey,
    })
  })

  // POST /api/v1/account/regenerate-key — generate new key, invalidate old, email notification
  // Same key-class rule as rotate-key: runtime keys only.
  router.post('/api/v1/account/regenerate-key', authMiddleware, (req: any, res) => {
    const tenant = req.tenant
    const { apiKey: rawKey, keyPrefix } = rotateRuntimeKeys(tenant.id, 'regenerated')
    try { getEventBus().emit(tenant.id, { type: 'key_rotated', data: { key_prefix: keyPrefix } }) } catch {}

    // Email notification
    sendEmail({
      to: tenant.email,
      subject: 'AEOESS — API Key Regenerated',
      textBody: `Your API key was regenerated at ${new Date().toISOString()}. If you did not do this, contact signal@aeoess.com immediately.`,
      htmlBody: `<p>Your AEOESS API key was regenerated at ${new Date().toISOString()}.</p><p>If you did not do this, contact <a href="mailto:signal@aeoess.com">signal@aeoess.com</a> immediately.</p>`,
    }).catch(() => {})

    res.json({
      api_key: rawKey,
      message: 'New API key generated. Save it now — the old key is invalidated.',
    })
  })

  return router
}
