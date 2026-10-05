// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Email/password authentication.
 *
 * Composes with the existing API-key auth surface:
 *   - signup-with-password creates a tenant (same as POST /api/v1/signup)
 *     plus stores a bcrypt password hash and sends a verification email.
 *     Returns one API key, just like the GitHub OAuth path.
 *   - login verifies email+password, issues a *new* API key named
 *     "email-login-<ts>", mirroring how /auth/github/callback issues a
 *     fresh key on every sign-in. Always a runtime key. The tenant
 *     administration key has its own explicit issuance action
 *     (src/auth/tenant-admin.ts).
 *   - forgot generates a single-use reset token (SHA-256 stored, raw in
 *     email link). 1h expiry.
 *   - reset verifies the token, updates the password hash, marks the
 *     token used, and as a defence-in-depth measure revokes ALL existing
 *     api_keys for the tenant, runtime and tenant_admin alike (forces
 *     re-issue, like Stripe / GitHub).
 *   - verify-email marks email_verified=1 when the verification link is
 *     opened. Soft signal today; will gate sensitive ops later.
 *
 * Account enumeration:
 *   - signup: returns 409 on duplicate (matches existing /api/v1/signup).
 *     Pre-existing leak; not introducing a new one.
 *   - login: returns generic "Invalid email or password" regardless of
 *     whether the email exists. Constant-time via bcrypt.compare against
 *     a dummy hash when the email is unknown.
 *   - forgot: returns 200 with same message regardless of whether the
 *     email is on file. Never reveals account existence.
 *
 * Password rules: min 10 chars. No upper-case requirement, no symbol
 *   requirement — NIST SP 800-63B §5.1.1.2 explicitly recommends against
 *   composition rules; length is what matters. Blocklist of the top 25
 *   common passwords is applied.
 */

import bcrypt from 'bcryptjs'
import { createHash, randomBytes, randomUUID } from 'node:crypto'
import { getDB } from '../db/schema.js'
import type { Tenant } from './api-keys.js'

const BCRYPT_ROUNDS = 12
const PASSWORD_MIN_LENGTH = 10
const RESET_TOKEN_TTL_MS = 60 * 60 * 1000 // 1 hour
const VERIFY_TOKEN_TTL_MS = 24 * 60 * 60 * 1000 // 24 hours

// Dummy bcrypt hash for constant-time response on unknown email.
// Generated once at module load. The hash is of a random string —
// no password will ever match it.
const DUMMY_HASH = bcrypt.hashSync(randomBytes(32).toString('hex'), BCRYPT_ROUNDS)

// Top 25 from rockyou + SecLists. Cheap defence against the laziest
// password choices. Not a substitute for length.
const COMMON_PASSWORDS = new Set([
  'password', 'password1', 'password123', 'qwerty', 'qwerty123',
  '123456', '12345678', '123456789', '1234567890', 'iloveyou',
  'letmein', 'welcome', 'admin', 'administrator', 'monkey',
  'dragon', 'abc123', 'football', 'baseball', 'superman',
  'sunshine', 'master', 'shadow', 'princess', 'starwars',
])

export interface PasswordValidationResult {
  ok: boolean
  reason?: string
}

export function validatePassword(password: string): PasswordValidationResult {
  if (typeof password !== 'string') return { ok: false, reason: 'Password must be a string' }
  if (password.length < PASSWORD_MIN_LENGTH) {
    return { ok: false, reason: `Password must be at least ${PASSWORD_MIN_LENGTH} characters` }
  }
  if (password.length > 256) {
    return { ok: false, reason: 'Password is too long (max 256 characters)' }
  }
  if (COMMON_PASSWORDS.has(password.toLowerCase())) {
    return { ok: false, reason: 'This password is too common, pick another' }
  }
  return { ok: true }
}

export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase()
}

export function isValidEmail(email: string): boolean {
  // Conservative: must have @ and a dot in the domain. Detailed
  // RFC 5322 validation is overkill and rejects real-world addresses.
  // We do not validate deliverability — the verification email is the
  // authoritative check.
  return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)
}

/**
 * Hash a password for storage. ~250ms at 12 rounds on modern hardware.
 */
export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, BCRYPT_ROUNDS)
}

/**
 * Verify a password against a stored hash. Constant-time on the hash
 * comparison itself; takes the same wall-clock time for valid and
 * invalid passwords because bcrypt does the same work either way.
 */
export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash)
}

/**
 * Constant-time bcrypt cycle against a known-bad hash. Used when the
 * email lookup found nothing — keeps the response wall-clock identical
 * to the "found tenant, wrong password" case so an attacker can't time
 * the response to enumerate registered emails.
 */
export async function burnTime(): Promise<void> {
  await bcrypt.compare(randomBytes(16).toString('hex'), DUMMY_HASH)
}

// ═══════════════════════════════════════
// Tenant lookup + password set
// ═══════════════════════════════════════

export interface TenantWithPassword extends Tenant {
  password_hash: string | null
  email_verified: 0 | 1
}

/**
 * Resolve a tenant by either its primary email OR any alias in
 * tenant_aliases. Returns null if no active tenant matches.
 *
 * This makes a tenant's primary email and any configured alias email (see
 * GATEWAY_OPERATOR_EMAIL_ALIASES in src/db/schema.ts) look up the same
 * tenant. That is necessary because the email-password sign-in surface
 * needs to be symmetric with GitHub OAuth.
 */
export function findTenantByEmail(email: string): TenantWithPassword | null {
  const db = getDB()
  const normalized = normalizeEmail(email)
  const row = db.prepare(`
    SELECT t.* FROM tenants t
    WHERE t.status = 'active' AND (
      t.email = ?
      OR EXISTS (SELECT 1 FROM tenant_aliases a WHERE a.email = ? AND a.tenant_id = t.id)
    )
    LIMIT 1
  `).get(normalized, normalized) as any
  if (!row) return null
  return {
    id: row.id,
    name: row.name,
    email: row.email,
    plan: row.plan,
    stripe_customer_id: row.stripe_customer_id,
    status: row.status,
    role: row.role === 'admin' ? 'admin' : 'user',
    password_hash: row.password_hash || null,
    email_verified: (row.email_verified === 1 ? 1 : 0) as 0 | 1,
  }
}

export function setTenantPassword(tenantId: string, passwordHash: string): void {
  const db = getDB()
  db.prepare(`UPDATE tenants SET password_hash = ?, password_set_at = datetime('now') WHERE id = ?`)
    .run(passwordHash, tenantId)
}

export function markEmailVerified(tenantId: string): void {
  const db = getDB()
  db.prepare(`UPDATE tenants SET email_verified = 1, email_verified_at = datetime('now') WHERE id = ?`)
    .run(tenantId)
}

// ═══════════════════════════════════════
// API key issuance (mirrors GitHub OAuth pattern)
// ═══════════════════════════════════════

function hashKey(key: string): string {
  return createHash('sha256').update(key).digest('hex')
}

/**
 * Issue a new runtime API key for an existing tenant. Mirrors the
 * github-oauth "additional key on each sign-in" pattern. Does not revoke
 * other keys. Never mints a tenant_admin key (see tenant-admin.ts).
 */
export function issueApiKey(tenantId: string, name: string): string {
  const db = getDB()
  const rawKey = `aps_live_${randomBytes(32).toString('hex')}`
  const keyHash = hashKey(rawKey)
  const keyPrefix = rawKey.slice(0, 12)
  db.prepare(`INSERT INTO api_keys (id, tenant_id, key_hash, key_prefix, name, key_class) VALUES (?, ?, ?, ?, ?, 'runtime')`)
    .run(randomUUID(), tenantId, keyHash, keyPrefix, name)
  return rawKey
}

/**
 * Revoke all active API keys for a tenant, every key class (runtime and
 * tenant_admin). Used on password reset as defence-in-depth: if an
 * attacker captured a key, the reset locks them out. The user re-issues a
 * fresh key via login. This is the one recovery operation that revokes
 * tenant_admin keys; runtime rotation does not (tenant-admin.ts).
 */
export function revokeAllApiKeysForTenant(tenantId: string): number {
  const db = getDB()
  const result = db.prepare(`UPDATE api_keys SET revoked_at = datetime('now') WHERE tenant_id = ? AND revoked_at IS NULL`)
    .run(tenantId)
  return result.changes
}

// ═══════════════════════════════════════
// Reset and verification tokens
// ═══════════════════════════════════════

export interface TokenPayload {
  rawToken: string  // sent in the email link, never stored
  tokenHash: string // SHA-256 hex, stored in DB
}

function generateToken(): TokenPayload {
  // 32 bytes = 256 bits = far beyond brute-force range.
  // base64url so the link is URL-safe without escaping.
  const rawToken = randomBytes(32).toString('base64url')
  const tokenHash = createHash('sha256').update(rawToken).digest('hex')
  return { rawToken, tokenHash }
}

export function createPasswordResetToken(tenantId: string): string {
  const { rawToken, tokenHash } = generateToken()
  const db = getDB()
  const expiresAt = new Date(Date.now() + RESET_TOKEN_TTL_MS).toISOString()
  db.prepare(`INSERT INTO password_reset_tokens (token_hash, tenant_id, expires_at) VALUES (?, ?, ?)`)
    .run(tokenHash, tenantId, expiresAt)
  return rawToken
}

export interface ConsumeResult {
  ok: boolean
  tenantId?: string
  reason?: string
}

export function consumePasswordResetToken(rawToken: string): ConsumeResult {
  const db = getDB()
  const tokenHash = createHash('sha256').update(rawToken).digest('hex')
  const row = db.prepare(`SELECT * FROM password_reset_tokens WHERE token_hash = ?`).get(tokenHash) as any
  if (!row) return { ok: false, reason: 'Invalid or expired reset link' }
  if (row.used_at) return { ok: false, reason: 'This reset link has already been used' }
  if (new Date(row.expires_at).getTime() < Date.now()) {
    return { ok: false, reason: 'This reset link has expired, request a new one' }
  }
  db.prepare(`UPDATE password_reset_tokens SET used_at = datetime('now') WHERE token_hash = ?`).run(tokenHash)
  return { ok: true, tenantId: row.tenant_id }
}

export function createEmailVerificationToken(tenantId: string): string {
  const { rawToken, tokenHash } = generateToken()
  const db = getDB()
  const expiresAt = new Date(Date.now() + VERIFY_TOKEN_TTL_MS).toISOString()
  db.prepare(`INSERT INTO email_verification_tokens (token_hash, tenant_id, expires_at) VALUES (?, ?, ?)`)
    .run(tokenHash, tenantId, expiresAt)
  return rawToken
}

export function consumeEmailVerificationToken(rawToken: string): ConsumeResult {
  const db = getDB()
  const tokenHash = createHash('sha256').update(rawToken).digest('hex')
  const row = db.prepare(`SELECT * FROM email_verification_tokens WHERE token_hash = ?`).get(tokenHash) as any
  if (!row) return { ok: false, reason: 'Invalid or expired verification link' }
  if (row.used_at) return { ok: false, reason: 'This verification link has already been used' }
  if (new Date(row.expires_at).getTime() < Date.now()) {
    return { ok: false, reason: 'This verification link has expired' }
  }
  db.prepare(`UPDATE email_verification_tokens SET used_at = datetime('now') WHERE token_hash = ?`).run(tokenHash)
  return { ok: true, tenantId: row.tenant_id }
}
