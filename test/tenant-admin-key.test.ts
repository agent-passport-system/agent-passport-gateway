// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// API key class: runtime vs tenant_admin.
//
//   - a DB created before the key_class / expires_at columns migrates every
//     existing key to runtime with no expiry
//   - createTenant and issueApiKey (signup, login) mint runtime keys only
//   - a tenant_admin key comes only from POST /auth/tenant-admin/issue with
//     the account password, expires after TENANT_ADMIN_TTL_MS, and an
//     expired one is refused by authenticateKey
//   - an admin row with NULL or malformed expiry is refused; a runtime key
//     with NULL expiry (every legacy key) keeps working
//   - an admin key reads GET /api/v1/account but gets 403
//     tenant_admin_scope on an ordinary authenticated route
//   - no API key can mint or renew one: the issuance route reads only
//     email + password
//   - runtime rotation (rotateRuntimeKeys, used by rotate-key and
//     regenerate-key) leaves an unexpired tenant_admin key working
//   - password reset (revokeAllApiKeysForTenant) revokes it
//   - requireTenantAdmin refuses runtime keys, including a platform
//     operator's runtime key (role=admin is a different authority)

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { unlinkSync } from 'node:fs'
import { randomUUID, randomBytes, createHash } from 'node:crypto'
import type { Server } from 'node:http'
import express from 'express'
import Database from 'better-sqlite3'
import { initDB, getDB } from '../src/db/schema.js'
import { createTenant, authenticateKey, requireTenantAdmin, authMiddleware } from '../src/auth/api-keys.js'
import {
  issueApiKey, hashPassword, setTenantPassword, revokeAllApiKeysForTenant,
  createPasswordResetToken, consumePasswordResetToken,
} from '../src/auth/email-password.js'
import {
  issueTenantAdminKey, rotateRuntimeKeys, TENANT_ADMIN_TTL_MS,
} from '../src/auth/tenant-admin.js'
import { createAuthRouter } from '../src/auth/auth-router.js'

let dbPath: string
let server: Server
let baseUrl: string
const LEGACY_TENANT = 'tenant-legacy'
const LEGACY_KEY = `aps_live_${randomBytes(32).toString('hex')}`
const PASSWORD = 'correct horse battery staple'

before(async () => {
  // Seed a DB file with the pre-key_class api_keys schema and one key.
  dbPath = join(tmpdir(), `aeoess-key-class-test-${randomUUID()}.db`)
  const old = new Database(dbPath)
  old.exec(`
    CREATE TABLE tenants (
      id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
      plan TEXT NOT NULL DEFAULT 'free', stripe_customer_id TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      status TEXT NOT NULL DEFAULT 'active'
    );
    CREATE TABLE api_keys (
      id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id),
      key_hash TEXT NOT NULL UNIQUE, key_prefix TEXT NOT NULL,
      name TEXT NOT NULL DEFAULT 'default',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      last_used_at TEXT, revoked_at TEXT
    );
  `)
  old.prepare(`INSERT INTO tenants (id, name, email) VALUES (?, ?, ?)`).run(LEGACY_TENANT, 'legacy', 'legacy@test.local')
  old.prepare(`INSERT INTO api_keys (id, tenant_id, key_hash, key_prefix, name) VALUES (?, ?, ?, ?, ?)`)
    .run('legacy-key-row', LEGACY_TENANT, createHash('sha256').update(LEGACY_KEY).digest('hex'), LEGACY_KEY.slice(0, 12), 'default')
  old.close()
  initDB(dbPath)

  const app = express()
  app.use(express.json())
  app.use(createAuthRouter({ sendEmail: async () => ({ sent: false, queued: false }) }))
  app.get('/api/v1/whoami', authMiddleware, (req: any, res) => res.json({ id: req.tenant.id, key_class: req.tenant.key_class }))
  await new Promise<void>((r) => {
    server = app.listen(0, '127.0.0.1', () => {
      baseUrl = `http://127.0.0.1:${(server.address() as any).port}`
      r()
    })
  })
})

after(() => {
  server?.close()
  try { getDB().close() } catch {}
  for (const f of [dbPath, `${dbPath}-wal`, `${dbPath}-shm`]) { try { unlinkSync(f) } catch {} }
})

async function call(method: string, path: string, body?: unknown, key?: string) {
  const headers: Record<string, string> = { 'content-type': 'application/json' }
  if (key) headers.authorization = `Bearer ${key}`
  const r = await fetch(`${baseUrl}${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) })
  let json: any = null
  try { json = await r.json() } catch { json = null }
  return { status: r.status, json }
}

async function tenantWithPassword(): Promise<{ id: string; email: string; runtimeKey: string }> {
  const email = `ta-${randomUUID()}@test.local`
  const { tenant, apiKey } = createTenant({ name: 'n', email })
  setTenantPassword(tenant.id, await hashPassword(PASSWORD))
  return { id: tenant.id, email, runtimeKey: apiKey }
}

function runMiddleware(tenant: any) {
  let status = 0
  let body: any = null
  let nextCalled = false
  const res = {
    status(s: number) { status = s; return this },
    json(b: any) { body = b; return this },
  }
  requireTenantAdmin({ tenant }, res, () => { nextCalled = true })
  return { status, body, nextCalled }
}

describe('api key class', () => {
  it('a key that existed before the migration becomes runtime with no expiry', () => {
    const row = getDB().prepare(`SELECT key_class, expires_at FROM api_keys WHERE id = 'legacy-key-row'`).get() as any
    assert.equal(row.key_class, 'runtime')
    assert.equal(row.expires_at, null)
    const t = authenticateKey(LEGACY_KEY)
    assert.ok(t)
    assert.equal(t!.id, LEGACY_TENANT)
    assert.equal(t!.key_class, 'runtime')
    assert.equal(t!.key_id, 'legacy-key-row')
  })

  it('createTenant and issueApiKey (signup, login) mint runtime keys only', () => {
    const { tenant, apiKey } = createTenant({ name: 'n', email: `kc-${randomUUID()}@test.local` })
    assert.equal(authenticateKey(apiKey)!.key_class, 'runtime')
    const second = issueApiKey(tenant.id, 'email-login-1')
    assert.equal(authenticateKey(second)!.key_class, 'runtime')
  })

  it('requireTenantAdmin: runtime key 403, tenant_admin key passes, missing tenant 401', () => {
    const rt = runMiddleware({ id: 't', role: 'user', key_class: 'runtime' })
    assert.equal(rt.status, 403)
    assert.equal(rt.body.code, 'tenant_admin_required')
    assert.equal(rt.nextCalled, false)
    assert.equal(runMiddleware({ id: 't', role: 'user' }).status, 403, 'no key_class means runtime')
    const ok = runMiddleware({ id: 't', role: 'user', key_class: 'tenant_admin' })
    assert.equal(ok.nextCalled, true)
    assert.equal(runMiddleware(undefined).status, 401)
  })

  it('platform operator role does not satisfy requireTenantAdmin', () => {
    const op = runMiddleware({ id: 't', role: 'admin', key_class: 'runtime' })
    assert.equal(op.status, 403)
    assert.equal(op.nextCalled, false)
  })
})

describe('tenant_admin issuance (POST /auth/tenant-admin/issue)', () => {
  it('issues a tenant_admin key that expires TENANT_ADMIN_TTL_MS (15 min) after issuance', async () => {
    assert.equal(TENANT_ADMIN_TTL_MS, 15 * 60 * 1000)
    const t = await tenantWithPassword()
    const before = Date.now()
    const r = await call('POST', '/auth/tenant-admin/issue', { email: t.email, password: PASSWORD })
    const after = Date.now()
    assert.equal(r.status, 201, JSON.stringify(r.json))
    assert.equal(r.json.key_class, 'tenant_admin')
    assert.equal(r.json.ttl_seconds, 900)
    const exp = Date.parse(r.json.expires_at)
    assert.ok(exp >= before + TENANT_ADMIN_TTL_MS && exp <= after + TENANT_ADMIN_TTL_MS)
    const acct = await call('GET', '/api/v1/account', undefined, r.json.api_key)
    assert.equal(acct.status, 200, 'account read is on the admin allowlist')
    assert.equal(acct.json.tenant_id, t.id)
    const who = await call('GET', '/api/v1/whoami', undefined, r.json.api_key)
    assert.equal(who.status, 403, 'an ordinary authenticated route is not')
    assert.equal(who.json.code, 'tenant_admin_scope')
    const row = getDB().prepare(`SELECT key_class, expires_at FROM api_keys WHERE key_hash = ?`)
      .get(createHash('sha256').update(r.json.api_key).digest('hex')) as any
    assert.equal(row.key_class, 'tenant_admin')
    assert.equal(row.expires_at, r.json.expires_at)
  })

  it('wrong password, unknown email or a missing password is 401 and mints nothing', async () => {
    const t = await tenantWithPassword()
    const count = () => (getDB().prepare(`SELECT COUNT(*) c FROM api_keys WHERE tenant_id = ?`).get(t.id) as any).c
    const n = count()
    for (const body of [
      { email: t.email, password: 'wrong password here' },
      { email: `nobody-${randomUUID()}@test.local`, password: PASSWORD },
      { email: t.email },
    ]) {
      const r = await call('POST', '/auth/tenant-admin/issue', body)
      assert.equal(r.status, 401, JSON.stringify(body))
    }
    assert.equal(count(), n)
  })

  it('a runtime key cannot mint or renew one: the bearer key is not a credential here', async () => {
    const t = await tenantWithPassword()
    const viaRuntime = await call('POST', '/auth/tenant-admin/issue', {}, t.runtimeKey)
    assert.equal(viaRuntime.status, 401)
    const admin = issueTenantAdminKey(t.id)
    const viaAdmin = await call('POST', '/auth/tenant-admin/issue', {}, admin.apiKey)
    assert.equal(viaAdmin.status, 401, 'an admin key cannot renew itself either')
    const admins = getDB().prepare(`SELECT COUNT(*) c FROM api_keys WHERE tenant_id = ? AND key_class = 'tenant_admin'`).get(t.id) as any
    assert.equal(admins.c, 1)
  })

  it('an expired tenant_admin key is refused server-side', async () => {
    const t = await tenantWithPassword()
    const stale = issueTenantAdminKey(t.id, Date.now() - TENANT_ADMIN_TTL_MS - 1)
    assert.equal(authenticateKey(stale.apiKey), null)
    const r = await call('GET', '/api/v1/whoami', undefined, stale.apiKey)
    assert.equal(r.status, 401)
    // And one that expires while held.
    const live = issueTenantAdminKey(t.id)
    assert.equal(authenticateKey(live.apiKey)!.key_class, 'tenant_admin')
    getDB().prepare(`UPDATE api_keys SET expires_at = ? WHERE id = ?`).run(new Date(Date.now() - 1).toISOString(), live.keyId)
    assert.equal(authenticateKey(live.apiKey), null)
  })
})

describe('tenant_admin keys must carry an expiry', () => {
  it('an admin row with expires_at NULL is refused at authentication', async () => {
    const t = await tenantWithPassword()
    // The state 562c128 left behind: an admin key with no expiry.
    const raw = `aps_live_${randomBytes(32).toString('hex')}`
    getDB().prepare(`INSERT INTO api_keys (id, tenant_id, key_hash, key_prefix, name, key_class, expires_at)
      VALUES (?, ?, ?, ?, 'legacy-admin', 'tenant_admin', NULL)`)
      .run(randomUUID(), t.id, createHash('sha256').update(raw).digest('hex'), raw.slice(0, 12))
    assert.equal(authenticateKey(raw), null)
    const r = await call('GET', '/api/v1/account', undefined, raw)
    assert.equal(r.status, 401)
    const lastUsed = getDB().prepare(`SELECT last_used_at FROM api_keys WHERE key_hash = ?`)
      .get(createHash('sha256').update(raw).digest('hex')) as any
    assert.equal(lastUsed.last_used_at, null, 'a refused key is not marked used')
  })

  it('an admin row with a malformed expiry is refused too', async () => {
    const t = await tenantWithPassword()
    const admin = issueTenantAdminKey(t.id)
    // 'never' sorts after any ISO date, so a string compare alone would pass it.
    getDB().prepare(`UPDATE api_keys SET expires_at = 'never' WHERE id = ?`).run(admin.keyId)
    assert.equal(authenticateKey(admin.apiKey), null)
  })

  it('a runtime key with expires_at NULL keeps working (legacy keys)', async () => {
    const t = await tenantWithPassword()
    const row = getDB().prepare(`SELECT expires_at, key_class FROM api_keys WHERE key_hash = ?`)
      .get(createHash('sha256').update(t.runtimeKey).digest('hex')) as any
    assert.deepEqual(row, { expires_at: null, key_class: 'runtime' })
    assert.equal(authenticateKey(t.runtimeKey)!.key_class, 'runtime')
    assert.equal((await call('GET', '/api/v1/whoami', undefined, t.runtimeKey)).status, 200)
    assert.equal(authenticateKey(LEGACY_KEY)!.key_class, 'runtime', 'the pre-migration key too')
  })
})

describe('rotation and recovery', () => {
  it('runtime rotation revokes runtime keys only and leaves an unexpired tenant_admin key working', async () => {
    const t = await tenantWithPassword()
    const extraRuntime = issueApiKey(t.id, 'email-login-x')
    const admin = issueTenantAdminKey(t.id)
    const rotated = rotateRuntimeKeys(t.id, 'rotated')
    assert.equal(rotated.revoked, 2)
    assert.equal(authenticateKey(t.runtimeKey), null)
    assert.equal(authenticateKey(extraRuntime), null)
    assert.equal(authenticateKey(rotated.apiKey)!.key_class, 'runtime')
    assert.equal(authenticateKey(admin.apiKey)!.key_class, 'tenant_admin', 'admin key survives rotation')
    // regenerate-key uses the same function.
    const regen = rotateRuntimeKeys(t.id, 'regenerated')
    assert.equal(regen.revoked, 1)
    assert.equal(authenticateKey(regen.apiKey)!.key_class, 'runtime')
    assert.equal(authenticateKey(admin.apiKey)!.key_class, 'tenant_admin')
    // Rotation never mints a tenant_admin key.
    const admins = getDB().prepare(`SELECT COUNT(*) c FROM api_keys WHERE tenant_id = ? AND key_class = 'tenant_admin'`).get(t.id) as any
    assert.equal(admins.c, 1)
  })

  it('password reset revokes every key class, tenant_admin included', async () => {
    const t = await tenantWithPassword()
    const admin = issueTenantAdminKey(t.id)
    const token = createPasswordResetToken(t.id)
    const consumed = consumePasswordResetToken(token)
    assert.equal(consumed.ok, true)
    // The same call POST /auth/email/reset makes after setting the hash.
    const revoked = revokeAllApiKeysForTenant(consumed.tenantId!)
    assert.equal(revoked, 2)
    assert.equal(authenticateKey(admin.apiKey), null)
    assert.equal(authenticateKey(t.runtimeKey), null)
  })
})
