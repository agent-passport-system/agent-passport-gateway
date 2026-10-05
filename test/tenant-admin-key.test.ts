// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// API key class: runtime vs tenant_admin.
//
//   - a DB created before the key_class column migrates every existing key
//     to runtime
//   - createTenant and default issueApiKey mint runtime keys
//   - only issueApiKey(..., 'tenant_admin') mints a tenant_admin key
//   - authenticateKey reports the presenting key's class and id
//   - requireTenantAdmin refuses runtime keys, including a platform
//     operator's runtime key (role=admin is a different authority)
//   - parseLoginKeyClass accepts only runtime or tenant_admin

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { unlinkSync } from 'node:fs'
import { randomUUID, randomBytes, createHash } from 'node:crypto'
import Database from 'better-sqlite3'
import { initDB, getDB } from '../src/db/schema.js'
import { createTenant, authenticateKey, requireTenantAdmin } from '../src/auth/api-keys.js'
import { issueApiKey, parseLoginKeyClass } from '../src/auth/email-password.js'

let dbPath: string
const LEGACY_TENANT = 'tenant-legacy'
const LEGACY_KEY = `aps_live_${randomBytes(32).toString('hex')}`

before(() => {
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
})

after(() => {
  try { getDB().close() } catch {}
  for (const f of [dbPath, `${dbPath}-wal`, `${dbPath}-shm`]) { try { unlinkSync(f) } catch {} }
})

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
  it('a key that existed before the migration becomes runtime', () => {
    const row = getDB().prepare(`SELECT key_class FROM api_keys WHERE id = 'legacy-key-row'`).get() as any
    assert.equal(row.key_class, 'runtime')
    const t = authenticateKey(LEGACY_KEY)
    assert.ok(t)
    assert.equal(t!.id, LEGACY_TENANT)
    assert.equal(t!.key_class, 'runtime')
    assert.equal(t!.key_id, 'legacy-key-row')
  })

  it('createTenant and default issueApiKey mint runtime keys', () => {
    const { tenant, apiKey } = createTenant({ name: 'n', email: `kc-${randomUUID()}@test.local` })
    assert.equal(authenticateKey(apiKey)!.key_class, 'runtime')
    const second = issueApiKey(tenant.id, 'email-login-1')
    assert.equal(authenticateKey(second)!.key_class, 'runtime')
  })

  it('issueApiKey with tenant_admin mints a tenant_admin key for that tenant only', () => {
    const { tenant } = createTenant({ name: 'n', email: `kc-${randomUUID()}@test.local` })
    const adminKey = issueApiKey(tenant.id, 'tenant-admin-1', 'tenant_admin')
    const t = authenticateKey(adminKey)!
    assert.equal(t.id, tenant.id)
    assert.equal(t.key_class, 'tenant_admin')
    const row = getDB().prepare(`SELECT key_class, name FROM api_keys WHERE id = ?`).get(t.key_id) as any
    assert.equal(row.key_class, 'tenant_admin')
  })

  it('requireTenantAdmin: runtime key 403, tenant_admin key passes, missing tenant 401', () => {
    const rt = runMiddleware({ id: 't', role: 'user', key_class: 'runtime' })
    assert.equal(rt.status, 403)
    assert.equal(rt.body.code, 'tenant_admin_required')
    assert.equal(rt.nextCalled, false)

    const legacyShape = runMiddleware({ id: 't', role: 'user' })
    assert.equal(legacyShape.status, 403, 'no key_class means runtime')

    const ok = runMiddleware({ id: 't', role: 'user', key_class: 'tenant_admin' })
    assert.equal(ok.nextCalled, true)
    assert.equal(ok.status, 0)

    const none = runMiddleware(undefined)
    assert.equal(none.status, 401)
  })

  it('platform operator role does not satisfy requireTenantAdmin', () => {
    const op = runMiddleware({ id: 't', role: 'admin', key_class: 'runtime' })
    assert.equal(op.status, 403)
    assert.equal(op.nextCalled, false)
  })

  it('parseLoginKeyClass accepts runtime (default) and tenant_admin only', () => {
    assert.equal(parseLoginKeyClass(undefined), 'runtime')
    assert.equal(parseLoginKeyClass(null), 'runtime')
    assert.equal(parseLoginKeyClass('runtime'), 'runtime')
    assert.equal(parseLoginKeyClass('tenant_admin'), 'tenant_admin')
    assert.equal(parseLoginKeyClass('admin'), null)
    assert.equal(parseLoginKeyClass('TENANT_ADMIN'), null)
    assert.equal(parseLoginKeyClass(['tenant_admin']), null)
  })
})
