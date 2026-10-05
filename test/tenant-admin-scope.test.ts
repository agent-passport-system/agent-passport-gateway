// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// tenant_admin key scope (TENANT_ADMIN_ROUTES in src/auth/api-keys.ts),
// over HTTP with the routers mounted the way server.ts mounts them.
//
//   - an admin key works on approver register, list and revoke and on
//     GET /api/v1/account
//   - it gets 403 tenant_admin_scope on approval open, sign, decide and
//     receipt, on runtime rotate-key and regenerate-key, and on ordinary
//     runtime routes, while a runtime key of the same tenant works there
//   - regression for the reproduced gap: an admin key could rotate in a
//     runtime key with no expiry that outlived the admin key. Now it cannot
//     mint, rotate or renew a runtime key at all.

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { unlinkSync } from 'node:fs'
import { randomUUID } from 'node:crypto'
import type { Server } from 'node:http'
import express from 'express'
import { generateKeyPair, sign as edSign } from 'agent-passport-system'
import { initDB, getDB } from '../src/db/schema.js'
import { initGatewayIdentity } from '../src/gateway/identity.js'
import {
  createTenant, authenticateKey, authMiddleware, tenantAdminRouteAllowed,
} from '../src/auth/api-keys.js'
import { hashPassword, setTenantPassword } from '../src/auth/email-password.js'
import { createAuthRouter } from '../src/auth/auth-router.js'
import { approverAdminRouter } from '../src/gateway/approval/approvers-router.js'
import { approvalRouter } from '../src/gateway/approval/index.js'
import { setApprovalConnectorRouter } from '../src/gateway/approval/connector.js'
import { getActiveApprover, registerApprover } from '../src/gateway/approval/approvers.js'
import { approvalCommitment } from '../src/gateway/approval/commitment.js'
import { getRequest } from '../src/gateway/approval/store.js'
import { guardsRouter } from '../src/gateway/guards/router.js'
import { simulationRouter, initModeConfigTable, initModeObservationsTable } from '../src/gateway/simulation/index.js'

const PASSWORD = 'correct horse battery staple'
let dbPath: string
let server: Server
let baseUrl: string

before(async () => {
  dbPath = join(tmpdir(), `aeoess-tenant-admin-scope-${randomUUID()}.db`)
  initDB(dbPath)
  initGatewayIdentity()
  initModeConfigTable()
  initModeObservationsTable()
  setApprovalConnectorRouter({
    async route(channel) {
      return { channel, sent: false, queued: true, transport: 'email_interim', routedAt: new Date().toISOString() }
    },
  })
  const app = express()
  app.use(express.json())
  app.use(createAuthRouter({ sendEmail: async () => ({ sent: false, queued: false }) }))
  app.use('/api/v1', authMiddleware, guardsRouter)
  app.use('/api/v1', authMiddleware, approverAdminRouter)
  app.use('/api/v1', authMiddleware, approvalRouter)
  app.use('/api/v1', authMiddleware, simulationRouter)
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

async function call(method: string, path: string, key?: string, body?: unknown) {
  const headers: Record<string, string> = { 'content-type': 'application/json' }
  if (key) headers.authorization = `Bearer ${key}`
  const r = await fetch(`${baseUrl}${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) })
  let json: any = null
  try { json = await r.json() } catch { json = null }
  return { status: r.status, json }
}

interface T { id: string; email: string; runtimeKey: string; adminKey: string }
async function tenant(): Promise<T> {
  const email = `scope-${randomUUID()}@test.local`
  const { tenant: t, apiKey } = createTenant({ name: 'n', email })
  setTenantPassword(t.id, await hashPassword(PASSWORD))
  const issued = await call('POST', '/auth/tenant-admin/issue', undefined, { email, password: PASSWORD })
  assert.equal(issued.status, 201, JSON.stringify(issued.json))
  return { id: t.id, email, runtimeKey: apiKey, adminKey: issued.json.api_key }
}

function runtimeKeyRows(tenantId: string): Array<{ id: string; revoked_at: string | null; expires_at: string | null }> {
  return getDB().prepare(
    `SELECT id, revoked_at, expires_at FROM api_keys WHERE tenant_id = ? AND key_class = 'runtime' ORDER BY id`,
  ).all(tenantId) as any
}

describe('tenant_admin scope - allowlisted management routes', () => {
  it('an admin key registers, lists and revokes approvers and reads the account', async () => {
    const t = await tenant()
    const kp = generateKeyPair()
    const reg = await call('POST', '/api/v1/approvers', t.adminKey, {
      approver_id: 'scope-approver', public_key: kp.publicKey, authority: ['payments:*'], principal_id: 'treasury-1',
    })
    assert.equal(reg.status, 201, JSON.stringify(reg.json))
    const list = await call('GET', '/api/v1/approvers', t.adminKey)
    assert.equal(list.status, 200)
    assert.equal(list.json.total, 1)
    const acct = await call('GET', '/api/v1/account', t.adminKey)
    assert.equal(acct.status, 200)
    assert.equal(acct.json.tenant_id, t.id)
    assert.ok(acct.json.api_keys.every((k: any) => !('key_hash' in k)))
    const rev = await call('POST', '/api/v1/approvers/scope-approver/revoke', t.adminKey, {})
    assert.equal(rev.status, 200)
    assert.equal(getActiveApprover(t.id, 'scope-approver'), undefined)
  })

  it('the allowlist is exact: method and full path', () => {
    assert.equal(tenantAdminRouteAllowed('GET', '/api/v1/account'), true)
    assert.equal(tenantAdminRouteAllowed('GET', '/api/v1/account?x=1'), true)
    assert.equal(tenantAdminRouteAllowed('GET', '/api/v1/approvers/'), true)
    assert.equal(tenantAdminRouteAllowed('POST', '/api/v1/approvers/a-1/revoke'), true)
    for (const [m, p] of [
      ['POST', '/api/v1/account'],
      ['HEAD', '/api/v1/account'],
      ['POST', '/api/v1/account/rotate-key'],
      ['POST', '/api/v1/account/regenerate-key'],
      ['GET', '/api/v1/account/x'],
      ['DELETE', '/api/v1/approvers/a-1'],
      ['POST', '/api/v1/approvers/a/b/revoke'],
      ['POST', '/api/v1/approvals'],
      ['GET', '/api/v1/approvals/x/receipt'],
      ['GET', '/api/v1/admin/tenants'],
      ['GET', '/api/v1/accounts'],
    ]) {
      assert.equal(tenantAdminRouteAllowed(m, p), false, `${m} ${p}`)
    }
  })
})

describe('tenant_admin scope - refused everywhere else', () => {
  it('approval open, list, sign, decide and receipt are 403 tenant_admin_scope', async () => {
    const t = await tenant()
    // A pending request opened with the runtime key, and a registered
    // approver, so the admin key's refusal is about scope and nothing else.
    getDB().prepare(`INSERT INTO agents (id, tenant_id, agent_id, public_key, status, entity_id) VALUES (?, ?, ?, ?, 'active', ?)`)
      .run(randomUUID(), t.id, 'agent-scope', generateKeyPair().publicKey, 'owner-scope')
    const kp = generateKeyPair()
    registerApprover({
      tenantId: t.id, approverId: 'ap-scope', publicKey: kp.publicKey, authority: ['payments:*'],
      principalId: 'treasury-scope', registeredBy: 'test',
    })
    const openBody = { action_class: 'payments:transfer', subject: 'inv-1', agent_id: 'agent-scope', requested_by: 'r' }

    const adminOpen = await call('POST', '/api/v1/approvals', t.adminKey, openBody)
    assert.equal(adminOpen.status, 403)
    assert.equal(adminOpen.json.code, 'tenant_admin_scope')
    assert.equal((getDB().prepare(`SELECT COUNT(*) c FROM approval_requests WHERE tenant_id = ?`).get(t.id) as any).c, 0)

    const opened = await call('POST', '/api/v1/approvals', t.runtimeKey, openBody)
    assert.equal(opened.status, 201, JSON.stringify(opened.json))
    const id = opened.json.id
    const sig = edSign(approvalCommitment(getRequest(t.id, id)!).message, kp.privateKey)

    const refusals = [
      await call('GET', '/api/v1/approvals', t.adminKey),
      await call('GET', `/api/v1/approvals/${id}`, t.adminKey),
      await call('POST', `/api/v1/approvals/${id}/sign`, t.adminKey, { approver_id: 'ap-scope', reason: 'reviewed it', signature: sig }),
      await call('POST', `/api/v1/approvals/${id}/decide`, t.adminKey, { verdict: 'rejected', reason: 'not this', decided_by: 'ops' }),
      await call('GET', `/api/v1/approvals/${id}/receipt`, t.adminKey),
    ]
    for (const r of refusals) {
      assert.equal(r.status, 403, JSON.stringify(r.json))
      assert.equal(r.json.code, 'tenant_admin_scope')
    }
    assert.equal((getDB().prepare(`SELECT COUNT(*) c FROM approval_signatures WHERE request_id = ?`).get(id) as any).c, 0)
    assert.equal(getRequest(t.id, id)!.status, 'pending')

    // The same calls with the runtime key go through.
    const s = await call('POST', `/api/v1/approvals/${id}/sign`, t.runtimeKey, { approver_id: 'ap-scope', reason: 'reviewed it', signature: sig })
    assert.equal(s.status, 201, JSON.stringify(s.json))
    const d = await call('POST', `/api/v1/approvals/${id}/decide`, t.runtimeKey, { verdict: 'approved', reason: 'looks right', decided_by: 'ops' })
    assert.equal(d.status, 200, JSON.stringify(d.json))
    assert.equal((await call('GET', `/api/v1/approvals/${id}/receipt`, t.runtimeKey)).status, 200)
    assert.equal((await call('GET', `/api/v1/approvals/${id}/receipt`, t.adminKey)).status, 403)
  })

  it('rotate-key and regenerate-key are 403 tenant_admin_scope', async () => {
    const t = await tenant()
    const before = runtimeKeyRows(t.id)
    for (const path of ['/api/v1/account/rotate-key', '/api/v1/account/regenerate-key']) {
      const r = await call('POST', path, t.adminKey, {})
      assert.equal(r.status, 403, path)
      assert.equal(r.json.code, 'tenant_admin_scope')
      assert.equal(r.json.api_key, undefined)
    }
    assert.deepEqual(runtimeKeyRows(t.id), before, 'no runtime key minted or revoked')
    assert.equal(authenticateKey(t.runtimeKey)!.key_class, 'runtime')
  })

  it('ordinary runtime routes are 403 for the admin key and work for the runtime key', async () => {
    const t = await tenant()
    for (const [method, path, body] of [
      ['GET', '/api/v1/guards', undefined],
      ['POST', '/api/v1/guards/dry-run', { action: 'x' }],
      ['GET', '/api/v1/modes', undefined],
      ['GET', '/api/v1/Approvals', undefined],
      ['GET', '/api/v1/not-a-route', undefined],
    ] as Array<[string, string, unknown]>) {
      const a = await call(method, path, t.adminKey, body)
      assert.equal(a.status, 403, `${method} ${path}`)
      assert.equal(a.json.code, 'tenant_admin_scope')
    }
    assert.equal((await call('GET', '/api/v1/guards', t.runtimeKey)).status, 200)
    assert.equal((await call('GET', '/api/v1/modes', t.runtimeKey)).status, 200)
  })
})

describe('regression: an admin key cannot leave a runtime key behind', () => {
  it('nothing the admin key can call mints a runtime key, before or after it expires', async () => {
    const t = await tenant()
    const before = runtimeKeyRows(t.id)

    // Every credential path an API key could try. Only issuance and login
    // mint keys, and both need the password, not a bearer key.
    const attempts: Array<[string, string, unknown]> = [
      ['POST', '/api/v1/account/rotate-key', {}],
      ['POST', '/api/v1/account/regenerate-key', {}],
      ['POST', '/auth/email/login', {}],
      ['POST', '/auth/email/login', { email: t.email }],
      ['POST', '/auth/tenant-admin/issue', { email: t.email }],
    ]
    for (const [m, p, b] of attempts) {
      const r = await call(m, p, t.adminKey, b)
      assert.ok(r.status === 401 || r.status === 403, `${p} -> ${r.status}`)
      assert.equal(r.json?.api_key, undefined, p)
    }
    assert.deepEqual(runtimeKeyRows(t.id), before)

    // Expire the admin key. The tenant's runtime keys are exactly the ones
    // it had before the admin key existed; none has an expiry tied to it.
    getDB().prepare(`UPDATE api_keys SET expires_at = ? WHERE tenant_id = ? AND key_class = 'tenant_admin'`)
      .run(new Date(Date.now() - 1).toISOString(), t.id)
    assert.equal(authenticateKey(t.adminKey), null)
    assert.equal((await call('GET', '/api/v1/account', t.adminKey)).status, 401)
    assert.equal((await call('POST', '/api/v1/account/rotate-key', t.adminKey, {})).status, 401)
    assert.deepEqual(runtimeKeyRows(t.id), before)
  })
})
