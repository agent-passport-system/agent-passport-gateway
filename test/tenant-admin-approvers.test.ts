// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Approver management through the tenant admin (approvers-router.ts),
// mounted the way server.ts mounts it: authMiddleware in front, real API
// keys, real tenants.
//
//   - a runtime key cannot register, list, revoke or widen approvers
//   - an expired tenant_admin key is refused
//   - the admin of tenant A cannot see or change tenant B's approvers
//   - authority ceiling: '*' and root wildcards refused, 33 entries refused
//   - end to end: issue admin -> register approver -> open (runtime key)
//     -> approver signs -> decide -> full receipt on the authenticated
//     route, with request_commitment and approver_evidence_digest kept out
//     of the public projection

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
import { createTenant, authMiddleware } from '../src/auth/api-keys.js'
import { hashPassword, setTenantPassword } from '../src/auth/email-password.js'
import { issueTenantAdminKey, TENANT_ADMIN_TTL_MS } from '../src/auth/tenant-admin.js'
import { createAuthRouter } from '../src/auth/auth-router.js'
import { approverAdminRouter } from '../src/gateway/approval/approvers-router.js'
import { approvalRouter } from '../src/gateway/approval/index.js'
import { setApprovalConnectorRouter } from '../src/gateway/approval/connector.js'
import { getActiveApprover, MAX_AUTHORITY_ENTRIES } from '../src/gateway/approval/approvers.js'
import { projectPublicBody } from '../src/gateway/receipt-projection.js'

const PASSWORD = 'correct horse battery staple'
let dbPath: string
let server: Server
let baseUrl: string

before(async () => {
  dbPath = join(tmpdir(), `aeoess-tenant-admin-approvers-${randomUUID()}.db`)
  initDB(dbPath)
  initGatewayIdentity()
  setApprovalConnectorRouter({
    async route(channel) {
      return { channel, sent: false, queued: true, transport: 'email_interim', routedAt: new Date().toISOString() }
    },
  })
  const app = express()
  app.use(express.json())
  app.use(createAuthRouter({ sendEmail: async () => ({ sent: false, queued: false }) }))
  app.use('/api/v1', authMiddleware, approverAdminRouter)
  app.use('/api/v1', authMiddleware, approvalRouter)
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
/** A tenant with a password, its signup runtime key and a tenant_admin key.
 *  viaRoute=true issues the admin key through POST /auth/tenant-admin/issue;
 *  otherwise issueTenantAdminKey is called directly, because the route is
 *  rate limited per IP (10 per 15 min) and this file makes many tenants. */
async function tenant(viaRoute = false): Promise<T> {
  const email = `appr-${randomUUID()}@test.local`
  const { tenant: t, apiKey } = createTenant({ name: 'n', email })
  setTenantPassword(t.id, await hashPassword(PASSWORD))
  if (!viaRoute) return { id: t.id, email, runtimeKey: apiKey, adminKey: issueTenantAdminKey(t.id).apiKey }
  const issued = await call('POST', '/auth/tenant-admin/issue', undefined, { email, password: PASSWORD })
  assert.equal(issued.status, 201, JSON.stringify(issued.json))
  return { id: t.id, email, runtimeKey: apiKey, adminKey: issued.json.api_key }
}

function approverBody(extra: Record<string, unknown> = {}) {
  const kp = generateKeyPair()
  return {
    kp,
    body: {
      approver_id: `appr-${randomUUID().slice(0, 8)}`, public_key: kp.publicKey,
      authority: ['payments:*'], principal_id: `treasury-${randomUUID().slice(0, 8)}`, ...extra,
    },
  }
}

describe('approver routes - runtime keys are refused', () => {
  it('a runtime key cannot register, list or revoke approvers', async () => {
    const t = await tenant(true)
    const { body } = approverBody()
    const reg = await call('POST', '/api/v1/approvers', t.runtimeKey, body)
    assert.equal(reg.status, 403)
    assert.equal(reg.json.code, 'tenant_admin_required')
    assert.equal(getActiveApprover(t.id, body.approver_id), undefined)

    const ok = await call('POST', '/api/v1/approvers', t.adminKey, body)
    assert.equal(ok.status, 201, JSON.stringify(ok.json))

    const list = await call('GET', '/api/v1/approvers', t.runtimeKey)
    assert.equal(list.status, 403)
    const rev = await call('POST', `/api/v1/approvers/${body.approver_id}/revoke`, t.runtimeKey, {})
    assert.equal(rev.status, 403)
    assert.ok(getActiveApprover(t.id, body.approver_id), 'still active')
  })

  it('a runtime key cannot widen an approver: no update route, re-register refused', async () => {
    const t = await tenant()
    const { body } = approverBody({ authority: ['read:*'] })
    assert.equal((await call('POST', '/api/v1/approvers', t.adminKey, body)).status, 201)
    const wider = { ...body, authority: ['read:*', 'payments:*'] }
    const viaRuntime = await call('POST', '/api/v1/approvers', t.runtimeKey, wider)
    assert.equal(viaRuntime.status, 403)
    for (const m of ['PUT', 'PATCH']) {
      const r = await call(m, `/api/v1/approvers/${body.approver_id}`, t.runtimeKey, wider)
      assert.ok(r.status === 403 || r.status === 404, `${m} -> ${r.status}`)
    }
    // Even the admin cannot widen in place: the id is taken.
    const viaAdmin = await call('POST', '/api/v1/approvers', t.adminKey, wider)
    assert.equal(viaAdmin.status, 409)
    assert.deepEqual(getActiveApprover(t.id, body.approver_id)!.authority, ['read:*'])
  })

  it('an expired tenant_admin key is refused', async () => {
    const t = await tenant()
    const stale = issueTenantAdminKey(t.id, Date.now() - TENANT_ADMIN_TTL_MS - 1)
    const r = await call('POST', '/api/v1/approvers', stale.apiKey, approverBody().body)
    assert.equal(r.status, 401)
  })

  it('the approver routes do not gate other /api/v1 routes', async () => {
    const t = await tenant()
    const r = await call('GET', '/api/v1/approvals', t.runtimeKey)
    assert.equal(r.status, 200)
  })
})

describe('approver routes - tenant isolation', () => {
  it('tenant A admin cannot list, revoke or shadow tenant B approvers', async () => {
    const A = await tenant()
    const B = await tenant()
    const { body } = approverBody()
    assert.equal((await call('POST', '/api/v1/approvers', B.adminKey, body)).status, 201)

    const listA = await call('GET', '/api/v1/approvers', A.adminKey)
    assert.equal(listA.status, 200)
    assert.equal(listA.json.approvers.some((x: any) => x.approver_id === body.approver_id), false)

    const revA = await call('POST', `/api/v1/approvers/${body.approver_id}/revoke`, A.adminKey, {})
    assert.equal(revA.status, 404)
    assert.ok(getActiveApprover(B.id, body.approver_id), 'B approver untouched')

    // Registering the same id under A creates an A-scoped row only.
    const { body: other } = approverBody({ approver_id: body.approver_id })
    assert.equal((await call('POST', '/api/v1/approvers', A.adminKey, other)).status, 201)
    assert.equal(getActiveApprover(B.id, body.approver_id)!.public_key, body.public_key)
    assert.equal(getActiveApprover(A.id, body.approver_id)!.public_key, other.public_key)

    // B's admin revokes its own.
    const revB = await call('POST', `/api/v1/approvers/${body.approver_id}/revoke`, B.adminKey, {})
    assert.equal(revB.status, 200)
    assert.equal(getActiveApprover(B.id, body.approver_id), undefined)
    assert.ok(getActiveApprover(A.id, body.approver_id), 'A row unaffected')
  })
})

describe('approver routes - authority ceiling', () => {
  for (const wildcard of [['*'], ['*:*'], [':*'], ['*:transfer'], ['payments:transfer:*'], ['read:*', '*']]) {
    it(`refuses ${JSON.stringify(wildcard)} with 400`, async () => {
      const t = await tenant()
      const { body } = approverBody({ authority: wildcard })
      const r = await call('POST', '/api/v1/approvers', t.adminKey, body)
      assert.equal(r.status, 400)
      assert.equal(r.json.code, 'authority_wildcard')
      assert.equal(getActiveApprover(t.id, body.approver_id), undefined)
    })
  }

  it('refuses 33 entries and accepts 32', async () => {
    const t = await tenant()
    const entries = (n: number) => Array.from({ length: n }, (_, i) => `ops:task${i}`)
    assert.equal(MAX_AUTHORITY_ENTRIES, 32)
    const over = approverBody({ authority: entries(33) })
    const r = await call('POST', '/api/v1/approvers', t.adminKey, over.body)
    assert.equal(r.status, 400)
    assert.equal(r.json.code, 'authority_too_many')
    const at = approverBody({ authority: entries(32) })
    assert.equal((await call('POST', '/api/v1/approvers', t.adminKey, at.body)).status, 201)
  })

  it('refuses entries outside the action-class grammar and normalizes case', async () => {
    const t = await tenant()
    for (const bad of [[], ['pay ments'], ['payments::x'], [''], [42], 'payments:*']) {
      const r = await call('POST', '/api/v1/approvers', t.adminKey, approverBody({ authority: bad }).body)
      assert.equal(r.status, 400, JSON.stringify(bad))
      assert.equal(r.json.code, 'authority_invalid', JSON.stringify(bad))
    }
    const ok = approverBody({ authority: [' Payments:Refund ', 'data', 'read:*'] })
    const r = await call('POST', '/api/v1/approvers', t.adminKey, ok.body)
    assert.equal(r.status, 201)
    assert.deepEqual(r.json.authority, ['payments:refund', 'data', 'read:*'])
  })
})

describe('end to end: issue admin, register, sign, decide, receipt', () => {
  it('works through the real key classes and keeps commitment fields out of the public projection', async () => {
    const t = await tenant(true)
    const agentKp = generateKeyPair()
    getDB().prepare(`INSERT INTO agents (id, tenant_id, agent_id, public_key, status, entity_id) VALUES (?, ?, ?, ?, 'active', ?)`)
      .run(randomUUID(), t.id, 'agent-e2e', agentKp.publicKey, 'entity-owner')

    const { kp, body } = approverBody({ principal_id: 'treasury-office', office_id: 'treasury' })
    const reg = await call('POST', '/api/v1/approvers', t.adminKey, body)
    assert.equal(reg.status, 201)
    assert.match(reg.json.registered_by, /^tenant_admin:/)
    const list = await call('GET', '/api/v1/approvers', t.adminKey)
    assert.equal(list.json.approvers.length, 1)

    // The runtime key opens and relays; the approver signs with its own key.
    const open = await call('POST', '/api/v1/approvals', t.runtimeKey, {
      action_class: 'payments:transfer', subject: 'invoice-e2e', agent_id: 'agent-e2e',
      requested_by: 'billing-bot', requested_scope: ['payments:transfer:max=100'],
    })
    assert.equal(open.status, 201, JSON.stringify(open.json))
    const id = open.json.id
    const detail = await call('GET', `/api/v1/approvals/${id}`, t.runtimeKey)
    assert.equal(detail.status, 200)
    assert.ok(detail.json.requested_by_key_id, 'opening key id recorded server-side')

    const signature = edSign(detail.json.commitment.message, kp.privateKey)
    const s = await call('POST', `/api/v1/approvals/${id}/sign`, t.runtimeKey, {
      approver_id: body.approver_id, reason: 'payee and cap checked', signature,
    })
    assert.equal(s.status, 201, JSON.stringify(s.json))

    const d = await call('POST', `/api/v1/approvals/${id}/decide`, t.runtimeKey, {
      verdict: 'approved', reason: 'outside approver signed', decided_by: 'ops',
    })
    assert.equal(d.status, 200, JSON.stringify(d.json))

    // D5: the tenant gets the full signed receipt on the authenticated route.
    const rc = await call('GET', `/api/v1/approvals/${id}/receipt`, t.runtimeKey)
    assert.equal(rc.status, 200)
    assert.equal(rc.json.payload.request_commitment, detail.json.commitment.digest)
    assert.match(rc.json.payload.approver_evidence_digest, /^[0-9a-f]{64}$/)
    assert.ok(rc.json.signature, 'gateway signature returned with the payload')

    // Another tenant cannot read it.
    const other = await tenant()
    assert.equal((await call('GET', `/api/v1/approvals/${id}/receipt`, other.runtimeKey)).status, 404)
    // Unauthenticated callers get 401 on this route.
    assert.equal((await call('GET', `/api/v1/approvals/${id}/receipt`)).status, 401)

    // The public projection of the same stored payload drops both fields.
    const row = getDB().prepare(`SELECT * FROM approval_receipts WHERE request_id = ?`).get(id) as any
    const projected = projectPublicBody('approval_receipt', row, JSON.parse(row.payload))
    assert.equal(projected.request_commitment, undefined)
    assert.equal(projected.approver_evidence_digest, undefined)
    assert.equal(projected.verdict, 'approved')
  })
})
