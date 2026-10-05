// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// G-C3 Scoped Human Approval - tests.
//
// Approval is SCOPED AUTHORITY, not a rubber-stamp button. These tests
// cover the five required controls:
//   1. approver scope check (must hold authority for the action class)
//   2. expiry (short TTL; expired requests cannot be decided)
//   3. no bulk approvals for high-risk
//   4. approver-outside-owner for high-risk
//   5. approval receipt issued + signed + projects PII-free
//
// The pure policy gate is tested directly; the lifecycle is tested through
// the real Express router against an in-memory DB.

import { describe, it, before, after, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import express from 'express'
import type { Server } from 'node:http'
import { initDB, getDB } from '../src/db/schema.js'
import { initGatewayIdentity } from '../src/gateway/identity.js'
import { approvalRouter } from '../src/gateway/approval/index.js'
import {
  classifyRisk, checkScopedAuthority, approverHoldsAuthority,
  clampTtlSeconds, isHighRiskTier, TIER_RULES,
} from '../src/gateway/approval/policy.js'
import { projectPublicBody, PUBLIC_BODY_WHITELISTS } from '../src/gateway/receipt-projection.js'
import { setApprovalConnectorRouter } from '../src/gateway/approval/connector.js'
import { clearApprovalFatigueStores } from '../src/sdk-migrated/v2/approval-fatigue.js'
import { registerApprover } from '../src/gateway/approval/approvers.js'
import { approvalCommitment } from '../src/gateway/approval/commitment.js'
import { getRequest } from '../src/gateway/approval/store.js'
import { generateKeyPair, sign as edSign } from 'agent-passport-system'

const TENANT = 'tenant-c3'
const OWNER_ENTITY = 'entity-owner'
const AGENT = 'agent-x'

// ── Test harness: in-memory DB + a mounted approval router ──

let server: Server
let baseUrl: string

function seedAgent(agentId: string, entityId: string | null) {
  const db = getDB()
  db.prepare(
    `INSERT OR IGNORE INTO tenants (id, name, email) VALUES (?, ?, ?)`
  ).run(TENANT, 'C3 Test', `c3-${Math.random().toString(36).slice(2)}@test.local`)
  db.prepare(
    `INSERT INTO agents (id, tenant_id, agent_id, public_key, status, entity_id)
     VALUES (?, ?, ?, ?, 'active', ?)`
  ).run(`row-${agentId}`, TENANT, agentId, 'pubkey-hex', entityId)
}

before(async () => {
  initDB(':memory:')
  initGatewayIdentity()
  // Silence the interim email transport so tests do not touch the queue file.
  setApprovalConnectorRouter({
    async route(channel) {
      return { channel, sent: false, queued: true, transport: 'email_interim', routedAt: new Date().toISOString() }
    },
  })

  const app = express()
  app.use(express.json())
  // Stub auth: inject a fixed tenant the way authMiddleware would.
  app.use((req: any, _res, next) => { req.tenant = { id: TENANT, role: 'user' }; next() })
  app.use('/api/v1', approvalRouter)

  await new Promise<void>((resolve) => {
    server = app.listen(0, () => {
      const addr = server.address()
      const port = typeof addr === 'object' && addr ? addr.port : 0
      baseUrl = `http://127.0.0.1:${port}/api/v1`
      resolve()
    })
  })

  seedAgent(AGENT, OWNER_ENTITY)
})

after(() => { server?.close() })

beforeEach(() => { clearApprovalFatigueStores() })

async function post(path: string, body: unknown) {
  const r = await fetch(`${baseUrl}${path}`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  })
  return { status: r.status, json: await r.json() as any }
}
async function get(path: string) {
  const r = await fetch(`${baseUrl}${path}`)
  return { status: r.status, json: await r.json() as any }
}

// Approvers are resolved from the registry and must sign the request
// commitment with their registered key (approvers.ts, commitment.ts).
type Kp = { publicKey: string; privateKey: string }
function registerTestApprover(approverId: string, authority: string[], principalId = `principal-${approverId}`): Kp {
  const kp = generateKeyPair()
  registerApprover({
    tenantId: TENANT, approverId, publicKey: kp.publicKey, authority,
    principalId, registeredBy: 'test-operator',
  })
  return kp
}
function commitSig(requestId: string, kp: Kp): string {
  return edSign(approvalCommitment(getRequest(TENANT, requestId)!).message, kp.privateKey)
}
/** Move created_at back so the server-measured review interval clears the
 *  impossible-latency floor (created_at is not part of the commitment). */
function backdate(requestId: string, ms = 60_000) {
  getDB().prepare(`UPDATE approval_requests SET created_at = ? WHERE id = ?`)
    .run(new Date(Date.now() - ms).toISOString(), requestId)
}

// ─────────────────────────────────────────────────────────────────────
// 1. Approver scope check (pure)
// ─────────────────────────────────────────────────────────────────────

describe('policy - approver scope check', () => {
  it('matches exact class, head segment, and glob', () => {
    assert.equal(approverHoldsAuthority(['payments:*'], 'payments:refund'), true)
    assert.equal(approverHoldsAuthority(['data'], 'data:export'), true)
    assert.equal(approverHoldsAuthority(['payments:refund'], 'payments:refund'), true)
    assert.equal(approverHoldsAuthority(['*'], 'anything:here'), true)
  })

  it('refuses when the approver lacks authority for the class', () => {
    assert.equal(approverHoldsAuthority(['read:*'], 'payments:refund'), false)
    assert.equal(approverHoldsAuthority([], 'payments:refund'), false)
  })

  it('checkScopedAuthority returns authority_missing when no authority held', () => {
    const r = checkScopedAuthority({
      actionClass: 'payments:refund', tier: 'high',
      approverAuthority: ['read:*'], approverId: 'a1',
      agentOwnerId: 'owner', batchSize: 1,
    })
    assert.equal(r.allowed, false)
    assert.equal(r.code, 'authority_missing')
  })

  it('allows when authority is held and the high-risk rules pass', () => {
    const r = checkScopedAuthority({
      actionClass: 'payments:refund', tier: 'high',
      approverAuthority: ['payments:*'], approverId: 'outsider',
      agentOwnerId: 'owner', batchSize: 1,
    })
    assert.equal(r.allowed, true)
  })
})

// ─────────────────────────────────────────────────────────────────────
// 2. Risk classification + TTL clamping
// ─────────────────────────────────────────────────────────────────────

describe('policy - risk classification and TTL', () => {
  it('classifies known and unknown classes (unknown is fail-safe high)', () => {
    assert.equal(classifyRisk('read:files'), 'low')
    assert.equal(classifyRisk('payments:refund'), 'high')
    assert.equal(classifyRisk('revoke:delegation'), 'critical')
    assert.equal(classifyRisk('totally-unknown-class'), 'high')
  })

  it('high and critical are high-risk tiers; low and medium are not', () => {
    assert.equal(isHighRiskTier('high'), true)
    assert.equal(isHighRiskTier('critical'), true)
    assert.equal(isHighRiskTier('low'), false)
    assert.equal(isHighRiskTier('medium'), false)
  })

  it('clamps requested TTL to the tier ceiling and never extends it', () => {
    // critical ceiling is 300s
    assert.equal(clampTtlSeconds('critical', 99999), TIER_RULES.critical.ttlSeconds)
    assert.equal(clampTtlSeconds('critical', 120), 120)
    assert.equal(clampTtlSeconds('high', undefined), TIER_RULES.high.ttlSeconds)
  })
})

// ─────────────────────────────────────────────────────────────────────
// 3. No bulk approvals for high-risk (pure + route)
// ─────────────────────────────────────────────────────────────────────

describe('no bulk approvals for high-risk', () => {
  it('checkScopedAuthority refuses batchSize > 1 on high-risk', () => {
    const r = checkScopedAuthority({
      actionClass: 'payments:refund', tier: 'high',
      approverAuthority: ['payments:*'], approverId: 'outsider',
      agentOwnerId: 'owner', batchSize: 5,
    })
    assert.equal(r.allowed, false)
    assert.equal(r.code, 'bulk_high_risk')
  })

  it('allows bulk on a low-risk tier', () => {
    const r = checkScopedAuthority({
      actionClass: 'read:files', tier: 'low',
      approverAuthority: ['read:*'], approverId: 'someone',
      agentOwnerId: 'owner', batchSize: 10,
    })
    assert.equal(r.allowed, true)
  })

  it('route: POST /approvals/:id/sign with batch_size>1 on high-risk is 403 bulk_high_risk', async () => {
    const created = await post('/approvals', {
      action_class: 'payments:refund', subject: 'inv-1',
      agent_id: AGENT, requested_by: 'requester',
    })
    assert.equal(created.status, 201)
    assert.equal(created.json.risk_tier, 'high')
    const kp = registerTestApprover('outsider-bulk', ['payments:*'])
    backdate(created.json.id)
    const signed = await post(`/approvals/${created.json.id}/sign`, {
      approver_id: 'outsider-bulk', reason: 'reviewed the refund batch',
      signature: commitSig(created.json.id, kp), batch_size: 12,
    })
    assert.equal(signed.status, 403)
    assert.equal(signed.json.code, 'bulk_high_risk')
  })
})

// ─────────────────────────────────────────────────────────────────────
// 4. Approver-outside-owner for high-risk (pure + route)
// ─────────────────────────────────────────────────────────────────────

describe('approver-outside-owner for high-risk', () => {
  it('checkScopedAuthority refuses self-approval on high-risk', () => {
    const r = checkScopedAuthority({
      actionClass: 'payments:refund', tier: 'high',
      approverAuthority: ['payments:*'], approverId: 'owner',
      agentOwnerId: 'owner', batchSize: 1,
    })
    assert.equal(r.allowed, false)
    assert.equal(r.code, 'self_approval_high_risk')
  })

  it('permits self-approval on a low-risk tier', () => {
    const r = checkScopedAuthority({
      actionClass: 'read:files', tier: 'low',
      approverAuthority: ['read:*'], approverId: 'owner',
      agentOwnerId: 'owner', batchSize: 1,
    })
    assert.equal(r.allowed, true)
  })

  it('route: owner signing their own agent high-risk request is 403 self_approval_high_risk', async () => {
    const created = await post('/approvals', {
      action_class: 'payments:refund', subject: 'inv-2',
      agent_id: AGENT, requested_by: 'requester',
    })
    assert.equal(created.status, 201)
    // The agent owner entity is OWNER_ENTITY; approver_id == owner => refuse.
    const kp = registerTestApprover(OWNER_ENTITY, ['payments:*'], OWNER_ENTITY)
    backdate(created.json.id)
    const signed = await post(`/approvals/${created.json.id}/sign`, {
      approver_id: OWNER_ENTITY, reason: 'I own this agent',
      signature: commitSig(created.json.id, kp), batch_size: 1,
    })
    assert.equal(signed.status, 403)
    assert.equal(signed.json.code, 'self_approval_high_risk')
  })

  it('route: an outside approver with authority can sign the high-risk request', async () => {
    const created = await post('/approvals', {
      action_class: 'payments:refund', subject: 'inv-3',
      agent_id: AGENT, requested_by: 'requester',
    })
    const kp = registerTestApprover('outsider-1', ['payments:*'])
    backdate(created.json.id)
    const signed = await post(`/approvals/${created.json.id}/sign`, {
      approver_id: 'outsider-1', reason: 'verified payee and amount',
      signature: commitSig(created.json.id, kp), batch_size: 1,
    })
    assert.equal(signed.status, 201)
    assert.ok(signed.json.signature_id)
  })

  it('route: missing reason is rejected (a reason is required)', async () => {
    const created = await post('/approvals', {
      action_class: 'payments:refund', subject: 'inv-4',
      agent_id: AGENT, requested_by: 'requester',
    })
    const kp = registerTestApprover('outsider-2', ['payments:*'])
    backdate(created.json.id)
    const signed = await post(`/approvals/${created.json.id}/sign`, {
      approver_id: 'outsider-2', signature: commitSig(created.json.id, kp), batch_size: 1,
    })
    assert.equal(signed.status, 400)
  })
})

// ─────────────────────────────────────────────────────────────────────
// 5. Expiry
// ─────────────────────────────────────────────────────────────────────

describe('expiry', () => {
  it('a request whose expiry has passed cannot be decided and sweeps to expired', async () => {
    const created = await post('/approvals', {
      action_class: 'payments:refund', subject: 'inv-exp',
      agent_id: AGENT, requested_by: 'requester',
    })
    assert.equal(created.status, 201)
    // Force the row to be already expired.
    getDB().prepare(
      `UPDATE approval_requests SET expires_at = ? WHERE id = ?`
    ).run('2000-01-01T00:00:00.000Z', created.json.id)

    // A GET sweeps expired requests to status 'expired'.
    const detail = await get(`/approvals/${created.json.id}`)
    assert.equal(detail.json.status, 'expired')

    // Decide must refuse with 409.
    const decided = await post(`/approvals/${created.json.id}/decide`, {
      verdict: 'approved', reason: 'too late', decided_by: 'admin',
    })
    assert.equal(decided.status, 409)
  })

  it('TTL is short by tier: critical <= high <= medium <= low', () => {
    assert.ok(TIER_RULES.critical.ttlSeconds <= TIER_RULES.high.ttlSeconds)
    assert.ok(TIER_RULES.high.ttlSeconds <= TIER_RULES.medium.ttlSeconds)
    assert.ok(TIER_RULES.medium.ttlSeconds <= TIER_RULES.low.ttlSeconds)
  })
})

// ─────────────────────────────────────────────────────────────────────
// 6. Approval receipt issued + signed + PII-free projection
// ─────────────────────────────────────────────────────────────────────

describe('approval receipt issued', () => {
  it('a decided (approved) request issues a signed receipt with a hash', async () => {
    const created = await post('/approvals', {
      action_class: 'payments:refund', subject: 'inv-receipt',
      agent_id: AGENT, requested_by: 'requester',
      requested_scope: ['payments:refund:inv-receipt'],
    })
    assert.equal(created.status, 201)

    const kp = registerTestApprover('outsider-r', ['payments:*'])
    backdate(created.json.id)
    const signed = await post(`/approvals/${created.json.id}/sign`, {
      approver_id: 'outsider-r', reason: 'amount and payee verified against the invoice',
      batch_size: 1, signature: commitSig(created.json.id, kp),
    })
    assert.equal(signed.status, 201)

    const decided = await post(`/approvals/${created.json.id}/decide`, {
      verdict: 'approved', reason: 'one approver with authority signed', decided_by: 'admin',
    })
    assert.equal(decided.status, 200)
    assert.equal(decided.json.status, 'approved')
    assert.ok(decided.json.receipt_id)
    assert.ok(/^[0-9a-f]{64}$/.test(decided.json.receipt_hash))

    // The receipt is fetchable, signed, and references the JWKS resolver.
    const rcpt = await get(`/approvals/${created.json.id}/receipt`)
    assert.equal(rcpt.status, 200)
    assert.ok(rcpt.json.signature, 'receipt is signed by the gateway identity')
    assert.equal(rcpt.json.jwks_url, '/.well-known/jwks.json')
    assert.equal(rcpt.json.payload.proof_type, 'approval_receipt')
    assert.equal(rcpt.json.payload.verdict, 'approved')
    assert.equal(rcpt.json.payload.action_class, 'payments:refund')
    // Claims discipline: verifier-derived assurance, no compliance claim.
    assert.match(rcpt.json.payload.statement, /supports evidence for/)
  })

  it('cannot approve with zero approver signatures (no rubber-stamp button)', async () => {
    const created = await post('/approvals', {
      action_class: 'payments:refund', subject: 'inv-nosig',
      agent_id: AGENT, requested_by: 'requester',
    })
    const decided = await post(`/approvals/${created.json.id}/decide`, {
      verdict: 'approved', reason: 'trying to skip the approver', decided_by: 'admin',
    })
    assert.equal(decided.status, 409)
  })

  it('public projection of an approval_receipt drops reason text and approver PII', () => {
    // The whitelist must NOT contain reason, approver ids, raw keys, tenant.
    const wl = PUBLIC_BODY_WHITELISTS['approval_receipt']
    assert.ok(wl, 'approval_receipt whitelist registered')
    for (const banned of ['reason', 'approver_id', 'approver_public_key', 'tenant_id', 'decided_by', 'requested_by']) {
      assert.ok(!wl.includes(banned), `whitelist must not expose ${banned}`)
    }
    // A payload carrying secrets is projected down to safe fields only.
    const projected = projectPublicBody('approval_receipt', { id: 'r1', created_at: 'now' }, {
      proof_type: 'approval_receipt', action_class: 'payments:refund',
      risk_tier: 'high', verdict: 'approved', scope_hash: 'abc',
      receipt_hash: 'def', reason: 'SECRET REASON', approver_id: 'SECRET-APPROVER',
      tenant_id: 'SECRET-TENANT',
    })
    assert.equal(projected.action_class, 'payments:refund')
    assert.equal(projected.verdict, 'approved')
    assert.equal(projected.reason, undefined)
    assert.equal(projected.approver_id, undefined)
    assert.equal(projected.tenant_id, undefined)
  })
})

// ─────────────────────────────────────────────────────────────────────
// 7. Tenant isolation + not-found
// ─────────────────────────────────────────────────────────────────────

describe('isolation and lifecycle guards', () => {
  it('signing an unknown request id is 404', async () => {
    const signed = await post('/approvals/does-not-exist/sign', {
      approver_id: 'a', reason: 'x reason', signature: '00',
    })
    assert.equal(signed.status, 404)
  })

  it('opening a request for an unknown agent is 404', async () => {
    const created = await post('/approvals', {
      action_class: 'read:files', subject: 's', agent_id: 'ghost-agent', requested_by: 'r',
    })
    assert.equal(created.status, 404)
  })

  it('a duplicate approver key on the same request is 409', async () => {
    const created = await post('/approvals', {
      action_class: 'read:files', subject: 'dup', agent_id: AGENT, requested_by: 'r',
    })
    const kp = registerTestApprover('dup-app', ['read:*'])
    backdate(created.json.id)
    const first = await post(`/approvals/${created.json.id}/sign`, {
      approver_id: 'dup-app', reason: 'first signature here',
      signature: commitSig(created.json.id, kp),
    })
    assert.equal(first.status, 201)
    const second = await post(`/approvals/${created.json.id}/sign`, {
      approver_id: 'dup-app', reason: 'second time same key',
      signature: commitSig(created.json.id, kp),
    })
    assert.equal(second.status, 409)
  })
})
