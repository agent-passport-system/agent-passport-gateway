// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// G-C3 Scoped Human Approval - approver binding tests.
//
// The approver principal, key and authority come from the approver registry,
// never from the /sign body. The approver signature is required and must
// verify, under the registered key, over the request commitment. Decide
// re-verifies against the row as it is at decide time. The receipt carries
// the request commitment and a digest over the verified approver evidence.
// Also: the revocation cascade preview counts pending approvals for the agent.

import { describe, it, before, after, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import express from 'express'
import type { Server } from 'node:http'
import { generateKeyPair, sign as edSign, canonicalizeJCS } from 'agent-passport-system'
import { initDB, getDB } from '../src/db/schema.js'
import { initGatewayIdentity, getJwks } from '../src/gateway/identity.js'
import { approvalRouter } from '../src/gateway/approval/index.js'
import { setApprovalConnectorRouter } from '../src/gateway/approval/connector.js'
import { registerApprover, revokeApprover } from '../src/gateway/approval/approvers.js'
import {
  approvalCommitment, verifyApproverSignature, approverKeyId, approverEvidenceDigest,
  APPROVAL_COMMITMENT_DOMAIN,
} from '../src/gateway/approval/commitment.js'
import { getRequest, decideRequest, type ApprovalRequestRow } from '../src/gateway/approval/store.js'
import { previewCascade } from '../src/gateway/revocation/cascade.js'
import { clearApprovalFatigueStores, getApprovalHistory } from '../src/sdk-migrated/v2/approval-fatigue.js'

const TENANT = 'tenant-binding'
const OWNER = 'entity-owner'
const AGENT = 'agent-pay'
const AGENT_KP = generateKeyPair()
// api_keys.id of the key the harness authenticates as (the requester key).
const REQUESTER_KEY_ID = 'key-runtime-requester'

let server: Server
let baseUrl: string

before(async () => {
  initDB(':memory:')
  initGatewayIdentity()
  setApprovalConnectorRouter({
    async route(channel) {
      return { channel, sent: false, queued: true, transport: 'email_interim', routedAt: new Date().toISOString() }
    },
  })
  const db = getDB()
  db.prepare(`INSERT OR IGNORE INTO tenants (id, name, email) VALUES (?, ?, ?)`).run(TENANT, 'binding', 'binding@test.local')
  db.prepare(`INSERT INTO agents (id, tenant_id, agent_id, public_key, status, entity_id) VALUES (?, ?, ?, ?, 'active', ?)`)
    .run('row-agent-pay', TENANT, AGENT, AGENT_KP.publicKey, OWNER)

  const app = express()
  app.use(express.json())
  app.use((req: any, _res, next) => { req.tenant = { id: TENANT, role: 'user', key_class: 'runtime', key_id: REQUESTER_KEY_ID }; next() })
  app.use('/api/v1', approvalRouter)
  await new Promise<void>((r) => {
    server = app.listen(0, '127.0.0.1', () => {
      const a = server.address() as any
      baseUrl = `http://127.0.0.1:${a.port}/api/v1`
      r()
    })
  })
})
after(() => { server?.close() })
beforeEach(() => { clearApprovalFatigueStores() })

async function call(method: string, path: string, body?: unknown) {
  const r = await fetch(`${baseUrl}${path}`, {
    method, headers: { 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  let json: any = null
  try { json = await r.json() } catch { json = null }
  return { status: r.status, json }
}

type Kp = { publicKey: string; privateKey: string }
let seq = 0
function approver(authority: string[], principalId?: string, publicKey?: string): { id: string; kp: Kp } {
  const id = `approver-${++seq}`
  const kp = generateKeyPair()
  registerApprover({
    tenantId: TENANT, approverId: id, publicKey: publicKey ?? kp.publicKey, authority,
    principalId: principalId ?? `principal-${id}`, registeredBy: 'test-operator',
  })
  return { id, kp }
}
async function open(extra: Record<string, unknown> = {}) {
  const r = await call('POST', '/approvals', {
    action_class: 'payments:transfer', subject: `invoice-${++seq}`, agent_id: AGENT,
    requested_by: 'requester-1', requested_scope: ['payments:transfer:max=100', 'payments:transfer:to=acct-A'],
    ...extra,
  })
  assert.equal(r.status, 201, JSON.stringify(r.json))
  return r.json.id as string
}
function backdate(id: string, ms = 60_000) {
  getDB().prepare(`UPDATE approval_requests SET created_at = ? WHERE id = ?`)
    .run(new Date(Date.now() - ms).toISOString(), id)
}
function sigFor(id: string, kp: Kp) {
  return edSign(approvalCommitment(getRequest(TENANT, id)!).message, kp.privateKey)
}
function receiptCount(id: string) {
  return (getDB().prepare(`SELECT COUNT(*) c FROM approval_receipts WHERE request_id = ?`).get(id) as any).c as number
}

// ─────────────────────────────────────────────────────────────────────
// Commitment (pure)
// ─────────────────────────────────────────────────────────────────────

const baseRow = {
  tenant_id: 't1', id: 'req-1', agent_id: 'a1', subject: 'invoice-9',
  subject_type: 'delegation', action_class: 'payments:transfer',
  requested_scope: JSON.stringify(['b-scope', 'a-scope']), risk_tier: 'high' as const,
  expires_at: '2026-10-05T12:00:00.000Z',
}

describe('approval commitment', () => {
  it('is the domain prefix followed by the JCS of the bound fields, scope sorted', () => {
    const c = approvalCommitment(baseRow)
    assert.equal(c.scheme, APPROVAL_COMMITMENT_DOMAIN)
    assert.equal(c.message, `${APPROVAL_COMMITMENT_DOMAIN}.` + canonicalizeJCS({
      tenant_id: 't1', request_id: 'req-1', agent_id: 'a1', subject: 'invoice-9',
      subject_type: 'delegation', action_class: 'payments:transfer',
      requested_scope: ['a-scope', 'b-scope'], risk_tier: 'high',
      expires_at: '2026-10-05T12:00:00.000Z',
    }))
    assert.equal(c.digest, crypto.createHash('sha256').update(c.message).digest('hex'))
  })

  it('does not depend on stored scope order', () => {
    const a = approvalCommitment(baseRow)
    const b = approvalCommitment({ ...baseRow, requested_scope: JSON.stringify(['a-scope', 'b-scope']) })
    assert.equal(a.digest, b.digest)
  })

  it('changes when any bound field changes', () => {
    const base = approvalCommitment(baseRow).digest
    const variants: Array<Partial<typeof baseRow>> = [
      { tenant_id: 't2' }, { id: 'req-2' }, { agent_id: 'a2' }, { subject: 'invoice-10' },
      { subject_type: 'artifact' }, { action_class: 'payments:refund' },
      { requested_scope: JSON.stringify(['a-scope']) }, { risk_tier: 'critical' as any },
      { expires_at: '2026-10-05T12:00:01.000Z' },
    ]
    for (const v of variants) {
      assert.notEqual(approvalCommitment({ ...baseRow, ...v } as any).digest, base, JSON.stringify(v))
    }
  })

  it('a signature verifies only under the signing key and only over the same commitment', () => {
    const kp = generateKeyPair()
    const other = generateKeyPair()
    const c = approvalCommitment(baseRow)
    const sig = edSign(c.message, kp.privateKey)
    assert.equal(verifyApproverSignature(c, sig, kp.publicKey), true)
    assert.equal(verifyApproverSignature(c, sig, other.publicKey), false)
    assert.equal(verifyApproverSignature(approvalCommitment({ ...baseRow, subject: 'x' }), sig, kp.publicKey), false)
    assert.equal(verifyApproverSignature(c, '', kp.publicKey), false)
    assert.equal(verifyApproverSignature(c, undefined, kp.publicKey), false)
    // Without the domain prefix the same JSON does not verify.
    const bare = edSign(c.message.slice(APPROVAL_COMMITMENT_DOMAIN.length + 1), kp.privateKey)
    assert.equal(verifyApproverSignature(c, bare, kp.publicKey), false)
  })

  it('evidence digest is order-independent and binds the commitment', () => {
    const e1 = { approver_id: 'x', key_id: 'k1', signature: 's1' }
    const e2 = { approver_id: 'y', key_id: 'k2', signature: 's2' }
    assert.equal(approverEvidenceDigest('d', [e1, e2]), approverEvidenceDigest('d', [e2, e1]))
    assert.notEqual(approverEvidenceDigest('d', [e1]), approverEvidenceDigest('d2', [e1]))
    assert.notEqual(approverEvidenceDigest('d', [e1]), approverEvidenceDigest('d', [{ ...e1, signature: 's9' }]))
  })
})

// ─────────────────────────────────────────────────────────────────────
// /sign: approver binding
// ─────────────────────────────────────────────────────────────────────

describe('sign - approver resolved from registry and signature verified', () => {
  it('an invalid signature fails', async () => {
    const a = approver(['payments:*'])
    const id = await open(); backdate(id)
    const r = await call('POST', `/approvals/${id}/sign`, { approver_id: a.id, reason: 'reviewed it', signature: 'not-a-signature' })
    assert.equal(r.status, 403)
    assert.equal(r.json.code, 'approver_signature_invalid')
  })

  it('an empty or missing signature fails', async () => {
    const a = approver(['payments:*'])
    const id = await open(); backdate(id)
    const empty = await call('POST', `/approvals/${id}/sign`, { approver_id: a.id, reason: 'reviewed it', signature: '' })
    assert.equal(empty.status, 400)
    assert.equal(empty.json.code, 'signature_required')
    const missing = await call('POST', `/approvals/${id}/sign`, { approver_id: a.id, reason: 'reviewed it' })
    assert.equal(missing.status, 400)
  })

  it('an unregistered approver fails', async () => {
    const id = await open(); backdate(id)
    const kp = generateKeyPair()
    const r = await call('POST', `/approvals/${id}/sign`, {
      approver_id: 'never-registered', reason: 'reviewed it', signature: sigFor(id, kp),
    })
    assert.equal(r.status, 403)
    assert.equal(r.json.code, 'approver_not_registered')
  })

  it('a signature by an unregistered key fails under a registered approver id', async () => {
    const a = approver(['payments:*'])
    const id = await open(); backdate(id)
    const attacker = generateKeyPair()
    const r = await call('POST', `/approvals/${id}/sign`, {
      approver_id: a.id, reason: 'reviewed it', signature: sigFor(id, attacker),
    })
    assert.equal(r.status, 403)
    assert.equal(r.json.code, 'approver_signature_invalid')
  })

  it('a registered key signing a different request commitment fails', async () => {
    const a = approver(['payments:*'])
    const idA = await open(); const idB = await open(); backdate(idB)
    const r = await call('POST', `/approvals/${idB}/sign`, { approver_id: a.id, reason: 'reviewed it', signature: sigFor(idA, a.kp) })
    assert.equal(r.status, 403)
    assert.equal(r.json.code, 'approver_signature_invalid')
  })

  it('an approver registered under the owner principal (owner alias) fails', async () => {
    const a = approver(['payments:*'], OWNER)
    const id = await open(); backdate(id)
    const r = await call('POST', `/approvals/${id}/sign`, { approver_id: a.id, reason: 'reviewed it', signature: sigFor(id, a.kp) })
    assert.equal(r.status, 403)
    assert.equal(r.json.code, 'self_approval_high_risk')
  })

  it('an approver whose principal is the requesting key (server-recorded) fails', async () => {
    const a = approver(['payments:*'], REQUESTER_KEY_ID)
    const id = await open(); backdate(id)
    assert.equal(getRequest(TENANT, id)!.requested_by_key_id, REQUESTER_KEY_ID)
    const r = await call('POST', `/approvals/${id}/sign`, { approver_id: a.id, reason: 'reviewed it', signature: sigFor(id, a.kp) })
    assert.equal(r.status, 403)
    assert.equal(r.json.code, 'self_approval_high_risk')
  })

  it('an approver whose principal is the agent itself fails', async () => {
    const a = approver(['payments:*'], AGENT)
    const id = await open(); backdate(id)
    const r = await call('POST', `/approvals/${id}/sign`, { approver_id: a.id, reason: 'reviewed it', signature: sigFor(id, a.kp) })
    assert.equal(r.status, 403)
    assert.equal(r.json.code, 'self_approval_high_risk')
  })

  it('the caller-supplied requested_by label is not compared', async () => {
    // Same string as the body requested_by, but nothing registered ties it
    // to the requester, so it is not an identity the check can rely on.
    const a = approver(['payments:*'], 'requester-1')
    const id = await open(); backdate(id)
    const r = await call('POST', `/approvals/${id}/sign`, { approver_id: a.id, reason: 'reviewed it', signature: sigFor(id, a.kp) })
    assert.equal(r.status, 201, JSON.stringify(r.json))
  })

  it('an approver registered with the agent own key fails', async () => {
    const id_ = `approver-agentkey-${++seq}`
    registerApprover({
      tenantId: TENANT, approverId: id_, publicKey: AGENT_KP.publicKey, authority: ['payments:*'],
      principalId: 'looks-outside', registeredBy: 'test-operator',
    })
    const id = await open(); backdate(id)
    const r = await call('POST', `/approvals/${id}/sign`, { approver_id: id_, reason: 'reviewed it', signature: sigFor(id, AGENT_KP) })
    assert.equal(r.status, 403)
    assert.equal(r.json.code, 'self_approval_high_risk')
  })

  it('registry authority decides: an approver without it is refused', async () => {
    const a = approver(['read:*'])
    const id = await open(); backdate(id)
    const r = await call('POST', `/approvals/${id}/sign`, { approver_id: a.id, reason: 'reviewed it', signature: sigFor(id, a.kp) })
    assert.equal(r.status, 403)
    assert.equal(r.json.code, 'authority_missing')
  })

  it('an approver key cannot be registered twice under an alias id', () => {
    const a = approver(['payments:*'])
    assert.throws(() => registerApprover({
      tenantId: TENANT, approverId: `${a.id}-alias`, publicKey: a.kp.publicKey,
      authority: ['payments:*'], principalId: 'someone-else', registeredBy: 'test-operator',
    }), /UNIQUE/)
  })
})

// ─────────────────────────────────────────────────────────────────────
// D2: server-bound fields on /sign are refused by name
// ─────────────────────────────────────────────────────────────────────

describe('sign - server-bound body fields are refused', () => {
  const cases: Array<[string, unknown]> = [
    ['approver_public_key', 'ab'.repeat(32)],
    ['authority', ['*']],
    ['key_class', 'approver'],
    ['office_id', 'treasury'],
    ['decision_latency_ms', 600000],
    ['batch_size', 1],
  ]
  for (const [field, value] of cases) {
    it(`${field} in the body is 400 server_bound_field and stores nothing`, async () => {
      const a = approver(['payments:*'])
      const id = await open(); backdate(id)
      const r = await call('POST', `/approvals/${id}/sign`, {
        approver_id: a.id, reason: 'reviewed it', signature: sigFor(id, a.kp), [field]: value,
      })
      assert.equal(r.status, 400)
      assert.equal(r.json.code, 'server_bound_field')
      assert.deepEqual(r.json.fields, [field])
      const c = getDB().prepare(`SELECT COUNT(*) c FROM approval_signatures WHERE request_id = ?`).get(id) as any
      assert.equal(c.c, 0)
      assert.equal(getApprovalHistory(a.id).length, 0)
    })
  }

  it('all six together are named in one 400', async () => {
    const a = approver(['payments:*'])
    const id = await open(); backdate(id)
    const r = await call('POST', `/approvals/${id}/sign`, {
      approver_id: a.id, reason: 'reviewed it', signature: sigFor(id, a.kp),
      ...Object.fromEntries(cases),
    })
    assert.equal(r.status, 400)
    assert.deepEqual(r.json.fields, cases.map(c => c[0]))
  })
})

// ─────────────────────────────────────────────────────────────────────
// D4: elapsed time is telemetry, fatigue history only from accepted signs
// ─────────────────────────────────────────────────────────────────────

describe('sign - elapsed time is not an authorization input', () => {
  it('a sign 1 ms after open is accepted when everything else is valid', async () => {
    const a = approver(['payments:*'])
    const id = await open(); backdate(id, 1)
    const r = await call('POST', `/approvals/${id}/sign`, { approver_id: a.id, reason: 'reviewed it', signature: sigFor(id, a.kp) })
    assert.equal(r.status, 201, JSON.stringify(r.json))
    assert.equal(getApprovalHistory(a.id).length, 1)
  })

  it('a created_at later than arrival records elapsed 0 and is accepted', async () => {
    const a = approver(['payments:*'])
    const id = await open()
    getDB().prepare(`UPDATE approval_requests SET created_at = ? WHERE id = ?`).run(new Date(Date.now() + 5_000).toISOString(), id)
    const r = await call('POST', `/approvals/${id}/sign`, { approver_id: a.id, reason: 'reviewed it', signature: sigFor(id, a.kp) })
    assert.equal(r.status, 201, JSON.stringify(r.json))
    const row = getDB().prepare(`SELECT elapsed_since_open_ms FROM approval_signatures WHERE request_id = ?`).get(id) as any
    assert.equal(row.elapsed_since_open_ms, 0, 'a created_at in the future clamps to 0')
  })

  it('the stored elapsed value is measured by the server from created_at', async () => {
    const a = approver(['payments:*'])
    const id = await open(); backdate(id, 90_000)
    const before = Date.now()
    const r = await call('POST', `/approvals/${id}/sign`, { approver_id: a.id, reason: 'reviewed it', signature: sigFor(id, a.kp) })
    const after = Date.now()
    assert.equal(r.status, 201)
    const created = Date.parse(getRequest(TENANT, id)!.created_at)
    const row = getDB().prepare(
      `SELECT elapsed_since_open_ms, decision_latency_ms FROM approval_signatures WHERE request_id = ?`,
    ).get(id) as any
    assert.ok(row.elapsed_since_open_ms >= before - created && row.elapsed_since_open_ms <= after - created,
      `elapsed ${row.elapsed_since_open_ms} within [${before - created}, ${after - created}]`)
    assert.equal(row.decision_latency_ms, null, 'the old caller-number column is not written')
    assert.equal(getApprovalHistory(a.id)[0].decision_latency_ms, row.elapsed_since_open_ms)
  })

  it('refused attempts and retries leave fatigue history unchanged', async () => {
    const a = approver(['payments:*'])
    const id = await open(); backdate(id)
    const other = await open()
    const attempts: Array<Record<string, unknown>> = [
      { approver_id: a.id, reason: 'reviewed it', signature: 'not-a-signature' },
      { approver_id: a.id, reason: 'reviewed it', signature: sigFor(other, a.kp) },
      { approver_id: a.id, reason: 'reviewed it', signature: sigFor(id, a.kp), decision_latency_ms: 1 },
      { approver_id: a.id, reason: 'reviewed it', signature: sigFor(id, a.kp), amount: 1 },
      { approver_id: a.id, reason: 'x', signature: sigFor(id, a.kp) },
      { approver_id: a.id, reason: 'reviewed it', signature: '' },
    ]
    for (let i = 0; i < 3; i++) {
      for (const body of attempts) {
        const r = await call('POST', `/approvals/${id}/sign`, body)
        assert.ok(r.status >= 400, `${JSON.stringify(body)} -> ${r.status}`)
      }
    }
    assert.equal(getApprovalHistory(a.id).length, 0, 'no refused attempt was recorded')

    const ok = await call('POST', `/approvals/${id}/sign`, { approver_id: a.id, reason: 'reviewed it', signature: sigFor(id, a.kp) })
    assert.equal(ok.status, 201)
    assert.equal(getApprovalHistory(a.id).length, 1)
    for (let i = 0; i < 5; i++) {
      const again = await call('POST', `/approvals/${id}/sign`, { approver_id: a.id, reason: 'reviewed it', signature: sigFor(id, a.kp) })
      assert.equal(again.status, 409)
    }
    assert.equal(getApprovalHistory(a.id).length, 1, 'retries add no history')
  })

  it('an owner-side approver refusal is not recorded either', async () => {
    const a = approver(['payments:*'], OWNER)
    const id = await open(); backdate(id)
    for (let i = 0; i < 3; i++) {
      const r = await call('POST', `/approvals/${id}/sign`, { approver_id: a.id, reason: 'reviewed it', signature: sigFor(id, a.kp) })
      assert.equal(r.status, 403)
    }
    assert.equal(getApprovalHistory(a.id).length, 0)
  })

  it('twenty-one fast accepted signs are neither refused nor flagged', async () => {
    const a = approver(['payments:*'])
    for (let i = 0; i < 21; i++) {
      const id = await open()
      const r = await call('POST', `/approvals/${id}/sign`, { approver_id: a.id, reason: 'reviewed it', signature: sigFor(id, a.kp) })
      assert.equal(r.status, 201, `sign ${i}: ${JSON.stringify(r.json)}`)
      // No rubber-stamp check runs on /sign and no fatigue flag is returned.
      assert.equal('fatigue_flag' in r.json, false, `sign ${i}`)
      assert.deepEqual(Object.keys(r.json).sort(), ['commitment_digest', 'request_id', 'signature_id'])
    }
    // History is still recorded as telemetry, one entry per accepted sign.
    assert.equal(getApprovalHistory(a.id).length, 21)
  })
})

// ─────────────────────────────────────────────────────────────────────
// End to end + decide-time re-verification
// ─────────────────────────────────────────────────────────────────────

describe('decide - evidence re-verified and committed in the receipt', () => {
  it('an explicitly authorized outside approver succeeds end to end with a checkable receipt', async () => {
    const a = approver(['payments:*'], 'treasury-office')
    const id = await open(); backdate(id)

    const detail = await call('GET', `/approvals/${id}`)
    assert.equal(detail.status, 200)
    const expected = approvalCommitment(getRequest(TENANT, id)!)
    assert.equal(detail.json.commitment.message, expected.message)
    assert.equal(detail.json.commitment.digest, expected.digest)

    // The approver signs the message it was shown.
    const signature = edSign(detail.json.commitment.message, a.kp.privateKey)
    const s = await call('POST', `/approvals/${id}/sign`, {
      approver_id: a.id, reason: 'payee and cap checked', signature,
    })
    assert.equal(s.status, 201, JSON.stringify(s.json))
    assert.equal(s.json.commitment_digest, expected.digest)

    const sigRow = getDB().prepare(`SELECT approver_public_key, elapsed_since_open_ms FROM approval_signatures WHERE request_id = ?`).get(id) as any
    assert.equal(sigRow.approver_public_key, a.kp.publicKey, 'registry key stored, not a body key')
    assert.ok(sigRow.elapsed_since_open_ms >= 59_000, 'server-measured elapsed time stored')

    const d = await call('POST', `/approvals/${id}/decide`, { verdict: 'approved', reason: 'one outside approver signed', decided_by: 'ops' })
    assert.equal(d.status, 200, JSON.stringify(d.json))

    const rc = await call('GET', `/approvals/${id}/receipt`)
    assert.equal(rc.status, 200)
    const p = rc.json.payload
    assert.equal(p.schema_version, '1.1.0')
    assert.equal(p.commitment_scheme, APPROVAL_COMMITMENT_DOMAIN)
    assert.equal(p.request_commitment, expected.digest)
    assert.equal(p.signature_count, 1)
    // Recompute the evidence digest from the signature rows the tenant can read.
    const sigs = (await call('GET', `/approvals/${id}`)).json.signatures
    const recomputed = approverEvidenceDigest(expected.digest, sigs.map((x: any) => ({
      approver_id: x.approver_id, key_id: approverKeyId(x.approver_public_key), signature: x.signature,
    })))
    assert.equal(p.approver_evidence_digest, recomputed)
    // receipt_hash covers the new fields and the gateway JWS verifies.
    const { receipt_hash, ...unhashed } = p
    const { canonicalJson } = await import('../src/gateway/approval/receipts.js')
    assert.equal(receipt_hash, crypto.createHash('sha256').update(canonicalJson(unhashed)).digest('hex'))
    const [h, b, sg] = String(rc.json.signature).split('.')
    const jwk = getJwks().keys[0]
    const pub = crypto.createPublicKey({ key: jwk as any, format: 'jwk' })
    assert.equal(crypto.verify(null, Buffer.from(`${h}.${b}`), pub, Buffer.from(sg, 'base64url')), true)
  })

  it('P6: a row changed after signing makes decide refuse and issues no receipt', async () => {
    const a = approver(['payments:*'])
    const id = await open(); backdate(id)
    const s = await call('POST', `/approvals/${id}/sign`, { approver_id: a.id, reason: 'reviewed it', signature: sigFor(id, a.kp) })
    assert.equal(s.status, 201)
    getDB().prepare(`UPDATE approval_requests SET requested_scope = ?, subject = ? WHERE id = ?`)
      .run(JSON.stringify(['payments:transfer:max=999999']), 'invoice-swapped', id)
    const d = await call('POST', `/approvals/${id}/decide`, { verdict: 'approved', reason: 'looks right', decided_by: 'ops' })
    assert.equal(d.status, 409)
    assert.equal(d.json.code, 'approver_evidence_invalid')
    assert.equal(receiptCount(id), 0)
    assert.equal(getRequest(TENANT, id)!.status, 'pending')
  })

  it('a revoked approver signature no longer counts at decide', async () => {
    const a = approver(['payments:*'])
    const id = await open(); backdate(id)
    assert.equal((await call('POST', `/approvals/${id}/sign`, { approver_id: a.id, reason: 'reviewed it', signature: sigFor(id, a.kp) })).status, 201)
    assert.equal(revokeApprover(TENANT, a.id), true)
    const d = await call('POST', `/approvals/${id}/decide`, { verdict: 'approved', reason: 'looks right', decided_by: 'ops' })
    assert.equal(d.status, 409)
    assert.equal(d.json.code, 'approver_evidence_invalid')
  })

  it('decideRequest refuses inside its transaction when the commitment moved', async () => {
    const id = await open()
    const r = decideRequest({
      tenantId: TENANT, id, verdict: 'approved', reason: 'r', decidedBy: 'ops',
      nowIso: new Date().toISOString(), expectedCommitmentDigest: 'stale-digest',
      commitmentOf: (row: ApprovalRequestRow) => approvalCommitment(row).digest,
    })
    assert.equal(r.error, 'commitment_mismatch')
    assert.equal(getRequest(TENANT, id)!.status, 'pending')
  })
})

// ─────────────────────────────────────────────────────────────────────
// P10: cascade preview pending-approval count
// ─────────────────────────────────────────────────────────────────────

describe('revocation cascade preview counts pending approvals', () => {
  it('reports the true number of live pending approvals for the agent', async () => {
    const AG = 'agent-cascade'
    getDB().prepare(`INSERT INTO agents (id, tenant_id, agent_id, public_key, status, entity_id) VALUES (?, ?, ?, ?, 'active', ?)`)
      .run('row-agent-cascade', TENANT, AG, generateKeyPair().publicKey, OWNER)
    const ids: string[] = []
    for (let i = 0; i < 3; i++) ids.push(await open({ agent_id: AG }))
    // One past-due row still marked pending (lazy sweep) is not counted.
    getDB().prepare(`UPDATE approval_requests SET expires_at = ? WHERE id = ?`).run('2000-01-01T00:00:00.000Z', ids[2])
    const actual = (getDB().prepare(
      `SELECT COUNT(*) c FROM approval_requests WHERE tenant_id = ? AND agent_id = ? AND status = 'pending' AND expires_at > ?`,
    ).get(TENANT, AG, new Date().toISOString()) as any).c
    assert.equal(actual, 2)
    const pv = previewCascade({ tenantId: TENANT, targetType: 'agent', targetId: AG })
    assert.equal(pv.pendingApprovals, 2)
    assert.ok(pv.recommendedActions.includes('schedule'))
  })
})

// ─────────────────────────────────────────────────────────────────────
// Unbindable authority-relevant fields are rejected, not dropped
// ─────────────────────────────────────────────────────────────────────

describe('unbindable fields', () => {
  it('open with amount, currency, params or target is 400 unbindable_field', async () => {
    for (const extra of [{ amount: 100 }, { currency: 'USD' }, { params: { to: 'acct-A' } }, { target: 'acct-A' }]) {
      const r = await call('POST', '/approvals', {
        action_class: 'payments:transfer', subject: 'inv-u', agent_id: AGENT, requested_by: 'requester-1', ...extra,
      })
      assert.equal(r.status, 400, JSON.stringify(extra))
      assert.equal(r.json.code, 'unbindable_field')
      assert.deepEqual(r.json.fields, Object.keys(extra))
    }
  })

  it('sign and decide bodies carrying them are refused too', async () => {
    const a = approver(['payments:*'])
    const id = await open(); backdate(id)
    const s = await call('POST', `/approvals/${id}/sign`, { approver_id: a.id, reason: 'reviewed it', signature: sigFor(id, a.kp), amount: 999999 })
    assert.equal(s.status, 400)
    assert.equal(s.json.code, 'unbindable_field')
    assert.equal((await call('POST', `/approvals/${id}/sign`, { approver_id: a.id, reason: 'reviewed it', signature: sigFor(id, a.kp) })).status, 201)
    const d = await call('POST', `/approvals/${id}/decide`, { verdict: 'approved', reason: 'looks right', decided_by: 'ops', params: { to: 'acct-B' } })
    assert.equal(d.status, 400)
    assert.equal(d.json.code, 'unbindable_field')
    assert.equal(getRequest(TENANT, id)!.status, 'pending')
  })
})
