// Deny-path coverage for the posture and activated signing-key rotation gates.
import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { unlinkSync } from 'node:fs'
import { randomUUID } from 'node:crypto'
import type { Server } from 'node:http'
import express from 'express'
import { initDB, getDB } from '../src/db/schema.js'
import { initGatewayIdentity } from '../src/gateway/identity.js'
import { authMiddleware, createTenant } from '../src/auth/api-keys.js'
import { gatewayRouter } from '../src/gateway/enforce.js'

let dbPath: string
let server: Server
let baseUrl: string

before(async () => {
  dbPath = join(tmpdir(), `aeoess-enforce-deny-${randomUUID()}.db`)
  initDB(dbPath)
  initGatewayIdentity()
  const app = express()
  app.use(express.json())
  app.use('/api/v1', authMiddleware, gatewayRouter)
  await new Promise<void>((resolve) => {
    server = app.listen(0, '127.0.0.1', () => {
      baseUrl = `http://127.0.0.1:${(server.address() as any).port}`
      resolve()
    })
  })
})

after(() => {
  server?.close()
  try { getDB().close() } catch {}
  for (const file of [dbPath, `${dbPath}-wal`, `${dbPath}-shm`]) {
    try { unlinkSync(file) } catch {}
  }
})

async function evaluate(apiKey: string, body: Record<string, unknown>) {
  const response = await fetch(`${baseUrl}/api/v1/evaluate`, {
    method: 'POST',
    headers: { authorization: `Bearer ${apiKey}`, 'content-type': 'application/json' },
    body: JSON.stringify(body),
  })
  return { status: response.status, json: await response.json() as any }
}

function insertAgent(tenantId: string, agentId: string, status: string, restrictedScopes: string | null = null) {
  getDB().prepare(`
    INSERT INTO agents (id, tenant_id, agent_id, public_key, status, restricted_scopes)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(randomUUID(), tenantId, agentId, `public-${agentId}`, status, restrictedScopes)
}

function assertDenyReceipt(tenantId: string, agentId: string, evaluationId: string, reasonCode: string) {
  const evaluation = getDB().prepare(
    `SELECT verdict FROM policy_evaluations WHERE tenant_id = ? AND id = ?`,
  ).get(tenantId, evaluationId) as any
  assert.equal(evaluation?.verdict, 'deny')
  const receipt = getDB().prepare(
    `SELECT * FROM evaluation_receipts WHERE tenant_id = ? AND agent_id = ? AND evaluation_id = ?`,
  ).get(tenantId, agentId, evaluationId) as any
  assert.ok(receipt, 'a deny evaluation receipt was minted')
  assert.equal(receipt.verdict, 'deny')
  assert.equal(receipt.event_type, 'authorization_deny')
  assert.equal(receipt.reason_code, reasonCode)
  assert.equal(receipt.schema_version, '1.0.0')
  assert.match(receipt.receipt_hash, /^[0-9a-f]{64}$/)
  assert.ok(receipt.gateway_signature, 'deny receipt carries the gateway signature')
}

describe('gateway enforcement deny paths', () => {
  it('scope_restricted matches pay:send but does not prefix-match payroll', async () => {
    const { tenant, apiKey } = createTenant({ name: 'scope deny', email: `scope-${randomUUID()}@test.local` })
    const agentId = `restricted-${randomUUID()}`
    insertAgent(tenant.id, agentId, 'restricted', JSON.stringify(['pay']))

    const denied = await evaluate(apiKey, {
      agent_id: agentId, action_type: 'payment:send', scope_required: 'pay:send', estimated_cost: 0,
    })
    assert.equal(denied.status, 200, JSON.stringify(denied.json))
    assert.equal(denied.json.verdict, 'deny')
    assert.ok(denied.json.violations.includes('scope_restricted'))
    assertDenyReceipt(tenant.id, agentId, denied.json.evaluation_id, 'scope_restricted')

    const allowed = await evaluate(apiKey, {
      agent_id: agentId, action_type: 'payroll:read', scope_required: 'payroll', estimated_cost: 0,
    })
    assert.equal(allowed.status, 200, JSON.stringify(allowed.json))
    assert.notEqual(allowed.json.violations?.includes('scope_restricted'), true)
  })

  it('key_retired denies the old key and permits the activated new key', async () => {
    const { tenant, apiKey } = createTenant({ name: 'rotation deny', email: `rotation-${randomUUID()}@test.local` })
    const agentId = `rotated-${randomUUID()}`
    insertAgent(tenant.id, agentId, 'active')
    const oldKey = `old-${randomUUID()}`
    const newKey = `new-${randomUUID()}`
    getDB().prepare(`
      INSERT INTO key_rotations
        (tenant_id, agent_id, old_key, new_key, mode, announced_at, activation_time, state, rotation_signature)
      VALUES (?, ?, ?, ?, 'planned', datetime('now'), datetime('now'), 'activated', ?)
    `).run(tenant.id, agentId, oldKey, newKey, `rotation-${randomUUID()}`)

    const denied = await evaluate(apiKey, {
      agent_id: agentId, action_type: 'payment:send', scope_required: 'pay:send',
      estimated_cost: 0, signing_key: oldKey,
    })
    assert.equal(denied.status, 200, JSON.stringify(denied.json))
    assert.equal(denied.json.verdict, 'deny')
    assert.ok(denied.json.violations.includes('key_retired'))
    assertDenyReceipt(tenant.id, agentId, denied.json.evaluation_id, 'key_retired')

    const allowed = await evaluate(apiKey, {
      agent_id: agentId, action_type: 'payment:send', scope_required: 'pay:send',
      estimated_cost: 0, signing_key: newKey,
    })
    assert.equal(allowed.status, 200, JSON.stringify(allowed.json))
    assert.notEqual(allowed.json.violations?.includes('key_retired'), true)
  })
})
