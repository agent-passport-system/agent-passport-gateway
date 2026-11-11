// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Reproduction (Day 268): a descendant's spend must count against every bounded
// ancestor. Found by code reading at 0.4.2 (48e1564): /evaluate
// checks and increments spend_used on the selected inbound delegation only, and the
// grant path checks a child's spend_limit against the parent's remaining budget at
// grant time only. These tests assert the CORRECT behavior. On 0.4.2 (48e1564) both failed:
// C spent $30 and then B spent $100 under B's $100, and two $100 children each spent
// $100 under one $100 parent. They pass with src/gateway/chain-spend.ts.
// ══════════════════════════════════════════════════════════════════
import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import express from 'express'
import type { Server } from 'node:http'
import { initDB, getDB } from '../../src/db/schema.js'
import { initGatewayIdentity } from '../../src/gateway/identity.js'
import { gatewayRouter } from '../../src/gateway/enforce.js'

const TENANT = 'tnt_spendrepro'
let server: Server, baseUrl: string
const post = (p: string, b: unknown) => fetch(`${baseUrl}${p}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b) })

function seedAgent(id: string, isRoot = 0) {
  getDB().prepare(`INSERT INTO agents (id, tenant_id, agent_id, public_key, status, is_root) VALUES (?, ?, ?, 'pk', 'active', ?)`).run(`row-${id}`, TENANT, id, isRoot)
}
async function grant(parent: string, child: string, spend: number) {
  const r = await post('/delegations', { parent_agent_id: parent, child_agent_id: child, scope: 'data:read', spend_limit: spend })
  assert.equal(r.status, 201, `setup grant ${parent}->${child}: ${await r.text()}`)
}
async function spend(agent: string, cost: number): Promise<string> {
  const body = await (await post('/evaluate', { agent_id: agent, action_type: 'data:read', scope_required: 'data:read', estimated_cost: cost })).json() as any
  return body.verdict
}
function spentUnder(parent: string, child: string): number {
  const row = getDB().prepare(`SELECT spend_used FROM delegations WHERE tenant_id = ? AND parent_agent_id = ? AND child_agent_id = ?`).get(TENANT, parent, child) as any
  return row.spend_used
}

before(async () => {
  initDB(':memory:')
  initGatewayIdentity()
  getDB().prepare(`INSERT OR IGNORE INTO tenants (id, name, email) VALUES (?, ?, ?)`).run(TENANT, 'SpendRepro', 'spend@test.local')
  const app = express()
  app.use(express.json())
  app.use((req: any, _res, next) => { req.tenant = { id: TENANT, role: 'user', plan: 'enterprise' }; next() })
  app.use('/api/v1', gatewayRouter)
  await new Promise<void>((resolve) => { server = app.listen(0, () => { const a = server.address(); baseUrl = `http://127.0.0.1:${typeof a === 'object' && a ? a.port : 0}/api/v1`; resolve() }) })
})
after(() => server?.close())

describe('ancestor spend: R grants B $100, B grants C $30', () => {
  it('after C spends $30, B can spend at most $70 more', async () => {
    seedAgent('R', 1); seedAgent('B'); seedAgent('C')
    await grant('R', 'B', 100); await grant('B', 'C', 30)
    const c30 = await spend('C', 30)
    const b100 = await spend('B', 100)
    const observed = { c30, b100, spentRB: spentUnder('R', 'B'), spentBC: spentUnder('B', 'C') }
    console.log('OBSERVED parent-child', JSON.stringify(observed))
    assert.equal(c30, 'permit', 'control: C spends within its own $30')
    assert.equal(b100, 'deny', 'B must not spend $100 when $30 of its $100 is already spent through C')
    assert.equal(await spend('B', 70), 'permit', 'B can still spend exactly the $70 that remains')
    assert.equal(await spend('C', 1), 'deny', 'C has $0 left in B after B spent the rest, even though its own row has room')
    assert.deepEqual({ RB: spentUnder('R', 'B'), BC: spentUnder('B', 'C') }, { RB: 100, BC: 30 })
  })
})

describe('ancestor spend: R2 grants B2 $100, B2 grants C2 $100 and D2 $100', () => {
  it('two children cannot together spend more than the parent holds', async () => {
    seedAgent('R2', 1); seedAgent('B2'); seedAgent('C2'); seedAgent('D2')
    await grant('R2', 'B2', 100); await grant('B2', 'C2', 100); await grant('B2', 'D2', 100)
    const c = await spend('C2', 100)
    const d = await spend('D2', 100)
    console.log('OBSERVED siblings', JSON.stringify({ c, d }))
    assert.equal(c, 'permit', 'control: C2 spends within its own $100')
    assert.equal(d, 'deny', 'D2 must not spend $100 when B2s whole $100 is already spent through C2')
  })
})
