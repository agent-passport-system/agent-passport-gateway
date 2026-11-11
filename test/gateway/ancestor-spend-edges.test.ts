// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Day 268: boundary cases for ancestor spend accounting on POST /evaluate.
// Rows are seeded directly, so a case can hold a chain the grant path would not
// create today (a legacy row, a zero-budget ancestor).
// ══════════════════════════════════════════════════════════════════
import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import express from 'express'
import type { Server } from 'node:http'
import { initDB, getDB } from '../../src/db/schema.js'
import { initGatewayIdentity } from '../../src/gateway/identity.js'
import { gatewayRouter } from '../../src/gateway/enforce.js'

const TENANT = 'tnt_spendedges'
let server: Server, baseUrl: string
let n = 0
const raw = (p: string, body: string) => fetch(`${baseUrl}${p}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body })

function agent(id: string) {
  getDB().prepare(`INSERT INTO agents (id, tenant_id, agent_id, public_key, status, is_root) VALUES (?, ?, ?, 'pk', 'active', 0)`).run(`row-${id}`, TENANT, id)
}
/** A delegation parent -> child. Returns its id. */
function row(parent: string, child: string, limit: number | null, used = 0, parentDelegationId: string | null = null): string {
  const id = `del-${++n}`
  getDB().prepare(`INSERT INTO delegations (id, tenant_id, parent_agent_id, child_agent_id, scope, status, spend_limit, spend_used, parent_delegation_id) VALUES (?, ?, ?, ?, 'data:read', 'active', ?, ?, ?)`)
    .run(id, TENANT, parent, child, limit, used, parentDelegationId)
  return id
}
const used = (id: string) => (getDB().prepare(`SELECT spend_used FROM delegations WHERE id = ?`).get(id) as any).spend_used
async function spend(agentId: string, costJson: string): Promise<{ verdict: string; reason: string; status: number }> {
  const r = await raw('/evaluate', `{"agent_id":"${agentId}","action_type":"data:read","scope_required":"data:read","estimated_cost":${costJson}}`)
  const body = await r.json() as any
  return { verdict: body.verdict, reason: body.reason ?? body.error ?? '', status: r.status }
}
/** Fresh three-level chain root -> p -> c with the given limits. */
function chain(tag: string, parentLimit: number | null, childLimit: number | null) {
  const root = `root-${tag}`, p = `p-${tag}`, c = `c-${tag}`
  agent(root); agent(p); agent(c)
  const top = row(root, p, parentLimit)
  const low = row(p, c, childLimit, 0, top)
  return { p, c, top, low }
}

before(async () => {
  initDB(':memory:')
  initGatewayIdentity()
  getDB().prepare(`INSERT OR IGNORE INTO tenants (id, name, email) VALUES (?, ?, ?)`).run(TENANT, 'SpendEdges', 'edges@test.local')
  const app = express()
  app.use(express.json())
  app.use((req: any, _res, next) => { req.tenant = { id: TENANT, role: 'user', plan: 'enterprise' }; next() })
  app.use('/api/v1', gatewayRouter)
  await new Promise<void>((resolve) => { server = app.listen(0, () => { const a = server.address(); baseUrl = `http://127.0.0.1:${typeof a === 'object' && a ? a.port : 0}/api/v1`; resolve() }) })
})
after(() => server?.close())

describe('ancestor spend boundaries on /evaluate', () => {
  it('a zero-budget ancestor denies any positive cost, even when the child row has room', async () => {
    const k = chain('zero', 0, 50)
    const r = await spend(k.c, '1')
    assert.equal(r.verdict, 'deny')
    assert.match(r.reason, /ancestor delegation \(hop 2\)/)
    assert.deepEqual([used(k.top), used(k.low)], [0, 0])
  })

  it('a zero cost is permitted and debits nothing', async () => {
    const k = chain('free', 0, 0)
    assert.equal((await spend(k.c, '0')).verdict, 'permit')
    assert.deepEqual([used(k.top), used(k.low)], [0, 0])
  })

  it('negative and non-finite costs are refused before any budget math', async () => {
    const k = chain('bad', 100, 50)
    for (const cost of ['-1', '-0.01', '1e999', '"10"', 'null']) {
      const r = await spend(k.c, cost)
      if (cost === 'null') {
        assert.equal(r.verdict, 'permit', 'no cost given is a free action')
      } else {
        assert.equal(r.verdict, 'deny', `cost ${cost}`)
      }
    }
    assert.deepEqual([used(k.top), used(k.low)], [0, 0])
  })

  it('spending exactly to the ancestor limit is permitted, one cent more is not', async () => {
    const k = chain('exact', 50, 50)
    agent('q-exact')
    const sibling = row('p-exact', 'q-exact', 50, 0, k.top)
    assert.equal((await spend(k.c, '30')).verdict, 'permit')
    assert.equal((await spend('q-exact', '20.01')).verdict, 'deny', 'only $20 left in the parent')
    assert.equal((await spend('q-exact', '20')).verdict, 'permit', 'exactly the $20 left')
    assert.deepEqual([used(k.top), used(k.low), used(sibling)], [50, 30, 20])
  })

  it('three children of one parent share its budget', async () => {
    const root = 'root-three', p = 'p-three'
    agent(root); agent(p)
    const top = row(root, p, 100)
    const kids = ['k1', 'k2', 'k3'].map(k => { agent(`${k}-three`); return row(p, `${k}-three`, 100, 0, top) })
    const verdicts = []
    for (const k of ['k1', 'k2', 'k3']) verdicts.push((await spend(`${k}-three`, '40')).verdict)
    assert.deepEqual(verdicts, ['permit', 'permit', 'deny'])
    assert.equal(used(top), 80)
    assert.deepEqual(kids.map(used), [40, 40, 0])
  })

  it('fractional amounts: an ancestor decides the same way its own row would', async () => {
    // The acting row and the ancestor carry the same limit and see the same spends, so any
    // float rounding in the comparison affects both alike. The ancestor rule adds no new
    // rounding behavior of its own.
    for (const [limit, first, second] of [[0.3, 0.1, 0.2], [7.21, 2.14, 5.07], [1, 0.001, 0.999]] as const) {
      const tag = `frac-${limit}`
      const k = chain(tag, limit, limit)
      const leafOnly = chain(`${tag}-leafonly`, null, limit)
      const a = [await spend(k.c, String(first)), await spend(k.c, String(second))].map(r => r.verdict)
      const b = [await spend(leafOnly.c, String(first)), await spend(leafOnly.c, String(second))].map(r => r.verdict)
      assert.deepEqual(a, b, `limit ${limit}: with ancestor ${a}, leaf only ${b}`)
    }
  })

  it('a child row whose chain cannot be read is denied', async () => {
    agent('orphan-p'); agent('orphan-c')
    const low = row('orphan-p', 'orphan-c', 50, 0, 'del-does-not-exist')
    const r = await spend('orphan-c', '1')
    assert.equal(r.verdict, 'deny')
    assert.equal(used(low), 0)
  })
})
