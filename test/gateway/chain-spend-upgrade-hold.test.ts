// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// 0.4.3 upgrade hold. A database written by an earlier version keeps each
// delegation's own direct spending only, so after the upgrade a parent's counter
// misses what its children spent before. Those chains are held and their spending
// refused until an operator reconciles or re-grants them. Rows created after the
// upgrade are not held. Rows are seeded first and the migration is then run again,
// which is what an existing database sees on its first boot of 0.4.3.
// ══════════════════════════════════════════════════════════════════
import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import express from 'express'
import type { Server } from 'node:http'
import { initDB, getDB } from '../../src/db/schema.js'
import { initGatewayIdentity } from '../../src/gateway/identity.js'
import { gatewayRouter } from '../../src/gateway/enforce.js'
import { CHAIN_SPEND_HOLD_MIGRATION_ID, runChainSpendUpgradeHold } from '../../src/gateway/chain-spend.js'

const TENANT = 'tnt_upgradehold'
let server: Server, baseUrl: string
let n = 0
const post = (p: string, b: unknown) => fetch(`${baseUrl}${p}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b) })
function agent(id: string, isRoot = 0) {
  getDB().prepare(`INSERT INTO agents (id, tenant_id, agent_id, public_key, status, is_root) VALUES (?, ?, ?, 'pk', 'active', ?)`).run(`row-${id}`, TENANT, id, isRoot)
}
function row(parent: string, child: string, limit: number | null, used: number, parentDelegationId: string | null): string {
  const id = `del-${++n}`
  getDB().prepare(`INSERT INTO delegations (id, tenant_id, parent_agent_id, child_agent_id, scope, status, spend_limit, spend_used, parent_delegation_id) VALUES (?, ?, ?, ?, 'data:read', 'active', ?, ?, ?)`)
    .run(id, TENANT, parent, child, limit, used, parentDelegationId)
  return id
}
async function spend(agentId: string, cost: number): Promise<{ verdict: string; reason: string }> {
  const body = await (await post('/evaluate', { agent_id: agentId, action_type: 'data:read', scope_required: 'data:read', estimated_cost: cost })).json() as any
  return { verdict: body.verdict, reason: String(body.reason ?? '') }
}
const holds = () => getDB().prepare(`SELECT delegation_id, reason, direct_spend_used FROM chain_spend_holds ORDER BY delegation_id`).all() as any[]
/** What a database written by 0.4.2 looks like on its first boot of 0.4.3. */
function bootAsUpgrade() {
  getDB().prepare(`DELETE FROM schema_migrations WHERE id = ?`).run(CHAIN_SPEND_HOLD_MIGRATION_ID)
  return runChainSpendUpgradeHold(getDB())
}

before(async () => {
  initDB(':memory:')
  initGatewayIdentity()
  getDB().prepare(`INSERT OR IGNORE INTO tenants (id, name, email) VALUES (?, ?, ?)`).run(TENANT, 'UpgradeHold', 'uh@test.local')
  const app = express()
  app.use(express.json())
  app.use((req: any, _res, next) => { req.tenant = { id: TENANT, role: 'user', plan: 'enterprise' }; next() })
  app.use('/api/v1', gatewayRouter)
  await new Promise<void>((resolve) => { server = app.listen(0, () => { const a = server.address(); baseUrl = `http://127.0.0.1:${typeof a === 'object' && a ? a.port : 0}/api/v1`; resolve() }) })
})
after(() => server?.close())

describe('0.4.3 upgrade hold', () => {
  it('a fresh database gets the marker and no holds', () => {
    assert.ok(getDB().prepare(`SELECT 1 FROM schema_migrations WHERE id = ? AND status = 'complete'`).get(CHAIN_SPEND_HOLD_MIGRATION_ID))
    assert.deepEqual(holds(), [])
    assert.equal(runChainSpendUpgradeHold(getDB()), 'already')
  })

  it('holds a parent whose child spent before the upgrade, and refuses spending through it', async () => {
    agent('R1', 1); agent('P1'); agent('C1'); agent('S1')
    const parent = row('R1', 'P1', 100, 0, null)
    const child = row('P1', 'C1', 30, 20, parent)
    row('P1', 'S1', 30, 0, parent)
    assert.equal(bootAsUpgrade(), 1)
    assert.deepEqual(holds(), [{ delegation_id: parent, reason: 'descendant_spent_before_upgrade', direct_spend_used: 0 }])
    for (const a of ['P1', 'C1', 'S1']) {
      const r = await spend(a, 1)
      assert.equal(r.verdict, 'deny', a)
      assert.match(r.reason, /on hold since the 0\.4\.3 upgrade/, a)
    }
    // The child's own counter and every row stay exactly as they were.
    assert.equal((getDB().prepare(`SELECT spend_used FROM delegations WHERE id = ?`).get(child) as any).spend_used, 20)
  })

  it('holds legacy sub-delegations that have no parent_delegation_id, and their grantor', async () => {
    agent('R2', 1); agent('P2'); agent('C2')
    const top = row('R2', 'P2', 100, 0, null)
    const legacy = row('P2', 'C2', 30, 5, null)
    bootAsUpgrade()
    const h = holds().filter(x => x.delegation_id === top || x.delegation_id === legacy)
    assert.deepEqual(h.map(x => x.reason).sort(), ['unbound_legacy_descendant', 'unbound_legacy_subdelegation'])
    assert.equal((await spend('C2', 1)).verdict, 'deny')
    assert.equal((await spend('P2', 1)).verdict, 'deny')
  })

  it('chains created after the upgrade are not held', async () => {
    agent('R3', 1); agent('P3'); agent('C3')
    for (const [p, c, limit] of [['R3', 'P3', 100], ['P3', 'C3', 30]] as const) {
      const r = await post('/delegations', { parent_agent_id: p, child_agent_id: c, scope: 'data:read', spend_limit: limit })
      assert.equal(r.status, 201, await r.text())
    }
    assert.equal((await spend('C3', 10)).verdict, 'permit')
    assert.equal((await spend('P3', 90)).verdict, 'permit')
    assert.equal((await spend('P3', 1)).verdict, 'deny', 'the post-upgrade chain is fully accounted')
  })

  it('a second run changes nothing, and deleting a hold row releases that chain', async () => {
    const before = holds()
    assert.equal(runChainSpendUpgradeHold(getDB()), 'already')
    assert.deepEqual(holds(), before)
    const parent = before.find(x => x.reason === 'descendant_spent_before_upgrade')!.delegation_id
    getDB().prepare(`DELETE FROM chain_spend_holds WHERE delegation_id = ?`).run(parent)
    assert.equal((await spend('S1', 1)).verdict, 'permit')
  })
  it('an interrupted migration commits nothing, and the next boot completes it', async () => {
    agent('R5', 1); agent('P5'); agent('C5')
    const parent = row('R5', 'P5', 100, 0, null)
    row('P5', 'C5', 30, 10, parent)
    const real = getDB()
    getDB().prepare(`DELETE FROM schema_migrations WHERE id = ?`).run(CHAIN_SPEND_HOLD_MIGRATION_ID)
    const heldBefore = holds().length
    // A database handle whose marker write fails after the hold rows were inserted in the
    // same transaction, as a crash or a full disk at that point would.
    const failing = new Proxy(real, {
      get(target, prop) {
        if (prop === 'prepare') {
          return (sql: string) => {
            const stmt = target.prepare(sql)
            if (!/INSERT INTO schema_migrations/.test(sql)) return stmt
            return { run: () => { throw new Error('simulated failure before the marker commits') } }
          }
        }
        const v = (target as any)[prop]
        return typeof v === 'function' ? v.bind(target) : v
      },
    }) as typeof real
    assert.throws(() => runChainSpendUpgradeHold(failing, { maxAttempts: 1 }), /simulated failure/)
    assert.equal(holds().length, heldBefore, 'no hold row from the failed run was kept')
    assert.equal(real.prepare(`SELECT 1 FROM schema_migrations WHERE id = ?`).get(CHAIN_SPEND_HOLD_MIGRATION_ID), undefined, 'no marker')
    assert.ok(typeof runChainSpendUpgradeHold(real) === 'number', 'the next boot runs it')
    assert.ok(holds().some(h => h.delegation_id === parent), 'and holds the parent')
    assert.equal((await spend('P5', 1)).verdict, 'deny')
  })

})
