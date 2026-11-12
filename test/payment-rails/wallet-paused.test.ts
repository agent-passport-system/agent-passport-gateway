// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Day 268: with NANO_WALLETS_PAUSED=1, POST /wallets/send refuses before any
// budget is touched and before any wallet code runs. Operators can use it to keep
// the Nano rail off.
// ══════════════════════════════════════════════════════════════════
import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import express from 'express'
import type { Server } from 'node:http'
import { initDB, getDB } from '../../src/db/schema.js'
import { initGatewayIdentity } from '../../src/gateway/identity.js'
import { walletRouter } from '../../src/payment-rails/wallet-routes.js'
import { setGenerousPilotCaps, initFrontier } from './pilot-fixtures.js'

const TENANT = 'tnt_paused'
let server: Server, baseUrl: string

before(async () => {
  setGenerousPilotCaps()
  process.env.NANO_WALLETS_PAUSED = '1'
  initDB(':memory:')
  initGatewayIdentity()
  const db = getDB()
  db.prepare(`INSERT OR IGNORE INTO tenants (id, name, email) VALUES (?, ?, ?)`).run(TENANT, 'Paused', 'p@test.local')
  db.prepare(`INSERT INTO agents (id, tenant_id, agent_id, public_key, status, is_root) VALUES ('r-a', ?, 'a', 'pk', 'active', 0)`).run(TENANT)
  db.prepare(`INSERT INTO agent_wallets (id, tenant_id, agent_id, nano_address, wallet_index, status) VALUES ('w-a', ?, 'a', 'nano_a', 1, 'active')`).run(TENANT)
  db.prepare(`INSERT INTO delegations (id, tenant_id, parent_agent_id, child_agent_id, scope, status, spend_limit, spend_used) VALUES ('d-a', ?, 'root', 'a', 'commerce:send', 'active', 10, 0)`).run(TENANT)
  const app = express()
  app.use(express.json())
  app.use((req: any, _res, next) => { req.tenant = { id: TENANT, role: 'user', plan: 'enterprise' }; next() })
  app.use('/api/v1', walletRouter)
  await new Promise<void>((resolve) => { server = app.listen(0, () => { const a = server.address(); baseUrl = `http://127.0.0.1:${typeof a === 'object' && a ? a.port : 0}/api/v1`; resolve() }) })
})
after(() => { server?.close(); delete process.env.NANO_WALLETS_PAUSED })

describe('paused Nano wallets', () => {
  it('POST /wallets/send is refused and nothing is debited or recorded', async () => {
    const r = await fetch(`${baseUrl}/wallets/send`, {
      method: 'POST', headers: { 'content-type': 'application/json', 'idempotency-key': 'paused-1' },
      body: JSON.stringify({ from_agent_id: 'a', to_address: 'nano_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3', amount_raw: '1000' }),
    })
    const body = await r.json() as any
    // Day 268 lifecycle: the route reserves through wallet_ops, and the pause gate refuses first
    // with 403 and a recorded denial. Before, the wallet service failed to construct (500).
    assert.equal(r.status, 403)
    assert.match(String(body.denial_reason), /paused by the operator/)
    const db = getDB()
    assert.equal((db.prepare(`SELECT spend_used FROM delegations WHERE id = 'd-a'`).get() as any).spend_used, 0)
    assert.equal((db.prepare(`SELECT COUNT(*) n FROM wallet_ops`).get() as any).n, 0)
    assert.equal((db.prepare(`SELECT COUNT(*) n FROM wallet_transactions WHERE status <> 'denied'`).get() as any).n, 0)
  })
})
