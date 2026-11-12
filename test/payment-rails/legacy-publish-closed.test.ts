// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// The legacy Nano publish path is closed in this release. This release writes no durable payment
// record before a block is broadcast, so a crash or timeout while publishing could leave a send the
// gateway cannot reconcile. Agent sends, receives and settlement payouts all refuse before deriving
// a key or calling a node, whatever the switches say, and the source has no Nano process call.
// ══════════════════════════════════════════════════════════════════
import { describe, it, before, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { initDB, getDB } from '../../src/db/schema.js'
import { initGatewayIdentity } from '../../src/gateway/identity.js'
import { AgentWalletService } from '../../src/payment-rails/wallet.js'
import { NanoLocalWallet, sendNano, receiveNano, LEGACY_PUBLISH_CLOSED, NanoSendNotBroadcastError } from '../../src/payment-rails/wallet-crypto.js'
import { NanoPaymentRail, SETTLEMENT_PAYOUT_CLOSED, xnoToRaw } from '../../src/payment-rails/nano.js'

const TENANT = 'tnt_closed'
const TO = 'nano_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3'

async function countingFetch<T>(fn: () => Promise<T>): Promise<{ result: T | Error; fetches: number }> {
  const real = globalThis.fetch
  let fetches = 0
  globalThis.fetch = (async () => { fetches++; throw new Error('no network in tests') }) as any
  try {
    return { result: await fn().catch((e: Error) => e), fetches }
  } finally {
    globalThis.fetch = real
  }
}

before(() => {
  initDB(':memory:')
  initGatewayIdentity()
  const db = getDB()
  db.prepare(`INSERT OR IGNORE INTO tenants (id, name, email) VALUES (?, 'Closed', 'closed@test.local')`).run(TENANT)
  db.prepare(`INSERT INTO agents (id, tenant_id, agent_id, public_key, status, is_root) VALUES ('r-root', ?, 'root', 'pk', 'active', 0)`).run(TENANT)
  db.prepare(`INSERT INTO agents (id, tenant_id, agent_id, public_key, status, is_root) VALUES ('r-c', ?, 'c', 'pk', 'active', 0)`).run(TENANT)
  db.prepare(`INSERT INTO agent_wallets (id, tenant_id, agent_id, nano_address, wallet_index, status) VALUES ('w-c', ?, 'c', 'nano_c', 1, 'active')`).run(TENANT)
  db.prepare(`INSERT INTO delegations (id, tenant_id, parent_agent_id, child_agent_id, scope, status, spend_limit, spend_used, spend_unit, spend_limit_minor, spend_used_minor) VALUES ('d-c', ?, 'root', 'c', 'commerce:send', 'active', 0, 0, 'nano:XNO:raw', ?, '0')`).run(TENANT, xnoToRaw('5'))
})

// Every relevant switch on and nothing paused, in every case below.
beforeEach(() => {
  process.env.NANO_WALLET_SEND_ENABLED = '1'
  process.env.SETTLE_PAYOUT_ENABLED = 'true'
  delete process.env.NANO_WALLETS_PAUSED
  delete process.env.NANO_RAIL_DISABLED
})
afterEach(() => {
  delete process.env.NANO_WALLET_SEND_ENABLED
  delete process.env.SETTLE_PAYOUT_ENABLED
})

describe('the legacy publish path is closed', () => {
  it('sendNano and receiveNano refuse before calling anything', async () => {
    const s = await countingFetch(() => sendNano({ rpcUrl: 'http://node.invalid', seed: '0'.repeat(128), fromIndex: 1, toAddress: TO, amountRaw: '1' }))
    assert.ok(s.result instanceof NanoSendNotBroadcastError && s.result.message === LEGACY_PUBLISH_CLOSED)
    const r = await countingFetch(() => receiveNano({ rpcUrl: 'http://node.invalid', seed: '0'.repeat(128), accountIndex: 1 }))
    assert.ok(r.result instanceof Error && r.result.message === LEGACY_PUBLISH_CLOSED)
    assert.equal(s.fetches + r.fetches, 0)
  })

  it('an enabled, unpaused wallet send is refused at publishing, releases its debit once, and calls no node', async () => {
    const svc = new AgentWalletService({ localWallet: new NanoLocalWallet({ seed: '0'.repeat(128), rpcUrl: 'http://node.invalid' }) })
    const out = await countingFetch(() => svc.send({ tenantId: TENANT, fromAgentId: 'c', toAddress: TO, amountRaw: xnoToRaw('1') }))
    const tx = out.result as any
    assert.equal(tx.status, 'failed')
    assert.equal(tx.denial_reason, LEGACY_PUBLISH_CLOSED)
    assert.equal(out.fetches, 0)
    // The debit came back exactly once: the counter is 0, not negative (applyUnitSpend refuses below 0).
    assert.equal((getDB().prepare(`SELECT spend_used_minor FROM delegations WHERE id = 'd-c'`).get() as any).spend_used_minor, '0')
    const rows = getDB().prepare(`SELECT status FROM wallet_transactions WHERE id = ?`).all(tx.id) as any[]
    assert.deepEqual(rows.map(r => r.status), ['failed'])
    // A second send behaves the same and the counter stays exact.
    const again = await countingFetch(() => svc.send({ tenantId: TENANT, fromAgentId: 'c', toAddress: TO, amountRaw: xnoToRaw('2') }))
    assert.equal((again.result as any).status, 'failed')
    assert.equal(again.fetches, 0)
    assert.equal((getDB().prepare(`SELECT spend_used_minor FROM delegations WHERE id = 'd-c'`).get() as any).spend_used_minor, '0')
  })

  it('an enabled receive through the wallet service refuses and calls no node', async () => {
    const svc = new AgentWalletService({ localWallet: new NanoLocalWallet({ seed: '0'.repeat(128), rpcUrl: 'http://node.invalid' }) })
    const out = await countingFetch(() => svc.receiveAll(TENANT, 'c'))
    assert.ok(out.result instanceof Error && out.result.message === LEGACY_PUBLISH_CLOSED)
    assert.equal(out.fetches, 0)
  })

  it('settlement payouts refuse before calling anything, with payouts enabled and nothing paused', async () => {
    const rail = new NanoPaymentRail({ rpcUrl: 'http://node.invalid', receivingAddress: TO } as any)
    const out = await countingFetch(() => rail.sendPayment({ destination: TO, amount: 1 }))
    assert.ok(out.result instanceof Error && out.result.message === SETTLEMENT_PAYOUT_CLOSED)
    assert.equal(out.fetches, 0)
  })

  it('the source has no Nano process call', () => {
    const hits: string[] = []
    const walk = (dir: string) => {
      for (const name of readdirSync(dir)) {
        const p = join(dir, name)
        if (statSync(p).isDirectory()) walk(p)
        else if (/\.(ts|js|mjs|cjs)$/.test(name)) {
          for (const m of readFileSync(p, 'utf8').matchAll(/action\s*:\s*['"`]process['"`]/g)) hits.push(`${p}:${m.index}`)
        }
      }
    }
    walk('src')
    assert.deepEqual(hits, [])
  })
})
