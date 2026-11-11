// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Day 268: Nano wallet send, delegation chain rules. The on-chain wallet is a fake
// injected through AgentWalletService's constructor, so no RPC is called and no
// Nano moves. On 0.4.2 (48e1564) four of these five cases fail, all but the not-published
// one. The send checked only the acting row's budget, never walked the chain for a
// revoked grantor, read a zero spend_limit as no limit, and reversed the debit on
// any error, including one raised while publishing.
// ══════════════════════════════════════════════════════════════════
import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import { initDB, getDB } from '../../src/db/schema.js'
import { initGatewayIdentity } from '../../src/gateway/identity.js'
import { AgentWalletService } from '../../src/payment-rails/wallet.js'
import { NanoSendNotBroadcastError } from '../../src/payment-rails/wallet-crypto.js'

const TENANT = 'tnt_walletchain'
const TO = 'nano_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3'
let n = 0

type SendBehavior = 'ok' | 'not_broadcast' | 'unknown'
function fakeWallet(behavior: () => SendBehavior) {
  const sent: string[] = []
  return {
    sent,
    wallet: {
      async send(_index: number, _to: string, amountRaw: string) {
        const b = behavior()
        if (b === 'not_broadcast') throw new NanoSendNotBroadcastError('Insufficient balance')
        if (b === 'unknown') throw new Error('socket hang up while publishing')
        sent.push(amountRaw)
        return { blockHash: 'B'.repeat(64), fromAddress: 'nano_from' }
      },
      async getBalance() { return { frontier: '', balance: '0', representative: '', open: true } },
      async receive() { return { received: 0, blocks: [] } },
      validateAddress() { return true },
    } as any,
  }
}

function agent(id: string, status = 'active') {
  getDB().prepare(`INSERT INTO agents (id, tenant_id, agent_id, public_key, status, is_root) VALUES (?, ?, ?, 'pk', ?, 0)`).run(`row-${id}`, TENANT, id, status)
}
function wallet(agentId: string) {
  getDB().prepare(`INSERT INTO agent_wallets (id, tenant_id, agent_id, nano_address, wallet_index, status) VALUES (?, ?, ?, ?, ?, 'active')`)
    .run(`w-${agentId}`, TENANT, agentId, `nano_${agentId}`, ++n)
}
function row(parent: string, child: string, limit: number | null, parentDelegationId: string | null = null): string {
  const id = `del-${++n}`
  getDB().prepare(`INSERT INTO delegations (id, tenant_id, parent_agent_id, child_agent_id, scope, status, spend_limit, spend_used, parent_delegation_id) VALUES (?, ?, ?, ?, 'commerce:send', 'active', ?, 0, ?)`)
    .run(id, TENANT, parent, child, limit, parentDelegationId)
  return id
}
const used = (id: string) => (getDB().prepare(`SELECT spend_used FROM delegations WHERE id = ?`).get(id) as any).spend_used
function chain(tag: string, parentLimit: number | null, childLimit: number | null, rootStatus = 'active') {
  const root = `root-${tag}`, p = `p-${tag}`, c = `c-${tag}`
  agent(root, rootStatus); agent(p); agent(c); wallet(p); wallet(c)
  const top = row(root, p, parentLimit)
  const low = row(p, c, childLimit, top)
  return { p, c, top, low }
}

before(() => {
  process.env.NANO_WALLET_SEND_ENABLED = '1'
  initDB(':memory:')
  initGatewayIdentity()
  getDB().prepare(`INSERT OR IGNORE INTO tenants (id, name, email) VALUES (?, ?, ?)`).run(TENANT, 'WalletChain', 'wc@test.local')
})

describe('wallet send is off by default', () => {
  it('without NANO_WALLET_SEND_ENABLED=1 a send is denied and no wallet code runs', async () => {
    const f = fakeWallet(() => 'ok')
    const svc = new AgentWalletService({ localWallet: f.wallet })
    const k = chain('off', 10, 5)
    delete process.env.NANO_WALLET_SEND_ENABLED
    try {
      const tx = await svc.send({ tenantId: TENANT, fromAgentId: k.c, toAddress: TO, amountXno: 1 })
      assert.equal(tx.status, 'denied')
      assert.match(String(tx.denial_reason), /disabled by default/)
      assert.equal(f.sent.length, 0)
      assert.deepEqual([used(k.top), used(k.low)], [0, 0])
    } finally {
      process.env.NANO_WALLET_SEND_ENABLED = '1'
    }
  })
})

describe('the operator pause wins', () => {
  it('NANO_WALLETS_PAUSED=1 refuses a send even with NANO_WALLET_SEND_ENABLED=1', async () => {
    const f = fakeWallet(() => 'ok')
    const svc = new AgentWalletService({ localWallet: f.wallet })
    const k = chain('pausewins', 10, 5)
    process.env.NANO_WALLETS_PAUSED = '1'
    try {
      const tx = await svc.send({ tenantId: TENANT, fromAgentId: k.c, toAddress: TO, amountXno: 1 })
      assert.equal(tx.status, 'denied')
      assert.match(String(tx.denial_reason), /paused by the operator/)
      assert.equal(f.sent.length, 0)
      assert.deepEqual([used(k.top), used(k.low)], [0, 0])
    } finally {
      delete process.env.NANO_WALLETS_PAUSED
    }
  })
})

describe('wallet send follows the delegation chain', () => {
  it('a child send counts against the parent budget', async () => {
    const f = fakeWallet(() => 'ok')
    const svc = new AgentWalletService({ localWallet: f.wallet })
    const k = chain('acct', 1, 0.3)
    assert.equal((await svc.send({ tenantId: TENANT, fromAgentId: k.c, toAddress: TO, amountXno: 0.3 })).status, 'confirmed')
    assert.equal((await svc.send({ tenantId: TENANT, fromAgentId: k.p, toAddress: TO, amountXno: 1 })).status, 'denied')
    assert.equal((await svc.send({ tenantId: TENANT, fromAgentId: k.p, toAddress: TO, amountXno: 0.7 })).status, 'confirmed')
    assert.deepEqual([used(k.top), used(k.low)], [1, 0.3])
    assert.equal(f.sent.length, 2)
  })

  it('a revoked grantor up the chain stops the send', async () => {
    const f = fakeWallet(() => 'ok')
    const svc = new AgentWalletService({ localWallet: f.wallet })
    const k = chain('revoked', 10, 5, 'revoked')
    const tx = await svc.send({ tenantId: TENANT, fromAgentId: k.c, toAddress: TO, amountXno: 1 })
    assert.equal(tx.status, 'denied')
    assert.match(String(tx.denial_reason), /authority chain is invalid/)
    assert.equal(f.sent.length, 0)
  })

  it('a zero spend_limit is a zero budget, not no limit', async () => {
    const f = fakeWallet(() => 'ok')
    const svc = new AgentWalletService({ localWallet: f.wallet })
    const k = chain('zero', 10, 0)
    assert.equal((await svc.send({ tenantId: TENANT, fromAgentId: k.c, toAddress: TO, amountXno: 0.000001 })).status, 'denied')
    assert.equal(f.sent.length, 0)
  })

  it('a send that failed before publishing releases the debit on every chain row', async () => {
    const f = fakeWallet(() => 'not_broadcast')
    const svc = new AgentWalletService({ localWallet: f.wallet })
    const k = chain('nb', 10, 5)
    assert.equal((await svc.send({ tenantId: TENANT, fromAgentId: k.c, toAddress: TO, amountXno: 2 })).status, 'failed')
    assert.deepEqual([used(k.top), used(k.low)], [0, 0])
  })

  it('a chain on upgrade hold cannot send', async () => {
    const f = fakeWallet(() => 'ok')
    const svc = new AgentWalletService({ localWallet: f.wallet })
    const k = chain('held', 10, 5)
    getDB().prepare(`INSERT INTO chain_spend_holds (delegation_id, tenant_id, reason, direct_spend_used, created_at) VALUES (?, ?, 'descendant_spent_before_upgrade', 0, ?)`).run(k.top, TENANT, new Date().toISOString())
    assert.equal((await svc.send({ tenantId: TENANT, fromAgentId: k.c, toAddress: TO, amountXno: 1 })).status, 'denied')
    assert.equal(f.sent.length, 0)
  })

  it('a send whose outcome is unknown keeps the debit on every chain row', async () => {
    let first = true
    const f = fakeWallet(() => (first ? ((first = false), 'unknown') : 'ok'))
    const svc = new AgentWalletService({ localWallet: f.wallet })
    const k = chain('unk', 5, 5)
    const tx = await svc.send({ tenantId: TENANT, fromAgentId: k.c, toAddress: TO, amountXno: 4 })
    assert.equal(tx.status, 'pending')
    assert.match(String(tx.denial_reason), /^outcome_unknown:/)
    assert.deepEqual([used(k.top), used(k.low)], [4, 4])
    // The $4 that may still settle is not available to spend again.
    assert.equal((await svc.send({ tenantId: TENANT, fromAgentId: k.c, toAddress: TO, amountXno: 2 })).status, 'denied')
    const stored = getDB().prepare(`SELECT status FROM wallet_transactions WHERE id = ?`).get(tx.id) as any
    assert.equal(stored.status, 'pending')
  })
})
