// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Day 268, lifecycle startup: the recovery pass the server runs at startup and on an interval, its
// reported state, the schema refusing a wallet_ops table of another shape, and the real server
// entry starting with the lifecycle installed. Nano calls go to fakes. Nothing reaches a network.
// ══════════════════════════════════════════════════════════════════
import { describe, it, before, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import Database from 'better-sqlite3'
// @ts-ignore nanocurrency-web has no type declarations
import nanoWebImport from 'nanocurrency-web'
import { initDB, getDB, ensureWalletOpsTable } from '../../src/db/schema.js'
import { initGatewayIdentity } from '../../src/gateway/identity.js'
import { stateBlockHash } from '../../src/payment-rails/nano-block.js'
import { reserveSend, getOp, listReservations, type WalletOp } from '../../src/payment-rails/wallet-ops.js'
import { commitAttempt, prepareOp, listAttempts, type NanoNode } from '../../src/payment-rails/nano-publish.js'
import { startNanoLifecycle, lifecycleHealth } from '../../src/payment-rails/nano-lifecycle-startup.js'
import { getOpRunner, resolveContradictedRelease, resolveIncident, resolveNodeFault, type RunContext } from '../../src/payment-rails/wallet-reconcile.js'
import { setGenerousPilotCaps, initFrontier } from './pilot-fixtures.js'

const nano = (nanoWebImport as any).default || nanoWebImport
const GENESIS = 'F47B23107E5F34B2CE06F562B5C435DF72A533251CB414C51B2B62A8F63A00E4'
const DEST = nano.wallet.fromLegacySeed('bb'.repeat(32)).accounts[0]
const TENANT = 'tnt_startup'
let n = 0
let clock = 5_000_000
const keys = new Map<string, any>()

function fakeNode(opts: { down?: boolean } = {}) {
  const calls: any[] = []
  const known = new Set<string>()
  const node: NanoNode = {
    async call(body: any) {
      calls.push(body)
      if (opts.down) throw new Error('Nano RPC network error: ECONNREFUSED')
      if (body.action === 'account_info') return { frontier: GENESIS, confirmed_frontier: GENESIS, confirmed_balance: '100000', confirmed_representative: body.account }
      if (body.action === 'work_generate') return { work: '0123456789abcdef' }
      if (body.action === 'process') { const h = stateBlockHash(body.block); known.add(h); return { hash: h } }
      if (body.action === 'block_info') { if (!known.has(body.hash)) throw new Error('Nano RPC: Block not found'); return { block_account: '', confirmed: 'false', contents: {} } }
      if (body.action === 'successors') return { blocks: [body.block] }
      throw new Error(`unexpected ${body.action}`)
    },
  }
  return { node, calls, process: () => calls.filter(c => c.action === 'process') }
}
function ctx(node: NanoNode, signer?: RunContext['signer']): RunContext {
  return {
    node, owner: 'startup-runner', leaseMs: 30_000, now: () => clock,
    signer: signer ?? ((op: WalletOp) => keys.get(op.nano_account)),
    openRepresentative: DEST.address, reconcile: { source: 'fake' }, rebroadcastMs: 10_000,
  }
}
function payment() {
  const t = ++n, db = getDB()
  for (const a of [`r${t}`, `p${t}`, `c${t}`]) db.prepare(`INSERT INTO agents (id, tenant_id, agent_id, public_key, status, is_root) VALUES (?, ?, ?, 'pk', 'active', 0)`).run(`row-${a}`, TENANT, a)
  const ins = db.prepare(`INSERT INTO delegations (id, tenant_id, parent_agent_id, child_agent_id, scope, status, spend_limit, spend_used, parent_delegation_id, spend_unit, spend_limit_minor, spend_used_minor) VALUES (?, ?, ?, ?, 'commerce:send', 'active', 0, 0, ?, 'nano:XNO:raw', '5000', '0')`)
  ins.run(`top${t}`, TENANT, `r${t}`, `p${t}`, null)
  ins.run(`low${t}`, TENANT, `p${t}`, `c${t}`, `top${t}`)
  const acct = nano.wallet.fromLegacySeed((0x4000 + t).toString(16).padStart(64, '0')).accounts[0]
  keys.set(acct.address, acct)
  db.prepare(`INSERT INTO agent_wallets (id, tenant_id, agent_id, nano_address, wallet_index, status) VALUES (?, ?, ?, ?, ?, 'active')`).run(`w${t}`, TENANT, `c${t}`, acct.address, 30_000 + t)
  initFrontier(db, `w${t}`, GENESIS, '100000')
  const r = reserveSend(db, { tenantId: TENANT, idempotencyKey: `k${t}`, fromAgentId: `c${t}`, walletId: `w${t}`, nanoAccount: acct.address,
    delegationId: `low${t}`, toAddress: DEST.address, amountRaw: '1000' }, { owner: 'route', now: clock, leaseMs: 30_000 })
  assert.ok('op' in r)
  return { op: r.op, acct, top: `top${t}`, low: `low${t}` }
}
const used = (id: string) => (getDB().prepare(`SELECT spend_used_minor FROM delegations WHERE id = ?`).get(id) as any).spend_used_minor

before(() => {
  setGenerousPilotCaps()
  initDB(':memory:')
  initGatewayIdentity()
  getDB().prepare(`INSERT OR IGNORE INTO tenants (id, name, email) VALUES (?, ?, ?)`).run(TENANT, 'Startup', 'st@test.local')
})
beforeEach(() => {
  clock += 1_000_000
  getDB().exec(`DELETE FROM wallet_op_attempts; DELETE FROM wallet_op_reservations; DELETE FROM wallet_ops;`)
  delete process.env.NANO_WALLETS_PAUSED
  process.env.NANO_WALLET_SEND_ENABLED = '1'
})

describe('startup recovery', () => {
  it('U1 an empty table: no node calls, state ok', async () => {
    const f = fakeNode()
    const h = startNanoLifecycle(getDB(), { ctx: ctx(f.node), tickMs: 3_600_000, gatewayAddress: null })
    await h.tickNow()
    const ready = getOpRunner().readiness()
    h.stop()
    assert.equal(f.calls.length, 0)
    assert.equal(h.status().state, 'ok')
    assert.equal(lifecycleHealth(h).code, 200)
    assert.equal(ready, null, 'ok: the runner takes new sends')
    assert.equal(getOpRunner().readiness(), 'lifecycle_not_installed', 'after stop no runner is installed')
  })

  it('U2 paused: an accepted-then-crashed send and a reserved send recover with no publish and no new block', async () => {
    const a = payment(), b = payment()
    const f = fakeNode()
    // a: prepared, attempt committed, node accepted, outcome never recorded (the crash).
    const claim = { owner: 'dead', now: clock + 40_000, leaseMs: 30_000 }
    const { takeOver } = await import('../../src/payment-rails/wallet-ops.js')
    const taken = takeOver(getDB(), a.op.id, claim)!
    const p = await prepareOp(getDB(), f.node, taken, claim, a.acct, DEST.address)
    const t = commitAttempt(getDB(), p, claim)
    assert.ok('token' in t)
    await f.node.call({ action: 'process', json_block: 'true', subtype: 'send', block: t.token.block })
    const storedA = getOp(getDB(), a.op.id)!.block_json
    process.env.NANO_WALLETS_PAUSED = '1'
    clock += 200_000
    const pausedSigner = () => { throw new Error('Nano wallets are paused by the operator (NANO_WALLETS_PAUSED=1).') }
    const h = startNanoLifecycle(getDB(), { ctx: ctx(f.node, pausedSigner), tickMs: 3_600_000, gatewayAddress: null })
    await h.tickNow()
    h.stop()
    assert.equal(f.process().length, 1, 'only the call from before the crash')
    assert.equal(getOp(getDB(), a.op.id)!.status, 'admitted')
    assert.equal(getOp(getDB(), a.op.id)!.block_json, storedA)
    assert.equal(listAttempts(getDB(), a.op.id).length, 1)
    assert.equal(getOp(getDB(), b.op.id)!.status, 'reserved', 'nothing signed while paused')
    assert.deepEqual([used(a.top), used(a.low), used(b.top), used(b.low)], ['1000', '1000', '1000', '1000'])
    assert.equal(h.status().pending, 2)
  })

  it('U3 unpaused after the crash: recovery republishes the same stored block once, keeps the reservation', async () => {
    const a = payment()
    const f = fakeNode()
    const claim = { owner: 'dead', now: clock + 40_000, leaseMs: 30_000 }
    const { takeOver } = await import('../../src/payment-rails/wallet-ops.js')
    const p = await prepareOp(getDB(), f.node, takeOver(getDB(), a.op.id, claim)!, claim, a.acct, DEST.address)
    const t = commitAttempt(getDB(), p, claim)
    assert.ok('token' in t)
    await f.node.call({ action: 'process', json_block: 'true', subtype: 'send', block: t.token.block })
    clock += 200_000
    const h = startNanoLifecycle(getDB(), { ctx: ctx(f.node), tickMs: 3_600_000, gatewayAddress: null })
    await h.tickNow()
    h.stop()
    const after = getOp(getDB(), a.op.id)!
    assert.equal(after.status, 'admitted')
    assert.equal(f.process().length, 2)
    assert.ok(f.process().every(c => stateBlockHash(c.block) === after.block_hash))
    assert.deepEqual(listReservations(getDB(), a.op.id).map(r => r.status), ['held', 'held'])
    assert.equal(h.status().state, 'ok')
  })

  it('U4 the node down: the pass reports degraded with the error, health is 503, nothing settles', async () => {
    const a = payment()
    const up = fakeNode()
    const claim = { owner: 'dead', now: clock + 40_000, leaseMs: 30_000 }
    const { takeOver } = await import('../../src/payment-rails/wallet-ops.js')
    const p = await prepareOp(getDB(), up.node, takeOver(getDB(), a.op.id, claim)!, claim, a.acct, DEST.address)
    assert.ok('token' in commitAttempt(getDB(), p, claim))
    clock += 200_000
    const down = fakeNode({ down: true })
    const h = startNanoLifecycle(getDB(), { ctx: ctx(down.node), tickMs: 3_600_000, gatewayAddress: null })
    await h.tickNow()
    const ready = getOpRunner().readiness()
    h.stop()
    assert.equal(h.status().state, 'degraded')
    assert.equal(ready, 'lifecycle_degraded', 'degraded: no new send is reserved')
    assert.match(String(h.status().last_error), /ECONNREFUSED/)
    assert.deepEqual(lifecycleHealth(h), { code: 503, body: { state: 'degraded' } }, 'no error text in the public body')
    assert.equal(getOp(getDB(), a.op.id)!.status, 'admitted')
    assert.deepEqual([used(a.top), used(a.low)], ['1000', '1000'])
  })

  it('U5 an unsafe wallet mapping: blocked, 503, and no attempt commits', async () => {
    const a = payment()
    getDB().prepare(`INSERT INTO agent_wallets (id, tenant_id, agent_id, nano_address, wallet_index, status) VALUES ('w-dup-st', ?, 'other', ?, 99_998, 'active')`).run(TENANT, a.acct.address)
    try {
      const f = fakeNode()
      clock += 40_000
      const h = startNanoLifecycle(getDB(), { ctx: ctx(f.node), tickMs: 3_600_000, gatewayAddress: null })
      await h.tickNow()
      const ready = getOpRunner().readiness()
      h.stop()
      assert.equal(h.status().state, 'blocked')
      assert.equal(ready, 'lifecycle_blocked')
      assert.equal(lifecycleHealth(h).code, 503)
      assert.equal(f.process().length, 0)
    } finally {
      getDB().prepare(`DELETE FROM agent_wallets WHERE id = 'w-dup-st'`).run()
    }
  })

  it('U7 one operation failing does not stop the pass for the others', async () => {
    const a = payment(), b = payment()
    // a is admitted and first in the pass. Its reconciliation fails on the node, which escapes runOp.
    getDB().prepare(`UPDATE wallet_ops SET created_at = '2000-01-01 00:00:00' WHERE id = ?`).run(a.op.id)
    const f = fakeNode()
    const claim = { owner: 'dead', now: clock + 40_000, leaseMs: 30_000 }
    const { takeOver } = await import('../../src/payment-rails/wallet-ops.js')
    const pa = await prepareOp(getDB(), f.node, takeOver(getDB(), a.op.id, claim)!, claim, a.acct, DEST.address)
    assert.ok('token' in commitAttempt(getDB(), pa, claim))
    clock += 200_000
    const picky: NanoNode = { call: async (body: any) => {
      if (body.hash === pa.block_hash) throw new Error('Nano RPC network error: ECONNRESET')
      return f.node.call(body)
    } }
    const h = startNanoLifecycle(getDB(), { ctx: ctx(picky), tickMs: 3_600_000, gatewayAddress: null })
    const results = await h.tickNow()
    h.stop()
    assert.equal(results[0].step, 'error')
    assert.equal(getOp(getDB(), b.op.id)!.status, 'admitted', 'b was still prepared and published')
    assert.equal(getOp(getDB(), a.op.id)!.status, 'admitted')
    assert.equal(h.status().state, 'degraded')
  })

  it('U6 before the first pass finishes the state is starting and health is 503', () => {
    const f = fakeNode()
    const h = startNanoLifecycle(getDB(), { ctx: ctx(f.node), tickMs: 3_600_000, gatewayAddress: null })
    const s = h.status()
    const ready = getOpRunner().readiness()
    h.stop()
    assert.equal(s.state, 'starting')
    assert.equal(ready, 'lifecycle_starting', 'no new send before the first pass finishes')
    assert.equal(lifecycleHealth({ status: () => s } as any).code, 503)
    assert.deepEqual(lifecycleHealth(null), { code: 200, body: { state: 'disabled' } })
  })
})

describe('watching released payments', () => {
  /** A payment released as failed_final at `clock`, whose stored block a node can later report confirmed. */
  async function released() {
    const a = payment()
    const f = fakeNode()
    const claim = { owner: 'dead', now: clock + 40_000, leaseMs: 30_000 }
    const { takeOver } = await import('../../src/payment-rails/wallet-ops.js')
    const p = await prepareOp(getDB(), f.node, takeOver(getDB(), a.op.id, claim)!, claim, a.acct, DEST.address)
    assert.ok('token' in commitAttempt(getDB(), p, claim))
    getDB().prepare(`UPDATE wallet_ops SET status = 'failed_final', lease_owner = NULL, lease_until = NULL, resolution = ? WHERE id = ?`)
      .run(JSON.stringify({ evidence: 'confirmed_conflict', source: 'fake', failed_at: clock }), a.op.id)
    getDB().prepare(`UPDATE wallet_op_reservations SET status = 'released' WHERE op_id = ?`).run(a.op.id)
    const op = getOp(getDB(), a.op.id)!
    return { ...a, op, block: JSON.parse(op.block_json!) }
  }
  function confirmingNode(op: WalletOp, block: any): NanoNode {
    return { async call(body: any) {
      if (body.action === 'block_info' && body.hash === op.block_hash) return { block_account: op.nano_account, confirmed: 'true', contents: block }
      throw new Error(`unexpected ${body.action}`)
    } }
  }
  const walletStatus = (id: string) => (getDB().prepare(`SELECT status FROM agent_wallets WHERE id = ?`).get(id) as any).status

  it('U8 a release later contradicted on the node: wallet frozen, state blocked, no new sends, until the operator records it resolved', async () => {
    const a = await released()
    clock += 1_000
    const h = startNanoLifecycle(getDB(), { ctx: ctx(confirmingNode(a.op, a.block)), tickMs: 3_600_000, gatewayAddress: null })
    await h.tickNow()
    assert.equal(walletStatus(a.op.wallet_id), 'frozen')
    assert.equal(h.status().state, 'blocked')
    assert.equal(h.status().contradicted, 1)
    assert.equal(getOpRunner().readiness(), 'lifecycle_blocked')
    assert.deepEqual(lifecycleHealth(h), { code: 503, body: { state: 'blocked' } })
    await h.tickNow()
    assert.equal(h.status().state, 'blocked', 'stays blocked on later passes while the wallet is frozen')
    getDB().prepare(`UPDATE agent_wallets SET status = 'active' WHERE id = ?`).run(a.op.wallet_id)
    await h.tickNow()
    assert.equal(h.status().state, 'blocked', 'unfreezing the wallet alone does not lift the block')
    assert.equal(resolveContradictedRelease(getDB(), a.op.id, 'operator', 'budgets reconciled', clock), true)
    assert.equal(resolveContradictedRelease(getDB(), a.op.id, 'operator', 'again', clock), false, 'recorded once')
    assert.equal(resolveContradictedRelease(getDB(), 'no-such-op', 'operator', 'x', clock), false)
    await h.tickNow()
    const after = h.status().state
    h.stop()
    assert.equal(after, 'ok', 'the recorded resolution lifts the block')
    assert.ok(getDB().prepare(`SELECT 1 FROM chain_spend_holds WHERE delegation_id = ?`).get(a.low), 'the chain hold stays an operator decision')
  })

  it('U10 while blocked by a contradiction, the pass still reconciles other payments', async () => {
    const a = await released()
    const b = payment()
    const base = fakeNode()
    const claim = { owner: 'dead', now: clock + 40_000, leaseMs: 30_000 }
    const { takeOver } = await import('../../src/payment-rails/wallet-ops.js')
    const pb = await prepareOp(getDB(), base.node, takeOver(getDB(), b.op.id, claim)!, claim, b.acct, DEST.address)
    assert.ok('token' in commitAttempt(getDB(), pb, claim))
    const bBlock = JSON.parse(getOp(getDB(), b.op.id)!.block_json!)
    const node: NanoNode = { async call(body: any) {
      if (body.action === 'block_info' && body.hash === a.op.block_hash) return { block_account: a.op.nano_account, confirmed: 'true', contents: a.block }
      if (body.action === 'block_info' && body.hash === pb.block_hash) return { block_account: b.acct.address, confirmed: 'true', contents: bBlock }
      return base.node.call(body)
    } }
    clock += 200_000
    const h = startNanoLifecycle(getDB(), { ctx: ctx(node), tickMs: 3_600_000, gatewayAddress: null })
    await h.tickNow()
    const state = h.status().state
    h.stop()
    assert.equal(state, 'blocked')
    assert.equal(getOp(getDB(), b.op.id)!.status, 'confirmed', 'reconciliation is read-only and keeps running while blocked')
    assert.deepEqual([used(b.top), used(b.low)], ['1000', '1000'])
  })

  async function admittedWith(resolution: object, freeze: boolean) {
    const a = payment()
    const f = fakeNode()
    const claim = { owner: 'dead', now: clock + 40_000, leaseMs: 30_000 }
    const { takeOver } = await import('../../src/payment-rails/wallet-ops.js')
    const p = await prepareOp(getDB(), f.node, takeOver(getDB(), a.op.id, claim)!, claim, a.acct, DEST.address)
    assert.ok('token' in commitAttempt(getDB(), p, claim))
    getDB().prepare(`UPDATE wallet_ops SET resolution = ? WHERE id = ?`).run(JSON.stringify(resolution), a.op.id)
    if (freeze) getDB().prepare(`UPDATE agent_wallets SET status = 'frozen' WHERE id = ?`).run(a.op.wallet_id)
    clock += 200_000
    return { ...a, f }
  }

  it('U11 an open conflict incident blocks new sends until resolveIncident, and the pass keeps running', async () => {
    const a = await admittedWith({ incident: { sibling: 'AB'.repeat(32), confirmed: true, balance_effect: 'decreased', sibling_balance_raw: '99000', prev_balance_raw: '100000', source: 'fake', at: clock } }, true)
    const h = startNanoLifecycle(getDB(), { ctx: ctx(a.f.node), tickMs: 3_600_000, gatewayAddress: null })
    await h.tickNow()
    assert.deepEqual([h.status().state, h.status().incidents], ['blocked', 1])
    assert.equal(getOpRunner().readiness(), 'lifecycle_blocked')
    getDB().prepare(`UPDATE agent_wallets SET status = 'active' WHERE id = ?`).run(a.op.wallet_id)
    await h.tickNow()
    assert.equal(h.status().state, 'blocked', 'unfreezing alone does not lift it')
    getDB().prepare(`UPDATE agent_wallets SET status = 'frozen' WHERE id = ?`).run(a.op.wallet_id)
    assert.deepEqual(resolveIncident(getDB(), a.op.id, { decision: 'ours_failed', by: 'operator', sibling: 'AB'.repeat(32), balance_effect: 'decreased',
      sibling_status: 'confirmed', sources: [{ source: 'operator-node', observed_at: clock }], disposition: { kind: 'loss_recorded', amount_raw: '1000' }, now: clock }), { ok: true })
    await h.tickNow()
    const after = h.status().state
    h.stop()
    assert.equal(after, 'ok')
  })

  it('U12 an open node fault refuses new sends (degraded) until resolveNodeFault, nothing frozen', async () => {
    const a = await admittedWith({ node_fault: { sibling: 'AB'.repeat(32), reason: 'sibling_signature_invalid', at: clock } }, false)
    const h = startNanoLifecycle(getDB(), { ctx: ctx(a.f.node), tickMs: 3_600_000, gatewayAddress: null })
    await h.tickNow()
    assert.deepEqual([h.status().state, h.status().node_faults], ['degraded', 1])
    assert.equal(getOpRunner().readiness(), 'lifecycle_degraded')
    assert.equal(resolveNodeFault(getDB(), a.op.id, { by: 'operator', evidence: 'node replaced', now: clock }), true)
    await h.tickNow()
    const after = h.status().state
    h.stop()
    assert.equal(after, 'ok')
    assert.equal((getDB().prepare(`SELECT status FROM agent_wallets WHERE id = ?`).get(a.op.wallet_id) as any).status, 'active')
  })

  it('U14 a node fault stays until resolveNodeFault even after the payment confirms', async () => {
    const a = await admittedWith({ node_fault: { sibling: 'AB'.repeat(32), reason: 'sibling_signature_invalid', at: clock } }, false)
    const op = getOp(getDB(), a.op.id)!
    const block = JSON.parse(op.block_json!)
    const node: NanoNode = { async call(body: any) {
      if (body.action === 'block_info' && body.hash === op.block_hash) return { block_account: op.nano_account, confirmed: 'true', contents: block }
      return a.f.node.call(body)
    } }
    const h = startNanoLifecycle(getDB(), { ctx: ctx(node), tickMs: 3_600_000, gatewayAddress: null })
    await h.tickNow()
    assert.equal(getOp(getDB(), a.op.id)!.status, 'confirmed')
    assert.deepEqual([h.status().state, h.status().node_faults], ['degraded', 1], 'the fault survives the confirmation')
    await h.tickNow()
    assert.equal(h.status().state, 'degraded')
    assert.equal(resolveNodeFault(getDB(), a.op.id, { by: 'operator', evidence: 'node replaced', now: clock }), true)
    await h.tickNow()
    const after = h.status().state
    h.stop()
    assert.equal(after, 'ok')
  })

  it('U13 a send waiting on a missing frontier record makes the pass degraded', async () => {
    const a = payment()
    getDB().prepare(`DELETE FROM wallet_frontiers WHERE nano_account = ?`).run(a.acct.address)
    clock += 40_000
    const f = fakeNode()
    const h = startNanoLifecycle(getDB(), { ctx: ctx(f.node), tickMs: 3_600_000, gatewayAddress: null })
    const results = await h.tickNow()
    const state = h.status().state
    h.stop()
    assert.equal(results[0].detail, 'frontier_not_initialized')
    assert.equal(state, 'degraded')
    assert.equal(f.process().length, 0)
  })

  it('U9 a release older than the watch window is not checked again', async () => {
    const a = await released()
    clock += 2_000
    const h = startNanoLifecycle(getDB(), { ctx: ctx(confirmingNode(a.op, a.block)), tickMs: 3_600_000, gatewayAddress: null, finalWatchMs: 1_000 })
    await h.tickNow()
    h.stop()
    assert.equal(walletStatus(a.op.wallet_id), 'active')
    assert.equal(h.status().state, 'ok')
  })
})

describe('schema and server start', () => {
  it('M1 a wallet_ops table of another shape stops initialization, naming the missing columns', () => {
    const db = new Database(':memory:')
    db.exec(`CREATE TABLE wallet_ops (id TEXT PRIMARY KEY, status TEXT)`)
    assert.throws(() => ensureWalletOpsTable(db), /\[migration\] wallet_ops is missing required columns: kind/)
  })

  it('M2 initialization is repeatable and leaves rows alone', () => {
    const db = new Database(':memory:')
    ensureWalletOpsTable(db)
    db.prepare(`INSERT INTO wallet_ops (id, kind, tenant_id, idempotency_key, request_fingerprint, nano_account, amount_raw, source_hash, status) VALUES ('x', 'receive', 't', 'k', 'fp', 'acct', '1', 's', 'reserved')`).run()
    ensureWalletOpsTable(db)
    ensureWalletOpsTable(db)
    assert.deepEqual(db.prepare(`SELECT id, status FROM wallet_ops`).all(), [{ id: 'x', status: 'reserved' }])
    assert.equal((db.prepare(`PRAGMA integrity_check`).get() as any).integrity_check, 'ok')
  })

  it('M3 the real server exits non-zero and never listens when the wallet_ops table has another shape', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'ops-start-'))
    const path = join(dir, 'start.db')
    const pre = new Database(path)
    pre.exec(`CREATE TABLE wallet_ops (id TEXT PRIMARY KEY, status TEXT)`)
    pre.close()
    const out = await runServer(path, {})
    rmSync(dir, { recursive: true, force: true })
    assert.notEqual(out.code, null, 'the server kept running with an incomplete schema')
    assert.notEqual(out.code, 0)
    assert.match(out.text, /\[migration\] wallet_ops is missing required columns/)
    assert.doesNotMatch(out.text, /Listening on/)
  })

  // This release does not activate the lifecycle (src/payment-rails/nano-activation.ts), so the real
  // server reports it disabled with no pause, the send switch on and the pilot caps set. With
  // activation it reports ok here.
  it('M4 the real server starts, does not install the lifecycle and reports it disabled on /healthz/nano-lifecycle', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'ops-up-'))
    const port = String(41_000 + Math.floor(Math.random() * 2000))
    const out = await runServer(join(dir, 'up.db'), { NANO_WALLET_SEND_ENABLED: '1', NANO_PILOT_MAX_PAYMENT_RAW: '1000', NANO_PILOT_MAX_WALLET_RAW: '10000', NANO_PILOT_MAX_PAYMENTS: '10', PORT: port }, async () => {
      for (let i = 0; i < 50; i++) {
        try {
          const r = await fetch(`http://127.0.0.1:${port}/healthz/nano-lifecycle`)
          const body = await r.json() as any
          if (body.state !== 'starting') return { status: r.status, body }
        } catch {}
        await new Promise(res => setTimeout(res, 200))
      }
      return null
    })
    rmSync(dir, { recursive: true, force: true })
    // The unauthenticated body is the state word and nothing else.
    assert.deepEqual(out.probe, { status: 200, body: { state: 'disabled' } })
  })
})

/** Spawn the real server entry. With `probe`, wait for it, then kill the server and return the probe result. */
async function runServer(dbPath: string, env: Record<string, string>, probe?: () => Promise<unknown>) {
  const child = spawn(process.execPath, ['--import', 'tsx', 'src/server.ts'], {
    cwd: process.cwd(),
    env: { ...process.env, DB_PATH: dbPath, PORT: '0', NODE_ENV: 'development', NANO_RPC_URL: 'http://127.0.0.1:9', ...env },
  })
  let text = ''
  child.stdout.on('data', d => { text += d })
  child.stderr.on('data', d => { text += d })
  if (probe) {
    const result = await probe()
    child.kill()
    await new Promise(res => child.on('exit', res))
    return { code: 0, text, probe: result }
  }
  const code = await new Promise<number | null>((resolve) => {
    const t = setTimeout(() => { child.kill(); resolve(null) }, 20_000)
    child.on('exit', c => { clearTimeout(t); resolve(c) })
  })
  return { code, text, probe: null }
}
