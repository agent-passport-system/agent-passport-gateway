// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Day 268, lifecycle phase D: the integrated lifecycle through the real route handlers, a runner
// in this process and a fake Nano ledger. Covers per-operation reservations, the block-to-payment
// binding, confirmation and conflict reconciliation, idempotency and 409 over HTTP, pause and
// revocation, crash recovery, and a contradicted failure. Nothing reaches a network.
// ══════════════════════════════════════════════════════════════════
import { describe, it, before, after, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import express from 'express'
import type { Server } from 'node:http'
// @ts-ignore nanocurrency-web has no type declarations
import nanoWebImport from 'nanocurrency-web'
import { initDB, getDB } from '../../src/db/schema.js'
import { initGatewayIdentity } from '../../src/gateway/identity.js'
import { walletRouter } from '../../src/payment-rails/wallet-routes.js'
import { stateBlockHash, canonicalBlockJson } from '../../src/payment-rails/nano-block.js'
import { getOp, listReservations, takeOver, type WalletOp } from '../../src/payment-rails/wallet-ops.js'
import { commitAttempt, listAttempts, type NanoNode } from '../../src/payment-rails/nano-publish.js'
import {
  inProcessRunner, lifecycleTick, reconcileOp, resolveIncident, resolveNodeFault, runOp, setOpRunner, watchFinalized, type IncidentResolution, type RunContext,
} from '../../src/payment-rails/wallet-reconcile.js'
import { setGenerousPilotCaps, initFrontier } from './pilot-fixtures.js'
import { getFrontier, initializeWalletFrontier } from '../../src/payment-rails/wallet-frontier.js'

const nano = (nanoWebImport as any).default || nanoWebImport
const GENESIS = 'F47B23107E5F34B2CE06F562B5C435DF72A533251CB414C51B2B62A8F63A00E4'
const DEST = nano.wallet.fromLegacySeed('cc'.repeat(32)).accounts[0]
const LEASE = 30_000
let n = 0
let clock = 1_000_000
let server: Server
let base = ''

/**
 * A fake ledger. Each account starts with one confirmed frontier and a balance. process() adds the
 * block unconfirmed (unless told to drop it). confirm() and conflict() change what block_info says.
 */
class FakeLedger {
  blocks = new Map<string, { block: any; account: string; confirmed: boolean }>()
  succ = new Map<string, string[]>()
  heads = new Map<string, { frontier: string; balance: string }>()
  processCalls: any[] = []
  dropProcess = false
  failProcess = false
  open(account: string, balance: string) {
    this.heads.set(account, { frontier: GENESIS, balance })
  }
  confirm(hash: string) {
    const b = this.blocks.get(hash)!
    b.confirmed = true
    this.heads.set(b.account, { frontier: hash, balance: b.block.balance })
  }
  /** A different confirmed block on `previous` for `acct`, signed by its key. */
  conflict(acct: any, previous: string, balance: string) {
    const blk = nano.block.send({ walletBalanceRaw: balance, fromAddress: acct.address, toAddress: acct.address,
      representativeAddress: acct.address, frontier: previous, amountRaw: '1', work: '0123456789abcdef' }, acct.privateKey)
    const h = stateBlockHash(blk)
    this.blocks.set(h, { block: JSON.parse(canonicalBlockJson(blk)), account: acct.address, confirmed: true })
    this.succ.set(previous, [h])
    return h
  }
  node: NanoNode = {
    call: async (body: any) => {
      switch (body.action) {
        case 'account_info': {
          const h = this.heads.get(body.account)
          if (!h) throw new Error('Nano RPC: Account not found')
          return { frontier: h.frontier, confirmed_frontier: h.frontier, confirmed_balance: h.balance, confirmed_representative: body.account }
        }
        case 'work_generate': return { work: '0123456789abcdef' }
        case 'process': {
          this.processCalls.push(body)
          if (this.failProcess) throw new Error('socket hang up')
          const h = stateBlockHash(body.block)
          if (!this.dropProcess && !this.blocks.has(h)) {
            this.blocks.set(h, { block: body.block, account: body.block.account, confirmed: false })
            const list = this.succ.get(body.block.previous) ?? []
            if (!list.includes(h)) this.succ.set(body.block.previous, [...list, h])
          }
          return { hash: h }
        }
        case 'block_info': {
          const b = this.blocks.get(String(body.hash).toUpperCase())
          if (!b) throw new Error('Nano RPC: Block not found')
          return { block_account: b.account, confirmed: b.confirmed ? 'true' : 'false', contents: b.block }
        }
        case 'successors': return { blocks: [body.block, ...(this.succ.get(body.block) ?? []).slice(0, 1)] }
        default: throw new Error(`unexpected ${body.action}`)
      }
    },
  }
}

let ledger: FakeLedger
const keys = new Map<string, any>()

function ctx(owner = 'runner-1'): RunContext {
  return {
    node: ledger.node, owner, leaseMs: LEASE, now: () => clock,
    signer: (op: WalletOp) => keys.get(op.nano_account),
    openRepresentative: DEST.address,
    reconcile: { source: 'fake-ledger' },
    rebroadcastMs: 10_000,
  }
}

/** A tenant with a paying agent, a two-hop chain in raw XNO, a wallet on a funded fake account. */
function setup(limit = '5000') {
  const t = ++n, tenant = `tnt_life_${t}`, root = `root-${t}`, p = `p-${t}`, c = `c-${t}`
  const db = getDB()
  db.prepare(`INSERT INTO tenants (id, name, email) VALUES (?, ?, ?)`).run(tenant, 'Life', `${tenant}@test.local`)
  for (const a of [root, p, c]) {
    db.prepare(`INSERT INTO agents (id, tenant_id, agent_id, public_key, status, is_root) VALUES (?, ?, ?, 'pk', 'active', 0)`).run(`row-${a}`, tenant, a)
  }
  const ins = db.prepare(`INSERT INTO delegations (id, tenant_id, parent_agent_id, child_agent_id, scope, status, spend_limit, spend_used, parent_delegation_id, spend_unit, spend_limit_minor, spend_used_minor) VALUES (?, ?, ?, ?, 'commerce:send', 'active', 0, 0, ?, 'nano:XNO:raw', ?, '0')`)
  ins.run(`top-${t}`, tenant, root, p, null, limit)
  ins.run(`low-${t}`, tenant, p, c, `top-${t}`, limit)
  const acct = nano.wallet.fromLegacySeed((0x3000 + t).toString(16).padStart(64, '0')).accounts[0]
  keys.set(acct.address, acct)
  db.prepare(`INSERT INTO agent_wallets (id, tenant_id, agent_id, nano_address, wallet_index, status) VALUES (?, ?, ?, ?, ?, 'active')`)
    .run(`w-${t}`, tenant, c, acct.address, 20_000 + t)
  ledger.open(acct.address, '100000')
  initFrontier(db, `w-${t}`, GENESIS, '100000')
  return { tenant, root, c, top: `top-${t}`, low: `low-${t}`, acct, wallet: `w-${t}` }
}
type S = ReturnType<typeof setup>
const used = (id: string) => (getDB().prepare(`SELECT spend_used_minor FROM delegations WHERE id = ?`).get(id) as any).spend_used_minor
const walletStatus = (id: string) => (getDB().prepare(`SELECT status FROM agent_wallets WHERE id = ?`).get(id) as any).status

async function send(s: S, key: string | null, body: Record<string, unknown> = {}) {
  const headers: Record<string, string> = { 'content-type': 'application/json', 'x-test-tenant': s.tenant }
  if (key) headers['idempotency-key'] = key
  const res = await fetch(`${base}/api/v1/wallets/send`, {
    method: 'POST', headers, body: JSON.stringify({ from_agent_id: s.c, to_address: DEST.address, amount_raw: '1000', ...body }),
  })
  return { status: res.status, body: await res.json() as any }
}
async function opStatus(s: S, id: string) {
  const res = await fetch(`${base}/api/v1/wallets/ops/${id}`, { headers: { 'x-test-tenant': s.tenant } })
  return { status: res.status, body: await res.json() as any }
}

before(async () => {
  setGenerousPilotCaps()
  initDB(':memory:')
  initGatewayIdentity()
  const app = express()
  app.use(express.json())
  app.use((req: any, _res, next) => { req.tenant = { id: req.get('x-test-tenant'), name: 't', plan: 'enterprise' }; next() })
  app.use('/api/v1', walletRouter)
  await new Promise<void>((resolve) => { server = app.listen(0, () => resolve()) })
  const addr = server.address()
  base = `http://127.0.0.1:${typeof addr === 'object' && addr ? addr.port : 0}`
})
after(async () => {
  setOpRunner(null)
  delete process.env.NANO_WALLET_SEND_ENABLED
  delete process.env.NANO_WALLETS_PAUSED
  await new Promise<void>((resolve) => server.close(() => resolve()))
})
beforeEach(() => {
  ledger = new FakeLedger()
  clock += 1_000_000
  delete process.env.NANO_WALLETS_PAUSED
  process.env.NANO_WALLET_SEND_ENABLED = '1'
  // The routes reserve under this runner's owner and clock. It schedules nothing, so each test
  // drives operations itself with runOp or lifecycleTick.
  setOpRunner({ owner: 'no-runner', leaseMs: LEASE, now: () => clock, schedule: () => {}, readiness: () => null })
})

describe('through the routes', () => {
  it('L1 202, one block published, confirmed only after the ledger confirms it, reservation consumed', async () => {
    const s = setup()
    const runner = inProcessRunner(getDB(), ctx())
    setOpRunner(runner)
    const r = await send(s, 'pay-1')
    assert.equal(r.status, 202)
    assert.equal(r.body.status, 'reserved')
    await runner.idle()
    const id = r.body.operation_id
    assert.equal((await opStatus(s, id)).body.status, 'admitted', 'node acceptance is not confirmation')
    assert.equal(ledger.processCalls.length, 1)
    clock += 1
    assert.equal((await runOp(getDB(), id, ctx())).status, 'admitted', 'still unconfirmed on the ledger')
    assert.equal(ledger.processCalls.length, 1, 'no rebroadcast inside the rebroadcast interval')
    ledger.confirm(getOp(getDB(), id)!.block_hash!)
    assert.equal((await runOp(getDB(), id, ctx())).status, 'confirmed')
    const view = (await opStatus(s, id)).body
    assert.equal(view.status, 'confirmed')
    assert.equal(view.resolution.evidence, 'block_info')
    assert.deepEqual(listReservations(getDB(), id).map(x => x.status), ['consumed', 'consumed'])
    assert.deepEqual([used(s.top), used(s.low)], ['1000', '1000'])
    const hist = getDB().prepare(`SELECT status, block_hash FROM wallet_transactions WHERE id = ?`).get(`wtx-${id}`) as any
    assert.deepEqual(hist, { status: 'confirmed', block_hash: view.block_hash })
  })

  it('L2 the same key returns the same operation, a changed request is 409, a missing key is 400', async () => {
    const s = setup()
    const first = await send(s, 'pay-2')
    const again = await send(s, 'pay-2')
    assert.equal(again.status, 202)
    assert.equal(again.body.replay, true)
    assert.equal(again.body.operation_id, first.body.operation_id)
    const changed = await send(s, 'pay-2', { amount_raw: '1001' })
    assert.equal(changed.status, 409)
    assert.equal(changed.body.error, 'idempotency_mismatch')
    const noKey = await send(s, null)
    assert.equal(noKey.status, 400)
    assert.match(noKey.body.error, /Idempotency-Key/)
    assert.deepEqual([used(s.top), used(s.low)], ['1000', '1000'])
  })

  it('L3 a second payment on a busy account is 409 wallet_busy, with no debit kept', async () => {
    const s = setup()
    assert.equal((await send(s, 'pay-3a')).status, 202)
    const busy = await send(s, 'pay-3b')
    assert.equal(busy.status, 409)
    assert.equal(busy.body.error, 'wallet_busy')
    assert.deepEqual([used(s.top), used(s.low)], ['1000', '1000'])
  })

  it('L4 paused: 403 at the route, nothing reserved, nothing published', async () => {
    const s = setup()
    process.env.NANO_WALLETS_PAUSED = '1'
    const r = await send(s, 'pay-4')
    assert.equal(r.status, 403)
    assert.equal(getDB().prepare(`SELECT COUNT(*) AS c FROM wallet_ops WHERE tenant_id = ?`).get(s.tenant).c, 0)
    assert.equal(ledger.processCalls.length, 0)
  })

  it('L5 revoked after reservation and before the first attempt: cancelled, released, nothing published', async () => {
    const s = setup()
    const r = await send(s, 'pay-5')
    getDB().prepare(`UPDATE delegations SET status = 'revoked' WHERE id = ?`).run(s.low)
    const out = await runOp(getDB(), r.body.operation_id, ctx('no-runner'))
    assert.equal(out.status, 'cancelled')
    assert.deepEqual([used(s.top), used(s.low)], ['0', '0'])
    assert.deepEqual(listReservations(getDB(), r.body.operation_id).map(x => x.status), ['released', 'released'])
    assert.equal(ledger.processCalls.length, 0)
  })

  it('L6 the receive route and settlement stay closed', async () => {
    const s = setup()
    const res = await fetch(`${base}/api/v1/wallets/${s.c}/receive`, { method: 'POST', headers: { 'x-test-tenant': s.tenant } })
    assert.equal(res.status, 503)
    assert.equal(ledger.processCalls.length, 0)
  })
})

describe('reservation ownership and block binding', () => {
  it('O1 each send holds its own reservation rows, and admission checks them, not the shared counter', async () => {
    const s = setup()
    const r = await send(s, 'own-1')
    const id = r.body.operation_id
    assert.deepEqual(listReservations(getDB(), id).map(x => [x.delegation_id, x.amount_raw, x.status]).sort(),
      [[s.low, '1000', 'held'], [s.top, '1000', 'held']].sort())
    await runOp(getDB(), id, ctx('no-runner')) // prepares and publishes
    // Another payment's debit sits on the same counter, and this operation's own rows are gone.
    getDB().prepare(`UPDATE delegations SET spend_used_minor = '5000' WHERE id IN (?, ?)`).run(s.top, s.low)
    getDB().prepare(`UPDATE wallet_op_reservations SET status = 'released' WHERE op_id = ?`).run(id)
    clock += 20_000
    const out = await runOp(getDB(), id, ctx('no-runner'))
    assert.equal(out.detail, 'reservation_not_held')
    assert.equal(ledger.processCalls.length, 1, 'no rebroadcast without its own reservation')
  })

  it('O2 a validly signed block moving more than the reserved amount, with consistent hash and fields, is refused', async () => {
    const s = setup()
    const r = await send(s, 'bind-1')
    const id = r.body.operation_id
    const c = ctx('no-runner')
    const { prepareOp } = await import('../../src/payment-rails/nano-publish.js')
    const op = await prepareOp(getDB(), ledger.node, getOp(getDB(), id)!, { owner: c.owner, now: clock, leaseMs: LEASE }, s.acct, DEST.address)
    // Re-sign a block for 2000 from the same previous and make every stored field agree with it.
    const big = nano.block.send({ walletBalanceRaw: '100000', fromAddress: s.acct.address, toAddress: DEST.address,
      representativeAddress: s.acct.address, frontier: GENESIS, amountRaw: '2000', work: '0123456789abcdef' }, s.acct.privateKey)
    getDB().prepare(`UPDATE wallet_ops SET block_json = ?, block_hash = ?, block_balance_raw = ? WHERE id = ?`)
      .run(canonicalBlockJson(big), stateBlockHash(big), big.balance, id)
    assert.deepEqual(commitAttempt(getDB(), op, { owner: c.owner, now: clock + 1, leaseMs: LEASE }), { refused: 'stored_block_amount_mismatch', cancelled: false })
    // A validly signed block for another account, made consistent the same way.
    const other = setup()
    const wrong = nano.block.send({ walletBalanceRaw: '100000', fromAddress: other.acct.address, toAddress: DEST.address,
      representativeAddress: other.acct.address, frontier: GENESIS, amountRaw: '1000', work: '0123456789abcdef' }, other.acct.privateKey)
    getDB().prepare(`UPDATE wallet_ops SET block_json = ?, block_hash = ?, block_balance_raw = ? WHERE id = ?`)
      .run(canonicalBlockJson(wrong), stateBlockHash(wrong), wrong.balance, id)
    assert.deepEqual(commitAttempt(getDB(), op, { owner: c.owner, now: clock + 2, leaseMs: LEASE }), { refused: 'stored_block_account_mismatch', cancelled: false })
    // A validly signed block for the right amount on another previous.
    const SOURCE = '19D3D919475DEED4696B5D13018151D1AF88B2BD3BCFF048B45031C1F36D1858'
    const moved = nano.block.send({ walletBalanceRaw: '100000', fromAddress: s.acct.address, toAddress: DEST.address,
      representativeAddress: s.acct.address, frontier: SOURCE, amountRaw: '1000', work: '0123456789abcdef' }, s.acct.privateKey)
    getDB().prepare(`UPDATE wallet_ops SET block_json = ?, block_hash = ?, block_balance_raw = ? WHERE id = ?`)
      .run(canonicalBlockJson(moved), stateBlockHash(moved), moved.balance, id)
    assert.deepEqual(commitAttempt(getDB(), op, { owner: c.owner, now: clock + 3, leaseMs: LEASE }), { refused: 'stored_block_previous_mismatch', cancelled: false })
    // The approved block with its signature changed: the hash does not cover the signature.
    const good = JSON.parse(op.block_json!)
    const flipped = { ...good, signature: (good.signature[0] === 'A' ? 'B' : 'A') + good.signature.slice(1) }
    getDB().prepare(`UPDATE wallet_ops SET block_json = ?, block_hash = ?, block_balance_raw = ? WHERE id = ?`)
      .run(JSON.stringify(flipped), op.block_hash, op.block_balance_raw, id)
    assert.deepEqual(commitAttempt(getDB(), op, { owner: c.owner, now: clock + 4, leaseMs: LEASE }), { refused: 'stored_block_signature_invalid', cancelled: false })
    assert.equal(ledger.processCalls.length, 0)
  })

  it('O3 a reservation row with another amount, or a missing one, is refused', async () => {
    for (const [tamper, reason] of [
      [(id: string) => getDB().prepare(`UPDATE wallet_op_reservations SET amount_raw = '999' WHERE op_id = ? AND delegation_id LIKE 'low-%'`).run(id), 'reservation_amount_mismatch'],
      [(id: string) => getDB().prepare(`DELETE FROM wallet_op_reservations WHERE op_id = ? AND delegation_id LIKE 'top-%'`).run(id), 'reservation_missing'],
    ] as Array<[(id: string) => unknown, string]>) {
      const s = setup()
      const r = await send(s, `own-3-${reason}`)
      tamper(r.body.operation_id)
      const out = await runOp(getDB(), r.body.operation_id, ctx('no-runner'))
      assert.equal(out.detail, reason)
      assert.equal(getOp(getDB(), r.body.operation_id)!.status, 'prepared')
    }
    assert.equal(ledger.processCalls.length, 0)
  })

  it('O4 releasing twice: the second refuses and the amount comes back once', async () => {
    const { releaseReservations } = await import('../../src/payment-rails/wallet-ops.js')
    const s = setup()
    const r = await send(s, 'own-4')
    const op = getOp(getDB(), r.body.operation_id)!
    assert.equal(getDB().transaction(() => releaseReservations(getDB(), op))(), 2)
    assert.throws(() => getDB().transaction(() => releaseReservations(getDB(), op))(), /reservation_not_held/)
    assert.deepEqual([used(s.top), used(s.low)], ['0', '0'])
  })

  it('O5 a three-row chain whose delegation ids do not sort in chain order is not refused', async () => {
    const t = ++n, tenant = `tnt_life_${t}`
    const db = getDB()
    db.prepare(`INSERT INTO tenants (id, name, email) VALUES (?, ?, ?)`).run(tenant, 'Life3', `${tenant}@test.local`)
    for (const a of ['g0', 'g1', 'g2', 'g3']) {
      db.prepare(`INSERT INTO agents (id, tenant_id, agent_id, public_key, status, is_root) VALUES (?, ?, ?, 'pk', 'active', 0)`).run(`row-${a}-${t}`, tenant, `${a}-${t}`)
    }
    const ins = db.prepare(`INSERT INTO delegations (id, tenant_id, parent_agent_id, child_agent_id, scope, status, spend_limit, spend_used, parent_delegation_id, spend_unit, spend_limit_minor, spend_used_minor) VALUES (?, ?, ?, ?, 'commerce:send', 'active', 0, 0, ?, 'nano:XNO:raw', '9000', '0')`)
    ins.run(`zz-${t}`, tenant, `g0-${t}`, `g1-${t}`, null)
    ins.run(`aa-${t}`, tenant, `g1-${t}`, `g2-${t}`, `zz-${t}`)
    ins.run(`mm-${t}`, tenant, `g2-${t}`, `g3-${t}`, `aa-${t}`)
    const acct = nano.wallet.fromLegacySeed((0x3000 + t).toString(16).padStart(64, '0')).accounts[0]
    keys.set(acct.address, acct)
    db.prepare(`INSERT INTO agent_wallets (id, tenant_id, agent_id, nano_address, wallet_index, status) VALUES (?, ?, ?, ?, ?, 'active')`).run(`w3-${t}`, tenant, `g3-${t}`, acct.address, 20_000 + t)
    ledger.open(acct.address, '100000')
    initFrontier(db, `w3-${t}`, GENESIS, '100000')
    const s3 = { tenant, c: `g3-${t}` } as any
    const r = await send(s3, 'three-1')
    assert.equal(r.status, 202)
    assert.equal(listReservations(db, r.body.operation_id).length, 3)
    const out = await runOp(db, r.body.operation_id, ctx('no-runner'))
    assert.equal(out.step, 'published_accepted')
    ledger.confirm(getOp(db, r.body.operation_id)!.block_hash!)
    clock += 1
    assert.equal((await runOp(db, r.body.operation_id, ctx('no-runner'))).status, 'confirmed')
    assert.deepEqual(listReservations(db, r.body.operation_id).map(x => x.status), ['consumed', 'consumed', 'consumed'])
  })
})

describe('reconciliation', () => {
  it('R1 a block on our previous signed with the account key is an incident: wallet frozen, chain held, reservation held, nothing released by time', async () => {
    const s = setup()
    const r = await send(s, 'rec-1')
    const id = r.body.operation_id
    ledger.dropProcess = true
    await runOp(getDB(), id, ctx('no-runner'))
    // Signed with the account's own key, as the gateway in an earlier life or a second process would sign it.
    const other = ledger.conflict(s.acct, GENESIS, '100000')
    clock += 1
    const out = await runOp(getDB(), id, ctx('no-runner'))
    assert.deepEqual([out.status, out.step, out.detail], ['admitted', 'incident', other])
    const res = JSON.parse(getOp(getDB(), id)!.resolution!)
    assert.equal(res.incident.balance_effect, 'decreased', 'the other block moved money out')
    assert.equal(res.incident.confirmed, true)
    assert.equal(walletStatus(s.wallet), 'frozen')
    assert.ok(getDB().prepare(`SELECT 1 FROM chain_spend_holds WHERE delegation_id = ? AND reason = ?`).get(s.low, `conflict_incident:${id}`))
    const calls = ledger.processCalls.length
    for (let i = 0; i < 3; i++) {
      clock += 3_600_000
      assert.equal((await runOp(getDB(), id, ctx('no-runner'))).step, 'incident')
    }
    assert.equal(getOp(getDB(), id)!.status, 'admitted')
    assert.deepEqual([used(s.top), used(s.low)], ['1000', '1000'])
    assert.deepEqual(listReservations(getDB(), id).map(x => x.status), ['held', 'held'])
    assert.equal(ledger.processCalls.length, calls, 'nothing republished from a frozen wallet')
  })

  it('R1b the same holds for a signed block no node calls confirmed: containment does not wait for confirmation', async () => {
    const s = setup()
    const r = await send(s, 'rec-1b')
    const id = r.body.operation_id
    ledger.dropProcess = true
    await runOp(getDB(), id, ctx('no-runner'))
    const h = ledger.conflict(s.acct, GENESIS, '100000')
    ledger.blocks.get(h)!.confirmed = false
    clock += 1
    assert.equal((await runOp(getDB(), id, ctx('no-runner'))).step, 'incident')
    assert.equal(JSON.parse(getOp(getDB(), id)!.resolution!).incident.confirmed, false)
    assert.equal(walletStatus(s.wallet), 'frozen')
    assert.deepEqual([used(s.top), used(s.low)], ['1000', '1000'])
  })

  it('R2 a block unknown to the node and a node error keep the reservation', async () => {
    const s = setup()
    const r = await send(s, 'rec-2')
    const id = r.body.operation_id
    ledger.dropProcess = true
    await runOp(getDB(), id, ctx('no-runner'))
    clock += 1
    assert.equal((await runOp(getDB(), id, ctx('no-runner'))).status, 'admitted')
    const broken = { ...ctx('no-runner'), node: { call: async () => { throw new Error('ECONNREFUSED') } } }
    clock += 100_000
    await assert.rejects(() => runOp(getDB(), id, broken))
    assert.equal(getOp(getDB(), id)!.status, 'admitted')
    assert.deepEqual([used(s.top), used(s.low)], ['1000', '1000'])
    assert.equal(walletStatus(s.wallet), 'active')
  })

  it('R3 reconciliation runs while paused, and confirms without publishing', async () => {
    const s = setup()
    const r = await send(s, 'rec-3')
    const id = r.body.operation_id
    await runOp(getDB(), id, ctx('no-runner'))
    ledger.confirm(getOp(getDB(), id)!.block_hash!)
    process.env.NANO_WALLETS_PAUSED = '1'
    clock += 1
    assert.equal((await runOp(getDB(), id, ctx('no-runner'))).status, 'confirmed')
    assert.equal(ledger.processCalls.length, 1)
  })

  it('R4 paused with an unknown outcome: no rebroadcast, reservation kept', async () => {
    const s = setup()
    const r = await send(s, 'rec-4')
    const id = r.body.operation_id
    ledger.dropProcess = true
    await runOp(getDB(), id, ctx('no-runner'))
    process.env.NANO_WALLETS_PAUSED = '1'
    clock += 100_000
    const out = await runOp(getDB(), id, ctx('no-runner'))
    assert.equal(out.detail, 'nano_wallets_paused')
    assert.equal(ledger.processCalls.length, 1)
    assert.deepEqual([used(s.top), used(s.low)], ['1000', '1000'])
  })

  it('R5 revoked after the first attempt: no rebroadcast, reservation kept until evidence', async () => {
    const s = setup()
    const r = await send(s, 'rec-5')
    const id = r.body.operation_id
    ledger.dropProcess = true
    await runOp(getDB(), id, ctx('no-runner'))
    getDB().prepare(`UPDATE delegations SET status = 'revoked' WHERE id = ?`).run(s.low)
    clock += 100_000
    assert.equal((await runOp(getDB(), id, ctx('no-runner'))).detail, 'delegation_not_active')
    assert.equal(ledger.processCalls.length, 1)
    assert.equal(getOp(getDB(), id)!.status, 'admitted')
    assert.deepEqual([used(s.top), used(s.low)], ['1000', '1000'])
  })

  it('R6 evidence that does not match our block is not confirmation', async () => {
    const s = setup()
    const r = await send(s, 'rec-6')
    const id = r.body.operation_id
    await runOp(getDB(), id, ctx('no-runner'))
    const h = getOp(getDB(), id)!.block_hash!
    const stored = ledger.blocks.get(h)!
    stored.confirmed = true
    stored.account = DEST.address // the node reports another account for our hash
    clock += 1
    assert.equal((await runOp(getDB(), id, ctx('no-runner'))).status, 'admitted')
    stored.account = s.acct.address
    stored.block = { ...stored.block, balance: '1' } // contents that do not hash to our block
    clock += 1
    assert.equal((await runOp(getDB(), id, ctx('no-runner'))).status, 'admitted')
  })

  it('R7 a block a node lists after our previous that names another previous is a node fault: no freeze, reservation held', async () => {
    const s = setup()
    const r = await send(s, 'rec-7')
    const id = r.body.operation_id
    ledger.dropProcess = true
    await runOp(getDB(), id, ctx('no-runner'))
    const SOURCE = '19D3D919475DEED4696B5D13018151D1AF88B2BD3BCFF048B45031C1F36D1858'
    const elsewhere = nano.block.send({ walletBalanceRaw: '100000', fromAddress: s.acct.address, toAddress: s.acct.address,
      representativeAddress: s.acct.address, frontier: SOURCE, amountRaw: '1', work: '0123456789abcdef' }, s.acct.privateKey)
    const h = stateBlockHash(elsewhere)
    ledger.blocks.set(h, { block: JSON.parse(canonicalBlockJson(elsewhere)), account: s.acct.address, confirmed: true })
    ledger.succ.set(GENESIS, [h])
    for (let i = 0; i < 3; i++) { clock += 70_000; await runOp(getDB(), id, ctx('no-runner')) }
    const out = await runOp(getDB(), id, ctx('no-runner'))
    assert.deepEqual([out.step, out.detail], ['node_fault', 'sibling_previous_mismatch'])
    assert.equal(getOp(getDB(), id)!.status, 'admitted')
    assert.equal(walletStatus(s.wallet), 'active')
    assert.deepEqual([used(s.top), used(s.low)], ['1000', '1000'])
  })

  it('R8 a node reporting a block on our previous whose signature does not verify: node fault, no freeze, reservation held', async () => {
    const s = setup()
    const r = await send(s, 'rec-8')
    const id = r.body.operation_id
    ledger.dropProcess = true
    await runOp(getDB(), id, ctx('no-runner'))
    // A fabricated block for our account: right account, previous and hash, signed by another key.
    const other = nano.wallet.fromLegacySeed('dd'.repeat(32)).accounts[0]
    const fake = nano.block.send({ walletBalanceRaw: '100000', fromAddress: s.acct.address, toAddress: DEST.address,
      representativeAddress: s.acct.address, frontier: GENESIS, amountRaw: '90000', work: '0123456789abcdef' }, other.privateKey)
    const h = stateBlockHash(fake)
    ledger.blocks.set(h, { block: JSON.parse(canonicalBlockJson(fake)), account: s.acct.address, confirmed: true })
    ledger.succ.set(GENESIS, [h])
    clock += 1
    const out = await runOp(getDB(), id, ctx('no-runner'))
    assert.deepEqual([out.step, out.detail], ['node_fault', 'sibling_signature_invalid'])
    assert.equal(walletStatus(s.wallet), 'active')
    assert.equal(JSON.parse(getOp(getDB(), id)!.resolution!).node_fault.reason, 'sibling_signature_invalid')
    assert.deepEqual([used(s.top), used(s.low)], ['1000', '1000'])
  })

  it('R9 a node naming a block on our previous that it cannot produce: node fault', async () => {
    const s = setup()
    const r = await send(s, 'rec-9')
    const id = r.body.operation_id
    ledger.dropProcess = true
    await runOp(getDB(), id, ctx('no-runner'))
    ledger.succ.set(GENESIS, ['AB'.repeat(32)])
    clock += 1
    const out = await runOp(getDB(), id, ctx('no-runner'))
    assert.deepEqual([out.step, out.detail], ['node_fault', 'sibling_not_found'])
    assert.equal(walletStatus(s.wallet), 'active')
  })
})

describe('terminal accounting is all or nothing', () => {
  async function published(key: string) {
    const s = setup()
    const r = await send(s, key)
    const id = r.body.operation_id
    await runOp(getDB(), id, ctx('no-runner'))
    return { s, id }
  }
  const snapshot = (s: S, id: string) => ({
    status: getOp(getDB(), id)!.status,
    used: [used(s.top), used(s.low)],
    rows: listReservations(getDB(), id).map(x => [x.delegation_id, x.amount_raw, x.status]),
    history: (getDB().prepare(`SELECT COUNT(*) AS c FROM wallet_transactions WHERE id = ?`).get(`wtx-${id}`) as any).c,
  })

  it('T1 a confirmed payment with a reservation row missing: nothing settles, it stays admitted', async () => {
    const { s, id } = await published('term-1')
    getDB().prepare(`DELETE FROM wallet_op_reservations WHERE op_id = ? AND delegation_id = ?`).run(id, s.top)
    const before = snapshot(s, id)
    ledger.confirm(getOp(getDB(), id)!.block_hash!)
    clock += 1
    const out = await runOp(getDB(), id, ctx('no-runner'))
    assert.equal(out.step, 'integrity_fault')
    assert.deepEqual(snapshot(s, id), before)
    assert.equal(before.status, 'admitted')
    assert.equal(before.history, 0)
  })

  it('T2 an operator release with a reservation amount changed: nothing releases, it stays admitted', async () => {
    const { s, id } = await published('term-2')
    ledger.blocks.delete(getOp(getDB(), id)!.block_hash!)
    ledger.succ.delete(GENESIS)
    ledger.conflict(s.acct, GENESIS, '100000')
    clock += 1; assert.equal((await runOp(getDB(), id, ctx('no-runner'))).step, 'incident')
    getDB().prepare(`UPDATE wallet_op_reservations SET amount_raw = '999' WHERE op_id = ? AND delegation_id = ?`).run(id, s.low)
    const before = snapshot(s, id)
    const sibling = JSON.parse(getOp(getDB(), id)!.resolution!).incident.sibling
    const out = resolveIncident(getDB(), id, { decision: 'ours_failed', by: 'op', sibling, balance_effect: 'decreased', sibling_status: 'confirmed',
      sources: [{ source: 'operator-node', observed_at: clock }], disposition: { kind: 'loss_recorded', amount_raw: '1' }, now: clock })
    assert.deepEqual(out, { ok: false, reason: 'reservation_inconsistent' })
    assert.deepEqual(snapshot(s, id), before)
    assert.deepEqual(before.used, ['1000', '1000'])
  })

  it('T3 a cancel with one reservation row already released: nothing changes', async () => {
    const s = setup()
    const r = await send(s, 'term-3')
    const id = r.body.operation_id
    getDB().prepare(`UPDATE wallet_op_reservations SET status = 'released' WHERE op_id = ? AND delegation_id = ?`).run(id, s.top)
    const before = snapshot(s, id)
    const { cancelOp } = await import('../../src/payment-rails/wallet-ops.js')
    assert.throws(() => cancelOp(getDB(), getOp(getDB(), id)!, { owner: 'no-runner', now: clock, leaseMs: LEASE }, 'test'), /reservation_not_held/)
    assert.deepEqual(snapshot(s, id), before)
    assert.equal(before.status, 'reserved')
  })
})

describe('crash recovery', () => {
  // lifecycleTick runs every operation in the database, so these tests start from an empty one.
  before(() => { initDB(':memory:'); initGatewayIdentity() })
  it('C1 the node accepted the block and the process died before recording it: recovery keeps the reservation, republishes the same block, builds no other', async () => {
    const s = setup()
    const r = await send(s, 'crash-1')
    const id = r.body.operation_id
    const c1 = ctx('dead-worker')
    // Prepare and commit the attempt, then hand the block to the node and "crash" before recordOutcome.
    const { prepareOp } = await import('../../src/payment-rails/nano-publish.js')
    clock += LEASE + 1 // the route's reservation lease has expired, so this worker takes the row
    const claimed = takeOver(getDB(), id, { owner: c1.owner, now: clock, leaseMs: LEASE })!
    const op = await prepareOp(getDB(), ledger.node, claimed, { owner: c1.owner, now: clock, leaseMs: LEASE }, s.acct, DEST.address)
    const a = commitAttempt(getDB(), op, { owner: c1.owner, now: clock + 1, leaseMs: LEASE })
    assert.ok('token' in a)
    await ledger.node.call({ action: 'process', json_block: 'true', subtype: 'send', block: a.token.block })
    assert.equal(listAttempts(getDB(), id)[0].outcome, null, 'the outcome was never recorded')
    const storedBlock = getOp(getDB(), id)!.block_json

    // A new process starts. Its tick finds the expired lease and recovers.
    clock += LEASE + 20_000
    const results = await lifecycleTick(getDB(), ctx('recovery'))
    assert.ok(results.length >= 1)
    const after = getOp(getDB(), id)!
    assert.equal(after.status, 'admitted')
    assert.equal(after.block_json, storedBlock, 'the same stored block')
    assert.ok(ledger.processCalls.every(c => stateBlockHash(c.block) === after.block_hash), 'no other block was ever published')
    assert.deepEqual([used(s.top), used(s.low)], ['1000', '1000'])
    ledger.confirm(after.block_hash!)
    clock += 1
    await lifecycleTick(getDB(), ctx('recovery'))
    assert.equal(getOp(getDB(), id)!.status, 'confirmed')
  })

  it('C2 a reserved operation whose worker died is prepared and published by recovery, once', async () => {
    const s = setup()
    const r = await send(s, 'crash-2')
    clock += LEASE + 1
    await lifecycleTick(getDB(), ctx('recovery'))
    const op = getOp(getDB(), r.body.operation_id)!
    assert.equal(op.status, 'admitted')
    assert.equal(ledger.processCalls.length, 1)
  })

  it('C3 an amount the account cannot cover is cancelled at preparation, released, never signed', async () => {
    const s = setup()
    ledger.open(s.acct.address, '500')
    initFrontier(getDB(), s.wallet, GENESIS, '500', true)
    const r = await send(s, 'crash-3')
    const out = await runOp(getDB(), r.body.operation_id, ctx('no-runner'))
    assert.equal(out.status, 'cancelled')
    assert.deepEqual([used(s.top), used(s.low)], ['0', '0'])
    assert.equal(ledger.processCalls.length, 0)
  })
})

describe('operator resolution of an incident', () => {
  async function incident(key: string) {
    const s = setup()
    const r = await send(s, key)
    const id = r.body.operation_id
    ledger.dropProcess = true
    await runOp(getDB(), id, ctx('no-runner'))
    const other = ledger.conflict(s.acct, GENESIS, '100000')
    clock += 1
    assert.equal((await runOp(getDB(), id, ctx('no-runner'))).step, 'incident')
    return { s, id, other }
  }
  // The incident's other block lowered the balance by 1 raw (ledger.conflict sends 1 raw).
  const full = (sibling: string, decision: 'ours_confirmed' | 'ours_failed', over: Partial<IncidentResolution> = {}): IncidentResolution => ({
    decision, by: 'operator', sibling, balance_effect: 'decreased',
    sibling_status: decision === 'ours_failed' ? 'confirmed' : 'rejected',
    sources: [{ source: 'operator-node', observed_at: clock }],
    disposition: decision === 'ours_failed' ? { kind: 'loss_recorded', amount_raw: '1' } : { kind: 'no_funds_moved' },
    now: clock, ...over,
  })

  it('OR1 an incomplete resolution is refused and changes nothing', async () => {
    const { s, id, other } = await incident('or-1')
    assert.deepEqual(resolveIncident(getDB(), id, full(other, 'ours_failed', { by: ' ' })), { ok: false, reason: 'resolution_incomplete' })
    assert.deepEqual(resolveIncident(getDB(), id, full(other, 'ours_failed', { decision: 'release' as any })), { ok: false, reason: 'bad_decision' })
    assert.deepEqual(resolveIncident(getDB(), id, full(other, 'ours_failed', { sources: [] })), { ok: false, reason: 'no_independent_source' })
    assert.deepEqual(resolveIncident(getDB(), id, full(other, 'ours_failed', { sources: [{ source: 'fake-ledger', observed_at: clock }] })),
      { ok: false, reason: 'no_independent_source' }, 'the node that reported the incident does not count')
    assert.deepEqual(resolveIncident(getDB(), id, full(other, 'ours_failed', { disposition: undefined as any })), { ok: false, reason: 'disposition_missing' })
    assert.equal(getOp(getDB(), id)!.status, 'admitted')
    assert.deepEqual([used(s.top), used(s.low)], ['1000', '1000'])
  })

  it('OR2 unfreezing the wallet first does not open a release path: resolution needs the wallet frozen', async () => {
    const { s, id, other } = await incident('or-2')
    getDB().prepare(`UPDATE agent_wallets SET status = 'active' WHERE id = ?`).run(s.wallet)
    assert.deepEqual(resolveIncident(getDB(), id, full(other, 'ours_failed')), { ok: false, reason: 'wallet_not_frozen' })
    assert.deepEqual([used(s.top), used(s.low)], ['1000', '1000'])
  })

  it('OR3 ours_confirmed counts the amount spent and advances the frontier record, wallet stays frozen', async () => {
    const { s, id, other } = await incident('or-3')
    const op = getOp(getDB(), id)!
    assert.deepEqual(resolveIncident(getDB(), id, full(other, 'ours_confirmed')), { ok: true })
    assert.equal(getOp(getDB(), id)!.status, 'confirmed')
    assert.deepEqual(listReservations(getDB(), id).map(x => x.status), ['consumed', 'consumed'])
    assert.deepEqual([used(s.top), used(s.low)], ['1000', '1000'])
    assert.equal(getFrontier(getDB(), s.acct.address)!.frontier, op.block_hash)
    assert.equal(walletStatus(s.wallet), 'frozen')
    assert.ok(getDB().prepare(`SELECT 1 FROM chain_spend_holds WHERE delegation_id = ?`).get(s.low))
    assert.equal(JSON.parse(getOp(getDB(), id)!.resolution!).incident.resolved.moved_raw, '0')
  })

  it('OR4 ours_failed with the moved amount recorded as a loss releases once, wallet stays frozen, and is watched', async () => {
    const { s, id, other } = await incident('or-4')
    assert.deepEqual(resolveIncident(getDB(), id, full(other, 'ours_failed')), { ok: true })
    assert.equal(getOp(getDB(), id)!.status, 'failed_final')
    assert.deepEqual([used(s.top), used(s.low)], ['0', '0'])
    assert.deepEqual(resolveIncident(getDB(), id, full(other, 'ours_failed')), { ok: false, reason: 'not_admitted' })
    assert.deepEqual([used(s.top), used(s.low)], ['0', '0'], 'released once')
    assert.equal(walletStatus(s.wallet), 'frozen')
    const resolved = JSON.parse(getOp(getDB(), id)!.resolution!).incident.resolved
    assert.deepEqual([resolved.disposition.kind, resolved.moved_raw, resolved.sources[0].source], ['loss_recorded', '1', 'operator-node'])
    const ours = getOp(getDB(), id)!
    ledger.blocks.set(ours.block_hash!, { block: JSON.parse(ours.block_json!), account: s.acct.address, confirmed: true })
    assert.deepEqual(await watchFinalized(getDB(), ledger.node, clock + 1, 24 * 3600_000, 'fake-ledger'), [id])
    assert.deepEqual([used(s.top), used(s.low)], ['0', '0'], 'no debit re-applied')
  })

  it('OR5 a node fault is cleared by resolveNodeFault, the operation stays open', async () => {
    const s = setup()
    const r = await send(s, 'or-5')
    const id = r.body.operation_id
    ledger.dropProcess = true
    await runOp(getDB(), id, ctx('no-runner'))
    ledger.succ.set(GENESIS, ['AB'.repeat(32)])
    clock += 1
    assert.equal((await runOp(getDB(), id, ctx('no-runner'))).step, 'node_fault')
    assert.equal(resolveNodeFault(getDB(), id, { by: '', evidence: 'x', now: clock }), false)
    assert.equal(resolveNodeFault(getDB(), id, { by: 'operator', evidence: 'node replaced', now: clock }), true)
    assert.equal(resolveNodeFault(getDB(), id, { by: 'operator', evidence: 'again', now: clock }), false)
    assert.equal(getOp(getDB(), id)!.status, 'admitted')
    assert.deepEqual([used(s.top), used(s.low)], ['1000', '1000'])
  })

  it('OR6 our block confirms after the incident opened: spent as usual, the incident still needs its resolution record', async () => {
    const { s, id, other } = await incident('or-6')
    const ours = getOp(getDB(), id)!
    ledger.blocks.set(ours.block_hash!, { block: JSON.parse(ours.block_json!), account: s.acct.address, confirmed: true })
    clock += 1
    assert.equal((await runOp(getDB(), id, ctx('no-runner'))).status, 'confirmed')
    assert.deepEqual([used(s.top), used(s.low)], ['1000', '1000'])
    const res = JSON.parse(getOp(getDB(), id)!.resolution!)
    assert.ok(res.incident && !res.incident.resolved, 'the incident survives the confirmation')
    assert.deepEqual(resolveIncident(getDB(), id, full(other, 'ours_failed')), { ok: false, reason: 'already_confirmed' })
    assert.deepEqual(resolveIncident(getDB(), id, full(other, 'ours_confirmed')), { ok: true })
    assert.ok(JSON.parse(getOp(getDB(), id)!.resolution!).incident.resolved)
    assert.deepEqual([used(s.top), used(s.low)], ['1000', '1000'], 'nothing moved')
  })

  it('OR7 a resolution that does not match the recorded incident is refused', async () => {
    const { s, id, other } = await incident('or-7')
    const cases: Array<[Partial<IncidentResolution>, string, 'ours_confirmed' | 'ours_failed']> = [
      [{ sibling: 'AB'.repeat(32) }, 'sibling_mismatch', 'ours_failed'],
      [{ balance_effect: 'unchanged' }, 'balance_effect_mismatch', 'ours_failed'],
      [{ sibling_status: 'unconfirmed' }, 'sibling_not_confirmed', 'ours_failed'],
      [{ sibling_status: 'confirmed' }, 'both_confirmed', 'ours_confirmed'],
      [{ disposition: { kind: 'no_funds_moved' } }, 'funds_moved', 'ours_failed'],
      [{ disposition: { kind: 'loss_recorded', amount_raw: '2' } }, 'loss_amount_mismatch', 'ours_failed'],
      [{ disposition: { kind: 'debited', adjustments: [{ delegation_id: s.low, amount_raw: '5' }] } }, 'adjustments_do_not_match_moved_amount', 'ours_failed'],
      [{ disposition: { kind: 'debited', adjustments: [] } }, 'adjustments_missing', 'ours_failed'],
    ]
    for (const [over, reason, decision] of cases) {
      assert.deepEqual(resolveIncident(getDB(), id, full(other, decision, over)), { ok: false, reason }, reason)
    }
    assert.equal(getOp(getDB(), id)!.status, 'admitted')
    assert.deepEqual([used(s.top), used(s.low)], ['1000', '1000'])
  })

  it('OR8 a debited disposition charges the moved amount to the named delegation chain in the same transaction', async () => {
    const { s, id, other } = await incident('or-8')
    const out = resolveIncident(getDB(), id, full(other, 'ours_failed', { disposition: { kind: 'debited', adjustments: [{ delegation_id: s.low, amount_raw: '1' }] } }))
    assert.deepEqual(out, { ok: true })
    assert.deepEqual([used(s.top), used(s.low)], ['1', '1'], 'our 1000 released, the other block 1 raw charged')
  })

  it('OR9 a debit that cannot be applied rolls the whole resolution back, the release included', async () => {
    const { s, id, other } = await incident('or-9')
    const foreign = setup() // another tenant: its delegation cannot be charged from this payment
    const before = [getOp(getDB(), id)!.status, used(s.top), used(s.low)]
    const out = resolveIncident(getDB(), id, full(other, 'ours_failed', { disposition: { kind: 'debited', adjustments: [{ delegation_id: foreign.low, amount_raw: '1' }] } }))
    assert.deepEqual(out, { ok: false, reason: `adjustment_chain_unreadable:${foreign.low}` })
    assert.deepEqual([getOp(getDB(), id)!.status, used(s.top), used(s.low)], before)
    assert.deepEqual(listReservations(getDB(), id).map(x => x.status), ['held', 'held'])
    assert.equal(walletStatus(s.wallet), 'frozen')
  })

  it('OR11 a budget our payment held in full still takes the smaller real spend: release first, then charge', async () => {
    const s = setup('1000')
    const r = await send(s, 'or-11')
    const id = r.body.operation_id
    assert.deepEqual([used(s.top), used(s.low)], ['1000', '1000'], 'the whole budget is held')
    ledger.dropProcess = true
    await runOp(getDB(), id, ctx('no-runner'))
    const other = ledger.conflict(s.acct, GENESIS, '100000')
    clock += 1
    assert.equal((await runOp(getDB(), id, ctx('no-runner'))).step, 'incident')
    const out = resolveIncident(getDB(), id, full(other, 'ours_failed', { disposition: { kind: 'debited', adjustments: [{ delegation_id: s.low, amount_raw: '1' }] } }))
    assert.deepEqual(out, { ok: true })
    assert.deepEqual([used(s.top), used(s.low)], ['1', '1'], 'exactly the other block spend, the rest available again')
  })

  it('OR10 ours_confirmed with the frontier record gone is refused, nothing changes', async () => {
    const { s, id, other } = await incident('or-10')
    getDB().prepare(`DELETE FROM wallet_frontiers WHERE nano_account = ?`).run(s.acct.address)
    assert.deepEqual(resolveIncident(getDB(), id, full(other, 'ours_confirmed')), { ok: false, reason: 'frontier_inconsistent' })
    assert.equal(getOp(getDB(), id)!.status, 'admitted')
    assert.deepEqual(listReservations(getDB(), id).map(x => x.status), ['held', 'held'])
    assert.equal((getDB().prepare(`SELECT COUNT(*) AS c FROM wallet_transactions WHERE id = ?`).get(`wtx-${id}`) as any).c, 0)
  })
})

describe('the frontier record (gate 1)', () => {
  it('F1 no record: the send stays reserved, nothing signed or published, reservation held', async () => {
    const s = setup()
    getDB().prepare(`DELETE FROM wallet_frontiers WHERE nano_account = ?`).run(s.acct.address)
    const r = await send(s, 'fr-1')
    const out = await runOp(getDB(), r.body.operation_id, ctx('no-runner'))
    assert.deepEqual([out.status, out.step, out.detail], ['reserved', 'prepare_failed', 'frontier_not_initialized'])
    assert.equal(ledger.processCalls.length, 0)
    assert.equal(getOp(getDB(), r.body.operation_id)!.block_hash, null)
    assert.deepEqual([used(s.top), used(s.low)], ['1000', '1000'])
  })

  it('F2 a node reporting another confirmed state stops the send and does not overwrite the record', async () => {
    const s = setup()
    ledger.heads.set(s.acct.address, { frontier: 'CD'.repeat(32), balance: '100000' })
    const r = await send(s, 'fr-2')
    const out = await runOp(getDB(), r.body.operation_id, ctx('no-runner'))
    assert.deepEqual([out.status, out.detail], ['reserved', 'frontier_mismatch'])
    assert.equal(getFrontier(getDB(), s.acct.address)!.frontier, GENESIS)
    ledger.heads.set(s.acct.address, { frontier: GENESIS, balance: '99999' })
    assert.equal((await runOp(getDB(), r.body.operation_id, ctx('no-runner'))).detail, 'frontier_balance_mismatch')
    assert.equal(ledger.processCalls.length, 0)
  })

  it('F3 a confirmed send advances the record, and the next send builds on it', async () => {
    const s = setup()
    const r = await send(s, 'fr-3a')
    await runOp(getDB(), r.body.operation_id, ctx('no-runner'))
    const first = getOp(getDB(), r.body.operation_id)!
    ledger.confirm(first.block_hash!)
    clock += 1
    assert.equal((await runOp(getDB(), first.id, ctx('no-runner'))).status, 'confirmed')
    assert.deepEqual([getFrontier(getDB(), s.acct.address)!.frontier, getFrontier(getDB(), s.acct.address)!.balance_raw], [first.block_hash, '99000'])
    const r2 = await send(s, 'fr-3b')
    const out = await runOp(getDB(), r2.body.operation_id, ctx('no-runner'))
    assert.equal(out.step, 'published_accepted')
    assert.equal(getOp(getDB(), r2.body.operation_id)!.block_previous, first.block_hash)
  })

  it('F5 a confirmation whose frontier record cannot advance does not settle: integrity fault, nothing moves', async () => {
    for (const tamper of ['delete', 'change'] as const) {
      const s = setup()
      const r = await send(s, `fr-5-${tamper}`)
      const id = r.body.operation_id
      await runOp(getDB(), id, ctx('no-runner'))
      if (tamper === 'delete') getDB().prepare(`DELETE FROM wallet_frontiers WHERE nano_account = ?`).run(s.acct.address)
      else getDB().prepare(`UPDATE wallet_frontiers SET frontier = ? WHERE nano_account = ?`).run('EF'.repeat(32), s.acct.address)
      ledger.confirm(getOp(getDB(), id)!.block_hash!)
      clock += 1
      const out = await runOp(getDB(), id, ctx('no-runner'))
      assert.deepEqual([out.status, out.step], ['admitted', 'integrity_fault'], tamper)
      assert.deepEqual(listReservations(getDB(), id).map(x => x.status), ['held', 'held'], tamper)
      assert.equal((getDB().prepare(`SELECT COUNT(*) AS c FROM wallet_transactions WHERE id = ?`).get(`wtx-${id}`) as any).c, 0, tamper)
      clock += 1
      assert.equal((await runOp(getDB(), id, ctx('no-runner'))).step, 'integrity_fault', `${tamper}: persists on the next pass`)
    }
  })

  it('F4 initialization is refused while an operation is in flight, when a record exists, and when malformed', async () => {
    const s = setup()
    const init = (over: Record<string, unknown> = {}) => initializeWalletFrontier(getDB(),
      { walletId: s.wallet, frontier: GENESIS, balanceRaw: '100000', by: 'op', evidence: 'node', now: clock, ...over } as any)
    assert.deepEqual(init(), { ok: false, reason: 'frontier_already_initialized' })
    assert.deepEqual(init({ frontier: 'xyz', replace: true }), { ok: false, reason: 'frontier_malformed' })
    assert.deepEqual(init({ balanceRaw: '-1', replace: true }), { ok: false, reason: 'balance_malformed' })
    assert.deepEqual(init({ evidence: '', replace: true }), { ok: false, reason: 'initialization_incomplete' })
    await send(s, 'fr-4')
    assert.deepEqual(init({ replace: true }), { ok: false, reason: 'operation_in_flight' })
  })
})

describe('pilot caps (gate 1)', () => {
  afterEach(() => setGenerousPilotCaps())

  it('P1 unconfigured caps refuse every send, recorded, nothing reserved', async () => {
    const s = setup()
    delete process.env.NANO_PILOT_MAX_WALLET_RAW
    const r = await send(s, 'cap-1')
    assert.equal(r.status, 403)
    assert.match(String(r.body.denial_reason), /pilot_caps_unconfigured/)
    assert.deepEqual([used(s.top), used(s.low)], ['0', '0'])
  })

  it('P2 a payment above the per-payment cap is refused', async () => {
    const s = setup()
    process.env.NANO_PILOT_MAX_PAYMENT_RAW = '999'
    const r = await send(s, 'cap-2')
    assert.match(String(r.body.denial_reason), /pilot_payment_cap/)
  })

  it('P3 the wallet cap counts confirmed sends, not cancelled ones', async () => {
    const s = setup()
    process.env.NANO_PILOT_MAX_WALLET_RAW = '1500'
    const a = await send(s, 'cap-3a')
    await runOp(getDB(), a.body.operation_id, ctx('no-runner'))
    ledger.confirm(getOp(getDB(), a.body.operation_id)!.block_hash!)
    clock += 1; await runOp(getDB(), a.body.operation_id, ctx('no-runner'))
    const b = await send(s, 'cap-3b')
    assert.match(String(b.body.denial_reason), /pilot_wallet_cap/)
    const s2 = setup()
    process.env.NANO_PILOT_MAX_WALLET_RAW = '1500'
    const c = await send(s2, 'cap-3c')
    getDB().prepare(`UPDATE delegations SET status = 'revoked' WHERE id = ?`).run(s2.low)
    await runOp(getDB(), c.body.operation_id, ctx('no-runner'))
    assert.equal(getOp(getDB(), c.body.operation_id)!.status, 'cancelled')
    getDB().prepare(`UPDATE delegations SET status = 'active' WHERE id = ?`).run(s2.low)
    assert.equal((await send(s2, 'cap-3d')).status, 202, 'a cancelled send does not count')
  })

  it('P5 the caps follow the Nano account across wallet rows', async () => {
    const s = setup()
    process.env.NANO_PILOT_MAX_WALLET_RAW = '1500'
    const a = await send(s, 'cap-5a')
    await runOp(getDB(), a.body.operation_id, ctx('no-runner'))
    ledger.confirm(getOp(getDB(), a.body.operation_id)!.block_hash!)
    clock += 1; await runOp(getDB(), a.body.operation_id, ctx('no-runner'))
    // The account is now under a different wallet row id: its history must still count.
    getDB().prepare(`UPDATE agent_wallets SET id = ? WHERE id = ?`).run(`${s.wallet}-new`, s.wallet)
    getDB().prepare(`UPDATE wallet_frontiers SET wallet_id = ? WHERE nano_account = ?`).run(`${s.wallet}-new`, s.acct.address)
    const b = await send(s, 'cap-5b')
    assert.match(String(b.body.denial_reason), /pilot_wallet_cap/)
  })

  it('P4 the payment count cap', async () => {
    const s = setup()
    process.env.NANO_PILOT_MAX_PAYMENTS = '1'
    const a = await send(s, 'cap-4a')
    await runOp(getDB(), a.body.operation_id, ctx('no-runner'))
    ledger.confirm(getOp(getDB(), a.body.operation_id)!.block_hash!)
    clock += 1; await runOp(getDB(), a.body.operation_id, ctx('no-runner'))
    assert.match(String((await send(s, 'cap-4b')).body.denial_reason), /pilot_payment_count_cap/)
  })
})

describe('activation gate 2: no new reservation unless the lifecycle is ready', () => {
  const opsFor = (tenant: string) => (getDB().prepare(`SELECT COUNT(*) AS c FROM wallet_ops WHERE tenant_id = ?`).get(tenant) as any).c
  const notReady = (readiness: string | null) => setOpRunner({ owner: 'no-runner', leaseMs: LEASE, now: () => clock, schedule: () => {}, readiness: () => readiness })
  afterEach(() => { delete process.env.NANO_RAIL_DISABLED })

  it('G1 no lifecycle installed: 503, nothing reserved, no budget moved', async () => {
    const s = setup()
    setOpRunner(null)
    const r = await send(s, 'ready-1')
    assert.equal(r.status, 503)
    assert.match(String(r.body.denial_reason), /lifecycle_not_installed/)
    assert.equal(opsFor(s.tenant), 0)
    assert.deepEqual([used(s.top), used(s.low)], ['0', '0'])
  })

  it('G2 NANO_RAIL_DISABLED=1 stops new reservations even with a ready runner', async () => {
    const s = setup()
    process.env.NANO_RAIL_DISABLED = '1'
    const r = await send(s, 'ready-2')
    assert.equal(r.status, 503)
    assert.match(String(r.body.denial_reason), /nano_rail_disabled/)
    assert.equal(opsFor(s.tenant), 0)
    assert.deepEqual([used(s.top), used(s.low)], ['0', '0'])
  })

  it('G3 a starting, degraded or blocked lifecycle: 503 and nothing reserved', async () => {
    for (const state of ['lifecycle_starting', 'lifecycle_degraded', 'lifecycle_blocked']) {
      const s = setup()
      notReady(state)
      const r = await send(s, `ready-3-${state}`)
      assert.equal(r.status, 503, state)
      assert.match(String(r.body.denial_reason), new RegExp(state))
      assert.equal(opsFor(s.tenant), 0, state)
    }
  })

  it('G4 the operator pause still answers first, as a recorded 403', async () => {
    const s = setup()
    setOpRunner(null)
    process.env.NANO_WALLETS_PAUSED = '1'
    const r = await send(s, 'ready-4')
    assert.equal(r.status, 403)
    assert.match(String(r.body.denial_reason), /paused/)
    assert.equal(opsFor(s.tenant), 0)
  })

  it('G5 a payment reserved while ready is still reported by its key when the lifecycle is not ready', async () => {
    const s = setup()
    const first = await send(s, 'ready-5')
    assert.equal(first.status, 202)
    setOpRunner(null)
    const again = await send(s, 'ready-5')
    assert.equal(again.status, 202)
    assert.equal(again.body.replay, true)
    assert.equal(again.body.operation_id, first.body.operation_id)
    assert.equal(opsFor(s.tenant), 1)
  })
})
