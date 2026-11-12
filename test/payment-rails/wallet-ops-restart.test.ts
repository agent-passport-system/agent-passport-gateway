// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Day 268, lifecycle phase B: what survives a restart, and what two connections to the same
// database file see. A file database, not :memory:, so a second connection and a reopen read
// what the first committed. Nothing is published.
import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import Database from 'better-sqlite3'
// @ts-ignore nanocurrency-web has no type declarations
import nanoWebImport from 'nanocurrency-web'
import { initDB, getDB } from '../../src/db/schema.js'
import { initGatewayIdentity } from '../../src/gateway/identity.js'
import {
  reserveSend, takeOver, listRecoverable, storePrepared, cancelOp, getOp, WalletOpError,
  type Claim, type ConfirmedAccount, type WalletOp,
} from '../../src/payment-rails/wallet-ops.js'
import { setGenerousPilotCaps, initFrontier } from './pilot-fixtures.js'

const nano = (nanoWebImport as any).default || nanoWebImport
const TENANT = 'tnt_walletops_restart'
const FRONTIER = 'F47B23107E5F34B2CE06F562B5C435DF72A533251CB414C51B2B62A8F63A00E4'
const LEASE = 30_000
const DEST = nano.wallet.fromLegacySeed('ee'.repeat(32)).accounts[0]
const at = (owner: string, now: number): Claim => ({ owner, now, leaseMs: LEASE })
let n = 0
let dir = ''
let path = ''

function account() {
  return nano.wallet.fromLegacySeed((0x1000 + ++n).toString(16).padStart(64, '0')).accounts[0]
}
function chain(db: Database.Database) {
  const t = ++n
  for (const a of [`root-${t}`, `p-${t}`, `c-${t}`]) {
    db.prepare(`INSERT INTO agents (id, tenant_id, agent_id, public_key, status, is_root) VALUES (?, ?, ?, 'pk', 'active', 0)`).run(`row-${a}`, TENANT, a)
  }
  const ins = db.prepare(`INSERT INTO delegations (id, tenant_id, parent_agent_id, child_agent_id, scope, status, spend_limit, spend_used, parent_delegation_id, spend_unit, spend_limit_minor, spend_used_minor) VALUES (?, ?, ?, ?, 'commerce:send', 'active', 0, 0, ?, 'nano:XNO:raw', ?, '0')`)
  ins.run(`top-${t}`, TENANT, `root-${t}`, `p-${t}`, null, '5000')
  ins.run(`low-${t}`, TENANT, `p-${t}`, `c-${t}`, `top-${t}`, '3000')
  return { c: `c-${t}`, top: `top-${t}`, low: `low-${t}` }
}
const used = (db: Database.Database, id: string) => (db.prepare(`SELECT spend_used_minor FROM delegations WHERE id = ?`).get(id) as any).spend_used_minor
function req(k: ReturnType<typeof chain>, acct: any) {
  return { tenantId: TENANT, idempotencyKey: `key-${++n}`, fromAgentId: k.c, walletId: `w-${k.c}`,
    nanoAccount: acct.address, delegationId: k.low, toAddress: DEST.address, amountRaw: '1000' }
}
function op(r: ReturnType<typeof reserveSend>): WalletOp {
  assert.ok('op' in r)
  return r.op
}
function prepare(db: Database.Database, o: WalletOp, acct: any, claim: Claim) {
  const info: ConfirmedAccount = { frontier: FRONTIER, confirmed_frontier: FRONTIER, confirmed_balance: '50000', confirmed_representative: acct.address }
  const block = nano.block.send({ walletBalanceRaw: '50000', fromAddress: acct.address, toAddress: DEST.address,
    representativeAddress: acct.address, frontier: FRONTIER, amountRaw: o.amount_raw, work: '0123456789abcdef' }, acct.privateKey)
  return storePrepared(db, o, claim, block, info)
}
function second(): Database.Database {
  const db = new Database(path)
  db.pragma('busy_timeout = 5000')
  return db
}

before(() => {
  setGenerousPilotCaps()
  dir = mkdtempSync(join(tmpdir(), 'wallet-ops-'))
  path = join(dir, 'gateway.db')
  initDB(path)
  initGatewayIdentity()
  getDB().prepare(`INSERT OR IGNORE INTO tenants (id, name, email) VALUES (?, ?, ?)`).run(TENANT, 'Restart', 'restart@test.local')
})
after(() => {
  try { getDB().close() } catch {}
  rmSync(dir, { recursive: true, force: true })
})

describe('restart and a second connection', () => {
  it('R1 a reserved and a prepared row, with their debits, survive closing and reopening the database', () => {
    const k1 = chain(getDB()), k2 = chain(getDB()), a1 = account(), a2 = account()
    const r = op(reserveSend(getDB(), req(k1, a1), at('A', 0)))
    const p = prepare(getDB(), op(reserveSend(getDB(), req(k2, a2), at('A', 0))), a2, at('A', 1))
    getDB().close()

    initDB(path) // a new process opening the same file
    const db = getDB()
    assert.equal(getOp(db, r.id)!.status, 'reserved')
    const again = getOp(db, p.id)!
    assert.equal(again.status, 'prepared')
    assert.equal(again.block_hash, p.block_hash)
    assert.equal(again.block_json, p.block_json)
    assert.deepEqual([used(db, k1.top), used(db, k1.low), used(db, k2.top), used(db, k2.low)], ['1000', '1000', '1000', '1000'])

    // Recovery after the leases expire: each row is listed once, taken over, and cancelled with one release.
    const queue = listRecoverable(db, LEASE + 1).map(o => o.id)
    assert.ok(queue.includes(r.id) && queue.includes(p.id))
    for (const id of [r.id, p.id]) {
      const claimed = takeOver(db, id, at('R', LEASE + 1))!
      cancelOp(db, claimed, at('R', LEASE + 2), 'recovered after restart')
    }
    assert.deepEqual([used(db, k1.top), used(db, k1.low), used(db, k2.top), used(db, k2.low)], ['0', '0', '0', '0'])
  })

  it('R2 two connections taking over the same expired row: exactly one gets it', () => {
    const k = chain(getDB()), a = account()
    const o = op(reserveSend(getDB(), req(k, a), at('A', 0)))
    const other = second()
    try {
      const first = takeOver(getDB(), o.id, at('B', LEASE + 1))
      const late = takeOver(other, o.id, at('C', LEASE + 1))
      assert.equal(first?.claim_epoch, 2)
      assert.equal(late, null)
      assert.throws(() => cancelOp(other, { ...o, claim_epoch: 2 }, at('C', LEASE + 2), 'not mine'),
        (e: any) => e instanceof WalletOpError && e.code === 'claim_lost')
      cancelOp(getDB(), first!, at('B', LEASE + 2), 'mine')
      assert.deepEqual([used(other, k.top), used(other, k.low)], ['0', '0'])
    } finally {
      other.close()
    }
  })

  it('R3 a second connection cannot reserve on an account the first holds, and its debit does not stay', () => {
    const k1 = chain(getDB()), k2 = chain(getDB()), a = account()
    op(reserveSend(getDB(), req(k1, a), at('A', 0)))
    const other = second()
    try {
      assert.throws(() => reserveSend(other, req(k2, a), at('B', 0)),
        (e: any) => e instanceof WalletOpError && e.code === 'wallet_busy')
      assert.deepEqual([used(other, k2.top), used(other, k2.low)], ['0', '0'])
    } finally {
      other.close()
    }
  })
})
