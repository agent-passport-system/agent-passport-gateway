// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Day 268, lifecycle phase B: wallet_ops rows, the atomic reservation, one operation in flight
// per Nano account, claim fencing, and the reserved and prepared states. Blocks are signed
// locally with throwaway keys. No node is called and nothing is published.
// ══════════════════════════════════════════════════════════════════
import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
// @ts-ignore nanocurrency-web has no type declarations
import nanoWebImport from 'nanocurrency-web'
import { initDB, getDB } from '../../src/db/schema.js'
import { initGatewayIdentity } from '../../src/gateway/identity.js'
import { stateBlockHash } from '../../src/payment-rails/nano-block.js'
import {
  reserveSend, reserveReceive, takeOver, renewLease, listRecoverable, storePrepared, cancelOp,
  parseConfirmedAccountInfo, walletAccountProblems, getOp, WalletOpError,
  type Claim, type ConfirmedAccount, type SendRequest, type WalletOp,
} from '../../src/payment-rails/wallet-ops.js'
import { setGenerousPilotCaps, initFrontier } from './pilot-fixtures.js'

const nano = (nanoWebImport as any).default || nanoWebImport
const TENANT = 'tnt_walletops'
const FRONTIER = 'F47B23107E5F34B2CE06F562B5C435DF72A533251CB414C51B2B62A8F63A00E4'
const SOURCE = '19D3D919475DEED4696B5D13018151D1AF88B2BD3BCFF048B45031C1F36D1858'
const ZERO64 = '0'.repeat(64)
const WORK = '0123456789abcdef'
const LEASE = 30_000
let n = 0

/** A fresh throwaway Nano account per call, so tests never share an account slot. */
function account() {
  return nano.wallet.fromLegacySeed((++n).toString(16).padStart(64, '0')).accounts[0]
}
const DEST = nano.wallet.fromLegacySeed('ff'.repeat(32)).accounts[0]
const at = (owner: string, now: number): Claim => ({ owner, now, leaseMs: LEASE })

function agent(id: string) {
  getDB().prepare(`INSERT INTO agents (id, tenant_id, agent_id, public_key, status, is_root) VALUES (?, ?, ?, 'pk', 'active', 0)`).run(`row-${id}`, TENANT, id)
}
function row(parent: string, child: string, limit: string | null, parentDelegationId: string | null = null): string {
  const id = `del-${++n}`
  getDB().prepare(`INSERT INTO delegations (id, tenant_id, parent_agent_id, child_agent_id, scope, status, spend_limit, spend_used, parent_delegation_id, spend_unit, spend_limit_minor, spend_used_minor) VALUES (?, ?, ?, ?, 'commerce:send', 'active', 0, 0, ?, 'nano:XNO:raw', ?, '0')`)
    .run(id, TENANT, parent, child, parentDelegationId, limit)
  return id
}
const used = (id: string) => (getDB().prepare(`SELECT spend_used_minor FROM delegations WHERE id = ?`).get(id) as any).spend_used_minor
function chain(topLimit: string | null, lowLimit: string) {
  const t = ++n, root = `root-${t}`, p = `p-${t}`, c = `c-${t}`
  agent(root); agent(p); agent(c)
  const top = row(root, p, topLimit)
  const low = row(p, c, lowLimit, top)
  return { c, top, low }
}
function sendReq(k: ReturnType<typeof chain>, acct: any, over: Partial<SendRequest> = {}): SendRequest {
  return {
    tenantId: TENANT, idempotencyKey: `key-${++n}`, fromAgentId: k.c, walletId: `w-${k.c}`,
    nanoAccount: acct.address, delegationId: k.low, toAddress: DEST.address, amountRaw: '1000', ...over,
  }
}
function confirmed(acct: any, balance: string, frontier = FRONTIER): ConfirmedAccount {
  return { frontier, confirmed_frontier: frontier, confirmed_balance: balance, confirmed_representative: acct.address }
}
function signSend(op: WalletOp, acct: any, info: ConfirmedAccount, over: Record<string, string> = {}) {
  return nano.block.send({
    walletBalanceRaw: info.confirmed_balance, fromAddress: acct.address, toAddress: op.to_address,
    representativeAddress: info.confirmed_representative, frontier: info.confirmed_frontier,
    amountRaw: op.amount_raw, work: WORK, ...over,
  }, acct.privateKey)
}
function reserved(r: ReturnType<typeof reserveSend>): WalletOp {
  assert.ok('op' in r, `expected a reservation, got ${JSON.stringify(r)}`)
  return r.op
}
function expectCode(fn: () => unknown, code: string) {
  assert.throws(fn, (e: any) => e instanceof WalletOpError && e.code === code)
}

before(() => {
  setGenerousPilotCaps()
  initDB(':memory:')
  initGatewayIdentity()
  getDB().prepare(`INSERT OR IGNORE INTO tenants (id, name, email) VALUES (?, ?, ?)`).run(TENANT, 'WalletOps', 'wo@test.local')
})

describe('reservation', () => {
  it('W1 commits the row and the exact debit on every unit row of the chain', () => {
    const k = chain('5000', '3000'), acct = account()
    const op = reserved(reserveSend(getDB(), sendReq(k, acct), at('A', 0)))
    assert.equal(op.status, 'reserved')
    assert.equal(op.claim_epoch, 1)
    assert.equal(op.lease_until, LEASE)
    assert.deepEqual([used(k.top), used(k.low)], ['1000', '1000'])
  })

  it('W2 the same key with the same request returns the same row and debits nothing more', () => {
    const k = chain('5000', '3000'), acct = account()
    const req = sendReq(k, acct)
    const first = reserved(reserveSend(getDB(), req, at('A', 0)))
    const again = reserveSend(getDB(), req, at('B', 5))
    assert.ok('op' in again && again.replay)
    assert.equal(again.op.id, first.id)
    assert.deepEqual([used(k.top), used(k.low)], ['1000', '1000'])
  })

  it('W3 the same key with a different amount or destination is refused and debits nothing', () => {
    const k = chain('5000', '3000'), acct = account()
    const req = sendReq(k, acct)
    reserved(reserveSend(getDB(), req, at('A', 0)))
    expectCode(() => reserveSend(getDB(), { ...req, amountRaw: '1001' }, at('A', 1)), 'idempotency_mismatch')
    expectCode(() => reserveSend(getDB(), { ...req, toAddress: acct.address }, at('A', 1)), 'idempotency_mismatch')
    assert.deepEqual([used(k.top), used(k.low)], ['1000', '1000'])
  })

  it('W4 a refusal inserts nothing and debits nothing', () => {
    const k = chain('5000', '3000'), acct = account()
    const r = reserveSend(getDB(), sendReq(k, acct, { amountRaw: '3001' }), at('A', 0))
    assert.deepEqual(r, { refused: 'budget_exceeded' })
    assert.deepEqual([used(k.top), used(k.low)], ['0', '0'])
    const held = chain('5000', '3000')
    getDB().prepare(`INSERT INTO chain_spend_holds (delegation_id, tenant_id, reason, created_at) VALUES (?, ?, 'test hold', datetime('now'))`).run(held.top, TENANT)
    assert.deepEqual(reserveSend(getDB(), sendReq(held, account()), at('A', 0)), { refused: 'chain_on_upgrade_hold' })
    const count = getDB().prepare(`SELECT COUNT(*) AS c FROM wallet_ops WHERE nano_account = ?`).get(acct.address) as any
    assert.equal(count.c, 0)
  })

  it('W5 a failure inside the transaction after the debit rolls the debit back', () => {
    const k = chain('5000', '3000'), acct = account()
    getDB().exec(`CREATE TEMP TRIGGER fail_777 BEFORE INSERT ON wallet_ops WHEN NEW.amount_raw = '777'
      BEGIN SELECT RAISE(ABORT, 'injected insert failure'); END`)
    try {
      assert.throws(() => reserveSend(getDB(), sendReq(k, acct, { amountRaw: '777' }), at('A', 0)), /injected insert failure/)
      assert.deepEqual([used(k.top), used(k.low)], ['0', '0'])
    } finally {
      getDB().exec(`DROP TRIGGER fail_777`)
    }
  })

  it('W6 refuses malformed requests before touching the database', () => {
    const k = chain('5000', '3000'), acct = account()
    for (const over of [{ amountRaw: '0' }, { amountRaw: '1.5' }, { amountRaw: '-1' }, { toAddress: 'nano_bad' }, { idempotencyKey: '' }]) {
      expectCode(() => reserveSend(getDB(), sendReq(k, acct, over), at('A', 0)), 'bad_request')
    }
    assert.deepEqual([used(k.top), used(k.low)], ['0', '0'])
  })
})

describe('one operation in flight per Nano account', () => {
  it('S1 a second send on the same account is wallet_busy, even from another wallet row and chain', () => {
    const acct = account()
    const k1 = chain('5000', '3000'), k2 = chain('5000', '3000')
    reserved(reserveSend(getDB(), sendReq(k1, acct), at('A', 0)))
    expectCode(() => reserveSend(getDB(), sendReq(k2, acct, { walletId: 'w-other' }), at('B', 0)), 'wallet_busy')
    assert.deepEqual([used(k2.top), used(k2.low)], ['0', '0'])
  })

  it('S2 a receive and a send exclude each other on one account, in both orders', () => {
    const k = chain('5000', '3000')
    const a1 = account()
    reserved(reserveSend(getDB(), sendReq(k, a1), at('A', 0)))
    expectCode(() => reserveReceive(getDB(), { tenantId: TENANT, idempotencyKey: `rk-${++n}`, walletId: 'w', nanoAccount: a1.address, kind: 'receive', sourceHash: SOURCE, amountRaw: '5' }, at('B', 0)), 'wallet_busy')
    const a2 = account()
    reserveReceive(getDB(), { tenantId: TENANT, idempotencyKey: `rk-${++n}`, walletId: 'w', nanoAccount: a2.address, kind: 'receive', sourceHash: SOURCE, amountRaw: '5' }, at('B', 0))
    expectCode(() => reserveSend(getDB(), sendReq(k, a2), at('A', 0)), 'wallet_busy')
    assert.deepEqual([used(k.top), used(k.low)], ['1000', '1000'])
  })

  it('S3 the partial unique index enforces it without the application check, and frees the account after cancel', () => {
    const k = chain('5000', '3000'), acct = account()
    const op = reserved(reserveSend(getDB(), sendReq(k, acct), at('A', 0)))
    assert.throws(() => getDB().prepare(`INSERT INTO wallet_ops (id, kind, tenant_id, idempotency_key, request_fingerprint, nano_account, amount_raw, source_hash, status)
      VALUES ('direct', 'receive', ?, 'direct-key', 'fp', ?, '1', ?, 'reserved')`).run(TENANT, acct.address, SOURCE), /UNIQUE constraint failed: wallet_ops\.nano_account/)
    cancelOp(getDB(), op, at('A', 1), 'test')
    reserved(reserveSend(getDB(), sendReq(k, acct), at('A', 2)))
  })
})

describe('storing the block', () => {
  it('P1 stores the signed block and its hash, and moves to prepared', () => {
    const k = chain('5000', '3000'), acct = account()
    const op = reserved(reserveSend(getDB(), sendReq(k, acct), at('A', 0)))
    const info = confirmed(acct, '50000')
    const block = signSend(op, acct, info)
    const p = storePrepared(getDB(), op, at('A', 1), block, info)
    assert.equal(p.status, 'prepared')
    assert.equal(p.block_hash, stateBlockHash(block))
    assert.equal(p.block_previous, FRONTIER)
    assert.equal(p.block_balance_raw, '49000')
    assert.equal(JSON.parse(p.block_json!).signature, block.signature.toUpperCase())
  })

  it('P2 refuses every block that is not exactly the approved one, and the row stays reserved', () => {
    const k = chain('5000', '3000'), acct = account(), other = account()
    const op = reserved(reserveSend(getDB(), sendReq(k, acct), at('A', 0)))
    const info = confirmed(acct, '50000')
    const tampered = { ...signSend(op, acct, info) }
    tampered.signature = tampered.signature.replace(/^./, (c: string) => (c === 'A' ? 'B' : 'A'))
    const cases: Array<[string, any, ConfirmedAccount]> = [
      ['frontier_unconfirmed', signSend(op, acct, info), { ...info, frontier: SOURCE }],
      ['block_previous_not_confirmed_frontier', signSend(op, acct, info, { frontier: SOURCE }), info],
      ['block_representative_changed', signSend(op, acct, info, { representativeAddress: other.address }), info],
      ['amount_exceeds_confirmed_balance', signSend(op, acct, confirmed(acct, '999')), confirmed(acct, '999')],
      ['block_link_mismatch', signSend(op, acct, info, { toAddress: other.address }), info],
      ['block_balance_mismatch', signSend(op, acct, info, { amountRaw: '999' }), info],
      ['block_account_mismatch', nano.block.send({ walletBalanceRaw: '50000', fromAddress: other.address, toAddress: DEST.address, representativeAddress: acct.address, frontier: FRONTIER, amountRaw: '1000', work: WORK }, other.privateKey), info],
      ['block_signature_invalid', tampered, info],
      ['block_work_malformed', signSend(op, acct, info, { work: '' }), info],
    ]
    for (const [reason, block, inf] of cases) {
      assert.throws(() => storePrepared(getDB(), op, at('A', 1), block, inf),
        (e: any) => e instanceof WalletOpError && e.code === 'block_mismatch' && e.message === reason, reason)
    }
    const now = getOp(getDB(), op.id)!
    assert.equal(now.status, 'reserved')
    assert.equal(now.block_json, null)
  })

  it('P3 requires the confirmed frontier, balance and representative from account_info', () => {
    const acct = account()
    const full = { frontier: FRONTIER, confirmed_frontier: FRONTIER, confirmed_balance: '1', confirmed_representative: acct.address }
    assert.deepEqual(parseConfirmedAccountInfo(full), full)
    for (const missing of ['frontier', 'confirmed_frontier', 'confirmed_balance', 'confirmed_representative']) {
      const partial: any = { ...full }
      delete partial[missing]
      assert.ok('error' in parseConfirmedAccountInfo(partial), missing)
    }
    assert.ok('error' in parseConfirmedAccountInfo({ ...full, confirmed_balance: '1.0' }))
    assert.ok('error' in parseConfirmedAccountInfo({ ...full, balance: '1' , confirmed_balance: undefined }))
  })

  it('P4 a prepared row never gets another block, from its holder or from a recovery worker', () => {
    const k = chain('5000', '3000'), acct = account()
    const op = reserved(reserveSend(getDB(), sendReq(k, acct), at('A', 0)))
    const info = confirmed(acct, '50000')
    const p = storePrepared(getDB(), op, at('A', 1), signSend(op, acct, info), info)
    const second = signSend(op, acct, confirmed(acct, '60000'))
    expectCode(() => storePrepared(getDB(), p, at('A', 2), second, confirmed(acct, '60000')), 'claim_lost')
    const b = takeOver(getDB(), op.id, at('B', LEASE + 1))!
    expectCode(() => storePrepared(getDB(), b, at('B', LEASE + 2), second, confirmed(acct, '60000')), 'claim_lost')
    assert.equal(getOp(getDB(), op.id)!.block_hash, p.block_hash)
  })

  it('P5 a receive block and an open block are checked against their own rules', () => {
    const acct = account()
    const r = reserveReceive(getDB(), { tenantId: TENANT, idempotencyKey: `rk-${++n}`, walletId: 'w', nanoAccount: acct.address, kind: 'receive', sourceHash: SOURCE, amountRaw: '5' }, at('A', 0)).op
    const info = confirmed(acct, '100')
    const recv = nano.block.receive({ walletBalanceRaw: '100', toAddress: acct.address, transactionHash: SOURCE, frontier: FRONTIER, representativeAddress: acct.address, amountRaw: '5', work: WORK }, acct.privateKey)
    assert.equal(storePrepared(getDB(), r, at('A', 1), recv, info).block_balance_raw, '105')

    const fresh = account()
    const o = reserveReceive(getDB(), { tenantId: TENANT, idempotencyKey: `rk-${++n}`, walletId: 'w', nanoAccount: fresh.address, kind: 'open', sourceHash: SOURCE, amountRaw: '7' }, at('A', 0)).op
    const unopened: ConfirmedAccount = { frontier: ZERO64, confirmed_frontier: ZERO64, confirmed_balance: '0', confirmed_representative: DEST.address }
    const open = nano.block.receive({ walletBalanceRaw: '0', toAddress: fresh.address, transactionHash: SOURCE, frontier: ZERO64, representativeAddress: DEST.address, amountRaw: '7', work: WORK }, fresh.privateKey)
    expectCode(() => storePrepared(getDB(), o, at('A', 1), open, confirmed(fresh, '0')), 'block_mismatch')
    assert.equal(storePrepared(getDB(), o, at('A', 1), open, unopened).status, 'prepared')

    // An open on an account that is already opened, and a receive on one that is not, are refused
    // even when the block is otherwise built correctly on the state given.
    const opened = account()
    const o2 = reserveReceive(getDB(), { tenantId: TENANT, idempotencyKey: `rk-${++n}`, walletId: 'w', nanoAccount: opened.address, kind: 'open', sourceHash: SOURCE, amountRaw: '7' }, at('A', 0)).op
    const onOpened = nano.block.receive({ walletBalanceRaw: '100', toAddress: opened.address, transactionHash: SOURCE, frontier: FRONTIER, representativeAddress: opened.address, amountRaw: '7', work: WORK }, opened.privateKey)
    assert.throws(() => storePrepared(getDB(), o2, at('A', 1), onOpened, confirmed(opened, '100')),
      (e: any) => e instanceof WalletOpError && e.message === 'open_on_opened_account')
    const never = account()
    const r2 = reserveReceive(getDB(), { tenantId: TENANT, idempotencyKey: `rk-${++n}`, walletId: 'w', nanoAccount: never.address, kind: 'receive', sourceHash: SOURCE, amountRaw: '7' }, at('A', 0)).op
    const onUnopened = nano.block.receive({ walletBalanceRaw: '0', toAddress: never.address, transactionHash: SOURCE, frontier: ZERO64, representativeAddress: DEST.address, amountRaw: '7', work: WORK }, never.privateKey)
    assert.throws(() => storePrepared(getDB(), r2, at('A', 1), onUnopened, { ...unopened }),
      (e: any) => e instanceof WalletOpError && e.message === 'receive_on_unopened_account')
  })
})

describe('claim fencing', () => {
  it('F1 a live lease cannot be taken over', () => {
    const k = chain('5000', '3000'), acct = account()
    const op = reserved(reserveSend(getDB(), sendReq(k, acct), at('A', 0)))
    assert.equal(takeOver(getDB(), op.id, at('B', LEASE - 1)), null)
  })

  it('F2 after a takeover every write by the old holder fails, and the release happens once', () => {
    const k = chain('5000', '3000'), acct = account()
    const a = reserved(reserveSend(getDB(), sendReq(k, acct), at('A', 0)))
    const b = takeOver(getDB(), a.id, at('B', LEASE + 10))!
    assert.equal(b.claim_epoch, 2)
    const info = confirmed(acct, '50000')
    expectCode(() => storePrepared(getDB(), a, at('A', LEASE + 11), signSend(a, acct, info), info), 'claim_lost')
    expectCode(() => cancelOp(getDB(), a, at('A', LEASE + 11), 'stale'), 'claim_lost')
    assert.equal(renewLease(getDB(), a, at('A', LEASE + 11)), false)
    assert.deepEqual([used(k.top), used(k.low)], ['1000', '1000'])
    cancelOp(getDB(), b, at('B', LEASE + 12), 'recovered')
    assert.deepEqual([used(k.top), used(k.low)], ['0', '0'])
    expectCode(() => cancelOp(getDB(), b, at('B', LEASE + 13), 'again'), 'claim_lost')
    assert.deepEqual([used(k.top), used(k.low)], ['0', '0'])
  })

  it('F3 a holder whose lease expired cannot write until it renews, and can renew if nobody took over', () => {
    const k = chain('5000', '3000'), acct = account()
    const a = reserved(reserveSend(getDB(), sendReq(k, acct), at('A', 0)))
    const info = confirmed(acct, '50000')
    expectCode(() => storePrepared(getDB(), a, at('A', LEASE + 1), signSend(a, acct, info), info), 'claim_lost')
    assert.equal(renewLease(getDB(), a, at('A', LEASE + 2)), true)
    assert.equal(storePrepared(getDB(), a, at('A', LEASE + 3), signSend(a, acct, info), info).status, 'prepared')
  })

  it('F4 a recovery worker can cancel a prepared row it took over, releasing once', () => {
    const k = chain('5000', '3000'), acct = account()
    const a = reserved(reserveSend(getDB(), sendReq(k, acct), at('A', 0)))
    const info = confirmed(acct, '50000')
    storePrepared(getDB(), a, at('A', 1), signSend(a, acct, info), info)
    assert.ok(listRecoverable(getDB(), LEASE + 5).some(o => o.id === a.id))
    const b = takeOver(getDB(), a.id, at('B', LEASE + 5))!
    assert.equal(cancelOp(getDB(), b, at('B', LEASE + 6), 'recovered').status, 'cancelled')
    assert.deepEqual([used(k.top), used(k.low)], ['0', '0'])
    assert.ok(!listRecoverable(getDB(), LEASE * 10).some(o => o.id === a.id))
  })
  it('F5 a holder that retakes its own expired row under the same owner name still fences its old copy', () => {
    const k = chain('5000', '3000'), acct = account()
    const stale = reserved(reserveSend(getDB(), sendReq(k, acct), at('A', 0)))
    const fresh = takeOver(getDB(), stale.id, at('A', LEASE + 1))!
    assert.equal(fresh.claim_epoch, 2)
    const info = confirmed(acct, '50000')
    expectCode(() => storePrepared(getDB(), stale, at('A', LEASE + 2), signSend(stale, acct, info), info), 'claim_lost')
    expectCode(() => cancelOp(getDB(), stale, at('A', LEASE + 2), 'stale copy'), 'claim_lost')
    assert.equal(renewLease(getDB(), stale, at('A', LEASE + 2)), false)
    // The right epoch with the wrong owner is refused too.
    expectCode(() => storePrepared(getDB(), fresh, at('B', LEASE + 2), signSend(fresh, acct, info), info), 'claim_lost')
    expectCode(() => cancelOp(getDB(), fresh, at('B', LEASE + 2), 'not mine'), 'claim_lost')
    assert.deepEqual([used(k.top), used(k.low)], ['1000', '1000'])
    assert.equal(storePrepared(getDB(), fresh, at('A', LEASE + 3), signSend(fresh, acct, info), info).status, 'prepared')
  })

  it('F6 a row with a publish attempt cannot be cancelled, and keeps its reservation', () => {
    const k = chain('5000', '3000'), acct = account()
    const op = reserved(reserveSend(getDB(), sendReq(k, acct), at('A', 0)))
    const info = confirmed(acct, '50000')
    storePrepared(getDB(), op, at('A', 1), signSend(op, acct, info), info)
    // Phase C commits attempts. Here the row is moved by hand to what a first attempt leaves.
    getDB().prepare(`UPDATE wallet_ops SET status = 'admitted', attempt_count = 1, admitted_at = 2, last_attempt_at = 2 WHERE id = ?`).run(op.id)
    expectCode(() => cancelOp(getDB(), op, at('A', 3), 'too late'), 'claim_lost')
    assert.equal(getOp(getDB(), op.id)!.status, 'admitted')
    assert.deepEqual([used(k.top), used(k.low)], ['1000', '1000'])
  })
})

describe('database rules', () => {
  it('D1 the CHECKs refuse impossible rows', () => {
    const k = chain('5000', '3000'), acct = account()
    const op = reserved(reserveSend(getDB(), sendReq(k, acct), at('A', 0)))
    const db = getDB()
    assert.throws(() => db.prepare(`UPDATE wallet_ops SET status = 'prepared' WHERE id = ?`).run(op.id), /CHECK constraint failed/)
    assert.throws(() => db.prepare(`UPDATE wallet_ops SET status = 'cancelled', attempt_count = 1 WHERE id = ?`).run(op.id), /CHECK constraint failed/)
    assert.throws(() => db.prepare(`UPDATE wallet_ops SET attempt_count = 1 WHERE id = ?`).run(op.id), /CHECK constraint failed/)
    const info = confirmed(acct, '50000')
    storePrepared(db, op, at('A', 1), signSend(op, acct, info), info)
    assert.throws(() => db.prepare(`UPDATE wallet_ops SET status = 'admitted' WHERE id = ?`).run(op.id), /CHECK constraint failed/)
    assert.throws(() => db.prepare(`UPDATE wallet_ops SET chain_rows = NULL WHERE id = ?`).run(op.id), /CHECK constraint failed/)
  })

  it('D2 the account mapping check finds shared accounts, shared indexes and the gateway account', () => {
    const db = getDB()
    const before = walletAccountProblems(db, null)
    const t = `tnt_map_${++n}`
    db.prepare(`INSERT INTO tenants (id, name, email) VALUES (?, 'Map', ?)`).run(t, `${t}@test.local`)
    const ins = db.prepare(`INSERT INTO agent_wallets (id, tenant_id, agent_id, nano_address, wallet_index, status) VALUES (?, ?, ?, ?, ?, 'active')`)
    const shared = account().address
    ins.run(`mw1-${n}`, t, 'a1', shared, 9001)
    ins.run(`mw2-${n}`, t, 'a2', shared, 9002)
    ins.run(`mw3-${n}`, t, 'a3', account().address, 9001)
    ins.run(`mw4-${n}`, t, 'a4', DEST.address, 0)
    const after = walletAccountProblems(db, DEST.address)
    assert.equal(before.length, 0)
    assert.ok(after.some(p => /nano_address shared by 2/.test(p)))
    assert.ok(after.some(p => /wallet_index 9001 shared by 2/.test(p)))
    assert.ok(after.some(p => /index 0 or below/.test(p)))
    assert.ok(after.some(p => /gateway account/.test(p)))
  })
})
