// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Day 268, lifecycle phase C: the publication boundary. Every Nano call goes to a fake node that
// records what it was sent. Nothing reaches a network. Covers the attempt commit (claim, pause,
// authority, stored block), one call per token, node acceptance staying unconfirmed, the closed
// legacy paths, and that the gateway has one `process` call.
// ══════════════════════════════════════════════════════════════════
import { describe, it, before, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'
// @ts-ignore nanocurrency-web has no type declarations
import nanoWebImport from 'nanocurrency-web'
import { initDB, getDB } from '../../src/db/schema.js'
import { initGatewayIdentity } from '../../src/gateway/identity.js'
import { stateBlockHash } from '../../src/payment-rails/nano-block.js'
import {
  reserveSend, reserveReceive, takeOver, cancelOp, getOp, isSlotConflict, WalletOpError,
  type Claim, type SendRequest, type WalletOp,
} from '../../src/payment-rails/wallet-ops.js'
import {
  commitAttempt, publishAttempt, prepareOp, listAttempts, AttemptToken, type NanoNode,
} from '../../src/payment-rails/nano-publish.js'
import { sendNano, receiveNano, LEGACY_PUBLISH_CLOSED, NanoSendNotBroadcastError } from '../../src/payment-rails/wallet-crypto.js'
import { NanoPaymentRail, SETTLEMENT_PAYOUT_CLOSED } from '../../src/payment-rails/nano.js'
import { setGenerousPilotCaps, initFrontier } from './pilot-fixtures.js'

const nano = (nanoWebImport as any).default || nanoWebImport
const TENANT = 'tnt_nanopublish'
const FRONTIER = 'F47B23107E5F34B2CE06F562B5C435DF72A533251CB414C51B2B62A8F63A00E4'
const SOURCE = '19D3D919475DEED4696B5D13018151D1AF88B2BD3BCFF048B45031C1F36D1858'
const DEST = nano.wallet.fromLegacySeed('dd'.repeat(32)).accounts[0]
const LEASE = 30_000
let n = 0

const at = (owner: string, now: number): Claim => ({ owner, now, leaseMs: LEASE })
const account = () => nano.wallet.fromLegacySeed((0x2000 + ++n).toString(16).padStart(64, '0')).accounts[0]

/** A fake node. Records every call. account_info answers from `accounts`, process from `onProcess`. */
function fakeNode(opts: { balance?: string; info?: (acct: string) => any; onProcess?: (body: any) => any } = {}) {
  const calls: any[] = []
  const node: NanoNode = {
    async call(body) {
      calls.push(body)
      if (body.action === 'account_info') {
        if (opts.info) return opts.info(String(body.account))
        return { frontier: FRONTIER, confirmed_frontier: FRONTIER, confirmed_balance: opts.balance ?? '50000', confirmed_representative: body.account }
      }
      if (body.action === 'work_generate') return { work: '0123456789abcdef' }
      if (body.action === 'process') {
        if (opts.onProcess) return opts.onProcess(body)
        return { hash: stateBlockHash(body.block) }
      }
      throw new Error(`unexpected action ${body.action}`)
    },
  }
  return { node, calls, processCalls: () => calls.filter(c => c.action === 'process') }
}

function agent(id: string, status = 'active') {
  getDB().prepare(`INSERT INTO agents (id, tenant_id, agent_id, public_key, status, is_root) VALUES (?, ?, ?, 'pk', ?, 0)`).run(`row-${id}`, TENANT, id, status)
}
function del(parent: string, child: string, limit: string, parentDel: string | null): string {
  const id = `del-${++n}`
  getDB().prepare(`INSERT INTO delegations (id, tenant_id, parent_agent_id, child_agent_id, scope, status, spend_limit, spend_used, parent_delegation_id, spend_unit, spend_limit_minor, spend_used_minor) VALUES (?, ?, ?, ?, 'commerce:send', 'active', 0, 0, ?, 'nano:XNO:raw', ?, '0')`)
    .run(id, TENANT, parent, child, parentDel, limit)
  return id
}
const used = (id: string) => (getDB().prepare(`SELECT spend_used_minor FROM delegations WHERE id = ?`).get(id) as any).spend_used_minor

/** A paying agent with a two-hop chain, a wallet row on a fresh Nano account, and its key. */
function setup() {
  const t = ++n, root = `root-${t}`, p = `p-${t}`, c = `c-${t}`
  agent(root); agent(p); agent(c)
  const top = del(root, p, '5000', null)
  const low = del(p, c, '3000', top)
  const acct = account()
  const walletId = `w-${t}`
  getDB().prepare(`INSERT INTO agent_wallets (id, tenant_id, agent_id, nano_address, wallet_index, status) VALUES (?, ?, ?, ?, ?, 'active')`)
    .run(walletId, TENANT, c, acct.address, 10_000 + t)
  initFrontier(getDB(), walletId, FRONTIER, '50000')
  return { root, p, c, top, low, acct, walletId }
}
type S = ReturnType<typeof setup>
function req(s: S, over: Partial<SendRequest> = {}): SendRequest {
  return { tenantId: TENANT, idempotencyKey: `k-${++n}`, fromAgentId: s.c, walletId: s.walletId, nanoAccount: s.acct.address,
    delegationId: s.low, toAddress: DEST.address, amountRaw: '1000', ...over }
}
function reserved(s: S, claim: Claim): WalletOp {
  const r = reserveSend(getDB(), req(s), claim)
  assert.ok('op' in r)
  return r.op
}
async function prepared(s: S, claim: Claim, node: NanoNode): Promise<WalletOp> {
  return prepareOp(getDB(), node, reserved(s, claim), claim, s.acct, DEST.address)
}
function token(r: ReturnType<typeof commitAttempt>): AttemptToken {
  assert.ok('token' in r, `expected a token, got ${JSON.stringify(r)}`)
  return r.token
}

before(() => {
  setGenerousPilotCaps()
  initDB(':memory:')
  initGatewayIdentity()
  getDB().prepare(`INSERT OR IGNORE INTO tenants (id, name, email) VALUES (?, ?, ?)`).run(TENANT, 'NanoPublish', 'np@test.local')
})
beforeEach(() => {
  delete process.env.NANO_WALLETS_PAUSED
  process.env.NANO_WALLET_SEND_ENABLED = '1'
})
afterEach(() => {
  delete process.env.NANO_WALLETS_PAUSED
  delete process.env.NANO_WALLET_SEND_ENABLED
})

describe('attempt and publish', () => {
  it('C1 one attempt, one call with exactly the stored block, and node acceptance leaves the send admitted', async () => {
    const s = setup(), f = fakeNode()
    const p = await prepared(s, at('A', 0), f.node)
    assert.equal(f.processCalls().length, 0, 'preparing never publishes')
    const t = token(commitAttempt(getDB(), p, at('A', 1)))
    const out = await publishAttempt(getDB(), f.node, t, () => 2)
    assert.deepEqual(out, { outcome: 'accepted', hash: p.block_hash })
    assert.equal(f.processCalls().length, 1)
    assert.deepEqual(f.processCalls()[0].block, JSON.parse(p.block_json!))
    assert.equal(f.processCalls()[0].subtype, 'send')
    const row = getOp(getDB(), p.id)!
    assert.equal(row.status, 'admitted')
    assert.equal(row.attempt_count, 1)
    assert.equal(listAttempts(getDB(), p.id)[0].outcome, 'accepted')
    assert.deepEqual([used(s.top), used(s.low)], ['1000', '1000'])
  })

  it('C2 a token allows one call, and only commitAttempt makes tokens', async () => {
    const s = setup(), f = fakeNode()
    const p = await prepared(s, at('A', 0), f.node)
    const t = token(commitAttempt(getDB(), p, at('A', 1)))
    await publishAttempt(getDB(), f.node, t)
    await assert.rejects(() => publishAttempt(getDB(), f.node, t), /unspent token/)
    const forged = Object.create(AttemptToken.prototype)
    Object.assign(forged, { opId: p.id, attempt: 2, kind: 'send', blockHash: p.block_hash, block: JSON.parse(p.block_json!) })
    await assert.rejects(() => publishAttempt(getDB(), f.node, forged), /unspent token/)
    assert.equal(f.processCalls().length, 1)
  })

  it('C3 a node error or a wrong hash leaves the send admitted, and a retry sends the identical block', async () => {
    const s = setup()
    let mode: 'error' | 'ok' = 'error'
    const f = fakeNode({ onProcess: (b) => { if (mode === 'error') throw new Error('socket hang up'); return { hash: stateBlockHash(b.block) } } })
    const p = await prepared(s, at('A', 0), f.node)
    const o1 = await publishAttempt(getDB(), f.node, token(commitAttempt(getDB(), p, at('A', 1))))
    assert.equal(o1.outcome, 'error')
    assert.equal(getOp(getDB(), p.id)!.status, 'admitted')
    mode = 'ok'
    const o2 = await publishAttempt(getDB(), f.node, token(commitAttempt(getDB(), p, at('A', 2))))
    assert.equal(o2.outcome, 'accepted')
    const [c1, c2] = f.processCalls()
    assert.deepEqual(c1.block, c2.block)
    assert.deepEqual(listAttempts(getDB(), p.id).map(a => [a.attempt_no, a.outcome]), [[1, 'error'], [2, 'accepted']])
  })

  it('C4 a hash from the node that differs from the stored hash blocks every further attempt', async () => {
    const s = setup(), f = fakeNode({ onProcess: () => ({ hash: SOURCE }) })
    const p = await prepared(s, at('A', 0), f.node)
    assert.equal((await publishAttempt(getDB(), f.node, token(commitAttempt(getDB(), p, at('A', 1))))).outcome, 'hash_mismatch')
    assert.deepEqual(commitAttempt(getDB(), p, at('A', 2)), { refused: 'publish_hash_mismatch_recorded', cancelled: false })
    assert.equal(f.processCalls().length, 1)
  })

  it('C5 a stored block changed in the database is refused before any call', async () => {
    const s = setup(), f = fakeNode()
    const p = await prepared(s, at('A', 0), f.node)
    const b = JSON.parse(p.block_json!)
    b.balance = '1'
    getDB().prepare(`UPDATE wallet_ops SET block_json = ? WHERE id = ?`).run(JSON.stringify(b), p.id)
    assert.deepEqual(commitAttempt(getDB(), p, at('A', 1)), { refused: 'stored_block_hash_mismatch', cancelled: false })
    assert.equal(f.processCalls().length, 0)
  })
})

describe('pause', () => {
  it('P1 paused or send-disabled: no attempt commits, the row stays prepared, no call', async () => {
    const s = setup(), f = fakeNode()
    const p = await prepared(s, at('A', 0), f.node)
    process.env.NANO_WALLETS_PAUSED = '1'
    assert.deepEqual(commitAttempt(getDB(), p, at('A', 1)), { refused: 'nano_wallets_paused', cancelled: false })
    delete process.env.NANO_WALLETS_PAUSED
    delete process.env.NANO_WALLET_SEND_ENABLED
    assert.deepEqual(commitAttempt(getDB(), p, at('A', 1)), { refused: 'nano_send_disabled', cancelled: false })
    const row = getOp(getDB(), p.id)!
    assert.equal(row.status, 'prepared')
    assert.equal(listAttempts(getDB(), p.id).length, 0)
    assert.equal(f.processCalls().length, 0)
  })

  it('P2 a pause set after the attempt commits stops the call if it is read before the call', async () => {
    const s = setup(), f = fakeNode()
    const p = await prepared(s, at('A', 0), f.node)
    const t = token(commitAttempt(getDB(), p, at('A', 1)))
    process.env.NANO_WALLETS_PAUSED = '1'
    assert.deepEqual(await publishAttempt(getDB(), f.node, t), { outcome: 'skipped_paused', reason: 'nano_wallets_paused' })
    assert.equal(f.processCalls().length, 0)
    assert.equal(getOp(getDB(), p.id)!.status, 'admitted', 'an attempt was committed, so the row is admitted')
  })

  it('P3 a recovery worker under pause commits nothing and calls nothing', async () => {
    const s = setup(), f = fakeNode({ onProcess: () => { throw new Error('timeout') } })
    const p = await prepared(s, at('A', 0), f.node)
    await publishAttempt(getDB(), f.node, token(commitAttempt(getDB(), p, at('A', 1))))
    process.env.NANO_WALLETS_PAUSED = '1'
    const r = takeOver(getDB(), p.id, at('R', LEASE + 5))!
    assert.deepEqual(commitAttempt(getDB(), r, at('R', LEASE + 6)), { refused: 'nano_wallets_paused', cancelled: false })
    assert.equal(f.processCalls().length, 1)
  })

  it('P4 receives publish when sends are disabled, and not when paused', async () => {
    const s = setup(), f = fakeNode()
    delete process.env.NANO_WALLET_SEND_ENABLED
    const r = reserveReceive(getDB(), { tenantId: TENANT, idempotencyKey: `rk-${++n}`, walletId: s.walletId, nanoAccount: s.acct.address, kind: 'receive', sourceHash: SOURCE, amountRaw: '5' }, at('A', 0)).op
    const p = await prepareOp(getDB(), f.node, r, at('A', 1), s.acct, DEST.address)
    assert.equal(p.block_balance_raw, '50005')
    process.env.NANO_WALLETS_PAUSED = '1'
    assert.deepEqual(commitAttempt(getDB(), p, at('A', 2)), { refused: 'nano_wallets_paused', cancelled: false })
    delete process.env.NANO_WALLETS_PAUSED
    await publishAttempt(getDB(), f.node, token(commitAttempt(getDB(), p, at('A', 3))))
    assert.equal(f.processCalls()[0].subtype, 'receive')
  })
})

describe('claims and cancellation', () => {
  it('K1 a worker whose claim was taken commits no attempt and makes no call', async () => {
    const s = setup(), f = fakeNode()
    const a = await prepared(s, at('A', 0), f.node)
    const b = takeOver(getDB(), a.id, at('B', LEASE + 1))!
    assert.throws(() => commitAttempt(getDB(), a, at('A', LEASE + 2)), (e: any) => e instanceof WalletOpError && e.code === 'claim_lost')
    await publishAttempt(getDB(), f.node, token(commitAttempt(getDB(), b, at('B', LEASE + 2))))
    assert.throws(() => commitAttempt(getDB(), a, at('A', LEASE + 3)), (e: any) => e instanceof WalletOpError && e.code === 'claim_lost')
    assert.equal(f.processCalls().length, 1)
    assert.deepEqual(listAttempts(getDB(), a.id).map(x => x.lease_owner), ['B'])
  })

  it('K2 cancel and first attempt: whichever commits first wins, the other changes nothing', async () => {
    const f = fakeNode()
    const s1 = setup()
    const p1 = await prepared(s1, at('A', 0), f.node)
    token(commitAttempt(getDB(), p1, at('A', 1)))
    assert.throws(() => cancelOp(getDB(), p1, at('A', 2), 'late cancel'), (e: any) => e instanceof WalletOpError && e.code === 'claim_lost')
    assert.deepEqual([used(s1.top), used(s1.low)], ['1000', '1000'])

    const s2 = setup()
    const p2 = await prepared(s2, at('A', 0), f.node)
    cancelOp(getDB(), p2, at('A', 1), 'cancel first')
    assert.throws(() => commitAttempt(getDB(), p2, at('A', 2)), (e: any) => e instanceof WalletOpError && e.code === 'claim_lost')
    assert.deepEqual([used(s2.top), used(s2.low)], ['0', '0'])
    assert.equal(listAttempts(getDB(), p2.id).length, 0)
  })
  it('K3 the same owner after a retake, the right epoch with another owner, and an expired lease: no attempt, no call', async () => {
    const s = setup(), f = fakeNode()
    const stale = await prepared(s, at('A', 0), f.node)
    assert.throws(() => commitAttempt(getDB(), stale, at('A', LEASE + 1)), (e: any) => e instanceof WalletOpError && e.code === 'claim_lost', 'expired lease')
    const fresh = takeOver(getDB(), stale.id, at('A', LEASE + 1))!
    assert.throws(() => commitAttempt(getDB(), stale, at('A', LEASE + 2)), (e: any) => e instanceof WalletOpError && e.code === 'claim_lost', 'old epoch')
    assert.throws(() => commitAttempt(getDB(), fresh, at('B', LEASE + 2)), (e: any) => e instanceof WalletOpError && e.code === 'claim_lost', 'other owner')
    assert.equal(listAttempts(getDB(), stale.id).length, 0)
    assert.equal(f.processCalls().length, 0)
    token(commitAttempt(getDB(), fresh, at('A', LEASE + 3)))
  })
})

describe('authority at each attempt', () => {
  const cases: Array<[string, (s: S) => void, string]> = [
    ['the delegation revoked', (s) => { getDB().prepare(`UPDATE delegations SET status = 'revoked' WHERE id = ?`).run(s.low) }, 'delegation_not_active'],
    ['a grantor up the chain revoked', (s) => { getDB().prepare(`UPDATE agents SET status = 'revoked' WHERE agent_id = ?`).run(s.root) }, 'authority_chain_agent_revoked'],
    ['the upper delegation revoked', (s) => { getDB().prepare(`UPDATE delegations SET status = 'revoked' WHERE id = ?`).run(s.top) }, 'authority_chain_inactive_delegation'],
    ['the paying agent suspended', (s) => { getDB().prepare(`UPDATE agents SET status = 'suspended' WHERE agent_id = ?`).run(s.c) }, 'paying_agent_not_active'],
    ['the wallet frozen', (s) => { getDB().prepare(`UPDATE agent_wallets SET status = 'frozen' WHERE id = ?`).run(s.walletId) }, 'wallet_not_active'],
    ['an upgrade hold', (s) => { getDB().prepare(`INSERT INTO chain_spend_holds (delegation_id, tenant_id, reason, created_at) VALUES (?, ?, 'hold', datetime('now'))`).run(s.top, TENANT) }, 'chain_on_upgrade_hold'],
  ]
  for (const [name, withdraw, reason] of cases) {
    it(`A1 ${name} before the first attempt: cancelled, released once, no call`, async () => {
      const s = setup(), f = fakeNode()
      const p = await prepared(s, at('A', 0), f.node)
      withdraw(s)
      assert.deepEqual(commitAttempt(getDB(), p, at('A', 1)), { refused: reason, cancelled: true })
      assert.equal(getOp(getDB(), p.id)!.status, 'cancelled')
      assert.deepEqual([used(s.top), used(s.low)], ['0', '0'])
      assert.equal(f.processCalls().length, 0)
    })
  }

  it('A2 revoked after the first attempt commits and before its call: that call proceeds, no retry commits, reservation kept', async () => {
    const s = setup(), f = fakeNode({ onProcess: () => { throw new Error('timeout') } })
    const p = await prepared(s, at('A', 0), f.node)
    const t = token(commitAttempt(getDB(), p, at('A', 1)))
    getDB().prepare(`UPDATE delegations SET status = 'revoked' WHERE id = ?`).run(s.low)
    await publishAttempt(getDB(), f.node, t) // the timing limit: this call was already allowed
    assert.equal(f.processCalls().length, 1)
    assert.deepEqual(commitAttempt(getDB(), p, at('A', 2)), { refused: 'delegation_not_active', cancelled: false })
    assert.equal(f.processCalls().length, 1)
    assert.equal(getOp(getDB(), p.id)!.status, 'admitted')
    assert.deepEqual([used(s.top), used(s.low)], ['1000', '1000'])
  })

  it('A3 a lost reservation is refused', async () => {
    const s = setup(), f = fakeNode()
    const p = await prepared(s, at('A', 0), f.node)
    getDB().prepare(`UPDATE delegations SET spend_used_minor = '0' WHERE id = ?`).run(s.low)
    assert.deepEqual(commitAttempt(getDB(), p, at('A', 1)), { refused: 'reservation_missing', cancelled: false })
    assert.equal(getOp(getDB(), p.id)!.status, 'prepared')
    assert.equal(f.processCalls().length, 0)
  })
})

describe('preparing', () => {
  it('R1 missing confirmed fields or an unconfirmed frontier build no block and call no process', async () => {
    const s = setup()
    const noConfirmed = fakeNode({ info: () => ({ frontier: FRONTIER, balance: '50000', representative: s.acct.address }) })
    const op = reserved(s, at('A', 0))
    await assert.rejects(() => prepareOp(getDB(), noConfirmed.node, op, at('A', 1), s.acct, DEST.address),
      (e: any) => e instanceof WalletOpError && e.message === 'account_info_confirmed_frontier_missing')
    const unconfirmed = fakeNode({ info: (a) => ({ frontier: SOURCE, confirmed_frontier: FRONTIER, confirmed_balance: '50000', confirmed_representative: a }) })
    await assert.rejects(() => prepareOp(getDB(), unconfirmed.node, op, at('A', 1), s.acct, DEST.address),
      (e: any) => e instanceof WalletOpError && e.message === 'frontier_unconfirmed')
    assert.equal(getOp(getDB(), op.id)!.status, 'reserved')
    assert.equal(noConfirmed.processCalls().length + unconfirmed.processCalls().length, 0)
  })

  it('R2 an amount above the confirmed balance is refused before signing', async () => {
    const s = setup(), f = fakeNode({ balance: '999' })
    initFrontier(getDB(), s.walletId, FRONTIER, '999', true)
    const op = reserved(s, at('A', 0))
    await assert.rejects(() => prepareOp(getDB(), f.node, op, at('A', 1), s.acct, DEST.address),
      (e: any) => e instanceof WalletOpError && e.message === 'amount_exceeds_confirmed_balance')
  })

  it('R3 an open on an unopened account uses the account key as work root', async () => {
    const s = setup()
    const f = fakeNode({ info: () => { throw new Error('Nano RPC: Account not found') } })
    const o = reserveReceive(getDB(), { tenantId: TENANT, idempotencyKey: `rk-${++n}`, walletId: s.walletId, nanoAccount: s.acct.address, kind: 'open', sourceHash: SOURCE, amountRaw: '7' }, at('A', 0)).op
    const p = await prepareOp(getDB(), f.node, o, at('A', 1), s.acct, DEST.address)
    assert.equal(p.block_previous, '0'.repeat(64))
    assert.equal(f.calls.find(c => c.action === 'work_generate').hash, s.acct.publicKey.toUpperCase())
  })
})

describe('one publication boundary', () => {
  it('B1 the legacy agent send and receive paths refuse before calling anything', async () => {
    const realFetch = globalThis.fetch
    let fetches = 0
    globalThis.fetch = (async () => { fetches++; throw new Error('no network in tests') }) as any
    try {
      await assert.rejects(() => sendNano({ rpcUrl: 'http://node.invalid', seed: '0'.repeat(128), fromIndex: 1, toAddress: DEST.address, amountRaw: '1' }),
        (e: any) => e instanceof NanoSendNotBroadcastError && e.message === LEGACY_PUBLISH_CLOSED)
      await assert.rejects(() => receiveNano({ rpcUrl: 'http://node.invalid', seed: '0'.repeat(128), accountIndex: 1 }),
        (e: any) => e.message === LEGACY_PUBLISH_CLOSED)
      assert.equal(fetches, 0)
    } finally {
      globalThis.fetch = realFetch
    }
  })

  it('B2 settlement payouts refuse before calling anything, with payouts enabled and nothing paused', async () => {
    const realFetch = globalThis.fetch
    let fetches = 0
    globalThis.fetch = (async () => { fetches++; throw new Error('no network in tests') }) as any
    process.env.SETTLE_PAYOUT_ENABLED = 'true'
    try {
      const rail = new NanoPaymentRail({ rpcUrl: 'http://node.invalid', receivingAddress: DEST.address } as any)
      await assert.rejects(() => rail.sendPayment({ destination: DEST.address, amount: 1 }), (e: any) => e.message === SETTLEMENT_PAYOUT_CLOSED)
      assert.equal(fetches, 0)
    } finally {
      delete process.env.SETTLE_PAYOUT_ENABLED
      globalThis.fetch = realFetch
    }
  })

  it('B3 the gateway source has exactly one Nano process call, in nano-publish.ts', () => {
    const hits: string[] = []
    const walk = (dir: string) => {
      for (const name of readdirSync(dir)) {
        const p = join(dir, name)
        if (statSync(p).isDirectory()) walk(p)
        else if (/\.(ts|js|mjs|cjs)$/.test(name)) {
          const src = readFileSync(p, 'utf8')
          for (const m of src.matchAll(/action\s*:\s*['"`]process['"`]/g)) hits.push(`${p}:${m.index}`)
        }
      }
    }
    walk('src')
    assert.equal(hits.length, 1, hits.join('\n'))
    assert.match(hits[0], /src\/payment-rails\/nano-publish\.ts:/)
  })

  it('B4 an account-slot conflict from SQLite maps to wallet_busy, not an unhandled error', () => {
    const s = setup()
    reserved(s, at('A', 0))
    let err: any
    try {
      getDB().prepare(`INSERT INTO wallet_ops (id, kind, tenant_id, idempotency_key, request_fingerprint, nano_account, amount_raw, source_hash, status)
        VALUES (?, 'receive', ?, ?, 'fp', ?, '1', ?, 'reserved')`).run(`direct-${++n}`, TENANT, `direct-${n}`, s.acct.address, SOURCE)
    } catch (e) { err = e }
    assert.ok(err, 'the partial unique index refused the second active row')
    assert.equal(isSlotConflict(err), true)
    assert.equal(isSlotConflict(new Error('UNIQUE constraint failed: wallet_ops.tenant_id, wallet_ops.idempotency_key')), false)
  })

  it('B5 an unsafe wallet-to-account mapping anywhere stops every attempt', async () => {
    const s = setup(), f = fakeNode()
    const p = await prepared(s, at('A', 0), f.node)
    getDB().prepare(`INSERT INTO agent_wallets (id, tenant_id, agent_id, nano_address, wallet_index, status) VALUES (?, ?, ?, ?, ?, 'active')`)
      .run('w-dup', TENANT, 'someone-else', s.acct.address, 99_999)
    try {
      assert.deepEqual(commitAttempt(getDB(), p, at('A', 1)), { refused: 'wallet_account_mapping_unsafe', cancelled: false })
      assert.equal(getOp(getDB(), p.id)!.status, 'prepared')
      assert.deepEqual([used(s.top), used(s.low)], ['1000', '1000'])
      assert.equal(f.processCalls().length, 0)
    } finally {
      getDB().prepare(`DELETE FROM agent_wallets WHERE id = 'w-dup'`).run()
    }
  })
})
