// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Day 268: explicit spending units on delegations (src/gateway/spend-units.ts).
// A unit-declared grant states its unit and an exact integer limit in that unit's minor
// denomination. Ambiguity is refused: a unit grant under a legacy bounded parent, a legacy
// grant under a unit parent, a different unit, or a limit above the parent's remaining.
// Legacy grants and /evaluate behave exactly as before. A unit-declared row carries a zero
// REAL budget, so /evaluate, which reads only the REAL columns, refuses to spend against it.
// ══════════════════════════════════════════════════════════════════
import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import express from 'express'
import type { Server } from 'node:http'
import { initDB, getDB } from '../../src/db/schema.js'
import { initGatewayIdentity } from '../../src/gateway/identity.js'
import { gatewayRouter, applyGrantWithReverify, AuthorityChangedError } from '../../src/gateway/enforce.js'
import { attestationSpendConstraints, buildAgentTrustProfile } from '../../src/gateway/trust-profile.js'
import { exactXnoToRaw, parseMinor, parseSendAmount, unitNarrowingViolation, unitSpendViolation } from '../../src/gateway/spend-units.js'
import type { UnitRow } from '../../src/gateway/spend-units.js'

const TENANT = 'tnt_units'
const XNO = 'nano:XNO:raw'
const USD = 'iso4217:USD:minor'
let server: Server, baseUrl: string
let n = 0
const get = async (p: string) => {
  const r = await fetch(`${baseUrl}${p}`)
  return { status: r.status, body: await r.json() as any }
}
const post = async (p: string, b: unknown) => {
  const r = await fetch(`${baseUrl}${p}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b) })
  return { status: r.status, body: await r.json() as any }
}
const agent = (id: string, isRoot = 0) =>
  getDB().prepare(`INSERT INTO agents (id, tenant_id, agent_id, public_key, status, is_root) VALUES (?, ?, ?, 'pk', 'active', ?)`).run(`row-${id}`, TENANT, id, isRoot)
const del = (id: string) => getDB().prepare(`SELECT * FROM delegations WHERE id = ?`).get(id) as any
const fresh = (tag: string) => { const a = `a-${tag}-${++n}`; agent(a); return a }

before(async () => {
  initDB(':memory:')
  initGatewayIdentity()
  getDB().prepare(`INSERT OR IGNORE INTO tenants (id, name, email) VALUES (?, ?, ?)`).run(TENANT, 'Units', 'u@test.local')
  agent('root', 1)
  const app = express()
  app.use(express.json())
  app.use((req: any, _res, next) => { req.tenant = { id: TENANT, role: 'user', plan: 'enterprise' }; next() })
  app.use('/api/v1', gatewayRouter)
  await new Promise<void>((resolve) => { server = app.listen(0, () => { const a = server.address(); baseUrl = `http://127.0.0.1:${typeof a === 'object' && a ? a.port : 0}/api/v1`; resolve() }) })
})
after(() => server?.close())

describe('amounts', () => {
  it('only canonical unsigned decimal integer strings parse, including values beyond 2^64', () => {
    assert.equal(parseMinor('0'), 0n)
    assert.equal(parseMinor('1000000000000000000000000000000'), 10n ** 30n)
    for (const bad of ['01', '-1', '1.0', '1e3', '', ' 1', 5 as unknown]) assert.equal(parseMinor(bad), null, String(bad))
  })
})

describe('unit narrowing rules', () => {
  const unitRow = (unit: string | null, limit: string | null, used = '0', real: number | null = 0): UnitRow =>
    ({ id: 'p', spend_unit: unit, spend_limit: real, spend_limit_minor: limit, spend_used_minor: unit ? used : null })
  it('refuses every ambiguous or widening combination', () => {
    const cases: [UnitRow | null, { spend_unit: string | null; spend_limit_minor: string | null }, string | null][] = [
      [null, { spend_unit: XNO, spend_limit_minor: '5' }, null],
      [null, { spend_unit: 'nano:XNO', spend_limit_minor: '5' }, 'spend_unit_unknown'],
      [unitRow(null, null, '0', 100), { spend_unit: XNO, spend_limit_minor: '5' }, 'parent_budget_unit_unproven'],
      [unitRow(null, null, '0', null), { spend_unit: XNO, spend_limit_minor: '5' }, null],
      [unitRow(null, null, '0', 100), { spend_unit: null, spend_limit_minor: null }, null],
      [unitRow(XNO, '10'), { spend_unit: null, spend_limit_minor: null }, 'spend_unit_required_under_unit_parent'],
      [unitRow(XNO, '10'), { spend_unit: USD, spend_limit_minor: '5' }, 'spend_unit_mismatch'],
      [unitRow(XNO, '10'), { spend_unit: XNO, spend_limit_minor: null }, 'child_unbounded_under_bounded_parent'],
      [unitRow(XNO, '10', '4'), { spend_unit: XNO, spend_limit_minor: '7' }, 'spend_limit_exceeds_parent_remaining'],
      [unitRow(XNO, '10', '4'), { spend_unit: XNO, spend_limit_minor: '6' }, null],
      [unitRow(XNO, null), { spend_unit: XNO, spend_limit_minor: null }, null],
    ]
    for (const [parent, child, expected] of cases) {
      assert.equal(unitNarrowingViolation(parent, child), expected, JSON.stringify({ parent, child }))
    }
  })
  it('a spend through a legacy bounded row, a different unit or past any limit is refused', () => {
    const leaf = unitRow(XNO, '10')
    assert.equal(unitSpendViolation([leaf], XNO, 10n), null)
    assert.equal(unitSpendViolation([leaf], XNO, 11n), 'budget_exceeded')
    assert.equal(unitSpendViolation([leaf], USD, 1n), 'unit_not_delegated')
    assert.equal(unitSpendViolation([leaf, unitRow(null, null, '0', 100)], XNO, 1n), 'unit_not_delegated')
    assert.equal(unitSpendViolation([leaf, unitRow(null, null, '0', null)], XNO, 1n), null)
    assert.equal(unitSpendViolation([leaf, unitRow(XNO, '3')], XNO, 4n), 'budget_exceeded')
    assert.equal(unitSpendViolation([unitRow(XNO, null)], XNO, 1n), 'spend_unbounded_refused')
    assert.equal(unitSpendViolation([leaf], XNO, 0n), 'amount_not_positive')
  })
})

describe('POST /delegations with explicit units', () => {
  it('a designated root grants an XNO budget, stored exactly, with a zero REAL budget beside it', async () => {
    const child = fresh('xno')
    const r = await post('/delegations', { parent_agent_id: 'root', child_agent_id: child, scope: 'commerce:send', spend_unit: XNO, spend_limit_minor: '25000000000000000000000000000000' })
    assert.equal(r.status, 201, JSON.stringify(r.body))
    const row = del(r.body.id)
    assert.deepEqual([row.spend_unit, row.spend_limit_minor, row.spend_used_minor, row.spend_limit, row.spend_limit_cents], [XNO, '25000000000000000000000000000000', '0', 0, 0])
  })

  it('rejects malformed unit requests before anything is written', async () => {
    const child = fresh('bad')
    const bad = [
      { spend_unit: 'XNO', spend_limit_minor: '5' },
      { spend_unit: XNO, spend_limit: 5 },
      { spend_unit: XNO, spend_limit_minor: '05' },
      { spend_unit: XNO, spend_limit_minor: 5 },
      { spend_limit_minor: '5' },
    ]
    for (const b of bad) {
      const r = await post('/delegations', { parent_agent_id: 'root', child_agent_id: child, scope: 'commerce:send', ...b })
      assert.equal(r.status, 400, JSON.stringify(b))
    }
    assert.equal((getDB().prepare(`SELECT COUNT(*) AS c FROM delegations WHERE child_agent_id = ?`).get(child) as any).c, 0)
  })

  it('under an XNO parent: a legacy request, another unit and an over-budget child are refused, the exact remaining is granted', async () => {
    const mid = fresh('mid')
    const top = await post('/delegations', { parent_agent_id: 'root', child_agent_id: mid, scope: 'commerce:send', spend_unit: XNO, spend_limit_minor: '100' })
    assert.equal(top.status, 201)
    getDB().prepare(`UPDATE delegations SET spend_used_minor = '40' WHERE id = ?`).run(top.body.id)
    const leaf = fresh('leaf')
    const attempt = async (b: object) => post('/delegations', { parent_agent_id: mid, child_agent_id: leaf, scope: 'commerce:send', ...b })
    assert.deepEqual((await attempt({ spend_limit: 5 })).body.violations, ['spend_unit_required_under_unit_parent'])
    assert.deepEqual((await attempt({})).body.violations, ['spend_unit_required_under_unit_parent'])
    assert.deepEqual((await attempt({ spend_unit: USD, spend_limit_minor: '5' })).body.violations, ['spend_unit_mismatch'])
    assert.deepEqual((await attempt({ spend_unit: XNO, spend_limit_minor: '61' })).body.violations, ['spend_limit_exceeds_parent_remaining'])
    assert.deepEqual((await attempt({ spend_unit: XNO })).body.violations, ['child_unbounded_under_bounded_parent'])
    const ok = await attempt({ spend_unit: XNO, spend_limit_minor: '60' })
    assert.equal(ok.status, 201, JSON.stringify(ok.body))
  })

  it('an XNO grant under a legacy bounded parent is refused, under a legacy unbounded parent it is allowed', async () => {
    const boundedMid = fresh('lb')
    const lb = await post('/delegations', { parent_agent_id: 'root', child_agent_id: boundedMid, scope: 'commerce:send', spend_limit: 100 })
    assert.equal(lb.status, 201)
    const r1 = await post('/delegations', { parent_agent_id: boundedMid, child_agent_id: fresh('lbc'), scope: 'commerce:send', spend_unit: XNO, spend_limit_minor: '5' })
    assert.deepEqual([r1.status, r1.body.violations], [403, ['parent_budget_unit_unproven']])

    const openMid = fresh('lu')
    const lu = await post('/delegations', { parent_agent_id: 'root', child_agent_id: openMid, scope: 'commerce:send' })
    assert.equal(lu.status, 201)
    const r2 = await post('/delegations', { parent_agent_id: openMid, child_agent_id: fresh('luc'), scope: 'commerce:send', spend_unit: XNO, spend_limit_minor: '5' })
    assert.equal(r2.status, 201, JSON.stringify(r2.body))
  })

  it('legacy grants are unchanged (control)', async () => {
    const mid = fresh('legacy')
    const top = await post('/delegations', { parent_agent_id: 'root', child_agent_id: mid, scope: 'commerce:send', spend_limit: 50 })
    assert.equal(top.status, 201)
    const row = del(top.body.id)
    assert.deepEqual([row.spend_unit, row.spend_limit_minor, row.spend_used_minor, row.spend_limit], [null, null, null, 50])
    const over = await post('/delegations', { parent_agent_id: mid, child_agent_id: fresh('legacyc'), scope: 'commerce:send', spend_limit: 60 })
    assert.equal(over.status, 403)
  })
})

describe('/evaluate against a unit-declared delegation', () => {
  it('a cost-bearing evaluation is denied and moves no budget, a cost-free one is unchanged', async () => {
    const a = fresh('eval')
    const g = await post('/delegations', { parent_agent_id: 'root', child_agent_id: a, scope: 'data:read', spend_unit: USD, spend_limit_minor: '10000' })
    assert.equal(g.status, 201)
    const spend = await post('/evaluate', { agent_id: a, action_type: 'data:read', scope_required: 'data:read', estimated_cost: 1 })
    assert.equal(spend.body.verdict, 'deny', JSON.stringify(spend.body))
    const row = del(g.body.id)
    assert.deepEqual([row.spend_used, row.spend_used_minor], [0, '0'])
    const free = await post('/evaluate', { agent_id: a, action_type: 'data:read', scope_required: 'data:read' })
    assert.equal(free.body.verdict, 'permit', JSON.stringify(free.body))
  })
})

describe('the grant re-verifies the unit budget inside the write lock', () => {
  it('a spend that commits after the route check makes the grant fail with AuthorityChangedError and write nothing', async () => {
    const mid = fresh('race')
    const top = await post('/delegations', { parent_agent_id: 'root', child_agent_id: mid, scope: 'commerce:send', spend_unit: XNO, spend_limit_minor: '100' })
    assert.equal(top.status, 201)
    getDB().prepare(`UPDATE delegations SET spend_used_minor = '90' WHERE id = ?`).run(top.body.id)
    const child = fresh('racec')
    const id = `del-race-${++n}`
    assert.throws(() => applyGrantWithReverify(getDB(), {
      tenantId: TENANT, grantorId: mid, childId: child, delegationId: id, scope: 'commerce:send',
      spendLimit: null, spendLimitCents: null, maxDepth: 3, childDepth: 1, wasOrigination: false,
      parentDelId: top.body.id, spendUnit: XNO, spendLimitMinor: '50',
    }), AuthorityChangedError)
    assert.equal(del(id), undefined)
  })
})

describe('send amounts from a request', () => {
  it('a JSON number is refused, because JSON.parse has already rounded it', () => {
    const body = JSON.parse('{"amount_xno": 1.000000000000000000000000000001}')
    assert.equal(typeof body.amount_xno, 'number')
    assert.equal(body.amount_xno, 1)
    assert.ok('error' in parseSendAmount(body))
  })
  it('an exact decimal string and a raw string convert without floating point', () => {
    assert.deepEqual(parseSendAmount({ amount_xno: '1.000000000000000000000000000001' }), { raw: '1000000000000000000000000000001' })
    assert.deepEqual(parseSendAmount({ amount_xno: '0.1' }), { raw: '100000000000000000000000000000' })
    assert.deepEqual(parseSendAmount({ amount_raw: '1000000000000000000000000000001' }), { raw: '1000000000000000000000000000001' })
    assert.equal(exactXnoToRaw('0.000000000000000000000000000001'), '1')
  })
  it('refuses everything ambiguous', () => {
    for (const b of [
      {}, { amount_xno: '1e-7' }, { amount_xno: '-1' }, { amount_xno: '0' }, { amount_xno: '01.5' },
      { amount_xno: '0.' + '1'.repeat(31) }, { amount_raw: '0' }, { amount_raw: '01' }, { amount_raw: 5 },
      { amount_raw: '5', amount_xno: '5' },
    ]) assert.ok('error' in parseSendAmount(b as any), JSON.stringify(b))
  })
})

describe('/evaluate under a unit-declared delegation: zero, missing and positive cost, and commerce', () => {
  it('non-commerce: missing and zero cost permit, a positive cost is refused with the unit named', async () => {
    const a = fresh('ev2')
    const g = await post('/delegations', { parent_agent_id: 'root', child_agent_id: a, scope: 'data:read', spend_unit: USD, spend_limit_minor: '10000' })
    assert.equal(g.status, 201)
    const call = (extra: object) => post('/evaluate', { agent_id: a, action_type: 'data:read', scope_required: 'data:read', ...extra })
    assert.equal((await call({})).body.verdict, 'permit')
    assert.equal((await call({ estimated_cost: 0 })).body.verdict, 'permit')
    const pos = await call({ estimated_cost: 1 })
    assert.equal(pos.body.verdict, 'deny')
    assert.match(JSON.stringify(pos.body), /declared in iso4217:USD:minor/)
    assert.deepEqual([del(g.body.id).spend_used, del(g.body.id).spend_used_minor], [0, '0'])
  })
  it('commerce: refused whatever cost is reported, so a zero-cost permit cannot stand in for a spend', async () => {
    const a = fresh('ev3')
    // commerce:checkout, not commerce:send: the high-risk guard refuses commerce:send before this
    // rule runs unless a signed playbook covers it, so it would not exercise the unit rule.
    const g = await post('/delegations', { parent_agent_id: 'root', child_agent_id: a, scope: 'commerce:checkout', spend_unit: XNO, spend_limit_minor: '10' })
    assert.equal(g.status, 201)
    for (const extra of [{}, { estimated_cost: 0 }, { estimated_cost: 1 }]) {
      const r = await post('/evaluate', { agent_id: a, action_type: 'commerce:checkout', scope_required: 'commerce:checkout', ...extra })
      assert.equal(r.body.verdict, 'deny', JSON.stringify(extra))
      assert.match(JSON.stringify(r.body), /commerce action|cost-bearing action/)
    }
  })
  it('legacy delegations never get the unit refusal (control)', async () => {
    const a = fresh('ev4')
    const g = await post('/delegations', { parent_agent_id: 'root', child_agent_id: a, scope: 'commerce:checkout', spend_limit: 10 })
    assert.equal(g.status, 201)
    // Other gates (the tier-3 freshness gate for money actions) may still refuse it. The unit rule
    // must not: it applies only to unit-declared delegations.
    const r = await post('/evaluate', { agent_id: a, action_type: 'commerce:checkout', scope_required: 'commerce:checkout' })
    assert.doesNotMatch(JSON.stringify(r.body), /declared in /)
  })
})

describe('budget fields exposed publicly (trust profile and the signed governance attestation)', () => {
  const profileOf = (a: string) => {
    const agentRow = getDB().prepare(`SELECT * FROM agents WHERE tenant_id = ? AND agent_id = ?`).get(TENANT, a) as any
    return buildAgentTrustProfile({ db: getDB(), agent: agentRow, agentId: a,
      computeContinuityScore: () => ({ score: 1, context_break: false, signals: {} }) })
  }
  it('a unit-declared budget is reported exactly, and its REAL limit as zero, never as no limit', async () => {
    const a = fresh('tp')
    const g = await post('/delegations', { parent_agent_id: 'root', child_agent_id: a, scope: 'commerce:send', spend_unit: XNO, spend_limit_minor: '7000000000000000000000000000000' })
    assert.equal(g.status, 201)
    const c = profileOf(a).active_constraints!
    assert.deepEqual([c.spend_unit, c.spend_limit_minor, c.spend_used_minor, c.spend_limit], [XNO, '7000000000000000000000000000000', '0', 0])
    // The signed attestation cannot state a unit budget exactly, so it is refused, never sent with a
    // zero REAL limit that would read as a zero budget.
    const att = attestationSpendConstraints(profileOf(a)._delegation_for_signal)
    assert.equal(att.ok, false)
  })
  it('a legacy budget: a zero limit is reported as 0, not as no limit, and no currency is asserted', async () => {
    const a = fresh('tp0')
    const g = await post('/delegations', { parent_agent_id: 'root', child_agent_id: a, scope: 'commerce:send', spend_limit: 25 })
    assert.equal(g.status, 201, JSON.stringify(g.body))
    getDB().prepare(`UPDATE delegations SET spend_limit = 0 WHERE id = ?`).run(g.body.id)
    const c = profileOf(a).active_constraints!
    assert.deepEqual([c.spend_limit, c.spend_unit], [0, null])
    const att = attestationSpendConstraints(profileOf(a)._delegation_for_signal)
    assert.ok('constraints' in att)
    assert.deepEqual(att.constraints, { scopes: ['commerce:send'], spend_limit: 0, spend_used: 0 })
    // Only the properties governance-attestation draft v0.1 allows in active_constraints.
    const allowed = ['scopes', 'spend_limit', 'spend_used', 'spend_currency', 'tool_restrictions', 'max_depth', 'current_depth', 'expires_at']
    assert.deepEqual(Object.keys(att.constraints).filter(k => !allowed.includes(k)), [])
    assert.ok(!('spend_currency' in att.constraints), 'a legacy row has no proven currency')
    const none = attestationSpendConstraints(null)
    assert.ok('constraints' in none)
    assert.deepEqual(none.constraints, { scopes: [], spend_limit: null, spend_used: 0 })
  })
})
