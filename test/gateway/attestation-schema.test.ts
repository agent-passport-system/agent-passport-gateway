// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// The signed governance_attestation from the real server entry, checked against the published
// draft v0.1 JSON Schema and verified with the server's own JWKS, for three delegations: a legacy
// budget, no active delegation, and a unit-declared budget, which must get 422 and no signed claim.
//
// test/fixtures/governance-attestation-v0.1.schema.json is §1.6 of
// agent-passport-system specs/governance-attestation-schema.md at 365f360, copied verbatim.
// Known inconsistency in that draft: §1.2 lists `iss` as a required claim field, but the §1.6 JSON
// Schema does not list it and sets additionalProperties false at the top level. This test follows
// §1.2 for `iss` alone and applies §1.6 strictly to everything else, active_constraints included.
// ══════════════════════════════════════════════════════════════════
import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { spawn, type ChildProcess } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import Database from 'better-sqlite3'
import { compactVerify, importJWK } from 'jose'
import { initDB, getDB } from '../../src/db/schema.js'

const SCHEMA = JSON.parse(readFileSync(new URL('../fixtures/governance-attestation-v0.1.schema.json', import.meta.url), 'utf8'))
const TENANT = 'tnt_attest'

/** The JSON Schema keywords the v0.1 schema uses. Returns a list of errors, empty when valid. */
function validate(schema: any, value: any, path = '$'): string[] {
  const errs: string[] = []
  const typeOf = (v: any) => v === null ? 'null' : Array.isArray(v) ? 'array' : Number.isInteger(v) ? 'integer' : typeof v
  if ('const' in schema && value !== schema.const) errs.push(`${path}: not ${JSON.stringify(schema.const)}`)
  if (schema.type) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type]
    const t = typeOf(value)
    if (!types.some((x: string) => x === t || (x === 'number' && t === 'integer'))) errs.push(`${path}: type ${t}, expected ${types.join('|')}`)
  }
  if (typeof value === 'number') {
    if (schema.minimum !== undefined && value < schema.minimum) errs.push(`${path}: below ${schema.minimum}`)
    if (schema.maximum !== undefined && value > schema.maximum) errs.push(`${path}: above ${schema.maximum}`)
  }
  if (typeof value === 'string') {
    if (schema.pattern && !new RegExp(schema.pattern).test(value)) errs.push(`${path}: does not match ${schema.pattern}`)
    if (schema.format === 'date-time' && !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/.test(value)) errs.push(`${path}: not date-time`)
  }
  if (Array.isArray(value) && schema.items) value.forEach((v, i) => errs.push(...validate(schema.items, v, `${path}[${i}]`)))
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    for (const r of schema.required ?? []) if (!(r in value)) errs.push(`${path}: missing ${r}`)
    for (const [k, v] of Object.entries(value)) {
      if (schema.properties?.[k]) errs.push(...validate(schema.properties[k], v, `${path}.${k}`))
      else if (schema.additionalProperties === false) errs.push(`${path}: property ${k} not allowed`)
    }
  }
  return errs
}

let dir = ''
let child: ChildProcess
let base = ''
let output = ''

before(async () => {
  dir = mkdtempSync(join(tmpdir(), 'attest-'))
  const path = join(dir, 'gw.db')
  initDB(path)
  const db = getDB()
  db.prepare(`INSERT INTO tenants (id, name, email) VALUES (?, 'Attest', 'attest@test.local')`).run(TENANT)
  for (const a of ['root', 'legacy', 'none', 'unit']) {
    db.prepare(`INSERT INTO agents (id, tenant_id, agent_id, public_key, status, is_root) VALUES (?, ?, ?, 'pk', 'active', ?)`).run(`row-${a}`, TENANT, a, a === 'root' ? 1 : 0)
  }
  db.prepare(`INSERT INTO delegations (id, tenant_id, parent_agent_id, child_agent_id, scope, status, spend_limit, spend_used) VALUES ('d-legacy', ?, 'root', 'legacy', 'commerce:send', 'active', 25, 3)`).run(TENANT)
  db.prepare(`INSERT INTO delegations (id, tenant_id, parent_agent_id, child_agent_id, scope, status, spend_limit, spend_used, spend_unit, spend_limit_minor, spend_used_minor) VALUES ('d-unit', ?, 'root', 'unit', 'commerce:send', 'active', 0, 0, 'nano:XNO:raw', '7000000000000000000000000000000', '0')`).run(TENANT)
  db.close()

  const port = String(43_000 + Math.floor(Math.random() * 2000))
  base = `http://127.0.0.1:${port}`
  child = spawn(process.execPath, ['--import', 'tsx', 'src/server.ts'], {
    cwd: process.cwd(),
    env: { ...process.env, DB_PATH: path, PORT: port, NODE_ENV: 'development', NANO_WALLETS_PAUSED: '1' },
  })
  child.stdout!.on('data', d => { output += d })
  child.stderr!.on('data', d => { output += d })
  for (let i = 0; i < 100; i++) {
    try { if ((await fetch(`${base}/healthz`)).ok) return } catch {}
    await new Promise(r => setTimeout(r, 150))
  }
  throw new Error(`server did not start:\n${output.slice(-2000)}`)
})

after(() => {
  child?.kill()
  rmSync(dir, { recursive: true, force: true })
})

async function attestation(agent: string) {
  const r = await fetch(`${base}/api/v1/public/trust/${agent}?signal=governance_attestation`)
  return { status: r.status, body: await r.json() as any }
}

async function verifyEnvelope(body: any) {
  const jwks = await (await fetch(`${base}/.well-known/jwks.json`)).json() as any
  const jwk = jwks.keys.find((k: any) => k.kid === body.kid)
  assert.ok(jwk, 'the envelope kid is in the server JWKS')
  const { payload, protectedHeader } = await compactVerify(body.jws, await importJWK(jwk, 'EdDSA'))
  assert.equal(protectedHeader.alg, 'EdDSA')
  const claim = JSON.parse(new TextDecoder().decode(payload))
  assert.deepEqual(claim, body.signed, 'the signed payload is the claim the envelope shows')
  return claim
}

function schemaErrors(claim: any): string[] {
  const { iss, ...rest } = claim
  assert.equal(typeof iss, 'string', '§1.2 requires iss')
  return validate(SCHEMA, rest)
}

describe('governance_attestation against draft v0.1', () => {
  it('a legacy budget: signature verifies, the claim validates, no currency is asserted', async () => {
    const { status, body } = await attestation('legacy')
    assert.equal(status, 200, JSON.stringify(body))
    const claim = await verifyEnvelope(body)
    assert.deepEqual(schemaErrors(claim), [])
    assert.deepEqual(claim.active_constraints, { scopes: ['commerce:send'], spend_limit: 25, spend_used: 3 })
  })

  it('no active delegation: signature verifies, the claim validates, empty constraints with no currency', async () => {
    const { status, body } = await attestation('none')
    assert.equal(status, 200, JSON.stringify(body))
    const claim = await verifyEnvelope(body)
    assert.deepEqual(schemaErrors(claim), [])
    assert.deepEqual(claim.active_constraints, { scopes: [], spend_limit: null, spend_used: 0 })
  })

  it('a unit-declared budget: 422, and nothing signed', async () => {
    const { status, body } = await attestation('unit')
    assert.equal(status, 422)
    assert.equal(body.error, 'attestation_unavailable')
    assert.equal(body.jws, undefined)
    assert.equal(body.signed, undefined)
  })

  it('the validator itself rejects what the old claims carried', () => {
    const ok = { signal_type: 'governance_attestation', delegation_chain_hash: 'a'.repeat(64), evaluation_timestamp: '2026-11-11T00:00:00Z' }
    assert.deepEqual(validate(SCHEMA, { ...ok, active_constraints: { scopes: [], spend_used: 0 } }), [])
    assert.notDeepEqual(validate(SCHEMA, { ...ok, active_constraints: { scopes: [], spend_used: 0, spend_unit: null } }), [])
    assert.notDeepEqual(validate(SCHEMA, { ...ok, active_constraints: { scopes: [], spend_used: 0, spend_currency: null } }), [])
    assert.notDeepEqual(validate(SCHEMA, { ...ok, active_constraints: { scopes: [], spend_used: 0, spend_limit_minor: '1' } }), [])
  })
})
