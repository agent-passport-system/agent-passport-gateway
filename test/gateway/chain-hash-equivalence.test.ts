// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// End to end: for the same delegation chain, the signed governance_attestation from the real
// server entry and the signed decision record from /audit-packet carry the same
// delegation_chain_hash. Covers a limited link, an unlimited link and a two-link chain, and records
// how the empty chain differs. Also pins the /evaluate verdicts the records come from.
//
// Deliberately imports nothing from src/gateway/delegation-chain-hash.ts, so the same file runs
// against the commit before the fix and fails there on the unlimited cases.

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { spawn, type ChildProcess } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import express from 'express'
import type { Server } from 'node:http'
import { compactVerify, importJWK } from 'jose'
import { initDB, getDB } from '../../src/db/schema.js'
import { initGatewayIdentity } from '../../src/gateway/identity.js'
import { gatewayRouter } from '../../src/gateway/enforce.js'

const TENANT = 'tnt_chain_eq'
let dir = '', child: ChildProcess, pub = '', priv = '', output = ''
let server: Server

const post = async (p: string, b: unknown) => {
  const r = await fetch(`${priv}${p}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b) })
  return { status: r.status, body: await r.json() as any }
}
const getJson = async (url: string) => { const r = await fetch(url); return { status: r.status, body: await r.json() as any } }

before(async () => {
  dir = mkdtempSync(join(tmpdir(), 'chain-eq-'))
  const path = join(dir, 'gw.db')
  initDB(path)
  initGatewayIdentity()
  const db = getDB()
  db.prepare(`INSERT INTO tenants (id, name, email) VALUES (?, 'ChainEq', 'eq@test.local')`).run(TENANT)
  for (const a of ['root', 'lim', 'unl', 'mid', 'leaf', 'none']) {
    db.prepare(`INSERT INTO agents (id, tenant_id, agent_id, public_key, status, is_root) VALUES (?, ?, ?, 'pk', 'active', ?)`).run(`row-${a}`, TENANT, a, a === 'root' ? 1 : 0)
  }
  const app = express()
  app.use(express.json())
  app.use((req: any, _res, next) => { req.tenant = { id: TENANT, role: 'user', plan: 'enterprise' }; next() })
  app.use('/api/v1', gatewayRouter)
  await new Promise<void>((resolve) => { server = app.listen(0, () => { const a = server.address(); priv = `http://127.0.0.1:${typeof a === 'object' && a ? a.port : 0}/api/v1`; resolve() }) })

  for (const g of [
    { parent_agent_id: 'root', child_agent_id: 'lim', scope: 'data:read', spend_limit: 5 },
    { parent_agent_id: 'root', child_agent_id: 'unl', scope: 'data:read' },
    { parent_agent_id: 'root', child_agent_id: 'mid', scope: 'data:read' },
    { parent_agent_id: 'mid', child_agent_id: 'leaf', scope: 'data:read', spend_limit: 5 },
  ]) {
    const r = await post('/delegations', g)
    assert.equal(r.status, 201, JSON.stringify(r.body))
  }

  const port = String(45_000 + Math.floor(Math.random() * 2000))
  pub = `http://127.0.0.1:${port}`
  child = spawn(process.execPath, ['--import', 'tsx', 'src/server.ts'], {
    cwd: process.cwd(),
    env: { ...process.env, DB_PATH: path, PORT: port, NODE_ENV: 'development', NANO_WALLETS_PAUSED: '1', NANO_RAIL_DISABLED: '1' },
  })
  child.stdout!.on('data', d => { output += d })
  child.stderr!.on('data', d => { output += d })
  for (let i = 0; i < 100; i++) {
    try { if ((await fetch(`${pub}/healthz`)).ok) return } catch {}
    await new Promise(r => setTimeout(r, 150))
  }
  throw new Error(`server did not start:\n${output.slice(-2000)}`)
})

after(() => {
  child?.kill()
  server?.close()
  rmSync(dir, { recursive: true, force: true })
})

/** delegation_chain_hash from the signed attestation payload, after verifying the JWS with the server JWKS. */
async function attestedHash(agent: string): Promise<string> {
  const { status, body } = await getJson(`${pub}/api/v1/public/trust/${agent}?signal=governance_attestation`)
  assert.equal(status, 200, JSON.stringify(body))
  const jwks = (await getJson(`${pub}/.well-known/jwks.json`)).body
  const jwk = jwks.keys.find((k: any) => k.kid === body.kid)
  const { payload } = await compactVerify(body.jws, await importJWK(jwk, 'EdDSA'))
  return JSON.parse(new TextDecoder().decode(payload)).delegation_chain_hash
}

/** Runs /evaluate for the agent and returns the verdict and the decision record's delegation_chain_hash. */
async function decided(agent: string, scope: string): Promise<{ verdict: string; hash: string | null }> {
  const ev = await post('/evaluate', { agent_id: agent, action_type: scope, scope_required: scope })
  assert.equal(ev.status, 200, JSON.stringify(ev.body))
  const row = getDB().prepare(`SELECT id FROM evaluation_receipts WHERE tenant_id = ? AND agent_id = ? ORDER BY id DESC LIMIT 1`).get(TENANT, agent) as any
  assert.ok(row, 'the evaluation left a receipt')
  const pkt = await fetch(`${priv}/audit-packet/${row.id}?format=json`)
  const body = await pkt.json() as any
  assert.equal(pkt.status, 200, JSON.stringify(body))
  return { verdict: ev.body.verdict, hash: body.decision_record?.delegation_chain_hash ?? null }
}

describe('delegation_chain_hash agrees between the attestation and the decision record', () => {
  for (const [label, agent] of [['a limited link', 'lim'], ['an unlimited link', 'unl'], ['a two-link chain with an unlimited root link', 'leaf']] as const) {
    it(`${label}: same hash, and the in-scope action is permitted`, async () => {
      const d = await decided(agent, 'data:read')
      assert.equal(d.verdict, 'permit')
      assert.match(String(d.hash), /^[0-9a-f]{64}$/)
      assert.equal(await attestedHash(agent), d.hash)
    })
  }

  it('the unlimited single link hashes to the published §2.3 vector shape', async () => {
    // The vector in the spec uses parent "root", child "a", scope "read:docs". Here the child is
    // "unl" and the scope "data:read", so check the rule rather than the literal: no spend_limit key.
    const { createHash } = await import('node:crypto')
    const expected = createHash('sha256').update('[{"child":"unl","parent":"root","scope":"data:read"}]').digest('hex')
    assert.equal(await attestedHash('unl'), expected)
  })

  it('an out-of-scope action is still denied', async () => {
    const d = await decided('lim', 'admin:write')
    assert.equal(d.verdict, 'deny')
  })

  it('no delegation: the attestation hashes the empty chain, and the decision record carries no hash', async () => {
    const { createHash } = await import('node:crypto')
    assert.equal(await attestedHash('none'), createHash('sha256').update('[]').digest('hex'))
    const d = await decided('none', 'data:read')
    assert.equal(d.verdict, 'deny')
    assert.equal(d.hash, null)
  })
})
