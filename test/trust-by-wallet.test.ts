// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Integration tests for /api/v1/public/trust/by-wallet/:address
// and the path-form fall-through on /api/v1/public/trust/:value.
//
// Spins up a self-contained Express app on a random port with an
// in-memory SQLite DB seeded with the aeoess-bound-demo fixture, then
// fires real fetch requests against it.

import { describe, it, before, after, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import express from 'express'
import Database from 'better-sqlite3'
import type { Server } from 'node:http'
import {
  recordBoundWallets,
  rebuildFromDb,
  lookupByAddress,
  clearReverseIndex,
} from '../src/gateway/wallet-reverse-index.js'
import { buildAgentTrustProfile, publicizeProfile } from '../src/gateway/trust-profile.js'

const ETH_A = '0x1234567890abcdef1234567890abcdef12345678'
const BASE_A = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
const UNKNOWN_ADDR = '0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead'
const FIXTURE_AGENT_ID = 'aeoess-bound-demo'
const TENANT_ID = 'tenant-test'

// Self-contained DB seeded with everything buildAgentTrustProfile reads
function seedDb(): Database.Database {
  const db = new Database(':memory:')
  db.exec(`
    CREATE TABLE tenants (id TEXT PRIMARY KEY);
    CREATE TABLE agents (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      agent_id TEXT NOT NULL,
      public_key TEXT NOT NULL,
      did TEXT,
      name TEXT,
      status TEXT NOT NULL DEFAULT 'active',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      metadata TEXT,
      UNIQUE(tenant_id, agent_id)
    );
    CREATE TABLE delegations (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      parent_agent_id TEXT NOT NULL,
      child_agent_id TEXT NOT NULL,
      scope TEXT NOT NULL,
      spend_limit REAL,
      spend_unit TEXT,
      spend_limit_minor TEXT,
      spend_used_minor TEXT,
      spend_used REAL DEFAULT 0,
      max_depth INTEGER DEFAULT 3,
      status TEXT NOT NULL DEFAULT 'active',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      revoked_at TEXT
    );
    CREATE TABLE policy_evaluations (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      agent_id TEXT NOT NULL,
      verdict TEXT NOT NULL,
      task_class TEXT DEFAULT '',
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE TABLE receipts (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      agent_id TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE TABLE issuance_dossiers (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      passport_id TEXT NOT NULL,
      passport_grade INTEGER,
      attestation_bundle_hash TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE TABLE agent_wallets (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      agent_id TEXT NOT NULL,
      nano_address TEXT,
      status TEXT
    );
    CREATE TABLE key_rotations (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      agent_id TEXT NOT NULL,
      mode TEXT,
      state TEXT,
      old_key TEXT,
      new_key TEXT,
      activation_time TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      completed_at TEXT
    );
    INSERT INTO tenants (id) VALUES ('${TENANT_ID}');
  `)
  // The aeoess-bound-demo fixture: an agent with two structural bindings
  // (ethereum + base) plus a Nano payment wallet.
  const metadata = JSON.stringify({
    bound_wallets: [
      { chain: 'ethereum', address: ETH_A, bound_at: '2026-04-10T00:00:00Z', binding_signature: 'fixture-eth-sig' },
      { chain: 'base', address: BASE_A, bound_at: '2026-04-10T00:00:00Z', binding_signature: 'fixture-base-sig' },
    ],
  })
  db.prepare(
    `INSERT INTO agents (id, tenant_id, agent_id, public_key, did, name, status, metadata) VALUES (?, ?, ?, ?, ?, ?, 'active', ?)`
  ).run(
    'uuid-aeoess-bound-demo',
    TENANT_ID,
    FIXTURE_AGENT_ID,
    '1ef065d8717910ffaba4416a134ad3ff93acc85e541450c461bd0c4a632befde',
    'did:aps:aeoess-bound-demo',
    'Aeoess Bound Demo',
    metadata,
  )
  return db
}

// Stub continuity scoring — the real one lives in server.ts
function stubContinuityScore() {
  return { score: 100, context_break: false, signals: [] }
}

// Build the same routes as server.ts mounts for /public/trust.
// Two endpoints under test:
//   GET /api/v1/public/trust/:agentId       (with path-form fall-through)
//   GET /api/v1/public/trust/by-wallet/:address
function makeApp(db: Database.Database) {
  const app = express()
  app.set('trust proxy', true)

  app.get('/api/v1/public/trust/by-wallet/:address', (req, res) => {
    const rawAddress = (req.params.address || '').trim()
    if (!/^0x[a-fA-F0-9]{40}$/.test(rawAddress)) {
      return res.status(400).json({ error: 'Invalid address format', hint: 'Expected 0x followed by 40 hex characters' })
    }
    const hit = lookupByAddress(rawAddress)
    if (!hit) {
      return res.json({ found: false, reason: 'no_wallet_binding', queried_address: rawAddress, queried_at: new Date().toISOString() })
    }
    const agent = db.prepare(
      `SELECT * FROM agents WHERE tenant_id = ? AND agent_id = ? AND status = 'active' LIMIT 1`
    ).get(hit.tenant_id, hit.agent_id) as any
    if (!agent) {
      return res.json({ found: false, reason: 'no_wallet_binding', queried_address: rawAddress, queried_at: new Date().toISOString() })
    }
    const profile = buildAgentTrustProfile({
      db, agent, agentId: hit.agent_id,
      matchedWalletEntry: hit.entry,
      computeContinuityScore: stubContinuityScore,
    })
    return res.json(publicizeProfile(profile))
  })

  app.get('/api/v1/public/trust/:agentId', (req, res) => {
    let { agentId } = req.params
    let agent = db.prepare(
      `SELECT * FROM agents WHERE agent_id = ? AND status = 'active' ORDER BY created_at ASC LIMIT 1`
    ).get(agentId) as any

    let matchedFromFallthrough: any
    if (!agent && /^0x[a-fA-F0-9]{40}$/.test(agentId)) {
      const hit = lookupByAddress(agentId)
      if (hit) {
        const fetched = db.prepare(
          `SELECT * FROM agents WHERE tenant_id = ? AND agent_id = ? AND status = 'active' LIMIT 1`
        ).get(hit.tenant_id, hit.agent_id) as any
        if (fetched) {
          agent = fetched
          agentId = hit.agent_id
          matchedFromFallthrough = hit.entry
        }
      }
    }

    if (!agent) {
      return res.json({ agent_id: agentId, grade: 0, grade_label: 'unknown', found: false, queried_at: new Date().toISOString() })
    }
    const profile = buildAgentTrustProfile({
      db, agent, agentId,
      matchedWalletEntry: matchedFromFallthrough,
      computeContinuityScore: stubContinuityScore,
    })
    return res.json(publicizeProfile(profile))
  })

  return app
}

let server: Server
let baseUrl: string
let db: Database.Database

before(async () => {
  db = seedDb()
  clearReverseIndex()
  rebuildFromDb(db)
  const app = makeApp(db)
  await new Promise<void>((resolve) => {
    server = app.listen(0, () => {
      const addr = server.address()
      const port = typeof addr === 'object' && addr ? addr.port : 0
      baseUrl = `http://127.0.0.1:${port}`
      resolve()
    })
  })
})

after(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()))
  db.close()
})

beforeEach(() => {
  // Each test re-seeds the index from the in-memory DB so cross-test
  // mutations don't leak. Re-record the fixture.
  clearReverseIndex()
  rebuildFromDb(db)
})

describe('GET /api/v1/public/trust/by-wallet/:address — happy path', () => {
  it('returns the bound agent envelope when the address matches (ethereum)', async () => {
    const r = await fetch(`${baseUrl}/api/v1/public/trust/by-wallet/${ETH_A}`)
    assert.equal(r.status, 200)
    const body = await r.json() as any
    assert.equal(body.found, true)
    assert.equal(body.agent_id, FIXTURE_AGENT_ID)
    assert.ok(Array.isArray(body.wallet_ref))
    assert.equal(body.wallet_ref.length, 2)
    assert.ok(body.matched_wallet)
    assert.equal(body.matched_wallet.chain, 'ethereum')
    assert.equal(body.matched_wallet.address, ETH_A)
    assert.equal(body.matched_wallet.binding_sig, 'fixture-eth-sig')
  })

  it('returns the bound agent envelope when the address matches (base)', async () => {
    const r = await fetch(`${baseUrl}/api/v1/public/trust/by-wallet/${BASE_A}`)
    assert.equal(r.status, 200)
    const body = await r.json() as any
    assert.equal(body.found, true)
    assert.equal(body.agent_id, FIXTURE_AGENT_ID)
    assert.equal(body.matched_wallet.chain, 'base')
  })

  it('case-insensitive: uppercase address resolves to the same agent', async () => {
    const r = await fetch(`${baseUrl}/api/v1/public/trust/by-wallet/${ETH_A.toUpperCase().replace(/^0X/, '0x')}`)
    assert.equal(r.status, 200)
    const body = await r.json() as any
    assert.equal(body.found, true)
    assert.equal(body.agent_id, FIXTURE_AGENT_ID)
  })

  it('does not require auth (200 not 401, no Authorization header sent)', async () => {
    const r = await fetch(`${baseUrl}/api/v1/public/trust/by-wallet/${ETH_A}`, {
      // intentionally no headers
    })
    assert.notEqual(r.status, 401)
    assert.equal(r.status, 200)
  })

  it('strips internal _-prefixed fields from the wire payload', async () => {
    const r = await fetch(`${baseUrl}/api/v1/public/trust/by-wallet/${ETH_A}`)
    const body = await r.json() as any
    for (const key of Object.keys(body)) {
      assert.ok(!key.startsWith('_'), `internal field leaked: ${key}`)
    }
  })
})

describe('GET /api/v1/public/trust/by-wallet/:address — miss + invalid', () => {
  it('returns uniform { found: false } shape for unknown address', async () => {
    const r = await fetch(`${baseUrl}/api/v1/public/trust/by-wallet/${UNKNOWN_ADDR}`)
    assert.equal(r.status, 200)
    const body = await r.json() as any
    assert.equal(body.found, false)
    assert.equal(body.reason, 'no_wallet_binding')
    assert.equal(body.queried_address, UNKNOWN_ADDR)
    // Must not leak agent_id or any binding info
    assert.equal(body.agent_id, undefined)
    assert.equal(body.wallet_ref, undefined)
  })

  it('rejects malformed addresses with 400', async () => {
    const cases = ['notanaddress', '0xshort', 'aeoess-bound-demo', '0x123']
    for (const c of cases) {
      const r = await fetch(`${baseUrl}/api/v1/public/trust/by-wallet/${encodeURIComponent(c)}`)
      assert.equal(r.status, 400, `should reject "${c}"`)
    }
  })
})

describe('GET /api/v1/public/trust/:agentId — path-form fall-through', () => {
  it('falls through to wallet lookup when :value is a 0x address with no agent_id match', async () => {
    const r = await fetch(`${baseUrl}/api/v1/public/trust/${ETH_A}`)
    assert.equal(r.status, 200)
    const body = await r.json() as any
    assert.equal(body.found, true)
    assert.equal(body.agent_id, FIXTURE_AGENT_ID)
    assert.ok(body.matched_wallet)
    assert.equal(body.matched_wallet.address, ETH_A)
  })

  it('does not fall through when an agent_id matches even if it starts with 0x', async () => {
    // Insert an agent whose agent_id literally starts with 0x but is NOT
    // a 40-char hex address. The handler should resolve it as agent_id.
    db.prepare(`INSERT INTO agents (id, tenant_id, agent_id, public_key, status, metadata) VALUES (?, ?, ?, ?, 'active', ?)`)
      .run('uuid-agent-0xnamed', TENANT_ID, '0xnamed-agent', 'pk', null)
    const r = await fetch(`${baseUrl}/api/v1/public/trust/${encodeURIComponent('0xnamed-agent')}`)
    assert.equal(r.status, 200)
    const body = await r.json() as any
    assert.equal(body.found, true)
    assert.equal(body.agent_id, '0xnamed-agent')
    // Cleanup so other tests don't see this row
    db.prepare(`DELETE FROM agents WHERE id = ?`).run('uuid-agent-0xnamed')
  })

  it('agent-id-shaped 0x address that matches a real agent_id wins over wallet lookup', async () => {
    // Edge case: an address-shaped agent_id that ALSO happens to be a
    // bound wallet address on a different agent. The agent_id match wins
    // because it's checked first; fall-through only fires on a miss.
    const COLLIDING = '0x9999999999999999999999999999999999999999'
    db.prepare(`INSERT INTO agents (id, tenant_id, agent_id, public_key, status, metadata) VALUES (?, ?, ?, ?, 'active', ?)`)
      .run('uuid-collide', TENANT_ID, COLLIDING, 'pk-collide', null)

    // Bind the same address to the fixture agent in the index
    recordBoundWallets({
      tenant_id: TENANT_ID,
      agent_id: FIXTURE_AGENT_ID,
      bound_wallets: [{ chain: 'ethereum', address: COLLIDING, binding_signature: 'collide-sig' }],
    })

    const r = await fetch(`${baseUrl}/api/v1/public/trust/${COLLIDING}`)
    const body = await r.json() as any
    assert.equal(body.found, true)
    assert.equal(body.agent_id, COLLIDING, 'agent_id match wins; fall-through only fires on miss')

    // Cleanup
    db.prepare(`DELETE FROM agents WHERE id = ?`).run('uuid-collide')
    clearReverseIndex()
    rebuildFromDb(db)
  })

  it('returns existing 404-style { found: false } shape when neither agent_id nor wallet match', async () => {
    const r = await fetch(`${baseUrl}/api/v1/public/trust/${UNKNOWN_ADDR}`)
    assert.equal(r.status, 200)
    const body = await r.json() as any
    assert.equal(body.found, false)
    assert.equal(body.grade, 0)
  })
})

describe('Trust profile emission — Solana wallet_ref preservation', () => {
  it('preserves chain="solana" and address verbatim in wallet_ref', () => {
    const SOL_ADDR = 'DRiP2Pn2K6fuMLKQmt5rZWxa91GPqgT4gJZN6fyUoF3z'
    const localDb = new Database(':memory:')
    localDb.exec(`
      CREATE TABLE tenants (id TEXT PRIMARY KEY);
      CREATE TABLE agents (
        id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, agent_id TEXT NOT NULL,
        public_key TEXT NOT NULL, did TEXT, name TEXT,
        status TEXT NOT NULL DEFAULT 'active',
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        metadata TEXT, UNIQUE(tenant_id, agent_id)
      );
      CREATE TABLE delegations (id TEXT PRIMARY KEY, tenant_id TEXT, parent_agent_id TEXT, child_agent_id TEXT, scope TEXT, spend_limit REAL, spend_used REAL DEFAULT 0, spend_unit TEXT, spend_limit_minor TEXT, spend_used_minor TEXT, max_depth INTEGER DEFAULT 3, status TEXT DEFAULT 'active', created_at TEXT DEFAULT (datetime('now')), revoked_at TEXT);
      CREATE TABLE policy_evaluations (id TEXT PRIMARY KEY, tenant_id TEXT, agent_id TEXT, verdict TEXT, task_class TEXT DEFAULT '', created_at TEXT DEFAULT (datetime('now')));
      CREATE TABLE receipts (id TEXT PRIMARY KEY, tenant_id TEXT, agent_id TEXT, created_at TEXT DEFAULT (datetime('now')));
      CREATE TABLE issuance_dossiers (id TEXT PRIMARY KEY, tenant_id TEXT, passport_id TEXT, passport_grade INTEGER, attestation_bundle_hash TEXT, created_at TEXT DEFAULT (datetime('now')));
      CREATE TABLE agent_wallets (id TEXT PRIMARY KEY, tenant_id TEXT, agent_id TEXT, nano_address TEXT, status TEXT);
      CREATE TABLE key_rotations (id TEXT PRIMARY KEY, tenant_id TEXT, agent_id TEXT, mode TEXT, state TEXT, old_key TEXT, new_key TEXT, activation_time TEXT, created_at TEXT DEFAULT (datetime('now')), completed_at TEXT);
      INSERT INTO tenants (id) VALUES ('tenant-sol');
    `)
    localDb.prepare(
      `INSERT INTO agents (id, tenant_id, agent_id, public_key, did, name, status, metadata) VALUES (?, ?, ?, ?, ?, ?, 'active', ?)`
    ).run(
      'uuid-sol-emit', 'tenant-sol', 'solana-emit-agent',
      '1ef065d8717910ffaba4416a134ad3ff93acc85e541450c461bd0c4a632befde',
      'did:aps:solana-emit-agent', 'Solana Emit',
      JSON.stringify({
        bound_wallets: [
          { chain: 'solana', address: SOL_ADDR, bound_at: '2026-04-15T09:00:00Z', binding_signature: 'sol-sig-fixture' },
        ],
      }),
    )
    const agent = localDb.prepare(`SELECT * FROM agents WHERE agent_id = ?`).get('solana-emit-agent') as any
    const profile = buildAgentTrustProfile({
      db: localDb, agent, agentId: 'solana-emit-agent',
      computeContinuityScore: stubContinuityScore,
    })
    assert.equal(profile.wallet_ref.length, 1)
    const sol = profile.wallet_ref[0]
    assert.equal(sol.chain, 'solana')
    assert.equal(sol.address, SOL_ADDR, 'Solana address must pass through character-for-character')
    assert.equal(sol.binding_sig, 'sol-sig-fixture')
    assert.equal(sol.bound_at, '2026-04-15T09:00:00Z')
    localDb.close()
  })
})

describe('Direct profile build via buildAgentTrustProfile', () => {
  it('matches the by-wallet HTTP shape when called directly', () => {
    const agent = db.prepare(
      `SELECT * FROM agents WHERE tenant_id = ? AND agent_id = ?`
    ).get(TENANT_ID, FIXTURE_AGENT_ID) as any

    const profile = buildAgentTrustProfile({
      db, agent, agentId: FIXTURE_AGENT_ID,
      matchedWalletEntry: { chain: 'ethereum', address: ETH_A, bound_at: '2026-04-10T00:00:00Z', binding_sig: 'fixture-eth-sig' },
      computeContinuityScore: stubContinuityScore,
    })
    assert.equal(profile.found, true)
    assert.equal(profile.agent_id, FIXTURE_AGENT_ID)
    assert.equal(profile.wallet_ref.length, 2)
    assert.equal(profile.matched_wallet?.address, ETH_A)
    assert.equal(profile.wallet_address, ETH_A)
    assert.equal(profile.wallet_chain, 'ethereum')
  })
})
