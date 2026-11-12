// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// delegation_chain_hash has one implementation. The signed governance_attestation used to keep
// null-valued keys while the decision record dropped them, so a chain with an unlimited link got
// two hashes. These vectors are the ones published in governance-attestation-schema.md §2.3.

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { initDB, getDB } from '../../src/db/schema.js'
import { canonicalChainJson, chainHash, resolveDelegationChain, computeDelegationChainHash } from '../../src/gateway/delegation-chain-hash.js'

const TENANT = 'tnt_chainhash'
const EMPTY = '4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945'
const LIMITED = '79cb50af244bbb9b9e16b2dc197b55f0c6327f27abea13aff6cd42bd5194387c'
const UNLIMITED = '9e0195d7a96d5f7d6a8efe78657c74fb8824755ec607784205a47915af83113d'

describe('canonical chain input', () => {
  it('sorts keys and drops null-valued keys', () => {
    assert.equal(canonicalChainJson([{ spend_limit: null, scope: 'read:docs', parent: 'root', child: 'a' }]),
      '[{"child":"a","parent":"root","scope":"read:docs"}]')
  })
  it('matches the published test vectors', () => {
    assert.equal(chainHash([]), EMPTY)
    assert.equal(chainHash([{ parent: 'root', child: 'a', scope: 'read:docs', spend_limit: 5 }]), LIMITED)
    assert.equal(chainHash([{ parent: 'root', child: 'a', scope: 'read:docs', spend_limit: null }]), UNLIMITED)
  })
})

describe('chain resolution from the delegations table', () => {
  before(() => {
    initDB(':memory:')
    const db = getDB()
    db.prepare(`INSERT OR IGNORE INTO tenants (id, name, email) VALUES (?, ?, ?)`).run(TENANT, 'Chain', 'c@test.local')
    const ins = db.prepare(`INSERT INTO delegations (id, tenant_id, parent_agent_id, child_agent_id, scope, spend_limit, status, created_at) VALUES (?, ?, ?, ?, ?, ?, 'active', ?)`)
    ins.run('d1', TENANT, 'root', 'a', 'read:docs', null, '2026-01-01 00:00:00')
    ins.run('d2', TENANT, 'a', 'b', 'read:docs', 5, '2026-01-01 00:00:01')
  })
  it('walks root first and keeps a null limit as null in the resolved links', () => {
    assert.deepEqual(resolveDelegationChain(getDB(), TENANT, 'b'), [
      { parent: 'root', child: 'a', scope: 'read:docs', spend_limit: null },
      { parent: 'a', child: 'b', scope: 'read:docs', spend_limit: 5 },
    ])
  })
  it('hashes an unlimited single link to the published vector, and no chain to the empty vector', () => {
    assert.equal(computeDelegationChainHash(getDB(), TENANT, 'a'), UNLIMITED)
    assert.equal(computeDelegationChainHash(getDB(), TENANT, 'nobody'), EMPTY)
  })
})

describe('every emitter uses the shared implementation', () => {
  const src = (p: string) => readFileSync(new URL(`../../src/${p}`, import.meta.url), 'utf8')
  it('the attestation endpoint and the decision record both import it and hash no chain of their own', () => {
    for (const f of ['server.ts', 'gateway/enforce.ts']) {
      const s = src(f)
      assert.match(s, /import \{ computeDelegationChainHash \} from '\.\/(gateway\/)?delegation-chain-hash\.js'/, f)
      assert.doesNotMatch(s, /canonicalJsonStringify\(chain\)/, f)
    }
  })
})
