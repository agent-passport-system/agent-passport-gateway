// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Day 268: the spend-unit columns are required, not best effort. ensureSpendUnitColumns adds only
// what is missing and throws if a column cannot be added. initDB does not catch it, and the server
// calls initDB before it listens, so a failed migration stops startup instead of serving requests
// against an incomplete schema. The other ALTERs in schema.ts keep their old try/catch.
// ══════════════════════════════════════════════════════════════════
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import Database from 'better-sqlite3'
import { spawn } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { ensureSpendUnitColumns, SPEND_UNIT_COLUMNS } from '../../src/db/schema.js'

const cols = (db: Database.Database) => (db.prepare(`PRAGMA table_info(delegations)`).all() as any[]).map(c => c.name)

describe('ensureSpendUnitColumns', () => {
  it('adds only the missing columns, leaves existing rows alone and is idempotent', () => {
    const db = new Database(':memory:')
    db.exec(`CREATE TABLE delegations (id TEXT PRIMARY KEY, spend_limit REAL, spend_unit TEXT)`)
    db.prepare(`INSERT INTO delegations (id, spend_limit, spend_unit) VALUES ('d1', 5, NULL)`).run()
    ensureSpendUnitColumns(db)
    for (const c of SPEND_UNIT_COLUMNS) assert.ok(cols(db).includes(c), c)
    ensureSpendUnitColumns(db)
    assert.equal(cols(db).length, 5)
    assert.deepEqual(db.prepare(`SELECT id, spend_limit, spend_unit, spend_limit_minor, spend_used_minor FROM delegations`).get(),
      { id: 'd1', spend_limit: 5, spend_unit: null, spend_limit_minor: null, spend_used_minor: null })
  })

  it('throws, naming the column, when a column cannot be added', () => {
    const db = new Database(':memory:')
    db.exec(`CREATE TABLE real_delegations (id TEXT PRIMARY KEY)`)
    db.exec(`CREATE VIEW delegations AS SELECT * FROM real_delegations`)
    assert.throws(() => ensureSpendUnitColumns(db), /could not add delegations\.spend_unit/)
  })
})

describe('the server does not start when the spend-unit columns cannot be added', () => {
  it('exits non-zero with the migration error and never listens', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'units-start-'))
    // Test-side injection only: make exactly the three spend-unit ALTERs throw, then load the real
    // server entry. Production code is unchanged.
    const pre = `const D = (await import('better-sqlite3')).default; const ex = D.prototype.exec; ` +
      `D.prototype.exec = function (sql) { if (/ALTER TABLE delegations ADD COLUMN spend_/.test(String(sql))) throw new Error('injected ALTER failure'); return ex.call(this, sql) };`
    const child = spawn(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', `${pre} await import('./src/server.ts')`], {
      cwd: process.cwd(),
      env: { ...process.env, DB_PATH: join(dir, 'start.db'), PORT: '0', NODE_ENV: 'development' },
    })
    let out = ''
    child.stdout.on('data', d => { out += d })
    child.stderr.on('data', d => { out += d })
    const code = await new Promise<number | null>((resolve) => {
      const t = setTimeout(() => { child.kill(); resolve(null) }, 20_000)
      child.on('exit', c => { clearTimeout(t); resolve(c) })
    })
    rmSync(dir, { recursive: true, force: true })
    assert.notEqual(code, null, 'the server kept running with an incomplete schema')
    assert.notEqual(code, 0)
    assert.match(out, /\[migration\] could not add delegations\.spend_unit: injected ALTER failure/)
    assert.doesNotMatch(out, /Listening on/)
  })
})
