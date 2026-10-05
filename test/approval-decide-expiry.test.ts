// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Request expiry racing a decide.
//
// /decide reads the clock before decideRequest takes its IMMEDIATE
// transaction. That transaction can wait for another writer on the same
// SQLite file, and the checks inside it take time too. decideRequest reads
// a fresh server clock after those checks, immediately before the UPDATE,
// so:
//
//   - a decide that starts before expiry, waits on another writer's lock
//     and gets it after expiry, is refused: 409 'Request has expired', the
//     row stays pending, no receipt. Before this change it compared expiry
//     with the time from before the wait, returned 200 and stored approved.
//   - expiry passing while the in-transaction checks run is refused the
//     same way, so a clock read at the start of the transaction would not
//     be enough.
//   - a decide well inside the window approves, and decided_at equals the
//     receipt's issued_at.

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { unlinkSync } from 'node:fs'
import { spawn } from 'node:child_process'
import { createRequire } from 'node:module'
import { randomUUID } from 'node:crypto'
import type { Server } from 'node:http'
import express from 'express'
import { generateKeyPair, sign as edSign } from 'agent-passport-system'
import { initDB, getDB } from '../src/db/schema.js'
import { initGatewayIdentity } from '../src/gateway/identity.js'
import { approvalRouter } from '../src/gateway/approval/index.js'
import { setApprovalConnectorRouter } from '../src/gateway/approval/connector.js'
import { registerApprover } from '../src/gateway/approval/approvers.js'
import { approvalCommitment } from '../src/gateway/approval/commitment.js'
import { getRequest, decideRequest } from '../src/gateway/approval/store.js'

const TENANT = 'tenant-expiry'
const AGENT = 'agent-expiry'
const SQLITE_MODULE = createRequire(import.meta.url).resolve('better-sqlite3')
let dbPath: string
let server: Server
let baseUrl: string

before(async () => {
  dbPath = join(tmpdir(), `aeoess-decide-expiry-${randomUUID()}.db`)
  initDB(dbPath)
  initGatewayIdentity()
  setApprovalConnectorRouter({
    async route(channel) {
      return { channel, sent: false, queued: true, transport: 'email_interim', routedAt: new Date().toISOString() }
    },
  })
  getDB().prepare(`INSERT INTO tenants (id, name, email) VALUES (?, ?, ?)`).run(TENANT, 'expiry', 'expiry@test.local')
  getDB().prepare(`INSERT INTO agents (id, tenant_id, agent_id, public_key, status, entity_id) VALUES (?, ?, ?, ?, 'active', ?)`)
    .run(randomUUID(), TENANT, AGENT, generateKeyPair().publicKey, 'owner-expiry')
  const app = express()
  app.use(express.json())
  app.use((req: any, _res, next) => { req.tenant = { id: TENANT, role: 'user', key_class: 'runtime', key_id: 'key-expiry' }; next() })
  app.use('/api/v1', approvalRouter)
  await new Promise<void>((r) => {
    server = app.listen(0, '127.0.0.1', () => {
      baseUrl = `http://127.0.0.1:${(server.address() as any).port}/api/v1`
      r()
    })
  })
})

after(() => {
  server?.close()
  try { getDB().close() } catch {}
  for (const f of [dbPath, `${dbPath}-wal`, `${dbPath}-shm`]) { try { unlinkSync(f) } catch {} }
})

async function call(method: string, path: string, body?: unknown) {
  const r = await fetch(`${baseUrl}${path}`, {
    method, headers: { 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  let json: any = null
  try { json = await r.json() } catch { json = null }
  return { status: r.status, json }
}

/** An open request with one accepted signature from a registered approver. */
async function signedRequest(ttlSeconds?: number): Promise<{ id: string; expiry: number }> {
  const approverId = `ap-${randomUUID().slice(0, 8)}`
  const kp = generateKeyPair()
  registerApprover({
    tenantId: TENANT, approverId, publicKey: kp.publicKey, authority: ['payments:*'],
    principalId: `p-${approverId}`, registeredBy: 'test',
  })
  const opened = await call('POST', '/approvals', {
    action_class: 'payments:transfer', subject: `inv-${randomUUID()}`, agent_id: AGENT, requested_by: 'r',
    ...(ttlSeconds === undefined ? {} : { ttl_seconds: ttlSeconds }),
  })
  assert.equal(opened.status, 201, JSON.stringify(opened.json))
  const id = opened.json.id
  const signature = edSign(approvalCommitment(getRequest(TENANT, id)!).message, kp.privateKey)
  const s = await call('POST', `/approvals/${id}/sign`, { approver_id: approverId, reason: 'reviewed it', signature })
  assert.equal(s.status, 201, JSON.stringify(s.json))
  return { id, expiry: Date.parse(getRequest(TENANT, id)!.expires_at) }
}

/** A second process on the same file: BEGIN IMMEDIATE, a write that
 *  touches no approval data, print 'locked', hold the write lock for
 *  holdMs, COMMIT. */
function holdWriteLockInOtherProcess(holdMs: number) {
  const code = `
    const Database = require(${JSON.stringify(SQLITE_MODULE)})
    const db = new Database(${JSON.stringify(dbPath)})
    db.pragma('busy_timeout = 5000')
    db.exec('BEGIN IMMEDIATE')
    db.prepare("UPDATE tenants SET name = name WHERE id = ?").run(${JSON.stringify(TENANT)})
    process.stdout.write('locked\\n')
    const until = Date.now() + ${holdMs}
    while (Date.now() < until) {}
    db.exec('COMMIT')
    process.stdout.write('committed\\n')
    db.close()
  `
  const child = spawn(process.execPath, ['-e', code], { stdio: ['ignore', 'pipe', 'inherit'] })
  let out = ''
  const locked = new Promise<void>((resolve, reject) => {
    child.stdout.on('data', (d) => { out += d; if (out.includes('locked')) resolve() })
    child.on('exit', (c) => { if (!out.includes('locked')) reject(new Error(`child exited ${c}`)) })
  })
  const done = new Promise<void>((resolve) => child.on('exit', () => resolve()))
  return { locked, done }
}

function receiptCount(id: string): number {
  return (getDB().prepare(`SELECT COUNT(*) c FROM approval_receipts WHERE request_id = ?`).get(id) as any).c
}

describe('decide vs. request expiry', () => {
  it('a decide that starts before expiry and gets the write lock after it is refused', async () => {
    const { id, expiry } = await signedRequest(1)
    const other = holdWriteLockInOtherProcess(1800)
    await other.locked
    const started = Date.now()
    assert.ok(started < expiry, `decide starts before expiry (${expiry - started} ms left)`)

    const d = await call('POST', `/approvals/${id}/decide`, { verdict: 'approved', reason: 'reviewed', decided_by: 'ops' })
    await other.done
    const answered = Date.now()
    assert.ok(answered > expiry, `the lock wait crossed expiry (${answered - expiry} ms after)`)

    assert.equal(d.status, 409, JSON.stringify(d.json))
    assert.equal(d.json.error, 'Request has expired')
    assert.notEqual(getRequest(TENANT, id)!.status, 'approved')
    assert.equal(receiptCount(id), 0)
  })

  it('expiry passing during the in-transaction checks refuses the approval', async () => {
    const { id, expiry } = await signedRequest(1)
    const nowIso = new Date().toISOString()
    assert.ok(Date.parse(nowIso) < expiry)
    let checkStartedAt = NaN
    const r = decideRequest({
      tenantId: TENANT, id, verdict: 'approved', reason: 'reviewed', decidedBy: 'ops', nowIso,
      checkInTx: () => {
        // The row has been read and passed the early expiry check. Let the
        // clock cross expiry before the write.
        checkStartedAt = Date.now()
        while (Date.now() <= expiry + 5) {}
        return null
      },
    })
    assert.ok(checkStartedAt < expiry, `the in-transaction read was before expiry (${expiry - checkStartedAt} ms left)`)
    assert.equal(r.error, 'expired')
    assert.equal(r.decidedAt, undefined)
    const stored = getRequest(TENANT, id)!
    assert.equal(stored.status, 'pending')
    assert.equal(stored.decided_at, null)
    assert.equal(receiptCount(id), 0)
  })

  it('a reject that waits past expiry still records, with the time it was written', async () => {
    const { id, expiry } = await signedRequest(1)
    const other = holdWriteLockInOtherProcess(1800)
    await other.locked
    assert.ok(Date.now() < expiry)
    const d = await call('POST', `/approvals/${id}/decide`, { verdict: 'rejected', reason: 'not this one', decided_by: 'ops' })
    await other.done
    assert.equal(d.status, 200, JSON.stringify(d.json))
    const stored = getRequest(TENANT, id)!
    assert.equal(stored.status, 'rejected')
    assert.ok(Date.parse(stored.decided_at!) > expiry, 'decided_at is the write time, after the lock wait')
  })

  it('a decide well inside the window approves; decided_at equals the receipt issued_at', async () => {
    const { id, expiry } = await signedRequest()
    assert.ok(expiry - Date.now() > 60_000)
    const d = await call('POST', `/approvals/${id}/decide`, { verdict: 'approved', reason: 'reviewed', decided_by: 'ops' })
    assert.equal(d.status, 200, JSON.stringify(d.json))
    const stored = getRequest(TENANT, id)!
    assert.equal(stored.status, 'approved')
    const rec = getDB().prepare(`SELECT payload FROM approval_receipts WHERE request_id = ?`).get(id) as any
    assert.ok(rec, 'receipt issued')
    const payload = JSON.parse(rec.payload)
    assert.ok(stored.decided_at)
    assert.equal(payload.issued_at, stored.decided_at)
  })
})
