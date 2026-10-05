// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Approver revocation racing a decide, with a second writer on the same
// SQLite file.
//
// The store is a WAL-mode SQLite file (schema.ts initDB) that more than one
// process can open; schema.ts already handles booting replicas contending
// for the write lock. So a revocation can come from another connection
// while a decide is in flight. Decide reads the signatures and the approver
// registry inside its IMMEDIATE transaction (store.ts decideRequest
// checkInTx), so:
//
//   - a revocation that holds the write lock when decide starts, and
//     commits while decide waits for the lock, is seen: decide refuses with
//     409 approver_evidence_invalid and issues no receipt. Before this
//     change the registry was read outside the transaction, saw the
//     approver as active, and the decision committed after the revocation.
//   - while decide's transaction is open, another connection cannot commit
//     a revocation into it: the write is refused with SQLITE_BUSY and lands
//     only after the decision.

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
import Database from 'better-sqlite3'
import { generateKeyPair, sign as edSign } from 'agent-passport-system'
import { initDB, getDB } from '../src/db/schema.js'
import { initGatewayIdentity } from '../src/gateway/identity.js'
import { approvalRouter } from '../src/gateway/approval/index.js'
import { setApprovalConnectorRouter } from '../src/gateway/approval/connector.js'
import { registerApprover, getActiveApprover } from '../src/gateway/approval/approvers.js'
import { approvalCommitment } from '../src/gateway/approval/commitment.js'
import { getRequest, decideRequest } from '../src/gateway/approval/store.js'

const TENANT = 'tenant-race'
const AGENT = 'agent-race'
const SQLITE_MODULE = createRequire(import.meta.url).resolve('better-sqlite3')
let dbPath: string
let server: Server
let baseUrl: string

before(async () => {
  dbPath = join(tmpdir(), `aeoess-decide-race-${randomUUID()}.db`)
  initDB(dbPath)
  initGatewayIdentity()
  setApprovalConnectorRouter({
    async route(channel) {
      return { channel, sent: false, queued: true, transport: 'email_interim', routedAt: new Date().toISOString() }
    },
  })
  getDB().prepare(`INSERT INTO tenants (id, name, email) VALUES (?, ?, ?)`).run(TENANT, 'race', 'race@test.local')
  getDB().prepare(`INSERT INTO agents (id, tenant_id, agent_id, public_key, status, entity_id) VALUES (?, ?, ?, ?, 'active', ?)`)
    .run(randomUUID(), TENANT, AGENT, generateKeyPair().publicKey, 'owner-race')
  const app = express()
  app.use(express.json())
  app.use((req: any, _res, next) => { req.tenant = { id: TENANT, role: 'user', key_class: 'runtime', key_id: 'key-race' }; next() })
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
async function signedRequest(): Promise<{ id: string; approverId: string }> {
  const approverId = `ap-${randomUUID().slice(0, 8)}`
  const kp = generateKeyPair()
  registerApprover({
    tenantId: TENANT, approverId, publicKey: kp.publicKey, authority: ['payments:*'],
    principalId: `p-${approverId}`, registeredBy: 'test',
  })
  const opened = await call('POST', '/approvals', {
    action_class: 'payments:transfer', subject: `inv-${randomUUID()}`, agent_id: AGENT, requested_by: 'r',
  })
  assert.equal(opened.status, 201, JSON.stringify(opened.json))
  const id = opened.json.id
  const signature = edSign(approvalCommitment(getRequest(TENANT, id)!).message, kp.privateKey)
  const s = await call('POST', `/approvals/${id}/sign`, { approver_id: approverId, reason: 'reviewed it', signature })
  assert.equal(s.status, 201, JSON.stringify(s.json))
  return { id, approverId }
}

/** A second process on the same file: BEGIN IMMEDIATE, revoke, print
 *  'locked', hold the write lock for holdMs, COMMIT, print 'committed'. */
function revokeInOtherProcess(approverId: string, holdMs: number) {
  const code = `
    const Database = require(${JSON.stringify(SQLITE_MODULE)})
    const db = new Database(${JSON.stringify(dbPath)})
    db.pragma('busy_timeout = 5000')
    db.exec('BEGIN IMMEDIATE')
    db.prepare("UPDATE approval_approvers SET status = 'revoked', revoked_at = ? WHERE tenant_id = ? AND approver_id = ? AND status = 'active'")
      .run(new Date().toISOString(), ${JSON.stringify(TENANT)}, ${JSON.stringify(approverId)})
    process.stdout.write('locked\\n')
    const until = Date.now() + ${holdMs}
    while (Date.now() < until) {}
    db.exec('COMMIT')
    process.stdout.write('committed ' + Date.now() + '\\n')
    db.close()
  `
  const child = spawn(process.execPath, ['-e', code], { stdio: ['ignore', 'pipe', 'inherit'] })
  let out = ''
  const locked = new Promise<void>((resolve, reject) => {
    child.stdout.on('data', (d) => { out += d; if (out.includes('locked')) resolve() })
    child.on('exit', (c) => { if (!out.includes('locked')) reject(new Error(`child exited ${c}`)) })
  })
  const done = new Promise<number>((resolve) => child.on('exit', () => {
    const m = /committed (\d+)/.exec(out)
    resolve(m ? Number(m[1]) : NaN)
  }))
  return { locked, done }
}

describe('decide vs. approver revocation from another writer', () => {
  it('a revocation committed while decide waits for the write lock is seen; decide refuses', async () => {
    const { id, approverId } = await signedRequest()
    const HOLD_MS = 800
    const other = revokeInOtherProcess(approverId, HOLD_MS)
    await other.locked
    // The revocation is written but not committed: this connection still
    // reads the approver as active, which is what a check outside the
    // transaction would have relied on.
    assert.ok(getActiveApprover(TENANT, approverId), 'uncommitted revocation is not visible yet')

    const started = Date.now()
    const d = await call('POST', `/approvals/${id}/decide`, { verdict: 'approved', reason: 'looks right', decided_by: 'ops' })
    const committedAt = await other.done
    // Decide was blocked on the lock until the other process committed, so
    // the race window was actually exercised.
    assert.ok(Number.isFinite(committedAt))
    assert.ok(Date.now() >= committedAt, 'decide answered after the revocation committed')
    assert.ok(Date.now() - started >= HOLD_MS / 2, `decide waited for the lock (${Date.now() - started} ms)`)

    assert.equal(d.status, 409, JSON.stringify(d.json))
    assert.equal(d.json.code, 'approver_evidence_invalid')
    assert.equal(d.json.invalid_signatures, 1)
    assert.equal(getRequest(TENANT, id)!.status, 'pending')
    assert.equal((getDB().prepare(`SELECT COUNT(*) c FROM approval_receipts WHERE request_id = ?`).get(id) as any).c, 0)
    assert.equal(getActiveApprover(TENANT, approverId), undefined)
  })

  it('a reject decision is not blocked by a revoked approver (nothing is granted)', async () => {
    const { id, approverId } = await signedRequest()
    const other = revokeInOtherProcess(approverId, 300)
    await other.locked
    const d = await call('POST', `/approvals/${id}/decide`, { verdict: 'rejected', reason: 'not this one', decided_by: 'ops' })
    await other.done
    assert.equal(d.status, 200, JSON.stringify(d.json))
    assert.equal(getRequest(TENANT, id)!.status, 'rejected')
  })

  it('while the decide transaction is open, another connection cannot commit a revocation into it', async () => {
    const { id, approverId } = await signedRequest()
    const other = new Database(dbPath)
    other.pragma('busy_timeout = 0')
    let busy: string | null = null
    try {
      const r = decideRequest({
        tenantId: TENANT, id, verdict: 'approved', reason: 'looks right', decidedBy: 'ops',
        nowIso: new Date().toISOString(),
        checkInTx: () => {
          assert.ok(getActiveApprover(TENANT, approverId))
          try {
            other.prepare(`UPDATE approval_approvers SET status = 'revoked', revoked_at = ? WHERE tenant_id = ? AND approver_id = ?`)
              .run(new Date().toISOString(), TENANT, approverId)
          } catch (e: any) { busy = String(e?.code || e?.message) }
          return null
        },
      })
      assert.equal(r.error, undefined)
    } finally { other.close() }
    assert.equal(busy, 'SQLITE_BUSY', 'the revocation could not land inside the decide transaction')
    assert.equal(getRequest(TENANT, id)!.status, 'approved')
    assert.ok(getActiveApprover(TENANT, approverId), 'it lands only afterwards, as a later revocation')
  })

  it('checkInTx refusing writes nothing', async () => {
    const { id } = await signedRequest()
    const r = decideRequest({
      tenantId: TENANT, id, verdict: 'approved', reason: 'r', decidedBy: 'ops',
      nowIso: new Date().toISOString(), checkInTx: () => 'evidence_invalid',
    })
    assert.equal(r.error, 'evidence_invalid')
    assert.equal(getRequest(TENANT, id)!.status, 'pending')
  })
})
