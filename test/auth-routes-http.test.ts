// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Credential routes over HTTP (src/auth/auth-router.ts), the same router
// instance type server.ts mounts, with real tenants, real keys and a
// stubbed mailer that records what would be sent.
//
//   - POST /auth/email/login issues a runtime key only, even when asked
//     for a tenant_admin key
//   - POST /auth/tenant-admin/issue needs the account password; a bearer
//     key is not a credential there
//   - POST /api/v1/account/rotate-key and regenerate-key revoke and mint
//     runtime keys only, so an unexpired tenant_admin key keeps working
//   - POST /auth/email/forgot + /auth/email/reset revoke every key class
//   - a tenant_admin issuance sends exactly one security notice (account,
//     time, action, what to do), never the key; a refused one sends none

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { unlinkSync } from 'node:fs'
import { randomUUID, createHash } from 'node:crypto'
import type { Server } from 'node:http'
import express from 'express'
import { initDB, getDB } from '../src/db/schema.js'
import { createTenant, authenticateKey } from '../src/auth/api-keys.js'
import { hashPassword, setTenantPassword } from '../src/auth/email-password.js'
import { createAuthRouter } from '../src/auth/auth-router.js'
import type { EmailOptions } from '../src/notifications/email.js'

const PASSWORD = 'correct horse battery staple'
let dbPath: string

before(() => {
  dbPath = join(tmpdir(), `aeoess-auth-routes-${randomUUID()}.db`)
  initDB(dbPath)
})

after(() => {
  try { getDB().close() } catch {}
  for (const f of [dbPath, `${dbPath}-wal`, `${dbPath}-shm`]) { try { unlinkSync(f) } catch {} }
})

interface Harness {
  call: (method: string, path: string, body?: unknown, key?: string) => Promise<{ status: number; json: any }>
  mails: EmailOptions[]
  close: () => void
}

/** A fresh app per describe block, so each gets its own rate-limit budget
 *  (the limiters are per router instance). */
async function harness(): Promise<Harness> {
  const mails: EmailOptions[] = []
  const app = express()
  app.use(express.json())
  app.use(createAuthRouter({
    appOrigin: 'https://portal.test.local',
    sendEmail: async (m) => { mails.push(m); return { sent: false, queued: false } },
  }))
  const server: Server = await new Promise((r) => { const s = app.listen(0, '127.0.0.1', () => r(s)) })
  const baseUrl = `http://127.0.0.1:${(server.address() as any).port}`
  return {
    mails,
    close: () => server.close(),
    async call(method, path, body, key) {
      const headers: Record<string, string> = { 'content-type': 'application/json' }
      if (key) headers.authorization = `Bearer ${key}`
      const r = await fetch(`${baseUrl}${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) })
      let json: any = null
      try { json = await r.json() } catch { json = null }
      return { status: r.status, json }
    },
  }
}

async function tenantWithPassword(): Promise<{ id: string; email: string; signupKey: string }> {
  const email = `routes-${randomUUID()}@test.local`
  const { tenant, apiKey } = createTenant({ name: 'Routes Test', email })
  setTenantPassword(tenant.id, await hashPassword(PASSWORD))
  return { id: tenant.id, email, signupKey: apiKey }
}

function keyRow(rawKey: string): any {
  return getDB().prepare(`SELECT key_class, expires_at, revoked_at FROM api_keys WHERE key_hash = ?`)
    .get(createHash('sha256').update(rawKey).digest('hex'))
}
function count(tenantId: string, keyClass: string): number {
  return (getDB().prepare(`SELECT COUNT(*) c FROM api_keys WHERE tenant_id = ? AND key_class = ?`).get(tenantId, keyClass) as any).c
}

describe('POST /auth/email/login', () => {
  let h: Harness
  before(async () => { h = await harness() })
  after(() => h.close())

  it('issues a runtime key with no expiry', async () => {
    const t = await tenantWithPassword()
    const r = await h.call('POST', '/auth/email/login', { email: t.email, password: PASSWORD })
    assert.equal(r.status, 200, JSON.stringify(r.json))
    assert.equal(r.json.key_class, 'runtime')
    assert.deepEqual(keyRow(r.json.api_key), { key_class: 'runtime', expires_at: null, revoked_at: null })
    assert.equal(authenticateKey(r.json.api_key)!.key_class, 'runtime')
  })

  it('a client asking for key_class=tenant_admin still gets a runtime key', async () => {
    const t = await tenantWithPassword()
    const r = await h.call('POST', '/auth/email/login', { email: t.email, password: PASSWORD, key_class: 'tenant_admin' })
    assert.equal(r.status, 200)
    assert.equal(r.json.key_class, 'runtime')
    assert.equal(keyRow(r.json.api_key).key_class, 'runtime')
    assert.equal(count(t.id, 'tenant_admin'), 0)
  })

  it('a wrong password is 401 and mints nothing', async () => {
    const t = await tenantWithPassword()
    const r = await h.call('POST', '/auth/email/login', { email: t.email, password: 'not the password' })
    assert.equal(r.status, 401)
    assert.equal(count(t.id, 'runtime'), 1, 'only the signup key')
  })
})

describe('POST /auth/tenant-admin/issue', () => {
  let h: Harness
  before(async () => { h = await harness() })
  after(() => h.close())

  it('the account password issues a tenant_admin key with an expiry', async () => {
    const t = await tenantWithPassword()
    const r = await h.call('POST', '/auth/tenant-admin/issue', { email: t.email, password: PASSWORD })
    assert.equal(r.status, 201, JSON.stringify(r.json))
    assert.equal(r.json.key_class, 'tenant_admin')
    const row = keyRow(r.json.api_key)
    assert.equal(row.key_class, 'tenant_admin')
    assert.equal(row.expires_at, r.json.expires_at)
    assert.ok(Date.parse(row.expires_at) > Date.now())
  })

  it('without the password it is 401, whatever bearer key is sent', async () => {
    const t = await tenantWithPassword()
    const admin = (await h.call('POST', '/auth/tenant-admin/issue', { email: t.email, password: PASSWORD })).json.api_key
    for (const [body, key] of [
      [{ email: t.email }, undefined],
      [{ email: t.email, password: 'not the password' }, undefined],
      [{}, t.signupKey],
      [{ email: t.email }, t.signupKey],
      [{}, admin],
      [{ email: t.email }, admin],
    ] as Array<[unknown, string | undefined]>) {
      const r = await h.call('POST', '/auth/tenant-admin/issue', body, key)
      assert.equal(r.status, 401, JSON.stringify(body))
    }
    assert.equal(count(t.id, 'tenant_admin'), 1)
  })
})

describe('POST /api/v1/account/rotate-key and regenerate-key', () => {
  let h: Harness
  before(async () => { h = await harness() })
  after(() => h.close())

  it('runtime rotation leaves an unexpired tenant_admin key working', async () => {
    const t = await tenantWithPassword()
    const login = (await h.call('POST', '/auth/email/login', { email: t.email, password: PASSWORD })).json.api_key
    const admin = (await h.call('POST', '/auth/tenant-admin/issue', { email: t.email, password: PASSWORD })).json.api_key

    const rot = await h.call('POST', '/api/v1/account/rotate-key', {}, login)
    assert.equal(rot.status, 200, JSON.stringify(rot.json))
    assert.equal(keyRow(rot.json.api_key).key_class, 'runtime')
    assert.equal(authenticateKey(t.signupKey), null)
    assert.equal(authenticateKey(login), null)
    assert.equal(authenticateKey(admin)!.key_class, 'tenant_admin')
    assert.equal((await h.call('GET', '/api/v1/account', undefined, admin)).status, 200)

    const mailsBefore = h.mails.length
    const regen = await h.call('POST', '/api/v1/account/regenerate-key', {}, rot.json.api_key)
    assert.equal(regen.status, 200)
    assert.equal(keyRow(regen.json.api_key).key_class, 'runtime')
    assert.equal(authenticateKey(rot.json.api_key), null)
    assert.equal(authenticateKey(admin)!.key_class, 'tenant_admin')
    assert.equal(count(t.id, 'tenant_admin'), 1, 'rotation minted no admin key')
    // Regenerate sends its notice; it carries no key.
    const regenMails = h.mails.slice(mailsBefore)
    assert.equal(regenMails.length, 1)
    assert.equal(regenMails[0].to, t.email)
    assert.ok(!JSON.stringify(regenMails[0]).includes(regen.json.api_key))
  })

  it('no key is 401', async () => {
    assert.equal((await h.call('POST', '/api/v1/account/rotate-key', {})).status, 401)
    assert.equal((await h.call('POST', '/api/v1/account/regenerate-key', {})).status, 401)
  })
})

describe('POST /auth/email/forgot + /auth/email/reset', () => {
  let h: Harness
  before(async () => { h = await harness() })
  after(() => h.close())

  it('reset revokes every key class, tenant_admin included', async () => {
    const t = await tenantWithPassword()
    const login = (await h.call('POST', '/auth/email/login', { email: t.email, password: PASSWORD })).json.api_key
    const admin = (await h.call('POST', '/auth/tenant-admin/issue', { email: t.email, password: PASSWORD })).json.api_key
    assert.equal(authenticateKey(admin)!.key_class, 'tenant_admin')

    const forgot = await h.call('POST', '/auth/email/forgot', { email: t.email })
    assert.equal(forgot.status, 200)
    const resetMail = h.mails.filter(m => m.to === t.email && m.subject.includes('Reset')).pop()
    assert.ok(resetMail, 'reset link sent')
    const token = decodeURIComponent(/reset_token=([^\s"&]+)/.exec(resetMail!.textBody)![1])

    const reset = await h.call('POST', '/auth/email/reset', { token, password: 'a different long passphrase' })
    assert.equal(reset.status, 200, JSON.stringify(reset.json))
    assert.equal(reset.json.api_keys_revoked, 3, 'signup + login + admin')
    for (const k of [t.signupKey, login, admin]) {
      assert.equal(authenticateKey(k), null)
      assert.ok(keyRow(k).revoked_at)
    }
    assert.equal((await h.call('GET', '/api/v1/account', undefined, admin)).status, 401)
    // The old password no longer issues anything; the new one does.
    assert.equal((await h.call('POST', '/auth/tenant-admin/issue', { email: t.email, password: PASSWORD })).status, 401)
    const again = await h.call('POST', '/auth/tenant-admin/issue', { email: t.email, password: 'a different long passphrase' })
    assert.equal(again.status, 201)
  })

  it('a used reset token is refused', async () => {
    const t = await tenantWithPassword()
    await h.call('POST', '/auth/email/forgot', { email: t.email })
    const mail = h.mails.filter(m => m.to === t.email).pop()!
    const token = decodeURIComponent(/reset_token=([^\s"&]+)/.exec(mail.textBody)![1])
    assert.equal((await h.call('POST', '/auth/email/reset', { token, password: 'a different long passphrase' })).status, 200)
    assert.equal((await h.call('POST', '/auth/email/reset', { token, password: 'yet another long passphrase' })).status, 400)
  })
})

describe('tenant_admin issuance security notice', () => {
  let h: Harness
  before(async () => { h = await harness() })
  after(() => h.close())

  it('a successful issuance sends exactly one notice to the account address, without the key', async () => {
    const t = await tenantWithPassword()
    const before = h.mails.length
    const r = await h.call('POST', '/auth/tenant-admin/issue', { email: t.email, password: PASSWORD })
    assert.equal(r.status, 201)
    const sent = h.mails.slice(before)
    assert.equal(sent.length, 1)
    const m = sent[0]
    assert.equal(m.to, t.email)
    assert.match(m.subject, /tenant admin key issued/i)
    // Account, time, action, and what to do if it was not them.
    assert.ok(m.textBody.includes(`Account: ${t.email}`))
    const time = /Time: (\S+)/.exec(m.textBody)![1]
    assert.ok(Math.abs(Date.parse(time) - Date.now()) < 60_000)
    assert.ok(m.textBody.includes('Action: tenant admin key issued'))
    assert.ok(m.textBody.includes(r.json.expires_at))
    assert.match(m.textBody, /If this was NOT you/)
    assert.match(m.textBody, /Forgot Password/)
    // Never the key, not even its prefix.
    const whole = JSON.stringify(m)
    assert.ok(!whole.includes(r.json.api_key))
    assert.ok(!whole.includes(r.json.api_key.slice(0, 12)))
    assert.ok(!whole.includes(PASSWORD))
  })

  it('a failed issuance sends none', async () => {
    const t = await tenantWithPassword()
    const inactive = await tenantWithPassword()
    getDB().prepare(`UPDATE tenants SET status = 'suspended' WHERE id = ?`).run(inactive.id)
    const before = h.mails.length
    for (const [body, key] of [
      [{ email: t.email, password: 'not the password' }, undefined],
      [{ email: t.email }, undefined],
      [{ email: `nobody-${randomUUID()}@test.local`, password: PASSWORD }, undefined],
      [{}, t.signupKey],
      [{ email: inactive.email, password: PASSWORD }, undefined],
    ] as Array<[unknown, string | undefined]>) {
      const r = await h.call('POST', '/auth/tenant-admin/issue', body, key)
      assert.ok(r.status === 401 || r.status === 403, `${JSON.stringify(body)} -> ${r.status}`)
    }
    assert.equal(h.mails.length, before, 'no notice for a refused issuance')
    assert.equal(count(t.id, 'tenant_admin'), 0)
    assert.equal(count(inactive.id, 'tenant_admin'), 0)
  })

  it('a mailer failure does not undo the issuance', async () => {
    const mails: EmailOptions[] = []
    const app = express()
    app.use(express.json())
    app.use(createAuthRouter({ sendEmail: async (m) => { mails.push(m); throw new Error('smtp down') } }))
    const server: Server = await new Promise((r) => { const s = app.listen(0, '127.0.0.1', () => r(s)) })
    try {
      const t = await tenantWithPassword()
      const r = await fetch(`http://127.0.0.1:${(server.address() as any).port}/auth/tenant-admin/issue`, {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email: t.email, password: PASSWORD }),
      })
      assert.equal(r.status, 201)
      assert.equal(mails.length, 1)
      assert.equal(count(t.id, 'tenant_admin'), 1)
    } finally { server.close() }
  })
})
