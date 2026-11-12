// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// The Nano lifecycle is in the source but not activated. The server installs the runner only
// behind NANO_LIFECYCLE_ACTIVATED, which is false in source and is not read from the environment.
// The last test starts the real server with no pause, the send switch on and the pilot caps set,
// sends a valid payment request and checks that nothing was reserved, signed or sent to the node.
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createServer } from 'node:http'
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import Database from 'better-sqlite3'
// @ts-ignore nanocurrency-web has no type declarations
import nanoWebImport from 'nanocurrency-web'
import { initDB } from '../../src/db/schema.js'
import { createTenant } from '../../src/auth/api-keys.js'
import { NANO_LIFECYCLE_ACTIVATED } from '../../src/payment-rails/nano-activation.js'
import { getOpRunner } from '../../src/payment-rails/wallet-reconcile.js'
import { initializeWalletFrontier } from '../../src/payment-rails/wallet-frontier.js'

const nano = (nanoWebImport as any).default || nanoWebImport
const read = (p: string) => readFileSync(new URL(`../../src/${p}`, import.meta.url), 'utf8')

/** Every file in src/ where `pattern` occurs, as "src/relative/path.ts". */
function filesMatching(pattern: RegExp): string[] {
  const hits = new Set<string>()
  const walk = (dir: string) => {
    for (const name of readdirSync(dir)) {
      const p = join(dir, name)
      if (statSync(p).isDirectory()) walk(p)
      else if (/\.(ts|js|mjs|cjs)$/.test(name) && pattern.test(readFileSync(p, 'utf8'))) hits.add(p.replace(/\\/g, '/'))
    }
  }
  walk('src')
  return [...hits].sort()
}

describe('Nano lifecycle activation is closed in source', () => {
  it('the activation constant is false and does not come from the environment', () => {
    assert.equal(NANO_LIFECYCLE_ACTIVATED, false)
    assert.doesNotMatch(read('payment-rails/nano-activation.ts'), /process\.env/)
  })

  it('the server starts the lifecycle in one place, behind the constant', () => {
    const server = read('server.ts')
    const calls = server.split('startNanoLifecycle(').length - 1
    assert.equal(calls, 1)
    const at = server.indexOf('startNanoLifecycle(')
    const guard = server.lastIndexOf('if (', at)
    assert.match(server.slice(guard, at), /^if \(NANO_LIFECYCLE_ACTIVATED && /)
    assert.equal(server.split('rpcNode(').length - 1, 1)
    assert.ok(server.indexOf('rpcNode(') > at)
  })

  it('nothing else in src/ starts the lifecycle, installs a runner or runs an operation', () => {
    // startNanoLifecycle: its definition and the one guarded call in server.ts.
    assert.deepEqual(filesMatching(/startNanoLifecycle\(/), ['src/payment-rails/nano-lifecycle-startup.ts', 'src/server.ts'])
    // setOpRunner: its definition, and startNanoLifecycle installing and removing the runner.
    assert.deepEqual(filesMatching(/setOpRunner\(/), ['src/payment-rails/nano-lifecycle-startup.ts', 'src/payment-rails/wallet-reconcile.ts'])
    // The functions that drive an operation toward publishing are called only inside the lifecycle files.
    assert.deepEqual(filesMatching(/\b(runOp|lifecycleTick|inProcessRunner)\(/),
      ['src/payment-rails/nano-lifecycle-startup.ts', 'src/payment-rails/wallet-reconcile.ts'])
    assert.deepEqual(filesMatching(/\b(publishAttempt|commitAttempt|prepareOp)\(/),
      ['src/payment-rails/nano-publish.ts', 'src/payment-rails/wallet-reconcile.ts'])
  })

  it('with no runner installed, the routes see a lifecycle that is not ready', () => {
    assert.equal(getOpRunner().readiness(), 'lifecycle_not_installed')
  })

  it('the real server, with no pause, the send switch on and caps set, refuses a valid send with 503 and reserves, signs and sends nothing', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'nano-closed-'))
    const dbPath = join(dir, 'gw.db')
    // A tenant with an API key, a two-hop delegation chain in raw XNO, an active wallet and its
    // operator-recorded starting state: everything a send needs to pass every gate before readiness.
    const db = initDB(dbPath)
    const { tenant, apiKey } = createTenant({ name: 'Closed', email: 'closed@test.local' })
    for (const a of ['root', 'p', 'c']) {
      db.prepare(`INSERT INTO agents (id, tenant_id, agent_id, public_key, status, is_root) VALUES (?, ?, ?, 'pk', 'active', 0)`).run(`row-${a}`, tenant.id, a)
    }
    const ins = db.prepare(`INSERT INTO delegations (id, tenant_id, parent_agent_id, child_agent_id, scope, status, spend_limit, spend_used,
      parent_delegation_id, spend_unit, spend_limit_minor, spend_used_minor) VALUES (?, ?, ?, ?, 'commerce:send', 'active', 0, 0, ?, 'nano:XNO:raw', '5000', '0')`)
    ins.run('top', tenant.id, 'root', 'p', null)
    ins.run('low', tenant.id, 'p', 'c', 'top')
    const acct = nano.wallet.fromLegacySeed('3a'.repeat(32)).accounts[0]
    const dest = nano.wallet.fromLegacySeed('cc'.repeat(32)).accounts[0]
    db.prepare(`INSERT INTO agent_wallets (id, tenant_id, agent_id, nano_address, wallet_index, status) VALUES ('w-1', ?, 'c', ?, 20001, 'active')`)
      .run(tenant.id, acct.address)
    const fr = initializeWalletFrontier(db, { walletId: 'w-1', frontier: 'F47B23107E5F34B2CE06F562B5C435DF72A533251CB414C51B2B62A8F63A00E4',
      balanceRaw: '100000', by: 'test-operator', evidence: 'fixture', now: 0, replace: false })
    assert.ok(fr.ok)
    db.close()

    // A stand-in Nano node that counts every request it receives.
    let nodeRequests = 0
    const node = createServer((_req, res) => { nodeRequests++; res.end('{}') })
    await new Promise<void>(r => node.listen(0, '127.0.0.1', () => r()))
    const nodePort = (node.address() as any).port

    const port = String(43_000 + Math.floor(Math.random() * 2000))
    const env: Record<string, string | undefined> = {
      ...process.env, DB_PATH: dbPath, PORT: port, NODE_ENV: 'development', NANO_RPC_URL: `http://127.0.0.1:${nodePort}`,
      NANO_WALLET_SEND_ENABLED: '1', NANO_PILOT_MAX_PAYMENT_RAW: '100000', NANO_PILOT_MAX_WALLET_RAW: '100000', NANO_PILOT_MAX_PAYMENTS: '10',
    }
    delete env.NANO_WALLETS_PAUSED
    delete env.NANO_RAIL_DISABLED
    const child = spawn(process.execPath, ['--import', 'tsx', 'src/server.ts'], { cwd: process.cwd(), env })
    let text = ''
    child.stdout.on('data', d => { text += d })
    child.stderr.on('data', d => { text += d })
    const base = `http://127.0.0.1:${port}`
    try {
      let health: any = null
      for (let i = 0; i < 75 && !health; i++) {
        try { const r = await fetch(`${base}/healthz/nano-lifecycle`); health = { status: r.status, body: await r.json() } } catch {}
        if (!health) await new Promise(res => setTimeout(res, 200))
      }
      assert.deepEqual(health, { status: 200, body: { state: 'disabled' } }, text.slice(-800))

      const send = (key: string) => fetch(`${base}/api/v1/wallets/send`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${apiKey}`, 'idempotency-key': key },
        body: JSON.stringify({ from_agent_id: 'c', to_address: dest.address, amount_raw: '1000' }),
      })
      const first = await send('k-1')
      const body = await first.json() as any
      assert.equal(first.status, 503, JSON.stringify(body))
      assert.equal(body.status, 'denied')
      assert.match(String(body.denial_reason), /lifecycle_not_installed/)
      // The same key again is a new refusal, not a replay: no operation was stored under it.
      assert.equal((await send('k-1')).status, 503)
      // Long enough for a scheduled operation to reach the node, had one been created.
      await new Promise(res => setTimeout(res, 1500))
    } finally {
      child.kill()
      await new Promise(res => child.on('exit', res))
      await new Promise<void>(r => node.close(() => r()))
    }

    const after = new Database(dbPath, { readonly: true })
    const count = (sql: string) => (after.prepare(sql).get() as any).c as number
    try {
      assert.equal(count(`SELECT COUNT(*) AS c FROM wallet_ops`), 0)
      assert.equal(count(`SELECT COUNT(*) AS c FROM wallet_op_reservations`), 0)
      assert.equal(count(`SELECT COUNT(*) AS c FROM wallet_op_attempts`), 0)
      assert.equal(count(`SELECT COUNT(*) AS c FROM wallet_transactions WHERE status <> 'denied'`), 0)
      assert.equal(count(`SELECT COUNT(*) AS c FROM wallet_transactions WHERE status = 'denied'`), 2)
      const used = after.prepare(`SELECT id, spend_used_minor FROM delegations ORDER BY id`).all()
      assert.deepEqual(used, [{ id: 'low', spend_used_minor: '0' }, { id: 'top', spend_used_minor: '0' }])
    } finally {
      after.close()
      rmSync(dir, { recursive: true, force: true })
    }
    assert.equal(nodeRequests, 0)
  })
})
