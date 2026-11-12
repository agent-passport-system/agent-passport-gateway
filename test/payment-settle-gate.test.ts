// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// POST /pay/nano/settle/:id - authorization + currency gate tests
// ══════════════════════════════════════════════════════════════════
// The settlement payout path used to send on-chain value with no
// authorization and no currency check: it passed a line item's amount
// straight to the Nano rail as XNO, dropping the item's currency, so a
// usd-denominated contribution paid out as XNO. These tests pin the fix:
//   1. The route is fail-closed by default (SETTLE_PAYOUT_ENABLED unset)
//      and sends nothing.
//   2. When enabled, a non-XNO line item is DENIED and never sent.
//   3. When enabled, a valid XNO line item is paid and a signed receipt
//      is recorded.
//   4. Mixed batch: only the XNO item is sent; the usd item is denied.
// The Nano rail's sendPayment is mocked, so NO real send is ever
// attempted; the tests assert on whether the mock was called.
// ══════════════════════════════════════════════════════════════════

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import express from 'express'
import type { Server } from 'node:http'

// The rail singleton reads NANO_RECEIVING_ADDRESS at first construction and
// throws without it. Set a dummy BEFORE anything calls getNanoRail(); no real
// send happens regardless because sendPayment is mocked in every test.
process.env.NANO_RECEIVING_ADDRESS = 'nano_1testreceiveaddressxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'

import { initDB, getDB } from '../src/db/schema.js'
import { initGatewayIdentity } from '../src/gateway/identity.js'
import { paymentRouter } from '../src/payment-rails/routes.js'
import { getNanoRail } from '../src/payment-rails/nano.js'

const TENANT_ID = 'tenant-settle-test'
const SETTLEMENT_ID = 'settlement-settle-test'
const SETTLEMENT_ID_MALFORMED = 'settlement-settle-malformed'

const LINE_ITEMS = [
  { source_id: 'src-usd', agent_id: 'agent-a', accesses: 1, amount: 5, currency: 'usd' },
  { source_id: 'src-xno', agent_id: 'agent-b', accesses: 1, amount: 2, currency: 'XNO' },
]

// A structurally malformed line item: no currency field at all. The normal
// settlements builder always sets amount+currency, but a corrupted settlement
// must still be denied and recorded cleanly, never sent, never 500.
const MALFORMED_LINE_ITEMS = [
  { source_id: 'src-bad', agent_id: 'agent-c', accesses: 1, amount: 5 },
]

let server: Server
let baseUrl: string
let rail: ReturnType<typeof getNanoRail>

function seed() {
  const db = getDB()
  db.prepare(`INSERT OR IGNORE INTO tenants (id, name, email) VALUES (?, ?, ?)`)
    .run(TENANT_ID, 'Settle Test Tenant', 'settle-test@example.com')
  const insert = db.prepare(
    `INSERT OR IGNORE INTO settlements (id, tenant_id, period_start, period_end, total_amount, line_items)
     VALUES (?, ?, ?, ?, ?, ?)`,
  )
  insert.run(SETTLEMENT_ID, TENANT_ID, '2026-07-01', '2026-07-08', 7, JSON.stringify(LINE_ITEMS))
  insert.run(SETTLEMENT_ID_MALFORMED, TENANT_ID, '2026-07-01', '2026-07-08', 5, JSON.stringify(MALFORMED_LINE_ITEMS))
}

async function settle(destination_map: Record<string, string>, settlementId: string = SETTLEMENT_ID) {
  const res = await fetch(`${baseUrl}/api/v1/pay/nano/settle/${settlementId}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ destination_map }),
  })
  return { status: res.status, body: await res.json() as any }
}

function fakeConfirmation() {
  return {
    invoiceId: 'inv-mock',
    rail: 'nano' as const,
    amount: 0,
    currency: 'XNO',
    txProof: 'MOCK_BLOCK_HASH',
    confirmedAt: new Date().toISOString(),
    confirmationTimeMs: 1,
  }
}

before(async () => {
  initDB(':memory:')
  initGatewayIdentity()
  seed()
  rail = getNanoRail()

  const app = express()
  app.use(express.json())
  // Stub auth: inject the test tenant, mirroring authMiddleware's req.tenant.
  app.use((req: any, _res, next) => {
    req.tenant = { id: TENANT_ID, name: 'Settle Test Tenant', plan: 'enterprise' }
    next()
  })
  app.use('/api/v1', paymentRouter)

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
  delete process.env.SETTLE_PAYOUT_ENABLED
  await new Promise<void>((resolve) => server.close(() => resolve()))
})

describe('POST /pay/nano/settle/:id - fail-closed authorization + currency gate', () => {
  it('every switch on and the real rail: the payout route publishes nothing and records no confirmed payout', async () => {
    const realFetch = globalThis.fetch
    let fetches = 0
    process.env.SETTLE_PAYOUT_ENABLED = 'true'
    process.env.NANO_WALLET_SEND_ENABLED = '1'
    delete process.env.NANO_WALLETS_PAUSED
    try {
      // Requests to this test server pass through. Any other fetch (a Nano node call) is counted and refused.
      globalThis.fetch = (async (url: any, init: any) => {
        if (String(url).startsWith(baseUrl)) return realFetch(url, init)
        fetches++
        throw new Error('no network in tests')
      }) as any
      const { status, body } = await settle({ 'src-xno': 'nano_1xno' })
      const xno = body.results?.find((x: any) => x.source_id === 'src-xno')
      assert.equal(status, 200)
      assert.equal(xno?.status, 'failed')
      assert.match(String(xno?.error), /settlement payouts are closed/)
      assert.equal(fetches, 0)
      const confirmed = getDB().prepare(`SELECT COUNT(*) AS c FROM payment_transactions WHERE settlement_id = ? AND status = 'confirmed'`).get(SETTLEMENT_ID) as any
      assert.equal(confirmed.c, 0)
    } finally {
      globalThis.fetch = realFetch
      delete process.env.SETTLE_PAYOUT_ENABLED
      delete process.env.NANO_WALLET_SEND_ENABLED
    }
  })

  it('is disabled by default (SETTLE_PAYOUT_ENABLED unset): returns 503 and sends nothing', async (t) => {
    delete process.env.SETTLE_PAYOUT_ENABLED
    const send = t.mock.method(rail, 'sendPayment', async () => fakeConfirmation())

    const { status, body } = await settle({ 'src-usd': 'nano_1usd', 'src-xno': 'nano_1xno' })

    assert.equal(status, 503)
    assert.match(body.error, /disabled/i)
    assert.equal(send.mock.callCount(), 0, 'no send may occur while payout is disabled')
  })

  it('when enabled, DENIES a non-XNO line item and never sends it', async (t) => {
    process.env.SETTLE_PAYOUT_ENABLED = 'true'
    const send = t.mock.method(rail, 'sendPayment', async () => fakeConfirmation())

    // Only the usd source has a destination; the xno source is skipped.
    const { status, body } = await settle({ 'src-usd': 'nano_1usd' })

    assert.equal(status, 200)
    assert.equal(send.mock.callCount(), 0, 'a usd line item must never reach sendPayment')
    const usd = body.results.find((r: any) => r.source_id === 'src-usd')
    assert.equal(usd.status, 'denied')
    assert.match(usd.reason, /currency mismatch/i)
    assert.equal(usd.currency, 'usd')
    assert.ok(usd.receipt && typeof usd.receipt.signature === 'string', 'denial is receipted')
    assert.equal(body.denied, 1)
  })

  it('when enabled, PAYS a valid XNO line item once and records a signed receipt', async (t) => {
    process.env.SETTLE_PAYOUT_ENABLED = 'true'
    const send = t.mock.method(rail, 'sendPayment', async () => fakeConfirmation())

    // Only the xno source has a destination; the usd source is skipped.
    const { status, body } = await settle({ 'src-xno': 'nano_1xno' })

    assert.equal(status, 200)
    assert.equal(send.mock.callCount(), 1, 'the XNO item is sent exactly once')
    // The amount handed to the rail is the item amount in XNO (no conversion).
    assert.equal(send.mock.calls[0].arguments[0].amount, 2)
    const xno = body.results.find((r: any) => r.source_id === 'src-xno')
    assert.equal(xno.status, 'confirmed')
    assert.equal(xno.block_hash, 'MOCK_BLOCK_HASH')
    assert.ok(xno.receipt && typeof xno.receipt.signature === 'string', 'payout is receipted')
    assert.equal(xno.receipt.kind, 'settlement_payout_receipt')
    assert.equal(body.confirmed, 1)
    // The recorded ledger row carries the true currency, not a hardcoded label.
    const row = getDB().prepare(
      `SELECT currency, status FROM payment_transactions WHERE settlement_id = ? AND status = 'confirmed'`,
    ).get(SETTLEMENT_ID) as any
    assert.equal(row.currency, 'XNO')
  })

  it('mixed batch: sends only the XNO item, denies the usd item, exactly one send', async (t) => {
    process.env.SETTLE_PAYOUT_ENABLED = 'true'
    const send = t.mock.method(rail, 'sendPayment', async () => fakeConfirmation())

    const { status, body } = await settle({ 'src-usd': 'nano_1usd', 'src-xno': 'nano_1xno' })

    assert.equal(status, 200)
    assert.equal(send.mock.callCount(), 1, 'only the XNO item is sent; the usd item is not')
    assert.equal(body.confirmed, 1)
    assert.equal(body.denied, 1)
    const usd = body.results.find((r: any) => r.source_id === 'src-usd')
    const xno = body.results.find((r: any) => r.source_id === 'src-xno')
    assert.equal(usd.status, 'denied')
    assert.equal(xno.status, 'confirmed')
  })

  it('when enabled, a malformed line item (no currency) is denied and recorded cleanly, never sent, no 500', async (t) => {
    process.env.SETTLE_PAYOUT_ENABLED = 'true'
    const send = t.mock.method(rail, 'sendPayment', async () => fakeConfirmation())

    const { status, body } = await settle({ 'src-bad': 'nano_1bad' }, SETTLEMENT_ID_MALFORMED)

    assert.equal(status, 200, 'a malformed line item must not 500 the batch')
    assert.equal(send.mock.callCount(), 0, 'a malformed line item must never reach sendPayment')
    const bad = body.results.find((r: any) => r.source_id === 'src-bad')
    assert.equal(bad.status, 'denied')
    assert.equal(body.denied, 1)
    // The denial was persisted (NOT-NULL-safe), not lost to a binding throw.
    const row = getDB().prepare(
      `SELECT status FROM payment_transactions WHERE settlement_id = ? AND status = 'denied'`,
    ).get(SETTLEMENT_ID_MALFORMED) as any
    assert.ok(row, 'denial ledger row persisted for the malformed item')
  })
})
