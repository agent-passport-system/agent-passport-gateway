// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Payment Rails — Gateway Routes
 *
 * POST /api/v1/pay/nano/invoice         — Create Nano payment request
 * GET  /api/v1/pay/nano/status/:id      — Check invoice status
 * POST /api/v1/pay/nano/settle/:id      — Execute settlement via Nano
 * GET  /api/v1/pay/nano/balance         — Gateway wallet balance
 * GET  /api/v1/pay/nano/history         — Recent transactions
 * POST /api/v1/pay/nano/verify          — Verify on-chain transaction
 */

import { Router } from 'express'
import { randomUUID } from 'node:crypto'
import { getNanoRail, rawToXno, xnoToRaw } from './nano.js'
import { getDB } from '../db/schema.js'
import { getEventBus } from '../gateway/events.js'
import { getGatewayIdentity } from '../gateway/identity.js'
import type { Tenant } from '../auth/api-keys.js'

export const paymentRouter = Router()

// The unit the Nano rail pays in. A settlement line item denominated in
// anything else (contributions default to 'usd') must never be sent on this
// rail, and the gateway performs no conversion. Case-sensitive to match how
// nano.ts labels its own amounts (`readonly currency = 'XNO'`).
const RAIL_CURRENCY = 'XNO'

// Gateway-signed receipt for one settlement payout decision (confirmed or
// denied). This is a gateway attestation of what the payout path did, signed
// with the same EdDSA identity used for evaluation receipts. It is NOT a
// delegation- or authority-linked receipt: settle has no payer delegation
// today (see the fail-closed gate below), so this records the decision and
// its signer, not an authorization. A payer-authority-linked receipt belongs
// with the treasury authority model that does not yet exist.
function signSettlementPayoutReceipt(body: {
  settlement_id: string
  source_id: string
  amount: number
  currency: string
  destination: string
  decision: 'confirmed' | 'denied'
  reason: string | null
  tx_proof: string | null
}): { kind: string; signature: string; kid: string; issued_at: string } {
  const issued_at = new Date().toISOString()
  const id = getGatewayIdentity()
  const signature = id.sign({ kind: 'settlement_payout_receipt', ...body, issued_at })
  return { kind: 'settlement_payout_receipt', signature, kid: id.kid, issued_at }
}

// ── POST /pay/nano/invoice — Create payment request ──

paymentRouter.post('/pay/nano/invoice', async (req: any, res) => {
  const tenant: Tenant = req.tenant
  try {
    const nano = getNanoRail()
    const { amount, settlement_id, agent_id, memo, expires_in } = req.body

    if (!amount || amount <= 0) {
      return res.status(400).json({ error: 'Required: amount (in XNO, > 0)' })
    }

    const invoice = await nano.createInvoice({
      amount,
      settlementId: settlement_id,
      agentId: agent_id,
      memo,
      expiresInSeconds: expires_in || 3600,
    })

    // Store in DB
    const db = getDB()
    db.prepare(`INSERT INTO payment_transactions
      (id, tenant_id, settlement_id, rail, direction, amount, currency,
       destination, status, invoice_data)
      VALUES (?, ?, ?, 'nano', 'inbound', ?, 'XNO', ?, 'pending', ?)`)
      .run(invoice.invoiceId, tenant.id, settlement_id || null,
        amount, invoice.destination, JSON.stringify(invoice))
    try { getEventBus().emit(tenant.id, { type: 'payment_created', data: { transaction_id: invoice.invoiceId, amount, direction: 'inbound', status: 'pending' } }) } catch {}

    res.status(201).json({
      invoice_id: invoice.invoiceId,
      pay_to: invoice.destination,
      amount_xno: invoice.amountHuman,
      amount_raw: invoice.metadata.amountRaw,
      expires_at: invoice.expiresAt,
      status: 'pending',
      instructions: `Send exactly ${invoice.amountHuman} to ${invoice.destination}. Payment confirms in <1 second. Zero fees.`,
    })
  } catch (e: any) {
    res.status(500).json({ error: e.message })
  }
})

// ── GET /pay/nano/status/:id — Check invoice payment status ──

paymentRouter.get('/pay/nano/status/:id', async (req: any, res) => {
  try {
    const nano = getNanoRail()
    const invoice = await nano.checkStatus(req.params.id)

    // Update DB if confirmed
    if (invoice.status === 'confirmed') {
      const db = getDB()
      db.prepare(`UPDATE payment_transactions
        SET status = 'confirmed',
            tx_proof = ?,
            confirmed_at = datetime('now')
        WHERE id = ? AND tenant_id = ?`)
        .run(invoice.metadata.blockHash as string, invoice.invoiceId, req.tenant.id)
    }

    res.json({
      invoice_id: invoice.invoiceId,
      status: invoice.status,
      amount_xno: invoice.amountHuman,
      destination: invoice.destination,
      block_hash: invoice.metadata.blockHash || null,
      sender: invoice.metadata.sender || null,
      confirmation_time_ms: invoice.metadata.confirmationTimeMs || null,
    })
  } catch (e: any) {
    res.status(404).json({ error: e.message })
  }
})

// ── POST /pay/nano/settle/:id — Execute settlement via Nano ──

paymentRouter.post('/pay/nano/settle/:id', async (req: any, res) => {
  const tenant: Tenant = req.tenant
  const db = getDB()

  // ── Authorization gate: fail closed until a payout authority model exists ──
  // Settlement payout disburses gateway-held value to external nano addresses.
  // Unlike the agent wallet send (wallet.ts), which is gated by an agent's own
  // active delegation + commerce:send scope + spend_limit, a settlement payout
  // is a TREASURY disbursement: there is no fromAgentId and no per-agent
  // delegation to authorize it. The gateway currently has no treasury/tenant
  // payout authority (no tenant spend cap, no payout delegation, no settlement
  // approval), so there is no correct authorization to check here yet. Rather
  // than disburse without authorization, this endpoint is disabled by default
  // and refuses to send. An operator must set SETTLE_PAYOUT_ENABLED=true to
  // enable it, and it should only be enabled once a real disbursement authority
  // gates it. Read from process.env at request time (not module load) so the
  // posture is explicit per deployment.
  if (process.env.SETTLE_PAYOUT_ENABLED !== 'true') {
    return res.status(503).json({
      error: 'Settlement payout is disabled',
      reason:
        'No treasury payout authority is configured, so this endpoint is fail-closed and sends nothing (SETTLE_PAYOUT_ENABLED is not "true"). It must stay disabled until an authorized disbursement gate exists.',
    })
  }

  try {
    const nano = getNanoRail()
    // Day 268: a payout is an outbound Nano send, so the wallet pause and the send switch apply.
    if (process.env.NANO_WALLETS_PAUSED === '1' || process.env.NANO_WALLET_SEND_ENABLED !== '1') {
      return res.status(503).json({ error: 'nano_send_not_enabled', message: 'Nano sends are paused or not enabled, so no payout is sent.' })
    }
    const settlement = db.prepare(
      `SELECT * FROM settlements WHERE id = ? AND tenant_id = ?`
    ).get(req.params.id, tenant.id) as any

    if (!settlement) {
      return res.status(404).json({ error: 'Settlement not found' })
    }

    const lineItems = JSON.parse(settlement.line_items || '[]')
    const { destination_map } = req.body
    // destination_map: { "source_id": "nano_address", ... }

    if (!destination_map || typeof destination_map !== 'object') {
      return res.status(400).json({
        error: 'Required: destination_map — object mapping source_id to nano address',
        example: { 'source-001': 'nano_3abc...', 'source-002': 'nano_1xyz...' },
      })
    }

    const results: any[] = []
    let totalPaid = 0

    for (const item of lineItems) {
      const destination = destination_map[item.source_id]
      if (!destination) {
        results.push({
          source_id: item.source_id,
          status: 'skipped',
          reason: 'No nano address in destination_map',
        })
        continue
      }

      // ── Currency gate (unconditional): the Nano rail pays XNO only ──
      // A line item denominated in anything else (contributions default to
      // 'usd', schema.ts) must never be paid out as XNO, and the gateway does
      // no conversion. Fail closed: deny, record the denial with an explicit
      // reason and a signed receipt, and never call sendPayment for it.
      if (item.currency !== RAIL_CURRENCY) {
        const reason = `currency mismatch: line item "${item.source_id}" is denominated in "${item.currency}", the Nano rail pays ${RAIL_CURRENCY}, and the gateway performs no conversion`
        const receipt = signSettlementPayoutReceipt({
          settlement_id: settlement.id, source_id: item.source_id, amount: item.amount,
          currency: item.currency, destination, decision: 'denied', reason, tx_proof: null,
        })
        // Bind NOT-NULL-safe values for the denial ledger row. A structurally
        // malformed line item (missing amount or currency) still lands here and
        // must record cleanly, not throw a NOT NULL binding error mid-batch. The
        // raw (possibly-bad) currency is preserved verbatim in `reason` and the
        // signed receipt above; this is a denial record, not a relabel, and the
        // item is never sent.
        const deniedAmount = Number.isFinite(item.amount) ? item.amount : 0
        const deniedCurrency = typeof item.currency === 'string' ? item.currency : String(item.currency)
        db.prepare(`INSERT INTO payment_transactions
          (id, tenant_id, settlement_id, rail, direction, amount, currency,
           destination, status, invoice_data)
          VALUES (?, ?, ?, 'nano', 'outbound', ?, ?, ?, 'denied', ?)`)
          .run(randomUUID(), tenant.id, settlement.id,
            deniedAmount, deniedCurrency, destination, JSON.stringify({ reason, receipt }))
        results.push({
          source_id: item.source_id,
          status: 'denied',
          reason,
          currency: item.currency,
          amount: item.amount,
          destination,
          receipt,
        })
        continue
      }

      try {
        const confirmation = await nano.sendPayment({
          destination,
          amount: item.amount,
          memo: `settlement:${settlement.id}:${item.source_id}`,
        })

        const receipt = signSettlementPayoutReceipt({
          settlement_id: settlement.id, source_id: item.source_id, amount: item.amount,
          currency: item.currency, destination, decision: 'confirmed', reason: null,
          tx_proof: confirmation.txProof,
        })
        // Record outbound transaction. currency is item.currency, which the
        // gate above guarantees is XNO, so this records the true unit rather
        // than a hardcoded label over a possibly-different currency.
        db.prepare(`INSERT INTO payment_transactions
          (id, tenant_id, settlement_id, rail, direction, amount, currency,
           destination, tx_proof, status, confirmed_at, invoice_data)
          VALUES (?, ?, ?, 'nano', 'outbound', ?, ?, ?, ?, 'confirmed', datetime('now'), ?)`)
          .run(randomUUID(), tenant.id, settlement.id,
            item.amount, item.currency, destination, confirmation.txProof, JSON.stringify({ receipt }))
        try { getEventBus().emit(tenant.id, { type: 'payment_created', data: { settlement_id: settlement.id, amount: item.amount, direction: 'outbound', status: 'confirmed' } }) } catch {}

        totalPaid += item.amount
        results.push({
          source_id: item.source_id,
          status: 'confirmed',
          block_hash: confirmation.txProof,
          amount_xno: item.amount,
          destination,
          confirmation_time_ms: confirmation.confirmationTimeMs,
          receipt,
        })
      } catch (e: any) {
        results.push({
          source_id: item.source_id,
          status: 'failed',
          error: e.message,
          destination,
        })
      }
    }

    res.json({
      settlement_id: settlement.id,
      rail: 'nano',
      total_amount: settlement.total_amount,
      total_paid: Math.round(totalPaid * 10000) / 10000,
      line_items: results.length,
      confirmed: results.filter(r => r.status === 'confirmed').length,
      denied: results.filter(r => r.status === 'denied').length,
      failed: results.filter(r => r.status === 'failed').length,
      skipped: results.filter(r => r.status === 'skipped').length,
      results,
    })
  } catch (e: any) {
    res.status(500).json({ error: e.message })
  }
})

// ── GET /pay/nano/balance — Gateway wallet balance ──

paymentRouter.get('/pay/nano/balance', async (_req: any, res) => {
  try {
    const nano = getNanoRail()
    const balance = await nano.getBalance()
    res.json({
      rail: 'nano',
      balance_xno: balance.balanceXno,
      balance_raw: balance.balance,
      receivable_raw: balance.receivable,
    })
  } catch (e: any) {
    res.status(500).json({ error: e.message })
  }
})

// ── GET /pay/nano/history — Recent transactions ──

paymentRouter.get('/pay/nano/history', async (_req: any, res) => {
  try {
    const nano = getNanoRail()
    const count = parseInt((_req as any).query?.count || '20')
    const history = await nano.getHistory(count)
    res.json({ rail: 'nano', transactions: history, count: history.length })
  } catch (e: any) {
    res.status(500).json({ error: e.message })
  }
})

// ── POST /pay/nano/verify — Verify on-chain transaction ──

paymentRouter.post('/pay/nano/verify', async (req: any, res) => {
  try {
    const nano = getNanoRail()
    const { block_hash, expected_amount } = req.body
    if (!block_hash) {
      return res.status(400).json({ error: 'Required: block_hash' })
    }
    const result = await nano.verifyTransaction(block_hash, expected_amount)
    res.json({ rail: 'nano', ...result })
  } catch (e: any) {
    res.status(500).json({ error: e.message })
  }
})
