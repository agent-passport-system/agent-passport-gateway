// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Agent Wallet Routes — APS-Native Nano Wallets
 *
 * Static routes registered BEFORE parameterized :agentId routes
 * to prevent Express matching "dashboard" as an agentId.
 */

import { parseSendAmount } from '../gateway/spend-units.js'
import { Router } from 'express'
import { RateLimiterMemory } from 'rate-limiter-flexible'
import { getWalletService } from './wallet.js'
import { getDB } from '../db/schema.js'
import { addressToPublicKey } from './nano-block.js'
import { WalletOpError, getOp, type WalletOp } from './wallet-ops.js'
import { getOpRunner } from './wallet-reconcile.js'
import type { Tenant } from '../auth/api-keys.js'

export const walletRouter = Router()

// ── Rate Limiters ──
const provisionLimiter = new RateLimiterMemory({
  points: 10,       // 10 wallet creations
  duration: 60,     // per minute per tenant
  keyPrefix: 'wallet_provision',
})
const sendLimiter = new RateLimiterMemory({
  points: 30,       // 30 sends
  duration: 60,     // per minute per tenant
  keyPrefix: 'wallet_send',
})

function rateLimit(limiter: RateLimiterMemory) {
  return async (req: any, res: any, next: any) => {
    try {
      await limiter.consume(req.tenant?.id || req.ip)
      next()
    } catch {
      res.status(429).json({ error: 'Rate limit exceeded. Try again shortly.' })
    }
  }
}

// ═══════════════════════════════════════
// STATIC ROUTES (must come before :agentId)
// ═══════════════════════════════════════

// ── GET /wallets/dashboard — Tenant wallet overview ──
walletRouter.get('/wallets/dashboard', async (req: any, res) => {
  const tenant: Tenant = req.tenant
  try {
    const ws = getWalletService()
    const dashboard = await ws.walletDashboard(tenant.id)
    res.json({ rail: 'nano', ...dashboard })
  } catch (e: any) {
    res.status(500).json({ error: e.message })
  }
})

// ── GET /wallets — List all wallets ──
walletRouter.get('/wallets', (req: any, res) => {
  const tenant: Tenant = req.tenant
  try {
    const ws = getWalletService()
    const wallets = ws.listWallets(tenant.id)
    res.json({
      wallets: wallets.map(w => ({
        agent_id: w.agent_id,
        nano_address: w.nano_address,
        status: w.status,
        balance_raw: w.balance_raw,
        created_at: w.created_at,
      })),
      count: wallets.length,
    })
  } catch (e: any) {
    res.status(500).json({ error: e.message })
  }
})

// ── POST /wallets/provision — Create wallet for agent ──
walletRouter.post('/wallets/provision', rateLimit(provisionLimiter), async (req: any, res) => {
  const tenant: Tenant = req.tenant
  try {
    const ws = getWalletService()
    const { agent_id } = req.body
    if (!agent_id) return res.status(400).json({ error: 'Required: agent_id' })

    const wallet = await ws.provisionWallet(tenant.id, agent_id)
    res.status(201).json({
      agent_id: wallet.agent_id,
      nano_address: wallet.nano_address,
      status: wallet.status,
      created_at: wallet.created_at,
      message: `Wallet provisioned. Fund ${wallet.nano_address} to start transacting. Zero fees.`,
    })
  } catch (e: any) {
    res.status(500).json({ error: e.message })
  }
})

// ── POST /wallets/send — Delegation-gated send ──
walletRouter.post('/wallets/send', rateLimit(sendLimiter), async (req: any, res) => {
  const tenant: Tenant = req.tenant
  try {
    const ws = getWalletService()
    const { from_agent_id, to_address, to_agent_id } = req.body
    if (!from_agent_id || !to_address) {
      return res.status(400).json({
        error: 'Required: from_agent_id, to_address, and amount_raw or amount_xno',
      })
    }
    // Day 268 lifecycle: one payment per key. A retry with the same key returns the same operation.
    const idempotencyKey = req.get('Idempotency-Key')
    if (!idempotencyKey) return res.status(400).json({ error: 'Required header: Idempotency-Key' })
    const amount = parseSendAmount(req.body)
    if ('error' in amount) return res.status(400).json({ error: amount.error })

    let resolvedAddress = to_address
    if (to_agent_id && !to_address.startsWith('nano_')) {
      const targetWallet = ws.getWallet(tenant.id, to_agent_id)
      if (targetWallet) resolvedAddress = targetWallet.nano_address
    }
    try { addressToPublicKey(resolvedAddress) } catch {
      return res.status(400).json({ error: `Invalid Nano address: ${resolvedAddress}` })
    }

    const runner = getOpRunner()
    const r = await ws.reserveSendOp({
      tenantId: tenant.id, fromAgentId: from_agent_id, toAddress: resolvedAddress, amountRaw: amount.raw,
      idempotencyKey, claim: { owner: runner.owner, now: runner.now(), leaseMs: runner.leaseMs },
      notReady: runner.readiness(),
    })
    if ('denied' in r) {
      // 503 when the lifecycle is not ready, so a client retries later. 403 for every other denial.
      return res.status(r.notReady ? 503 : 403).json({ status: 'denied', transaction_id: r.denied.id, denial_reason: r.denied.denial_reason || null })
    }
    if (!r.replay) runner.schedule(r.op.id)
    // 202: the payment is reserved. It is not sent or confirmed until GET /wallets/ops/:id says so.
    res.status(202).json(opView(r.op, r.replay))
  } catch (e: any) {
    if (e instanceof WalletOpError) {
      const code = e.code === 'bad_request' ? 400 : 409
      return res.status(code).json({ error: e.code, message: e.message })
    }
    res.status(500).json({ error: e.message })
  }
})

// ── GET /wallets/ops/:id — one lifecycle operation, as the database has it ──
walletRouter.get('/wallets/ops/:id', (req: any, res) => {
  const tenant: Tenant = req.tenant
  const op = getOp(getDB(), req.params.id)
  if (!op || op.tenant_id !== tenant.id) return res.status(404).json({ error: 'not_found' })
  res.json(opView(op, false))
})

function opView(op: WalletOp, replay: boolean) {
  return {
    operation_id: op.id,
    kind: op.kind,
    status: op.status,
    replay,
    from_agent_id: op.from_agent_id,
    to_address: op.to_address,
    amount_raw: op.amount_raw,
    block_hash: op.block_hash,
    attempts: op.attempt_count,
    resolution: op.status === 'confirmed' || op.status === 'failed_final' ? JSON.parse(op.resolution ?? 'null') : null,
    cancel_reason: op.cancel_reason,
  }
}

// ═══════════════════════════════════════
// PARAMETERIZED ROUTES (:agentId)
// ═══════════════════════════════════════

// ── GET /wallets/:agentId/balance — Live on-chain balance ──
walletRouter.get('/wallets/:agentId/balance', async (req: any, res) => {
  const tenant: Tenant = req.tenant
  try {
    const ws = getWalletService()
    const balance = await ws.getBalance(tenant.id, req.params.agentId)
    res.json({ agent_id: req.params.agentId, ...balance })
  } catch (e: any) {
    res.status(404).json({ error: e.message })
  }
})

// ── POST /wallets/:agentId/receive — Pocket pending funds ──
walletRouter.post('/wallets/:agentId/receive', async (_req: any, res) => {
  // Day 268 lifecycle: receives are not on wallet_ops routes yet, and the old receive path is closed.
  res.status(503).json({ error: 'receive_not_available', message: 'receive is not on the Nano lifecycle yet: nothing was signed or published' })
})

// ── GET /wallets/:agentId/txs — Transaction history ──
walletRouter.get('/wallets/:agentId/txs', (req: any, res) => {
  const tenant: Tenant = req.tenant
  try {
    const ws = getWalletService()
    const limit = parseInt(req.query.limit as string) || 50
    const txs = ws.getTransactions(tenant.id, req.params.agentId, limit)
    res.json({ agent_id: req.params.agentId, transactions: txs, count: txs.length })
  } catch (e: any) {
    res.status(500).json({ error: e.message })
  }
})

// ── POST /wallets/:agentId/freeze — Freeze wallet ──
walletRouter.post('/wallets/:agentId/freeze', (req: any, res) => {
  const tenant: Tenant = req.tenant
  try {
    const ws = getWalletService()
    ws.freezeWallet(tenant.id, req.params.agentId)
    res.json({ agent_id: req.params.agentId, status: 'frozen' })
  } catch (e: any) {
    res.status(500).json({ error: e.message })
  }
})

// ── POST /wallets/:agentId/unfreeze — Reactivate wallet ──
walletRouter.post('/wallets/:agentId/unfreeze', (req: any, res) => {
  const tenant: Tenant = req.tenant
  try {
    const ws = getWalletService()
    const unfrozen = ws.unfreezeWallet(tenant.id, req.params.agentId)
    if (!unfrozen) {
      return res.status(404).json({ error: 'No frozen wallet found for this agent' })
    }
    res.json({ agent_id: req.params.agentId, status: 'active' })
  } catch (e: any) {
    res.status(500).json({ error: e.message })
  }
})
