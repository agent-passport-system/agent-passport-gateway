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
    const { from_agent_id, to_address, to_agent_id, memo } = req.body
    if (!from_agent_id || !to_address) {
      return res.status(400).json({
        error: 'Required: from_agent_id, to_address, and amount_raw or amount_xno',
      })
    }
    // Day 268: one exact raw amount from the request, used for the check, the debit and the send.
    const amount = parseSendAmount(req.body)
    if ('error' in amount) return res.status(400).json({ error: amount.error })

    // Resolve destination: agent_id → nano address, or validate raw address
    let resolvedAddress = to_address
    if (to_agent_id && !to_address.startsWith('nano_')) {
      const targetWallet = ws.getWallet(tenant.id, to_agent_id)
      if (targetWallet) resolvedAddress = targetWallet.nano_address
    }

    // Bug #14 fix: validate Nano address format
    if (!resolvedAddress.startsWith('nano_') || resolvedAddress.length !== 65) {
      return res.status(400).json({ error: `Invalid Nano address: ${resolvedAddress}` })
    }

    const tx = await ws.send({
      tenantId: tenant.id,
      fromAgentId: from_agent_id,
      toAddress: resolvedAddress,
      amountRaw: amount.raw,
      toAgentId: to_agent_id,
      memo,
    })

    const statusCode = tx.status === 'denied' ? 403 : tx.status === 'failed' ? 500 : 200
    res.status(statusCode).json({
      transaction_id: tx.id,
      status: tx.status,
      block_hash: tx.block_hash || null,
      amount_xno: tx.amount_xno,
      from: from_agent_id,
      to: resolvedAddress,
      delegation_id: tx.delegation_id || null,
      denial_reason: tx.denial_reason || null,
    })
  } catch (e: any) {
    res.status(500).json({ error: e.message })
  }
})

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
walletRouter.post('/wallets/:agentId/receive', async (req: any, res) => {
  const tenant: Tenant = req.tenant
  try {
    const ws = getWalletService()
    const result = await ws.receiveAll(tenant.id, req.params.agentId)
    res.json({
      agent_id: req.params.agentId,
      received_count: result.received,
      blocks: result.blocks,
    })
  } catch (e: any) {
    res.status(404).json({ error: e.message })
  }
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
