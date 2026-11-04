// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Agent Wallet Service — APS-Native Nano Wallets
 *
 * Every agent with a passport gets a Nano wallet.
 * Spending is delegation-scoped. Every tx produces a signed receipt.
 * Feeless. Instant. Tied to cryptographic identity.
 *
 * Competitive landscape:
 *   ChainHop: 0.75% per tx, no identity governance
 *   Coinbase Agentic Wallets: gas fees, EVM-only, x402 protocol
 *   APS Wallets: 0% fees (Nano L1), delegation-scoped, receipt-linked
 *
 * Architecture:
 *   Master seed → HD derivation → one Nano address per agent
 *   Agent index = row in agent_wallets table
 *   Gateway is custodial — agents interact via authenticated API
 *   All sends gated by delegation scope + spend limits
 */

import { randomUUID } from 'node:crypto'
import { getEventBus } from '../gateway/events.js'

// ── Types ──

export interface AgentWallet {
  id: string
  tenant_id: string
  agent_id: string
  nano_address: string
  wallet_index: number           // position in HD derivation
  status: 'active' | 'frozen' | 'revoked'
  balance_raw: string            // last known balance in raw
  total_received_raw: string
  total_sent_raw: string
  created_at: string
}

export interface WalletTransaction {
  id: string
  tenant_id: string
  from_agent_id: string
  to_agent_id?: string           // null if external
  to_address: string
  amount_raw: string
  amount_xno: string
  block_hash?: string
  delegation_id?: string         // which delegation authorized this
  scope_used?: string
  evaluation_id?: string         // linked gateway evaluation
  status: 'pending' | 'confirmed' | 'failed' | 'denied'
  denial_reason?: string
  created_at: string
  confirmed_at?: string
}

// ── Wallet Service ──

import { xnoToRaw, rawToXno } from './nano.js'
import { getDB } from '../db/schema.js'
import { toCents } from '../billing/money.js'
import { NanoLocalWallet, getLocalWallet, deriveAddress, getMasterSeed } from './wallet-crypto.js'

// Dynamic import for SDK scope matching (ESM)
let _scopeAuthorizes: ((scopes: string[], required: string) => boolean) | null = null
async function loadScopeAuthorizes() {
  if (!_scopeAuthorizes) {
    const sdk = await import('agent-passport-system')
    _scopeAuthorizes = sdk.scopeAuthorizes
  }
  return _scopeAuthorizes
}

export class AgentWalletService {
  private localWallet: NanoLocalWallet

  constructor(opts?: { localWallet?: NanoLocalWallet }) {
    this.localWallet = opts?.localWallet || getLocalWallet()
  }

  /**
   * Provision a new Nano wallet for an agent.
   *
   * Sybil defense (4-gate pipeline):
   *   Gate 1: Agent must be registered with a public key
   *   Gate 2: Agent must have an active delegation (someone vouched for them)
   *   Gate 3: publicKey dedup — same key can't get multiple wallets
   *   Gate 4: Anomaly rate — same principal can't mass-provision wallets
   */
  async provisionWallet(tenantId: string, agentId: string): Promise<AgentWallet> {
    const db = getDB()

    // Check if agent already has a wallet
    const existing = db.prepare(
      `SELECT * FROM agent_wallets WHERE tenant_id = ? AND agent_id = ?`
    ).get(tenantId, agentId) as AgentWallet | undefined
    if (existing) return existing

    // ── Sybil Gate 1: Agent must be registered ──
    const agent = db.prepare(
      `SELECT * FROM agents WHERE tenant_id = ? AND agent_id = ? AND status = 'active'`
    ).get(tenantId, agentId) as any
    if (!agent) {
      throw new Error(`Sybil gate: agent "${agentId}" is not registered. Register first via POST /agents.`)
    }

    // ── Sybil Gate 2: Agent must have active delegation ──
    // A delegation means a known principal vouched for this agent
    const delegation = db.prepare(
      `SELECT * FROM delegations WHERE tenant_id = ? AND child_agent_id = ? AND status = 'active' LIMIT 1`
    ).get(tenantId, agentId) as any
    if (!delegation) {
      throw new Error(`Sybil gate: agent "${agentId}" has no active delegation. A principal must delegate authority before wallet provisioning.`)
    }

    // ── Sybil Gate 3: publicKey dedup ──
    // Same public key can't get wallets under different agent_ids WITHIN THIS TENANT
    if (agent.public_key) {
      const keyDupe = db.prepare(
        `SELECT aw.agent_id FROM agent_wallets aw
         JOIN agents a ON aw.tenant_id = a.tenant_id AND aw.agent_id = a.agent_id
         WHERE aw.tenant_id = ? AND a.public_key = ? AND aw.agent_id != ?`
      ).get(tenantId, agent.public_key, agentId) as any
      if (keyDupe) {
        db.prepare(`INSERT INTO alerts (id, tenant_id, alert_type, severity, message)
          VALUES (?, ?, ?, ?, ?)`)
          .run(randomUUID(), tenantId, 'sybil_key_reuse', 'critical',
            `publicKey dedup: "${agentId}" shares key with "${keyDupe.agent_id}"`)
        try { getEventBus().emit(tenantId, { type: 'alert', agentId, data: { alert_type: 'sybil_key_reuse', severity: 'critical' } }) } catch {}
        throw new Error(`Sybil gate: this public key already has a wallet under agent "${keyDupe.agent_id}".`)
      }
    }

    // ── Sybil Gate 4: Anomaly rate — same principal can't mass-provision ──
    const principalId = delegation.parent_agent_id
    const recentProvisions = db.prepare(
      `SELECT COUNT(*) as c FROM agent_wallets aw
       JOIN delegations d ON aw.tenant_id = d.tenant_id AND aw.agent_id = d.child_agent_id
       WHERE d.tenant_id = ? AND d.parent_agent_id = ? AND aw.created_at > datetime('now', '-1 hour')`
    ).get(tenantId, principalId) as any
    if (recentProvisions.c >= 5) {
      db.prepare(`INSERT INTO alerts (id, tenant_id, alert_type, severity, message)
        VALUES (?, ?, ?, ?, ?)`)
        .run(randomUUID(), tenantId, 'sybil_mass_provision', 'critical',
          `Principal "${principalId}" provisioned ${recentProvisions.c} wallets in 1hr. Possible farming.`)
      try { getEventBus().emit(tenantId, { type: 'alert', agentId, data: { alert_type: 'sybil_mass_provision', severity: 'critical' } }) } catch {}
      throw new Error(`Sybil gate: principal "${principalId}" has provisioned too many wallets recently. Max 5 per hour.`)
    }

    // Atomic wallet creation — prevents index collision under concurrent requests
    const createWallet = db.transaction(() => {
      const maxIdx = db.prepare(
        `SELECT MAX(wallet_index) as mx FROM agent_wallets`
      ).get() as any
      // Index 0 is the gateway's own wallet (nano.ts settles from index 0), so agent
      // wallets start at 1 and never share an account with the gateway.
      const walletIndex = Math.max(maxIdx?.mx ?? 0, 0) + 1

      const seed = getMasterSeed()
      const derived = deriveAddress(seed, walletIndex)
      const nanoAddress = derived.address

      const id = randomUUID()
      db.prepare(`INSERT INTO agent_wallets
        (id, tenant_id, agent_id, nano_address, wallet_index, status,
         balance_raw, total_received_raw, total_sent_raw)
        VALUES (?, ?, ?, ?, ?, 'active', '0', '0', '0')`)
        .run(id, tenantId, agentId, nanoAddress, walletIndex)

      return {
        id, tenant_id: tenantId, agent_id: agentId,
        nano_address: nanoAddress, wallet_index: walletIndex,
        status: 'active' as const, balance_raw: '0',
        total_received_raw: '0', total_sent_raw: '0',
        created_at: new Date().toISOString(),
      } as AgentWallet
    })

    const wallet = createWallet()
    try { getEventBus().emit(tenantId, { type: 'wallet_provisioned', agentId, data: { wallet_id: wallet.id, nano_address: wallet.nano_address } }) } catch {}
    return wallet
  }

  /**
   * Get live balance from the Nano network.
   */
  async getBalance(tenantId: string, agentId: string): Promise<{
    balance_raw: string
    balance_xno: string
    receivable_raw: string
    receivable_xno: string
    nano_address: string
  }> {
    const db = getDB()
    const wallet = db.prepare(
      `SELECT * FROM agent_wallets WHERE tenant_id = ? AND agent_id = ? AND status = 'active'`
    ).get(tenantId, agentId) as AgentWallet | undefined
    if (!wallet) throw new Error(`No active wallet for agent "${agentId}"`)

    const result = await this.localWallet.getBalance(wallet.nano_address)

    // Update cached balance
    db.prepare(`UPDATE agent_wallets SET balance_raw = ? WHERE id = ?`)
      .run(result.balance, wallet.id)

    return {
      balance_raw: result.balance,
      balance_xno: rawToXno(result.balance),
      receivable_raw: '0',
      receivable_xno: '0',
      nano_address: wallet.nano_address,
    }
  }

  /**
   * Delegation-gated send. The core differentiator.
   *
   * Before any XNO leaves an agent's wallet:
   *   1. Agent must have active wallet (not frozen/revoked)
   *   2. Agent must have active delegation with commerce:* scope
   *   3. Amount must be within delegation spend limit
   *   4. Gateway records evaluation + receipt
   *
   * Returns block hash as on-chain proof.
   */
  async send(opts: {
    tenantId: string
    fromAgentId: string
    toAddress: string
    amountXno: number
    toAgentId?: string           // if sending to another APS agent
    memo?: string
  }): Promise<WalletTransaction> {
    const db = getDB()
    const amountRaw = xnoToRaw(String(opts.amountXno))
    const txId = randomUUID()

    // ── Gate 1: Wallet exists and is active ──
    const wallet = db.prepare(
      `SELECT * FROM agent_wallets WHERE tenant_id = ? AND agent_id = ? AND status = 'active'`
    ).get(opts.tenantId, opts.fromAgentId) as AgentWallet | undefined
    if (!wallet) {
      return this.recordDenied(txId, opts, amountRaw, 'No active wallet for agent')
    }

    // ── Gate 2: Active delegation with commerce scope ──
    // Uses SDK scopeAuthorizes() — respects monotonic narrowing invariant
    const delegation = db.prepare(`
      SELECT * FROM delegations
      WHERE tenant_id = ? AND child_agent_id = ? AND status = 'active'
      ORDER BY created_at DESC LIMIT 1
    `).get(opts.tenantId, opts.fromAgentId) as any
    if (!delegation) {
      return this.recordDenied(txId, opts, amountRaw, 'No active delegation for agent')
    }

    const scopes = delegation.scope.split(',').map((s: string) => s.trim())
    const scopeAuth = await loadScopeAuthorizes()
    const hasCommerceScope = scopeAuth
      ? scopeAuth(scopes, 'commerce:send')
      : scopes.some((s: string) => s === '*' || s === 'commerce:*' || s === 'commerce:send')
    if (!hasCommerceScope) {
      return this.recordDenied(txId, opts, amountRaw,
        `Agent lacks commerce:send scope. Has: [${delegation.scope}]`)
    }

    // ── Gate 3: Atomic spend limit check + optimistic debit (C3: prevents TOCTOU) ──
    const spendCheckPassed = db.transaction(() => {
      const freshDel = db.prepare(`SELECT spend_limit, spend_used FROM delegations WHERE id = ? AND tenant_id = ?`).get(delegation.id, opts.tenantId) as any
      if (freshDel?.spend_limit) {
        const remaining = Math.round((freshDel.spend_limit - (freshDel.spend_used || 0)) * 1e6) / 1e6
        const amount = Math.round(opts.amountXno * 1e6) / 1e6
        if (amount > remaining) return false
      }
      // C4 dual-write: mirror to spend_used_cents. Note: this column treats
      // spend_used uniformly across rails — same convention as the REAL
      // column already does (i.e. XNO and USD both accumulate here). The
      // unit-confusion concern is pre-existing and will be addressed when
      // we introduce a per-rail spend_used column in Phase B.
      const incCents = toCents(opts.amountXno) || 0
      db.prepare(
        `UPDATE delegations
         SET spend_used = spend_used + ?,
             spend_used_cents = COALESCE(spend_used_cents, 0) + ?
         WHERE id = ?`
      ).run(opts.amountXno, incCents, delegation.id)
      return true
    }).immediate()

    if (!spendCheckPassed) {
      const remaining = Math.round((delegation.spend_limit - (delegation.spend_used || 0)) * 1e6) / 1e6
      return this.recordDenied(txId, opts, amountRaw,
        `Amount ${Math.round(opts.amountXno * 1e6) / 1e6} XNO exceeds remaining budget ${remaining} XNO`)
    }

    // ── Gate 4: Execute on-chain send ──
    try {
      const result = await this.localWallet.send(
        wallet.wallet_index, opts.toAddress, amountRaw
      )

      // Spend already debited atomically above

      // Update wallet totals
      const newSent = (BigInt(wallet.total_sent_raw) + BigInt(amountRaw)).toString()
      db.prepare(`UPDATE agent_wallets SET total_sent_raw = ? WHERE id = ?`)
        .run(newSent, wallet.id)

      // Record confirmed transaction
      const tx: WalletTransaction = {
        id: txId,
        tenant_id: opts.tenantId,
        from_agent_id: opts.fromAgentId,
        to_agent_id: opts.toAgentId,
        to_address: opts.toAddress,
        amount_raw: amountRaw,
        amount_xno: String(opts.amountXno),
        block_hash: result.blockHash,
        delegation_id: delegation.id,
        scope_used: 'commerce:send',
        status: 'confirmed',
        created_at: new Date().toISOString(),
        confirmed_at: new Date().toISOString(),
      }

      db.prepare(`INSERT INTO wallet_transactions
        (id, tenant_id, from_agent_id, to_agent_id, to_address,
         amount_raw, amount_xno, block_hash, delegation_id,
         scope_used, status, confirmed_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'confirmed', datetime('now'))`)
        .run(txId, opts.tenantId, opts.fromAgentId,
          opts.toAgentId || null, opts.toAddress,
          amountRaw, String(opts.amountXno), result.blockHash,
          delegation.id, 'commerce:send')
      try { getEventBus().emit(opts.tenantId, { type: 'wallet_transaction', agentId: opts.fromAgentId, data: { tx_id: txId, direction: 'send', amount_xno: opts.amountXno, status: 'confirmed' } }) } catch {}

      return tx

    } catch (e: any) {
      // Reverse the optimistic debit since on-chain send failed.
      // C4 dual-write: keep both columns in sync on the rollback.
      const reverseCents = toCents(opts.amountXno) || 0
      db.prepare(
        `UPDATE delegations
         SET spend_used = spend_used - ?,
             spend_used_cents = COALESCE(spend_used_cents, 0) - ?
         WHERE id = ?`
      ).run(opts.amountXno, reverseCents, delegation.id)

      db.prepare(`INSERT INTO wallet_transactions
        (id, tenant_id, from_agent_id, to_address, amount_raw, amount_xno,
         delegation_id, scope_used, status, denial_reason)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'failed', ?)`)
        .run(txId, opts.tenantId, opts.fromAgentId, opts.toAddress,
          amountRaw, String(opts.amountXno), delegation.id,
          'commerce:send', e.message)
      try { getEventBus().emit(opts.tenantId, { type: 'wallet_transaction', agentId: opts.fromAgentId, data: { tx_id: txId, direction: 'send', amount_xno: opts.amountXno, status: 'failed' } }) } catch {}

      return {
        id: txId, tenant_id: opts.tenantId,
        from_agent_id: opts.fromAgentId,
        to_address: opts.toAddress,
        amount_raw: amountRaw, amount_xno: String(opts.amountXno),
        status: 'failed' as const, denial_reason: e.message,
        created_at: new Date().toISOString(),
      }
    }
  }

  /** Record a denied transaction */
  private recordDenied(
    txId: string,
    opts: { tenantId: string; fromAgentId: string; toAddress: string; amountXno: number },
    amountRaw: string,
    reason: string,
  ): WalletTransaction {
    const db = getDB()
    db.prepare(`INSERT INTO wallet_transactions
      (id, tenant_id, from_agent_id, to_address, amount_raw, amount_xno,
       status, denial_reason)
      VALUES (?, ?, ?, ?, ?, ?, 'denied', ?)`)
      .run(txId, opts.tenantId, opts.fromAgentId, opts.toAddress,
        amountRaw, String(opts.amountXno), reason)
    try { getEventBus().emit(opts.tenantId, { type: 'wallet_transaction', agentId: opts.fromAgentId, data: { tx_id: txId, direction: 'send', amount_xno: opts.amountXno, status: 'denied', reason } }) } catch {}

    // Fire alert
    db.prepare(`INSERT INTO alerts (id, tenant_id, alert_type, severity, message)
      VALUES (?, ?, ?, ?, ?)`)
      .run(randomUUID(), opts.tenantId, 'wallet_denied', 'warning',
        `Wallet send DENIED for "${opts.fromAgentId}": ${reason}`)
    try { getEventBus().emit(opts.tenantId, { type: 'alert', agentId: opts.fromAgentId, data: { alert_type: 'wallet_denied', severity: 'warning', reason } }) } catch {}

    return {
      id: txId, tenant_id: opts.tenantId,
      from_agent_id: opts.fromAgentId,
      to_address: opts.toAddress,
      amount_raw: amountRaw, amount_xno: String(opts.amountXno),
      status: 'denied', denial_reason: reason,
      created_at: new Date().toISOString(),
    }
  }

  /**
   * Receive all pending funds for an agent's wallet.
   * Nano requires explicitly "pocketing" received blocks.
   */
  async receiveAll(tenantId: string, agentId: string): Promise<{
    received: number; blocks: string[]
  }> {
    const db = getDB()
    const wallet = db.prepare(
      `SELECT * FROM agent_wallets WHERE tenant_id = ? AND agent_id = ? AND status = 'active'`
    ).get(tenantId, agentId) as AgentWallet | undefined
    if (!wallet) throw new Error(`No active wallet for agent "${agentId}"`)

    // Local crypto: derive key, sign receive blocks, publish via public RPC
    const result = await this.localWallet.receive(wallet.wallet_index)

    // Update balance cache after receiving
    if (result.received > 0) {
      const info = await this.localWallet.getBalance(wallet.nano_address)
      db.prepare(`UPDATE agent_wallets SET balance_raw = ?, total_received_raw = ? WHERE id = ?`)
        .run(info.balance, info.balance, wallet.id)
    }

    return result
  }

  /**
   * Freeze a wallet — no sends allowed. Part of revocation cascade.
   * When an agent's delegation is revoked, their wallet freezes.
   */
  freezeWallet(tenantId: string, agentId: string): void {
    const db = getDB()
    db.prepare(`UPDATE agent_wallets SET status = 'frozen' WHERE tenant_id = ? AND agent_id = ?`)
      .run(tenantId, agentId)
    db.prepare(`INSERT INTO alerts (id, tenant_id, alert_type, severity, message)
      VALUES (?, ?, ?, ?, ?)`)
      .run(randomUUID(), tenantId, 'wallet_frozen', 'critical',
        `Wallet for agent "${agentId}" has been frozen`)
    try { getEventBus().emit(tenantId, { type: 'wallet_frozen', agentId, data: {} }) } catch {}
    try { getEventBus().emit(tenantId, { type: 'alert', agentId, data: { alert_type: 'wallet_frozen', severity: 'critical' } }) } catch {}
  }

  /** Revoke a wallet permanently */
  revokeWallet(tenantId: string, agentId: string): void {
    const db = getDB()
    db.prepare(`UPDATE agent_wallets SET status = 'revoked' WHERE tenant_id = ? AND agent_id = ?`)
      .run(tenantId, agentId)
  }

  /** Unfreeze a wallet — reactivate from frozen state only */
  unfreezeWallet(tenantId: string, agentId: string): boolean {
    const db = getDB()
    const result = db.prepare(
      `UPDATE agent_wallets SET status = 'active' WHERE tenant_id = ? AND agent_id = ? AND status = 'frozen'`
    ).run(tenantId, agentId)
    return result.changes > 0
  }

  /** Get wallet info */
  getWallet(tenantId: string, agentId: string): AgentWallet | undefined {
    const db = getDB()
    return db.prepare(
      `SELECT * FROM agent_wallets WHERE tenant_id = ? AND agent_id = ?`
    ).get(tenantId, agentId) as AgentWallet | undefined
  }

  /** Get transaction history for an agent */
  getTransactions(tenantId: string, agentId: string, limit: number = 50): WalletTransaction[] {
    const db = getDB()
    return db.prepare(`
      SELECT * FROM wallet_transactions
      WHERE tenant_id = ? AND (from_agent_id = ? OR to_agent_id = ?)
      ORDER BY created_at DESC LIMIT ?
    `).all(tenantId, agentId, agentId, limit) as WalletTransaction[]
  }

  /** List all wallets for a tenant */
  listWallets(tenantId: string): AgentWallet[] {
    const db = getDB()
    return db.prepare(
      `SELECT * FROM agent_wallets WHERE tenant_id = ? ORDER BY created_at DESC`
    ).all(tenantId) as AgentWallet[]
  }

  /** Dashboard: wallet summary for tenant */
  async walletDashboard(tenantId: string): Promise<{
    total_wallets: number
    active_wallets: number
    frozen_wallets: number
    total_transactions: number
    total_denied: number
    recent_transactions: WalletTransaction[]
  }> {
    const db = getDB()

    const total = db.prepare(`SELECT COUNT(*) as c FROM agent_wallets WHERE tenant_id = ?`).get(tenantId) as any
    const active = db.prepare(`SELECT COUNT(*) as c FROM agent_wallets WHERE tenant_id = ? AND status = 'active'`).get(tenantId) as any
    const frozen = db.prepare(`SELECT COUNT(*) as c FROM agent_wallets WHERE tenant_id = ? AND status = 'frozen'`).get(tenantId) as any
    const txTotal = db.prepare(`SELECT COUNT(*) as c FROM wallet_transactions WHERE tenant_id = ?`).get(tenantId) as any
    const denied = db.prepare(`SELECT COUNT(*) as c FROM wallet_transactions WHERE tenant_id = ? AND status = 'denied'`).get(tenantId) as any
    const recent = db.prepare(`SELECT * FROM wallet_transactions WHERE tenant_id = ? ORDER BY created_at DESC LIMIT 20`).all(tenantId) as WalletTransaction[]

    return {
      total_wallets: total.c,
      active_wallets: active.c,
      frozen_wallets: frozen.c,
      total_transactions: txTotal.c,
      total_denied: denied.c,
      recent_transactions: recent,
    }
  }
}

// ── Singleton ──

let _walletService: AgentWalletService | null = null

export function getWalletService(): AgentWalletService {
  if (!_walletService) {
    _walletService = new AgentWalletService()
  }
  return _walletService
}
