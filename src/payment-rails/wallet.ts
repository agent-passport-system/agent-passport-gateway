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

import { rawToXno } from './nano.js'
import { getDB } from '../db/schema.js'
import { NanoLocalWallet, NanoSendNotBroadcastError, getLocalWallet, deriveAddress, getMasterSeed } from './wallet-crypto.js'
import { checkBoundAuthorityChain } from '../gateway/enforce.js'
import { boundChainSpendRows, chainSpendHold } from '../gateway/chain-spend.js'
import { XNO_RAW, applyUnitSpend, parseMinor, rawToExactXno, unitChainRows, unitSpendViolation } from '../gateway/spend-units.js'
import type { UnitRow } from '../gateway/spend-units.js'

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
    /** Canonical decimal integer string of raw XNO. The one amount checked, debited and sent. */
    amountRaw: string
    toAgentId?: string           // if sending to another APS agent
    memo?: string
  }): Promise<WalletTransaction> {
    const db = getDB()
    const txId = randomUUID()
    // Day 268: the caller passes raw XNO as a canonical string (see parseSendAmount). Anything
    // else is refused before any gate, so a rounded or malformed amount can never be debited or sent.
    const amountRaw = parseMinor(opts.amountRaw) !== null && opts.amountRaw !== '0' ? opts.amountRaw : null
    if (amountRaw === null) {
      return this.recordDenied(txId, { ...opts, amountRaw: '0' }, '0', 'amount_raw_not_canonical_positive')
    }
    const amountXnoText = rawToExactXno(amountRaw)

    // 0.4.3: Nano sends are off unless the operator opts in. Delegation spend limits are
    // created in USD and this route debits XNO against the same counter, so a limit does
    // not mean the same amount here. Until budgets carry their own unit, sending needs
    // NANO_WALLET_SEND_ENABLED=1 and an operator who has accepted that.
    // The operator pause wins over the enable flag.
    if (process.env.NANO_WALLETS_PAUSED === '1') {
      return this.recordDenied(txId, opts, amountRaw,
        'Nano wallets are paused by the operator (NANO_WALLETS_PAUSED=1).')
    }
    if (process.env.NANO_WALLET_SEND_ENABLED !== '1') {
      return this.recordDenied(txId, opts, amountRaw,
        'Nano wallet send is disabled by default: delegation limits are in USD and this route debits XNO. Set NANO_WALLET_SEND_ENABLED=1 to enable it.')
    }

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

    // ── Gate 2b (Day 268): the delegation's whole bound chain must still be authoritative ──
    // A revoked, suspended or frozen grantor anywhere up the chain ends this send, the same
    // rule /evaluate applies.
    const chainCheck = checkBoundAuthorityChain(db, opts.tenantId, delegation.id)
    if (!chainCheck.ok) {
      return this.recordDenied(txId, opts, amountRaw,
        `Delegation authority chain is invalid (code=${chainCheck.code}, hop=${chainCheck.hop})`)
    }
    // ── Gate 3: exact budget check and debit, in raw XNO (Day 268, explicit units) ──
    // The send must fit the delegation and every bounded ancestor on its bound chain, each declared
    // in nano:XNO:raw. A legacy row with a REAL limit has no proven unit and refuses the send. Amounts
    // are BigInt raw, so nothing is rounded and nothing is converted from USD. The upgrade hold
    // (gateway/chain-spend.ts) still applies. One IMMEDIATE transaction, so concurrent sends cannot
    // both pass against the same remaining budget.
    const amount = BigInt(amountRaw)
    let unitRows: UnitRow[] | null = null
    let spendRefusal = 'spend_refused'
    const spendCheckPassed = db.transaction(() => {
      const rows = unitChainRows(db, opts.tenantId, delegation.id)
      if (!rows) { spendRefusal = 'delegation_chain_unreadable'; return false }
      const holdRows = boundChainSpendRows(db, opts.tenantId, delegation.id)
      if (!holdRows || chainSpendHold(db, holdRows)) { spendRefusal = 'chain_on_upgrade_hold'; return false }
      const violation = unitSpendViolation(rows, XNO_RAW, amount)
      if (violation) { spendRefusal = violation; return false }
      applyUnitSpend(db, rows, amount)
      unitRows = rows
      return true
    }).immediate()

    if (!spendCheckPassed) {
      return this.recordDenied(txId, opts, amountRaw, `Send refused: ${spendRefusal} (amount ${amountRaw} raw XNO)`)
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
        amount_xno: amountXnoText,
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
          amountRaw, amountXnoText, result.blockHash,
          delegation.id, 'commerce:send')
      try { getEventBus().emit(opts.tenantId, { type: 'wallet_transaction', agentId: opts.fromAgentId, data: { tx_id: txId, direction: 'send', amount_xno: amountXnoText, status: 'confirmed' } }) } catch {}

      return tx

    } catch (e: any) {
      if (!(e instanceof NanoSendNotBroadcastError)) {
        // Day 268: the error came during or after publishing, so the block may still be
        // accepted. The debit stays on every chain row and the transaction is recorded as
        // pending with the reason, for reconciliation. Releasing the budget here could let
        // a second send go out while the first one settles.
        db.prepare(`INSERT INTO wallet_transactions
          (id, tenant_id, from_agent_id, to_address, amount_raw, amount_xno,
           delegation_id, scope_used, status, denial_reason)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)`)
          .run(txId, opts.tenantId, opts.fromAgentId, opts.toAddress,
            amountRaw, amountXnoText, delegation.id,
            'commerce:send', `outcome_unknown: ${e?.message ?? String(e)}`)
        try { getEventBus().emit(opts.tenantId, { type: 'wallet_transaction', agentId: opts.fromAgentId, data: { tx_id: txId, direction: 'send', amount_xno: amountXnoText, status: 'pending' } }) } catch {}
        return {
          id: txId, tenant_id: opts.tenantId,
          from_agent_id: opts.fromAgentId,
          to_address: opts.toAddress,
          amount_raw: amountRaw, amount_xno: amountXnoText,
          status: 'pending' as const, denial_reason: `outcome_unknown: ${e?.message ?? String(e)}`,
          created_at: new Date().toISOString(),
        }
      }
      // Nothing was published: reverse the debit on every chain row, exactly.
      // unitRows is always set here: this path runs only after the transaction above debited it.
      const debited = unitRows as UnitRow[] | null
      if (debited) db.transaction(() => applyUnitSpend(db, debited, -amount)).immediate()

      db.prepare(`INSERT INTO wallet_transactions
        (id, tenant_id, from_agent_id, to_address, amount_raw, amount_xno,
         delegation_id, scope_used, status, denial_reason)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'failed', ?)`)
        .run(txId, opts.tenantId, opts.fromAgentId, opts.toAddress,
          amountRaw, amountXnoText, delegation.id,
          'commerce:send', e.message)
      try { getEventBus().emit(opts.tenantId, { type: 'wallet_transaction', agentId: opts.fromAgentId, data: { tx_id: txId, direction: 'send', amount_xno: amountXnoText, status: 'failed' } }) } catch {}

      return {
        id: txId, tenant_id: opts.tenantId,
        from_agent_id: opts.fromAgentId,
        to_address: opts.toAddress,
        amount_raw: amountRaw, amount_xno: amountXnoText,
        status: 'failed' as const, denial_reason: e.message,
        created_at: new Date().toISOString(),
      }
    }
  }

  /** Record a denied transaction */
  private recordDenied(
    txId: string,
    opts: { tenantId: string; fromAgentId: string; toAddress: string; amountRaw: string },
    amountRaw: string,
    reason: string,
  ): WalletTransaction {
    const db = getDB()
    const amountXnoText = rawToExactXno(amountRaw)
    db.prepare(`INSERT INTO wallet_transactions
      (id, tenant_id, from_agent_id, to_address, amount_raw, amount_xno,
       status, denial_reason)
      VALUES (?, ?, ?, ?, ?, ?, 'denied', ?)`)
      .run(txId, opts.tenantId, opts.fromAgentId, opts.toAddress,
        amountRaw, amountXnoText, reason)
    try { getEventBus().emit(opts.tenantId, { type: 'wallet_transaction', agentId: opts.fromAgentId, data: { tx_id: txId, direction: 'send', amount_xno: amountXnoText, status: 'denied', reason } }) } catch {}

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
      amount_raw: amountRaw, amount_xno: amountXnoText,
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
