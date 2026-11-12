// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Nano Payment Rail — AEOESS Gateway Adapter
 *
 * Feeless, instant, Layer 1. Perfect for agent micro-transactions.
 * Uses Nano JSON-RPC via public node (reads) and optional
 * wallet-enabled node (sends).
 *
 * Nano units: 1 XNO = 10^30 raw.
 * All internal amounts stored in raw (string) to avoid floating point.
 *
 * RPC docs: https://docs.nano.org/commands/rpc-protocol/
 */

import { randomUUID } from 'node:crypto'
import type { PaymentRail, PaymentInvoice, PaymentConfirmation } from './types.js'
import { nanoRpc } from './rpc-client.js'
import { getLocalWallet } from './wallet-crypto.js'

/** The refusal sendPayment raises before doing anything. */
export const SETTLEMENT_PAYOUT_CLOSED = 'Nano settlement payouts are closed in this release: nothing was signed or published'

// ── Unit Conversion ──

const RAW_PER_XNO = BigInt('1000000000000000000000000000000') // 10^30

export function xnoToRaw(xno: string | number): string {
  // Handle decimal XNO amounts → raw (integer string)
  const parts = String(xno).split('.')
  const whole = BigInt(parts[0] || '0') * RAW_PER_XNO
  if (!parts[1]) return whole.toString()
  // Pad decimal to 30 places, then add
  const decStr = parts[1].padEnd(30, '0').slice(0, 30)
  return (whole + BigInt(decStr)).toString()
}

export function rawToXno(raw: string): string {
  const bigRaw = BigInt(raw)
  const whole = bigRaw / RAW_PER_XNO
  const frac = bigRaw % RAW_PER_XNO
  if (frac === 0n) return whole.toString()
  const fracStr = frac.toString().padStart(30, '0').replace(/0+$/, '')
  return `${whole}.${fracStr}`
}

// ── Nano RPC Client ──

interface NanoRpcConfig {
  /** Public node URL for reads (e.g. https://proxy.nanos.cc/proxy) */
  rpcUrl: string
  /** Wallet-enabled node URL for sends (optional, requires enable_control) */
  sendRpcUrl?: string
  /** Wallet ID on the send node */
  walletId?: string
  /** Gateway's receiving Nano address */
  receivingAddress: string
  /** Source account address for outbound sends (must be in wallet) */
  sendingAddress?: string
}

// ── Invoice Store (in-memory, backed by DB in routes) ──

const pendingInvoices = new Map<string, PaymentInvoice & { expectedRaw: string }>()

// ── Nano Payment Rail Implementation ──

export class NanoPaymentRail implements PaymentRail {
  readonly name = 'nano'
  readonly currency = 'XNO'
  private config: NanoRpcConfig

  constructor(config: NanoRpcConfig) {
    this.config = config
  }

  /**
   * Create a payment invoice.
   * Uses amount-uniqueness: base amount + random raw offset (1-9999)
   * so each invoice has a distinguishable on-chain fingerprint.
   */
  async createInvoice(opts: {
    amount: number         // in XNO (human units, e.g. 0.001)
    settlementId?: string
    agentId?: string
    memo?: string
    expiresInSeconds?: number
  }): Promise<PaymentInvoice> {
    const baseRaw = BigInt(xnoToRaw(String(opts.amount)))
    // Add random offset (1-9999 raw) for uniqueness — negligible value
    const offset = BigInt(Math.floor(Math.random() * 9999) + 1)
    const uniqueRaw = (baseRaw + offset).toString()

    const invoiceId = randomUUID()
    const now = new Date()
    const expiresAt = opts.expiresInSeconds
      ? new Date(now.getTime() + opts.expiresInSeconds * 1000).toISOString()
      : new Date(now.getTime() + 3600_000).toISOString() // 1hr default

    const invoice: PaymentInvoice & { expectedRaw: string } = {
      invoiceId,
      rail: 'nano',
      amount: opts.amount,
      amountHuman: `${rawToXno(uniqueRaw)} XNO`,
      currency: 'XNO',
      destination: this.config.receivingAddress,
      memo: opts.memo || opts.settlementId || undefined,
      status: 'pending',
      createdAt: now.toISOString(),
      expiresAt,
      metadata: {
        settlementId: opts.settlementId,
        agentId: opts.agentId,
        amountRaw: uniqueRaw,
      },
      expectedRaw: uniqueRaw,
    }

    pendingInvoices.set(invoiceId, invoice)
    return invoice
  }

  /**
   * Check invoice status by polling account history for matching amount.
   */
  async checkStatus(invoiceId: string): Promise<PaymentInvoice> {
    let invoice = pendingInvoices.get(invoiceId)

    // Fallback: reconstruct from DB if not in memory (e.g. after restart)
    if (!invoice) {
      try {
        // Import lazily to avoid circular deps
        const { getDB } = await import('../db/schema.js')
        const db = getDB()
        const row = db.prepare(
          `SELECT * FROM payment_transactions WHERE id = ? AND rail = 'nano'`
        ).get(invoiceId) as any
        if (row?.invoice_data) {
          const stored = JSON.parse(row.invoice_data)
          invoice = { ...stored, expectedRaw: stored.metadata?.amountRaw || '0' }
          pendingInvoices.set(invoiceId, invoice as any)
        }
      } catch { /* DB not available in standalone mode */ }
    }

    if (!invoice) throw new Error(`Invoice ${invoiceId} not found`)

    // Already confirmed or expired
    if (invoice.status !== 'pending') return invoice

    // Check expiry
    if (invoice.expiresAt && new Date(invoice.expiresAt) < new Date()) {
      invoice.status = 'expired'
      return invoice
    }

    // Poll account history for matching receive
    try {
      const history = await nanoRpc(this.config.rpcUrl, {
        action: 'account_history',
        account: this.config.receivingAddress,
        count: '50',
      })

      if (history.history) {
        for (const block of history.history) {
          // Look for receive/open blocks with matching amount
          if ((block.type === 'receive' || block.subtype === 'receive')
            && block.amount === invoice.expectedRaw) {
            invoice.status = 'confirmed'
            invoice.metadata.blockHash = block.hash
            invoice.metadata.sender = block.account
            invoice.metadata.confirmedAt = new Date().toISOString()
            invoice.metadata.confirmationTimeMs =
              Date.now() - new Date(invoice.createdAt).getTime()
            break
          }
        }
      }
    } catch (e: any) {
      // RPC failure is non-fatal — invoice stays pending
      console.error('Nano RPC poll error:', e.message)
    }

    return invoice
  }

  /**
   * Send payment from gateway wallet (outbound settlement).
   * Uses local key derivation + signing via NanoLocalWallet.
   * Gateway wallet = index 0 of the master seed.
   */
  async sendPayment(opts: {
    destination: string
    amount: number        // in XNO
    memo?: string
  }): Promise<PaymentConfirmation> {
    // Settlement payouts publish from the gateway's own account and are closed with the rest of
    // the legacy publish path. Refused before any key is derived or any node is called.
    void opts
    throw new Error(SETTLEMENT_PAYOUT_CLOSED)
  }

  /**
   * Verify an on-chain Nano transaction by block hash.
   */
  async verifyTransaction(txProof: string, expectedAmount?: number): Promise<{
    verified: boolean
    amount: number
    sender?: string
    receiver?: string
    timestamp?: string
    error?: string
  }> {
    try {
      const blockInfo = await nanoRpc(this.config.rpcUrl, {
        action: 'block_info',
        json_block: 'true',
        hash: txProof,
      })

      const amountXno = parseFloat(rawToXno(blockInfo.amount || '0'))
      const verified = blockInfo.confirmed === 'true'
        && (!expectedAmount || Math.abs(amountXno - expectedAmount) < 0.000001)

      return {
        verified,
        amount: amountXno,
        sender: blockInfo.block_account,
        receiver: blockInfo.contents?.link_as_account,
        timestamp: blockInfo.local_timestamp
          ? new Date(parseInt(blockInfo.local_timestamp) * 1000).toISOString()
          : undefined,
      }
    } catch (e: any) {
      return { verified: false, amount: 0, error: e.message }
    }
  }

  /**
   * Check gateway wallet balance.
   */
  async getBalance(): Promise<{ balance: string; receivable: string; balanceXno: string }> {
    const result = await nanoRpc(this.config.rpcUrl, {
      action: 'account_balance',
      account: this.config.receivingAddress,
    })
    return {
      balance: result.balance,
      receivable: result.receivable || result.pending || '0',
      balanceXno: rawToXno(result.balance),
    }
  }

  /**
   * Get recent transaction history for the gateway address.
   */
  async getHistory(count: number = 20): Promise<any[]> {
    const result = await nanoRpc(this.config.rpcUrl, {
      action: 'account_history',
      account: this.config.receivingAddress,
      count: String(count),
    })
    return (result.history || []).map((tx: any) => ({
      hash: tx.hash,
      type: tx.type || tx.subtype,
      account: tx.account,
      amountRaw: tx.amount,
      amountXno: rawToXno(tx.amount || '0'),
      timestamp: tx.local_timestamp
        ? new Date(parseInt(tx.local_timestamp) * 1000).toISOString()
        : undefined,
    }))
  }

  /**
   * Poll all pending invoices and update their status.
   * Call this on a timer (e.g. every 5 seconds).
   */
  async pollPendingInvoices(): Promise<{ checked: number; confirmed: number }> {
    let confirmed = 0
    const pending = [...pendingInvoices.values()].filter(i => i.status === 'pending')
    for (const inv of pending) {
      await this.checkStatus(inv.invoiceId)
      if (inv.status === 'confirmed') confirmed++
    }
    return { checked: pending.length, confirmed }
  }
}

// ── Factory ──

export function createNanoRail(opts: {
  rpcUrl?: string
  sendRpcUrl?: string
  walletId?: string
  receivingAddress: string
  sendingAddress?: string
}): NanoPaymentRail {
  return new NanoPaymentRail({
    rpcUrl: opts.rpcUrl || 'https://rpc.nano.to',
    sendRpcUrl: opts.sendRpcUrl,
    walletId: opts.walletId,
    receivingAddress: opts.receivingAddress,
    sendingAddress: opts.sendingAddress,
  })
}

// ── Singleton (configured via env) ──

let _instance: NanoPaymentRail | null = null

export function getNanoRail(): NanoPaymentRail {
  if (!_instance) {
    const addr = process.env.NANO_RECEIVING_ADDRESS
    if (!addr) throw new Error('NANO_RECEIVING_ADDRESS env var required')
    _instance = createNanoRail({
      rpcUrl: process.env.NANO_RPC_URL || 'https://rpc.nano.to',
      sendRpcUrl: process.env.NANO_SEND_RPC_URL,
      walletId: process.env.NANO_WALLET_ID,
      receivingAddress: addr,
      sendingAddress: process.env.NANO_SENDING_ADDRESS,
    })
  }
  return _instance
}
