// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Gate 1 (Day 268): the locally recorded account state sends are built on.
 *
 * The node's account_info is not trusted on its own. An operator records a verified frontier and
 * balance for a wallet's account before its first send (initializeWalletFrontier). A send is
 * prepared only when the node's confirmed frontier and balance equal this record, and the record
 * advances only when the gateway confirms the block it built on it (advanceFrontier, in the same
 * transaction as the confirmation). A disagreement leaves the send reserved for an operator.
 */
import type Database from 'better-sqlite3'
import { addressToPublicKey, parseRaw } from './nano-block.js'
import type { WalletOp } from './wallet-ops.js'

export interface WalletFrontier {
  nano_account: string
  wallet_id: string
  frontier: string
  balance_raw: string
  initialized_by: string
  evidence: string
  initialized_at: number
  updated_at: number
  last_op_id: string | null
}

const HEX64 = /^[0-9A-F]{64}$/

export function getFrontier(db: Database.Database, account: string): WalletFrontier | null {
  return (db.prepare(`SELECT * FROM wallet_frontiers WHERE nano_account = ?`).get(account) as WalletFrontier | undefined) ?? null
}

/**
 * Record the verified starting state of a wallet's account. Refused when a record exists (use
 * replace with the reason in evidence), when an operation is in flight on the account, or when
 * any field is missing or malformed. The caller states where the values were verified.
 */
export function initializeWalletFrontier(db: Database.Database, r: {
  walletId: string; frontier: string; balanceRaw: string; by: string; evidence: string; now: number; replace?: boolean
}): { ok: true } | { ok: false; reason: string } {
  const frontier = String(r.frontier ?? '').toUpperCase()
  if (!HEX64.test(frontier)) return { ok: false, reason: 'frontier_malformed' }
  if (parseRaw(r.balanceRaw) === null) return { ok: false, reason: 'balance_malformed' }
  if (!r.by?.trim() || !r.evidence?.trim()) return { ok: false, reason: 'initialization_incomplete' }
  return db.transaction(() => {
    const w = db.prepare(`SELECT id, nano_address FROM agent_wallets WHERE id = ?`).get(r.walletId) as any
    if (!w) return { ok: false as const, reason: 'wallet_missing' }
    try { addressToPublicKey(w.nano_address) } catch { return { ok: false as const, reason: 'wallet_address_invalid' } }
    const busy = db.prepare(`SELECT 1 FROM wallet_ops WHERE nano_account = ? AND status IN ('reserved', 'prepared', 'admitted')`).get(w.nano_address)
    if (busy) return { ok: false as const, reason: 'operation_in_flight' }
    const existing = getFrontier(db, w.nano_address)
    if (existing && !r.replace) return { ok: false as const, reason: 'frontier_already_initialized' }
    db.prepare(`INSERT INTO wallet_frontiers (nano_account, wallet_id, frontier, balance_raw, initialized_by, evidence, initialized_at, updated_at, last_op_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
      ON CONFLICT(nano_account) DO UPDATE SET wallet_id = excluded.wallet_id, frontier = excluded.frontier, balance_raw = excluded.balance_raw,
        initialized_by = excluded.initialized_by, evidence = excluded.evidence, initialized_at = excluded.initialized_at,
        updated_at = excluded.updated_at, last_op_id = NULL`)
      .run(w.nano_address, w.id, frontier, r.balanceRaw, r.by, existing ? `${r.evidence} (replaced ${existing.frontier})` : r.evidence, r.now, r.now)
    return { ok: true as const }
  }).immediate()
}

/** Why the node's confirmed state is not the one this send may be built on, or null when it is. */
export function frontierViolation(db: Database.Database, account: string, confirmedFrontier: string, confirmedBalance: string): string | null {
  const local = getFrontier(db, account)
  if (!local) return 'frontier_not_initialized'
  if (local.frontier !== confirmedFrontier.toUpperCase()) return 'frontier_mismatch'
  if (local.balance_raw !== confirmedBalance) return 'frontier_balance_mismatch'
  return null
}

/**
 * Move the record to a confirmed send's block. Only from the block's own previous, so a record that
 * changed in between is left alone. Call inside the confirming transaction. Returns whether it moved.
 */
export function advanceFrontier(db: Database.Database, op: WalletOp, now: number): boolean {
  if (op.kind !== 'send' || !op.block_hash || !op.block_previous || op.block_balance_raw == null) return false
  return db.prepare(`UPDATE wallet_frontiers SET frontier = ?, balance_raw = ?, last_op_id = ?, updated_at = ?
    WHERE nano_account = ? AND frontier = ?`)
    .run(op.block_hash, op.block_balance_raw, op.id, now, op.nano_account, op.block_previous).changes === 1
}
