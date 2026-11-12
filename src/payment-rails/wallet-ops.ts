// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Nano account-chain operations, lifecycle phase B (Day 268).
 * Design: the hosted payments lifecycle design, revision 3 (Day 268).
 *
 * Phase B covers durable operation rows, the atomic budget reservation, one operation in flight
 * per Nano account, claim fencing, and the reserved and prepared states. Nothing in this file
 * calls a Nano node or publishes a block, and no route uses it yet.
 *
 * Fencing rule: every write after the insert is a compare-and-set on id, status, claim_epoch and
 * lease_owner, with a lease that has not expired, and counts only when it changed exactly one
 * row. Taking over an expired lease increments claim_epoch, so every later write by the old
 * holder changes zero rows and throws claim_lost.
 */
import type Database from 'better-sqlite3'
import { createHash, randomUUID } from 'node:crypto'
// @ts-ignore nanocurrency-web has no type declarations
import nanoWebImport from 'nanocurrency-web'
import { XNO_RAW, unitChainRows, unitSpendViolation, applyUnitSpend, type UnitRow } from '../gateway/spend-units.js'
import { boundChainSpendRows, chainSpendHold } from '../gateway/chain-spend.js'
import { addressToPublicKey, canonicalBlockJson, parseRaw, stateBlockHash, type StateBlock } from './nano-block.js'

const nanoWeb = (nanoWebImport as any).default || nanoWebImport
const nanoTools = nanoWeb.tools

export type OpKind = 'send' | 'receive' | 'open'
export type OpStatus = 'reserved' | 'prepared' | 'admitted' | 'confirmed' | 'failed_final' | 'cancelled'
const ACTIVE = `status IN ('reserved', 'prepared', 'admitted')`

export interface WalletOp {
  id: string
  kind: OpKind
  tenant_id: string
  idempotency_key: string
  request_fingerprint: string
  nano_account: string
  wallet_id: string | null
  from_agent_id: string | null
  delegation_id: string | null
  to_address: string | null
  unit: string | null
  amount_raw: string
  source_hash: string | null
  chain_rows: string | null
  block_json: string | null
  block_hash: string | null
  block_previous: string | null
  block_balance_raw: string | null
  prev_balance_raw: string | null
  status: OpStatus
  claim_epoch: number
  lease_owner: string | null
  lease_until: number | null
  admitted_at: number | null
  last_attempt_at: number | null
  attempt_count: number
  cancel_reason: string | null
  resolution: string | null
  created_at: string
  updated_at: string
}

export type WalletOpErrorCode = 'idempotency_mismatch' | 'wallet_busy' | 'claim_lost' | 'block_mismatch' | 'bad_request' | 'reservation_inconsistent' | 'frontier_inconsistent'

export class WalletOpError extends Error {
  constructor(readonly code: WalletOpErrorCode, message: string) {
    super(message)
    this.name = 'WalletOpError'
  }
}

/** Who is acting, the time they act at (ms since epoch), and how long a claim they take lasts. */
export interface Claim { owner: string; now: number; leaseMs: number }

export interface SendRequest {
  tenantId: string
  idempotencyKey: string
  fromAgentId: string
  walletId: string
  nanoAccount: string
  delegationId: string
  toAddress: string
  amountRaw: string
}

export interface ReceiveRequest {
  tenantId: string
  idempotencyKey: string
  walletId: string
  nanoAccount: string
  kind: 'receive' | 'open'
  sourceHash: string
  amountRaw: string
}

/** The confirmed account state a block must be built on. See parseConfirmedAccountInfo. */
export interface ConfirmedAccount {
  frontier: string
  confirmed_frontier: string
  confirmed_balance: string
  confirmed_representative: string
}

export type ReserveResult = { op: WalletOp; replay: boolean } | { refused: string }

const HEX64 = /^[0-9A-Fa-f]{64}$/
const KEY = /^[\x21-\x7e]{1,200}$/
const ZERO64 = '0'.repeat(64)

function fingerprint(fields: Record<string, string>): string {
  const ordered = Object.keys(fields).sort().map(k => [k, fields[k]])
  return createHash('sha256').update(JSON.stringify(ordered)).digest('hex')
}

export function sendFingerprint(r: SendRequest): string {
  return fingerprint({
    kind: 'send', tenant_id: r.tenantId, from_agent_id: r.fromAgentId, wallet_id: r.walletId,
    nano_account: r.nanoAccount, delegation_id: r.delegationId, to_address: r.toAddress,
    unit: XNO_RAW, amount_raw: r.amountRaw,
  })
}

export function receiveFingerprint(r: ReceiveRequest): string {
  return fingerprint({
    kind: r.kind, tenant_id: r.tenantId, wallet_id: r.walletId, nano_account: r.nanoAccount,
    source_hash: r.sourceHash.toUpperCase(), amount_raw: r.amountRaw,
  })
}

export function getOp(db: Database.Database, id: string): WalletOp | undefined {
  return db.prepare(`SELECT * FROM wallet_ops WHERE id = ?`).get(id) as WalletOp | undefined
}

/** The account-wide constraint that allows one operation in flight per Nano account. */
export function isSlotConflict(e: any): boolean {
  return e?.code === 'SQLITE_CONSTRAINT_UNIQUE' && /wallet_ops\.nano_account/.test(String(e?.message))
}

function requireAddress(a: unknown, name: string): void {
  try { addressToPublicKey(String(a)) } catch { throw new WalletOpError('bad_request', `${name} is not a valid Nano address`) }
}

function requirePositiveRaw(a: unknown): bigint {
  const v = parseRaw(a)
  if (v === null || v === 0n) throw new WalletOpError('bad_request', 'amount_raw must be a canonical positive raw amount')
  return v
}

function requireKey(k: unknown): void {
  if (typeof k !== 'string' || !KEY.test(k)) throw new WalletOpError('bad_request', 'idempotency key must be 1 to 200 printable ASCII characters')
}

/** An existing row for this key: the same request returns it, a different request is refused. */
function replayOrMismatch(db: Database.Database, tenantId: string, key: string, fp: string): WalletOp | null {
  const existing = db.prepare(`SELECT * FROM wallet_ops WHERE tenant_id = ? AND idempotency_key = ?`).get(tenantId, key) as WalletOp | undefined
  if (!existing) return null
  if (existing.request_fingerprint !== fp) {
    throw new WalletOpError('idempotency_mismatch', 'this idempotency key was used for a different request')
  }
  return existing
}

function refuseIfAccountBusy(db: Database.Database, nanoAccount: string): void {
  const busy = db.prepare(`SELECT id FROM wallet_ops WHERE nano_account = ? AND ${ACTIVE}`).get(nanoAccount)
  if (busy) throw new WalletOpError('wallet_busy', 'another operation is in flight on this Nano account')
}

/**
 * Reserve a send: the operation row and the exact debit on every unit-declared delegation of the
 * chain commit together in one IMMEDIATE transaction, or not at all. The same key with the same
 * request returns the existing row and debits nothing. A refusal inserts nothing and debits nothing.
 */
/**
 * Gate 1 pilot exposure caps, in exact raw XNO, read at each reservation: the largest single payment,
 * the most a wallet may have sent or hold in unresolved sends together, and the most sends a wallet
 * may make. null when any is unset or malformed, which refuses every send: no default enables one.
 */
export function pilotCaps(): { maxPaymentRaw: bigint; maxWalletRaw: bigint; maxPayments: number } | null {
  const maxPaymentRaw = parseRaw(process.env.NANO_PILOT_MAX_PAYMENT_RAW)
  const maxWalletRaw = parseRaw(process.env.NANO_PILOT_MAX_WALLET_RAW)
  const n = process.env.NANO_PILOT_MAX_PAYMENTS
  const maxPayments = n && /^[1-9][0-9]{0,5}$/.test(n) ? Number(n) : null
  if (maxPaymentRaw === null || maxPaymentRaw === 0n || maxWalletRaw === null || maxWalletRaw === 0n || maxPayments === null) return null
  return { maxPaymentRaw, maxWalletRaw, maxPayments }
}

export function reserveSend(db: Database.Database, r: SendRequest, claim: Claim): ReserveResult {
  requireKey(r.idempotencyKey)
  requireAddress(r.nanoAccount, 'nano_account')
  requireAddress(r.toAddress, 'to_address')
  const amount = requirePositiveRaw(r.amountRaw)
  const fp = sendFingerprint(r)

  return db.transaction((): ReserveResult => {
    const replay = replayOrMismatch(db, r.tenantId, r.idempotencyKey, fp)
    if (replay) return { op: replay, replay: true }
    refuseIfAccountBusy(db, r.nanoAccount)

    // Pilot caps, inside the reservation transaction, per Nano account (the same identity as the
    // in-flight lock), across every wallet row that has pointed at it. Every send that is not
    // cancelled counts, confirmed, unresolved and operator-released alike, so an uncertain payment
    // cannot reset them.
    const caps = pilotCaps()
    if (!caps) return { refused: 'pilot_caps_unconfigured' }
    if (amount > caps.maxPaymentRaw) return { refused: 'pilot_payment_cap' }
    const earlier = db.prepare(`SELECT amount_raw FROM wallet_ops WHERE nano_account = ? AND kind = 'send' AND status <> 'cancelled'`)
      .all(r.nanoAccount) as Array<{ amount_raw: string }>
    if (earlier.length + 1 > caps.maxPayments) return { refused: 'pilot_payment_count_cap' }
    if (earlier.reduce((s, x) => s + BigInt(x.amount_raw), 0n) + amount > caps.maxWalletRaw) return { refused: 'pilot_wallet_cap' }

    const rows = unitChainRows(db, r.tenantId, r.delegationId)
    if (!rows) return { refused: 'delegation_chain_unreadable' }
    const holdRows = boundChainSpendRows(db, r.tenantId, r.delegationId)
    if (!holdRows || chainSpendHold(db, holdRows)) return { refused: 'chain_on_upgrade_hold' }
    const violation = unitSpendViolation(rows, XNO_RAW, amount)
    if (violation) return { refused: violation }

    applyUnitSpend(db, rows, amount)
    const id = randomUUID()
    try {
      db.prepare(`INSERT INTO wallet_ops
        (id, kind, tenant_id, idempotency_key, request_fingerprint, nano_account, wallet_id,
         from_agent_id, delegation_id, to_address, unit, amount_raw, chain_rows, status,
         claim_epoch, lease_owner, lease_until)
        VALUES (?, 'send', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'reserved', 1, ?, ?)`)
        .run(id, r.tenantId, r.idempotencyKey, fp, r.nanoAccount, r.walletId, r.fromAgentId,
          r.delegationId, r.toAddress, XNO_RAW, r.amountRaw, JSON.stringify(rows),
          claim.owner, claim.now + claim.leaseMs)
      const hold = db.prepare(`INSERT INTO wallet_op_reservations (op_id, delegation_id, unit, amount_raw, status)
        VALUES (?, ?, ?, ?, 'held')`)
      for (const row of rows) if (row.spend_unit != null) hold.run(id, row.id, XNO_RAW, r.amountRaw)
    } catch (e) {
      // Throwing rolls the whole transaction back, the debit included.
      if (isSlotConflict(e)) throw new WalletOpError('wallet_busy', 'another operation is in flight on this Nano account')
      throw e
    }
    return { op: getOp(db, id)!, replay: false }
  }).immediate()
}

/** Reserve a receive or open: the same slot and identity rules, no budget. */
export function reserveReceive(db: Database.Database, r: ReceiveRequest, claim: Claim): { op: WalletOp; replay: boolean } {
  requireKey(r.idempotencyKey)
  requireAddress(r.nanoAccount, 'nano_account')
  requirePositiveRaw(r.amountRaw)
  if (!HEX64.test(r.sourceHash)) throw new WalletOpError('bad_request', 'source_hash must be 32 bytes of hex')
  if (r.kind !== 'receive' && r.kind !== 'open') throw new WalletOpError('bad_request', 'kind must be receive or open')
  const fp = receiveFingerprint(r)

  return db.transaction(() => {
    const replay = replayOrMismatch(db, r.tenantId, r.idempotencyKey, fp)
    if (replay) return { op: replay, replay: true }
    refuseIfAccountBusy(db, r.nanoAccount)
    const id = randomUUID()
    try {
      db.prepare(`INSERT INTO wallet_ops
        (id, kind, tenant_id, idempotency_key, request_fingerprint, nano_account, wallet_id,
         amount_raw, source_hash, status, claim_epoch, lease_owner, lease_until)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'reserved', 1, ?, ?)`)
        .run(id, r.kind, r.tenantId, r.idempotencyKey, fp, r.nanoAccount, r.walletId,
          r.amountRaw, r.sourceHash.toUpperCase(), claim.owner, claim.now + claim.leaseMs)
    } catch (e) {
      if (isSlotConflict(e)) throw new WalletOpError('wallet_busy', 'another operation is in flight on this Nano account')
      throw e
    }
    return { op: getOp(db, id)!, replay: false }
  }).immediate()
}

/**
 * Take over an operation whose lease has expired. Increments claim_epoch, so every write by the
 * previous holder fails from here on. Returns the row as now claimed, or null when the row is not
 * in flight or its lease is still live.
 */
export function takeOver(db: Database.Database, id: string, claim: Claim): WalletOp | null {
  const res = db.prepare(`UPDATE wallet_ops
      SET claim_epoch = claim_epoch + 1, lease_owner = ?, lease_until = ?, updated_at = datetime('now')
    WHERE id = ? AND ${ACTIVE} AND (lease_until IS NULL OR lease_until <= ?)`)
    .run(claim.owner, claim.now + claim.leaseMs, id, claim.now)
  return res.changes === 1 ? getOp(db, id)! : null
}

/** Extend a claim. Works after expiry too, as long as nobody took the row over in between. */
export function renewLease(db: Database.Database, op: Pick<WalletOp, 'id' | 'claim_epoch'>, claim: Claim): boolean {
  const res = db.prepare(`UPDATE wallet_ops SET lease_until = ?, updated_at = datetime('now')
    WHERE id = ? AND ${ACTIVE} AND claim_epoch = ? AND lease_owner = ?`)
    .run(claim.now + claim.leaseMs, op.id, op.claim_epoch, claim.owner)
  return res.changes === 1
}

/** Operations in flight whose lease has expired, oldest first: the recovery worker's queue. */
export function listRecoverable(db: Database.Database, now: number): WalletOp[] {
  return db.prepare(`SELECT * FROM wallet_ops WHERE ${ACTIVE} AND (lease_until IS NULL OR lease_until <= ?)
    ORDER BY created_at, id`).all(now) as WalletOp[]
}

/**
 * The confirmed account state from an account_info response requested with include_confirmed and
 * representative. Every field must be present and well formed, or no block is built.
 */
export function parseConfirmedAccountInfo(info: any): ConfirmedAccount | { error: string } {
  if (!info || typeof info !== 'object') return { error: 'account_info_missing' }
  const { frontier, confirmed_frontier, confirmed_balance, confirmed_representative } = info
  if (typeof frontier !== 'string' || !HEX64.test(frontier)) return { error: 'account_info_frontier_missing' }
  if (typeof confirmed_frontier !== 'string' || !HEX64.test(confirmed_frontier)) return { error: 'account_info_confirmed_frontier_missing' }
  if (parseRaw(confirmed_balance) === null) return { error: 'account_info_confirmed_balance_missing' }
  try { addressToPublicKey(String(confirmed_representative)) } catch { return { error: 'account_info_confirmed_representative_missing' } }
  return {
    frontier: frontier.toUpperCase(), confirmed_frontier: confirmed_frontier.toUpperCase(),
    confirmed_balance, confirmed_representative,
  }
}

/**
 * Whether `block` is exactly the block this operation may store, built on `account`. Returns null
 * when it is, otherwise the reason. For an open, `account` is the all-zero state of an unopened
 * account (frontier and confirmed_frontier zero, balance 0) and the caller picks the representative.
 */
export function blockViolation(op: WalletOp, block: StateBlock, account: ConfirmedAccount): string | null {
  if (account.frontier !== account.confirmed_frontier) return 'frontier_unconfirmed'
  if (block?.type !== 'state') return 'block_not_state'
  if (block.account !== op.nano_account) return 'block_account_mismatch'
  if (typeof block.previous !== 'string' || block.previous.toUpperCase() !== account.confirmed_frontier) return 'block_previous_not_confirmed_frontier'
  if (op.kind !== 'open' && block.representative !== account.confirmed_representative) return 'block_representative_changed'
  if (typeof block.signature !== 'string' || !/^[0-9A-Fa-f]{128}$/.test(block.signature)) return 'block_signature_malformed'
  if (typeof block.work !== 'string' || !/^[0-9A-Fa-f]{16}$/.test(block.work)) return 'block_work_malformed'
  const balance = BigInt(account.confirmed_balance)
  const amount = BigInt(op.amount_raw)
  let expected: bigint
  let link: string
  if (op.kind === 'send') {
    if (amount > balance) return 'amount_exceeds_confirmed_balance'
    expected = balance - amount
    link = addressToPublicKey(op.to_address!)
  } else {
    if (op.kind === 'open' && (account.confirmed_frontier !== ZERO64 || balance !== 0n)) return 'open_on_opened_account'
    if (op.kind === 'receive' && account.confirmed_frontier === ZERO64) return 'receive_on_unopened_account'
    expected = balance + amount
    link = op.source_hash!
  }
  if (block.balance !== expected.toString()) return 'block_balance_mismatch'
  if (typeof block.link !== 'string' || block.link.toUpperCase() !== link) return 'block_link_mismatch'
  try { stateBlockHash(block) } catch { return 'block_unhashable' }
  if (!nanoTools.verifyBlock(addressToPublicKey(op.nano_account), block)) return 'block_signature_invalid'
  return null
}

/**
 * Store the one signed block for a reserved operation and move it to prepared. Requires the
 * caller's current claim. A row that is already prepared or admitted never gets another block.
 */
export function storePrepared(db: Database.Database, op: WalletOp, claim: Claim, block: StateBlock, account: ConfirmedAccount): WalletOp {
  const violation = blockViolation(op, block, account)
  if (violation) throw new WalletOpError('block_mismatch', violation)
  const hash = stateBlockHash(block)
  const res = db.prepare(`UPDATE wallet_ops
      SET status = 'prepared', block_json = ?, block_hash = ?, block_previous = ?, block_balance_raw = ?,
          prev_balance_raw = ?, updated_at = datetime('now')
    WHERE id = ? AND status = 'reserved' AND claim_epoch = ? AND lease_owner = ? AND lease_until > ?`)
    .run(canonicalBlockJson(block), hash, block.previous.toUpperCase(), block.balance, account.confirmed_balance,
      op.id, op.claim_epoch, claim.owner, claim.now)
  if (res.changes !== 1) throw new WalletOpError('claim_lost', 'the row is not reserved under this claim')
  return getOp(db, op.id)!
}

/**
 * Cancel an operation that never had a publish attempt, and release a send's reservation in the
 * same transaction. Exactly one of a cancel and a first attempt can change the row.
 */
export function cancelOp(db: Database.Database, op: WalletOp, claim: Claim, reason: string): WalletOp {
  return db.transaction(() => {
    const res = db.prepare(`UPDATE wallet_ops SET status = 'cancelled', cancel_reason = ?, updated_at = datetime('now')
      WHERE id = ? AND status IN ('reserved', 'prepared') AND attempt_count = 0
        AND claim_epoch = ? AND lease_owner = ? AND lease_until > ?`)
      .run(reason, op.id, op.claim_epoch, claim.owner, claim.now)
    if (res.changes !== 1) throw new WalletOpError('claim_lost', 'the row cannot be cancelled under this claim')
    releaseReservations(db, getOp(db, op.id)!)
    return getOp(db, op.id)!
  }).immediate()
}

interface ReservationRow { op_id: string; delegation_id: string; unit: string; amount_raw: string; status: string }

export function listReservations(db: Database.Database, opId: string): ReservationRow[] {
  return db.prepare(`SELECT * FROM wallet_op_reservations WHERE op_id = ? ORDER BY delegation_id`).all(opId) as ReservationRow[]
}

/**
 * Move an operation's complete reservation from held to `to`, or throw and change nothing.
 *
 * Call inside the transaction that moves the operation to its terminal state. Before any row
 * changes, the operation's reservation must be exactly what it reserved: one held row per
 * unit-declared delegation of its chain, each for the operation's amount in raw XNO. Every row's
 * compare-and-set must then change exactly one row. Any failure throws reservation_inconsistent,
 * which rolls back the caller's transaction, terminal status included, so no part of a reservation
 * is ever released or consumed alone. A release also returns each row's amount to its delegation's
 * spend counter. An operation with no reservation (a receive or open) settles nothing.
 */
function settleReservations(db: Database.Database, op: WalletOp, to: 'released' | 'consumed'): number {
  if (op.kind !== 'send') {
    if (listReservations(db, op.id).length > 0) throw new WalletOpError('reservation_inconsistent', 'a receive has reservation rows')
    return 0
  }
  const bad = ownReservationViolation(db, op)
  if (bad) throw new WalletOpError('reservation_inconsistent', bad)
  const held = listReservations(db, op.id)
  const cas = db.prepare(`UPDATE wallet_op_reservations SET status = ?, settled_at = datetime('now')
    WHERE op_id = ? AND delegation_id = ? AND status = 'held' AND unit = ? AND amount_raw = ?`)
  for (const r of held) {
    if (cas.run(to, op.id, r.delegation_id, XNO_RAW, op.amount_raw).changes !== 1) {
      throw new WalletOpError('reservation_inconsistent', `reservation row for ${r.delegation_id} did not settle`)
    }
    if (to === 'released') {
      applyUnitSpend(db, [{ id: r.delegation_id, spend_unit: r.unit, spend_limit: null, spend_limit_minor: null, spend_used_minor: null }], -BigInt(r.amount_raw))
    }
  }
  return held.length
}
export const releaseReservations = (db: Database.Database, op: WalletOp) => settleReservations(db, op, 'released')
export const consumeReservations = (db: Database.Database, op: WalletOp) => settleReservations(db, op, 'consumed')

/**
 * Whether a send still holds its own reservation: one held row per unit-declared delegation of the
 * chain it reserved against, each for exactly the operation's amount in raw XNO. Null when it does.
 */
export function ownReservationViolation(db: Database.Database, op: WalletOp): string | null {
  const expected = (JSON.parse(op.chain_rows ?? '[]') as UnitRow[]).filter(r => r.spend_unit != null).map(r => r.id).sort()
  const rows = listReservations(db, op.id)
  const held = rows.filter(r => r.status === 'held')
  if (held.length !== rows.length) return 'reservation_not_held'
  const have = held.map(r => r.delegation_id).sort()
  if (expected.length === 0 || have.length !== expected.length || have.some((d, i) => d !== expected[i])) return 'reservation_missing'
  for (const r of held) if (r.unit !== XNO_RAW || r.amount_raw !== op.amount_raw) return 'reservation_amount_mismatch'
  return null
}

/**
 * Problems that make publishing unsafe: two agent wallets on one Nano account or one derivation
 * index, or an agent wallet on the gateway's own account. An empty list means none were found.
 */
export function walletAccountProblems(db: Database.Database, gatewayAddress: string | null): string[] {
  const problems: string[] = []
  const dupAddr = db.prepare(`SELECT nano_address, COUNT(*) AS c FROM agent_wallets GROUP BY nano_address HAVING c > 1`).all() as any[]
  for (const d of dupAddr) problems.push(`nano_address shared by ${d.c} wallets`)
  const dupIdx = db.prepare(`SELECT wallet_index, COUNT(*) AS c FROM agent_wallets GROUP BY wallet_index HAVING c > 1`).all() as any[]
  for (const d of dupIdx) problems.push(`wallet_index ${d.wallet_index} shared by ${d.c} wallets`)
  const zero = db.prepare(`SELECT COUNT(*) AS c FROM agent_wallets WHERE wallet_index <= 0`).get() as any
  if (zero.c > 0) problems.push('an agent wallet uses index 0 or below')
  if (gatewayAddress) {
    const gw = db.prepare(`SELECT COUNT(*) AS c FROM agent_wallets WHERE nano_address = ?`).get(gatewayAddress) as any
    if (gw.c > 0) problems.push('an agent wallet uses the gateway account')
  }
  return problems
}
