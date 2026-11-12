// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Nano lifecycle phase D (Day 268): reconciliation and the operation runner.
 *
 * An admitted operation becomes confirmed only on evidence that its own block is confirmed. Nothing
 * returns a held amount automatically (activation gate 1, Day 268). Anything that is not our own
 * confirmed block keeps the operation admitted with its reservation. Time alone never releases.
 * Reconciliation only reads the node, so it runs while Nano is paused.
 *
 * A different block on our previous is checked locally: account, previous, hash and signature.
 * - It verifies: the account's signing authority was used outside this operation. That is an
 *   incident. The wallet freezes, the chain is held, the lifecycle blocks new sends, and the
 *   reservation stays held whether or not any node calls the other block confirmed.
 * - It does not verify, or the node cannot produce it: the node is wrong. That is a node fault.
 *   Nothing freezes, the operation stays open and the lifecycle refuses new sends.
 * Only an operator ends either, with resolveIncident or resolveNodeFault, and only resolveIncident
 * can release, with the evidence and accounting recorded.
 *
 * Trust assumption, stated on purpose: a confirmation comes from the configured node. A wrong
 * confirmation counts an amount as spent, it cannot return spending authority. watchFinalized
 * keeps checking failed_final operations (operator releases), and if one later shows confirmed it
 * freezes the wallet, holds the delegation chain and alerts.
 */
import type Database from 'better-sqlite3'
import { randomUUID } from 'node:crypto'
import { getEventBus } from '../gateway/events.js'
import { XNO_RAW, applyUnitSpend, rawToExactXno, unitChainRows, unitSpendViolation } from '../gateway/spend-units.js'
import { stateBlockHash, type StateBlock } from './nano-block.js'
import {
  WalletOpError, cancelOp, consumeReservations, getOp, releaseReservations, takeOver,
  type Claim, type WalletOp,
} from './wallet-ops.js'
import { blockSignatureValid, commitAttempt, prepareOp, publishAttempt, type NanoNode, type Signer } from './nano-publish.js'
import { advanceFrontier } from './wallet-frontier.js'
import { parseRaw } from './nano-block.js'

const ZERO64 = '0'.repeat(64)

export interface ReconcileOptions {
  /** Label of the node the evidence came from, recorded with it. */
  source: string
}

export type ReconcileResult =
  | { status: 'confirmed' }
  | { status: 'incident'; sibling: string }
  | { status: 'node_fault'; reason: string }
  | { status: 'unknown'; reason: string }

const isConfirmed = (info: any) => info?.confirmed === true || info?.confirmed === 'true'

async function blockInfo(node: NanoNode, hash: string): Promise<any | null> {
  try {
    return await node.call({ action: 'block_info', json_block: 'true', hash })
  } catch (e: any) {
    if (/Block not found/i.test(String(e?.message))) return null
    throw e
  }
}

function heldRow(db: Database.Database, op: Pick<WalletOp, 'id' | 'claim_epoch'>, claim: Claim): WalletOp {
  const row = db.prepare(`SELECT * FROM wallet_ops WHERE id = ? AND status = 'admitted' AND claim_epoch = ?
      AND lease_owner = ? AND lease_until > ?`).get(op.id, op.claim_epoch, claim.owner, claim.now) as WalletOp | undefined
  if (!row) throw new WalletOpError('claim_lost', 'no admitted row under this claim')
  return row
}

/** Move an admitted row to a final state under the caller's claim. Throws claim_lost if it changed. */
function finalize(db: Database.Database, row: WalletOp, claim: Claim, to: 'confirmed' | 'failed_final', resolution: object): void {
  const res = db.prepare(`UPDATE wallet_ops SET status = ?, resolution = ?, updated_at = datetime('now')
    WHERE id = ? AND status = 'admitted' AND claim_epoch = ? AND lease_owner = ? AND lease_until > ?`)
    .run(to, JSON.stringify(resolution), row.id, row.claim_epoch, claim.owner, claim.now)
  if (res.changes !== 1) throw new WalletOpError('claim_lost', 'the row changed under this claim')
}

function recordConfirmedHistory(db: Database.Database, row: WalletOp): void {
  if (row.kind === 'send') {
    db.prepare(`INSERT INTO wallet_transactions
      (id, tenant_id, from_agent_id, to_address, amount_raw, amount_xno, block_hash, delegation_id,
       scope_used, status, confirmed_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'commerce:send', 'confirmed', datetime('now'))`)
      .run(`wtx-${row.id}`, row.tenant_id, row.from_agent_id, row.to_address, row.amount_raw,
        rawToExactXno(row.amount_raw), row.block_hash, row.delegation_id)
    const w = db.prepare(`SELECT total_sent_raw FROM agent_wallets WHERE id = ?`).get(row.wallet_id) as any
    if (w) db.prepare(`UPDATE agent_wallets SET total_sent_raw = ? WHERE id = ?`)
      .run((BigInt(w.total_sent_raw) + BigInt(row.amount_raw)).toString(), row.wallet_id)
  } else {
    const w = db.prepare(`SELECT total_received_raw FROM agent_wallets WHERE id = ?`).get(row.wallet_id) as any
    if (w) db.prepare(`UPDATE agent_wallets SET total_received_raw = ? WHERE id = ?`)
      .run((BigInt(w.total_received_raw) + BigInt(row.amount_raw)).toString(), row.wallet_id)
  }
}

/** Whether a node's block_info says this is our block, confirmed: account and recomputed hash both match. */
function isOurConfirmedBlock(info: any, row: WalletOp): boolean {
  if (!info || !isConfirmed(info) || info.block_account !== row.nano_account) return false
  try { return stateBlockHash(info.contents as StateBlock) === row.block_hash } catch { return false }
}

/**
 * Look at the node and settle an admitted operation if the evidence allows. Needs the caller's
 * current claim. Writes only on evidence: confirmed, a conflict seen (first sighting recorded),
 * or failed_final (second sighting).
 */
export async function reconcileOp(
  db: Database.Database, node: NanoNode, op: Pick<WalletOp, 'id' | 'claim_epoch'>, claim: Claim, opts: ReconcileOptions,
): Promise<ReconcileResult> {
  const row = heldRow(db, op, claim)
  const ours = await blockInfo(node, row.block_hash!)
  if (isOurConfirmedBlock(ours, row)) {
    db.transaction(() => {
      const again = heldRow(db, row, claim)
      const prior = again.resolution ? JSON.parse(again.resolution) : {}
      finalize(db, again, claim, 'confirmed', {
        ...prior, evidence: 'block_info', source: opts.source, hash: row.block_hash, observed_at: claim.now,
      })
      consumeReservations(db, again)
      recordConfirmedHistory(db, again)
      // The confirmation and the frontier record move together, or neither does: a confirmed send
      // whose record cannot advance is an integrity fault the operator must look at.
      if (again.kind === 'send' && !advanceFrontier(db, again, claim.now)) {
        throw new WalletOpError('frontier_inconsistent', `frontier record does not name ${again.block_previous} for op ${again.id}`)
      }
    }).immediate()
    return { status: 'confirmed' }
  }

  // An open has no previous block to conflict on. Its conflicts stay unknown in this release.
  if (row.block_previous === ZERO64) return { status: 'unknown', reason: ours ? 'ours_unconfirmed' : 'ours_unknown_to_node' }

  const succ = await node.call({ action: 'successors', block: row.block_previous, count: '2' })
  const blocks: string[] = Array.isArray(succ?.blocks) ? succ.blocks.map((h: any) => String(h).toUpperCase()) : []
  if (blocks[0] !== row.block_previous) return { status: 'unknown', reason: 'successors_unexpected' }
  const other = blocks[1]
  if (!other || other === row.block_hash) return { status: 'unknown', reason: ours ? 'ours_unconfirmed' : 'ours_unknown_to_node' }

  const prior = row.resolution ? JSON.parse(row.resolution) : {}
  if (prior.incident?.sibling === other) return { status: 'incident', sibling: other }

  const theirs = await blockInfo(node, other)
  const problem = siblingProblem(theirs, row, other)
  if (problem) {
    if (!(prior.node_fault?.sibling === other && prior.node_fault?.reason === problem && !prior.node_fault?.resolved)) {
      writeResolution(db, row, claim, { ...prior, node_fault: { sibling: other, reason: problem, source: opts.source, at: claim.now } })
      console.error(`[nano-lifecycle] node_fault op=${row.id}: ${problem} (${opts.source})`)
    }
    return { status: 'node_fault', reason: problem }
  }

  const effect = balanceEffect(theirs.contents.balance, row.prev_balance_raw)
  db.transaction(() => {
    const again = heldRow(db, row, claim)
    const p = again.resolution ? JSON.parse(again.resolution) : {}
    writeResolution(db, again, claim, { ...p, incident: {
      sibling: other, confirmed: isConfirmed(theirs), balance_effect: effect, sibling_balance_raw: String(theirs.contents.balance),
      prev_balance_raw: again.prev_balance_raw, source: opts.source, at: claim.now,
    } })
    db.prepare(`UPDATE agent_wallets SET status = 'frozen' WHERE id = ?`).run(again.wallet_id)
    if (again.delegation_id) {
      db.prepare(`INSERT OR IGNORE INTO chain_spend_holds (delegation_id, tenant_id, reason, created_at)
        VALUES (?, ?, ?, datetime('now'))`).run(again.delegation_id, again.tenant_id, `conflict_incident:${again.id}`)
    }
  }).immediate()
  try { getEventBus().emit(row.tenant_id, { type: 'wallet_transaction', data: { op_id: row.id, status: 'conflict_incident', balance_effect: effect } } as any) } catch {}
  console.error(`[nano-lifecycle] conflict_incident op=${row.id}: signed block ${other} on our previous (balance ${effect}), wallet frozen, operator action needed`)
  return { status: 'incident', sibling: other }
}

/** Why a reported block on our previous is not a signed block of our account, or null when it is. */
function siblingProblem(info: any, row: WalletOp, hash: string): string | null {
  if (!info) return 'sibling_not_found'
  if (info.block_account !== row.nano_account) return 'sibling_account_mismatch'
  const contents = info.contents
  if (!contents || typeof contents !== 'object') return 'sibling_contents_missing'
  if (contents.account !== row.nano_account) return 'sibling_contents_account_mismatch'
  if (String(contents.previous ?? '').toUpperCase() !== row.block_previous) return 'sibling_previous_mismatch'
  try { if (stateBlockHash(contents) !== hash) return 'sibling_hash_mismatch' } catch { return 'sibling_hash_mismatch' }
  if (!blockSignatureValid(row.nano_account, contents)) return 'sibling_signature_invalid'
  return null
}

function balanceEffect(siblingBalance: unknown, prevBalance: string | null): 'decreased' | 'increased' | 'unchanged' | 'unreadable' {
  const s = parseRaw(String(siblingBalance)), p = parseRaw(prevBalance)
  if (s === null || p === null) return 'unreadable'
  return s < p ? 'decreased' : s > p ? 'increased' : 'unchanged'
}

/** Replace an admitted row's resolution under the caller's claim. Throws claim_lost if it changed. */
function writeResolution(db: Database.Database, row: WalletOp, claim: Claim, resolution: object): void {
  const res = db.prepare(`UPDATE wallet_ops SET resolution = ?, updated_at = datetime('now')
    WHERE id = ? AND status = 'admitted' AND claim_epoch = ? AND lease_owner = ? AND lease_until > ?`)
    .run(JSON.stringify(resolution), row.id, row.claim_epoch, claim.owner, claim.now)
  if (res.changes !== 1) throw new WalletOpError('claim_lost', 'the row changed under this claim')
}

/** One observation of the incident's blocks, from somewhere other than the node that reported it. */
export interface IncidentSource { source: string; observed_at: number; detail?: string }

export interface IncidentResolution {
  /** What the operator established: our block confirmed after all, or the other block won. */
  decision: 'ours_confirmed' | 'ours_failed'
  by: string
  /** The other block as recorded on the incident. Must match it. */
  sibling: string
  /** The other block's status as the operator observed it. */
  sibling_status: 'confirmed' | 'unconfirmed' | 'rejected'
  /** The balance effect as recorded on the incident. Must match it. */
  balance_effect: 'decreased' | 'increased' | 'unchanged'
  /**
   * At least one observation from a source other than the node that reported the incident. The
   * operator records it: the gateway does not contact or authenticate the source.
   */
  sources: IncidentSource[]
  /**
   * What happened to any money the other block moved out:
   * - no_funds_moved: allowed only when the other block did not lower the balance
   * - debited: the moved amount is charged to the listed delegations, applied here
   * - loss_recorded: the moved amount is recorded as an unattributed loss, no budget changes
   */
  disposition:
    | { kind: 'no_funds_moved' }
    | { kind: 'debited'; adjustments: Array<{ delegation_id: string; amount_raw: string }> }
    | { kind: 'loss_recorded'; amount_raw: string }
  note?: string
  now: number
}

type Fail = { ok: false; reason: string }
const failR = (reason: string): Fail => ({ ok: false, reason })

/**
 * Check a resolution against the recorded incident. Returns the amount the other block moved out
 * (0 when none) or the reason the resolution does not match what was recorded.
 */
function validateResolution(row: WalletOp, incident: any, r: IncidentResolution): bigint | Fail {
  if (r.decision !== 'ours_confirmed' && r.decision !== 'ours_failed') return failR('bad_decision')
  if (!r.by?.trim()) return failR('resolution_incomplete')
  if (r.sibling !== incident.sibling) return failR('sibling_mismatch')
  if (r.balance_effect !== incident.balance_effect) return failR('balance_effect_mismatch')
  if (!['confirmed', 'unconfirmed', 'rejected'].includes(r.sibling_status)) return failR('bad_sibling_status')
  const outside = (r.sources ?? []).filter(s => s && typeof s.source === 'string' && s.source.trim()
    && s.source !== incident.source && Number.isFinite(s.observed_at))
  if (outside.length === 0) return failR('no_independent_source')
  // Our block and the other block cannot both be final on the same previous.
  if (r.decision === 'ours_confirmed' && r.sibling_status === 'confirmed') return failR('both_confirmed')
  // Releasing is safe only when the other block, not ours, is the one that took the previous.
  if (r.decision === 'ours_failed' && r.sibling_status !== 'confirmed') return failR('sibling_not_confirmed')
  const sib = parseRaw(incident.sibling_balance_raw), prev = parseRaw(incident.prev_balance_raw ?? row.prev_balance_raw)
  if (sib === null || prev === null) return failR('incident_amounts_unreadable')
  // A block that never took effect moved nothing, whatever balance it names.
  const moved = r.sibling_status === 'confirmed' && prev > sib ? prev - sib : 0n
  const d = r.disposition
  if (!d || typeof d !== 'object') return failR('disposition_missing')
  if (d.kind === 'no_funds_moved') return moved === 0n ? moved : failR('funds_moved')
  if (d.kind === 'loss_recorded') return parseRaw(d.amount_raw) === moved && moved > 0n ? moved : failR('loss_amount_mismatch')
  if (d.kind === 'debited') {
    if (!Array.isArray(d.adjustments) || d.adjustments.length === 0) return failR('adjustments_missing')
    let sum = 0n
    for (const a of d.adjustments) {
      const v = parseRaw(a?.amount_raw)
      if (v === null || v === 0n || typeof a.delegation_id !== 'string') return failR('bad_adjustment')
      sum += v
    }
    return sum === moved && moved > 0n ? moved : failR('adjustments_do_not_match_moved_amount')
  }
  return failR('bad_disposition')
}

/**
 * The only way to end a conflict incident: a structured operator override, checked against what the
 * gateway recorded and applied in one transaction. The evidence is the operator's: the gateway does
 * not verify the sources it names. It requires the wallet to be frozen, the recorded other block and
 * balance effect, an operator-recorded observation from a source other than the reporting node, and
 * a disposition for any money the other block moved, whose amount must equal what the block moved.
 * A "debited" disposition is charged to the named delegations' chains after our reservation is
 * released, and refused if their budgets cannot absorb it. loss_recorded is stored on this payment
 * record only: there is no separate loss ledger.
 * ours_confirmed counts our amount as spent. ours_failed releases it, the only release left, and is
 * watched afterwards like any failed_final. Neither unfreezes the wallet or clears the chain hold.
 * Fences out any runner. Everything moves in one transaction or nothing does.
 */
export function resolveIncident(db: Database.Database, opId: string, r: IncidentResolution): { ok: true } | Fail {
  try {
    return db.transaction((): { ok: true } | Fail => {
      const row = getOp(db, opId)
      if (!row) return failR('not_admitted')
      const res = row.resolution ? JSON.parse(row.resolution) : {}
      if (!res.incident || res.incident.resolved) return failR(row.status === 'admitted' ? 'no_open_incident' : 'not_admitted')
      if (row.status !== 'admitted' && row.status !== 'confirmed') return failR('not_admitted')
      const w = db.prepare(`SELECT status FROM agent_wallets WHERE id = ?`).get(row.wallet_id) as any
      if (w?.status !== 'frozen') return failR('wallet_not_frozen')
      // Our own block confirmed after the incident opened: the amount is already spent, so only
      // ours_confirmed can be recorded.
      if (row.status === 'confirmed' && r.decision !== 'ours_confirmed') return failR('already_confirmed')
      const moved = validateResolution(row, res.incident, r)
      if (typeof moved !== 'bigint') return moved

      const resolved = {
        by: r.by, decision: r.decision, sibling_status: r.sibling_status, sources: r.sources,
        disposition: r.disposition, moved_raw: moved.toString(), note: r.note ?? null, at: r.now,
      }
      if (row.status === 'confirmed') {
        const upd = db.prepare(`UPDATE wallet_ops SET resolution = ?, updated_at = datetime('now') WHERE id = ? AND status = 'confirmed' AND resolution IS ?`)
          .run(JSON.stringify({ ...res, incident: { ...res.incident, resolved } }), opId, row.resolution)
        if (upd.changes !== 1) throw new ResolutionRefused('changed')
        return { ok: true }
      }
      const to = r.decision === 'ours_confirmed' ? 'confirmed' : 'failed_final'
      const next = {
        ...res, incident: { ...res.incident, resolved },
        evidence: 'operator_resolution', ...(to === 'failed_final' ? { failed_at: r.now } : { observed_at: r.now }),
      }
      const upd = db.prepare(`UPDATE wallet_ops SET status = ?, resolution = ?, claim_epoch = claim_epoch + 1, lease_owner = NULL,
        lease_until = NULL, updated_at = datetime('now') WHERE id = ? AND status = 'admitted' AND resolution IS ?`)
        .run(to, JSON.stringify(next), opId, row.resolution)
      if (upd.changes !== 1) throw new ResolutionRefused('changed')
      const again = getOp(db, opId)!
      if (to === 'confirmed') {
        consumeReservations(db, again)
        recordConfirmedHistory(db, again)
        if (again.kind === 'send' && !advanceFrontier(db, again, r.now)) {
          throw new WalletOpError('frontier_inconsistent', `frontier record does not name ${again.block_previous} for op ${again.id}`)
        }
      } else {
        // Release our reservation first, then charge what the other block moved, so a budget our
        // payment held in full can still take the smaller real spend. Any refusal below rolls the
        // release and the status change back with it.
        releaseReservations(db, again)
      }
      if (r.disposition.kind === 'debited') {
        for (const a of r.disposition.adjustments) {
          const rows = unitChainRows(db, row.tenant_id, a.delegation_id)
          if (!rows) throw new ResolutionRefused(`adjustment_chain_unreadable:${a.delegation_id}`)
          const amount = BigInt(a.amount_raw)
          const v = unitSpendViolation(rows, XNO_RAW, amount)
          if (v) throw new ResolutionRefused(`adjustment_refused:${a.delegation_id}:${v}`)
          applyUnitSpend(db, rows, amount)
        }
      }
      return { ok: true }
    }).immediate()
  } catch (e: any) {
    if (e instanceof ResolutionRefused) return failR(e.message)
    if (e instanceof WalletOpError) return failR(e.code)
    throw e
  }
}

/** Rolls the resolution transaction back with a reason, after a write already happened inside it. */
class ResolutionRefused extends Error {}

/**
 * Record that an operator dealt with a node fault (replaced or cleared the node). Works whatever the
 * payment's status, since a fault persists after the payment confirms. Changes nothing else.
 */
export function resolveNodeFault(db: Database.Database, opId: string, r: { by: string; evidence: string; now: number }): boolean {
  if (!r.by?.trim() || !r.evidence?.trim()) return false
  const row = getOp(db, opId)
  if (!row || !row.resolution) return false
  const res = JSON.parse(row.resolution)
  if (!res.node_fault || res.node_fault.resolved) return false
  const next = { ...res, node_fault: { ...res.node_fault, resolved: { by: r.by, evidence: r.evidence, at: r.now } } }
  return db.prepare(`UPDATE wallet_ops SET resolution = ?, updated_at = datetime('now') WHERE id = ? AND resolution = ?`)
    .run(JSON.stringify(next), opId, row.resolution).changes === 1
}

/**
 * Re-check failed_final operations finalized within `watchMs`. If one's own block now shows
 * confirmed, the release was wrong: freeze the wallet, hold the delegation chain so nothing more is
 * spent from it, record it and alert. The debit is not re-applied.
 */
export async function watchFinalized(db: Database.Database, node: NanoNode, now: number, watchMs: number, source: string): Promise<string[]> {
  const rows = db.prepare(`SELECT * FROM wallet_ops WHERE status = 'failed_final'`).all() as WalletOp[]
  const contradicted: string[] = []
  for (const row of rows) {
    const res = row.resolution ? JSON.parse(row.resolution) : {}
    if (res.contradicted || typeof res.failed_at !== 'number' || now - res.failed_at > watchMs) continue
    const info = await blockInfo(node, row.block_hash!)
    if (!isOurConfirmedBlock(info, row)) continue
    db.transaction(() => {
      db.prepare(`UPDATE wallet_ops SET resolution = ?, updated_at = datetime('now') WHERE id = ? AND status = 'failed_final'`)
        .run(JSON.stringify({ ...res, contradicted: { at: now, source } }), row.id)
      db.prepare(`UPDATE agent_wallets SET status = 'frozen' WHERE id = ?`).run(row.wallet_id)
      if (row.delegation_id) {
        db.prepare(`INSERT OR IGNORE INTO chain_spend_holds (delegation_id, tenant_id, reason, created_at)
          VALUES (?, ?, ?, datetime('now'))`).run(row.delegation_id, row.tenant_id, `contradicted_final:${row.id}`)
      }
    }).immediate()
    contradicted.push(row.id)
    try { getEventBus().emit(row.tenant_id, { type: 'wallet_transaction', data: { op_id: row.id, status: 'contradicted_final' } } as any) } catch {}
    console.error(`[nano-lifecycle] contradicted_final op=${row.id}: wallet frozen, chain held, operator action needed`)
  }
  return contradicted
}

/**
 * Record that an operator has resolved a contradicted release: they established what the competing
 * and released blocks did and reconciled the affected budgets. This only lifts the lifecycle's block
 * on new sends. It does not unfreeze the wallet, clear the chain hold or change any budget: those
 * stay separate operator decisions. Returns false when the operation is not an unresolved
 * contradicted release.
 */
export function resolveContradictedRelease(db: Database.Database, opId: string, by: string, note: string, now: number): boolean {
  const row = db.prepare(`SELECT * FROM wallet_ops WHERE id = ? AND status = 'failed_final'`).get(opId) as WalletOp | undefined
  if (!row?.resolution) return false
  const res = JSON.parse(row.resolution)
  if (!res.contradicted || res.contradicted.resolved) return false
  const next = { ...res, contradicted: { ...res.contradicted, resolved: { at: now, by, note } } }
  return db.prepare(`UPDATE wallet_ops SET resolution = ?, updated_at = datetime('now') WHERE id = ? AND status = 'failed_final' AND resolution = ?`)
    .run(JSON.stringify(next), opId, row.resolution).changes === 1
}

/** Reasons from preparing that mean the operation can never be built, so it is cancelled. */
const CANCEL_ON_PREPARE = new Set(['amount_exceeds_confirmed_balance', 'open_on_opened_account', 'receive_on_unopened_account'])

export interface RunContext {
  node: NanoNode
  owner: string
  leaseMs: number
  now: () => number
  /** The key for an operation's account. Production derives it from the master seed. */
  signer: (op: WalletOp) => Signer
  openRepresentative: string
  reconcile: ReconcileOptions
  /** Minimum time between publish attempts on an admitted operation. */
  rebroadcastMs: number
}

export type RunResult = { status: WalletOp['status']; step: string; detail?: string }

const claimAt = (ctx: RunContext): Claim => ({ owner: ctx.owner, now: ctx.now(), leaseMs: ctx.leaseMs })

/** Take the claim if it is ours and live, or if it has expired. Otherwise someone else holds it. */
function acquire(db: Database.Database, id: string, ctx: RunContext): WalletOp | null {
  const op = getOp(db, id)
  if (!op) return null
  const c = claimAt(ctx)
  if (op.lease_owner === ctx.owner && (op.lease_until ?? 0) > c.now) return op
  return takeOver(db, id, c)
}

/**
 * Drive one operation as far as it can go now: prepare a reserved row, publish a prepared row,
 * reconcile an admitted row and, when nothing settled it and enough time passed, publish the same
 * stored block again. Never builds a second block. Every publish goes through commitAttempt.
 */
export async function runOp(db: Database.Database, id: string, ctx: RunContext): Promise<RunResult> {
  let op = acquire(db, id, ctx)
  if (!op) {
    const cur = getOp(db, id)
    return { status: cur?.status ?? 'cancelled', step: cur ? 'claimed_elsewhere' : 'not_found' }
  }
  try {
    if (op.status === 'reserved') {
      try {
        op = await prepareOp(db, ctx.node, op, claimAt(ctx), ctx.signer(op), ctx.openRepresentative)
      } catch (e: any) {
        if (e instanceof WalletOpError && e.code === 'block_mismatch' && CANCEL_ON_PREPARE.has(e.message)) {
          const done = cancelOp(db, op, claimAt(ctx), `cannot_build: ${e.message}`)
          return { status: done.status, step: 'cancelled', detail: e.message }
        }
        return { status: 'reserved', step: 'prepare_failed', detail: String(e?.message ?? e) }
      }
    }
    if (op.status === 'prepared') {
      const a = commitAttempt(db, op, claimAt(ctx))
      if ('refused' in a) return { status: getOp(db, id)!.status, step: 'attempt_refused', detail: a.refused }
      const out = await publishAttempt(db, ctx.node, a.token, ctx.now)
      return { status: 'admitted', step: `published_${out.outcome}` }
    }
    if (op.status === 'admitted') {
      const r = await reconcileOp(db, ctx.node, op, claimAt(ctx), ctx.reconcile)
      if (r.status === 'confirmed') return { status: 'confirmed', step: 'reconciled' }
      if (r.status === 'incident') return { status: 'admitted', step: 'incident', detail: r.sibling }
      if (r.status === 'node_fault') return { status: 'admitted', step: 'node_fault', detail: r.reason }
      const fresh = getOp(db, id)!
      if (ctx.now() - (fresh.last_attempt_at ?? 0) < ctx.rebroadcastMs) return { status: 'admitted', step: 'waiting', detail: r.reason }
      const a = commitAttempt(db, fresh, claimAt(ctx))
      if ('refused' in a) return { status: 'admitted', step: 'rebroadcast_refused', detail: a.refused }
      const out = await publishAttempt(db, ctx.node, a.token, ctx.now)
      return { status: 'admitted', step: `rebroadcast_${out.outcome}` }
    }
    return { status: op.status, step: 'final' }
  } catch (e: any) {
    if (e instanceof WalletOpError && e.code === 'claim_lost') return { status: getOp(db, id)!.status, step: 'claim_lost' }
    if (e instanceof WalletOpError && (e.code === 'reservation_inconsistent' || e.code === 'frontier_inconsistent')) {
      // Nothing settled: the transaction rolled back. The operator has to look at this row.
      console.error(`[nano-lifecycle] ${e.code} op=${id}: ${e.message}`)
      return { status: getOp(db, id)!.status, step: 'integrity_fault', detail: e.message }
    }
    throw e
  }
}

export const newOwnerId = () => `worker-${randomUUID()}`

/** What the routes need from the process that runs operations. */
export interface OpRunner {
  owner: string
  leaseMs: number
  now: () => number
  schedule(id: string): void
  /** null when a new send may be reserved, otherwise the reason it may not (activation gate 2). */
  readiness(): string | null
}

const idleRunner: OpRunner = { owner: 'no-runner', leaseMs: 60_000, now: Date.now, schedule: () => {}, readiness: () => 'lifecycle_not_installed' }
let current: OpRunner = idleRunner

/**
 * The runner the routes use. Without one installed, reserved operations wait for a runner or for
 * recovery, and nothing is published.
 */
export function getOpRunner(): OpRunner { return current }
export function setOpRunner(r: OpRunner | null): void { current = r ?? idleRunner }

/** A runner that drives each scheduled operation with runOp in this process. */
export function inProcessRunner(db: Database.Database, ctx: RunContext): OpRunner & { idle(): Promise<void> } {
  const pending = new Set<Promise<unknown>>()
  return {
    owner: ctx.owner, leaseMs: ctx.leaseMs, now: ctx.now,
    schedule(id: string) {
      const p = runOp(db, id, ctx).catch(e => console.error(`[nano-lifecycle] runOp ${id}: ${e?.message ?? e}`))
      pending.add(p)
      p.finally(() => pending.delete(p))
    },
    async idle() { while (pending.size) await Promise.all([...pending]) },
    readiness: () => null,
  }
}

/**
 * One recovery pass: run every operation that is not final and whose lease has expired or is ours.
 * Call at startup and on an interval.
 */
export async function lifecycleTick(db: Database.Database, ctx: RunContext): Promise<RunResult[]> {
  const ids = (db.prepare(`SELECT id FROM wallet_ops WHERE status IN ('reserved', 'prepared', 'admitted')
    AND (lease_until IS NULL OR lease_until <= ? OR lease_owner = ?) ORDER BY created_at, id`)
    .all(ctx.now(), ctx.owner) as Array<{ id: string }>).map(r => r.id)
  const out: RunResult[] = []
  for (const id of ids) {
    // One operation's failure (a node outage, say) is reported and does not stop the others.
    try { out.push(await runOp(db, id, ctx)) } catch (e: any) {
      out.push({ status: getOp(db, id)?.status ?? 'cancelled', step: 'error', detail: String(e?.message ?? e) })
    }
  }
  return out
}
