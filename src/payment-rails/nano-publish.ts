// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Nano lifecycle phase C (Day 268): the one publication boundary.
 *
 * This file holds the gateway's only Nano `process` call. A call needs an attempt token, and the
 * only way to get one is commitAttempt, which in one IMMEDIATE transaction re-checks the caller's
 * claim, the pause, the authority behind the operation and the stored block, then records the
 * attempt. A token allows one call. The legacy publish paths in wallet-crypto.ts and nano.ts are
 * closed and cannot reach this function.
 *
 * Timing limit, stated on purpose: a pause or revocation that commits after an attempt commits
 * does not stop the call that attempt allowed. Each attempt commit is the boundary.
 *
 * A node accepting a block is not confirmation. publishAttempt records what the node said and
 * leaves the operation admitted. Only reconciliation (phase D) moves it to confirmed.
 */
import type Database from 'better-sqlite3'
// @ts-ignore nanocurrency-web has no type declarations
import nanoWebImport from 'nanocurrency-web'
import { nanoRpc } from './rpc-client.js'
import { checkBoundAuthorityChain } from '../gateway/enforce.js'
import { boundChainSpendRows, chainSpendHold } from '../gateway/chain-spend.js'
import { parseMinor, type UnitRow } from '../gateway/spend-units.js'
import { addressToPublicKey, parseRaw, stateBlockHash, type StateBlock } from './nano-block.js'
import { frontierViolation } from './wallet-frontier.js'
import {
  WalletOpError, cancelOp, ownReservationViolation, parseConfirmedAccountInfo, storePrepared, walletAccountProblems,
  type Claim, type ConfirmedAccount, type OpKind, type WalletOp,
} from './wallet-ops.js'

const nanoWeb = (nanoWebImport as any).default || nanoWebImport
const nanoBlock = nanoWeb.block
const nanoTools = nanoWeb.tools

/** The node calls the lifecycle makes. Production uses rpcNode, tests a fake. */
export interface NanoNode { call(body: Record<string, unknown>): Promise<any> }

export function rpcNode(rpcUrl: string): NanoNode {
  return { call: (body) => nanoRpc(rpcUrl, body) }
}

/** The emergency switches, read at the moment of each check. */
export function nanoPublishAllowed(kind: OpKind): { ok: true } | { ok: false; reason: string } {
  if (process.env.NANO_WALLETS_PAUSED === '1') return { ok: false, reason: 'nano_wallets_paused' }
  if (kind === 'send' && process.env.NANO_WALLET_SEND_ENABLED !== '1') return { ok: false, reason: 'nano_send_disabled' }
  return { ok: true }
}

/**
 * Whether the authority behind an operation still holds, against the current database. Returns
 * null when it does, otherwise the reason. Read inside the attempt transaction.
 */
export function attemptAuthorityViolation(db: Database.Database, op: WalletOp): string | null {
  if (walletAccountProblems(db, null).length > 0) return 'wallet_account_mapping_unsafe'
  const wallet = db.prepare(`SELECT tenant_id, agent_id, nano_address, status FROM agent_wallets WHERE id = ?`).get(op.wallet_id) as any
  if (!wallet || wallet.tenant_id !== op.tenant_id) return 'wallet_missing'
  if (wallet.nano_address !== op.nano_account) return 'wallet_account_changed'
  if (wallet.status !== 'active') return 'wallet_not_active'
  if (op.kind !== 'send') return null

  const d = db.prepare(`SELECT tenant_id, child_agent_id, status FROM delegations WHERE id = ?`).get(op.delegation_id) as any
  if (!d || d.tenant_id !== op.tenant_id) return 'delegation_missing'
  if (d.child_agent_id !== op.from_agent_id || wallet.agent_id !== op.from_agent_id) return 'delegation_agent_mismatch'
  if (d.status !== 'active') return 'delegation_not_active'
  const chain = checkBoundAuthorityChain(db, op.tenant_id, op.delegation_id!)
  if (!chain.ok) return `authority_chain_${chain.code}`
  const agent = db.prepare(`SELECT status FROM agents WHERE tenant_id = ? AND agent_id = ?`).get(op.tenant_id, op.from_agent_id) as any
  if (!agent || (agent.status !== 'active' && agent.status !== 'restricted')) return 'paying_agent_not_active'
  const holdRows = boundChainSpendRows(db, op.tenant_id, op.delegation_id!)
  if (!holdRows || chainSpendHold(db, holdRows)) return 'chain_on_upgrade_hold'
  // The operation's own reservation rows, then the counters they debited.
  const own = ownReservationViolation(db, op)
  if (own) return own
  const amount = BigInt(op.amount_raw)
  for (const r of JSON.parse(op.chain_rows!) as UnitRow[]) {
    if (r.spend_unit == null) continue
    const cur = db.prepare(`SELECT spend_used_minor FROM delegations WHERE id = ?`).get(r.id) as any
    const used = parseMinor(cur?.spend_used_minor ?? null)
    if (used === null || used < amount) return 'reservation_missing'
  }
  return null
}

/** Violations that mean the stored state is wrong, not that permission was withdrawn. */
export const INTEGRITY_FAULTS: ReadonlySet<string> = new Set([
  'wallet_account_mapping_unsafe', 'wallet_missing', 'wallet_account_changed', 'delegation_missing',
  'delegation_agent_mismatch', 'reservation_missing', 'reservation_not_held', 'reservation_amount_mismatch',
])

/**
 * Whether the stored block is exactly the approved operation, read from the block itself: its
 * account and previous are the operation's, its signature verifies under that account, it pays the
 * approved destination (or receives the approved source), and previous balance minus block balance
 * is exactly the reserved amount for a send (block minus previous for a receive or open).
 */
export function storedBlockViolation(row: WalletOp, block: StateBlock): string | null {
  if (block.account !== row.nano_account) return 'stored_block_account_mismatch'
  if (block.previous !== row.block_previous) return 'stored_block_previous_mismatch'
  if (block.balance !== row.block_balance_raw) return 'stored_block_balance_mismatch'
  const prev = parseRaw(row.prev_balance_raw)
  const now = parseRaw(block.balance)
  const amount = parseRaw(row.amount_raw)
  if (prev === null || now === null || amount === null) return 'stored_block_amount_unreadable'
  if (row.kind === 'send') {
    if (block.link !== addressToPublicKey(row.to_address!)) return 'stored_block_destination_mismatch'
    if (prev - now !== amount) return 'stored_block_amount_mismatch'
  } else {
    if (block.link !== row.source_hash) return 'stored_block_source_mismatch'
    if (now - prev !== amount) return 'stored_block_amount_mismatch'
  }
  if (!nanoTools.verifyBlock(addressToPublicKey(row.nano_account), block)) return 'stored_block_signature_invalid'
  return null
}

/**
 * Whether a block a node reported verifies under the account's key. A valid signature shows the
 * account's signing authority was used. It does not say by whom.
 */
export function blockSignatureValid(account: string, block: unknown): boolean {
  try { return nanoTools.verifyBlock(addressToPublicKey(account), block) === true } catch { return false }
}

const issued = new WeakSet<AttemptToken>()

/** Permission for exactly one `process` call with one stored block. Created only by commitAttempt. */
export class AttemptToken {
  private constructor(
    readonly opId: string,
    readonly attempt: number,
    readonly kind: OpKind,
    readonly blockHash: string,
    readonly block: StateBlock,
  ) {}
  /** @internal */
  static mint(opId: string, attempt: number, kind: OpKind, blockHash: string, block: StateBlock): AttemptToken {
    const t = new AttemptToken(opId, attempt, kind, blockHash, block)
    issued.add(t)
    return t
  }
}

export type AttemptResult =
  | { token: AttemptToken; attempt: number }
  | { refused: string; cancelled: boolean }

/**
 * Commit one publish attempt. The first attempt moves the row from prepared to admitted, and
 * competes with cancel for the same row. A refused first attempt for withdrawn authority cancels
 * the operation and releases its reservation in the same transaction. A refused retry changes
 * nothing. A caller without the current claim gets claim_lost and no token.
 */
export function commitAttempt(db: Database.Database, op: Pick<WalletOp, 'id' | 'claim_epoch'>, claim: Claim): AttemptResult {
  return db.transaction((): AttemptResult => {
    const row = db.prepare(`SELECT * FROM wallet_ops WHERE id = ? AND claim_epoch = ? AND lease_owner = ?
        AND lease_until > ? AND status IN ('prepared', 'admitted')`)
      .get(op.id, op.claim_epoch, claim.owner, claim.now) as WalletOp | undefined
    if (!row) throw new WalletOpError('claim_lost', 'no publishable row under this claim')

    const gate = nanoPublishAllowed(row.kind)
    if ('reason' in gate) return { refused: gate.reason, cancelled: false }

    const bad = attemptAuthorityViolation(db, row)
    if (bad) {
      // Withdrawn authority on a first attempt cancels and releases. An integrity fault (an unsafe
      // account mapping, a missing reservation, a row that no longer matches its wallet or
      // delegation) changes nothing: releasing a reservation that is not there would be wrong,
      // and the operator has to look.
      if (row.status === 'prepared' && !INTEGRITY_FAULTS.has(bad)) {
        cancelOp(db, row, claim, `authority_withdrawn: ${bad}`)
        return { refused: bad, cancelled: true }
      }
      return { refused: bad, cancelled: false }
    }

    const block = JSON.parse(row.block_json!) as StateBlock
    if (stateBlockHash(block) !== row.block_hash) return { refused: 'stored_block_hash_mismatch', cancelled: false }
    const binding = storedBlockViolation(row, block)
    if (binding) return { refused: binding, cancelled: false }
    const flagged = db.prepare(`SELECT 1 FROM wallet_op_attempts WHERE op_id = ? AND outcome = 'hash_mismatch'`).get(row.id)
    if (flagged) return { refused: 'publish_hash_mismatch_recorded', cancelled: false }

    const attempt = row.attempt_count + 1
    const res = db.prepare(`UPDATE wallet_ops
        SET status = 'admitted', attempt_count = ?, last_attempt_at = ?, admitted_at = COALESCE(admitted_at, ?),
            updated_at = datetime('now')
      WHERE id = ? AND status = ? AND attempt_count = ? AND claim_epoch = ? AND lease_owner = ? AND lease_until > ?`)
      .run(attempt, claim.now, claim.now, row.id, row.status, row.attempt_count, row.claim_epoch, claim.owner, claim.now)
    if (res.changes !== 1) throw new WalletOpError('claim_lost', 'the row changed under this claim')
    db.prepare(`INSERT INTO wallet_op_attempts (op_id, attempt_no, claim_epoch, lease_owner, block_hash, committed_at)
      VALUES (?, ?, ?, ?, ?, ?)`).run(row.id, attempt, row.claim_epoch, claim.owner, row.block_hash, claim.now)
    return { token: AttemptToken.mint(row.id, attempt, row.kind, row.block_hash!, block), attempt }
  }).immediate()
}

export type PublishOutcome =
  | { outcome: 'accepted'; hash: string }
  | { outcome: 'hash_mismatch'; hash: string }
  | { outcome: 'error'; error: string }
  | { outcome: 'skipped_paused'; reason: string }

function recordOutcome(db: Database.Database, t: AttemptToken, outcome: string, detail: string | null, now: number): void {
  db.prepare(`UPDATE wallet_op_attempts SET outcome = ?, detail = ?, outcome_at = ?
    WHERE op_id = ? AND attempt_no = ? AND outcome IS NULL`).run(outcome, detail, now, t.opId, t.attempt)
}

/**
 * The gateway's only Nano `process` call. Spends the token, re-reads the pause, then calls the
 * node with the stored block. Whatever the node answers, the operation stays admitted.
 */
export async function publishAttempt(db: Database.Database, node: NanoNode, token: AttemptToken, now: () => number = Date.now): Promise<PublishOutcome> {
  if (!issued.has(token)) throw new Error('publishAttempt needs an unspent token from commitAttempt')
  issued.delete(token)
  const gate = nanoPublishAllowed(token.kind)
  if ('reason' in gate) {
    recordOutcome(db, token, 'skipped_paused', gate.reason, now())
    return { outcome: 'skipped_paused', reason: gate.reason }
  }
  let res: any
  try {
    res = await node.call({ action: 'process', json_block: 'true', subtype: token.kind, block: token.block })
  } catch (e: any) {
    const error = String(e?.message ?? e)
    recordOutcome(db, token, 'error', error.slice(0, 500), now())
    return { outcome: 'error', error }
  }
  const hash = typeof res?.hash === 'string' ? res.hash.toUpperCase() : ''
  if (hash !== token.blockHash) {
    recordOutcome(db, token, 'hash_mismatch', hash || 'no hash in response', now())
    return { outcome: 'hash_mismatch', hash }
  }
  recordOutcome(db, token, 'accepted', null, now())
  return { outcome: 'accepted', hash }
}

/** Signs a block for an operation's account. Production derives the key from the master seed. */
export interface Signer { address: string; privateKey: string }

const ZERO64 = '0'.repeat(64)

/**
 * Build, sign and store the one block for a reserved operation, on the account's confirmed state.
 * Reads the node, never publishes. A missing confirmed field, an unconfirmed frontier or a block
 * that does not match the operation leaves the row reserved.
 */
export async function prepareOp(
  db: Database.Database, node: NanoNode, op: WalletOp, claim: Claim, signer: Signer, openRepresentative: string,
): Promise<WalletOp> {
  if (signer.address !== op.nano_account) throw new WalletOpError('block_mismatch', 'signer_account_mismatch')
  let account: ConfirmedAccount
  if (op.kind === 'open') {
    try {
      await node.call({ action: 'account_info', account: op.nano_account, include_confirmed: 'true', representative: 'true' })
      throw new WalletOpError('block_mismatch', 'open_on_opened_account')
    } catch (e: any) {
      if (e instanceof WalletOpError) throw e
      if (!/Account not found/.test(String(e?.message))) throw e
    }
    account = { frontier: ZERO64, confirmed_frontier: ZERO64, confirmed_balance: '0', confirmed_representative: openRepresentative }
  } else {
    const parsed = parseConfirmedAccountInfo(
      await node.call({ action: 'account_info', account: op.nano_account, include_confirmed: 'true', representative: 'true' }))
    if ('error' in parsed) throw new WalletOpError('block_mismatch', parsed.error)
    account = parsed
    // Gate 1: a send is built only on the locally recorded state. A node that disagrees, or an
    // account with no recorded state, leaves the operation reserved for an operator.
    if (op.kind === 'send') {
      const bad = frontierViolation(db, op.nano_account, account.confirmed_frontier, account.confirmed_balance)
      if (bad) throw new WalletOpError('block_mismatch', bad)
    }
  }
  if (account.frontier !== account.confirmed_frontier) throw new WalletOpError('block_mismatch', 'frontier_unconfirmed')
  const workRoot = op.kind === 'open' ? addressToPublicKey(op.nano_account) : account.confirmed_frontier
  const work = (await node.call({ action: 'work_generate', hash: workRoot }))?.work
  if (typeof work !== 'string') throw new WalletOpError('block_mismatch', 'work_missing')

  const block: StateBlock = op.kind === 'send'
    ? nanoBlock.send({
        walletBalanceRaw: account.confirmed_balance, fromAddress: op.nano_account, toAddress: op.to_address,
        representativeAddress: account.confirmed_representative, frontier: account.confirmed_frontier,
        amountRaw: op.amount_raw, work,
      }, signer.privateKey)
    : nanoBlock.receive({
        walletBalanceRaw: account.confirmed_balance, toAddress: op.nano_account, transactionHash: op.source_hash,
        frontier: account.confirmed_frontier, representativeAddress: account.confirmed_representative,
        amountRaw: op.amount_raw, work,
      }, signer.privateKey)
  return storePrepared(db, op, claim, block, account)
}

/** The attempt history of one operation, oldest first. */
export function listAttempts(db: Database.Database, opId: string): any[] {
  return db.prepare(`SELECT * FROM wallet_op_attempts WHERE op_id = ? ORDER BY attempt_no`).all(opId)
}

