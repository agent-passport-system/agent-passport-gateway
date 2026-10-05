// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * G-C3 Scoped Human Approval - durable store.
 *
 * The v2 helper libraries (approval-fatigue, separation-of-powers,
 * effect-sampling) keep their state in process memory (Maps/arrays) and
 * are NOT durable across restarts. Scoped-approval state must survive a
 * restart and feed the audit export, so this module owns SQLite-backed
 * tables. We self-create them with CREATE TABLE IF NOT EXISTS (mirroring
 * identity.ts and coordination self-init) to stay in-worktree and avoid a
 * migration-ordering collision with schema.ts running first at boot.
 *
 * Tables:
 *   approval_requests   - one row per scoped-approval request
 *   approval_signatures - one row per collected approver signature
 *   approval_receipts   - signed approval-receipt rows (see receipts.ts)
 *   approval_samples    - review-sample pulls (effect-sampling, durable)
 */

import { randomUUID } from 'node:crypto'
import { getDB } from '../../db/schema.js'
import type { RiskTier } from './policy.js'

let _initialized = false

export function initApprovalTables(): void {
  if (_initialized) return
  const db = getDB()
  db.exec(`
    CREATE TABLE IF NOT EXISTS approval_requests (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      sdk_request_id TEXT,
      action_class TEXT NOT NULL,
      subject TEXT NOT NULL,
      subject_type TEXT NOT NULL DEFAULT 'delegation',
      risk_tier TEXT NOT NULL,
      requested_by TEXT NOT NULL,
      agent_id TEXT NOT NULL,
      agent_owner_id TEXT NOT NULL,
      requested_scope TEXT NOT NULL DEFAULT '[]',
      status TEXT NOT NULL DEFAULT 'pending',
      decision_reason TEXT,
      decided_by TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      expires_at TEXT NOT NULL,
      decided_at TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_approval_req_tenant ON approval_requests(tenant_id, status);
    CREATE INDEX IF NOT EXISTS idx_approval_req_expiry ON approval_requests(status, expires_at);

    CREATE TABLE IF NOT EXISTS approval_signatures (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      request_id TEXT NOT NULL,
      approver_id TEXT NOT NULL,
      approver_public_key TEXT NOT NULL,
      key_class TEXT NOT NULL,
      office_id TEXT,
      reason TEXT NOT NULL,
      signature TEXT NOT NULL,
      decision_latency_ms INTEGER,
      signed_at TEXT NOT NULL DEFAULT (datetime('now')),
      UNIQUE(request_id, approver_public_key)
    );
    CREATE INDEX IF NOT EXISTS idx_approval_sig_request ON approval_signatures(tenant_id, request_id);

    CREATE TABLE IF NOT EXISTS approval_receipts (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      request_id TEXT NOT NULL,
      action_class TEXT NOT NULL,
      risk_tier TEXT NOT NULL,
      verdict TEXT NOT NULL,
      schema_version TEXT NOT NULL DEFAULT '1.0.0',
      receipt_hash TEXT NOT NULL,
      payload TEXT NOT NULL,
      signature TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_approval_rcpt_tenant ON approval_receipts(tenant_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_approval_rcpt_request ON approval_receipts(request_id);

    CREATE TABLE IF NOT EXISTS approval_samples (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      request_id TEXT NOT NULL,
      risk_tier TEXT NOT NULL,
      sampled INTEGER NOT NULL DEFAULT 0,
      review_status TEXT NOT NULL DEFAULT 'pending',
      reviewer_id TEXT,
      review_result TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      reviewed_at TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_approval_sample_request ON approval_samples(tenant_id, request_id);
    CREATE INDEX IF NOT EXISTS idx_approval_sample_pending ON approval_samples(sampled, review_status);

    -- Approver registry (approvers.ts). One key per approver per tenant,
    -- and one approver per key, so a key cannot be re-registered under an
    -- alias id.
    CREATE TABLE IF NOT EXISTS approval_approvers (
      tenant_id TEXT NOT NULL,
      approver_id TEXT NOT NULL,
      public_key TEXT NOT NULL,
      authority TEXT NOT NULL,
      principal_id TEXT NOT NULL,
      key_class TEXT NOT NULL DEFAULT 'approver',
      office_id TEXT,
      status TEXT NOT NULL DEFAULT 'active',
      registered_by TEXT NOT NULL,
      created_at TEXT NOT NULL,
      revoked_at TEXT,
      PRIMARY KEY (tenant_id, approver_id),
      UNIQUE (tenant_id, public_key)
    );
  `)
  // requested_by_key_id: api_keys.id of the key that opened the request,
  // recorded by the server (the requester side of the independence check).
  // elapsed_since_open_ms: request created_at to /sign arrival, both server
  // clocks. Telemetry only, never an authorization input, and not a measure
  // of how long anyone read the request.
  try { db.exec(`ALTER TABLE approval_requests ADD COLUMN requested_by_key_id TEXT`) } catch {}
  try { db.exec(`ALTER TABLE approval_signatures ADD COLUMN elapsed_since_open_ms INTEGER`) } catch {}
  _initialized = true
}

// ── Request rows ──

export interface ApprovalRequestRow {
  id: string
  tenant_id: string
  sdk_request_id: string | null
  action_class: string
  subject: string
  subject_type: string
  risk_tier: RiskTier
  requested_by: string
  requested_by_key_id: string | null
  agent_id: string
  agent_owner_id: string
  requested_scope: string
  status: 'pending' | 'approved' | 'rejected' | 'expired'
  decision_reason: string | null
  decided_by: string | null
  created_at: string
  expires_at: string
  decided_at: string | null
}

export function insertRequest(row: {
  tenantId: string
  sdkRequestId: string | null
  actionClass: string
  subject: string
  subjectType: string
  riskTier: RiskTier
  requestedBy: string
  requestedByKeyId?: string | null
  agentId: string
  agentOwnerId: string
  requestedScope: string[]
  expiresAt: string
}): string {
  const db = getDB()
  const id = randomUUID()
  // created_at is written with millisecond precision (ISO) because /sign
  // records the server-measured elapsed time from it (telemetry).
  db.prepare(`
    INSERT INTO approval_requests (
      id, tenant_id, sdk_request_id, action_class, subject, subject_type,
      risk_tier, requested_by, requested_by_key_id, agent_id, agent_owner_id,
      requested_scope, status, created_at, expires_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)
  `).run(
    id, row.tenantId, row.sdkRequestId, row.actionClass, row.subject,
    row.subjectType, row.riskTier, row.requestedBy, row.requestedByKeyId ?? null,
    row.agentId, row.agentOwnerId, JSON.stringify(row.requestedScope),
    new Date().toISOString(), row.expiresAt,
  )
  return id
}

/** Parse a stored timestamp. New rows are ISO; rows written by the column
 *  default are SQLite 'YYYY-MM-DD HH:MM:SS' in UTC. NaN when unparseable. */
export function parseStoredTime(s: string | null | undefined): number {
  if (!s) return NaN
  return s.includes('T') ? Date.parse(s) : Date.parse(s.replace(' ', 'T') + 'Z')
}

export function getRequest(tenantId: string, id: string): ApprovalRequestRow | undefined {
  return getDB().prepare(
    `SELECT * FROM approval_requests WHERE tenant_id = ? AND id = ?`
  ).get(tenantId, id) as ApprovalRequestRow | undefined
}

export function listRequests(tenantId: string, status?: string, limit = 50): ApprovalRequestRow[] {
  const db = getDB()
  if (status) {
    return db.prepare(
      `SELECT * FROM approval_requests WHERE tenant_id = ? AND status = ? ORDER BY created_at DESC LIMIT ?`
    ).all(tenantId, status, limit) as ApprovalRequestRow[]
  }
  return db.prepare(
    `SELECT * FROM approval_requests WHERE tenant_id = ? ORDER BY created_at DESC LIMIT ?`
  ).all(tenantId, limit) as ApprovalRequestRow[]
}

/** Decide a request (approve|reject). Atomic + status-guarded: only a
 *  pending, non-expired request may be decided. When commitmentOf and
 *  expectedCommitmentDigest are given, the row read inside the transaction
 *  must still produce that commitment, so the content the approvers'
 *  signatures were verified against is the content being decided.
 *  checkInTx, when given, runs inside the same IMMEDIATE transaction after
 *  those checks and before the UPDATE; a non-null return is the error code
 *  and nothing is written. The caller uses it to read the signatures and
 *  the approver registry under the write lock, so an approver revocation
 *  committed by another connection either lands before the read (and is
 *  seen) or waits until the decision has committed.
 *  nowIso is the caller's clock from before the lock and only serves the
 *  early expiry refusal. The decision time is read from the server clock
 *  after checkInTx, immediately before the UPDATE: an approval whose
 *  request expired while this call waited for the write lock, or while
 *  the checks above ran, is refused as 'expired'. That same instant is
 *  written as decided_at (approve and reject) and returned as decidedAt
 *  for the receipt.
 *  Returns the updated row or null with an error code. */
export function decideRequest(opts: {
  tenantId: string
  id: string
  verdict: 'approved' | 'rejected'
  reason: string
  decidedBy: string
  nowIso: string
  expectedCommitmentDigest?: string
  commitmentOf?: (row: ApprovalRequestRow) => string
  checkInTx?: (row: ApprovalRequestRow) => string | null
}): { row: ApprovalRequestRow | null; error?: string; decidedAt?: string } {
  const db = getDB()
  return db.transaction(() => {
    const row = db.prepare(
      `SELECT * FROM approval_requests WHERE tenant_id = ? AND id = ?`
    ).get(opts.tenantId, opts.id) as ApprovalRequestRow | undefined
    if (!row) return { row: null, error: 'not_found' }
    if (row.status !== 'pending') return { row, error: `not_pending:${row.status}` }
    if (row.expires_at <= opts.nowIso) return { row, error: 'expired' }
    if (opts.expectedCommitmentDigest !== undefined && opts.commitmentOf
        && opts.commitmentOf(row) !== opts.expectedCommitmentDigest) {
      return { row, error: 'commitment_mismatch' }
    }
    if (opts.checkInTx) {
      const err = opts.checkInTx(row)
      if (err) return { row, error: err }
    }
    const decidedAt = new Date().toISOString()
    if (opts.verdict === 'approved' && row.expires_at <= decidedAt) return { row, error: 'expired' }
    db.prepare(`
      UPDATE approval_requests
      SET status = ?, decision_reason = ?, decided_by = ?, decided_at = ?
      WHERE tenant_id = ? AND id = ? AND status = 'pending'
    `).run(opts.verdict, opts.reason, opts.decidedBy, decidedAt, opts.tenantId, opts.id)
    const updated = db.prepare(
      `SELECT * FROM approval_requests WHERE tenant_id = ? AND id = ?`
    ).get(opts.tenantId, opts.id) as ApprovalRequestRow
    return { row: updated, decidedAt }
  }).immediate()
}

/** Mark all pending requests whose expiry has passed as 'expired'. Returns
 *  the rows that were transitioned so the caller can emit events. */
export function expirePastDue(tenantId: string, nowIso: string): ApprovalRequestRow[] {
  const db = getDB()
  const due = db.prepare(
    `SELECT * FROM approval_requests WHERE tenant_id = ? AND status = 'pending' AND expires_at <= ?`
  ).all(tenantId, nowIso) as ApprovalRequestRow[]
  if (due.length === 0) return []
  const stmt = db.prepare(
    `UPDATE approval_requests SET status = 'expired', decided_at = ? WHERE id = ? AND status = 'pending'`
  )
  const tx = db.transaction((rows: ApprovalRequestRow[]) => {
    for (const r of rows) stmt.run(nowIso, r.id)
  })
  tx(due)
  return due.map(r => ({ ...r, status: 'expired' as const, decided_at: nowIso }))
}

// ── Signatures ──

export function insertSignature(row: {
  tenantId: string
  requestId: string
  approverId: string
  approverPublicKey: string
  keyClass: string
  officeId?: string | null
  reason: string
  signature: string
  /** Server-measured request age at /sign arrival. Telemetry only. */
  elapsedSinceOpenMs?: number | null
}): string {
  const db = getDB()
  const id = randomUUID()
  // decision_latency_ms is left NULL on new rows. Older rows may hold a
  // caller-supplied number; new rows write elapsed_since_open_ms instead.
  db.prepare(`
    INSERT INTO approval_signatures (
      id, tenant_id, request_id, approver_id, approver_public_key,
      key_class, office_id, reason, signature, elapsed_since_open_ms
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id, row.tenantId, row.requestId, row.approverId, row.approverPublicKey,
    row.keyClass, row.officeId ?? null, row.reason, row.signature,
    row.elapsedSinceOpenMs ?? null,
  )
  return id
}

export function getSignatures(tenantId: string, requestId: string): Array<{
  approver_id: string; approver_public_key: string; key_class: string
  office_id: string | null; reason: string; signature: string; signed_at: string
}> {
  return getDB().prepare(
    `SELECT approver_id, approver_public_key, key_class, office_id, reason, signature, signed_at
     FROM approval_signatures WHERE tenant_id = ? AND request_id = ? ORDER BY signed_at ASC`
  ).all(tenantId, requestId) as any[]
}

// ── Samples ──

export function insertSample(row: {
  tenantId: string
  requestId: string
  riskTier: RiskTier
  sampled: boolean
}): string {
  const db = getDB()
  const id = randomUUID()
  db.prepare(`
    INSERT INTO approval_samples (id, tenant_id, request_id, risk_tier, sampled, review_status)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(id, row.tenantId, row.requestId, row.riskTier, row.sampled ? 1 : 0,
    row.sampled ? 'pending' : 'not_sampled')
  return id
}

export function getSample(tenantId: string, requestId: string): {
  id: string; sampled: number; review_status: string
} | undefined {
  return getDB().prepare(
    `SELECT id, sampled, review_status FROM approval_samples WHERE tenant_id = ? AND request_id = ? LIMIT 1`
  ).get(tenantId, requestId) as any
}

// ── Receipts ──

export function insertReceipt(row: {
  tenantId: string
  requestId: string
  actionClass: string
  riskTier: RiskTier
  verdict: string
  receiptHash: string
  payload: string
  signature: string | null
  schemaVersion?: string
}): string {
  const db = getDB()
  const id = randomUUID()
  db.prepare(`
    INSERT INTO approval_receipts (
      id, tenant_id, request_id, action_class, risk_tier, verdict,
      schema_version, receipt_hash, payload, signature
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id, row.tenantId, row.requestId, row.actionClass, row.riskTier,
    row.verdict, row.schemaVersion ?? '1.0.0', row.receiptHash, row.payload, row.signature,
  )
  return id
}

export function getReceipt(tenantId: string, id: string): {
  id: string; request_id: string; action_class: string; risk_tier: string
  verdict: string; receipt_hash: string; payload: string; signature: string | null
  created_at: string; schema_version: string
} | undefined {
  return getDB().prepare(
    `SELECT * FROM approval_receipts WHERE tenant_id = ? AND id = ?`
  ).get(tenantId, id) as any
}
