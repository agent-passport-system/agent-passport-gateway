// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * G-C3 Scoped Human Approval - router.
 *
 * Approval is SCOPED AUTHORITY, not a rubber-stamp button. Mounted at
 * /api/v1 alongside the other gateway routers, but as a SEPARATE router
 * (not bolted into the 2858-line enforce.ts gatewayRouter) with a unique
 * /approvals prefix so it cannot collide with /evaluate, /receipt, /revoke,
 * /delegations, /audit, /tasks, /access-receipts, /derivations.
 *
 * Routes:
 *   POST /approvals                 - open a scoped-approval request
 *   GET  /approvals                 - list requests (tenant-scoped)
 *   GET  /approvals/:id             - request detail + signatures + sample
 *   POST /approvals/:id/sign        - an approver signs (scoped-authority gated)
 *   POST /approvals/:id/decide      - finalize approve/reject + issue receipt
 *   GET  /approvals/:id/receipt     - fetch the issued approval receipt
 *                                     (full signed payload, tenant-authenticated)
 *
 * Approvers are registered by the tenant admin (approvers-router.ts,
 * /approvers, tenant_admin key only).
 *
 * Consumes (does not reinvent):
 *   - SDK createApprovalRequest / addApprovalSignature / evaluateThreshold
 *     for the multi-party signing + threshold core.
 *   - SDK checkHumanApprovalThreshold for value-based high-risk routing.
 *   - getGatewayIdentity().sign (via receipts.ts) for the receipt signature.
 *   - getEventBus().emit for the SSE spine.
 *   - v2 effect-sampling for the review-sample pull.
 *   - v2 approval-fatigue history, fed only by accepted signatures. Nothing
 *     on this router reads it back: /sign runs no fatigue or rubber-stamp
 *     check and returns no fatigue flag.
 *   - v2 separation-of-powers for approver-outside-owner.
 *   - v2 scope-violations is available for action-class scope match; the
 *     scoped-authority gate here uses policy.checkScopedAuthority.
 *   - the G-C1 connector seam (connector.ts) for approver notification and
 *     sample-for-review, interim email transport until C1 lands.
 */

import { Router } from 'express'
import { randomUUID } from 'node:crypto'
import { RateLimiterMemory } from 'rate-limiter-flexible'
import { getDB } from '../../db/schema.js'
import { getEventBus } from '../events.js'
import type { Tenant } from '../../auth/api-keys.js'

import {
  classifyRisk, clampTtlSeconds, isHighRiskTier, checkScopedAuthority,
  type RiskTier,
} from './policy.js'
import {
  initApprovalTables, insertRequest, getRequest, listRequests, decideRequest,
  expirePastDue, insertSignature, getSignatures, insertSample, getSample,
  getReceipt, parseStoredTime, type ApprovalRequestRow,
} from './store.js'
import { issueApprovalReceipt, emitApprovalSet } from './receipts.js'
import {
  approvalCommitment, verifyApproverSignature, approverKeyId, approverEvidenceDigest,
} from './commitment.js'
import { getActiveApprover } from './approvers.js'
import { getApprovalConnectorRouter } from './connector.js'

// v2 pure-logic helpers (consume, do not re-implement). These keep
// in-memory state; durable approval state lives in store.ts.
import {
  createSamplingPolicy, shouldSample, recordSample,
} from '../../sdk-migrated/v2/effect-sampling.js'
import {
  recordApproval,
} from '../../sdk-migrated/v2/approval-fatigue.js'

// ── SDK charter approval surface (consume the real threshold/signature core).
// TODO(W2-approval-token / W2-narrow / W2-set): the installed alpha SDK
// (agent-passport-system@2.6.0-alpha.3) exposes the multi-party threshold
// signing core below but NOT ephemeral approval tokens, monotonic scope
// narrowing, or SET emission. Those are stubbed in receipts.ts.
import {
  createApprovalRequest as sdkCreateApprovalRequest,
  checkHumanApprovalThreshold as sdkCheckHumanApprovalThreshold,
} from 'agent-passport-system'

export const approvalRouter = Router()

// ── one-time module init ──
let _bootstrapped = false
let _samplingPolicyId: string | null = null

function bootstrap(): void {
  if (_bootstrapped) return
  initApprovalTables()
  // A single sampling policy drives the review-sample pull. Critical always
  // sampled; high-risk half; medium quarter; low rarely. Mirrors TIER_RULES.
  _samplingPolicyId = createSamplingPolicy({
    name: 'scoped-approval-review',
    base_rate: 0.05,
    medium_rate: 0.25,
    high_rate: 0.5,
    critical_rate: 1.0,
  }).id
  _bootstrapped = true
}

const approvalLimiter = new RateLimiterMemory({
  points: 60,
  duration: 60,
  keyPrefix: 'approval',
})

/** Resolve the owner (principal) of an agent within a tenant. Agents are
 *  tenant-scoped; the owner is the tenant principal unless the agent row
 *  carries an explicit entity_id. Used for the approver-outside-owner rule. */
function resolveAgentOwner(tenantId: string, agentId: string): string | null {
  const db = getDB()
  const row = db.prepare(
    `SELECT agent_id, entity_id FROM agents WHERE tenant_id = ? AND agent_id = ?`
  ).get(tenantId, agentId) as { agent_id: string; entity_id: string | null } | undefined
  if (!row) return null
  // Owner identity = explicit entity_id if present, else the tenant id.
  return row.entity_id || tenantId
}

/** The agent's own registered public key, so an approver key equal to it
 *  (the agent approving itself) can be refused. */
function agentPublicKey(tenantId: string, agentId: string): string | null {
  const row = getDB().prepare(
    `SELECT public_key FROM agents WHERE tenant_id = ? AND agent_id = ?`
  ).get(tenantId, agentId) as { public_key: string } | undefined
  return row?.public_key ? String(row.public_key).toLowerCase() : null
}

/** Authority-relevant fields an approval cannot bind: nothing stores them,
 *  the commitment does not cover them and the receipt does not carry them.
 *  Silently dropping them would let a caller believe "transfer of 100 to
 *  acct-A" was approved when only the action class and scope were. */
const UNBINDABLE_FIELDS = ['amount', 'currency', 'params', 'target'] as const

/** /sign body fields the gateway derives from storage. approver_id selects
 *  a registered approver; its key, authority, key class and office come
 *  from the registry, the elapsed time is measured by the server, and the
 *  batch is always 1 (one /sign call is one signature over one request
 *  commitment). A body carrying any of these is refused rather than
 *  silently ignored. */
const SERVER_BOUND_SIGN_FIELDS = [
  'approver_public_key', 'authority', 'key_class', 'office_id', 'decision_latency_ms',
  'batch_size',
] as const

/** Request content fixed at open. The commitment an approver signs and the
 *  receipt both come from the stored row, so these in a /sign or /decide
 *  body could never change what is approved. They are refused rather than
 *  silently ignored, so a caller cannot believe it changed them. */
const REQUEST_BOUND_FIELDS = ['subject', 'action_class', 'requested_scope'] as const

function rejectRequestBound(body: any, res: any): boolean {
  const present = REQUEST_BOUND_FIELDS.filter(f => body && Object.prototype.hasOwnProperty.call(body, f))
  if (present.length === 0) return false
  res.status(400).json({
    error: `Fields fixed when the request was opened: ${present.join(', ')}. Open a new request to change them.`,
    code: 'request_bound_field', fields: present,
  })
  return true
}

function rejectServerBound(body: any, res: any): boolean {
  const present = SERVER_BOUND_SIGN_FIELDS.filter(f => body && Object.prototype.hasOwnProperty.call(body, f))
  if (present.length === 0) return false
  res.status(400).json({
    error: `Fields set by the gateway, not the caller: ${present.join(', ')}. Send approver_id, reason and signature.`,
    code: 'server_bound_field', fields: present,
  })
  return true
}

function rejectUnbindable(body: any, res: any): boolean {
  const present = UNBINDABLE_FIELDS.filter(f => body && Object.prototype.hasOwnProperty.call(body, f))
  if (present.length === 0) return false
  res.status(400).json({
    error: `Fields not bound by an approval: ${present.join(', ')}. Encode limits in requested_scope.`,
    code: 'unbindable_field', fields: present,
  })
  return true
}

function sweepExpired(tenantId: string): void {
  const expired = expirePastDue(tenantId, new Date().toISOString())
  for (const r of expired) {
    try {
      getEventBus().emit(tenantId, {
        type: 'approval_expired',
        agentId: r.agent_id,
        data: { request_id: r.id, action_class: r.action_class, risk_tier: r.risk_tier },
      })
    } catch { /* SSE emit must not crash the request */ }
  }
}

// ═══════════════════════════════════════
// POST /approvals - open a scoped-approval request
// ═══════════════════════════════════════
approvalRouter.post('/approvals', async (req: any, res) => {
  bootstrap()
  const tenant: Tenant = req.tenant
  try { await approvalLimiter.consume(tenant.id) } catch {
    return res.status(429).json({ error: 'Rate limit exceeded' })
  }
  if (rejectUnbindable(req.body, res)) return

  const {
    action_class, subject, subject_type, agent_id, requested_by,
    requested_scope, ttl_seconds, approver_to, estimated_total,
  } = req.body || {}

  if (!action_class || !subject || !agent_id || !requested_by) {
    return res.status(400).json({
      error: 'Required: action_class, subject, agent_id, requested_by',
    })
  }

  // Agent must exist under this tenant (tenant isolation + owner resolution).
  const agentOwner = resolveAgentOwner(tenant.id, agent_id)
  if (!agentOwner) {
    return res.status(404).json({ error: `Agent "${agent_id}" not found for tenant` })
  }

  const tier: RiskTier = classifyRisk(action_class)

  // SDK value-threshold check: when an estimated total is supplied, the SDK
  // decides whether human approval is required for the value band. We use it
  // as an ADVISORY signal recorded on the request; the scoped-authority gate
  // below is the binding control.
  let valueGate: string | null = null
  if (estimated_total && typeof estimated_total === 'object') {
    try {
      // checkHumanApprovalThreshold(delegation, estimatedTotal) -> reason|null
      valueGate = sdkCheckHumanApprovalThreshold(
        // Minimal delegation shape the SDK reads; real delegation comes from
        // the delegations table in the integrated path.
        { requiresHumanApproval: true } as any,
        estimated_total as any,
      )
    } catch { valueGate = null }
  }

  const ttl = clampTtlSeconds(tier, typeof ttl_seconds === 'number' ? ttl_seconds : undefined)
  const expiresAt = new Date(Date.now() + ttl * 1000).toISOString()

  // Consume the SDK multi-party request builder for the canonical request id
  // + expiry model. We persist our own durable row keyed to it.
  let sdkRequestId: string | null = null
  try {
    const sdkReq = sdkCreateApprovalRequest(
      `scoped-approval-${tier}`,
      subject,
      // Map our action to the SDK subject type; default 'delegation'.
      (subject_type || 'delegation') as any,
      requested_by,
      ttl,
    )
    sdkRequestId = sdkReq.requestId
  } catch { sdkRequestId = null }

  const scopeArr: string[] = Array.isArray(requested_scope)
    ? requested_scope.map(String) : []

  const id = insertRequest({
    tenantId: tenant.id,
    sdkRequestId,
    actionClass: action_class,
    subject,
    subjectType: subject_type || 'delegation',
    riskTier: tier,
    requestedBy: requested_by,
    // The key that opened the request, recorded server-side. requested_by
    // is a caller-supplied label and is not used for the independence check.
    requestedByKeyId: tenant.key_id ?? null,
    agentId: agent_id,
    agentOwnerId: agentOwner,
    requestedScope: scopeArr,
    expiresAt,
  })

  // Pull the review sample now (durable). effect-sampling decides; critical
  // is always sampled. The sample is the 'pull a sample for review' control.
  let sampled = false
  try {
    sampled = shouldSample(_samplingPolicyId!, tier)
    recordSample({
      policy_id: _samplingPolicyId!, agent_id: agent_id,
      action_id: id, risk_class: tier, sampled,
    })
  } catch { sampled = false }
  insertSample({ tenantId: tenant.id, requestId: id, riskTier: tier, sampled })

  // Route approver notification (and the sample-for-review) through the C1
  // connector seam - interim email transport until C1 lands.
  const connector = getApprovalConnectorRouter()
  const summary = `Scoped approval requested for ${action_class} on agent ${agent_id}.`
  try {
    if (approver_to) {
      await connector.route('notify_approver', {
        to: approver_to, requestId: id, actionClass: action_class,
        riskTier: tier, summary,
      })
    }
    if (sampled && approver_to) {
      await connector.route('sample_for_review', {
        to: approver_to, requestId: id, actionClass: action_class,
        riskTier: tier, summary: `Review sample pulled for ${action_class}.`,
      })
    }
  } catch { /* notification is best-effort; the request still stands */ }

  try {
    getEventBus().emit(tenant.id, {
      type: 'approval_requested',
      agentId: agent_id,
      data: { request_id: id, action_class, risk_tier: tier, sampled, expires_at: expiresAt },
    })
  } catch {}

  res.status(201).json({
    id, status: 'pending', action_class, risk_tier: tier,
    high_risk: isHighRiskTier(tier), expires_at: expiresAt,
    sampled, value_gate: valueGate, sdk_request_id: sdkRequestId,
  })
})

// ═══════════════════════════════════════
// GET /approvals - list (tenant-scoped)
// ═══════════════════════════════════════
approvalRouter.get('/approvals', (req: any, res) => {
  bootstrap()
  const tenant: Tenant = req.tenant
  sweepExpired(tenant.id)
  const status = req.query.status as string | undefined
  const rows = listRequests(tenant.id, status)
  res.json({ approvals: rows, total: rows.length })
})

// ═══════════════════════════════════════
// GET /approvals/:id - detail
// ═══════════════════════════════════════
approvalRouter.get('/approvals/:id', (req: any, res) => {
  bootstrap()
  const tenant: Tenant = req.tenant
  sweepExpired(tenant.id)
  const row = getRequest(tenant.id, req.params.id)
  if (!row) return res.status(404).json({ error: 'Approval request not found' })
  const signatures = getSignatures(tenant.id, req.params.id)
  const sample = getSample(tenant.id, req.params.id)
  // The exact message an approver signs (commitment.ts).
  const c = approvalCommitment(row)
  const commitment = { scheme: c.scheme, message: c.message, digest: c.digest }
  res.json({ ...row, signatures, sample, commitment })
})

// ═══════════════════════════════════════
// POST /approvals/:id/sign - an approver signs
// Body: approver_id, reason, signature. approver_id selects an approver the
// tenant admin registered (approvers.ts); its key, authority, key class and
// office come from the registry. approver_public_key, authority, key_class,
// office_id, decision_latency_ms and batch_size in the body are refused
// with 400 server_bound_field. One /sign call carries one signature over
// one request commitment, so the batch is always 1. subject, action_class
// and requested_scope are fixed at open and refused with 400
// request_bound_field (also on /decide).
// The signature must verify under the registered key over the request
// commitment (commitment.ts). Then the scoped-authority gate: authority
// match; for high-risk tiers the approver must be independent of the
// owner side (see below); reason required.
// Elapsed time since the request opened is recorded as telemetry and is
// never a reason to refuse. No fatigue or rubber-stamp check runs here.
// ═══════════════════════════════════════
approvalRouter.post('/approvals/:id/sign', (req: any, res) => {
  bootstrap()
  const tenant: Tenant = req.tenant
  // Server clock at arrival, before any other work.
  const arrivedMs = Date.now()
  sweepExpired(tenant.id)

  const row = getRequest(tenant.id, req.params.id)
  if (!row) return res.status(404).json({ error: 'Approval request not found' })
  if (row.status !== 'pending') {
    return res.status(409).json({ error: `Request is "${row.status}", not pending` })
  }
  if (row.expires_at <= new Date().toISOString()) {
    return res.status(409).json({ error: 'Request has expired' })
  }

  if (rejectUnbindable(req.body, res)) return
  if (rejectServerBound(req.body, res)) return
  if (rejectRequestBound(req.body, res)) return
  const { approver_id, reason, signature } = req.body || {}

  if (!approver_id || !reason) {
    return res.status(400).json({ error: 'Required: approver_id, reason, signature' })
  }
  if (typeof signature !== 'string' || signature.length === 0) {
    return res.status(400).json({ error: 'Required: signature', code: 'signature_required' })
  }
  // Rule 5: a reason is required and must be substantive.
  if (typeof reason !== 'string' || reason.trim().length < 3) {
    return res.status(400).json({ error: 'A substantive reason is required' })
  }

  // Approver principal, key and authority from the registry only.
  const approver = getActiveApprover(tenant.id, String(approver_id))
  if (!approver) {
    return res.status(403).json({
      error: 'Approver is not registered for this tenant', code: 'approver_not_registered',
    })
  }

  // The signature must verify under the registered key over this request's
  // commitment. A signature over any other request content fails here.
  const commitment = approvalCommitment(row)
  if (!verifyApproverSignature(commitment, signature, approver.public_key)) {
    return res.status(403).json({
      error: 'Approver signature does not verify over the request commitment',
      code: 'approver_signature_invalid',
    })
  }

  const tier = row.risk_tier as RiskTier

  // Independence check for high-risk tiers. It compares registered
  // identities and key material only, never caller-supplied names:
  //   owner side  = the agent owner (agents.entity_id, else the tenant id),
  //                 the agent itself (agent_id), and the API key that opened
  //                 the request (requested_by_key_id, recorded server-side)
  //   approver    = its registered approver_id and principal_id
  //   key         = the agent's registered public key vs the approver key
  // It shows the approver is not registered as one of those identities and
  // does not hold the agent's key. It does not prove that a different human
  // holds the approver key: that is up to the tenant admin who registered it.
  if (isHighRiskTier(tier) && agentPublicKey(tenant.id, row.agent_id) === approver.public_key) {
    return res.status(403).json({
      error: 'High-risk approval requires an approver outside the agent owner',
      code: 'self_approval_high_risk',
    })
  }
  const scopeCheck = checkScopedAuthority({
    actionClass: row.action_class,
    tier,
    approverAuthority: approver.authority,
    approverId: approver.approver_id,
    approverPrincipalId: approver.principal_id,
    agentOwnerId: row.agent_owner_id,
    ownerAliases: [row.agent_id, row.requested_by_key_id].filter((x): x is string => !!x),
    batchSize: 1,
  })
  if (!scopeCheck.allowed) {
    return res.status(403).json({ error: scopeCheck.reason, code: scopeCheck.code })
  }

  // Request age at arrival: created_at (written by this server at open) to
  // arrivedMs. Telemetry only. It says nothing about how long anyone read
  // the request; a caller can wait or not.
  const openedMs = parseStoredTime(row.created_at)
  const elapsedMs = Number.isFinite(openedMs) ? Math.max(0, arrivedMs - openedMs) : null

  // Persist the verified signature with the registry key and office.
  let sigId: string
  try {
    sigId = insertSignature({
      tenantId: tenant.id,
      requestId: row.id,
      approverId: approver.approver_id,
      approverPublicKey: approver.public_key,
      keyClass: approver.key_class,
      officeId: approver.office_id,
      reason,
      signature,
      elapsedSinceOpenMs: elapsedMs,
    })
  } catch (e: any) {
    if (String(e?.message || '').includes('UNIQUE')) {
      return res.status(409).json({ error: 'This approver key has already signed' })
    }
    throw e
  }

  // Fatigue history is written only here, after the signature is accepted
  // and stored, so a refused attempt is never recorded and a retry (which
  // hits the UNIQUE above) cannot add history. The helper's latency field
  // carries the request age; it is not reading time. Nothing on this route
  // reads the history back: the rubber-stamp check was removed because its
  // only discriminating input here was that age.
  recordApproval({
    id: sigId,
    principal_id: approver.approver_id,
    agent_id: row.agent_id,
    intent_id: row.id,
    decision: 'approved',
    decision_latency_ms: elapsedMs ?? 0,
    risk_class: tier,
    intent_complexity: isHighRiskTier(tier) ? 0.8 : 0.2,
    timestamp: new Date(arrivedMs).toISOString(),
  })

  res.status(201).json({
    signature_id: sigId, request_id: row.id, commitment_digest: commitment.digest,
  })
})

// ═══════════════════════════════════════
// POST /approvals/:id/decide - finalize + issue receipt
// ═══════════════════════════════════════
approvalRouter.post('/approvals/:id/decide', (req: any, res) => {
  bootstrap()
  const tenant: Tenant = req.tenant
  sweepExpired(tenant.id)

  if (rejectUnbindable(req.body, res)) return
  if (rejectRequestBound(req.body, res)) return
  const { verdict, reason, decided_by } = req.body || {}
  if (verdict !== 'approved' && verdict !== 'rejected') {
    return res.status(400).json({ error: 'verdict must be "approved" or "rejected"' })
  }
  if (!reason || typeof reason !== 'string' || reason.trim().length < 3) {
    return res.status(400).json({ error: 'A substantive reason is required' })
  }
  if (!decided_by) return res.status(400).json({ error: 'Required: decided_by' })

  const existing = getRequest(tenant.id, req.params.id)
  if (!existing) return res.status(404).json({ error: 'Approval request not found' })

  // Approver evidence is checked inside decideRequest's IMMEDIATE
  // transaction (checkInTx), not before it. The store is a SQLite file in
  // WAL mode that more than one process can open, so an approver
  // revocation committed by another connection between a check here and
  // the decision commit would otherwise go unseen. Under the write lock it
  // either landed before the reads below or waits for this commit.
  //
  // On approve, require at least one collected signature - an approval with
  // zero approver signatures is a rubber-stamp button, which this module
  // exists to refuse. Every stored signature is re-verified against the
  // commitment of the row as it is NOW, under the approver's current
  // registry key. A row changed after signing, or a revoked or re-keyed
  // approver, fails here.
  const commitment = approvalCommitment(existing)
  let verified: Array<{ approver_id: string; key_id: string; signature: string }> = []
  let invalid = 0
  const now = new Date().toISOString()
  const { row, error } = decideRequest({
    tenantId: tenant.id, id: req.params.id, verdict,
    reason, decidedBy: decided_by, nowIso: now,
    expectedCommitmentDigest: commitment.digest,
    commitmentOf: (r) => approvalCommitment(r).digest,
    checkInTx: (r) => {
      const sigs = getSignatures(tenant.id, r.id)
      if (verdict === 'approved' && sigs.length === 0) return 'no_signatures'
      verified = []
      invalid = 0
      for (const s of sigs) {
        const reg = getActiveApprover(tenant.id, s.approver_id)
        if (reg && reg.public_key === s.approver_public_key
            && verifyApproverSignature(commitment, s.signature, reg.public_key)) {
          verified.push({ approver_id: s.approver_id, key_id: approverKeyId(reg.public_key), signature: s.signature })
        } else {
          invalid++
        }
      }
      if (verdict === 'approved' && invalid > 0) return 'evidence_invalid'
      return null
    },
  })
  if (error === 'no_signatures') {
    return res.status(409).json({ error: 'Cannot approve with zero approver signatures' })
  }
  if (error === 'evidence_invalid') {
    return res.status(409).json({
      error: 'Approver evidence does not verify against the current request content',
      code: 'approver_evidence_invalid', invalid_signatures: invalid,
    })
  }
  if (error === 'not_found') return res.status(404).json({ error: 'Approval request not found' })
  if (error === 'expired') {
    // Expiry wins over a late decision. Surface it and emit.
    try {
      getEventBus().emit(tenant.id, {
        type: 'approval_expired', agentId: existing.agent_id,
        data: { request_id: existing.id, action_class: existing.action_class },
      })
    } catch {}
    return res.status(409).json({ error: 'Request has expired' })
  }
  if (error === 'commitment_mismatch') {
    return res.status(409).json({
      error: 'Request content changed after approver evidence was verified',
      code: 'approver_evidence_invalid',
    })
  }
  if (error) return res.status(409).json({ error: `Cannot decide: ${error}` })

  const decided = row as ApprovalRequestRow
  const sample = getSample(tenant.id, decided.id)

  // Issue the signed approval receipt (evidence, not a token).
  const receipt = issueApprovalReceipt({
    tenantId: tenant.id,
    requestId: decided.id,
    actionClass: decided.action_class,
    riskTier: decided.risk_tier as RiskTier,
    verdict: verdict as 'approved' | 'rejected',
    subject: decided.subject,
    subjectType: decided.subject_type,
    approvedScope: safeParseArray(decided.requested_scope),
    approverKeyHashes: verified.map(v => v.key_id),
    signatureCount: verified.length,
    requestCommitment: commitment.digest,
    approverEvidenceDigest: approverEvidenceDigest(commitment.digest, verified),
    sampled: !!sample && sample.sampled === 1,
    issuedAt: now,
  })

  // Wave 2 SET emission seam (stub). In-band SSE event is emitted below.
  emitApprovalSet(verdict === 'approved' ? 'approval_granted' : 'approval_denied', receipt)

  try {
    getEventBus().emit(tenant.id, {
      type: verdict === 'approved' ? 'approval_granted' : 'approval_denied',
      agentId: decided.agent_id,
      data: {
        request_id: decided.id, action_class: decided.action_class,
        risk_tier: decided.risk_tier, receipt_id: receipt.id,
        receipt_hash: receipt.receiptHash,
      },
    })
  } catch {}

  res.json({
    request_id: decided.id, status: decided.status,
    receipt_id: receipt.id, receipt_hash: receipt.receiptHash,
  })
})

// ═══════════════════════════════════════
// GET /approvals/:id/receipt - fetch the issued receipt
// ═══════════════════════════════════════
approvalRouter.get('/approvals/:id/receipt', (req: any, res) => {
  bootstrap()
  const tenant: Tenant = req.tenant
  const db = getDB()
  const rcpt = db.prepare(
    `SELECT * FROM approval_receipts WHERE tenant_id = ? AND request_id = ? ORDER BY created_at DESC LIMIT 1`
  ).get(tenant.id, req.params.id) as any
  if (!rcpt) return res.status(404).json({ error: 'No receipt for this request' })
  let payload: any = null
  try { payload = JSON.parse(rcpt.payload) } catch { payload = null }
  res.json({
    id: rcpt.id, request_id: rcpt.request_id, verdict: rcpt.verdict,
    receipt_hash: rcpt.receipt_hash, signature: rcpt.signature,
    jwks_url: '/.well-known/jwks.json', payload,
  })
})

function safeParseArray(s: string): string[] {
  try { const v = JSON.parse(s); return Array.isArray(v) ? v.map(String) : [] } catch { return [] }
}

// Re-export the receipt fetcher for the public resolution endpoint glue.
export { getReceipt, randomUUID }
