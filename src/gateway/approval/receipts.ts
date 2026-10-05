// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * G-C3 Scoped Human Approval - receipts.
 *
 * Builds the canonical approval-receipt payload, hashes it, signs it with
 * the SINGLE gateway identity (getGatewayIdentity().sign - the same signer
 * verifiers resolve via /.well-known/jwks.json), and persists it.
 *
 * Thin-gateway posture: the receipt is EVIDENCE that a scoped approval step
 * occurred and met its rules. It is NOT the trusted approval token. The
 * short-lived bearer token, the monotonic narrowing of the approved scope,
 * and the SET (Shared Signal) emission are all SDK Wave 2 primitives,
 * stubbed below behind typed seams. The enforcing sink verifies this
 * receipt against the gateway JWKS; assurance is verifier-derived, never
 * issuer-set.
 */

import { createHash } from 'node:crypto'
import { getGatewayIdentity } from '../identity.js'
import type { RiskTier } from './policy.js'
import { insertReceipt } from './store.js'
import { APPROVAL_COMMITMENT_DOMAIN } from './commitment.js'

/** Stable canonical JSON: object keys sorted, null/undefined dropped.
 *  Matches the gateway-side canonical form used by enforce.ts so the
 *  receipt_hash is reproducible by an external verifier. */
export function canonicalJson(v: unknown, seen = new WeakSet<object>()): string {
  if (v === null || v === undefined) return 'null'
  if (typeof v !== 'object') return JSON.stringify(v)
  if (v instanceof Date) return JSON.stringify(v)
  if (seen.has(v as object)) return '"[circular]"'
  seen.add(v as object)
  if (Array.isArray(v)) return '[' + v.map(i => canonicalJson(i, seen)).join(',') + ']'
  const keys = Object.keys(v as Record<string, unknown>).sort()
    .filter(k => { const val = (v as Record<string, unknown>)[k]; return val !== null && val !== undefined })
  return '{' + keys.map(k =>
    JSON.stringify(k) + ':' + canonicalJson((v as Record<string, unknown>)[k], seen)
  ).join(',') + '}'
}

export interface ApprovalReceiptInput {
  tenantId: string
  requestId: string
  actionClass: string
  riskTier: RiskTier
  verdict: 'approved' | 'rejected' | 'expired'
  /** Subject of the approval (artifact/delegation id). */
  subject: string
  subjectType: string
  /** The scope that was approved. Carried as a hash on the public body. */
  approvedScope: string[]
  /** Approver public keys that signed (hashed, not raw, on public body). */
  approverKeyHashes: string[]
  /** How many approver signatures verified against the request commitment. */
  signatureCount: number
  /** sha256 of the request commitment the approvers signed (commitment.ts). */
  requestCommitment: string
  /** Digest over the verified approver ids, key ids and signatures. */
  approverEvidenceDigest: string
  /** Whether a review sample was pulled for this request. */
  sampled: boolean
  issuedAt: string
}

export interface ApprovalReceipt {
  id: string
  receiptHash: string
  signature: string | null
  payload: Record<string, unknown>
}

/** Hash a list of strings into a single stable fingerprint (sorted). */
function listHash(items: string[]): string {
  return createHash('sha256').update(JSON.stringify([...items].sort())).digest('hex')
}

/**
 * Build, sign, and persist an approval receipt. The signed payload is the
 * canonical receipt body; the signature is an EdDSA JWS from the gateway
 * identity. Returns the stored receipt with its id.
 */
export function issueApprovalReceipt(input: ApprovalReceiptInput): ApprovalReceipt {
  const scopeHash = listHash(input.approvedScope)
  const approversHash = listHash(input.approverKeyHashes)

  // Canonical receipt body. PII-free by construction: no reason text, no
  // approver identities in the clear - only hashes and counts. The public
  // projection whitelist (receipt-projection.ts) is a second guard.
  const payload: Record<string, unknown> = {
    // 1.1.0: adds commitment_scheme, request_commitment and
    // approver_evidence_digest; signature_count counts verified signatures.
    schema_version: '1.1.0',
    proof_type: 'approval_receipt',
    request_id: input.requestId,
    action_class: input.actionClass,
    risk_tier: input.riskTier,
    verdict: input.verdict,
    subject: input.subject,
    subject_type: input.subjectType,
    scope_hash: scopeHash,
    approvers_hash: approversHash,
    signature_count: input.signatureCount,
    commitment_scheme: APPROVAL_COMMITMENT_DOMAIN,
    request_commitment: input.requestCommitment,
    approver_evidence_digest: input.approverEvidenceDigest,
    sampled: input.sampled,
    issued_at: input.issuedAt,
    // Claims discipline: this receipt SUPPORTS EVIDENCE FOR a scoped
    // approval step. Assurance is verifier-derived via the gateway JWKS.
    statement: 'supports evidence for scoped approval; assurance is verifier-derived via JWKS',
  }

  const receiptHash = createHash('sha256').update(canonicalJson(payload)).digest('hex')
  payload.receipt_hash = receiptHash

  // Sign with the single gateway identity. Verifiers resolve the key at
  // /.well-known/jwks.json. If the identity is not initialized (e.g. a unit
  // test that did not boot it), persist unsigned rather than throwing - the
  // receipt is still durable evidence and the signature can be re-derived.
  let signature: string | null = null
  try {
    signature = getGatewayIdentity().sign(payload)
  } catch {
    signature = null
  }

  const id = insertReceipt({
    tenantId: input.tenantId,
    requestId: input.requestId,
    actionClass: input.actionClass,
    riskTier: input.riskTier,
    verdict: input.verdict,
    receiptHash,
    payload: JSON.stringify(payload),
    signature,
    schemaVersion: payload.schema_version as string,
  })

  return { id, receiptHash, signature, payload }
}

// ─────────────────────────────────────────────────────────────────────
// SDK Wave 2 seams. None of these are reimplemented in the gateway
// (thin-gateway directive 6). Each is a typed no-op / stub until the
// installed SDK exposes the Wave 2 approval surface.
// ─────────────────────────────────────────────────────────────────────

export interface EphemeralApprovalToken {
  /** Opaque short-lived bearer the sink verifies. Stubbed until W2. */
  token: string
  scope: string[]
  expiresAt: string
}

/**
 * Mint the short-lived, customer-verifiable approval token. The gateway
 * does NOT hold or persist this token as a trust anchor; the sink verifies
 * it. Stubbed until the SDK ships the Wave 2 approval-token surface.
 */
export function mintEphemeralApprovalToken(
  _scope: string[],
  _ttlSeconds: number,
): EphemeralApprovalToken | null {
  // TODO(W2-approval-token): SDK mintEphemeralApprovalToken(scope, ttl) ->
  // short-lived bearer the enforcing sink verifies offline. Not present in
  // agent-passport-system@2.6.0-alpha.3. Returning null keeps the gateway
  // thin - it signs the receipt and coordinates, it never holds the token.
  return null
}

/**
 * Monotonic narrowing check: the approved scope must be a non-widening
 * subset of the parent authority. Stubbed until W2; never reimplemented
 * in the gateway.
 */
export function narrowApprovedScope(
  _parentScope: string[],
  requestedScope: string[],
): { narrowed: string[]; monotonic: boolean } {
  // TODO(W2-narrow): SDK narrowAuthority(parentScope, requestedScope)
  // monotonic check. Until the SDK ships it, we pass the requested scope
  // through unchanged and report monotonic=false so callers know the
  // narrowing invariant has NOT yet been machine-checked.
  return { narrowed: requestedScope, monotonic: false }
}

/**
 * Emit a SET (Shared Signal Token) for the approval decision so subscribed
 * sinks learn of grant/deny out of band. Stubbed until W2.
 */
export function emitApprovalSet(
  _event: 'approval_granted' | 'approval_denied',
  _receipt: ApprovalReceipt,
): { emitted: boolean } {
  // TODO(W2-set): SDK emitSET(approval_granted | approval_denied)
  // shared-signal token. Not present in the installed alpha SDK. The SSE
  // spine (getEventBus().emit) carries the in-band event today; the SET is
  // the cross-domain shared-signal that lands in Wave 2.
  return { emitted: false }
}
