// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * G-C3 Scoped Human Approval - request commitment and approver evidence.
 *
 * An approver signature means something only if it is bound to the request
 * it approves. This module defines the ONE canonical commitment an approver
 * signs, and the digest the receipt carries over the verified signatures.
 *
 * Commitment message (UTF-8 string, Ed25519-signed by the approver key held
 * in the approver registry):
 *
 *   APS-GW-APPROVAL-REQUEST-V1.<canonicalizeJCS(fields)>
 *
 * where fields = {
 *   tenant_id, request_id, agent_id, subject, subject_type, action_class,
 *   requested_scope (sorted), risk_tier, expires_at
 * }
 *
 * canonicalizeJCS is the SDK RFC 8785 canonicalizer, the same one the
 * regulated-action profile uses, so an approver client reproduces the bytes
 * with the public SDK. The signature is the SDK sign() hex form (128 hex
 * chars). The domain prefix keeps an approval signature from being replayed
 * as any other APS signature over the same JSON.
 */

import { createHash } from 'node:crypto'
import { canonicalizeJCS, verify as edVerify } from 'agent-passport-system'
import type { ApprovalRequestRow } from './store.js'

export const APPROVAL_COMMITMENT_DOMAIN = 'APS-GW-APPROVAL-REQUEST-V1'
export const APPROVER_EVIDENCE_DOMAIN = 'APS-GW-APPROVAL-EVIDENCE-V1'

export interface ApprovalCommitmentFields {
  tenant_id: string
  request_id: string
  agent_id: string
  subject: string
  subject_type: string
  action_class: string
  requested_scope: string[]
  risk_tier: string
  expires_at: string
}

export interface ApprovalCommitment {
  scheme: typeof APPROVAL_COMMITMENT_DOMAIN
  fields: ApprovalCommitmentFields
  /** The exact string the approver signs. */
  message: string
  /** sha256 hex of message. Carried on the receipt. */
  digest: string
}

function parseScope(s: string): string[] {
  try { const v = JSON.parse(s); return Array.isArray(v) ? v.map(String) : [] } catch { return [] }
}

/** Build the canonical commitment for a stored request row. */
export function approvalCommitment(row: Pick<ApprovalRequestRow,
  'tenant_id' | 'id' | 'agent_id' | 'subject' | 'subject_type' | 'action_class'
  | 'requested_scope' | 'risk_tier' | 'expires_at'>): ApprovalCommitment {
  const fields: ApprovalCommitmentFields = {
    tenant_id: row.tenant_id,
    request_id: row.id,
    agent_id: row.agent_id,
    subject: row.subject,
    subject_type: row.subject_type,
    action_class: row.action_class,
    requested_scope: [...parseScope(row.requested_scope)].sort(),
    risk_tier: row.risk_tier,
    expires_at: row.expires_at,
  }
  const message = `${APPROVAL_COMMITMENT_DOMAIN}.${canonicalizeJCS(fields)}`
  const digest = createHash('sha256').update(message, 'utf8').digest('hex')
  return { scheme: APPROVAL_COMMITMENT_DOMAIN, fields, message, digest }
}

/** Verify an approver signature over a commitment with a registry key.
 *  Never pass a key taken from a request body. */
export function verifyApproverSignature(
  commitment: ApprovalCommitment,
  signatureHex: unknown,
  registryPublicKeyHex: string,
): boolean {
  if (typeof signatureHex !== 'string' || signatureHex.length === 0) return false
  try { return edVerify(commitment.message, signatureHex, registryPublicKeyHex) } catch { return false }
}

/** Short key id for an approver public key (same derivation the receipt's
 *  approvers_hash has always used). */
export function approverKeyId(publicKeyHex: string): string {
  return createHash('sha256').update(publicKeyHex).digest('hex').slice(0, 16)
}

/**
 * Digest over the verified approver evidence for one request: the request
 * commitment digest plus every verified (approver_id, key_id, signature),
 * sorted. Anyone holding the signature rows and the commitment can
 * recompute it and compare against the receipt.
 */
export function approverEvidenceDigest(
  commitmentDigest: string,
  approvers: Array<{ approver_id: string; key_id: string; signature: string }>,
): string {
  const sorted = approvers
    .map(a => canonicalizeJCS({ approver_id: a.approver_id, key_id: a.key_id, signature: a.signature }))
    .sort()
    .map(s => JSON.parse(s))
  const body = canonicalizeJCS({ commitment_digest: commitmentDigest, approvers: sorted })
  return createHash('sha256').update(`${APPROVER_EVIDENCE_DOMAIN}.${body}`, 'utf8').digest('hex')
}
