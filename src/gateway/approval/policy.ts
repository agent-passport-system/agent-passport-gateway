// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * G-C3 Scoped Human Approval - Policy.
 *
 * Approval is SCOPED AUTHORITY, not a rubber-stamp button. This module
 * encodes the scoped-authority rules that decide whether a given approver
 * may approve a given action class, and under what conditions:
 *
 *   1. The approver must HOLD AUTHORITY for the action class. An approver
 *      authority set is a list of action-class globs (e.g. 'payments:*',
 *      'data:export'). A request's action class must match at least one.
 *   2. HIGH-RISK and CRITICAL requests require the approver to be OUTSIDE
 *      the agent owner. Self-approval of one's own agent's high-risk action
 *      is refused (separation of powers, v2 separation-of-powers helper).
 *   3. NO BULK approvals for high-risk: a single approval action may not
 *      cover more than one high-risk request.
 *   4. Approvals EXPIRE QUICKLY. TTL is tier-scaled and short; the floor
 *      is enforced here, not issuer-chosen-unbounded.
 *   5. A REASON is required on every grant/deny.
 *   6. A SAMPLE is pulled for review (effect-sampling), tier-scaled.
 *
 * Risk tiers mirror the v2 effect-sampling risk classes
 * (low | medium | high | critical) so the same sampling policy applies.
 *
 * This module holds pure logic only. It never mints tokens and never
 * narrows authority itself - those are SDK Wave 2 seams (see connector.ts
 * and receipts.ts TODO(W2-*) markers). The gateway checks-before and emits;
 * the enforcing sink verifies the receipt against the gateway JWKS.
 */

export type RiskTier = 'low' | 'medium' | 'high' | 'critical'

/** Per-tier approval ceilings. TTL is a short floor, not an issuer choice.
 *  highRisk = whether the tier is treated as high-risk for the
 *  outside-owner, no-bulk, and always-sample rules. */
export interface TierRule {
  /** Maximum seconds an approval request stays valid before it expires.
   *  Short by design - assurance is verifier-derived and time-bounded. */
  ttlSeconds: number
  /** True when this tier is subject to the high-risk constraints:
   *  approver-outside-owner and no-bulk-approval. */
  highRisk: boolean
  /** Sampling rate for the review-sample pull (0..1). Critical always 1.0. */
  sampleRate: number
}

/** TTL floors are short on purpose. A high-risk approval that sits open for
 *  hours is an attack surface; tight expiry keeps the granted scope fresh.
 *  These are the ceilings the gateway enforces; a caller may request a
 *  SHORTER ttl but never a longer one (see clampTtlSeconds). */
export const TIER_RULES: Record<RiskTier, TierRule> = {
  low:      { ttlSeconds: 3600, highRisk: false, sampleRate: 0.05 },
  medium:   { ttlSeconds: 1800, highRisk: false, sampleRate: 0.25 },
  high:     { ttlSeconds: 600,  highRisk: true,  sampleRate: 0.5  },
  critical: { ttlSeconds: 300,  highRisk: true,  sampleRate: 1.0  },
}

/** Default action-class to risk-tier mapping. The first segment of the
 *  action class (before ':') keys the table; unknown classes default to
 *  'high' (fail-safe - an unrecognized action is treated as high-risk so
 *  it inherits outside-owner + no-bulk + tight TTL, not the lax low tier). */
const ACTION_CLASS_TIERS: Record<string, RiskTier> = {
  read:        'low',
  list:        'low',
  query:       'low',
  notify:      'low',
  write:       'medium',
  update:      'medium',
  data:        'high',
  export:      'high',
  payments:    'high',
  payment:     'high',
  transfer:    'high',
  delegation:  'high',
  delegate:    'high',
  revoke:      'critical',
  admin:       'critical',
  root:        'critical',
  rotate:      'critical',
  dissolution: 'critical',
}

/** Classify an action class into a risk tier. Unknown -> 'high' (fail-safe). */
export function classifyRisk(actionClass: string): RiskTier {
  const head = (actionClass || '').split(':')[0]?.trim().toLowerCase() || ''
  return ACTION_CLASS_TIERS[head] ?? 'high'
}

export function tierRule(tier: RiskTier): TierRule {
  return TIER_RULES[tier]
}

export function isHighRiskTier(tier: RiskTier): boolean {
  return TIER_RULES[tier].highRisk
}

/** Clamp a requested TTL to the tier ceiling. A caller may ask for a
 *  shorter expiry but never longer than the tier floor allows. A non-
 *  positive or missing request collapses to the tier ceiling. */
export function clampTtlSeconds(tier: RiskTier, requested?: number): number {
  const ceiling = TIER_RULES[tier].ttlSeconds
  if (!requested || requested <= 0) return ceiling
  return Math.min(requested, ceiling)
}

/**
 * Scope authority match: does an approver hold authority for the action
 * class? The approver authority set is a list of action-class patterns.
 * A pattern matches when it equals the class, equals its head segment,
 * or is a '<head>:*' / '*' glob covering it.
 *
 * Examples:
 *   authority ['payments:*'] matches 'payments:refund'  -> true
 *   authority ['data']       matches 'data:export'      -> true
 *   authority ['read:*']     matches 'payments:refund'  -> false
 */
export function approverHoldsAuthority(
  approverAuthority: readonly string[],
  actionClass: string,
): boolean {
  if (!approverAuthority || approverAuthority.length === 0) return false
  const cls = (actionClass || '').trim().toLowerCase()
  if (!cls) return false
  const head = cls.split(':')[0] || ''
  for (const raw of approverAuthority) {
    const pat = (raw || '').trim().toLowerCase()
    if (!pat) continue
    if (pat === '*') return true
    if (pat === cls) return true
    if (pat === head) return true
    // '<head>:*' glob
    if (pat.endsWith(':*') && pat.slice(0, -2) === head) return true
  }
  return false
}

/** A single scoped-authority decision input. */
export interface ScopeCheckInput {
  actionClass: string
  tier: RiskTier
  /** Authority globs the approver holds. */
  approverAuthority: readonly string[]
  /** Approver identity (tenant-scoped principal id). */
  approverId: string
  /** Registry owner relationship of the approver (the principal it acts
   *  for). Compared against the owner set alongside approverId. */
  approverPrincipalId?: string
  /** Further registered identities that count as the owner side for the
   *  independence check (the agent id, the API key id that opened the
   *  request). Pass stored, server-recorded ids only, never caller-supplied
   *  names. Never widens what is allowed. */
  ownerAliases?: readonly string[]
  /** The agent whose action is being approved, and the agent OWNER
   *  (principal that owns the agent). For high-risk, approverId must
   *  differ from the owner. */
  agentOwnerId: string
  /** How many requests this single approval action would cover. >1 = bulk.
   *  Derived by the caller of this function, never taken from a request
   *  body. /sign always passes 1 (one signature, one request commitment). */
  batchSize: number
}

export interface ScopeCheckResult {
  allowed: boolean
  /** Machine-readable reason code on refusal. */
  code?:
    | 'authority_missing'
    | 'self_approval_high_risk'
    | 'bulk_high_risk'
  reason?: string
}

/**
 * The core scoped-authority gate. Returns allowed=false with a code on the
 * first failed rule. Pure - no IO, no token issuance.
 */
export function checkScopedAuthority(input: ScopeCheckInput): ScopeCheckResult {
  // Rule 1: approver must hold authority for the action class.
  if (!approverHoldsAuthority(input.approverAuthority, input.actionClass)) {
    return {
      allowed: false,
      code: 'authority_missing',
      reason: `Approver does not hold authority for action class "${input.actionClass}"`,
    }
  }

  const highRisk = isHighRiskTier(input.tier)

  // Rule 2: high-risk requires approver OUTSIDE the agent owner. Both the
  // approver id and its registered principal must be outside the owner set.
  // This compares registered identities; it does not establish that a
  // different human holds the approver's key.
  const ownerSide = new Set([input.agentOwnerId, ...(input.ownerAliases ?? [])].filter(Boolean))
  const approverSide = [input.approverId, input.approverPrincipalId].filter(Boolean) as string[]
  if (highRisk && approverSide.some(x => ownerSide.has(x))) {
    return {
      allowed: false,
      code: 'self_approval_high_risk',
      reason: 'High-risk approval requires an approver outside the agent owner',
    }
  }

  // Rule 3: no bulk approvals for high-risk.
  if (highRisk && input.batchSize > 1) {
    return {
      allowed: false,
      code: 'bulk_high_risk',
      reason: 'Bulk approval is not permitted for high-risk action classes',
    }
  }

  return { allowed: true }
}
