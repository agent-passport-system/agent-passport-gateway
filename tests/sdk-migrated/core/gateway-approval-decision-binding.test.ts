// ══════════════════════════════════════════════════════════════════
// Proxy Gateway — stored decision bound to the approved intent
// ══════════════════════════════════════════════════════════════════
// Every decision here verifies under the gateway key, so the decision
// signature check admits it. What must refuse it before dispatch is the
// decision's intentId, its verdict, and (for envelopes) its constraints.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createProxyGateway } from '../../../src/sdk-migrated/core/proxy-gateway.js'
import { joinSocialContract, delegate } from 'agent-passport-system'
import { generateKeyPair, sign } from 'agent-passport-system'
import { canonicalize } from 'agent-passport-system'
import { loadFloor } from 'agent-passport-system'
import { clearStores } from 'agent-passport-system'
import { evaluateIntent, FloorValidatorV1 } from 'agent-passport-system'
import type {
  ToolCallRequest, ToolExecutor, GatewayConfig, GatewayApproval,
  PolicyValidator, PolicyEvaluationResult, PolicyVerdict
} from 'agent-passport-system'
import { readFileSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const floorYaml = readFileSync(join(__dirname, '../../../node_modules/agent-passport-system/values/floor.yaml'), 'utf-8')
const floor = loadFloor(floorYaml)

const NULL_PROTO_ENTRY = 'null-prototype-entry'

/** Floor validator whose result is overridden for requests whose params carry `verdictOverride`. */
function overridingValidator(): PolicyValidator {
  const base = new FloorValidatorV1()
  return {
    version: base.version, name: 'overriding-validator',
    evaluate(intent, ctx) {
      const result = base.evaluate(intent, ctx)
      const params = JSON.parse(intent.action.target) as { verdictOverride?: string; constraintsOverride?: unknown }
      const out: PolicyEvaluationResult = { ...result }
      if (params.verdictOverride !== undefined) out.verdict = params.verdictOverride as PolicyVerdict
      // Params travel as JSON, so a null-prototype entry has to be built here.
      if (params.constraintsOverride === NULL_PROTO_ENTRY) out.constraints = ['max_spend:10', Object.assign(Object.create(null), { limit: 10 })]
      else if (params.constraintsOverride !== undefined) out.constraints = params.constraintsOverride as string[]
      return out
    }
  }
}

function setup(extra: Partial<GatewayConfig> = {}) {
  clearStores()
  const gatewayKeys = generateKeyPair()
  const principal = joinSocialContract({
    name: 'Binding Principal', mission: 'Testing decision binding', owner: 'tester',
    capabilities: ['testing'], platform: 'test', models: ['test-model'], floor
  })
  const agent = joinSocialContract({
    name: 'Binding Agent', mission: 'Tool execution', owner: 'tester',
    capabilities: ['payments:send'], platform: 'test', models: ['test-model'], floor
  })
  const delegation = delegate({
    from: principal, toPublicKey: agent.keyPair.publicKey,
    scope: ['payments:send'], spendLimit: 100000, maxDepth: 2
  })
  const config: GatewayConfig = {
    gatewayId: 'gateway-binding-001', gatewayPublicKey: gatewayKeys.publicKey,
    gatewayPrivateKey: gatewayKeys.privateKey, floor, approvalTTLSeconds: 30, recheckRevocationOnExecute: true,
    validator: overridingValidator(), ...extra,
  }

  const calls: Array<{ tool: string; params: Record<string, unknown> }> = []
  const executor: ToolExecutor = async (tool, params) => {
    calls.push({ tool, params })
    return { success: true, result: { ok: true } }
  }

  const gateway = createProxyGateway(config, executor)
  gateway.registerAgent(agent.passport, agent.attestation, [delegation])

  function makeRequest(params: Record<string, unknown>): ToolCallRequest {
    const requestId = `req-${Date.now()}-${Math.random().toString(36).slice(2)}`
    const tool = 'payments:transfer'
    const scopeRequired = 'payments:send'
    const payload = canonicalize({ requestId, agentId: agent.agentId, tool, params, scopeRequired, spend: undefined })
    return {
      requestId, agentId: agent.agentId, agentPublicKey: agent.keyPair.publicKey,
      signature: sign(payload, agent.keyPair.privateKey),
      tool, params, scopeRequired, context: 'binding test'
    }
  }

  function storedApproval(approvalId: string): GatewayApproval {
    return (gateway as unknown as { approvals: Map<string, GatewayApproval> }).approvals.get(approvalId)!
  }

  /** A decision over the stored intent, genuinely signed with the gateway key, carrying `verdict`. */
  function gatewaySignedDecisionFor(approvalId: string, verdict: string) {
    const stored = storedApproval(approvalId)
    const base = new FloorValidatorV1()
    return evaluateIntent({
      intent: stored.intent,
      evaluatorId: config.gatewayId, evaluatorPublicKey: gatewayKeys.publicKey, evaluatorPrivateKey: gatewayKeys.privateKey,
      validator: { version: '1', name: 'fixed', evaluate: (i, c) => ({ ...base.evaluate(i, c), verdict: verdict as PolicyVerdict }) },
      validationContext: {
        floorVersion: stored.decision.floorVersion, floorPrinciples: [],
        delegation: { scope: ['payments:send'], spendLimit: 100000, spentAmount: 0, expiresAt: new Date(Date.now() + 3600000).toISOString(), revoked: false, currentDepth: 0, maxDepth: 2 },
        agentRegistered: true, agentAttestationValid: true
      }
    })
  }

  return { gateway, calls, makeRequest, storedApproval, gatewaySignedDecisionFor, gatewayKeys }
}

const A = { to: 'DE89370400440532013000', amount: 4000, currency: 'EUR' }
const B = { to: 'FR1420041010050500013M02606', amount: 25, currency: 'EUR' }

/** Asserts a refusal before dispatch: not executed, executor untouched, nothing consumed, counted as denied. */
async function expectRefused(ctx: ReturnType<typeof setup>, id: string, reason: string) {
  const deniedBefore = ctx.gateway.getStats().totalDenied
  const result = await ctx.gateway.executeApproval(id)
  assert.equal(result.executed, false)
  assert.equal(result.denialReason, reason)
  assert.equal(ctx.calls.length, 0, 'executor must not be called')
  assert.equal(ctx.storedApproval(id).consumed, false, 'a refused approval is not consumed')
  assert.equal(ctx.gateway.getStats().totalDenied, deniedBefore + 1)
  assert.notEqual(result.decision, ctx.storedApproval(id).decision, 'refusal returns a copy of the decision')
  return result
}

describe('ProxyGateway approved decision bound to the approved intent', () => {
  it('refuses when the stored decision is a genuine decision from another approval', async () => {
    const ctx = setup()
    const idA = ctx.gateway.approve(ctx.makeRequest(structuredClone(A))).approval!.approvalId
    const idB = ctx.gateway.approve(ctx.makeRequest(structuredClone(B))).approval!.approvalId
    const decisionB = structuredClone(ctx.storedApproval(idB).decision)
    assert.equal(decisionB.verdict, 'permit')
    assert.notEqual(decisionB.intentId, ctx.storedApproval(idA).intent.intentId)
    ctx.storedApproval(idA).decision = decisionB
    await expectRefused(ctx, idA, 'Approved decision does not reference the approved intent')
  })

  it('refuses when the stored decision is a genuine deny the gateway returned for another request', async () => {
    const ctx = setup()
    const idA = ctx.gateway.approve(ctx.makeRequest(structuredClone(A))).approval!.approvalId
    const denied = ctx.gateway.approve(ctx.makeRequest({ ...B, verdictOverride: 'deny' }))
    assert.equal(denied.approved, false)
    assert.equal(denied.denial!.decision!.verdict, 'deny')
    ctx.storedApproval(idA).decision = structuredClone(denied.denial!.decision!)
    await expectRefused(ctx, idA, 'Approved decision does not reference the approved intent')
  })

  it('refuses a gateway-signed deny over the approved intent itself', async () => {
    const ctx = setup()
    const idA = ctx.gateway.approve(ctx.makeRequest(structuredClone(A))).approval!.approvalId
    const deny = ctx.gatewaySignedDecisionFor(idA, 'deny')
    assert.equal(deny.intentId, ctx.storedApproval(idA).intent.intentId)
    ctx.storedApproval(idA).decision = deny
    await expectRefused(ctx, idA, 'Approved decision verdict is not admissible')
  })

  it('refuses a verdict outside permit and narrow, even when approve() let it through', async () => {
    const ctx = setup()
    const approved = ctx.gateway.approve(ctx.makeRequest({ ...A, verdictOverride: 'escalate' }))
    assert.equal(approved.approved, true)
    assert.equal(approved.approval!.decision.verdict, 'escalate')
    await expectRefused(ctx, approved.approval!.approvalId, 'Approved decision verdict is not admissible')
  })

  for (const [label, constraints] of [
    ['a string', 'max_spend:10'],
    // join() cannot convert a null-prototype object to a string.
    ['a list with an entry join() cannot convert', NULL_PROTO_ENTRY],
  ] as const) {
    it(`refuses a narrow decision whose constraints are ${label} when envelopes are produced`, async () => {
      const ctx = setup({ produceEnvelope: true })
      const approved = ctx.gateway.approve(ctx.makeRequest({ ...A, verdictOverride: 'narrow', constraintsOverride: constraints }))
      assert.equal(approved.approved, true)
      await expectRefused(ctx, approved.approval!.approvalId, 'Approved decision constraints cannot be recorded in the execution envelope')
    })
  }

  // ── Positive controls ──

  it('executes a permit decision over its own intent', async () => {
    const ctx = setup({ produceEnvelope: true })
    const id = ctx.gateway.approve(ctx.makeRequest(structuredClone(A))).approval!.approvalId
    const result = await ctx.gateway.executeApproval(id)
    assert.equal(result.executed, true, result.denialReason)
    assert.equal(ctx.calls.length, 1)
    assert.ok(result.proof?.policyReceipt)
    assert.ok(result.envelope)
  })

  it('executes a narrow decision with string constraints and records them in the envelope', async () => {
    const ctx = setup({ produceEnvelope: true })
    const approved = ctx.gateway.approve(ctx.makeRequest({ ...A, verdictOverride: 'narrow', constraintsOverride: ['max_spend:10'] }))
    const result = await ctx.gateway.executeApproval(approved.approval!.approvalId)
    assert.equal(result.executed, true, result.denialReason)
    assert.equal(ctx.calls.length, 1)
    assert.equal(result.envelope!.decision.narrowing, 'max_spend:10')
  })

  it('executes a narrow decision without constraints when envelopes are produced', async () => {
    const ctx = setup({ produceEnvelope: true })
    const approved = ctx.gateway.approve(ctx.makeRequest({ ...A, verdictOverride: 'narrow' }))
    const result = await ctx.gateway.executeApproval(approved.approval!.approvalId)
    assert.equal(result.executed, true, result.denialReason)
    assert.equal(ctx.calls.length, 1)
    assert.equal(result.envelope!.decision.narrowing, null)
  })

  it('executes a permit decision with a string constraint when envelopes are produced', async () => {
    const ctx = setup({ produceEnvelope: true })
    const approved = ctx.gateway.approve(ctx.makeRequest({ ...A, constraintsOverride: 'max_spend:10' }))
    assert.equal(approved.approval!.decision.verdict, 'permit')
    const result = await ctx.gateway.executeApproval(approved.approval!.approvalId)
    assert.equal(result.executed, true, result.denialReason)
    assert.equal(ctx.calls.length, 1)
    assert.ok(result.envelope)
  })

  it('executes a narrow decision with a string constraint when envelopes are not produced', async () => {
    const ctx = setup()
    const approved = ctx.gateway.approve(ctx.makeRequest({ ...A, verdictOverride: 'narrow', constraintsOverride: 'max_spend:10' }))
    const result = await ctx.gateway.executeApproval(approved.approval!.approvalId)
    assert.equal(result.executed, true, result.denialReason)
    assert.equal(ctx.calls.length, 1)
  })
})
