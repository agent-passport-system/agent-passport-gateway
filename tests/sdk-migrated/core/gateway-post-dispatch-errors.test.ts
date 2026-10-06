// ══════════════════════════════════════════════════════════════════
// Proxy Gateway — nothing throws after dispatch
// ══════════════════════════════════════════════════════════════════
// Once the executor has run, executeApproval and processToolCall must
// return, never throw. Each post-dispatch step that fails is named in
// postDispatchErrors; `executed` stays true and `outcome` is what was
// observed from the executor. Each test forces one step to fail from
// inside the executor (or through config) and runs on both paths where
// the step exists.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createProxyGateway } from '../../../src/sdk-migrated/core/proxy-gateway.js'
import type { ToolCallResult } from '../../../src/sdk-migrated/core/proxy-gateway.js'
import { joinSocialContract, delegate, createObligation } from 'agent-passport-system'
import { generateKeyPair, sign } from 'agent-passport-system'
import { canonicalize } from 'agent-passport-system'
import { loadFloor } from 'agent-passport-system'
import { clearStores } from 'agent-passport-system'
import type {
  ToolCallRequest, GatewayConfig, GatewayApproval, Delegation, Obligation,
  PolicyValidator, EvidenceClass
} from 'agent-passport-system'
import { FloorValidatorV1 } from 'agent-passport-system'
import { readFileSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const floorYaml = readFileSync(join(__dirname, '../../../node_modules/agent-passport-system/values/floor.yaml'), 'utf-8')
const floor = loadFloor(floorYaml)

const HOUR = 3600_000
type Path = 'executeApproval' | 'processToolCall'
const PATHS: Path[] = ['executeApproval', 'processToolCall']

interface InternalAgent {
  delegations: Map<string, Delegation>
  executionFrame?: { active: boolean }
  reputation?: { mu: number }
  turnCount?: number
}

function setup(opts: {
  config?: Partial<GatewayConfig>
  delegationHours?: number
  spend?: { amount: number; currency: string }
  evidenceClass?: string
} = {}) {
  clearStores()
  const gatewayKeys = generateKeyPair()
  const principal = joinSocialContract({
    name: 'Post Principal', mission: 'Testing post-dispatch', owner: 'tester',
    capabilities: ['testing'], platform: 'test', models: ['test-model'], floor
  })
  const agent = joinSocialContract({
    name: 'Post Agent', mission: 'Tool execution', owner: 'tester',
    capabilities: ['payments:send'], platform: 'test', models: ['test-model'], floor
  })
  const delegation = delegate({
    from: principal, toPublicKey: agent.keyPair.publicKey,
    scope: ['payments:send'], spendLimit: 100000, maxDepth: 2, expiresInHours: opts.delegationHours ?? 1
  })
  const config: GatewayConfig = {
    gatewayId: 'gateway-post-001', gatewayPublicKey: gatewayKeys.publicKey,
    gatewayPrivateKey: gatewayKeys.privateKey, floor, approvalTTLSeconds: 7200,
    recheckRevocationOnExecute: true, ...opts.config,
  }

  const ctx = {
    calls: 0,
    /** Runs inside the executor, after every pre-dispatch check. */
    during: (() => {}) as (request: ToolCallRequest, approvalId?: string) => void,
    /** What the executor returns. */
    returns: { success: true, result: { ok: true } } as unknown,
    request: undefined as unknown as ToolCallRequest,
    approvalId: undefined as string | undefined,
  }

  const gateway = createProxyGateway(config, async () => {
    ctx.calls++
    ctx.during(ctx.request, ctx.approvalId)
    return ctx.returns as { success: boolean }
  })
  gateway.registerAgent(agent.passport, agent.attestation, [delegation])

  function makeRequest(): ToolCallRequest {
    const requestId = `req-${Math.random().toString(36).slice(2)}`
    const tool = 'payments:transfer'
    const scopeRequired = 'payments:send'
    const params = { ref: requestId }
    const payload = canonicalize({ requestId, agentId: agent.agentId, tool, params, scopeRequired, spend: opts.spend })
    return {
      requestId, agentId: agent.agentId, agentPublicKey: agent.keyPair.publicKey,
      signature: sign(payload, agent.keyPair.privateKey),
      tool, params, scopeRequired, spend: opts.spend, context: 'post-dispatch test',
      evidenceClass: opts.evidenceClass as EvidenceClass | undefined,
    }
  }

  function storedApproval(approvalId: string): GatewayApproval {
    return (gateway as unknown as { approvals: Map<string, GatewayApproval> }).approvals.get(approvalId)!
  }

  function internalAgent(): InternalAgent {
    return (gateway as unknown as { agents: Map<string, InternalAgent> }).agents.get(agent.agentId)!
  }

  /** Dispatch one call on `path`. Fails the test if anything throws. */
  async function run(path: Path): Promise<ToolCallResult> {
    ctx.request = makeRequest()
    if (path === 'executeApproval') {
      const approved = gateway.approve(ctx.request)
      assert.equal(approved.approved, true, approved.denial?.reason)
      ctx.approvalId = approved.approval!.approvalId
      return gateway.executeApproval(ctx.approvalId)
    }
    return gateway.processToolCall(ctx.request)
  }

  function obligation(overrides: Partial<Obligation> = {}): Obligation {
    return {
      ...createObligation({
        delegationId: delegation.delegationId,
        obligorAgentId: agent.agentId, obligorPublicKey: agent.keyPair.publicKey,
        action: { type: 'payments:transfer', scope: 'payments:send', description: 'Pay' },
        deadline: new Date(Date.now() + 24 * HOUR).toISOString(),
        evidence: { type: 'action_receipt', matchCriteria: { toolMatch: 'gateway:payments:transfer' } },
        penalty: { type: 'reputation_penalty', severity: 'minor', reputationImpact: -10, gracePeriodMinutes: 60, autoExecute: false },
        principalPrivateKey: principal.keyPair.privateKey, principalPublicKey: principal.publicKey
      }),
      ...overrides,
    } as Obligation
  }

  return { ctx, gateway, run, storedApproval, internalAgent, obligation, delegation, agentId: agent.agentId }
}

/** The call was dispatched once, returned, and named `step` as failed. */
function expectStepFailed(s: ReturnType<typeof setup>, path: Path, result: ToolCallResult, step: string, outcome = 'succeeded') {
  assert.equal(result.executed, true)
  assert.equal(result.outcome, outcome)
  assert.equal(s.ctx.calls, 1)
  const errors = result.postDispatchErrors ?? []
  assert.ok(errors.some(e => e.startsWith(`${step}: `)), `expected a ${step} entry, got ${JSON.stringify(errors)}`)
  if (path === 'executeApproval') assert.equal(s.storedApproval(s.ctx.approvalId!).consumed, true)
}

function throwingCallback(name: string) {
  return () => { throw new Error(`${name} failed`) }
}

describe('ProxyGateway nothing throws after dispatch', () => {
  for (const path of PATHS) {
    describe(path, () => {
      it('delegation expires while the executor is awaited: executed, observed outcome, no receipt, no throw', async (t) => {
        t.mock.timers.enable({ apis: ['Date'], now: Date.now() })
        const seen: Array<string[] | undefined> = []
        const s = setup({ config: { produceEnvelope: true, onToolCall: (_req, r) => { seen.push(r.postDispatchErrors && [...r.postDispatchErrors]) } } })
        s.ctx.during = () => t.mock.timers.tick(HOUR + 1000)
        const result = await s.run(path)
        expectStepFailed(s, path, result, 'createReceipt')
        assert.deepEqual(seen, [result.postDispatchErrors], 'onToolCall sees the post-dispatch errors')
        assert.equal(result.result && (result.result as { ok: boolean }).ok, true)
        assert.equal(result.receipt, undefined, 'no receipt is invented')
        assert.equal(result.proof, undefined)
        assert.equal(result.envelope, undefined)
        assert.ok(result.postDispatchErrors!.includes('createReceipt: Cannot create receipt: delegation invalid — Delegation expired'))
        assert.ok(result.postDispatchErrors!.includes('createPolicyReceipt: skipped, no receipt'))
        assert.ok(result.postDispatchErrors!.includes('createExecutionEnvelope: skipped, no policy receipt'))
      })

      it('keeps tool_reported_failure as the outcome when a post-dispatch step fails', async (t) => {
        t.mock.timers.enable({ apis: ['Date'], now: Date.now() })
        const s = setup()
        s.ctx.returns = { success: false, error: 'tool said no' }
        s.ctx.during = () => t.mock.timers.tick(HOUR + 1000)
        const result = await s.run(path)
        expectStepFailed(s, path, result, 'createReceipt', 'tool_reported_failure')
        assert.equal(result.toolError, 'tool said no')
      })

      it('createSAO: a result that cannot be serialized', async () => {
        const s = setup({ config: { enableCrossChainEnforcement: true } })
        s.ctx.returns = { success: true, result: 1n }
        const result = await s.run(path)
        expectStepFailed(s, path, result, 'createSAO')
        assert.equal(result.sao, undefined)
        assert.ok(result.receipt, 'later steps still run')
      })

      it('recordAccess: the execution frame was closed during the call', async () => {
        const s = setup({ config: { enableCrossChainEnforcement: true } })
        s.ctx.during = () => { s.internalAgent().executionFrame = { ...s.internalAgent().executionFrame!, active: false } }
        const result = await s.run(path)
        expectStepFailed(s, path, result, 'recordAccess')
        assert.ok(result.receipt)
      })

      it('checkFulfillment: an obligation whose evidence has no match criteria', async () => {
        const s = setup({ config: { enableObligationMonitoring: true } })
        s.gateway.registerObligation(s.agentId, s.obligation({ evidence: { type: 'action_receipt' } as Obligation['evidence'] }))
        const result = await s.run(path)
        expectStepFailed(s, path, result, 'checkFulfillment')
        assert.ok(result.receipt)
      })

      it('resolveObligation: a matching obligation whose deadline cannot be read as a date', async () => {
        const s = setup({ config: { enableObligationMonitoring: true } })
        s.gateway.registerObligation(s.agentId, s.obligation({ deadline: 1n as unknown as string }))
        const result = await s.run(path)
        expectStepFailed(s, path, result, 'resolveObligation')
        assert.equal(result.obligationResolutions, undefined)
        assert.equal(s.gateway.getAgentObligations(s.agentId)![0].status, 'pending', 'an unresolved obligation stays pending')
      })

      it('onObligationResolved: the callback throws', async () => {
        const s = setup({ config: { enableObligationMonitoring: true, onObligationResolved: throwingCallback('onObligationResolved') } })
        s.gateway.registerObligation(s.agentId, s.obligation())
        const result = await s.run(path)
        expectStepFailed(s, path, result, 'onObligationResolved')
        assert.equal(result.obligationResolutions!.length, 1)
      })

      it('updateReputationFromResult: an evidence class the SDK does not know', async () => {
        const s = setup({ config: { enableReputationGating: true }, evidenceClass: 'not-a-class' })
        const result = await s.run(path)
        expectStepFailed(s, path, result, 'updateReputationFromResult')
      })

      it('onReputationUpdated: the callback throws', async () => {
        const s = setup({ config: { enableReputationGating: true, onReputationUpdated: throwingCallback('onReputationUpdated') } })
        const result = await s.run(path)
        expectStepFailed(s, path, result, 'onReputationUpdated')
      })

      it('onDemotion: the callback throws after a demotion', async () => {
        const s = setup({ config: { enableReputationGating: true, onDemotion: throwingCallback('onDemotion') } })
        s.gateway.setAgentReputation(s.agentId, { ...s.gateway.getAgentReputation(s.agentId)!, mu: 90, sigma: 1 })
        const tierBefore = s.gateway.getAgentTier(s.agentId)!.tier
        assert.ok(tierBefore > 0)
        s.ctx.during = () => { s.internalAgent().reputation = { ...s.internalAgent().reputation!, mu: 0 } }
        const result = await s.run(path)
        expectStepFailed(s, path, result, 'onDemotion')
        assert.equal(s.gateway.getAgentTier(s.agentId)!.tier, tierBefore - 1, 'the demotion itself was applied')
      })

      it('onToolCall: the callback throws', async () => {
        const s = setup({ config: { onToolCall: throwingCallback('onToolCall') } })
        const result = await s.run(path)
        expectStepFailed(s, path, result, 'onToolCall')
        assert.ok(result.receipt)
      })

      it('onToolCall: the callback throws after the executor threw', async () => {
        const s = setup({ config: { onToolCall: throwingCallback('onToolCall') } })
        s.ctx.during = () => { throw new Error('executor blew up') }
        const result = await s.run(path)
        expectStepFailed(s, path, result, 'onToolCall', 'unknown')
        assert.equal(result.toolError, 'executor blew up')
      })

      for (const [label, returned] of [['undefined', undefined], ['a string', 'done']] as const) {
        it(`the executor returns ${label} instead of a result object`, async () => {
          const s = setup()
          s.ctx.returns = returned
          const result = await s.run(path)
          assert.equal(result.executed, true)
          assert.equal(result.outcome, 'unknown')
          assert.equal(result.toolError, 'Executor did not return a result object')
          assert.equal(s.ctx.calls, 1)
        })
      }

      it('triggerDemotion: the agent passport is unreadable when the demotion is built', async () => {
        const s = setup({ config: { enableReputationGating: true } })
        s.gateway.setAgentReputation(s.agentId, { ...s.gateway.getAgentReputation(s.agentId)!, mu: 90, sigma: 1 })
        const tierBefore = s.gateway.getAgentTier(s.agentId)!.tier
        assert.ok(tierBefore > 0)
        s.ctx.during = () => {
          const internal = s.internalAgent() as InternalAgent & { passport: unknown }
          internal.reputation = { ...internal.reputation!, mu: 0 }
          internal.passport = {}
        }
        const result = await s.run(path)
        expectStepFailed(s, path, result, 'triggerDemotion')
        assert.equal(s.gateway.getAgentTier(s.agentId)!.tier, tierBefore, 'no demotion is applied without a demotion event')
      })
    })
  }

  describe('executeApproval only', () => {
    it('createPolicyReceipt: the stored decision was changed to deny during the call', async () => {
      const s = setup()
      s.ctx.during = (_r, id) => { s.storedApproval(id!).decision.verdict = 'deny' }
      const result = await s.run('executeApproval')
      expectStepFailed(s, 'executeApproval', result, 'createPolicyReceipt')
      assert.ok(result.receipt, 'the receipt was produced')
      assert.equal(result.proof, undefined)
    })

    it('createExecutionEnvelope: the stored decision constraints were changed during the call', async () => {
      const s = setup({ config: { produceEnvelope: true } })
      s.ctx.during = (_r, id) => {
        const decision = s.storedApproval(id!).decision
        decision.verdict = 'narrow'
        decision.constraints = 'max_spend:10' as unknown as string[]
      }
      const result = await s.run('executeApproval')
      expectStepFailed(s, 'executeApproval', result, 'createExecutionEnvelope')
      assert.ok(result.proof?.policyReceipt)
      assert.equal(result.envelope, undefined)
    })
  })

  describe('processToolCall only', () => {
    it('createExecutionEnvelope: the validator changed its constraints during the call', async () => {
      const base = new FloorValidatorV1()
      const constraints: unknown[] = ['max_spend:10']
      const validator: PolicyValidator = {
        version: base.version, name: 'narrowing',
        evaluate: (i, c) => ({ ...base.evaluate(i, c), verdict: 'narrow', constraints: constraints as string[] })
      }
      const s = setup({ config: { produceEnvelope: true, validator } })
      s.ctx.during = () => { constraints.push(Object.create(null)) }
      const result = await s.run('processToolCall')
      expectStepFailed(s, 'processToolCall', result, 'createExecutionEnvelope')
      assert.equal(result.envelope, undefined)
    })

    it('buildSuccessEvaluations: the caller changed request.spend during the call', async () => {
      const s = setup({ spend: { amount: 5, currency: 'usd' } })
      s.ctx.during = (request) => { request.spend = { amount: 5n as unknown as number, currency: 'usd' } }
      const result = await s.run('processToolCall')
      expectStepFailed(s, 'processToolCall', result, 'buildSuccessEvaluations')
      assert.equal(result.constraintVector, undefined)
    })

    it('buildAuthorizationWitness: the gateway signing key became unusable during the call', async () => {
      const s = setup()
      s.ctx.during = () => { (s.gateway as unknown as { config: GatewayConfig }).config.gatewayPrivateKey = 'not-a-key' }
      const result = await s.run('processToolCall')
      expectStepFailed(s, 'processToolCall', result, 'buildAuthorizationWitness')
      assert.equal(result.authorizationWitness, undefined)
      assert.ok(result.constraintVector)
    })

    it('checkNearMisses: the onNearMiss callback throws', async () => {
      const s = setup({ delegationHours: 0.05, config: { enableNearMissAlerting: true, onNearMiss: throwingCallback('onNearMiss') } })
      const result = await s.run('processToolCall')
      expectStepFailed(s, 'processToolCall', result, 'checkNearMisses')
    })

    it('shouldProbe: the fidelity attestation became malformed during the call', async () => {
      const s = setup({ config: { enableFidelityGating: true, onProbeRequired: () => {} } })
      s.ctx.during = () => { (s.internalAgent() as InternalAgent & { fidelityAttestation: unknown }).fidelityAttestation = {} }
      const result = await s.run('processToolCall')
      expectStepFailed(s, 'processToolCall', result, 'shouldProbe')
    })

    it('onProbeRequired: the callback throws', async () => {
      const s = setup({ config: {
        enableFidelityGating: true, onProbeRequired: throwingCallback('onProbeRequired'),
        probeSchedule: { onDelegation: false, turnInterval: 1, onSubstrateChange: false, highStakesTurnInterval: 1, onContextRotation: false },
      } })
      s.internalAgent().turnCount = 5
      const result = await s.run('processToolCall')
      expectStepFailed(s, 'processToolCall', result, 'onProbeRequired')
    })
  })
})
