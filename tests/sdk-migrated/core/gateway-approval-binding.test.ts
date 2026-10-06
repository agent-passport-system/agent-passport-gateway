// ══════════════════════════════════════════════════════════════════
// Proxy Gateway — approval parameter binding and dispatch outcome
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createProxyGateway } from '../../../src/sdk-migrated/core/proxy-gateway.js'
import { joinSocialContract, delegate } from 'agent-passport-system'
import { generateKeyPair, sign } from 'agent-passport-system'
import { canonicalize } from 'agent-passport-system'
import { loadFloor } from 'agent-passport-system'
import { clearStores } from 'agent-passport-system'
import type { ToolCallRequest, ToolExecutor, GatewayConfig, GatewayApproval } from 'agent-passport-system'
import { readFileSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const floorYaml = readFileSync(join(__dirname, '../../../node_modules/agent-passport-system/values/floor.yaml'), 'utf-8')
const floor = loadFloor(floorYaml)

type Behavior = 'success' | 'error' | 'throw'

function setup(behavior: Behavior = 'success') {
  clearStores()
  const gatewayKeys = generateKeyPair()
  const principal = joinSocialContract({
    name: 'Binding Principal', mission: 'Testing approval binding', owner: 'tester',
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
    gatewayPrivateKey: gatewayKeys.privateKey, floor, approvalTTLSeconds: 30, recheckRevocationOnExecute: true
  }

  const calls: Array<{ tool: string; params: Record<string, unknown>; snapshot: string }> = []
  const executor: ToolExecutor = async (tool, params) => {
    calls.push({ tool, params, snapshot: JSON.stringify(params) })
    if (behavior === 'throw') throw new Error('Executor crashed mid-call')
    if (behavior === 'error') return { success: false, error: 'Tool reported failure' }
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

  return { gateway, calls, makeRequest, storedApproval }
}

const APPROVED = { to: 'DE89370400440532013000', amount: 4000, currency: 'EUR', meta: { memo: 'invoice 17' } }

describe('ProxyGateway approval parameter binding', () => {
  it('mutating the returned approval after approve() does not change what is dispatched', async () => {
    const { gateway, calls, makeRequest } = setup()
    const approved = gateway.approve(makeRequest(structuredClone(APPROVED)))
    assert.equal(approved.approved, true)
    const approval = approved.approval!

    try { (approval.params as any).amount = 4100 } catch { /* frozen is fine */ }
    try { (approval.params as any).meta.memo = 'changed' } catch { /* frozen is fine */ }

    const result = await gateway.executeApproval(approval.approvalId)
    assert.equal(result.executed, true, result.denialReason)
    assert.equal(calls.length, 1)
    assert.deepEqual(calls[0].params, APPROVED)
    assert.equal(result.receipt!.action.target, JSON.stringify(APPROVED))
  })

  it('mutating the original request.params after approve() does not change what is dispatched', async () => {
    const { gateway, calls, makeRequest } = setup()
    const request = makeRequest(structuredClone(APPROVED))
    const approved = gateway.approve(request)
    assert.equal(approved.approved, true)

    ;(request.params as any).amount = 4100
    ;(request.params as any).meta.memo = 'changed'

    const result = await gateway.executeApproval(approved.approval!.approvalId)
    assert.equal(result.executed, true, result.denialReason)
    assert.equal(calls.length, 1)
    assert.deepEqual(calls[0].params, APPROVED)
    assert.equal(result.receipt!.action.target, JSON.stringify(APPROVED))
  })

  it('refuses execution when stored params no longer match the approved intent', async () => {
    const { gateway, calls, makeRequest, storedApproval } = setup()
    const approved = gateway.approve(makeRequest(structuredClone(APPROVED)))
    assert.equal(approved.approved, true)
    const id = approved.approval!.approvalId

    const stored = storedApproval(id)
    stored.params = { ...APPROVED, amount: 4100 }
    const deniedBefore = gateway.getStats().totalDenied

    const result = await gateway.executeApproval(id)
    assert.equal(result.executed, false)
    assert.equal(result.denialReason, 'Approval parameters do not match the approved intent')
    assert.equal(calls.length, 0, 'executor must not be called')
    assert.equal(storedApproval(id).consumed, false, 'a refused approval is not consumed')
    assert.equal(gateway.getStats().totalDenied, deniedBefore + 1)
  })
})

describe('ProxyGateway dispatch outcome', () => {
  it('approval path: a throwing executor yields outcome unknown, executed true, called once', async () => {
    const { gateway, calls, makeRequest } = setup('throw')
    const approved = gateway.approve(makeRequest(structuredClone(APPROVED)))
    const result = await gateway.executeApproval(approved.approval!.approvalId)
    assert.equal(result.executed, true)
    assert.equal(result.outcome, 'unknown')
    assert.equal(result.toolError, 'Executor crashed mid-call')
    assert.equal(calls.length, 1)
  })

  it('approval path: after a throw the approval stays consumed and a retry is refused as replay', async () => {
    const { gateway, calls, makeRequest, storedApproval } = setup('throw')
    const approved = gateway.approve(makeRequest(structuredClone(APPROVED)))
    const id = approved.approval!.approvalId
    await gateway.executeApproval(id)
    assert.equal(storedApproval(id).consumed, true)

    const replaysBefore = gateway.getStats().replayAttemptsBlocked
    const retry = await gateway.executeApproval(id)
    assert.equal(retry.executed, false)
    assert.equal(retry.denialReason, 'Approval already consumed (replay)')
    assert.equal(gateway.getStats().replayAttemptsBlocked, replaysBefore + 1)
    assert.equal(calls.length, 1, 'executor called exactly once')
  })

  it('approval path: tool-reported failure yields outcome tool_reported_failure', async () => {
    const { gateway, makeRequest } = setup('error')
    const approved = gateway.approve(makeRequest(structuredClone(APPROVED)))
    const result = await gateway.executeApproval(approved.approval!.approvalId)
    assert.equal(result.executed, true)
    assert.equal(result.outcome, 'tool_reported_failure')
    assert.equal(result.toolError, 'Tool reported failure')
  })

  it('approval path: success yields outcome succeeded', async () => {
    const { gateway, makeRequest } = setup('success')
    const approved = gateway.approve(makeRequest(structuredClone(APPROVED)))
    const result = await gateway.executeApproval(approved.approval!.approvalId)
    assert.equal(result.executed, true)
    assert.equal(result.outcome, 'succeeded')
  })

  it('single step path: throw, tool failure and success map to distinct outcomes', async () => {
    for (const [behavior, expected] of [['throw', 'unknown'], ['error', 'tool_reported_failure'], ['success', 'succeeded']] as const) {
      const { gateway, calls, makeRequest } = setup(behavior)
      const result = await gateway.processToolCall(makeRequest(structuredClone(APPROVED)))
      assert.equal(result.executed, true, `${behavior}: ${result.denialReason}`)
      assert.equal(result.outcome, expected, behavior)
      assert.equal(calls.length, 1)
    }
  })
})
