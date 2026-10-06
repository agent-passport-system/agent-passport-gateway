// ══════════════════════════════════════════════════════════════════
// Proxy Gateway — stored decision signature at execute time
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

function setup() {
  clearStores()
  const gatewayKeys = generateKeyPair()
  const principal = joinSocialContract({
    name: 'Integrity Principal', mission: 'Testing approval integrity', owner: 'tester',
    capabilities: ['testing'], platform: 'test', models: ['test-model'], floor
  })
  const agent = joinSocialContract({
    name: 'Integrity Agent', mission: 'Tool execution', owner: 'tester',
    capabilities: ['payments:send'], platform: 'test', models: ['test-model'], floor
  })
  const delegation = delegate({
    from: principal, toPublicKey: agent.keyPair.publicKey,
    scope: ['payments:send'], spendLimit: 100000, maxDepth: 2
  })
  const config: GatewayConfig = {
    gatewayId: 'gateway-integrity-001', gatewayPublicKey: gatewayKeys.publicKey,
    gatewayPrivateKey: gatewayKeys.privateKey, floor, approvalTTLSeconds: 30, recheckRevocationOnExecute: true,
  }

  const calls: Array<{ tool: string; params: Record<string, unknown> }> = []
  const executor: ToolExecutor = async (tool, params) => {
    calls.push({ tool, params })
    return { success: true, result: { ok: true } }
  }

  const gateway = createProxyGateway(config, executor)
  gateway.registerAgent(agent.passport, agent.attestation, [delegation])

  function makeRequest(params: Record<string, unknown>, spend?: { amount: number; currency: string }): ToolCallRequest {
    const requestId = `req-${Date.now()}-${Math.random().toString(36).slice(2)}`
    const tool = 'payments:transfer'
    const scopeRequired = 'payments:send'
    const payload = canonicalize({ requestId, agentId: agent.agentId, tool, params, scopeRequired, spend })
    return {
      requestId, agentId: agent.agentId, agentPublicKey: agent.keyPair.publicKey,
      signature: sign(payload, agent.keyPair.privateKey),
      tool, params, scopeRequired, spend, context: 'integrity test'
    }
  }

  function storedApproval(approvalId: string): GatewayApproval {
    return (gateway as unknown as { approvals: Map<string, GatewayApproval> }).approvals.get(approvalId)!
  }

  return { gateway, calls, makeRequest, storedApproval }
}

const APPROVED = { to: 'DE89370400440532013000', amount: 4000, currency: 'EUR' }

/** Asserts a refusal before dispatch: not executed, executor untouched, nothing consumed, counted as denied. */
async function expectRefused(
  ctx: ReturnType<typeof setup>, id: string, reason: string
) {
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

describe('ProxyGateway approved decision signature at execute time', () => {
  for (const verdict of ['narrow', 'deny'] as const) {
    it(`refuses a decision whose verdict was edited to ${verdict}, without calling the executor`, async () => {
      const ctx = setup()
      const id = ctx.gateway.approve(ctx.makeRequest(structuredClone(APPROVED))).approval!.approvalId
      assert.equal(ctx.storedApproval(id).decision.verdict, 'permit')
      ctx.storedApproval(id).decision.verdict = verdict
      await expectRefused(ctx, id, 'Approved decision signature does not verify')
    })
  }

  it('refuses a decision re-signed with a key other than the gateway key', async () => {
    const ctx = setup()
    const id = ctx.gateway.approve(ctx.makeRequest(structuredClone(APPROVED))).approval!.approvalId

    // Edit, swap in an outside public key, and re-sign: verifies under decision.evaluatorPublicKey.
    const other = generateKeyPair()
    const stored = ctx.storedApproval(id).decision
    stored.reason = 'edited after evaluation'
    stored.evaluatorPublicKey = other.publicKey
    const { signature: _old, ...unsigned } = stored
    stored.signature = sign(canonicalize(unsigned), other.privateKey)

    await expectRefused(ctx, id, 'Approved decision signature does not verify')
  })

  it('executes when the stored decision is unedited', async () => {
    const ctx = setup()
    const id = ctx.gateway.approve(ctx.makeRequest(structuredClone(APPROVED))).approval!.approvalId
    const result = await ctx.gateway.executeApproval(id)
    assert.equal(result.executed, true, result.denialReason)
    assert.equal(ctx.calls.length, 1)
  })
})
