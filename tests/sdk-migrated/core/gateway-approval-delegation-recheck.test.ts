// ══════════════════════════════════════════════════════════════════
// Proxy Gateway — delegation rechecked when the approval is consumed
// ══════════════════════════════════════════════════════════════════
// draft-pidlisnyi-aps-04 7.3.2: time and revocation state are rechecked at
// the moment the approval is consumed. The delegation the approval names must
// still verify (signature, notBefore, expiry, revocation) whatever
// recheckRevocationOnExecute says, and it must be the delegation the signed
// intent names. Otherwise the gateway refuses before dispatch.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createProxyGateway } from '../../../src/sdk-migrated/core/proxy-gateway.js'
import { joinSocialContract, delegate } from 'agent-passport-system'
import { generateKeyPair, sign } from 'agent-passport-system'
import { canonicalize } from 'agent-passport-system'
import { loadFloor } from 'agent-passport-system'
import { clearStores } from 'agent-passport-system'
import type { ToolCallRequest, ToolExecutor, GatewayConfig, GatewayApproval, Delegation } from 'agent-passport-system'
import { readFileSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const floorYaml = readFileSync(join(__dirname, '../../../node_modules/agent-passport-system/values/floor.yaml'), 'utf-8')
const floor = loadFloor(floorYaml)

const HOUR = 3600_000

function setup(opts: { recheck: boolean; readExpiresInHours?: number }) {
  clearStores()
  const gatewayKeys = generateKeyPair()
  const principal = joinSocialContract({
    name: 'Recheck Principal', mission: 'Testing delegation recheck', owner: 'tester',
    capabilities: ['testing'], platform: 'test', models: ['test-model'], floor
  })
  const agent = joinSocialContract({
    name: 'Recheck Agent', mission: 'Tool execution', owner: 'tester',
    capabilities: ['payments:send', 'data:read'], platform: 'test', models: ['test-model'], floor
  })
  const sendDelegation = delegate({
    from: principal, toPublicKey: agent.keyPair.publicKey,
    scope: ['payments:send'], spendLimit: 100000, maxDepth: 2, expiresInHours: 1
  })
  const readDelegation = delegate({
    from: principal, toPublicKey: agent.keyPair.publicKey,
    scope: ['data:read'], maxDepth: 2, expiresInHours: opts.readExpiresInHours ?? 1
  })
  const config: GatewayConfig = {
    gatewayId: 'gateway-recheck-001', gatewayPublicKey: gatewayKeys.publicKey,
    gatewayPrivateKey: gatewayKeys.privateKey, floor, approvalTTLSeconds: 7200,
    recheckRevocationOnExecute: opts.recheck,
  }

  const calls: string[] = []
  let gate: Promise<void> = Promise.resolve()
  const executor: ToolExecutor = async (tool) => {
    calls.push(tool)
    await gate
    return { success: true, result: { ok: true } }
  }

  const gateway = createProxyGateway(config, executor)
  gateway.registerAgent(agent.passport, agent.attestation, [sendDelegation, readDelegation])

  function makeRequest(scopeRequired: 'payments:send' | 'data:read'): ToolCallRequest {
    const requestId = `req-${Math.random().toString(36).slice(2)}`
    const tool = scopeRequired === 'payments:send' ? 'payments:transfer' : 'data:fetch'
    const params = { ref: requestId }
    const payload = canonicalize({ requestId, agentId: agent.agentId, tool, params, scopeRequired, spend: undefined })
    return {
      requestId, agentId: agent.agentId, agentPublicKey: agent.keyPair.publicKey,
      signature: sign(payload, agent.keyPair.privateKey),
      tool, params, scopeRequired, context: 'recheck test'
    }
  }

  function approveFor(scopeRequired: 'payments:send' | 'data:read'): string {
    const approved = gateway.approve(makeRequest(scopeRequired))
    assert.equal(approved.approved, true, approved.denial?.reason)
    return approved.approval!.approvalId
  }

  function storedApproval(approvalId: string): GatewayApproval {
    return (gateway as unknown as { approvals: Map<string, GatewayApproval> }).approvals.get(approvalId)!
  }

  /** The live delegation map the gateway dispatches against. */
  function liveDelegations(): Map<string, Delegation> {
    return (gateway as unknown as { agents: Map<string, { delegations: Map<string, Delegation> }> }).agents.get(agent.agentId)!.delegations
  }

  /** A copy of `d` changed by `edit` and genuinely re-signed by the principal. */
  function resigned(d: Delegation, edit: Partial<Delegation>): Delegation {
    const { signature: _sig, ...unsigned } = d
    const changed = { ...unsigned, ...edit }
    return { ...changed, signature: sign(canonicalize(changed), principal.keyPair.privateKey) } as Delegation
  }

  function hold(): () => void {
    let release!: () => void
    gate = new Promise<void>(resolve => { release = resolve })
    return release
  }

  return { gateway, calls, approveFor, storedApproval, liveDelegations, resigned, hold, principal, sendDelegation, readDelegation }
}

/** Asserts a refusal before dispatch: not executed, executor untouched, nothing consumed, counted as denied. */
async function expectRefused(ctx: ReturnType<typeof setup>, id: string, reason: string) {
  const deniedBefore = ctx.gateway.getStats().totalDenied
  const callsBefore = ctx.calls.length
  const result = await ctx.gateway.executeApproval(id)
  assert.equal(result.executed, false)
  assert.equal(result.denialReason, reason)
  assert.equal(ctx.calls.length, callsBefore, 'executor must not be called')
  assert.equal(ctx.storedApproval(id).consumed, false, 'a refused approval is not consumed')
  assert.equal(ctx.gateway.getStats().totalDenied, deniedBefore + 1)
  return result
}

describe('ProxyGateway delegation rechecked when the approval is consumed', () => {
  for (const recheck of [false, true]) {
    it(`refuses when the delegation expired between approve and execute (recheckRevocationOnExecute ${recheck})`, async (t) => {
      t.mock.timers.enable({ apis: ['Date'], now: Date.now() })
      const ctx = setup({ recheck })
      const id = ctx.approveFor('payments:send')
      t.mock.timers.tick(HOUR + 1000)
      await expectRefused(ctx, id, 'Delegation expired')
    })

    it(`refuses when the delegation was revoked between approve and execute (recheckRevocationOnExecute ${recheck})`, async () => {
      const ctx = setup({ recheck })
      const id = ctx.approveFor('payments:send')
      ctx.gateway.delegationStore.revokeDelegation(
        ctx.sendDelegation.delegationId, ctx.principal.publicKey, 'test', ctx.principal.keyPair.privateKey)
      await expectRefused(ctx, id, 'Delegation revoked')
    })

    it(`executes when the delegation is still valid (recheckRevocationOnExecute ${recheck})`, async () => {
      const ctx = setup({ recheck })
      const id = ctx.approveFor('payments:send')
      const result = await ctx.gateway.executeApproval(id)
      assert.equal(result.executed, true, result.denialReason)
      assert.equal(ctx.calls.length, 1)
      assert.ok(result.receipt)
      assert.equal(result.postDispatchErrors, undefined)
    })
  }

  it('refuses when the live delegation no longer verifies under its signature', async () => {
    const ctx = setup({ recheck: false })
    const id = ctx.approveFor('payments:send')
    // The registered delegation is frozen, so the edit goes in as an unsigned copy.
    const d = ctx.sendDelegation
    ctx.liveDelegations().set(d.delegationId, { ...d, expiresAt: new Date(Date.now() + 1000 * HOUR).toISOString() })
    await expectRefused(ctx, id, 'Delegation signature does not verify')
  })

  it('refuses when the live delegation is genuinely signed but not yet valid', async () => {
    const ctx = setup({ recheck: false })
    const id = ctx.approveFor('payments:send')
    const d = ctx.sendDelegation
    ctx.liveDelegations().set(d.delegationId, ctx.resigned(d, { notBefore: new Date(Date.now() + HOUR).toISOString() }))
    await expectRefused(ctx, id, 'Delegation not yet valid')
  })

  it('refuses when the live delegation is genuinely signed but invalid for another reason', async () => {
    const ctx = setup({ recheck: false })
    const id = ctx.approveFor('payments:send')
    const d = ctx.sendDelegation
    ctx.liveDelegations().set(d.delegationId, ctx.resigned(d, { currentDepth: d.maxDepth + 1 }))
    await expectRefused(ctx, id, 'Delegation invalid: Depth limit exceeded')
  })

  it('refuses when approval.delegationId names another genuine delegation of the same agent', async () => {
    const ctx = setup({ recheck: true })
    const id = ctx.approveFor('payments:send')
    assert.equal(ctx.storedApproval(id).intent.delegationId, ctx.sendDelegation.delegationId)
    ctx.storedApproval(id).delegationId = ctx.readDelegation.delegationId
    await expectRefused(ctx, id, 'Approval delegation does not match the approved intent')
  })

  it('rechecks at consumption: a delegation that expires while the approval waits for the agent lock is refused', async (t) => {
    t.mock.timers.enable({ apis: ['Date'], now: Date.now() })
    const ctx = setup({ recheck: true, readExpiresInHours: 0.5 })
    const first = ctx.approveFor('payments:send')
    const second = ctx.approveFor('data:read')
    const release = ctx.hold()
    const firstRun = ctx.gateway.executeApproval(first)
    await new Promise(resolve => setImmediate(resolve))
    assert.equal(ctx.calls.length, 1, 'first approval is in the executor')
    const deniedBefore = ctx.gateway.getStats().totalDenied
    const secondRun = ctx.gateway.executeApproval(second)
    await new Promise(resolve => setImmediate(resolve))
    t.mock.timers.tick(0.5 * HOUR + 1000)
    release()
    const [firstResult, secondResult] = await Promise.all([firstRun, secondRun])
    assert.equal(firstResult.executed, true, firstResult.denialReason)
    assert.equal(secondResult.executed, false)
    assert.equal(secondResult.denialReason, 'Delegation expired')
    assert.equal(ctx.calls.length, 1, 'the second approval never reached the executor')
    assert.equal(ctx.storedApproval(second).consumed, false)
    assert.equal(ctx.gateway.getStats().totalDenied, deniedBefore + 1)
  })
})
