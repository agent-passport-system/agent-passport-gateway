// ══════════════════════════════════════════════════════════════════
// Proxy Gateway — stored approval integrity and thrown dispatch records
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createProxyGateway } from '../../../src/sdk-migrated/core/proxy-gateway.js'
import type { ToolCallResult } from '../../../src/sdk-migrated/core/proxy-gateway.js'
import { joinSocialContract, delegate } from 'agent-passport-system'
import { generateKeyPair, sign } from 'agent-passport-system'
import { canonicalize } from 'agent-passport-system'
import { loadFloor } from 'agent-passport-system'
import { clearStores } from 'agent-passport-system'
import type { ToolCallRequest, ToolExecutor, GatewayConfig, GatewayApproval, StorageBackend } from 'agent-passport-system'
import { readFileSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const floorYaml = readFileSync(join(__dirname, '../../../node_modules/agent-passport-system/values/floor.yaml'), 'utf-8')
const floor = loadFloor(floorYaml)

type Behavior = 'success' | 'error' | 'throw'

/** Records every write; implements only what the gateway calls on these paths. */
function storageStub() {
  const nonces: string[] = []
  const receipts: unknown[] = []
  const tx = {
    async appendReceipt(r: unknown) { receipts.push(r) },
    async checkAndStoreNonce(n: string) { nonces.push(n); return true },
    async putReputation() {},
  }
  const backend = {
    async putAgent() {}, async putDelegation() {}, async putReputation() {},
    async transaction<T>(fn: (t: typeof tx) => Promise<T>): Promise<T> { return fn(tx) },
  }
  return { backend: backend as unknown as StorageBackend, nonces, receipts }
}

function setup(behavior: Behavior = 'success', opts: { storage?: StorageBackend } = {}) {
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
  const toolCalls: Array<{ request: ToolCallRequest; result: ToolCallResult }> = []
  const config: GatewayConfig = {
    gatewayId: 'gateway-integrity-001', gatewayPublicKey: gatewayKeys.publicKey,
    gatewayPrivateKey: gatewayKeys.privateKey, floor, approvalTTLSeconds: 30, recheckRevocationOnExecute: true,
    storage: opts.storage,
    onToolCall: (request, result) => { toolCalls.push({ request, result }) },
  }

  const calls: Array<{ tool: string; params: Record<string, unknown> }> = []
  const executor: ToolExecutor = async (tool, params) => {
    calls.push({ tool, params })
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
      tool, params, scopeRequired, context: 'integrity test'
    }
  }

  function storedApproval(approvalId: string): GatewayApproval {
    return (gateway as unknown as { approvals: Map<string, GatewayApproval> }).approvals.get(approvalId)!
  }

  return { gateway, agentId: agent.agentId, calls, toolCalls, makeRequest, storedApproval }
}

const APPROVED = { to: 'DE89370400440532013000', amount: 4000, currency: 'EUR', meta: { memo: 'invoice 17' } }
const EDITED = { ...APPROVED, amount: 4100 }

/** Fire-and-forget storage writes settle after a few microtask turns. */
const settle = () => new Promise(resolve => setImmediate(resolve))

describe('ProxyGateway stored approval exposure', () => {
  it('editing params and intent target through getAgentApprovals does not reach dispatch', async () => {
    const { gateway, agentId, calls, makeRequest, storedApproval } = setup()
    const approved = gateway.approve(makeRequest(structuredClone(APPROVED)))
    assert.equal(approved.approved, true)
    const id = approved.approval!.approvalId

    const listed = gateway.getAgentApprovals(agentId)
    assert.equal(listed.length, 1)
    listed[0].params = { ...EDITED }
    listed[0].intent.action.target = JSON.stringify(EDITED)

    const result = await gateway.executeApproval(id)
    assert.equal(result.executed, true, result.denialReason)
    assert.equal(calls.length, 1)
    assert.deepEqual(calls[0].params, APPROVED)
    assert.equal(result.receipt!.action.target, JSON.stringify(APPROVED))
    assert.equal(storedApproval(id).intent.action.target, JSON.stringify(APPROVED))
    assert.notEqual(listed[0], storedApproval(id), 'returns a copy, not the stored approval')
  })

  it('the decision on an execute result is a copy of the stored decision', async () => {
    const { gateway, makeRequest, storedApproval } = setup()
    const approved = gateway.approve(makeRequest(structuredClone(APPROVED)))
    const id = approved.approval!.approvalId
    const result = await gateway.executeApproval(id)
    assert.equal(result.executed, true, result.denialReason)
    assert.notEqual(result.decision, storedApproval(id).decision)
    ;(result.decision as any).verdict = 'deny'
    assert.notEqual(storedApproval(id).decision.verdict, 'deny')
  })

  it('a params mismatch refusal returns a copy of the stored decision', async () => {
    const { gateway, makeRequest, storedApproval } = setup()
    const approved = gateway.approve(makeRequest(structuredClone(APPROVED)))
    const id = approved.approval!.approvalId
    storedApproval(id).params = { ...EDITED }
    const result = await gateway.executeApproval(id)
    assert.equal(result.denialReason, 'Approval parameters do not match the approved intent')
    assert.ok(result.decision)
    assert.notEqual(result.decision, storedApproval(id).decision)
  })
})

describe('ProxyGateway approved intent signature at execute time', () => {
  it('refuses an intent whose target was edited after signing, without calling the executor', async () => {
    const { gateway, calls, makeRequest, storedApproval } = setup()
    const approved = gateway.approve(makeRequest(structuredClone(APPROVED)))
    const id = approved.approval!.approvalId

    // Keep params and target consistent so only the signature can catch it.
    const stored = storedApproval(id)
    stored.params = { ...EDITED }
    stored.intent.action.target = JSON.stringify(EDITED)
    const deniedBefore = gateway.getStats().totalDenied

    const result = await gateway.executeApproval(id)
    assert.equal(result.executed, false)
    assert.equal(result.denialReason, 'Approved intent signature does not verify')
    assert.equal(calls.length, 0, 'executor must not be called')
    assert.equal(storedApproval(id).consumed, false, 'a refused approval is not consumed')
    assert.equal(gateway.getStats().totalDenied, deniedBefore + 1)
    assert.notEqual(result.decision, storedApproval(id).decision, 'refusal returns a copy of the decision')
  })

  it('refuses an intent re-signed with a key other than the gateway key', async () => {
    const { gateway, calls, makeRequest, storedApproval } = setup()
    const approved = gateway.approve(makeRequest(structuredClone(APPROVED)))
    const id = approved.approval!.approvalId

    // Edit, swap in an outside public key, and re-sign: verifies under intent.agentPublicKey.
    const other = generateKeyPair()
    const stored = storedApproval(id)
    stored.params = { ...EDITED }
    stored.intent.action.target = JSON.stringify(EDITED)
    stored.intent.agentPublicKey = other.publicKey
    const { signature: _old, ...unsigned } = stored.intent
    stored.intent.signature = sign(canonicalize(unsigned), other.privateKey)

    const result = await gateway.executeApproval(id)
    assert.equal(result.executed, false)
    assert.equal(result.denialReason, 'Approved intent signature does not verify')
    assert.equal(calls.length, 0, 'executor must not be called')
  })

  it('checks the intent signature before params against target', async () => {
    const { gateway, calls, makeRequest, storedApproval } = setup()
    const approved = gateway.approve(makeRequest(structuredClone(APPROVED)))
    const id = approved.approval!.approvalId

    // Target edited, params left alone: both checks would fail.
    storedApproval(id).intent.action.target = JSON.stringify(EDITED)

    const result = await gateway.executeApproval(id)
    assert.equal(result.executed, false)
    assert.equal(result.denialReason, 'Approved intent signature does not verify')
    assert.equal(calls.length, 0)
  })
})

describe('ProxyGateway thrown dispatch records', () => {
  it('approval path: a throw stores the nonce and onToolCall fires with outcome unknown', async () => {
    const storage = storageStub()
    const { gateway, calls, toolCalls, makeRequest, storedApproval } = setup('throw', { storage: storage.backend })
    const request = makeRequest(structuredClone(APPROVED))
    const approved = gateway.approve(request)
    const id = approved.approval!.approvalId
    const result = await gateway.executeApproval(id)
    await settle()

    assert.equal(result.executed, true)
    assert.equal(result.outcome, 'unknown')
    assert.equal(calls.length, 1)
    assert.deepEqual(storage.nonces, [request.requestId])
    assert.equal(storage.receipts.length, 0, 'no receipt for an unknown outcome')
    assert.equal(toolCalls.length, 1)
    assert.equal(toolCalls[0].result.outcome, 'unknown')
    assert.equal(toolCalls[0].request.requestId, request.requestId)
    assert.deepEqual(toolCalls[0].request.params, APPROVED)
    assert.ok(Object.isFrozen(toolCalls[0].request), 'onToolCall gets a frozen copy of the request')
    assert.notEqual(result.decision, storedApproval(id).decision, 'throw result carries a copy of the decision')
  })

  it('single step path: a throw stores the nonce', async () => {
    const storage = storageStub()
    const { gateway, toolCalls, makeRequest } = setup('throw', { storage: storage.backend })
    const request = makeRequest(structuredClone(APPROVED))
    const result = await gateway.processToolCall(request)
    await settle()

    assert.equal(result.outcome, 'unknown')
    assert.deepEqual(storage.nonces, [request.requestId])
    assert.equal(storage.receipts.length, 0, 'no receipt for an unknown outcome')
    assert.equal(toolCalls.length, 1)
  })

  it('approval path: onToolCall fires for tool failure and success', async () => {
    for (const [behavior, expected] of [['error', 'tool_reported_failure'], ['success', 'succeeded']] as const) {
      const { gateway, toolCalls, makeRequest } = setup(behavior)
      const request = makeRequest(structuredClone(APPROVED))
      const approved = gateway.approve(request)
      const result = await gateway.executeApproval(approved.approval!.approvalId)
      assert.equal(result.executed, true, `${behavior}: ${result.denialReason}`)
      assert.equal(toolCalls.length, 1, behavior)
      assert.equal(toolCalls[0].result.outcome, expected)
      assert.equal(toolCalls[0].request.requestId, request.requestId)
    }
  })
})
