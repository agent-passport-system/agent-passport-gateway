// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Nano Wallet Crypto — Local Key Management & Block Signing
 *
 * No Nano node needed. All cryptography runs locally.
 * Only work generation and block publishing use public RPC.
 *
 * Master seed → HD derivation → one address per agent index
 * Private keys never leave this process.
 */

// @ts-ignore — nanocurrency-web has no type declarations
import nanoWebImport from 'nanocurrency-web'
import { readFileSync, writeFileSync, existsSync } from 'node:fs'
import { randomBytes } from 'node:crypto'
import { nanoRpc } from './rpc-client.js'

// Handle CJS/ESM interop — nanocurrency-web is CJS
const nanoWeb = (nanoWebImport as any).default || nanoWebImport
const { wallet: nanoWallet, block: nanoBlock, tools: nanoTools } = nanoWeb

// ── Seed Management ──

// Determine seed path: env var > /data/ (Railway) > home dir
function defaultSeedPath(): string {
  if (process.env.NANO_SEED_PATH) return process.env.NANO_SEED_PATH
  const dbPath = process.env.DB_PATH || ''
  if (dbPath.startsWith('/data')) return '/data/.aeoess-nano-seed'
  const home = process.env.HOME || '/tmp'
  return `${home}/.aeoess-nano-seed`
}

const DEFAULT_SEED_PATH = defaultSeedPath()

export function getMasterSeed(seedPath?: string): string {
  const path = seedPath || DEFAULT_SEED_PATH
  if (existsSync(path)) {
    return readFileSync(path, 'utf-8').trim()
  }
  // Generate new seed from the operating system CSPRNG. Entropy is passed
  // explicitly so seed strength never depends on the library's default source.
  const wallet = nanoWallet.generate(randomBytes(32).toString('hex'))
  writeFileSync(path, wallet.seed, { mode: 0o600 })
  console.log(`[NANO] New master seed generated and saved to ${path}`)
  console.log(`[NANO] BACK THIS UP IMMEDIATELY. Loss = loss of all agent funds.`)
  return wallet.seed
}

// ── Key Derivation ──

export interface DerivedAccount {
  address: string
  publicKey: string
  privateKey: string
  index: number
}

export function deriveAccount(seed: string, index: number): DerivedAccount {
  const accounts = nanoWallet.accounts(seed, index, index)
  const acct = accounts[0]
  return {
    address: acct.address,
    publicKey: acct.publicKey,
    privateKey: acct.privateKey,
    index,
  }
}

/** Safe version — returns only address + publicKey, no private key */
export function deriveAddress(seed: string, index: number): { address: string; publicKey: string } {
  const accounts = nanoWallet.accounts(seed, index, index)
  return { address: accounts[0].address, publicKey: accounts[0].publicKey }
}

// ── Account Info (from public RPC) ──

export async function getAccountInfo(rpcUrl: string, address: string): Promise<{
  frontier: string
  balance: string
  representative: string
  open: boolean
}> {
  try {
    const info = await nanoRpc(rpcUrl, {
      action: 'account_info',
      account: address,
      representative: 'true',
    })

    return {
      frontier: info.frontier,
      balance: info.balance,
      representative: info.representative,
      open: true,
    }
  } catch (e: any) {
    if (e.message?.includes('Account not found')) {
      return { frontier: '0'.repeat(64), balance: '0', representative: '', open: false }
    }
    throw e
  }
}

// ── Default representative (Nano Foundation) ──
const DEFAULT_REP = 'nano_1stofnrxuz3cai7ze75o174bpm7scwj9jn3nxsn8ntzg784jf1gzn1jjdkou'

// ── Work Generation (public RPC) ──

async function generateWork(rpcUrl: string, hash: string): Promise<string> {
  const result = await nanoRpc(rpcUrl, {
    action: 'work_generate',
    hash,
  })
  return result.work
}

// ── Publish Block (public RPC) ──

async function publishBlock(rpcUrl: string, block: any): Promise<string> {
  const result = await nanoRpc(rpcUrl, {
    action: 'process',
    json_block: 'true',
    subtype: block.subtype || 'send',
    block: {
      type: 'state',
      account: block.account,
      previous: block.previous,
      representative: block.representative,
      balance: block.balance,
      link: block.link,
      signature: block.signature,
      work: block.work,
    },
  })
  return result.hash
}

// ══════════════════════════════════════════════════════
// Send Nano — local signing, remote work + publish
// ══════════════════════════════════════════════════════

export async function sendNano(opts: {
  rpcUrl: string
  seed: string
  fromIndex: number
  toAddress: string
  amountRaw: string
}): Promise<{ blockHash: string; fromAddress: string }> {
  const account = deriveAccount(opts.seed, opts.fromIndex)
  const info = await getAccountInfo(opts.rpcUrl, account.address)
  if (!info.open) throw new Error(`Account ${account.address} has not been opened (no balance)`)

  const currentBalance = BigInt(info.balance)
  const sendAmount = BigInt(opts.amountRaw)
  if (sendAmount > currentBalance) {
    throw new Error(`Insufficient balance: have ${info.balance} raw, need ${opts.amountRaw} raw`)
  }
  const newBalance = (currentBalance - sendAmount).toString()

  // Generate work on the frontier
  const work = await generateWork(opts.rpcUrl, info.frontier)

  // Build and sign block locally
  const sendBlock = nanoBlock.send({
    walletBalanceRaw: info.balance,
    fromAddress: account.address,
    toAddress: opts.toAddress,
    representativeAddress: info.representative || DEFAULT_REP,
    frontier: info.frontier,
    amountRaw: opts.amountRaw,
    work,
  }, account.privateKey)

  // Publish to network
  const blockHash = await publishBlock(opts.rpcUrl, {
    account: account.address,
    previous: info.frontier,
    representative: info.representative || DEFAULT_REP,
    balance: newBalance,
    link: nanoTools.addressToPublicKey(opts.toAddress),
    signature: sendBlock.signature,
    work,
    subtype: 'send',
  })

  return { blockHash, fromAddress: account.address }
}

// ══════════════════════════════════════════════════════
// Receive Nano — pocket pending blocks
// ══════════════════════════════════════════════════════

export async function receiveNano(opts: {
  rpcUrl: string
  seed: string
  accountIndex: number
}): Promise<{ received: number; blocks: string[] }> {
  const account = deriveAccount(opts.seed, opts.accountIndex)
  const info = await getAccountInfo(opts.rpcUrl, account.address)

  // Get receivable blocks
  let receivable: any
  try {
    receivable = await nanoRpc(opts.rpcUrl, {
      action: 'receivable',
      account: account.address,
      count: '100',
      source: 'true',
    })
  } catch {
    return { received: 0, blocks: [] }
  }

  const pendingBlocks = receivable.blocks
  if (!pendingBlocks || typeof pendingBlocks !== 'object') return { received: 0, blocks: [] }

  const hashes = Object.keys(pendingBlocks)
  const blocks: string[] = []
  let currentFrontier = info.frontier
  let currentBalance = BigInt(info.balance)

  for (const sendHash of hashes) {
    try {
      const amount = typeof pendingBlocks[sendHash] === 'object'
        ? pendingBlocks[sendHash].amount
        : pendingBlocks[sendHash]

      const workHash = info.open ? currentFrontier : nanoTools.addressToPublicKey(account.address)
      const work = await generateWork(opts.rpcUrl, workHash)

      const newBalance = (currentBalance + BigInt(amount)).toString()

      const receiveBlock = nanoBlock.receive({
        walletBalanceRaw: currentBalance.toString(),
        toAddress: account.address,
        representativeAddress: info.representative || DEFAULT_REP,
        frontier: currentFrontier,
        transactionHash: sendHash,
        amountRaw: amount,
        work,
      }, account.privateKey)

      const blockHash = await publishBlock(opts.rpcUrl, {
        account: account.address,
        previous: currentFrontier === '0'.repeat(64) ? '0'.repeat(64) : currentFrontier,
        representative: info.representative || DEFAULT_REP,
        balance: newBalance,
        link: sendHash,
        signature: receiveBlock.signature,
        work,
        subtype: info.open ? 'receive' : 'open',
      })

      blocks.push(blockHash)
      currentFrontier = blockHash
      currentBalance = BigInt(newBalance)
    } catch (e: any) {
      console.error(`[NANO] Failed to receive ${sendHash}:`, e.message)
    }
  }

  return { received: blocks.length, blocks }
}

// ══════════════════════════════════════════════════════
// NanoLocalWallet — the full service, no node required
// ══════════════════════════════════════════════════════

export class NanoLocalWallet {
  private seed: string
  private rpcUrl: string

  constructor(opts?: { seed?: string; seedPath?: string; rpcUrl?: string }) {
    this.seed = opts?.seed || getMasterSeed(opts?.seedPath)
    this.rpcUrl = opts?.rpcUrl || process.env.NANO_RPC_URL || 'https://rpc.nano.to'
  }

  /** Get or derive address for agent at given index */
  getAddress(index: number): string {
    return deriveAccount(this.seed, index).address
  }

  /** Get live balance for an address */
  async getBalance(address: string) {
    return getAccountInfo(this.rpcUrl, address)
  }

  /** Send XNO from an agent wallet */
  async send(fromIndex: number, toAddress: string, amountRaw: string) {
    return sendNano({
      rpcUrl: this.rpcUrl,
      seed: this.seed,
      fromIndex,
      toAddress,
      amountRaw,
    })
  }

  /** Receive all pending for an agent wallet */
  async receive(accountIndex: number) {
    return receiveNano({
      rpcUrl: this.rpcUrl,
      seed: this.seed,
      accountIndex,
    })
  }

  /** Validate a Nano address */
  validateAddress(address: string): boolean {
    return nanoTools.validateAddress(address)
  }
}

// ── Singleton ──

let _localWallet: NanoLocalWallet | null = null

export function getLocalWallet(): NanoLocalWallet {
  if (!_localWallet) {
    _localWallet = new NanoLocalWallet()
  }
  return _localWallet
}
