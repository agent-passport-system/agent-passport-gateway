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

const SEED_PATTERN = /^[0-9a-fA-F]{128}$/

/** Raised when no master seed is provisioned. The gateway never creates one implicitly. */
export class NanoSeedMissingError extends Error {
  constructor(public readonly seedPath: string) {
    super(
      `Nano master seed not found at ${seedPath}. Provision the existing seed, or create a new one ` +
      `deliberately with \`npm run nano:seed-init\`. The gateway does not generate a seed on demand, ` +
      `because a silently created seed changes every derived address.`
    )
    this.name = 'NanoSeedMissingError'
  }
}

/** Raised while an operator has paused the Nano wallets, for example during a seed rotation. */
export class NanoWalletsPausedError extends Error {
  constructor() {
    super('Nano wallets are paused by the operator (NANO_WALLETS_PAUSED=1). Try again later.')
    this.name = 'NanoWalletsPausedError'
  }
}

function walletsPaused(): boolean {
  return process.env.NANO_WALLETS_PAUSED === '1'
}

/**
 * Startup check for production. Throws when the Nano wallets are in use and the seed file is
 * missing or malformed. Skipped when the operator has disabled the rail (NANO_RAIL_DISABLED=1)
 * or paused the wallets (NANO_WALLETS_PAUSED=1).
 */
export function assertNanoSeedProvisioned(seedPath?: string): void {
  if (process.env.NANO_RAIL_DISABLED === '1' || walletsPaused()) return
  const path = seedPath || DEFAULT_SEED_PATH
  if (!existsSync(path)) throw new NanoSeedMissingError(path)
  if (!SEED_PATTERN.test(readFileSync(path, 'utf-8').trim())) {
    throw new Error(`Nano master seed at ${path} is not a 64 byte hex seed`)
  }
}

/**
 * Load the provisioned master seed. Fails closed: a missing or malformed seed file is an error,
 * never a reason to generate a replacement.
 */
export function getMasterSeed(seedPath?: string): string {
  if (walletsPaused()) throw new NanoWalletsPausedError()
  const path = seedPath || DEFAULT_SEED_PATH
  if (!existsSync(path)) {
    throw new NanoSeedMissingError(path)
  }
  const seed = readFileSync(path, 'utf-8').trim()
  if (!SEED_PATTERN.test(seed)) {
    throw new Error(`Nano master seed at ${path} is not a 64 byte hex seed`)
  }
  return seed
}

/**
 * Deliberate initialization step. Creates a new master seed from the operating system CSPRNG and
 * refuses to overwrite an existing file. Entropy is passed explicitly so seed strength never
 * depends on the library's default source. Returns the path and the public index 0 address only.
 */
export function initMasterSeed(seedPath?: string): { path: string; address: string } {
  const path = seedPath || DEFAULT_SEED_PATH
  const wallet = nanoWallet.generate(randomBytes(32).toString('hex'))
  if (!SEED_PATTERN.test(wallet.seed)) {
    throw new Error('generated seed has an unexpected format')
  }
  // 'wx' fails if the file already exists, so an existing seed is never replaced.
  writeFileSync(path, wallet.seed, { mode: 0o600, flag: 'wx' })
  return { path, address: nanoWallet.accounts(wallet.seed, 0, 0)[0].address }
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
export const DEFAULT_REP = 'nano_1stofnrxuz3cai7ze75o174bpm7scwj9jn3nxsn8ntzg784jf1gzn1jjdkou'

// ── Work Generation (public RPC) ──

async function generateWork(rpcUrl: string, hash: string): Promise<string> {
  const result = await nanoRpc(rpcUrl, {
    action: 'work_generate',
    hash,
  })
  return result.work
}

// ── Publish Block ──
// Day 268, lifecycle C: the only Nano `process` call is publishAttempt in nano-publish.ts, behind
// a committed attempt. This file no longer publishes.

// ══════════════════════════════════════════════════════
// Send Nano — local signing, remote work + publish
// ══════════════════════════════════════════════════════

/** Day 268: a send that failed before the block was handed to the network. Nothing was
 *  published, so the caller may release what it reserved for this send. Any other error
 *  from sendNano happened during or after publishing, and the caller must treat the
 *  outcome as unknown: the block may still be accepted. */
/** The refusal both legacy publish paths raise before doing anything. */
export const LEGACY_PUBLISH_CLOSED = 'the legacy Nano publish path is closed: nothing was signed or published (Day 268 lifecycle)'

export class NanoSendNotBroadcastError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'NanoSendNotBroadcastError'
  }
}

export async function sendNano(opts: {
  rpcUrl: string
  seed: string
  fromIndex: number
  toAddress: string
  amountRaw: string
}): Promise<{ blockHash: string; fromAddress: string }> {
  // Day 268, lifecycle C: this path published outside the lifecycle. It is closed before any key
  // is derived or any node is called. Sends go through wallet_ops and nano-publish.ts.
  void opts
  throw new NanoSendNotBroadcastError(LEGACY_PUBLISH_CLOSED)
}

// ══════════════════════════════════════════════════════
// Receive Nano — pocket pending blocks
// ══════════════════════════════════════════════════════

export async function receiveNano(opts: {
  rpcUrl: string
  seed: string
  accountIndex: number
}): Promise<{ received: number; blocks: string[] }> {
  // Day 268, lifecycle C: closed like sendNano. Receives go through wallet_ops.
  void opts
  throw new NanoSendNotBroadcastError(LEGACY_PUBLISH_CLOSED)
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
