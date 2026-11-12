// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Nano state block hash and field checks (Day 268, lifecycle B).
 *
 * The hash is computed here from the Nano specification, so the gateway knows a block's hash
 * before any RPC: blake2b-256 over a 32-byte preamble ending in 6, the account key, previous,
 * the representative key, the balance as 16 big-endian bytes, and link. The published
 * block_hash example in the nano-docs RPC reference is a test vector (test/payment-rails/
 * nano-block.test.ts). Nothing here talks to a node.
 */
import { blake2b } from '@noble/hashes/blake2b'

const ALPHABET = '13456789abcdefghijkmnopqrstuwxyz'
const HEX64 = /^[0-9A-F]{64}$/
const CANONICAL = /^(0|[1-9][0-9]*)$/
const MAX_BALANCE = (1n << 128n) - 1n

export interface StateBlock {
  type: 'state'
  account: string
  previous: string
  representative: string
  balance: string
  link: string
  signature: string
  work: string
}

const toHex = (b: Uint8Array) => Buffer.from(b).toString('hex').toUpperCase()

/** The 32-byte public key of a nano_ or xrb_ address, as uppercase hex. Throws on a bad address or checksum. */
export function addressToPublicKey(address: string): string {
  const m = /^(nano|xrb)_([13456789abcdefghijkmnopqrstuwxyz]{60})$/.exec(address)
  if (!m) throw new Error('nano address malformed')
  let bits = ''
  for (const c of m[2]) bits += ALPHABET.indexOf(c).toString(2).padStart(5, '0')
  // 300 bits: 4 padding bits, 256 key bits, 40 checksum bits
  if (!/^0000/.test(bits)) throw new Error('nano address padding is not zero')
  const bytes = (s: string) => Uint8Array.from(s.match(/.{8}/g)!.map(x => parseInt(x, 2)))
  const key = bytes(bits.slice(4, 260))
  const checksum = blake2b(key, { dkLen: 5 }).reverse()
  if (toHex(checksum) !== toHex(bytes(bits.slice(260)))) throw new Error('nano address checksum mismatch')
  return toHex(key)
}

/** A raw amount or balance as a canonical non-negative integer that fits Nano's 128-bit balance. */
export function parseRaw(raw: unknown): bigint | null {
  if (typeof raw !== 'string' || !CANONICAL.test(raw)) return null
  const v = BigInt(raw)
  return v <= MAX_BALANCE ? v : null
}

function hexBytes(h: string, name: string): Uint8Array {
  if (typeof h !== 'string' || !HEX64.test(h.toUpperCase())) throw new Error(`${name} is not 32 bytes of hex`)
  return Uint8Array.from(Buffer.from(h, 'hex'))
}

/** The hash of a state block, as uppercase hex. Throws when any hashed field is malformed. */
export function stateBlockHash(b: Pick<StateBlock, 'account' | 'previous' | 'representative' | 'balance' | 'link'>): string {
  const balance = parseRaw(b.balance)
  if (balance === null) throw new Error('balance is not a canonical raw amount below 2^128')
  const preamble = new Uint8Array(32)
  preamble[31] = 6
  const parts = [
    preamble,
    hexBytes(addressToPublicKey(b.account), 'account'),
    hexBytes(b.previous, 'previous'),
    hexBytes(addressToPublicKey(b.representative), 'representative'),
    Uint8Array.from(Buffer.from(balance.toString(16).padStart(32, '0'), 'hex')),
    hexBytes(b.link, 'link'),
  ]
  return toHex(blake2b(Buffer.concat(parts), { dkLen: 32 }))
}

/** The stored form of a block: fixed key order, uppercase hex fields, so equal blocks store equal text. */
export function canonicalBlockJson(b: StateBlock): string {
  return JSON.stringify({
    type: 'state',
    account: b.account,
    previous: b.previous.toUpperCase(),
    representative: b.representative,
    balance: b.balance,
    link: b.link.toUpperCase(),
    signature: b.signature.toUpperCase(),
    work: b.work.toLowerCase(),
  })
}
