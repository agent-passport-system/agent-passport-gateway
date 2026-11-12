// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Day 268, lifecycle B: the local state block hash against the published block_hash example in
// the nano-docs RPC reference (docs/commands/rpc-protocol.md), and against blocks that
// nanocurrency-web 2.0.0 signs. No node, no network.
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
// @ts-ignore nanocurrency-web has no type declarations
import nanoWebImport from 'nanocurrency-web'
import { addressToPublicKey, canonicalBlockJson, parseRaw, stateBlockHash } from '../../src/payment-rails/nano-block.js'

const nano = (nanoWebImport as any).default || nanoWebImport

const DOCS_BLOCK = {
  type: 'state' as const,
  account: 'nano_3qgmh14nwztqw4wmcdzy4xpqeejey68chx6nciczwn9abji7ihhum9qtpmdr',
  previous: 'F47B23107E5F34B2CE06F562B5C435DF72A533251CB414C51B2B62A8F63A00E4',
  representative: 'nano_1hza3f7wiiqa7ig3jczyxj5yo86yegcmqk3criaz838j91sxcckpfhbhhra1',
  balance: '1000000000000000000000',
  link: '19D3D919475DEED4696B5D13018151D1AF88B2BD3BCFF048B45031C1F36D1858',
  signature: '3BFBA64A775550E6D49DF1EB8EEC2136DCD74F090E2ED658FBD9E80F17CB1C9F9F7BDE2B93D95558EC2F277FFF15FD11E6E2162A1714731B743D1E941FA4560A',
  work: 'cab7404f0b5449d0',
}
const DOCS_HASH = 'FF0144381CFF0B2C079A115E7ADA7E96F43FD219446E7524C48D1CC9900C4F17'

describe('nano state block hash', () => {
  it('N1 equals the published block_hash example', () => {
    assert.equal(stateBlockHash(DOCS_BLOCK), DOCS_HASH)
  })

  it('N2 changes when any hashed field changes', () => {
    const variants = [
      { ...DOCS_BLOCK, balance: '1000000000000000000001' },
      { ...DOCS_BLOCK, previous: DOCS_BLOCK.previous.replace(/^F/, 'E') },
      { ...DOCS_BLOCK, link: DOCS_BLOCK.link.replace(/^1/, '2') },
      { ...DOCS_BLOCK, representative: DOCS_BLOCK.account },
    ]
    for (const v of variants) assert.notEqual(stateBlockHash(v), DOCS_HASH)
  })

  it('N3 matches the hash nanocurrency-web signs, for small, large and whole-balance sends', () => {
    // The expected hashes were checked outside this repository:
    // each block's signature verifies over exactly this hash with an independent ed25519-blake2b
    // verifier. Pinned here so a change to the hash or to the library shows up as a failure.
    const from = nano.wallet.fromLegacySeed('00'.repeat(31) + '01').accounts[0]
    const to = nano.wallet.fromLegacySeed('00'.repeat(31) + '02').accounts[0]
    const cases: Array<[string, string, string]> = [
      ['1000000000000000000000000000000', '1', '0A353CC84ACA2710B4DC3A5E07356B3E8ADABD0E891F8C57492A16095B2AE4ED'],
      [((1n << 128n) - 1n).toString(), (7n * 10n ** 30n + 123456789n).toString(), '87B85C01547543A169B68E518265F0A3F737A86FE84FE6F2D935002F4F3EF279'],
      ['133248297920938463463374607431768211455', '133248297920938463463374607431768211455', '0DAEEE80702732B7ABBC62239DAB6E96222C950EC2D9CEA801B507FD8879C913'],
    ]
    for (const [bal, amt, hash] of cases) {
      const b = nano.block.send({ walletBalanceRaw: bal, fromAddress: from.address, toAddress: to.address,
        representativeAddress: from.address, frontier: DOCS_BLOCK.previous, amountRaw: amt, work: '0123456789abcdef' }, from.privateKey)
      assert.equal(b.balance, (BigInt(bal) - BigInt(amt)).toString())
      assert.ok(nano.tools.verifyBlock(from.publicKey, b))
      assert.equal(stateBlockHash(b), hash)
      assert.equal(b.link.toUpperCase(), addressToPublicKey(to.address))
    }
  })

  it('N4 refuses a balance that is negative, not canonical, or above 2^128 - 1', () => {
    for (const balance of ['-1', '01', '1e3', ' 5', (1n << 128n).toString()]) {
      assert.throws(() => stateBlockHash({ ...DOCS_BLOCK, balance }), /balance/)
      assert.equal(parseRaw(balance), null)
    }
  })

  it('N5 nanocurrency-web 2.0.0 signs a send above the balance, with balance -1, and the hash refuses it', () => {
    const from = nano.wallet.fromLegacySeed('00'.repeat(31) + '01').accounts[0]
    const b = nano.block.send({ walletBalanceRaw: '5', fromAddress: from.address, toAddress: from.address,
      representativeAddress: from.address, frontier: DOCS_BLOCK.previous, amountRaw: '6', work: '' }, from.privateKey)
    assert.equal(b.balance, '-1')
    assert.throws(() => stateBlockHash(b), /balance/)
  })

  it('N6 refuses an address with a bad checksum', () => {
    const bad = DOCS_BLOCK.account.slice(0, -1) + (DOCS_BLOCK.account.endsWith('r') ? 'q' : 'r')
    assert.throws(() => addressToPublicKey(bad), /checksum/)
  })

  it('N7 canonical block text is the same for equal blocks written in different hex case', () => {
    const lower = { ...DOCS_BLOCK, previous: DOCS_BLOCK.previous.toLowerCase(), link: DOCS_BLOCK.link.toLowerCase() }
    assert.equal(canonicalBlockJson(lower), canonicalBlockJson(DOCS_BLOCK))
  })
})
