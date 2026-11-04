// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync, statSync, readFileSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { getMasterSeed, initMasterSeed, NanoSeedMissingError, NanoWalletsPausedError, assertNanoSeedProvisioned, deriveAddress } from '../src/payment-rails/wallet-crypto.js'

const dir = () => mkdtempSync(join(tmpdir(), 'nano-seed-'))

describe('Nano master seed: fail closed', () => {
  it('throws when no seed is provisioned and creates no file', () => {
    const p = join(dir(), 'seed')
    assert.throws(() => getMasterSeed(p), NanoSeedMissingError)
    assert.equal(existsSync(p), false)
  })

  it('rejects a malformed seed file', () => {
    const p = join(dir(), 'seed')
    writeFileSync(p, 'not-a-seed')
    assert.throws(() => getMasterSeed(p), /not a 64 byte hex seed/)
  })

  it('initMasterSeed writes a 0600 file with a 128 hex character seed', () => {
    const p = join(dir(), 'seed')
    const { path, address } = initMasterSeed(p)
    assert.equal(path, p)
    assert.equal(statSync(p).mode & 0o777, 0o600)
    const seed = readFileSync(p, 'utf8')
    assert.match(seed, /^[0-9a-f]{128}$/i)
    assert.equal(getMasterSeed(p), seed)
    assert.equal(address, deriveAddress(seed, 0).address)
  })

  it('initMasterSeed refuses to overwrite an existing seed', () => {
    const p = join(dir(), 'seed')
    initMasterSeed(p)
    const before = readFileSync(p, 'utf8')
    assert.throws(() => initMasterSeed(p), /EEXIST/)
    assert.equal(readFileSync(p, 'utf8'), before)
  })

  it('two initializations produce different seeds', () => {
    const a = join(dir(), 'seed'), b = join(dir(), 'seed')
    initMasterSeed(a); initMasterSeed(b)
    assert.notEqual(readFileSync(a, 'utf8'), readFileSync(b, 'utf8'))
  })
})

describe('Nano master seed: operator pause and startup check', () => {
  it('getMasterSeed refuses while NANO_WALLETS_PAUSED=1, even with a valid seed', () => {
    const p = join(dir(), 'seed')
    initMasterSeed(p)
    process.env.NANO_WALLETS_PAUSED = '1'
    try {
      assert.throws(() => getMasterSeed(p), NanoWalletsPausedError)
    } finally {
      delete process.env.NANO_WALLETS_PAUSED
    }
    assert.match(getMasterSeed(p), /^[0-9a-f]{128}$/i)
  })

  it('assertNanoSeedProvisioned throws for a missing seed and passes for a valid one', () => {
    const p = join(dir(), 'seed')
    assert.throws(() => assertNanoSeedProvisioned(p), NanoSeedMissingError)
    initMasterSeed(p)
    assert.doesNotThrow(() => assertNanoSeedProvisioned(p))
  })

  it('assertNanoSeedProvisioned is skipped when the rail is disabled or paused', () => {
    const p = join(dir(), 'missing')
    for (const flag of ['NANO_RAIL_DISABLED', 'NANO_WALLETS_PAUSED']) {
      process.env[flag] = '1'
      try {
        assert.doesNotThrow(() => assertNanoSeedProvisioned(p))
      } finally {
        delete process.env[flag]
      }
    }
  })
})
