// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Print the public addresses a seed file derives, to check that a backup restores the
 * expected wallets before production switches to it.
 *
 *   npm run nano:seed-addresses -- /path/to/seed [count]
 *
 * Prints index and address only. The seed itself is never printed.
 */
import { readFileSync } from 'node:fs'
import { deriveAddress } from '../src/payment-rails/wallet-crypto.js'

const [path, countArg] = process.argv.slice(2)
if (!path) {
  console.error('usage: nano-seed-addresses <seed file> [count]')
  process.exit(2)
}
const seed = readFileSync(path, 'utf-8').trim()
if (!/^[0-9a-fA-F]{128}$/.test(seed)) {
  console.error('seed file is not a 64 byte hex seed')
  process.exit(1)
}
const count = Math.max(1, Math.min(100, parseInt(countArg || '3', 10) || 3))
for (let i = 0; i < count; i++) {
  console.log(`${i}\t${deriveAddress(seed, i).address}`)
}
