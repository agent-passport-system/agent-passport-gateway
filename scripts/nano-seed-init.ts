// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Create a new Nano master seed, deliberately and once.
 *
 *   npm run nano:seed-init                 # uses NANO_SEED_PATH or the default path
 *   npm run nano:seed-init -- /path/seed   # explicit path
 *
 * Refuses to overwrite an existing seed. Prints the seed path and the public index 0 address.
 * The seed itself is never printed. Back up the file before routing funds to any address.
 */
import { initMasterSeed } from '../src/payment-rails/wallet-crypto.js'

const { path, address } = initMasterSeed(process.argv[2])
console.log(`[NANO] New master seed written to ${path} (mode 0600).`)
console.log(`[NANO] Gateway wallet (index 0): ${address}`)
console.log('[NANO] Back up the seed file before routing funds to any derived address.')
