// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Test fixtures for gate 1: pilot caps large enough not to interfere, and the operator step that
// records a wallet's verified starting frontier. Not a test file itself.
import type Database from 'better-sqlite3'
import { initializeWalletFrontier } from '../../src/payment-rails/wallet-frontier.js'

/** Caps far above anything these tests send. Tests of the caps set their own. */
export function setGenerousPilotCaps(): void {
  process.env.NANO_PILOT_MAX_PAYMENT_RAW = '1000000000000000000000000000000000'
  process.env.NANO_PILOT_MAX_WALLET_RAW = '1000000000000000000000000000000000'
  process.env.NANO_PILOT_MAX_PAYMENTS = '100000'
}

export function clearPilotCaps(): void {
  delete process.env.NANO_PILOT_MAX_PAYMENT_RAW
  delete process.env.NANO_PILOT_MAX_WALLET_RAW
  delete process.env.NANO_PILOT_MAX_PAYMENTS
}

/** The operator records the account state the fake node reports, as it would after verifying it. */
export function initFrontier(db: Database.Database, walletId: string, frontier: string, balanceRaw: string, replace = false): void {
  const r = initializeWalletFrontier(db, { walletId, frontier, balanceRaw, by: 'test-operator', evidence: 'fixture', now: 0, replace })
  if (!r.ok) throw new Error(`initFrontier: ${r.reason}`)
}
