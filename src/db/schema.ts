// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * AEOESS Gateway — Database Schema
 * SQLite for MVP, PostgreSQL migration path clear.
 */

import Database from 'better-sqlite3'
import { randomUUID } from 'node:crypto'

let db: Database.Database

/**
 * Reads GATEWAY_OPERATOR_EMAIL and GATEWAY_OPERATOR_EMAIL_ALIASES (comma
 * separated). Both are unset by default, with no email baked in. The
 * operator role elevation and identity reconciliation migrations below
 * are no-ops until an operator explicitly sets GATEWAY_OPERATOR_EMAIL.
 */
function operatorEmailConfig(): { email: string | null; aliases: string[] } {
  const email = (process.env.GATEWAY_OPERATOR_EMAIL || '').trim().toLowerCase() || null
  const aliases = (process.env.GATEWAY_OPERATOR_EMAIL_ALIASES || '')
    .split(',')
    .map(s => s.trim().toLowerCase())
    .filter(Boolean)
  return { email, aliases }
}

/**
 * ONE-TIME backfill for is_root (B1, Consilium): is_root is an ORIGIN property derived from HISTORY,
 * never from current edges. An agent is a root iff it has NEVER appeared as `child_agent_id` in
 * delegations under ANY status (active, revoked, expired, pending, suspended). Any agent that has
 * ever received a delegation -- even one now revoked or expired -- is is_root=0.
 *
 * Why the origin rule (and not "active grantor with no active inbound", the prior version):
 *   - it refuses a SEVERED child: a revoked/expired inbound plus an active outbound must NOT become a
 *     fresh-budget root (the prior rule promoted it, because the inbound was no longer active);
 *   - it preserves an IDLE real root: an origin principal that has not granted anything yet stays a
 *     root (the prior rule left it is_root=0, so its first grant 403'd).
 * A self-delegation A->A makes A appear as its own child, so A is correctly is_root=0.
 *
 * Scoped per tenant. Idempotent (the `is_root = 0` guard makes a re-run a no-op). Returns the number
 * of agents promoted. New roots created after migration require the audited admin designation path
 * (client-supplied is_root at POST /agents is ignored -- Consilium policy change).
 */
export function backfillAgentRoots(database: Database.Database): number {
  const info = database.prepare(`
    UPDATE agents SET is_root = 1
    WHERE is_root = 0
      AND NOT EXISTS (
        SELECT 1 FROM delegations d
        WHERE d.tenant_id = agents.tenant_id AND d.child_agent_id = agents.agent_id
      )
  `).run()
  return info.changes
}

export const IS_ROOT_MIGRATION_ID = 'is_root_origin_backfill_v1'

/**
 * B5 (Consilium): run the is_root origin backfill exactly once, TRANSACTIONALLY and versioned.
 * Gated on a schema_migrations `complete` row written in the SAME transaction as the backfill, NOT
 * on column presence. So a crash after the ALTER but before the backfill commits rolls back and
 * re-runs correctly on the next boot (the prior column-presence gate would skip it forever). The
 * IMMEDIATE lock plus a re-check inside the transaction serialize concurrent boots: the loser waits
 * (busy_timeout), then sees the marker complete and skips. Idempotent and safe to re-run.
 * Requires the schema_migrations table to already exist (created in the schema block above).
 */
export function runIsRootOriginBackfill(
  database: Database.Database,
  opts: { maxAttempts?: number; busyMs?: number } = {},
): 'applied' | 'already' {
  const maxAttempts = Number.isFinite(opts.maxAttempts as number) ? Math.max(1, opts.maxAttempts as number) : 12
  const busyMs = Number.isFinite(opts.busyMs as number) ? Math.max(0, opts.busyMs as number) : 5000
  try { database.pragma(`busy_timeout = ${busyMs}`) } catch {}

  const markerComplete = () =>
    database.prepare(`SELECT 1 FROM schema_migrations WHERE id = ? AND status = 'complete'`).get(IS_ROOT_MIGRATION_ID)

  const txn = database.transaction(() => {
    // Re-check inside the write lock: a concurrent boot may have completed it between the read above
    // and acquiring the lock here.
    if (markerComplete()) return false
    backfillAgentRoots(database)
    database.prepare(
      `INSERT INTO schema_migrations (id, status, applied_at) VALUES (?, 'complete', ?)
       ON CONFLICT(id) DO UPDATE SET status = 'complete', applied_at = excluded.applied_at`,
    ).run(IS_ROOT_MIGRATION_ID, new Date().toISOString())
    return true
  })

  // B5 panel F3: on a multi-replica boot (Railway rolling restart), a concurrent replica may hold the
  // write lock while it runs a large-fleet backfill for LONGER than busy_timeout, so `.immediate()`
  // can throw SQLITE_BUSY. The prior code let that propagate uncaught and CRASH the booting replica.
  // Instead, re-check the marker each round (the winner may have committed -> 'already') and retry a
  // bounded number of times; each attempt itself waits up to busy_timeout for the lock, so the total
  // wait rides out a slow winner. Only a genuinely stuck lock (marker never appears) surfaces an error,
  // fail-closed: better to crash-loop the boot than serve on an unmigrated DB.
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    if (markerComplete()) return 'already'
    try {
      const applied = txn.immediate() // BEGIN IMMEDIATE: take the write lock up front
      return applied ? 'applied' : 'already'
    } catch (e: any) {
      const busy = e && (e.code === 'SQLITE_BUSY' || /database is locked|SQLITE_BUSY/i.test(String(e.message || '')))
      if (busy && attempt < maxAttempts) continue
      throw e
    }
  }
  if (markerComplete()) return 'already'
  throw new Error('is_root migration could not acquire the write lock after retries; another process may be stuck holding it')
}

export function initDB(path: string = './gateway.db'): Database.Database {
  db = new Database(path)
  db.pragma('journal_mode = WAL')
  db.pragma('foreign_keys = ON')
  db.pragma('busy_timeout = 5000')
  createTables()
  return db
}

export function getDB(): Database.Database { return db }

function createTables() {
  db.exec(`
    -- Tenants (customers)
    CREATE TABLE IF NOT EXISTS tenants (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      plan TEXT NOT NULL DEFAULT 'free',
      stripe_customer_id TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      status TEXT NOT NULL DEFAULT 'active'
    );

    -- API Keys (one tenant can have multiple)
    CREATE TABLE IF NOT EXISTS api_keys (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      key_hash TEXT NOT NULL UNIQUE,
      key_prefix TEXT NOT NULL,
      name TEXT NOT NULL DEFAULT 'default',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      last_used_at TEXT,
      revoked_at TEXT
    );

    -- Agents (registered under each tenant)
    CREATE TABLE IF NOT EXISTS agents (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      agent_id TEXT NOT NULL,
      public_key TEXT NOT NULL,
      did TEXT,
      name TEXT,
      status TEXT NOT NULL DEFAULT 'active',
      -- Audit item 3: a DESIGNATED root grantor. Only is_root=1 agents may create a delegation
      -- with no inbound delegation (a fresh-budget root grant). Default 0 (not a root).
      is_root INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      UNIQUE(tenant_id, agent_id)
    );

    -- Delegations
    -- R3-5 (round-2 Consilium) APPEND-ONLY invariant: rows here are NEVER hard-deleted. Revocation and
    -- expiry are status updates (status='revoked', revoked_at set); the row persists. The B1 origin rule
    -- (is_root iff the agent has NEVER been a child_agent_id under ANY status) depends on this: deleting
    -- a revoked delegation would erase the history that proves an agent was once a delegatee and could
    -- silently re-root it. No DELETE FROM delegations exists in the codebase (grep-verified); /revoke and
    -- the cascade paths only UPDATE status. The same holds for agents (revocation is a status update).
    CREATE TABLE IF NOT EXISTS delegations (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      parent_agent_id TEXT NOT NULL,
      child_agent_id TEXT NOT NULL,
      scope TEXT NOT NULL,
      spend_limit REAL,
      spend_used REAL DEFAULT 0,
      max_depth INTEGER DEFAULT 3,
      current_depth INTEGER NOT NULL DEFAULT 0,
      status TEXT NOT NULL DEFAULT 'active',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      revoked_at TEXT,
      -- B6 (Consilium): DB-level money invariants, defense in depth behind the app cost guard.
      -- A negative cost or a refund below zero is structurally impossible at the row level.
      -- The ceiling CHECK carries a sub-cent (0.005) tolerance: spend is tracked in float dollars, so a
      -- legitimate spend-to-the-limit can land a few ULPs above spend_limit by IEEE-754 rounding
      -- (2.14 + 5.07 = 7.210000000000001). The tolerance is below money granularity (1 cent), so it
      -- absorbs that noise without masking any real over-limit (which is always >= 1 cent). The
      -- authoritative ceiling is the app-layer overspend guard (deny); this CHECK is a corruption
      -- backstop. Panel B6 F1: the exact form here 500'd on a legitimate at-limit spend.
      CHECK (spend_used >= 0),
      CHECK (spend_limit IS NULL OR spend_limit >= 0),
      CHECK (spend_limit IS NULL OR spend_used <= spend_limit + 0.005)
    );

    -- Policy Evaluations (the billable unit)
    CREATE TABLE IF NOT EXISTS policy_evaluations (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      agent_id TEXT NOT NULL,
      action_type TEXT NOT NULL,
      action_target TEXT NOT NULL,
      scope_required TEXT NOT NULL,
      verdict TEXT NOT NULL,
      reason TEXT,
      duration_ms INTEGER,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    -- Action Receipts (signed proof of execution)
    CREATE TABLE IF NOT EXISTS receipts (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      evaluation_id TEXT REFERENCES policy_evaluations(id),
      agent_id TEXT NOT NULL,
      action_type TEXT NOT NULL,
      verdict TEXT NOT NULL,
      execution_result TEXT NOT NULL,
      signature TEXT NOT NULL,
      payload TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    -- Usage (metered billing)
    CREATE TABLE IF NOT EXISTS usage (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      period TEXT NOT NULL,
      evaluations INTEGER DEFAULT 0,
      agents_active INTEGER DEFAULT 0,
      receipts_stored INTEGER DEFAULT 0,
      data_lineage_queries INTEGER DEFAULT 0,
      updated_at TEXT NOT NULL DEFAULT (datetime('now')),
      UNIQUE(tenant_id, period)
    );

    -- Revocation Events
    CREATE TABLE IF NOT EXISTS revocations (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      target_type TEXT NOT NULL,
      target_id TEXT NOT NULL,
      cascade_count INTEGER DEFAULT 0,
      revoked_by TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    -- Alerts
    CREATE TABLE IF NOT EXISTS alerts (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      alert_type TEXT NOT NULL,
      severity TEXT NOT NULL DEFAULT 'info',
      message TEXT NOT NULL,
      acknowledged_at TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    -- Data Sources (Pixel: registered data with terms)
    CREATE TABLE IF NOT EXISTS data_sources (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      source_id TEXT NOT NULL,
      source_name TEXT NOT NULL,
      source_url TEXT,
      data_terms TEXT NOT NULL DEFAULT '{}',
      owner_agent_id TEXT,
      status TEXT NOT NULL DEFAULT 'active',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      revoked_at TEXT,
      UNIQUE(tenant_id, source_id)
    );

    -- Access Receipts (Pixel: who accessed what data, when)
    CREATE TABLE IF NOT EXISTS access_receipts (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      source_id TEXT NOT NULL,
      agent_id TEXT NOT NULL,
      purpose TEXT NOT NULL DEFAULT 'read',
      terms_snapshot TEXT,
      signature TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    -- Contribution Ledger (Pixel: aggregated usage per source per agent)
    CREATE TABLE IF NOT EXISTS contributions (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      source_id TEXT NOT NULL,
      agent_id TEXT NOT NULL,
      access_count INTEGER DEFAULT 0,
      amount REAL DEFAULT 0.0,
      currency TEXT DEFAULT 'usd',
      updated_at TEXT NOT NULL DEFAULT (datetime('now')),
      UNIQUE(tenant_id, source_id, agent_id)
    );

    -- Settlements (Pixel: Merkle-committed payment records)
    CREATE TABLE IF NOT EXISTS settlements (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      period_start TEXT NOT NULL,
      period_end TEXT NOT NULL,
      total_amount REAL DEFAULT 0.0,
      line_items TEXT NOT NULL DEFAULT '[]',
      merkle_root TEXT,
      signature TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    -- Indexes
    CREATE INDEX IF NOT EXISTS idx_evals_tenant ON policy_evaluations(tenant_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_evals_agent ON policy_evaluations(tenant_id, agent_id);
    CREATE INDEX IF NOT EXISTS idx_receipts_tenant ON receipts(tenant_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_delegations_tenant ON delegations(tenant_id, status);
    -- B5 (Consilium): index the delegation-graph lookups the authz path and the backfill run.
    CREATE INDEX IF NOT EXISTS idx_delegations_parent ON delegations(tenant_id, status, parent_agent_id);
    CREATE INDEX IF NOT EXISTS idx_delegations_child ON delegations(tenant_id, status, child_agent_id);
    CREATE INDEX IF NOT EXISTS idx_usage_tenant ON usage(tenant_id, period);
    -- B5 (Consilium): versioned migration ledger. A migration is gated on its complete-status row
    -- here, written in the SAME transaction as its data change, so a crash mid-migration re-runs.
    CREATE TABLE IF NOT EXISTS schema_migrations (
      id TEXT PRIMARY KEY,
      status TEXT NOT NULL,
      applied_at TEXT
    );
    -- Consilium policy: root designation is an explicit, audited admin action, never self-service at
    -- POST /agents. Every designation writes a row here (who designated, when, which agent/tenant).
    -- R3-1 (round-2 Consilium): re_root + reason record the deliberate re-rooting of an agent that has
    -- a delegation history (ever a child). Designating such an agent is the audited override that lets
    -- it originate despite the DEAD path; it requires an explicit re_root:true and a reason, both stored
    -- here for the audit trail.
    -- R4-1 (round-3 Consilium): this table is the ONE coherent designation history per agent. The action
    -- column discriminates 'designation' (an admin act via POST /root-designations) from 'auto_demotion'
    -- (an automatic, audited demotion when a designated root RECEIVES an inbound delegation and thereby
    -- becomes subordinate). An auto_demotion row carries caused_by_delegation_id (the delegation that
    -- subordinated the root) and designated_by = the grantor who caused it. Demotion is not silent
    -- (silent clearing was rejected: any grantor could then destroy an admin's designation); it is
    -- recorded, and restoration is the existing audited POST /root-designations (re_root:true + reason).
    CREATE TABLE IF NOT EXISTS root_designations (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      agent_id TEXT NOT NULL,
      designated_by TEXT NOT NULL,
      designated_at TEXT NOT NULL,
      re_root INTEGER NOT NULL DEFAULT 0,
      reason TEXT,
      action TEXT NOT NULL DEFAULT 'designation',
      caused_by_delegation_id TEXT,
      revoked_at TEXT
    );
    -- B3 (Consilium): bilateral interaction receipts. A row is stored only after BOTH the requesting
    -- and serving signatures are checked against BOTH agents' REGISTERED keys (via the SDK
    -- verifyBilateralReceipt primitive). status is 'attested' (both sides valid) or
    -- 'partial_attestation' (exactly one valid side, e.g. a dumb Web2 sink that cannot countersign).
    -- A forged/mismatched present signature is rejected at the route and never reaches this table.
    CREATE TABLE IF NOT EXISTS bilateral_receipts (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      receipt_id TEXT NOT NULL,
      requesting_agent_id TEXT NOT NULL,
      serving_agent_id TEXT NOT NULL,
      delegation_id TEXT,
      status TEXT NOT NULL,
      requesting_sig_valid INTEGER NOT NULL,
      serving_sig_valid INTEGER NOT NULL,
      outcome_consistent INTEGER NOT NULL,
      timing_valid INTEGER NOT NULL,
      payload TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      -- B3 panel F1: a receipt_id is stored at most once per tenant. receipt_id is inside the signed
      -- body (verifyBilateralReceipt strips only the signature fields), so it cannot be altered without
      -- breaking a signature; a replay of the same signed receipt hits this and is rejected 409.
      UNIQUE (tenant_id, receipt_id)
    );
    CREATE INDEX IF NOT EXISTS idx_bilateral_receipts_tenant ON bilateral_receipts(tenant_id, created_at);
    -- B3 F1 (re-verification): the table-level UNIQUE above is applied only when the table is CREATED.
    -- On a DB that already has bilateral_receipts (created before the constraint), CREATE TABLE IF NOT
    -- EXISTS is a no-op and the constraint is silently absent, reopening the concurrent-replay backstop.
    -- A CREATE UNIQUE INDEX IF NOT EXISTS DOES apply to an existing table, so the replay backstop holds
    -- on fresh and upgraded DBs alike (it fails loudly only if pre-existing duplicate rows exist).
    CREATE UNIQUE INDEX IF NOT EXISTS uq_bilateral_receipts_tenant_receipt ON bilateral_receipts(tenant_id, receipt_id);
    CREATE INDEX IF NOT EXISTS idx_alerts_tenant ON alerts(tenant_id, acknowledged_at);
    CREATE INDEX IF NOT EXISTS idx_data_sources_tenant ON data_sources(tenant_id, status);
    CREATE INDEX IF NOT EXISTS idx_access_receipts_tenant ON access_receipts(tenant_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_access_receipts_source ON access_receipts(tenant_id, source_id);
    CREATE INDEX IF NOT EXISTS idx_contributions_tenant ON contributions(tenant_id);
    CREATE INDEX IF NOT EXISTS idx_settlements_tenant ON settlements(tenant_id, period_start);

    -- Derivations (Pixel: agent declares "I used these sources to produce this output")
    CREATE TABLE IF NOT EXISTS derivations (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      agent_id TEXT NOT NULL,
      source_ids TEXT NOT NULL DEFAULT '[]',
      output_description TEXT,
      output_url TEXT,
      access_receipt_ids TEXT NOT NULL DEFAULT '[]',
      signature TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_derivations_tenant ON derivations(tenant_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_derivations_agent ON derivations(tenant_id, agent_id);

    -- Payment Transactions (Nano adapter + future rails)
    CREATE TABLE IF NOT EXISTS payment_transactions (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      settlement_id TEXT REFERENCES settlements(id),
      rail TEXT NOT NULL DEFAULT 'nano',
      direction TEXT NOT NULL,
      amount REAL NOT NULL,
      currency TEXT NOT NULL DEFAULT 'XNO',
      destination TEXT,
      tx_proof TEXT,
      status TEXT NOT NULL DEFAULT 'pending',
      invoice_data TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      confirmed_at TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_payments_tenant ON payment_transactions(tenant_id, status);
    CREATE INDEX IF NOT EXISTS idx_payments_settlement ON payment_transactions(settlement_id);
    CREATE INDEX IF NOT EXISTS idx_payments_rail ON payment_transactions(rail, status);

    -- Agent Wallets (Nano address per agent, delegation-gated)
    CREATE TABLE IF NOT EXISTS agent_wallets (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      agent_id TEXT NOT NULL,
      nano_address TEXT NOT NULL,
      wallet_index INTEGER NOT NULL,
      status TEXT NOT NULL DEFAULT 'active',
      balance_raw TEXT NOT NULL DEFAULT '0',
      total_received_raw TEXT NOT NULL DEFAULT '0',
      total_sent_raw TEXT NOT NULL DEFAULT '0',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      UNIQUE(tenant_id, agent_id)
    );

    CREATE INDEX IF NOT EXISTS idx_agent_wallets_tenant ON agent_wallets(tenant_id, status);

    -- Wallet Transactions (every send/receive/denied, linked to delegations)
    CREATE TABLE IF NOT EXISTS wallet_transactions (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      from_agent_id TEXT NOT NULL,
      to_agent_id TEXT,
      to_address TEXT NOT NULL,
      amount_raw TEXT NOT NULL,
      amount_xno TEXT NOT NULL,
      block_hash TEXT,
      delegation_id TEXT,
      scope_used TEXT,
      evaluation_id TEXT,
      status TEXT NOT NULL DEFAULT 'pending',
      denial_reason TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      confirmed_at TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_wallet_tx_tenant ON wallet_transactions(tenant_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_wallet_tx_agent ON wallet_transactions(tenant_id, from_agent_id);
    CREATE INDEX IF NOT EXISTS idx_wallet_tx_status ON wallet_transactions(tenant_id, status);

    -- Issuance Dossiers (attestation evidence per passport)
    CREATE TABLE IF NOT EXISTS issuance_dossiers (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      passport_id TEXT NOT NULL,
      public_key_hash TEXT NOT NULL,
      passport_grade INTEGER NOT NULL DEFAULT 0,
      flags TEXT NOT NULL DEFAULT '[]',
      attestation_bundle_hash TEXT,
      observed_context TEXT NOT NULL DEFAULT '{}',
      runtime_attestations TEXT NOT NULL DEFAULT '[]',
      provider_attestations TEXT NOT NULL DEFAULT '[]',
      self_declared_signals TEXT NOT NULL DEFAULT '[]',
      derived_signals TEXT NOT NULL DEFAULT '[]',
      prior_passport_ref TEXT,
      transport_type TEXT,
      issuance_velocity INTEGER,
      connection_timing_ms INTEGER,
      request_payload_fingerprint TEXT,
      cluster_risk TEXT DEFAULT 'unknown',
      cluster_id TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      UNIQUE(tenant_id, passport_id)
    );

    CREATE INDEX IF NOT EXISTS idx_dossiers_tenant ON issuance_dossiers(tenant_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_dossiers_pubkey ON issuance_dossiers(public_key_hash);
    CREATE INDEX IF NOT EXISTS idx_dossiers_grade ON issuance_dossiers(tenant_id, passport_grade);

    -- MCP Stats Snapshots (persistent counters across Railway restarts)
    CREATE TABLE IF NOT EXISTS mcp_stats_snapshots (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      session_id TEXT NOT NULL,
      snapshot_at TEXT NOT NULL,
      uptime_seconds REAL NOT NULL DEFAULT 0,
      passports_issued INTEGER DEFAULT 0,
      sessions_total INTEGER DEFAULT 0,
      sessions_active INTEGER DEFAULT 0,
      tool_calls_total INTEGER DEFAULT 0,
      evaluations_total INTEGER DEFAULT 0,
      delegations_created INTEGER DEFAULT 0,
      receipts_stored INTEGER DEFAULT 0,
      version TEXT,
      tenant_id TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_mcp_stats_session ON mcp_stats_snapshots(session_id, snapshot_at);
    CREATE INDEX IF NOT EXISTS idx_mcp_stats_time ON mcp_stats_snapshots(snapshot_at);

    -- Key Rotations (identity continuity enforcement)
    CREATE TABLE IF NOT EXISTS key_rotations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      tenant_id TEXT NOT NULL,
      agent_id TEXT NOT NULL,
      old_key TEXT NOT NULL,
      new_key TEXT NOT NULL,
      mode TEXT NOT NULL CHECK(mode IN ('planned', 'emergency')),
      announced_at TEXT NOT NULL,
      activation_time TEXT NOT NULL,
      state TEXT NOT NULL CHECK(state IN ('announced', 'revocation_in_progress', 'revocation_complete', 'activated')),
      completed_at TEXT,
      rotation_signature TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_rotations_agent ON key_rotations(tenant_id, agent_id);

    -- Evaluation Receipts (auto-minted from every policy evaluation)
    CREATE TABLE IF NOT EXISTS evaluation_receipts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      tenant_id TEXT NOT NULL,
      agent_id TEXT NOT NULL,
      evaluation_id TEXT,
      event_type TEXT NOT NULL CHECK(event_type IN ('authorization_permit', 'authorization_deny')),
      decision_stage TEXT NOT NULL DEFAULT 'gateway_authorization',
      action_type TEXT,
      scope_requested_json TEXT,
      verdict TEXT NOT NULL CHECK(verdict IN ('permit', 'deny')),
      reason_code TEXT,
      delegation_id TEXT,
      policy_hash TEXT,
      schema_version TEXT NOT NULL DEFAULT '1.0.0',
      receipt_hash TEXT,
      gateway_signature TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_eval_receipts_agent ON evaluation_receipts(tenant_id, agent_id);
    CREATE INDEX IF NOT EXISTS idx_eval_receipts_deny ON evaluation_receipts(verdict) WHERE verdict = 'deny';

    -- Posture Events (audit trail for agent status transitions)
    CREATE TABLE IF NOT EXISTS posture_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      tenant_id TEXT NOT NULL,
      agent_id TEXT NOT NULL,
      old_status TEXT NOT NULL,
      new_status TEXT NOT NULL,
      restricted_scopes TEXT,
      reason TEXT NOT NULL,
      changed_by TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_posture_events_agent ON posture_events(agent_id);

    -- Receipt Window Seals (Merkle-committed batches of evaluation receipts)
    CREATE TABLE IF NOT EXISTS receipt_window_seals (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      seal_id TEXT NOT NULL UNIQUE,
      seq_start INTEGER NOT NULL,
      seq_end INTEGER NOT NULL,
      receipt_count INTEGER NOT NULL,
      permit_count INTEGER DEFAULT 0,
      deny_count INTEGER DEFAULT 0,
      commitment_hash TEXT NOT NULL,
      leaf_schema TEXT DEFAULT 'gateway_receipt_v1',
      scope_note TEXT DEFAULT 'gateway-issued evaluation receipts only',
      gateway_signature TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now'))
    );

    -- Risk Queue (G-A3): prioritized operator inbox of actions a human
    -- should act on, derived from gateway-observed events. Modeled on the
    -- alerts table (resolved_at mirrors acknowledged_at). A row here surfaces
    -- a decision for a human; it does not record that an action was taken.
    CREATE TABLE IF NOT EXISTS risk_queue (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      kind TEXT NOT NULL,
      severity TEXT NOT NULL DEFAULT 'medium',
      priority INTEGER NOT NULL DEFAULT 0,
      agent_id TEXT,
      subject TEXT,
      summary TEXT NOT NULL,
      detail TEXT NOT NULL DEFAULT '{}',
      source_event_id TEXT,
      resolved_at TEXT,
      resolved_action TEXT,
      resolution_receipt TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_risk_queue_open
      ON risk_queue(tenant_id, resolved_at, priority);
  `)

  db.exec(`
    -- Recovery Policies (one per agent, consulted on denial)
    CREATE TABLE IF NOT EXISTS recovery_policies (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      agent_id TEXT NOT NULL,
      policy_json TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now')),
      UNIQUE(tenant_id, agent_id)
    );

    CREATE INDEX IF NOT EXISTS idx_recovery_policies_agent ON recovery_policies(tenant_id, agent_id);

    -- Recovery Events (audit trail for recovery actions)
    CREATE TABLE IF NOT EXISTS recovery_events (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      agent_id TEXT NOT NULL,
      delegation_id TEXT,
      evaluation_id TEXT,
      failure_type TEXT NOT NULL,
      strategy_applied TEXT NOT NULL,
      attempt_number INTEGER NOT NULL,
      recovery_succeeded INTEGER,
      timestamp TEXT DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_recovery_events_agent ON recovery_events(tenant_id, agent_id);

    -- Agent Sessions (crash-recovery checkpoint — Primitive #3)
    CREATE TABLE IF NOT EXISTS agent_sessions (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      agent_id TEXT NOT NULL,
      session_data TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now')),
      expires_at TEXT,
      UNIQUE(tenant_id, agent_id)
    );

    CREATE INDEX IF NOT EXISTS idx_sessions_agent ON agent_sessions(tenant_id, agent_id);

    -- Behavioral Memory Objects (BMO — Bring Your Own Memory)
    CREATE TABLE IF NOT EXISTS behavioral_memory_objects (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      principal_id TEXT NOT NULL,
      issuer_id TEXT NOT NULL,
      pattern_category TEXT NOT NULL,
      pattern_description TEXT NOT NULL,
      confidence REAL NOT NULL DEFAULT 0.5,
      observation_count INTEGER NOT NULL DEFAULT 1,
      observation_window_start TEXT NOT NULL,
      observation_window_end TEXT NOT NULL,
      derivation_source TEXT NOT NULL,
      retention_ttl INTEGER,
      expires_at TEXT,
      relational_entities TEXT NOT NULL DEFAULT '[]',
      portable INTEGER NOT NULL DEFAULT 0,
      issuer_signature TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_bmo_principal ON behavioral_memory_objects(tenant_id, principal_id);
    CREATE INDEX IF NOT EXISTS idx_bmo_issuer ON behavioral_memory_objects(tenant_id, issuer_id);
    CREATE INDEX IF NOT EXISTS idx_bmo_expires ON behavioral_memory_objects(expires_at);

    -- Coordination (Nate Primitive #4: Workflow State)
    CREATE TABLE IF NOT EXISTS tasks (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      title TEXT NOT NULL,
      description TEXT,
      status TEXT NOT NULL DEFAULT 'draft',
      created_by TEXT NOT NULL,
      assigned_to TEXT,
      scope TEXT,
      acceptance_criteria TEXT,
      deliverable TEXT,
      evidence TEXT,
      review_verdict TEXT,
      review_notes TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now')),
      completed_at TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_tasks_tenant ON tasks(tenant_id, status);
    CREATE INDEX IF NOT EXISTS idx_tasks_agent ON tasks(tenant_id, assigned_to);

    CREATE TABLE IF NOT EXISTS task_events (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      task_id TEXT NOT NULL REFERENCES tasks(id),
      event_type TEXT NOT NULL,
      agent_id TEXT,
      data TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_task_events ON task_events(tenant_id, task_id);
  `)

  // Add columns (idempotent via try/catch)
  try { db.exec(`ALTER TABLE evaluation_receipts ADD COLUMN seal_id TEXT`) } catch {}

  // Add posture columns to agents table (idempotent via try/catch)
  try { db.exec(`ALTER TABLE agents ADD COLUMN restricted_scopes TEXT`) } catch {}
  try { db.exec(`ALTER TABLE agents ADD COLUMN posture_reason TEXT`) } catch {}
  try { db.exec(`ALTER TABLE agents ADD COLUMN posture_updated_at TEXT`) } catch {}
  try { db.exec(`ALTER TABLE agents ADD COLUMN agent_type TEXT DEFAULT 'general'`) } catch {}
  try { db.exec(`ALTER TABLE receipt_window_seals ADD COLUMN tenant_id TEXT`) } catch {}
  try { db.exec(`ALTER TABLE policy_evaluations ADD COLUMN task_class TEXT DEFAULT ''`) } catch {}
  try { db.exec(`ALTER TABLE agents ADD COLUMN entity_id TEXT DEFAULT NULL`) } catch {}
  try { db.exec(`ALTER TABLE agents ADD COLUMN entity_verification_endpoint TEXT DEFAULT NULL`) } catch {}
  // Round-3: track the real chain depth so a delegation chain cannot grow past max_depth.
  try { db.exec(`ALTER TABLE delegations ADD COLUMN current_depth INTEGER NOT NULL DEFAULT 0`) } catch {}
  // C1 (Day 217): bind every sub-delegation to the exact inbound delegation row that authorized and
  // bounded it. NULL means an origination grant (the grantor held no inbound delegation). A narrowing
  // grant stores the id of the specific parent delegation row selected at grant time -- not
  // re-resolved later -- so authority is always evaluated over that BOUND chain via
  // checkBoundAuthorityChain (src/gateway/enforce.ts), and revocation anywhere on the chain (including
  // an ancestor's agent posture) invalidates every descendant bound to it without rewriting any row.
  // Legacy rows predate this column and read NULL; per the D-20260921-DAY217-GW-C1-REPRO handoff this is
  // treated as origination and is safe only because two aggregate checks (max active chain depth 1, zero
  // orphan-state rows) show every active row today is a true origination -- rerun both immediately before
  // any deploy that reads this column, and do NOT backfill from current_depth (DEFAULT 0 since its own
  // migration, so pre-migration rows read 0 regardless of real depth).
  try { db.exec(`ALTER TABLE delegations ADD COLUMN parent_delegation_id TEXT`) } catch {}
  try { db.exec(`CREATE INDEX IF NOT EXISTS idx_delegations_tenant_parent_deleg ON delegations(tenant_id, parent_delegation_id)`) } catch {}
  try { db.exec(`ALTER TABLE agents ADD COLUMN metadata TEXT DEFAULT NULL`) } catch {}
  // R3-1: re-root audit fields on an existing root_designations table (additive, idempotent).
  try { db.exec(`ALTER TABLE root_designations ADD COLUMN re_root INTEGER NOT NULL DEFAULT 0`) } catch {}
  try { db.exec(`ALTER TABLE root_designations ADD COLUMN reason TEXT`) } catch {}
  // R4-1: audited auto-demotion fields (additive, idempotent).
  try { db.exec(`ALTER TABLE root_designations ADD COLUMN action TEXT NOT NULL DEFAULT 'designation'`) } catch {}
  try { db.exec(`ALTER TABLE root_designations ADD COLUMN caused_by_delegation_id TEXT`) } catch {}

  // Audit item 3 (HIGH money): designated root grantors. Only is_root=1 agents may grant a
  // delegation with no inbound delegation; without this any no-inbound agent could be named a
  // fresh-budget root and reset an exhausted child's spend. The ALTER succeeds exactly ONCE (when
  // the column is first added to an existing DB), and only then do we run the ONE-TIME backfill
  // that promotes the agents already acting as de-facto roots. On a fresh DB the column exists from
  // CREATE TABLE, the ALTER throws, and the backfill is skipped (no data to backfill).
  // B1/B5: ensure the is_root column (idempotent ALTER), then run the origin backfill
  // TRANSACTIONALLY, gated on a schema_migrations marker (not on column presence) so a crash between
  // the ALTER and the backfill commit re-runs correctly on the next boot. Runs at initDB, i.e. before
  // the server calls app.listen() (server.ts), so it completes before any traffic is accepted.
  try { db.exec(`ALTER TABLE agents ADD COLUMN is_root INTEGER NOT NULL DEFAULT 0`) } catch {}
  runIsRootOriginBackfill(db)

  // Audit item 5 (HIGH replay): durable capability-token nullifier set. A consumed token preimage
  // must survive restarts and be shared across processes; the reference MCP store is per-process.
  // Backed here so a co-located MCP injects the DB-backed SqliteNullifierStore (src/capabilityToken/
  // nullifier-store.ts) behind the existing NullifierStore interface.
  try {
    db.exec(`CREATE TABLE IF NOT EXISTS capability_nullifiers (
      nullifier  TEXT PRIMARY KEY,
      expires_at TEXT,
      created_at TEXT NOT NULL
    )`)
  } catch {}

  // API key class. Separates a tenant administration credential from the
  // runtime keys agents and integrations use.
  // key_class = 'runtime'      → every key minted before this column existed,
  //                              and every key minted by signup, GitHub
  //                              OAuth, rotate/regenerate and default login
  // key_class = 'tenant_admin' → minted only by POST /auth/email/login with
  //                              key_class=tenant_admin (password required),
  //                              so a runtime key can never mint one.
  // Not the platform-operator role: that is tenants.role (below).
  try { db.exec(`ALTER TABLE api_keys ADD COLUMN key_class TEXT NOT NULL DEFAULT 'runtime'`) } catch {}

  // Security triage 2026-04-11 fix 1: tenant role column.
  // Decouples admin authorization from the `plan` billing concept.
  // role = 'admin'  → platform operator (can access /api/v1/admin/* routes)
  // role = 'user'   → regular tenant (default)
  // The operator tenant is elevated to 'admin' by the idempotent UPDATE
  // below, keyed on GATEWAY_OPERATOR_EMAIL and GATEWAY_OPERATOR_EMAIL_ALIASES.
  // Neither has a default, so a fresh deployment elevates nobody until the
  // operator explicitly configures their own login email.
  try { db.exec(`ALTER TABLE tenants ADD COLUMN role TEXT NOT NULL DEFAULT 'user'`) } catch {}
  {
    const { email: operatorEmail, aliases: operatorAliases } = operatorEmailConfig()
    const elevateEmails = operatorEmail ? [operatorEmail, ...operatorAliases] : []
    if (elevateEmails.length === 0) {
      console.log('[migration] GATEWAY_OPERATOR_EMAIL not set, skipping operator role elevation')
    } else {
      try {
        const placeholders = elevateEmails.map(() => '?').join(', ')
        db.prepare(`UPDATE tenants SET role = 'admin'
                    WHERE email IN (${placeholders})
                      AND role != 'admin'`).run(...elevateEmails)
      } catch {}
    }
  }

  db.exec(`CREATE TABLE IF NOT EXISTS stripe_events (event_id TEXT PRIMARY KEY, processed_at TEXT DEFAULT (datetime('now')))`)

  // ═══════════════════════════════════════
  // G-D4 (onboarding / D2 isolation): per-tenant isolation switch.
  //
  // isolation_mode is the D2 settled decision surfaced on the existing
  // tenant model (build directive 9: extend, do not fork the tenant store).
  //   'hard'     → regulated tenant. NO cross-tenant path. Cross-tenant
  //                signal contribution and consumption are both blocked,
  //                regardless of opt-in. This is the default-safe value
  //                for a freshly onboarded regulated tenant.
  //   'standard' → tenant MAY contribute to / consume de-identified,
  //                aggregated, opt-in, above-k-floor cross-tenant signal.
  //
  // The column default is 'hard' so a tenant created before opting in is
  // isolated by default (D2 isolation-by-default). Opt-in is a separate,
  // explicit flag (cohort_opt_in) so that switching to 'standard' does not
  // by itself enrol the tenant in the cohort.
  // ═══════════════════════════════════════
  try { db.exec(`ALTER TABLE tenants ADD COLUMN isolation_mode TEXT NOT NULL DEFAULT 'hard'`) } catch {}
  try { db.exec(`ALTER TABLE tenants ADD COLUMN cohort_opt_in INTEGER NOT NULL DEFAULT 0`) } catch {}
  // Customer-brings-own trust root: where the tenant signing key lives.
  //   'gateway' → gateway-generated, DB-stored Ed25519 key (today's default).
  //   'hsm'     → customer HSM-resident key, bound via the W2-B1 seam.
  //   'kms'     → customer KMS-resident key, bound via the W2-B1 seam.
  // key_ref is an opaque reference (HSM slot URI / KMS key ARN), NEVER the
  // private key material itself. Hash-and-pointer discipline applies here too.
  try { db.exec(`ALTER TABLE tenants ADD COLUMN trust_root_source TEXT NOT NULL DEFAULT 'gateway'`) } catch {}
  try { db.exec(`ALTER TABLE tenants ADD COLUMN trust_root_key_ref TEXT`) } catch {}
  // air_gapped marks a tenant whose deployment has no outbound network path.
  // Cross-tenant emission is structurally impossible for an air-gapped tenant
  // (there is nowhere to emit to); we still record the flag so onboarding and
  // export bundling can branch on it.
  try { db.exec(`ALTER TABLE tenants ADD COLUMN air_gapped INTEGER NOT NULL DEFAULT 0`) } catch {}

  // DB-layer guard: isolation_mode must be one of the two settled values.
  // Defence in depth alongside the application-layer resolver.
  try {
    db.exec(`
      CREATE TRIGGER IF NOT EXISTS check_tenants_isolation_insert
        BEFORE INSERT ON tenants
        FOR EACH ROW
        WHEN NEW.isolation_mode NOT IN ('hard', 'standard')
        BEGIN SELECT RAISE(ABORT, 'invalid isolation_mode (allowed: hard, standard)'); END;
      CREATE TRIGGER IF NOT EXISTS check_tenants_isolation_update
        BEFORE UPDATE OF isolation_mode ON tenants
        FOR EACH ROW
        WHEN NEW.isolation_mode NOT IN ('hard', 'standard')
        BEGIN SELECT RAISE(ABORT, 'invalid isolation_mode (allowed: hard, standard)'); END;
    `)
  } catch (e: any) {
    console.error('[migration] isolation-trigger install failed:', e?.message || e)
  }

  // Cohort emission ledger. The k-floor that holds OVER TIME-SERIES (C3)
  // cannot be enforced from a single snapshot: an attacker who watches two
  // emissions where the cohort shrank from {A,B,C} to {A,B} learns C's
  // contribution by differencing, even though each snapshot independently
  // cleared k. To gate against that we persist the membership digest of
  // every emitted cohort window keyed by (cohort_key, emission_seq) and the
  // gate compares the new window against the prior emitted window for the
  // same cohort_key. member_digest is a hash of the SORTED set of
  // tenant-id hashes (never raw tenant ids), so the ledger itself stores no
  // tenant identity. metric_key namespaces independent time-series.
  db.exec(`
    CREATE TABLE IF NOT EXISTS cohort_emissions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      cohort_key TEXT NOT NULL,
      metric_key TEXT NOT NULL,
      emission_seq INTEGER NOT NULL,
      k_observed INTEGER NOT NULL,
      member_digest TEXT NOT NULL,
      member_count INTEGER NOT NULL,
      emitted_at TEXT NOT NULL DEFAULT (datetime('now')),
      UNIQUE(cohort_key, metric_key, emission_seq)
    );
    CREATE INDEX IF NOT EXISTS idx_cohort_emissions_key
      ON cohort_emissions(cohort_key, metric_key, emission_seq);

    -- Onboarding lifecycle ledger: append-only record of deployment-hardening
    -- and isolation-switch events per tenant. Hash-and-pointer: stores event
    -- type + an opaque detail pointer, never PHI or raw payloads.
    CREATE TABLE IF NOT EXISTS onboarding_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      event_type TEXT NOT NULL,
      detail_pointer TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_onboarding_events_tenant
      ON onboarding_events(tenant_id, created_at);
  `)

  // H4 (audit 2026-05-12): Enum-shaped columns (tenants.plan, tenants.status)
  // were not constrained at the DB layer. A typo in a Stripe webhook
  // metadata field or a future endpoint that skips validation could write
  // "Pro" / "PRO" / "gold" / "" — all of which silently disable plan-limit
  // enforcement via PLAN_LIMITS[unknownKey] → undefined → || PLAN_LIMITS.free.
  // The validation now lives in two places:
  //   1. App layer: Stripe webhook + billing/checkout already validate against an allowlist.
  //   2. DB layer (defence in depth): BEFORE INSERT/UPDATE triggers below.
  // SQLite trigger names are scoped per-database; CREATE TRIGGER IF NOT
  // EXISTS makes this idempotent across restarts.
  try {
    db.exec(`
      CREATE TRIGGER IF NOT EXISTS check_tenants_plan_insert
        BEFORE INSERT ON tenants
        FOR EACH ROW
        WHEN NEW.plan NOT IN ('free', 'pro', 'enterprise')
        BEGIN SELECT RAISE(ABORT, 'invalid plan value (allowed: free, pro, enterprise)'); END;
      CREATE TRIGGER IF NOT EXISTS check_tenants_plan_update
        BEFORE UPDATE OF plan ON tenants
        FOR EACH ROW
        WHEN NEW.plan NOT IN ('free', 'pro', 'enterprise')
        BEGIN SELECT RAISE(ABORT, 'invalid plan value (allowed: free, pro, enterprise)'); END;
      CREATE TRIGGER IF NOT EXISTS check_tenants_status_insert
        BEFORE INSERT ON tenants
        FOR EACH ROW
        WHEN NEW.status NOT IN ('active', 'suspended', 'deleted')
        BEGIN SELECT RAISE(ABORT, 'invalid status value (allowed: active, suspended, deleted)'); END;
      CREATE TRIGGER IF NOT EXISTS check_tenants_status_update
        BEFORE UPDATE OF status ON tenants
        FOR EACH ROW
        WHEN NEW.status NOT IN ('active', 'suspended', 'deleted')
        BEGIN SELECT RAISE(ABORT, 'invalid status value (allowed: active, suspended, deleted)'); END;
    `)
  } catch (e: any) {
    console.error('[migration] enum-trigger install failed:', e?.message || e)
  }

  // R3-2 (round-2 Consilium): pin agents.status to its value domain at the DB layer, the same
  // BEFORE INSERT/UPDATE trigger pattern used for tenants above. The authz path branches on literal
  // status values (active / restricted / suspended / revoked / frozen); an out-of-domain value written
  // by a typo or a validation-skipping path would be mis-read. The legitimate set is every value the
  // code writes: 'active' (register default, thaw restore), 'restricted' + 'suspended' (posture route),
  // 'revoked' (revoke cascade, panic zero_authority), 'frozen' (panic read_only). Additive and
  // idempotent (CREATE TRIGGER IF NOT EXISTS); safe on the existing agents table.
  // R4-3 CROSS-POINT: this enum MUST stay in sync with the app-level status writers. Adding or removing
  // a status value requires updating BOTH this trigger AND every write site: the posture route enum in
  // src/gateway/enforce.ts (the ['active','restricted','suspended'] validation), the panic-freeze paths
  // in src/gateway/revocation/freeze.ts ('revoked' | 'frozen' | 'active'), and the /revoke cascade
  // ('revoked'). A live volume must also have NO pre-existing out-of-domain rows before this trigger can
  // be trusted (an existing bad row would abort its next legitimate UPDATE); see the runbook invariant.
  try {
    db.exec(`
      CREATE TRIGGER IF NOT EXISTS check_agents_status_insert
        BEFORE INSERT ON agents
        FOR EACH ROW
        WHEN NEW.status NOT IN ('active', 'restricted', 'suspended', 'revoked', 'frozen')
        BEGIN SELECT RAISE(ABORT, 'invalid agent status value (allowed: active, restricted, suspended, revoked, frozen)'); END;
      CREATE TRIGGER IF NOT EXISTS check_agents_status_update
        BEFORE UPDATE OF status ON agents
        FOR EACH ROW
        WHEN NEW.status NOT IN ('active', 'restricted', 'suspended', 'revoked', 'frozen')
        BEGIN SELECT RAISE(ABORT, 'invalid agent status value (allowed: active, restricted, suspended, revoked, frozen)'); END;
    `)
  } catch (e: any) {
    console.error('[migration] agents-status-trigger install failed:', e?.message || e)
  }

  // ═══════════════════════════════════════
  // C4 (audit 2026-05-12): Money-as-REAL is unsafe. SQLite stores REAL as
  // IEEE 754 double; cents arithmetic on doubles drifts under repeated
  // additions (the classic 0.1 + 0.2 ≠ 0.3 problem). Settlement math
  // belongs on INTEGER cents.
  //
  // This migration is ADDITIVE ONLY. We add *_cents INTEGER columns
  // alongside the existing REAL columns and dual-write through the
  // moneyDual() helper (src/lib/money.ts). Reads still come from the
  // REAL column. A later phase will:
  //   1. Backfill *_cents from REAL once dual-write has run for a billing cycle.
  //   2. Verify drift is bounded.
  //   3. Cut reads over to *_cents.
  //   4. Drop the REAL columns.
  // Splitting in two phases means: no risk of partial-write corruption
  // mid-rollout; no downtime; and the old code path still works on
  // databases that haven't received the new column yet.
  // ═══════════════════════════════════════
  // Scope: USD-denominated columns only. payment_transactions.amount is
  // rail-native (XNO for Nano, future rails may differ) — its REAL value is
  // a unit conversion problem, not a cents problem, and gets its own future
  // migration once we add an explicit `currency` cents column per rail.
  try { db.exec(`ALTER TABLE delegations ADD COLUMN spend_limit_cents INTEGER`) } catch {}
  try { db.exec(`ALTER TABLE delegations ADD COLUMN spend_used_cents INTEGER DEFAULT 0`) } catch {}
  try { db.exec(`ALTER TABLE contributions ADD COLUMN amount_cents INTEGER DEFAULT 0`) } catch {}
  try { db.exec(`ALTER TABLE settlements ADD COLUMN total_amount_cents INTEGER DEFAULT 0`) } catch {}

  // ═══════════════════════════════════════
  // Email/password authentication (2026-05-11)
  //
  // password_hash is nullable: existing tenants created via GitHub OAuth
  // or via email-only signup do not have one. They authenticate via
  // existing API keys or GitHub OAuth until they opt into password auth
  // via the forgot-password flow.
  //
  // email_verified is a soft signal — does not gate login. Useful for
  // future-proofing sensitive ops (e.g. plan upgrades).
  // ═══════════════════════════════════════
  try { db.exec(`ALTER TABLE tenants ADD COLUMN password_hash TEXT`) } catch {}
  try { db.exec(`ALTER TABLE tenants ADD COLUMN password_set_at TEXT`) } catch {}
  try { db.exec(`ALTER TABLE tenants ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0`) } catch {}
  try { db.exec(`ALTER TABLE tenants ADD COLUMN email_verified_at TEXT`) } catch {}

  // ═══════════════════════════════════════
  // Source-based data classification (G-D3, 2026-05-31)
  //
  // Classification of a data source comes from a LABELED SOURCE (a
  // connector emits the label: a Salesforce field, an Epic record type,
  // a connector label), NEVER from gateway payload scanning. We extend
  // the existing data_sources table rather than introducing a parallel
  // sources table, so a single source_id has exactly one classification.
  //
  //   data_class            the class string declared by the source label
  //                         (vocabulary lives behind the W2-classification
  //                         seam in the data-classification module).
  //   class_confidence      'declared' | 'detected' | 'inferred' - how the
  //                         connector arrived at the class. This is a
  //                         source-supplied input, not a verdict.
  //   class_grade           verifier-derived assurance grade (0..3) computed
  //                         from confidence + evidence via the SDK
  //                         classifyEvidenceQuality / evidenceQualityToGrade
  //                         pattern. NOT issuer-set.
  //   class_evidence        JSON describing the labeling evidence
  //                         (connectorId, recordType, fieldRef).
  //   class_source_label    the connector label descriptor as received.
  //   classified_at         when the class was last attached.
  //
  // All nullable: a source registered before classification, or one with
  // no connector label, has no class and is treated as unclassified.
  // ═══════════════════════════════════════
  try { db.exec(`ALTER TABLE data_sources ADD COLUMN data_class TEXT`) } catch {}
  try { db.exec(`ALTER TABLE data_sources ADD COLUMN class_confidence TEXT`) } catch {}
  try { db.exec(`ALTER TABLE data_sources ADD COLUMN class_grade INTEGER`) } catch {}
  try { db.exec(`ALTER TABLE data_sources ADD COLUMN class_evidence TEXT`) } catch {}
  try { db.exec(`ALTER TABLE data_sources ADD COLUMN class_source_label TEXT`) } catch {}
  try { db.exec(`ALTER TABLE data_sources ADD COLUMN classified_at TEXT`) } catch {}

  // Destination registry (G-D3). A destination is a sink an agent may
  // send classified data to. The gateway records the destination's
  // POLICY and its sink-confirmation SUPPORT; it does not perform the
  // confirmation. Enforcement stays at the sink. risk_tier and
  // allowed_data_classes drive the before-the-fact destination-control
  // check, which returns permit/deny without mutating anything.
  db.exec(`
    CREATE TABLE IF NOT EXISTS destinations (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      destination_id TEXT NOT NULL,
      destination_name TEXT NOT NULL,
      placement TEXT NOT NULL DEFAULT 'external',
      allowed_data_classes TEXT NOT NULL DEFAULT '[]',
      allowed_agent_roles TEXT NOT NULL DEFAULT '[]',
      allowed_purposes TEXT NOT NULL DEFAULT '[]',
      storage_policy TEXT NOT NULL DEFAULT '{}',
      training_policy TEXT NOT NULL DEFAULT '{}',
      sink_confirmation_support TEXT NOT NULL DEFAULT 'none',
      risk_tier TEXT NOT NULL DEFAULT 'unknown',
      attestation TEXT,
      status TEXT NOT NULL DEFAULT 'active',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      revoked_at TEXT,
      UNIQUE(tenant_id, destination_id)
    );
  `)
  try { db.exec(`CREATE INDEX IF NOT EXISTS idx_destinations_tenant ON destinations(tenant_id, status)`) } catch {}

  // Password reset and email verification tokens.
  // Store SHA-256(token), never the raw token. Single-use (used_at).
  // Expires after 1 hour (password_reset) or 24 hours (email_verification).
  db.exec(`
    CREATE TABLE IF NOT EXISTS password_reset_tokens (
      token_hash TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      expires_at TEXT NOT NULL,
      used_at TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_password_reset_tenant ON password_reset_tokens(tenant_id);

    CREATE TABLE IF NOT EXISTS email_verification_tokens (
      token_hash TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      expires_at TEXT NOT NULL,
      used_at TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_email_verify_tenant ON email_verification_tokens(tenant_id);

    -- ─────────────────────────────────────
    -- tenant_aliases: many-emails-to-one-tenant mapping.
    -- A tenant's "primary" email lives on tenants.email; additional
    -- addresses through which the tenant should be reachable (GitHub
    -- verified emails, work + personal mailboxes, vanity addresses)
    -- live here. Lookups in GitHub OAuth, /auth/email/login, and
    -- /auth/email/forgot all check this table.
    --
    -- email is the PK and unique across the table — an address can
    -- only resolve to one tenant. Removing the row de-links it.
    -- ─────────────────────────────────────
    CREATE TABLE IF NOT EXISTS tenant_aliases (
      email TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL REFERENCES tenants(id),
      source TEXT NOT NULL DEFAULT 'manual',
      verified INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_tenant_aliases_tenant ON tenant_aliases(tenant_id);
  `)

  // Backfill tenant_aliases from tenants.email so every existing tenant
  // is reachable via its primary email through the alias path. Idempotent
  // via INSERT OR IGNORE on the PK.
  try {
    db.prepare(`INSERT OR IGNORE INTO tenant_aliases (email, tenant_id, source, verified)
                SELECT email, id, 'primary', 1 FROM tenants
                WHERE status = 'active' AND email NOT LIKE 'tombstone-%'`).run()
  } catch (e: any) {
    console.error('[migration] tenant_aliases backfill failed:', e?.message || e)
  }

  // ───────────────────────────────────────
  // Operator identity reconciliation (must run AFTER email_verified columns
  // have been added above — otherwise the UPDATE references columns that
  // do not exist yet and silently fails in the try/catch).
  //
  // Anchored on the only stable signal: role='admin', set by the role
  // elevation migration above (itself gated on GATEWAY_OPERATOR_EMAIL).
  // Anchoring on role rather than a specific email value survives a login
  // provider (e.g. OAuth) creating a fresh tenant under one of the
  // configured alias emails after the operator's primary email has
  // already changed. Re-anchoring on email value in that case can
  // tombstone the wrong row.
  //
  // Idempotent. No-op if GATEWAY_OPERATOR_EMAIL is unset. Note this does
  // not demote a tenant that was already elevated to role='admin' while
  // the variable was set; there is no code path that revokes role='admin'
  // once granted. It only stops advancing that tenant's email and aliases
  // toward whatever GATEWAY_OPERATOR_EMAIL currently says.
  //
  // Goal end-state when GATEWAY_OPERATOR_EMAIL=E and
  // GATEWAY_OPERATOR_EMAIL_ALIASES=A1,A2,... (idempotent):
  //   - role='admin' tenant has email=E, email_verified=1
  //   - any other tenant currently holding E has its data moved into the
  //     admin and its email tombstoned + status='deleted'
  //   - any tenant holding one of A1, A2, ... that is NOT admin has its
  //     data merged into admin + tombstoned + status='deleted'
  //   - E and each alias are seeded as verified tenant_aliases rows on the
  //     admin, so any login surface (email-password, OAuth) that
  //     authenticates one of them resolves to the same tenant
  // ───────────────────────────────────────
  {
    const { email: operatorEmail, aliases: operatorAliases } = operatorEmailConfig()
    if (!operatorEmail) {
      console.log('[migration] GATEWAY_OPERATOR_EMAIL not set, skipping operator identity reconcile')
    } else {
      try {
        const admin = db.prepare(
          `SELECT id, email FROM tenants WHERE role = 'admin' LIMIT 1`
        ).get() as { id?: string; email?: string } | undefined

        if (!admin?.id) {
          console.warn('[migration] reconcile: no admin tenant found, skipping')
        } else {
          // Helper to merge all FK rows from one tenant into another, then
          // tombstone the source.
          const mergeInto = (sourceId: string, destId: string, label: string) => {
            if (sourceId === destId) return
            const tables = db.prepare(
              `SELECT m.name AS table_name
                 FROM sqlite_master m
                WHERE m.type = 'table'
                  AND EXISTS (
                    SELECT 1 FROM pragma_table_info(m.name) p
                    WHERE p.name = 'tenant_id'
                  )
                  AND m.name != 'tenants'`
            ).all() as Array<{ table_name: string }>
            for (const { table_name } of tables) {
              try {
                const r = db.prepare(
                  `UPDATE "${table_name}" SET tenant_id = ? WHERE tenant_id = ?`
                ).run(destId, sourceId)
                if (r.changes > 0) {
                  console.log(`[migration] reconcile/${label}: moved ${r.changes} row(s) in ${table_name} from ${sourceId} -> ${destId}`)
                }
              } catch (e: any) {
                console.error(`[migration] reconcile/${label}: ${table_name} move failed:`, e?.message || e)
              }
            }
            db.prepare(
              `UPDATE tenants SET email = ?, status = 'deleted' WHERE id = ?`
            ).run(`tombstone-${label}-${sourceId.substring(0, 8)}@deleted.local`, sourceId)
          }

          // Step 1: any non-admin tenant currently holding the configured
          // operator email (an imposter installed before reconciliation,
          // or a stray signup). Merge it into the admin, tombstone it.
          const imposters = db.prepare(
            `SELECT id FROM tenants WHERE email = ? AND id != ?`
          ).all(operatorEmail, admin.id) as Array<{ id: string }>
          for (const imp of imposters) {
            mergeInto(imp.id, admin.id, 'operator-imposter')
          }

          // Step 2: any non-admin tenant currently holding one of the
          // configured alias emails. Merge their data into admin.
          for (const alias of operatorAliases) {
            const strays = db.prepare(
              `SELECT id FROM tenants WHERE email = ? AND id != ?`
            ).all(alias, admin.id) as Array<{ id: string }>
            for (const s of strays) {
              mergeInto(s.id, admin.id, 'operator-alias-stray')
            }
          }

          // Step 3: the operator email slot is guaranteed free (or was
          // already on admin). Set the admin's email.
          try {
            db.prepare(
              `UPDATE tenants SET email = ?,
                                  email_verified = 1,
                                  email_verified_at = COALESCE(email_verified_at, datetime('now'))
                WHERE id = ?`
            ).run(operatorEmail, admin.id)
          } catch (e: any) {
            console.error('[migration] reconcile: admin email set failed:', e?.message || e)
          }

          if (admin.email !== operatorEmail) {
            console.log(`[migration] reconcile: admin email was '${admin.email}', now '${operatorEmail}' (tenant_id=${admin.id})`)
          }

          // Seed admin aliases so every configured alias email resolves to
          // the same tenant on every login surface (email-password, GitHub
          // OAuth, forgot-password). Without this, a fresh sign-in through
          // an alias address would re-create the tenant it is meant to
          // resolve to.
          try {
            db.prepare(`INSERT OR IGNORE INTO tenant_aliases (email, tenant_id, source, verified)
                        VALUES (?, ?, 'primary', 1)`).run(operatorEmail, admin.id)
            for (const alias of operatorAliases) {
              db.prepare(`INSERT OR IGNORE INTO tenant_aliases (email, tenant_id, source, verified)
                          VALUES (?, ?, 'alias', 1)`).run(alias, admin.id)
            }
          } catch (e: any) {
            console.error('[migration] admin alias seed failed:', e?.message || e)
          }
        }
      } catch (e: any) {
        console.error('[migration] operator-identity reconcile failed:', e?.message || e)
      }
    }
  }
}

// ═══════════════════════════════════════
// tenant_aliases lookup helper.
// Used by GitHub OAuth callback + /auth/email/* flows. Resolves any
// known email (primary or alias) to the owning tenant. Active-only.
// ═══════════════════════════════════════
export interface TenantAliasResolveResult {
  tenant_id: string
  matched_email: string
  source: string
}

export function resolveTenantByEmail(emailOrAlias: string): TenantAliasResolveResult | null {
  if (!db) return null
  const normalized = emailOrAlias.trim().toLowerCase()
  const row = db.prepare(`
    SELECT a.tenant_id, a.email AS matched_email, a.source
    FROM tenant_aliases a
    JOIN tenants t ON t.id = a.tenant_id
    WHERE a.email = ? AND t.status = 'active'
    LIMIT 1
  `).get(normalized) as { tenant_id: string; matched_email: string; source: string } | undefined
  return row || null
}

/**
 * Add an alias email for an existing tenant. Idempotent via INSERT OR IGNORE.
 * Returns whether a new row was inserted (false if alias already pointed
 * at this OR another tenant — caller should check first if exclusivity matters).
 */
export function addTenantAlias(opts: {
  tenantId: string
  email: string
  source?: string
  verified?: boolean
}): { inserted: boolean } {
  if (!db) return { inserted: false }
  const email = opts.email.trim().toLowerCase()
  const result = db.prepare(`
    INSERT OR IGNORE INTO tenant_aliases (email, tenant_id, source, verified)
    VALUES (?, ?, ?, ?)
  `).run(email, opts.tenantId, opts.source || 'manual', opts.verified ? 1 : 0)
  return { inserted: result.changes > 0 }
}

// ═══════════════════════════════════════
// Plan Limits
// ═══════════════════════════════════════

// C1+C2 (audit 2026-05-12): Production-tier limits previously set to
// 25 / 50,000 disagreed with pricing.html which promised 100 / 500,000.
// We bumped the engineered limits up to match the public commitment.
// Free tier deliberately tight to push paying signups; Enterprise stays
// uncapped and is sold via direct contract.
export const PLAN_LIMITS = {
  free:       { evaluationsPerMonth: 1000,    maxAgents: 3,    complianceReports: false, sla: false },
  pro:        { evaluationsPerMonth: 500000,  maxAgents: 100,  complianceReports: true,  sla: false },
  enterprise: { evaluationsPerMonth: -1,      maxAgents: -1,   complianceReports: true,  sla: true  },
} as const

export type Plan = keyof typeof PLAN_LIMITS
