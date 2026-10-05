// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * AEOESS Gateway — Server Entry Point
 *
 * The revenue product. Hosted enforcement for AI agent governance.
 *
 * Endpoints:
 *   POST /api/v1/evaluate      — policy evaluation (billable)
 *   POST /api/v1/receipt        — store signed receipt
 *   POST /api/v1/revoke         — cascade revocation
 *   POST /api/v1/agents         — register agent
 *   GET  /api/v1/agents         — list agents
 *   POST /api/v1/delegations    — create delegation
 *   GET  /api/v1/delegations    — list delegations
 *   GET  /api/v1/audit          — audit trail
 *   GET  /api/v1/dashboard      — dashboard summary
 *   GET  /api/v1/usage          — usage history
 *   POST /api/v1/alerts/:id/ack — acknowledge alert
 *   POST /api/v1/data-sources   — register data source (Pixel)
 *   GET  /api/v1/data-sources   — list data sources
 *   POST /api/v1/access-receipts — record data access
 *   GET  /api/v1/attribution    — attribution dashboard
 *   POST /api/v1/settlements    — generate settlement
 *   GET  /api/v1/settlements    — list settlements
 *   GET  /api/v1/my-consumption — agent self-service (what did I consume?)
 *   GET  /api/v1/tenant/:tenantId/audit-export — audit log export (jsonl/csv/pdf)
 *   POST /api/v1/pay/nano/invoice    — create Nano payment request
 *   GET  /api/v1/pay/nano/status/:id — check invoice status
 *   POST /api/v1/pay/nano/settle/:id — execute settlement via Nano
 *   GET  /api/v1/pay/nano/balance    — gateway wallet balance
 *   GET  /api/v1/pay/nano/history    — recent Nano transactions
 *   POST /api/v1/pay/nano/verify     — verify on-chain transaction
 *   POST /api/v1/wallets/provision        — create wallet for agent
 *   GET  /api/v1/wallets/:id/balance      — live on-chain balance
 *   POST /api/v1/wallets/send             — delegation-gated send
 *   POST /api/v1/wallets/:id/receive      — pocket pending funds
 *   GET  /api/v1/wallets/:id/txs          — transaction history
 *   POST /api/v1/wallets/:id/freeze       — freeze wallet
 *   POST /api/v1/wallets/:id/unfreeze     — reactivate wallet
 *   GET  /api/v1/wallets                  — list all wallets
 *   GET  /api/v1/wallets/dashboard        — tenant wallet overview
 *   GET  /healthz               — health check
 */

import express from 'express'
import { mkdirSync, existsSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { createHash, randomBytes, randomUUID } from 'node:crypto'

// Ensure DB directory exists (Railway Volumes mount at /data)
const dbPath = process.env.DB_PATH || './gateway.db'
const dbDir = dirname(dbPath)
if (dbDir !== '.' && !existsSync(dbDir)) {
  mkdirSync(dbDir, { recursive: true })
  console.log('Created DB directory:', dbDir)
}
import cors from 'cors'
import helmet from 'helmet'
import { RateLimiterMemory } from 'rate-limiter-flexible'
import { initDB, getDB, PLAN_LIMITS, resolveTenantByEmail, addTenantAlias } from './db/schema.js'
import { lookupByAddress, rebuildFromDb as rebuildWalletReverseIndex } from './gateway/wallet-reverse-index.js'
import { buildAgentTrustProfile, publicizeProfile, type TrustProfile } from './gateway/trust-profile.js'
import { authMiddleware, requireAdmin, createTenant } from './auth/api-keys.js'
import { tenantAdminRouter, rotateRuntimeKeys } from './auth/tenant-admin.js'
import { gatewayRouter } from './gateway/enforce.js'
import { initLineageTables } from './gateway/lineage.js'
import { initGatewayIdentity, getGatewayIdentity, getJwks } from './gateway/identity.js'
import { paymentRouter } from './payment-rails/routes.js'
import { walletRouter } from './payment-rails/wallet-routes.js'
import { rekorRouter, initAnchorTable } from './gateway/rekor.js'
import { finopsRouter } from './gateway/finops.js'
import { CONFORMANCE_SUMMARY, conformanceBadge } from './gateway/conformance-summary.js'
import { eventsRouter, getEventBus } from './gateway/events.js'
import { riskQueueRouter } from './gateway/risk-queue.js'
import { sessionsRouter } from './gateway/sessions.js'
import { billingRouter, handleStripeWebhook } from './billing/stripe.js'
import { coordinationRouter } from './gateway/coordination.js'
import { bmoRouter } from './gateway/bmo.js'
import { providerAttestationRouter } from './gateway/provider-attestation.js'
import { bmoEvidenceRouter } from './gateway/bmo-evidence.js'
import { auditExportRouter } from './gateway/audit-export.js'
// G-C2: pre-flight guards (a), governance automations (b), incident playbooks (c).
import { guardsRouter } from './gateway/guards/router.js'
import { automationsRouter } from './gateway/automations/router.js'
import { playbooksRouter } from './gateway/playbooks/router.js'
import { initPlaybookTables } from './gateway/playbooks/index.js'
import { approvalRouter } from './gateway/approval/index.js'
// G-D1: enforcement modes + policy simulation.
import { simulationRouter, initModeConfigTable, initModeObservationsTable } from './gateway/simulation/index.js'
import { dataClassificationRouter } from './gateway/data-classification/router.js'
import { destinationsRouter } from './gateway/destinations/router.js'
import { tenantIsolationRouter, applyDeploymentIsolationDefault } from './gateway/tenant-isolation/index.js'
import { projectPublicBody, payloadFingerprint } from './gateway/receipt-projection.js'
import { sendEmail, signupWelcomeEmail, weeklyDigestEmail, spendAlertEmail, passwordResetEmail, emailVerificationEmail, passwordChangedEmail } from './notifications/email.js'
import { connectorsRouter, mountInboundIdentityBridge, initConnectorTables } from './notifications/connectors/index.js'
import {
  validatePassword, isValidEmail, normalizeEmail,
  hashPassword, verifyPassword, burnTime,
  findTenantByEmail, setTenantPassword, markEmailVerified,
  issueApiKey, revokeAllApiKeysForTenant,
  createPasswordResetToken, consumePasswordResetToken,
  createEmailVerificationToken, consumeEmailVerificationToken,
} from './auth/email-password.js'

const PORT = parseInt(process.env.PORT || '3200')
const DB_PATH = dbPath

const app = express()
app.set('trust proxy', 1) // Trust first proxy (Railway) for correct req.ip

// Security
// CSP: gateway origin renders no HTML except a 302 redirect from GET /
// (to ${APP_ORIGIN}/portal.html) and JSON for every API endpoint. We can
// therefore lock script/style/connect/img origins tight.
//
// Note: a previous comment in this slot claimed CSP was off because of a
// React-via-Babel landing page. That landing page was removed in bb8607b;
// the comment outlived the code. Re-enabling here.
app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      defaultSrc:    ["'self'"],
      scriptSrc:     ["'self'"],
      styleSrc:      ["'self'"],
      imgSrc:        ["'self'", 'data:'],
      connectSrc:    ["'self'", 'https://aeoess.com'],
      fontSrc:       ["'self'"],
      objectSrc:     ["'none'"],
      frameAncestors:["'none'"],
      baseUri:       ["'self'"],
      formAction:    ["'self'", 'https://aeoess.com'],
      upgradeInsecureRequests: [],
    },
  },
}))
const allowedOrigins = (process.env.ALLOWED_ORIGINS || 'https://aeoess.com,https://gateway.aeoess.com').split(',').map(s => s.trim())
app.use(cors({ origin: (origin, callback) => {
  if (!origin || allowedOrigins.includes(origin)) callback(null, true)
  else callback(null, false)
} }))
// Stripe webhook needs raw body (must be before express.json)
app.post('/api/v1/billing/webhook', express.raw({ type: 'application/json' }), handleStripeWebhook)

// Inbound identity-bridge (Okta / Entra offboard -> revoke) needs the raw body
// for HMAC verification, so it is mounted before express.json like Stripe.
// DARK by default in Stage 1 integration: the inbound IdP bridge stays unmounted
// unless GATEWAY_IDP_BRIDGE_ENABLED is explicitly set to 'true', and no per-tenant
// IdP secret wiring is configured here. This is a Tima-gated surface (G-C1 founder
// gate). The outbound connector adapters (OTel, Slack, Teams, Jira, ServiceNow,
// internal-HTTP) are unaffected and stay active via connectorsRouter.
if (process.env.GATEWAY_IDP_BRIDGE_ENABLED === 'true') {
  mountInboundIdentityBridge(app)
}

app.use(express.json({ limit: '1mb' }))

// ═══════════════════════════════════════
// Gateway is an API host, not a UI. Users hitting the root in a browser
// get redirected to the marketing site's portal where they can sign in
// and reach their dashboard. The 'gateway.aeoess.com/' marketing splash
// (the React-via-Babel design) was an architectural mistake — it pretended
// to be a user surface when it was actually a public aggregate view that
// duplicates dashboard.html. Removed in favour of a clean redirect.
//
// API clients hitting paths under /api/v1/*, /auth/*, /.well-known/* etc.
// still get JSON responses as before — this redirect only fires for GET /.
// ═══════════════════════════════════════
app.get('/', (_req, res) => res.redirect(302, `${APP_ORIGIN}/portal.html`))
app.get('/index.html', (_req, res) => res.redirect(301, `${APP_ORIGIN}/portal.html`))

// Health check (no auth)
app.get('/healthz', (_req, res) => {
  res.json({ status: 'ok', service: 'aeoess-gateway', version: '0.4.0' })
})

app.get('/health', (_req, res) => {
  res.json({ status: 'ok', version: '0.4.0', uptime_seconds: Math.floor(process.uptime()), timestamp: new Date().toISOString() })
})

app.get('/api/v1/status', (_req, res) => {
  let dbWritable = false
  try { getDB().prepare('SELECT 1').get(); dbWritable = true } catch {}
  res.json({
    gateway: 'operational',
    version: '0.4.0',
    uptime_seconds: Math.floor(process.uptime()),
    database: dbWritable ? 'connected' : 'error',
    timestamp: new Date().toISOString(),
    checks: {
      db_writable: dbWritable,
      issuer_key_loaded: !!process.env.AEOESS_ISSUER_PRIVATE_KEY,
    },
  })
})

// ═══════════════════════════════════════
// Receipt Resolution (WG interop, no auth)
// GET /.well-known/receipts/:id
// Cross-system lineage traversal: any WG member can resolve
// a proof reference to its full receipt + signature + JWKS.
// From desiorac on A2A#1672 + MCP#1763.
// ═══════════════════════════════════════
const receiptResolutionLimiter = new RateLimiterMemory({
  points: 120,      // 120 requests
  duration: 60,     // per minute per IP
  keyPrefix: 'receipt_resolve',
})

const receiptResolutionCache = new Map<string, { data: any; expires: number }>()
const RECEIPT_CACHE_TTL = 10 * 60 * 1000 // 10 min (receipts are immutable)

app.get('/.well-known/receipts/:receiptId', async (req, res) => {
  try {
    await receiptResolutionLimiter.consume(req.ip || 'unknown')
  } catch {
    return res.status(429).json({ error: 'Rate limit exceeded. 120 req/min.' })
  }

  const { receiptId } = req.params

  // Cache check (receipts are immutable — long cache is safe)
  const cached = receiptResolutionCache.get(receiptId)
  if (cached && cached.expires > Date.now()) {
    res.setHeader('Cache-Control', 'public, max-age=600')
    return res.json(cached.data)
  }

  const db = getDB()

  // Search across receipt tables — receipts are identified by prefix or universal lookup
  // Tables: receipts (policy), access_receipts (data), derivations (lineage), settlements
  const tables = [
    { table: 'receipts', type: 'policy_receipt', payloadField: 'payload', signatureField: 'signature' },
    { table: 'access_receipts', type: 'access_receipt', payloadField: null, signatureField: 'signature' },
    { table: 'derivations', type: 'derivation_receipt', payloadField: 'derivation_json', signatureField: 'signature' },
    { table: 'settlements', type: 'settlement', payloadField: 'merkle_root', signatureField: 'signature' },
    // G-C3 scoped-approval receipts resolve publicly with the
    // approval_receipt whitelist (no reason text, no approver PII).
    { table: 'approval_receipts', type: 'approval_receipt', payloadField: 'payload', signatureField: 'signature' },
  ]

  for (const { table, type, payloadField, signatureField } of tables) {
    try {
      const row = db.prepare(`SELECT * FROM ${table} WHERE id = ? LIMIT 1`).get(receiptId) as any
      if (row) {
        // Security triage 2026-04-11 fix 2: project the body to a
        // whitelist of public-safe fields per receipt type. Before this
        // fix, the endpoint returned JSON.parse(row[payloadField])
        // verbatim, which meant tenant IDs, delegation details, spend
        // amounts, principal IDs, and any other field the writer had
        // stored would leak to any caller who knew a receipt ID.
        // Receipt IDs leak via logs, shared URLs, screenshots, and
        // response headers on sibling endpoints, so treating the ID as
        // a soft authorization mechanism was not defensible.
        //
        // Relying parties that need the full canonical payload to
        // verify the signature themselves must fetch it through an
        // authenticated endpoint. The public endpoint now returns the
        // safe projection plus a payload_sha256 fingerprint so that a
        // consumer who obtains the full payload elsewhere can confirm
        // it matches what the gateway signed.
        // Reference: CODE-AUDIT-2026-04-11.md §2.9.
        let parsedPayload: any = null
        if (payloadField && row[payloadField]) {
          try { parsedPayload = JSON.parse(row[payloadField]) } catch { parsedPayload = null }
        }

        const body = projectPublicBody(type, row, parsedPayload)
        const payloadSha256 = payloadField && row[payloadField]
          ? payloadFingerprint(typeof row[payloadField] === 'string' ? row[payloadField] : JSON.stringify(row[payloadField]))
          : null

        const result = {
          proofId: `aps:${receiptId}`,
          proofType: type,
          issuer: 'https://gateway.aeoess.com',
          issuedAt: row.created_at,
          signature: row[signatureField] || null,
          body,
          payloadSha256,
          projectionVersion: 'v1',
          jwksUrl: 'https://gateway.aeoess.com/.well-known/jwks.json',
          resolvedAt: new Date().toISOString(),
        }

        receiptResolutionCache.set(receiptId, { data: result, expires: Date.now() + RECEIPT_CACHE_TTL })
        res.setHeader('Cache-Control', 'public, max-age=600')
        return res.json(result)
      }
    } catch {
      // Table might not have the right columns — skip
      continue
    }
  }

  res.status(404).json({
    proofId: `aps:${receiptId}`,
    error: 'Receipt not found',
    hint: 'This endpoint resolves APS receipt IDs. Try the trust profile at /api/v1/public/trust/:agentId for agent lookups.',
    resolvedAt: new Date().toISOString(),
  })
})

// JWKS endpoint — public key for verifying gateway-signed attestations
// Used by insumer-examples multi-attestation verifier, OATR, and any
// relying party that needs to verify APS trust attestation JWS.
app.get('/.well-known/jwks.json', (_req, res) => {
  res.setHeader('Cache-Control', 'public, max-age=3600, stale-if-error=86400')
  res.setHeader('CDN-Cache-Control', 'public, max-age=3600, stale-if-error=86400')
  res.json(getJwks())
})

// Rate limiter for public signup endpoint
const signupLimiter = new RateLimiterMemory({
  points: 5,        // 5 signups
  duration: 3600,   // per hour per IP
  keyPrefix: 'signup',
})

// Public: create tenant (signup)
app.post('/api/v1/signup', async (req, res) => {
  // Rate limit by IP
  try {
    await signupLimiter.consume(req.ip || 'unknown')
  } catch {
    return res.status(429).json({ error: 'Signup rate limit exceeded. Try again later.' })
  }

  const { name, email, plan } = req.body
  if (!name || !email) {
    return res.status(400).json({ error: 'Required: name, email' })
  }
  // Validate plan — only 'free' allowed via self-signup
  // 'pro' and 'enterprise' require manual provisioning
  const validPlan = plan === 'free' || !plan ? 'free' : 'free'
  try {
    const { tenant, apiKey } = createTenant({ name, email, plan: validPlan })
    try { getEventBus().emit(tenant.id, { type: 'tenant_created', data: { plan: tenant.plan, name } }) } catch {}
    res.status(201).json({
      message: 'Account created. Save your API key — it will not be shown again.',
      tenant_id: tenant.id,
      plan: tenant.plan,
      api_key: apiKey,
    })
    // Welcome email (best-effort, never blocks signup)
    try { sendEmail({ ...signupWelcomeEmail(name, email, apiKey), to: email }).catch(() => {}) } catch {}
  } catch (e: any) {
    if (e.message?.includes('UNIQUE')) {
      return res.status(409).json({ error: 'Email already registered' })
    }
    return res.status(500).json({ error: e.message })
  }
})

// ═══════════════════════════════════════
// GitHub OAuth — Sign in / sign up via GitHub
// Tenants identified by their verified primary GitHub email.
// New email → create tenant. Existing email → issue an additional API key.
// Requires GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET env vars.
// ═══════════════════════════════════════
const githubStateStore = new Map<string, number>() // state -> expiresAt
const GITHUB_STATE_TTL_MS = 10 * 60 * 1000

setInterval(() => {
  const now = Date.now()
  for (const [s, exp] of githubStateStore.entries()) {
    if (exp < now) githubStateStore.delete(s)
  }
}, 60_000).unref()

const githubOAuthLimiter = new RateLimiterMemory({
  points: 30,
  duration: 60,
  keyPrefix: 'github_oauth',
})

const APP_ORIGIN = process.env.APP_ORIGIN || 'https://aeoess.com'
const GATEWAY_URL = process.env.GATEWAY_URL || 'https://gateway.aeoess.com'

function githubOAuthConfigured(): boolean {
  return !!(process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET)
}

app.get('/auth/github/start', async (req, res) => {
  if (!githubOAuthConfigured()) {
    return res.status(503).type('html').send(
      `<!doctype html><meta charset="utf-8"><title>GitHub sign-in unavailable</title>` +
      `<body style="font-family:-apple-system,system-ui;background:#1c1c1e;color:#ececec;padding:60px 40px;max-width:600px;margin:0 auto">` +
      `<h1 style="font-weight:500">GitHub sign-in not configured</h1>` +
      `<p style="color:#b0b0b0">The gateway is missing GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET. Use email signup or contact <a href="mailto:signal@aeoess.com" style="color:#7cacde">signal@aeoess.com</a>.</p>` +
      `<p><a href="${APP_ORIGIN}/portal.html" style="color:#7cacde">← Back to portal</a></p></body>`
    )
  }
  try { await githubOAuthLimiter.consume(req.ip || 'unknown') }
  catch { return res.status(429).send('Rate limit exceeded. Try again later.') }

  const state = randomBytes(24).toString('hex')
  githubStateStore.set(state, Date.now() + GITHUB_STATE_TTL_MS)

  const params = new URLSearchParams({
    client_id: process.env.GITHUB_CLIENT_ID!,
    redirect_uri: `${GATEWAY_URL}/auth/github/callback`,
    scope: 'read:user user:email',
    state,
    allow_signup: 'true',
  })
  res.redirect('https://github.com/login/oauth/authorize?' + params.toString())
})

app.get('/auth/github/callback', async (req, res) => {
  function redirectErr(msg: string) {
    return res.redirect(`${APP_ORIGIN}/portal.html?auth_error=${encodeURIComponent(msg)}`)
  }
  if (!githubOAuthConfigured()) return redirectErr('GitHub sign-in not configured')

  const code = typeof req.query.code === 'string' ? req.query.code : ''
  const state = typeof req.query.state === 'string' ? req.query.state : ''
  const ghError = typeof req.query.error === 'string' ? req.query.error : ''

  if (ghError) return redirectErr('GitHub sign-in cancelled')
  if (!code || !state) return redirectErr('Missing code or state from GitHub')

  // CSRF state check
  const stateExp = githubStateStore.get(state)
  if (!stateExp || stateExp < Date.now()) return redirectErr('Sign-in link expired, try again')
  githubStateStore.delete(state)

  // Exchange code for access token
  let accessToken: string
  try {
    const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({
        client_id: process.env.GITHUB_CLIENT_ID,
        client_secret: process.env.GITHUB_CLIENT_SECRET,
        code,
      }),
    })
    const tokenJson = await tokenRes.json() as { access_token?: string; error?: string; error_description?: string }
    if (!tokenJson.access_token) {
      console.error('[github-oauth] token exchange failed', tokenJson.error, tokenJson.error_description)
      return redirectErr('Could not verify with GitHub, try email signup')
    }
    accessToken = tokenJson.access_token
  } catch (e) {
    console.error('[github-oauth] token fetch error', e)
    return redirectErr('GitHub is unreachable, try email signup')
  }

  // Fetch user info + every verified email (not just primary)
  let userLogin: string
  let userName: string | null
  let primaryEmail: string
  let verifiedEmails: string[] = []
  try {
    const [userRes, emailsRes] = await Promise.all([
      fetch('https://api.github.com/user', {
        headers: { Authorization: `token ${accessToken}`, 'User-Agent': 'aeoess-gateway', 'Accept': 'application/vnd.github+json' },
      }),
      fetch('https://api.github.com/user/emails', {
        headers: { Authorization: `token ${accessToken}`, 'User-Agent': 'aeoess-gateway', 'Accept': 'application/vnd.github+json' },
      }),
    ])
    if (!userRes.ok || !emailsRes.ok) {
      console.error('[github-oauth] api errors', userRes.status, emailsRes.status)
      return redirectErr('Could not load your GitHub profile')
    }
    const userInfo = await userRes.json() as { login: string; name: string | null }
    userLogin = userInfo.login
    userName = userInfo.name
    const emails = await emailsRes.json() as Array<{ email: string; primary: boolean; verified: boolean }>
    const primary = emails.find(e => e.primary && e.verified) || emails.find(e => e.verified)
    if (!primary) return redirectErr('Your GitHub email is not verified, verify it on GitHub first')
    primaryEmail = primary.email
    // Keep the primary first in the list so it's preferred on alias-creation.
    verifiedEmails = [primary.email, ...emails.filter(e => e.verified && e.email !== primary.email).map(e => e.email)]
  } catch (e) {
    console.error('[github-oauth] user fetch error', e)
    return redirectErr('Could not load your GitHub profile')
  }

  // Find tenant by ANY verified email (primary or otherwise) through the
  // tenant_aliases table. This is what makes "one account, multiple
  // verified emails" work: a tenant whose primary email differs from its
  // GitHub primary email still resolves to the same row, as long as that
  // GitHub email has been seeded as an alias.
  const db = getDB()
  let resolvedTenantId: string | null = null
  let matchedVia: string | null = null
  for (const candidate of verifiedEmails) {
    const r = resolveTenantByEmail(candidate)
    if (r) { resolvedTenantId = r.tenant_id; matchedVia = candidate; break }
  }

  let apiKey: string
  let tenantId: string
  if (resolvedTenantId) {
    // Existing tenant — issue an additional key without revoking others.
    tenantId = resolvedTenantId
    apiKey = `aps_live_${randomBytes(32).toString('hex')}`
    const keyHash = createHash('sha256').update(apiKey).digest('hex')
    const keyPrefix = apiKey.slice(0, 12)
    db.prepare(`INSERT INTO api_keys (id, tenant_id, key_hash, key_prefix, name) VALUES (?, ?, ?, ?, ?)`)
      .run(randomUUID(), tenantId, keyHash, keyPrefix, 'github-oauth')
    // Backfill: ensure every verified GitHub email we just saw is recorded
    // as an alias on this tenant. addTenantAlias is INSERT OR IGNORE, so it
    // never steals an alias from another tenant — if some other tenant
    // already claims one of these addresses, that alias is left alone.
    for (const em of verifiedEmails) {
      try { addTenantAlias({ tenantId, email: em, source: 'github', verified: true }) } catch {}
    }
    console.log(`[github-oauth] linked existing tenant ${tenantId} via verified email '${matchedVia}' (github login=${userLogin})`)
  } else {
    // New tenant — full signup. We only get here if NONE of the user's
    // verified GitHub emails resolve to any existing tenant.
    try {
      const name = userName || userLogin || primaryEmail.split('@')[0]
      const result = createTenant({ name, email: primaryEmail, plan: 'free' })
      tenantId = result.tenant.id
      apiKey = result.apiKey
      // Backfill aliases for the fresh tenant so future logins via a
      // different verified email still find it.
      for (const em of verifiedEmails) {
        try { addTenantAlias({ tenantId, email: em, source: em === primaryEmail ? 'primary' : 'github', verified: true }) } catch {}
      }
      try { getEventBus().emit(tenantId, { type: 'tenant_created', data: { plan: 'free', source: 'github', github_login: userLogin } }) } catch {}
      try { sendEmail({ ...signupWelcomeEmail(name, primaryEmail, apiKey), to: primaryEmail }).catch(() => {}) } catch {}
      console.log(`[github-oauth] created new tenant ${tenantId} (github login=${userLogin}, primary=${primaryEmail})`)
    } catch (e: any) {
      console.error('[github-oauth] tenant create error', e)
      return redirectErr('Could not create your account, email signal@aeoess.com')
    }
  }

  res.redirect(`${APP_ORIGIN}/dashboard.html#welcome=${encodeURIComponent(apiKey)}`)
})

// ═══════════════════════════════════════
// Email/password authentication
// Composes with existing API-key surface — each successful flow issues
// or re-issues an aps_live_* key. See src/auth/email-password.ts for
// the rationale on enumeration defence and password rules.
// ═══════════════════════════════════════

const emailAuthSignupLimiter = new RateLimiterMemory({
  points: 5,
  duration: 3600,
  keyPrefix: 'email_auth_signup',
})

const emailAuthLoginLimiter = new RateLimiterMemory({
  points: 10,
  duration: 900, // 10 attempts per 15 min per IP
  keyPrefix: 'email_auth_login',
})

const emailAuthForgotLimiter = new RateLimiterMemory({
  points: 5,
  duration: 3600,
  keyPrefix: 'email_auth_forgot',
})

const emailAuthResetLimiter = new RateLimiterMemory({
  points: 10,
  duration: 3600,
  keyPrefix: 'email_auth_reset',
})

// POST /auth/email/signup — create tenant with password
app.post('/auth/email/signup', async (req, res) => {
  try {
    await emailAuthSignupLimiter.consume(req.ip || 'unknown')
  } catch {
    return res.status(429).json({ error: 'Signup rate limit exceeded. Try again later.' })
  }

  const { name, email: rawEmail, password } = req.body || {}
  if (!name || typeof name !== 'string' || !name.trim()) {
    return res.status(400).json({ error: 'Required: name' })
  }
  if (!rawEmail || typeof rawEmail !== 'string' || !isValidEmail(rawEmail)) {
    return res.status(400).json({ error: 'Valid email required' })
  }
  const passwordCheck = validatePassword(password)
  if (!passwordCheck.ok) {
    return res.status(400).json({ error: passwordCheck.reason })
  }

  const email = normalizeEmail(rawEmail)
  const existing = findTenantByEmail(email)
  if (existing) {
    // Match the pre-existing /api/v1/signup behaviour (409 on duplicate).
    // The portal already handles this case with "sign in instead".
    return res.status(409).json({ error: 'Email already registered' })
  }

  let tenantId: string
  let apiKey: string
  try {
    const result = createTenant({ name: name.trim(), email, plan: 'free' })
    tenantId = result.tenant.id
    apiKey = result.apiKey
  } catch (e: any) {
    if (e.message?.includes('UNIQUE')) {
      return res.status(409).json({ error: 'Email already registered' })
    }
    console.error('[email-auth/signup] tenant create error', e)
    return res.status(500).json({ error: 'Could not create account' })
  }

  try {
    const hash = await hashPassword(password)
    setTenantPassword(tenantId, hash)
  } catch (e: any) {
    console.error('[email-auth/signup] password hash error', e)
    // Tenant was created but password failed to store. They can still
    // sign in via the forgot-password flow. Surface 500 so client knows
    // signup did not fully complete.
    return res.status(500).json({ error: 'Account created without password — use Forgot Password to set one' })
  }

  // Emit tenant_created event (matches /api/v1/signup behaviour)
  try { getEventBus().emit(tenantId, { type: 'tenant_created', data: { plan: 'free', source: 'email-password', name } }) } catch {}

  // Send welcome email with API key (matches /api/v1/signup behaviour)
  try { sendEmail({ ...signupWelcomeEmail(name, email, apiKey), to: email }).catch(() => {}) } catch {}

  // Send email verification (best-effort)
  try {
    const verifyToken = createEmailVerificationToken(tenantId)
    const verifyUrl = `${GATEWAY_URL}/auth/email/verify?token=${encodeURIComponent(verifyToken)}`
    sendEmail({ ...emailVerificationEmail(name, email, verifyUrl), to: email }).catch(() => {})
  } catch (e) {
    console.error('[email-auth/signup] verify email send failed', e)
  }

  return res.status(201).json({
    message: 'Account created. Save your API key — it will not be shown again.',
    tenant_id: tenantId,
    plan: 'free',
    api_key: apiKey,
    email_verified: false,
  })
})

// POST /auth/email/login — verify password, issue new runtime API key.
// Never a tenant_admin key: that has its own explicit issuance action,
// POST /auth/tenant-admin/issue (src/auth/tenant-admin.ts).
app.post('/auth/email/login', async (req, res) => {
  try {
    await emailAuthLoginLimiter.consume(req.ip || 'unknown')
  } catch {
    return res.status(429).json({ error: 'Too many login attempts, try again later.' })
  }

  const { email: rawEmail, password } = req.body || {}
  if (!rawEmail || typeof rawEmail !== 'string' || !isValidEmail(rawEmail)) {
    // Don't leak whether the email is valid-format; still burn time.
    await burnTime()
    return res.status(401).json({ error: 'Invalid email or password' })
  }
  if (typeof password !== 'string' || password.length === 0) {
    await burnTime()
    return res.status(401).json({ error: 'Invalid email or password' })
  }

  const email = normalizeEmail(rawEmail)
  const tenant = findTenantByEmail(email)

  // Constant-time on unknown-email path: still run a bcrypt compare so
  // attackers can't distinguish "no such user" from "wrong password" by
  // response timing.
  if (!tenant || !tenant.password_hash) {
    await burnTime()
    return res.status(401).json({ error: 'Invalid email or password' })
  }

  const ok = await verifyPassword(password, tenant.password_hash)
  if (!ok) {
    return res.status(401).json({ error: 'Invalid email or password' })
  }

  if (tenant.status !== 'active') {
    return res.status(403).json({ error: 'Account is not active. Contact signal@aeoess.com' })
  }

  // Issue a fresh API key for this sign-in. Mirrors github-oauth pattern.
  const apiKey = issueApiKey(tenant.id, `email-login-${Date.now()}`)

  return res.status(200).json({
    message: 'Signed in. Save your API key — it will not be shown again.',
    tenant_id: tenant.id,
    plan: tenant.plan,
    api_key: apiKey,
    key_class: 'runtime',
    email_verified: tenant.email_verified === 1,
  })
})

// POST /auth/tenant-admin/issue — explicit tenant_admin key issuance
// (account password required, 15-minute expiry). See src/auth/tenant-admin.ts.
app.use(tenantAdminRouter)

// POST /auth/email/forgot — send password reset link (always 200)
app.post('/auth/email/forgot', async (req, res) => {
  try {
    await emailAuthForgotLimiter.consume(req.ip || 'unknown')
  } catch {
    // Even on rate-limit, return generic 200 to prevent timing/enumeration.
    return res.status(200).json({ message: 'If that email is on file, a reset link has been sent.' })
  }

  const { email: rawEmail } = req.body || {}
  // Generic 200 regardless — never reveals whether the email exists.
  const genericResponse = { message: 'If that email is on file, a reset link has been sent.' }

  if (!rawEmail || typeof rawEmail !== 'string' || !isValidEmail(rawEmail)) {
    return res.status(200).json(genericResponse)
  }

  const email = normalizeEmail(rawEmail)
  const tenant = findTenantByEmail(email)
  if (!tenant) {
    return res.status(200).json(genericResponse)
  }

  try {
    const resetToken = createPasswordResetToken(tenant.id)
    const resetUrl = `${APP_ORIGIN}/portal.html?reset_token=${encodeURIComponent(resetToken)}`
    sendEmail({ ...passwordResetEmail(tenant.name, email, resetUrl), to: email }).catch(() => {})
  } catch (e) {
    console.error('[email-auth/forgot] reset token error', e)
    // Still return 200 to prevent enumeration.
  }

  return res.status(200).json(genericResponse)
})

// POST /auth/email/reset — consume reset token, set new password
app.post('/auth/email/reset', async (req, res) => {
  try {
    await emailAuthResetLimiter.consume(req.ip || 'unknown')
  } catch {
    return res.status(429).json({ error: 'Too many reset attempts, try again later.' })
  }

  const { token, password } = req.body || {}
  if (!token || typeof token !== 'string') {
    return res.status(400).json({ error: 'Reset token required' })
  }
  const passwordCheck = validatePassword(password)
  if (!passwordCheck.ok) {
    return res.status(400).json({ error: passwordCheck.reason })
  }

  const consumed = consumePasswordResetToken(token)
  if (!consumed.ok || !consumed.tenantId) {
    return res.status(400).json({ error: consumed.reason || 'Invalid reset token' })
  }

  try {
    const hash = await hashPassword(password)
    setTenantPassword(consumed.tenantId, hash)
  } catch (e: any) {
    console.error('[email-auth/reset] hash error', e)
    return res.status(500).json({ error: 'Could not update password, try again' })
  }

  // Defence-in-depth: revoke ALL existing keys. User signs in fresh.
  const revokedCount = revokeAllApiKeysForTenant(consumed.tenantId)

  // Notify the user that the password changed (best-effort).
  try {
    const db = getDB()
    const row = db.prepare(`SELECT name, email FROM tenants WHERE id = ?`).get(consumed.tenantId) as any
    if (row?.email) {
      sendEmail({ ...passwordChangedEmail(row.name || row.email, row.email), to: row.email }).catch(() => {})
    }
  } catch (e) {
    console.error('[email-auth/reset] notify email failed', e)
  }

  return res.status(200).json({
    message: 'Password updated. Sign in to issue a new API key.',
    api_keys_revoked: revokedCount,
  })
})

// GET /auth/email/verify?token=... — mark email_verified=1
app.get('/auth/email/verify', async (req, res) => {
  const token = typeof req.query.token === 'string' ? req.query.token : ''
  if (!token) {
    return res.redirect(`${APP_ORIGIN}/portal.html?verify_error=${encodeURIComponent('Missing verification token')}`)
  }

  const consumed = consumeEmailVerificationToken(token)
  if (!consumed.ok || !consumed.tenantId) {
    return res.redirect(`${APP_ORIGIN}/portal.html?verify_error=${encodeURIComponent(consumed.reason || 'Invalid verification link')}`)
  }

  try {
    markEmailVerified(consumed.tenantId)
  } catch (e) {
    console.error('[email-auth/verify] mark verified error', e)
  }

  res.redirect(`${APP_ORIGIN}/portal.html?verify_ok=1`)
})

// ═══════════════════════════════════════
// Public landing-page data (no auth required)
//
// Powers the gateway.aeoess.com/ landing page metrics + decisions feed.
// Returns aggregate counts only — never individual tenant/agent IDs
// (privacy + competitive-intel leak). Cached for 30s to keep the public
// page cheap to render.
// ═══════════════════════════════════════
const publicStatsLimiter = new RateLimiterMemory({
  points: 60, duration: 60, keyPrefix: 'public_stats',
})

let _statsCache: { data: any; expires: number } | null = null
const STATS_CACHE_TTL_MS = 30 * 1000

app.get('/api/v1/public/stats', async (req, res) => {
  try { await publicStatsLimiter.consume(req.ip || 'unknown') }
  catch { return res.status(429).json({ error: 'Rate limit exceeded. 60 req/min.' }) }

  const now = Date.now()
  if (_statsCache && _statsCache.expires > now) {
    return res.json(_statsCache.data)
  }

  try {
    const db = getDB()
    // Aggregate over all tenants. Exclude soft-deleted tenants and
    // tombstoned rows so the public number reflects real operator usage.
    const activeTenants = db.prepare(
      `SELECT COUNT(*) as n FROM tenants WHERE status = 'active'`
    ).get() as { n: number }

    const evals24h = db.prepare(`
      SELECT COUNT(*) as total,
             SUM(CASE WHEN verdict = 'deny' THEN 1 ELSE 0 END) as denies,
             AVG(duration_ms) as avg_ms,
             MAX(duration_ms) as max_ms
      FROM policy_evaluations
      WHERE created_at >= datetime('now', '-24 hours')
    `).get() as { total: number; denies: number; avg_ms: number | null; max_ms: number | null }

    // P50 approximation: median duration_ms from a sampled window.
    // SQLite has no native PERCENTILE, so we approximate via ORDER BY OFFSET.
    const sampleSize = Math.min(evals24h.total, 10000)
    let p50ms: number | null = null
    if (sampleSize > 0) {
      const row = db.prepare(`
        SELECT duration_ms FROM (
          SELECT duration_ms FROM policy_evaluations
          WHERE created_at >= datetime('now', '-24 hours') AND duration_ms IS NOT NULL
          ORDER BY duration_ms ASC LIMIT ?
        ) ORDER BY duration_ms ASC LIMIT 1 OFFSET ?
      `).get(sampleSize, Math.floor(sampleSize / 2)) as { duration_ms: number } | undefined
      p50ms = row?.duration_ms ?? null
    }

    // Receipts as additional accountability surface count.
    const receipts24h = db.prepare(`
      SELECT COUNT(*) as n FROM receipts
      WHERE created_at >= datetime('now', '-24 hours')
    `).get() as { n: number }

    const agentsTotal = db.prepare(
      `SELECT COUNT(*) as n FROM agents WHERE status = 'active'`
    ).get() as { n: number }

    const denyRate = evals24h.total > 0
      ? evals24h.denies / evals24h.total
      : 0

    const data = {
      evals_24h: evals24h.total,
      denies_24h: evals24h.denies,
      deny_rate: Number(denyRate.toFixed(4)),
      p50_latency_ms: p50ms,
      avg_latency_ms: evals24h.avg_ms != null ? Number(evals24h.avg_ms.toFixed(2)) : null,
      max_latency_ms: evals24h.max_ms,
      receipts_24h: receipts24h.n,
      active_agents: agentsTotal.n,
      active_tenants: activeTenants.n,
      generated_at: new Date().toISOString(),
    }
    _statsCache = { data, expires: now + STATS_CACHE_TTL_MS }
    res.json(data)
  } catch (e: any) {
    console.error('[public/stats] error:', e?.message || e)
    res.status(500).json({ error: 'stats unavailable' })
  }
})

const publicDecisionsLimiter = new RateLimiterMemory({
  points: 60, duration: 60, keyPrefix: 'public_decisions',
})

app.get('/api/v1/public/recent-decisions', async (req, res) => {
  try { await publicDecisionsLimiter.consume(req.ip || 'unknown') }
  catch { return res.status(429).json({ error: 'Rate limit exceeded. 60 req/min.' }) }

  try {
    const db = getDB()
    // Anonymized recent decisions: hash the agent_id to a short stable
    // pseudonym (no rainbow back to the real agent_id). No tenant_id is
    // ever exposed. action_target is truncated to its scope prefix to
    // avoid leaking endpoint URLs or merchant names.
    const rows = db.prepare(`
      SELECT id, agent_id, action_type, scope_required, verdict, reason, duration_ms, created_at
      FROM policy_evaluations
      ORDER BY created_at DESC LIMIT 20
    `).all() as Array<any>

    // Stable pseudonym: 6-hex prefix of sha256(agent_id || tenant_id_unknown).
    // Same agent always renders the same pseudonym in one snapshot.
    const decisions = rows.map(r => {
      const h = createHash('sha256').update(String(r.agent_id)).digest('hex').substring(0, 6)
      return {
        ts: r.created_at,
        decision: r.verdict,
        scope: r.scope_required,
        action_type: r.action_type,
        pseudonym: `agt:${h}`,
        duration_ms: r.duration_ms,
      }
    })
    res.json({ decisions, count: decisions.length })
  } catch (e: any) {
    console.error('[public/recent-decisions] error:', e?.message || e)
    res.status(500).json({ error: 'recent decisions unavailable' })
  }
})

// ═══════════════════════════════════════
// Public conformance status.
//
// The APS conformance suite at github.com/aeoess/aps-conformance-suite ships
// fixture vectors across several categories (see CONFORMANCE_SUMMARY below for
// the current per-category tally). The gateway's runtime canonicalization +
// signature paths are tested against the same vectors in CI. This endpoint
// exposes the current pass count so the dashboard can read it without scraping
// GitHub.
//
// The numbers are sourced from a single hand-edited constant — when the
// fixture set grows, bump the constant; CI ensures the code actually
// satisfies the vectors before any of this becomes meaningful.
// ═══════════════════════════════════════
const publicConformanceLimiter = new RateLimiterMemory({
  points: 60, duration: 60, keyPrefix: 'public_conformance',
})

// Single source of truth for the public conformance surface lives in
// ./gateway/conformance-summary.js. Both the JSON endpoint and the shields
// badge derive from the same CONFORMANCE_SUMMARY object; there is no second
// hardcoded copy. Re-exported here for existing importers of server.ts.
export { CONFORMANCE_SUMMARY, conformanceBadge } from './gateway/conformance-summary.js'

app.get('/api/v1/public/conformance', async (req, res) => {
  try { await publicConformanceLimiter.consume(req.ip || 'unknown') }
  catch { return res.status(429).json({ error: 'Rate limit exceeded.' }) }
  res.json(CONFORMANCE_SUMMARY)
})

app.get('/api/v1/public/conformance/badge', async (req, res) => {
  try { await publicConformanceLimiter.consume(req.ip || 'unknown') }
  catch { return res.status(429).json({ error: 'Rate limit exceeded.' }) }
  res.json(conformanceBadge())
})

// ═══════════════════════════════════════
// Compliance coverage (authenticated, per-tenant view).
//
// Reports which regulatory frameworks the calling tenant's plan unlocks
// + which AEOESS primitives map to each framework. The mapping is static
// because the underlying alignment (governance block primitives → regs)
// is a design decision, not per-tenant data. Per-tenant info that DOES
// appear: which capabilities are unlocked by your plan tier.
// ═══════════════════════════════════════
app.get('/api/v1/compliance/coverage', authMiddleware, (req: any, res) => {
  const tenant = req.tenant
  const plan = String(tenant.plan || 'free')
  // The framework-to-primitive map is identical for every tenant; the
  // gating bit is whether their plan tier unlocks the compliance-report
  // download. That bit is encoded in PLAN_LIMITS.complianceReports.
  const enterpriseReports = plan === 'enterprise'
  const proOrHigher = plan === 'pro' || plan === 'enterprise'

  res.json({
    plan,
    compliance_reports_available: enterpriseReports,
    frameworks: [
      {
        id: 'eu_ai_act',
        name: 'EU AI Act',
        coverage_pct: 88,
        status: proOrHigher ? 'covered' : 'limited',
        primitives_covered: [
          'cascade_revocation', 'signed_evaluation_receipts', 'audit_trail',
          'governance_block', 'instruction_provenance', 'rights_propagation',
        ],
        gaps: ['fundamental_rights_impact_assessment_template'],
      },
      {
        id: 'nist_ai_rmf',
        name: 'NIST AI RMF',
        coverage_pct: 92,
        status: 'covered',
        primitives_covered: [
          'measure-1.1 (evaluation_receipts)', 'measure-2.7 (audit_trail)',
          'manage-3.1 (cascade_revocation)', 'govern-1.5 (governance_block)',
          'map-3.4 (instruction_provenance)',
        ],
        gaps: ['quantitative_bias_metrics_export'],
      },
      {
        id: 'iso_42001',
        name: 'ISO/IEC 42001',
        coverage_pct: 81,
        status: proOrHigher ? 'covered' : 'limited',
        primitives_covered: [
          'A.6.2 (rights_propagation)', 'A.7.4 (audit_trail)',
          'A.8.3 (signed_evaluation_receipts)', 'A.9.2 (cascade_revocation)',
        ],
        gaps: ['supplier_relationship_documentation'],
      },
      {
        id: 'sr_11_7',
        name: 'SR 11-7 (Fed)',
        coverage_pct: 76,
        status: enterpriseReports ? 'covered' : 'enterprise-only',
        primitives_covered: [
          'model_inventory (agents)', 'effective_challenge (cascade_revocation)',
          'use_appropriateness (governance_block)', 'ongoing_monitoring (live_decisions)',
        ],
        gaps: ['independent_validation_attestations'],
      },
    ],
  })
})

// ═══════════════════════════════════════
// Integrations status (authenticated).
//
// Returns the on/off state of each integration we ship — Stripe Issuing
// payment rail, Mycelium TrailRecord (Base anchoring), Asqav (RFC 3161 +
// OpenTimestamps). The tenant's integration state is derived from the
// data we already have (tenants.stripe_customer_id, payment_rail rows,
// etc.); we do not maintain a separate per-integration table yet.
// ═══════════════════════════════════════
app.get('/api/v1/integrations/status', authMiddleware, (req: any, res) => {
  const tenant = req.tenant
  const db = getDB()
  const tenantRow = db.prepare(`SELECT stripe_customer_id FROM tenants WHERE id = ?`).get(tenant.id) as any
  const stripeConnected = !!tenantRow?.stripe_customer_id

  res.json({
    integrations: [
      {
        id: 'stripe_issuing',
        name: 'Stripe Issuing',
        description: 'Spend gates + signed PaymentReceipt on every agent-initiated charge.',
        connected: stripeConnected,
        connect_url: stripeConnected ? null : 'mailto:signal@aeoess.com?subject=Connect%20Stripe%20Issuing',
        category: 'payment_rail',
        availability: 'pro+',
      },
      {
        id: 'mycelium_trails',
        name: 'Mycelium TrailRecord',
        description: 'Base mainnet anchoring of the PaymentReceipt. Anchoring queued; first block not yet published.',
        connected: false,
        connect_url: 'https://github.com/aeoess/agent-passport-system/pull/24',
        category: 'anchoring',
        availability: 'all',
      },
      {
        id: 'asqav_timestamp',
        name: 'Asqav protectmcp',
        description: 'RFC 3161 timestamp + OpenTimestamps anchoring of evaluation receipts.',
        connected: true,
        connect_url: null,
        category: 'anchoring',
        availability: 'all',
      },
      {
        id: 'mcp_server',
        name: 'Agent Passport MCP',
        description: 'Connect Claude Desktop / Cursor / VS Code to the gateway via MCP. See the Connect section.',
        connected: true,
        connect_url: null,
        category: 'runtime',
        availability: 'all',
      },
    ],
  })
})

// ═══════════════════════════════════════
// Public Trust Profile (no auth required)
// Cross-org trust querying: any sandbox, registry, or agent
// can check an agent's grade before interaction.
// From 0xbrainkid on NVIDIA/OpenShell#682.
// ═══════════════════════════════════════
const publicTrustLimiter = new RateLimiterMemory({
  points: 60,       // 60 requests
  duration: 60,     // per minute per IP
  keyPrefix: 'public_trust',
})

const trustProfileCache = new Map<string, { data: any; expires: number }>()
const TRUST_CACHE_TTL = 5 * 60 * 1000 // 5 min

/**
 * Context Continuity Score (0-100)
 * Measures behavioral consistency for an agent. Higher = more consistent.
 * Three dimensions: activity regularity, behavioral consistency, identity maturity.
 * Context break detected when activity gap + behavioral shift co-occur.
 */
function computeContinuityScore(db: any, tenantId: string, agentId: string, ageDays: number) {
  // Fetch last 50 evaluation timestamps and verdicts
  const evals = db.prepare(
    `SELECT created_at, verdict FROM policy_evaluations
     WHERE tenant_id = ? AND agent_id = ?
     ORDER BY created_at DESC LIMIT 50`
  ).all(tenantId, agentId) as { created_at: string, verdict: string }[]

  if (evals.length < 2) {
    return { score: ageDays > 7 ? 30 : 10, context_break: false, signals: ['insufficient_data'] }
  }

  // 1. Activity Regularity (0-40): std dev of time gaps between evals
  const timestamps = evals.map(e => new Date(e.created_at).getTime()).reverse()
  const gaps: number[] = []
  for (let i = 1; i < timestamps.length; i++) {
    gaps.push(timestamps[i] - timestamps[i - 1])
  }
  const meanGap = gaps.reduce((a, b) => a + b, 0) / gaps.length
  const variance = gaps.reduce((a, g) => a + Math.pow(g - meanGap, 2), 0) / gaps.length
  const stdDev = Math.sqrt(variance)
  const cv = meanGap > 0 ? stdDev / meanGap : 0 // coefficient of variation
  // cv < 0.5 = very regular, cv > 2 = erratic
  const activityScore = Math.round(Math.max(0, Math.min(40, 40 * (1 - Math.min(cv, 2) / 2))))

  // 2. Behavioral Consistency (0-30): recent denial rate vs historical
  const totalDenials = evals.filter(e => e.verdict === 'deny').length
  const historicalDenialRate = totalDenials / evals.length
  const recentEvals = evals.slice(0, Math.min(10, evals.length))
  const recentDenials = recentEvals.filter(e => e.verdict === 'deny').length
  const recentDenialRate = recentDenials / recentEvals.length
  const denialDrift = Math.abs(recentDenialRate - historicalDenialRate)
  // drift < 0.1 = consistent, drift > 0.3 = behavioral shift
  const behaviorScore = Math.round(Math.max(0, Math.min(30, 30 * (1 - Math.min(denialDrift, 0.5) / 0.5))))

  // 3. Identity Maturity (0-30): age + evaluation volume
  const ageScore = Math.min(15, ageDays)  // max 15 from age
  const volumeScore = Math.min(15, Math.round(evals.length / 50 * 15)) // max 15 from volume
  const maturityScore = ageScore + volumeScore

  const score = activityScore + behaviorScore + maturityScore

  // Context break detection: large gap + behavioral shift
  const signals: string[] = []
  const maxGap = Math.max(...gaps)
  const maxGapHours = maxGap / (1000 * 60 * 60)
  let contextBreak = false

  if (maxGapHours > 24) signals.push('activity_gap_' + Math.round(maxGapHours) + 'h')
  if (denialDrift > 0.2) signals.push('denial_drift_' + Math.round(denialDrift * 100) + 'pct')
  if (cv > 1.5) signals.push('erratic_timing')
  if (maxGapHours > 24 && denialDrift > 0.15) {
    contextBreak = true
    signals.push('context_break')
  }

  return { score: Math.max(0, Math.min(100, score)), context_break: contextBreak, signals }
}

// Recursive canonical JSON stringifier — sorted object keys, arrays preserved.
// Used to hash delegation chains deterministically for delegation_chain_hash.
function canonicalJsonStringify(v: unknown): string {
  if (v === null || typeof v !== 'object') return JSON.stringify(v)
  if (Array.isArray(v)) return '[' + v.map(canonicalJsonStringify).join(',') + ']'
  const keys = Object.keys(v as Record<string, unknown>).sort()
  return '{' + keys.map(k =>
    JSON.stringify(k) + ':' + canonicalJsonStringify((v as Record<string, unknown>)[k])
  ).join(',') + '}'
}

// Resolve the delegation chain root→current for an agent, then SHA-256
// the canonicalized array. Returns lowercase hex. Empty chain → hash of "[]".
function computeDelegationChainHash(
  db: import('better-sqlite3').Database,
  tenantId: string,
  agentId: string,
): string {
  const chain: Array<{ parent: string; child: string; scope: string; spend_limit: number | null }> = []
  let currentChild: string | null = agentId
  const seen = new Set<string>()
  // Walk root-ward: at each step the row where this agent is the child.
  while (currentChild && !seen.has(currentChild)) {
    seen.add(currentChild)
    const row = db.prepare(
      `SELECT parent_agent_id, child_agent_id, scope, spend_limit FROM delegations
       WHERE tenant_id = ? AND child_agent_id = ? AND status = 'active'
       ORDER BY created_at DESC LIMIT 1`
    ).get(tenantId, currentChild) as
      | { parent_agent_id: string; child_agent_id: string; scope: string; spend_limit: number | null }
      | undefined
    if (!row) break
    chain.push({
      parent: row.parent_agent_id,
      child: row.child_agent_id,
      scope: row.scope,
      spend_limit: row.spend_limit,
    })
    currentChild = row.parent_agent_id
  }
  chain.reverse() // root → current
  return createHash('sha256').update(canonicalJsonStringify(chain)).digest('hex')
}

// Sign the public trust profile with the gateway's Ed25519 key and attach
// the compact JWS as a response header. Body is unchanged, so callers that
// don't care about the signature see no difference. Verifiers fetch the
// JWKS at /.well-known/jwks.json, read X-APS-JWS, verify with the kid
// advertised there (gateway-v1). Also exposes the kid on X-APS-JWS-KID
// for easy discovery by clients that want to short-circuit to a specific
// key without parsing the JWS header.
function attachTrustProfileJws(res: express.Response, profile: Record<string, unknown>): void {
  try {
    const identity = getGatewayIdentity()
    const jws = identity.sign(profile)
    res.setHeader('X-APS-JWS', jws)
    res.setHeader('X-APS-JWS-KID', identity.kid)
    res.setHeader('X-APS-JWS-JWKS', 'https://gateway.aeoess.com/.well-known/jwks.json')
  } catch {
    // Signing failure must not break the response. Ed25519 signing is
    // effectively infallible once the identity is loaded, but a missing
    // identity (identity not initialized) should degrade gracefully
    // rather than 500 the entire endpoint.
  }
}

app.get('/api/v1/public/trust/:agentId', async (req, res) => {
  // Rate limit
  try {
    await publicTrustLimiter.consume(req.ip || 'unknown')
  } catch {
    return res.status(429).json({ error: 'Rate limit exceeded. 60 req/min.' })
  }

  let { agentId } = req.params

  // Wallet resolution: ?wallet=nano_...&chain=nano
  const walletParam = req.query.wallet as string | undefined
  const chainParam = (req.query.chain as string) || 'nano'

  if (walletParam) {
    const wdb = getDB()
    const walletRow = wdb.prepare(
      `SELECT agent_id FROM agent_wallets WHERE nano_address = ? AND status = 'active' LIMIT 1`
    ).get(walletParam) as any
    if (!walletRow) {
      return res.json({ found: false, wallet: walletParam, chain: chainParam, reason: 'no_agent_mapping' })
    }
    agentId = walletRow.agent_id
  }

  // CDN caching
  res.setHeader('Cache-Control', 'public, max-age=60, stale-while-revalidate=300, stale-if-error=600')
  res.setHeader('CDN-Cache-Control', 'public, max-age=60, stale-while-revalidate=300, stale-if-error=600')

  const cached = trustProfileCache.get(agentId)
  if (cached && cached.expires > Date.now() && !req.query.signal && !walletParam) {
    attachTrustProfileJws(res, cached.data)
    return res.json(cached.data)
  }

  const db = getDB()

  // Search across ALL tenants — warn on ambiguity
  const allMatches = db.prepare(
    `SELECT * FROM agents WHERE agent_id = ? AND status = 'active' ORDER BY created_at ASC`
  ).all(agentId) as any[]
  const agent = allMatches[0]
  if (allMatches.length > 1) {
    res.setHeader('X-APS-Warning', `Ambiguous: ${allMatches.length} tenants have agent "${agentId}". Showing oldest.`)
  }

  // Path-form fall-through for SkyeProfile and similar wallet-first
  // orchestrators: if :agentId looks like an EVM address and no agent
  // matches, try the wallet → agent reverse index. Promised to
  // douglasborthwick-crypto on insumer-examples#1.
  let resolvedAgent: any = agent
  let matchedWalletEntryForFallthrough: { chain: string; address: string; bound_at: string; binding_sig: string } | undefined
  if (!resolvedAgent && /^0x[a-fA-F0-9]{40}$/.test(agentId)) {
    const hit = lookupByAddress(agentId)
    if (hit) {
      const fetched = db.prepare(
        `SELECT * FROM agents WHERE tenant_id = ? AND agent_id = ? AND status = 'active' LIMIT 1`
      ).get(hit.tenant_id, hit.agent_id) as any
      if (fetched) {
        resolvedAgent = fetched
        agentId = hit.agent_id
        matchedWalletEntryForFallthrough = hit.entry
      }
    }
  }

  if (!resolvedAgent) {
    if (req.query.signal === 'governance_attestation') {
      return res.status(404).json({
        error: 'Agent not found',
        agent_id: agentId,
        hint: 'governance_attestation can only be issued for registered agents.',
      })
    }
    const notFound = { agent_id: agentId, grade: 0, grade_label: 'unknown', found: false, queried_at: new Date().toISOString() }
    return res.json(notFound)
  }

  const tenantId = resolvedAgent.tenant_id

  const profile: TrustProfile = buildAgentTrustProfile({
    db,
    agent: resolvedAgent,
    agentId,
    walletParam,
    chainParam,
    matchedWalletEntry: matchedWalletEntryForFallthrough,
    windowDays: parseInt(req.query.window_days as string) || parseInt(process.env.TRUST_WINDOW_DEFAULT || '0'),
    computeContinuityScore,
  })
  const grade = profile._grade_for_signal!
  const delegation = profile._delegation_for_signal

  // Optional: enrich with RNWY behavioral trust signal
  if (process.env.RNWY_TRUST_ENABLED === 'true') {
    try {
      // RNWY uses numeric IDs — check if agent has rnwy_id in metadata
      const rnwyMeta = db.prepare(`SELECT metadata FROM agents WHERE tenant_id = ? AND agent_id = ?`).get(tenantId, agentId) as any
      const meta = rnwyMeta?.metadata ? JSON.parse(rnwyMeta.metadata) : {}
      const rnwyId = meta?.rnwy_id
      if (rnwyId) {
        const rnwyRes = await fetch(`https://rnwy.com/api/trust-check?id=${encodeURIComponent(rnwyId)}&chain=base`, {
          signal: AbortSignal.timeout(2000)
        })
        if (rnwyRes.ok) {
          const rnwy = await rnwyRes.json() as any
          ;(profile as any).behavioral_trust = {
            source: 'rnwy',
            score: rnwy.score ?? null,
            tier: rnwy.tier ?? null,
            sybil_severity: rnwy.sybilSeverity ?? null,
            badges: rnwy.badges?.earned ?? [],
            fetched_at: new Date().toISOString(),
          }
        }
      }
    } catch { /* RNWY unavailable — profile still works without it */ }
  }

  // Cache (strip internal _-prefixed fields before storing)
  const publicProfile = publicizeProfile(profile)
  trustProfileCache.set(agentId, { data: publicProfile, expires: Date.now() + TRUST_CACHE_TTL })

  // Signal projection: ?signal=governance_attestation returns a signed
  // governance_attestation envelope per
  // agent-passport-system/specs/governance-attestation-schema.md
  // Default (no param) preserves the existing passport_grade response.
  if (req.query.signal === 'governance_attestation') {
    const evalTs = new Date().toISOString()
    const expTs = new Date(Date.now() + 5 * 60 * 1000).toISOString()
    const chainHash = computeDelegationChainHash(db, tenantId, agentId)
    const activeConstraints = delegation
      ? {
          scopes: delegation.scope ? delegation.scope.split(',').map((s: string) => s.trim()) : [],
          spend_limit: delegation.spend_limit ?? null,
          spend_used: delegation.spend_used ?? 0,
          spend_currency: 'XNO',
        }
      : { scopes: [], spend_limit: null, spend_used: 0, spend_currency: 'XNO' }

    const claim = {
      signal_type: 'governance_attestation' as const,
      iss: 'https://gateway.aeoess.com',
      gateway_id: 'gateway.aeoess.com',
      policy_version: 'floor-v1.2.0',
      attestation_grade: grade,
      evaluation_timestamp: evalTs,
      expires_at: expTs,
      delegation_chain_hash: chainHash,
      active_constraints: activeConstraints,
    }
    const identity = getGatewayIdentity()
    const jws = identity.sign(claim)
    return res.json({
      issuer: 'https://gateway.aeoess.com',
      type: 'governance_attestation',
      kid: identity.kid,
      alg: 'EdDSA',
      jwks: 'https://gateway.aeoess.com/.well-known/jwks.json',
      signed: claim,
      jws,
    })
  }

  attachTrustProfileJws(res, publicProfile)
  res.json(publicProfile)
})

// ──────────────────────────────────────────────────────────────────
// GET /api/v1/public/trust/by-wallet/:address
// ──────────────────────────────────────────────────────────────────
// Wallet → agent reverse lookup. Public, no auth, same rate as the
// agent_id endpoint. Promised to douglasborthwick-crypto on
// insumer-examples#1 for SkyeProfile orchestrator integration.
// ──────────────────────────────────────────────────────────────────
app.get('/api/v1/public/trust/by-wallet/:address', async (req, res) => {
  try {
    await publicTrustLimiter.consume(req.ip || 'unknown')
  } catch {
    return res.status(429).json({ error: 'Rate limit exceeded. 60 req/min.' })
  }

  const rawAddress = (req.params.address || '').trim()

  // Strict 0x address validation. Refuse early before scanning.
  if (!/^0x[a-fA-F0-9]{40}$/.test(rawAddress)) {
    return res.status(400).json({
      error: 'Invalid address format',
      hint: 'Expected 0x followed by 40 hex characters',
    })
  }

  res.setHeader('Cache-Control', 'public, max-age=60, stale-while-revalidate=300, stale-if-error=600')
  res.setHeader('CDN-Cache-Control', 'public, max-age=60, stale-while-revalidate=300, stale-if-error=600')

  const hit = lookupByAddress(rawAddress)
  if (!hit) {
    // Uniform shape regardless of whether the address is unknown or
    // simply not bound. Don't leak existence of agents the caller does
    // not already know about.
    return res.json({
      found: false,
      reason: 'no_wallet_binding',
      queried_address: rawAddress,
      queried_at: new Date().toISOString(),
    })
  }

  const db = getDB()
  const agent = db.prepare(
    `SELECT * FROM agents WHERE tenant_id = ? AND agent_id = ? AND status = 'active' LIMIT 1`
  ).get(hit.tenant_id, hit.agent_id) as any

  if (!agent) {
    // Index pointed at a row that no longer exists. Treat as not bound.
    return res.json({
      found: false,
      reason: 'no_wallet_binding',
      queried_address: rawAddress,
      queried_at: new Date().toISOString(),
    })
  }

  const profile = buildAgentTrustProfile({
    db,
    agent,
    agentId: hit.agent_id,
    matchedWalletEntry: hit.entry,
    windowDays: parseInt(req.query.window_days as string) || parseInt(process.env.TRUST_WINDOW_DEFAULT || '0'),
    computeContinuityScore,
  })

  return res.json(publicizeProfile(profile))
})

// Signed trust attestation — JWS compact format for multi-attestation verifiers
// Returns the same trust profile but Ed25519-signed by the gateway.
// Verifiable via /.well-known/jwks.json
app.get('/api/v1/public/trust/:agentId/attestation', async (req, res) => {
  // Same rate limit as trust profile
  try {
    await publicTrustLimiter.consume(req.ip || 'unknown')
  } catch {
    return res.status(429).json({ error: 'Rate limit exceeded. 60 req/min.' })
  }

  // CDN caching: attestations valid for 60s, serve stale during deploys
  res.setHeader('Cache-Control', 'public, max-age=60, stale-while-revalidate=300, stale-if-error=600')
  res.setHeader('CDN-Cache-Control', 'public, max-age=60, stale-while-revalidate=300, stale-if-error=600')

  const { agentId } = req.params

  // Reuse the trust profile logic — fetch from cache or compute
  const cached = trustProfileCache.get(agentId)
  let profile: any
  if (cached && cached.expires > Date.now()) {
    profile = cached.data
  } else {
    // Profile not cached — consumer should query trust profile first
    return res.status(404).json({
      error: 'Trust profile not cached. Query /api/v1/public/trust/' + agentId + ' first.',
      hint: 'The attestation endpoint signs a cached trust profile. Fetch the profile first, then request the signed attestation.',
    })
  }

  const identity = getGatewayIdentity()
  const jws = identity.sign({
    ...profile,
    iss: 'https://gateway.aeoess.com',
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 300, // 5 min validity
  })

  res.json({
    issuer: 'https://gateway.aeoess.com',
    type: 'passport_grade',
    kid: identity.kid,
    alg: 'EdDSA',
    jwks: 'https://gateway.aeoess.com/.well-known/jwks.json',
    signed: profile,
    jws,
  })
})

// ═══════════════════════════════════════
// Key Rotation Enforcement
// POST /api/v1/key-rotation — register a rotation (authenticated)
// ═══════════════════════════════════════

app.post('/api/v1/key-rotation', authMiddleware, (req: any, res) => {
  try {
    const b = req.body || {}
    const tenantId = req.tenant?.id
    if (!tenantId) return res.status(401).json({ error: 'Authentication required' })

    const required = ['agent_id', 'old_key', 'new_key', 'mode', 'activation_time', 'rotation_signature']
    for (const f of required) {
      if (!b[f]) return res.status(400).json({ error: `${f} required` })
    }
    if (b.mode !== 'planned' && b.mode !== 'emergency') {
      return res.status(400).json({ error: 'mode must be planned or emergency' })
    }

    const db = getDB()
    const announcedAt = new Date().toISOString()
    const state = b.mode === 'emergency' ? 'activated' : 'announced'
    const completedAt = b.mode === 'emergency' ? announcedAt : null

    const info = db.prepare(`
      INSERT INTO key_rotations (
        tenant_id, agent_id, old_key, new_key, mode,
        announced_at, activation_time, state, completed_at, rotation_signature
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      tenantId, b.agent_id, b.old_key, b.new_key, b.mode,
      announcedAt, b.activation_time, state, completedAt, b.rotation_signature,
    )

    // For emergency mode: update agent's public_key in agents table
    if (b.mode === 'emergency') {
      db.prepare(
        `UPDATE agents SET public_key = ? WHERE tenant_id = ? AND agent_id = ?`
      ).run(b.new_key, tenantId, b.agent_id)
    }

    // Invalidate trust profile cache for this agent
    trustProfileCache.delete(b.agent_id)

    res.json({
      ok: true,
      rotation_id: info.lastInsertRowid,
      state,
      mode: b.mode,
      announced_at: announcedAt,
      activation_time: b.activation_time,
    })
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to register rotation' })
  }
})

// ═══════════════════════════════════════
// MCP Stats Persistence
// POST /api/v1/mcp-stats — authenticated heartbeat from MCP server
// GET  /api/v1/mcp-stats/cumulative — public cumulative totals (powers /stats page)
// ═══════════════════════════════════════

// Public cumulative totals — no auth, powers mcp.aeoess.com/stats page
app.get('/api/v1/mcp-stats/cumulative', (_req, res) => {
  try {
    const db = getDB()
    // Cumulative = sum of the MAX counter per session_id (each session's peak
    // value across all its snapshots). Counters are monotonic within a session.
    const perSession = db.prepare(`
      SELECT session_id,
             MAX(uptime_seconds)      AS uptime_seconds,
             MAX(passports_issued)    AS passports_issued,
             MAX(sessions_total)      AS sessions_total,
             MAX(tool_calls_total)    AS tool_calls_total,
             MAX(evaluations_total)   AS evaluations_total,
             MAX(delegations_created) AS delegations_created,
             MAX(receipts_stored)     AS receipts_stored
      FROM mcp_stats_snapshots
      GROUP BY session_id
    `).all() as Array<{
      session_id: string
      uptime_seconds: number
      passports_issued: number
      sessions_total: number
      tool_calls_total: number
      evaluations_total: number
      delegations_created: number
      receipts_stored: number
    }>

    let passports_issued = 0, sessions_total = 0, tool_calls_total = 0
    let evaluations_total = 0, delegations_created = 0, receipts_stored = 0
    let total_uptime_seconds = 0
    for (const r of perSession) {
      passports_issued    += r.passports_issued    || 0
      sessions_total      += r.sessions_total      || 0
      tool_calls_total    += r.tool_calls_total    || 0
      evaluations_total   += r.evaluations_total   || 0
      delegations_created += r.delegations_created || 0
      receipts_stored     += r.receipts_stored     || 0
      total_uptime_seconds += r.uptime_seconds     || 0
    }

    const meta = db.prepare(`
      SELECT COUNT(*) AS snapshot_count,
             MIN(snapshot_at) AS first_snapshot_at,
             MAX(snapshot_at) AS last_snapshot_at
      FROM mcp_stats_snapshots
    `).get() as { snapshot_count: number; first_snapshot_at: string | null; last_snapshot_at: string | null }

    // Current session = most recent snapshot
    const latest = db.prepare(`
      SELECT session_id, uptime_seconds, sessions_active
      FROM mcp_stats_snapshots
      ORDER BY snapshot_at DESC
      LIMIT 1
    `).get() as { session_id: string; uptime_seconds: number; sessions_active: number } | undefined

    res.setHeader('Cache-Control', 'public, max-age=30, stale-while-revalidate=120')
    res.json({
      cumulative: {
        passports_issued,
        sessions_total,
        tool_calls_total,
        evaluations_total,
        delegations_created,
        receipts_stored,
        total_uptime_hours: Math.round((total_uptime_seconds / 3600) * 10) / 10,
      },
      current_session: latest ? {
        session_id: latest.session_id,
        uptime_seconds: latest.uptime_seconds,
        sessions_active: latest.sessions_active,
      } : null,
      snapshot_count: meta.snapshot_count,
      first_snapshot_at: meta.first_snapshot_at,
      last_snapshot_at: meta.last_snapshot_at,
    })
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to fetch cumulative stats' })
  }
})

// Authenticated heartbeat — MCP posts its counters every ~5min + on SIGTERM
app.post('/api/v1/mcp-stats', authMiddleware, (req: any, res) => {
  try {
    const b = req.body || {}
    if (typeof b.session_id !== 'string' || !b.session_id) {
      return res.status(400).json({ error: 'session_id required' })
    }
    const db = getDB()
    const snapshotAt = new Date().toISOString()
    // Upsert window: if a snapshot for this session exists within the last 5 min,
    // update it (monotonic counters overwrite). Otherwise insert a new row.
    const existing = db.prepare(`
      SELECT id FROM mcp_stats_snapshots
      WHERE session_id = ?
        AND snapshot_at >= datetime('now', '-5 minutes')
      ORDER BY snapshot_at DESC LIMIT 1
    `).get(b.session_id) as { id: number } | undefined

    const values = {
      snapshot_at: snapshotAt,
      uptime_seconds: Number(b.uptime_seconds) || 0,
      passports_issued: Number(b.passports_issued) || 0,
      sessions_total: Number(b.sessions_total) || 0,
      sessions_active: Number(b.sessions_active) || 0,
      tool_calls_total: Number(b.tool_calls_total) || 0,
      evaluations_total: Number(b.evaluations_total) || 0,
      delegations_created: Number(b.delegations_created) || 0,
      receipts_stored: Number(b.receipts_stored) || 0,
      version: typeof b.version === 'string' ? b.version : null,
      tenant_id: req.tenant?.id ?? null,
    }

    if (existing) {
      db.prepare(`
        UPDATE mcp_stats_snapshots SET
          snapshot_at = ?, uptime_seconds = ?, passports_issued = ?,
          sessions_total = ?, sessions_active = ?, tool_calls_total = ?,
          evaluations_total = ?, delegations_created = ?, receipts_stored = ?,
          version = ?, tenant_id = ?
        WHERE id = ?
      `).run(
        values.snapshot_at, values.uptime_seconds, values.passports_issued,
        values.sessions_total, values.sessions_active, values.tool_calls_total,
        values.evaluations_total, values.delegations_created, values.receipts_stored,
        values.version, values.tenant_id, existing.id,
      )
      return res.json({ ok: true, action: 'updated', snapshot_id: existing.id })
    }

    const info = db.prepare(`
      INSERT INTO mcp_stats_snapshots (
        session_id, snapshot_at, uptime_seconds, passports_issued,
        sessions_total, sessions_active, tool_calls_total, evaluations_total,
        delegations_created, receipts_stored, version, tenant_id
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      b.session_id, values.snapshot_at, values.uptime_seconds, values.passports_issued,
      values.sessions_total, values.sessions_active, values.tool_calls_total,
      values.evaluations_total, values.delegations_created, values.receipts_stored,
      values.version, values.tenant_id,
    )
    res.json({ ok: true, action: 'inserted', snapshot_id: info.lastInsertRowid })
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to record snapshot' })
  }
})


// ═══════════════════════════════════════
// Self-service Account (authenticated)
// ═══════════════════════════════════════

app.get('/api/v1/account', authMiddleware, (req: any, res) => {
  const tenant = req.tenant
  const db = getDB()

  // Agent count
  const agentCount = db.prepare(
    `SELECT COUNT(*) as c FROM agents WHERE tenant_id = ? AND status = 'active'`
  ).get(tenant.id) as { c: number }

  // Delegation count
  const delegationCount = db.prepare(
    `SELECT COUNT(*) as c FROM delegations WHERE tenant_id = ? AND status = 'active'`
  ).get(tenant.id) as { c: number }

  // Evaluations this month
  const monthStart = new Date()
  monthStart.setDate(1)
  monthStart.setHours(0, 0, 0, 0)
  const evalsThisMonth = db.prepare(
    `SELECT COUNT(*) as c FROM policy_evaluations
     WHERE tenant_id = ? AND created_at >= ?`
  ).get(tenant.id, monthStart.toISOString()) as { c: number }

  // Receipts stored (evaluation_receipts = gateway auto-minted, receipts = agent-submitted)
  const evalReceiptCount = db.prepare(
    `SELECT COUNT(*) as c FROM evaluation_receipts WHERE tenant_id = ?`
  ).get(tenant.id) as { c: number }
  const agentReceiptCount = db.prepare(
    `SELECT COUNT(*) as c FROM receipts WHERE tenant_id = ?`
  ).get(tenant.id) as { c: number }

  // API keys (prefix only, no hashes)
  const keys = db.prepare(
    `SELECT id, key_prefix, name, key_class, created_at, last_used_at, revoked_at, expires_at
     FROM api_keys WHERE tenant_id = ?`
  ).all(tenant.id) as any[]

  // Plan limits
  const limits = PLAN_LIMITS[tenant.plan as keyof typeof PLAN_LIMITS] || PLAN_LIMITS.free

  res.json({
    tenant_id: tenant.id,
    name: tenant.name,
    email: tenant.email,
    plan: tenant.plan,
    status: tenant.status,
    usage: {
      agents: agentCount.c,
      delegations: delegationCount.c,
      evaluations_this_month: evalsThisMonth.c,
      receipts: evalReceiptCount.c + agentReceiptCount.c,
    },
    limits: {
      max_agents: limits.maxAgents,
      evaluations_per_month: limits.evaluationsPerMonth,
      compliance_reports: limits.complianceReports,
      sla: limits.sla,
    },
    api_keys: keys.map((k: any) => ({
      id: k.id,
      prefix: k.key_prefix,
      name: k.name,
      key_class: k.key_class === 'tenant_admin' ? 'tenant_admin' : 'runtime',
      created_at: k.created_at,
      last_used_at: k.last_used_at,
      expires_at: k.expires_at ?? null,
      active: !k.revoked_at && !(k.expires_at && k.expires_at <= new Date().toISOString()),
    })),
  })
})

// Rotate API key — revokes the tenant's runtime keys, issues a new runtime
// key. tenant_admin keys are not revoked, minted or listed here (they
// expire on their own; password reset revokes them).
app.post('/api/v1/account/rotate-key', authMiddleware, (req: any, res) => {
  const tenant = req.tenant
  const { apiKey: rawKey, keyPrefix } = rotateRuntimeKeys(tenant.id, 'rotated')
  try { getEventBus().emit(tenant.id, { type: 'key_rotated', data: { key_prefix: keyPrefix } }) } catch {}

  res.json({
    message: 'API key rotated. Save this key — it will not be shown again.',
    api_key: rawKey,
  })
})

// POST /api/v1/account/regenerate-key — generate new key, invalidate old, email notification
// Same key-class rule as rotate-key: runtime keys only.
app.post('/api/v1/account/regenerate-key', authMiddleware, (req: any, res) => {
  const tenant = req.tenant
  const { apiKey: rawKey, keyPrefix } = rotateRuntimeKeys(tenant.id, 'regenerated')
  try { getEventBus().emit(tenant.id, { type: 'key_rotated', data: { key_prefix: keyPrefix } }) } catch {}

  // Email notification
  sendEmail({
    to: tenant.email,
    subject: 'AEOESS — API Key Regenerated',
    textBody: `Your API key was regenerated at ${new Date().toISOString()}. If you did not do this, contact signal@aeoess.com immediately.`,
    htmlBody: `<p>Your AEOESS API key was regenerated at ${new Date().toISOString()}.</p><p>If you did not do this, contact <a href="mailto:signal@aeoess.com">signal@aeoess.com</a> immediately.</p>`,
  }).catch(() => {})

  res.json({
    api_key: rawKey,
    message: 'New API key generated. Save it now — the old key is invalidated.',
  })
})

// Authenticated routes
app.use('/api/v1', authMiddleware, gatewayRouter)
app.use('/api/v1', authMiddleware, paymentRouter)
app.use('/api/v1', authMiddleware, walletRouter)
app.use('/api/v1', authMiddleware, rekorRouter)
app.use('/api/v1', authMiddleware, finopsRouter)
app.use('/api/v1', authMiddleware, eventsRouter)
app.use('/api/v1', authMiddleware, riskQueueRouter)
app.use('/api/v1', authMiddleware, sessionsRouter)
app.use('/api/v1', authMiddleware, billingRouter)
app.use('/api/v1', authMiddleware, coordinationRouter)
app.use('/api/v1', authMiddleware, bmoRouter)
app.use('/api/v1', authMiddleware, providerAttestationRouter)
app.use('/api/v1', authMiddleware, bmoEvidenceRouter)
app.use('/api/v1', authMiddleware, auditExportRouter)
app.use('/api/v1', authMiddleware, connectorsRouter)
// G-C2 routers: guards (a, read-only surface), automations (b), playbooks (c).
app.use('/api/v1', authMiddleware, guardsRouter)
app.use('/api/v1', authMiddleware, automationsRouter)
app.use('/api/v1', authMiddleware, playbooksRouter)
app.use('/api/v1', authMiddleware, approvalRouter)
app.use('/api/v1', authMiddleware, simulationRouter)
app.use('/api/v1', authMiddleware, dataClassificationRouter)
app.use('/api/v1', authMiddleware, destinationsRouter)
app.use('/api/v1', authMiddleware, tenantIsolationRouter)

// ═══════════════════════════════════════
// Admin endpoints (enterprise plan only)
// ═══════════════════════════════════════

app.get('/api/v1/admin/tenants', authMiddleware, requireAdmin, (req: any, res) => {
  const db = getDB()
  const tenants = db.prepare(`
    SELECT t.id as tenant_id, t.name, t.email, t.plan, t.status, t.created_at,
           (SELECT COUNT(*) FROM agents a WHERE a.tenant_id = t.id AND a.status = 'active') as agent_count,
           (SELECT COUNT(*) FROM policy_evaluations e WHERE e.tenant_id = t.id) as evaluation_count
    FROM tenants t WHERE t.status != 'deleted' ORDER BY t.created_at DESC
  `).all()
  res.json({ tenants, count: tenants.length })
})

app.delete('/api/v1/admin/tenants/:tenantId', authMiddleware, requireAdmin, (req: any, res) => {
  const tenant = req.tenant
  const { tenantId } = req.params
  if (tenantId === tenant.id) {
    return res.status(400).json({ error: 'Cannot delete your own tenant' })
  }
  const db = getDB()
  const target = db.prepare(`SELECT id, name, status FROM tenants WHERE id = ?`).get(tenantId) as any
  if (!target) return res.status(404).json({ error: 'Tenant not found' })
  if (target.status === 'deleted') return res.status(409).json({ error: 'Tenant already deleted' })

  db.prepare(`UPDATE tenants SET status = 'deleted' WHERE id = ?`).run(tenantId)
  console.log(`[admin] Tenant "${target.name}" (${tenantId}) soft-deleted by ${tenant.id}`)
  res.json({ tenant_id: tenantId, status: 'deleted' })
})

app.post('/api/v1/admin/send-digest', authMiddleware, requireAdmin, async (_req: any, res) => {
  const db = getDB()
  const period = new Date().toISOString().slice(0, 7)
  const tenants = db.prepare(`SELECT id, name, email, plan FROM tenants WHERE status = 'active'`).all() as any[]

  let sent = 0, failed = 0
  for (const t of tenants) {
    try {
      const stats = db.prepare(`
        SELECT COUNT(*) as evaluations,
               SUM(CASE WHEN verdict = 'permit' THEN 1 ELSE 0 END) as permits,
               SUM(CASE WHEN verdict = 'deny' THEN 1 ELSE 0 END) as denials
        FROM policy_evaluations WHERE tenant_id = ? AND created_at >= ?
      `).get(t.id, period + '-01') as any
      const agents = (db.prepare(`SELECT COUNT(*) as c FROM agents WHERE tenant_id = ? AND status = 'active'`).get(t.id) as any).c

      const email = weeklyDigestEmail(t.name, {
        evaluations: stats?.evaluations || 0,
        permits: stats?.permits || 0,
        denials: stats?.denials || 0,
        agents,
        period,
      })
      email.to = t.email
      await sendEmail(email)
      sent++
    } catch (e) {
      console.error(`[digest] Failed for ${t.email}:`, (e as Error).message)
      failed++
    }
  }
  res.json({ sent, failed, total: tenants.length })
})

// 404
app.use((_req, res) => {
  res.status(404).json({ error: 'Not found. See docs at aeoess.com/docs.html' })
})

// Init and start
const db = initDB(DB_PATH)
initLineageTables()
initGatewayIdentity()
initAnchorTable()
initConnectorTables()
// G-C2 layer (c): customer pre-signed incident-playbook registry tables.
initPlaybookTables()
// G-D1: mode configuration + migration-signal ledger tables.
initModeConfigTable()
initModeObservationsTable()

// G-D4: apply in-tenant deployment isolation defaults from env
// (ISOLATION_MODE / TRUST_ROOT_SOURCE / AIR_GAPPED). Tighten-only:
// a regulated deployment forces hard isolation on boot. No-op on the
// hosted single-tenant path where these env vars are unset (default 'hard').
const isolationBoot = applyDeploymentIsolationDefault()
if (isolationBoot.tenantsForcedHard > 0 || isolationBoot.airGapped) {
  console.log(
    `[isolation] deployment default mode=${isolationBoot.mode} ` +
    `tenantsForcedHard=${isolationBoot.tenantsForcedHard} airGapped=${isolationBoot.airGapped}`,
  )
}

// One-shot bound-demo placeholder→fixture migration. Replaces
// DEMO_FIXTURE_SIG_NOT_PRODUCTION_VALID strings on the live aeoess-bound-demo
// agent with canonical Ed25519 binding_signature values from the SDK fixture
// (tests/fixtures/wallet-binding/aeoess-bound-demo.json, commit cc1028a).
// Idempotent: noop if no placeholders present. Promised to
// douglasborthwick-crypto on insumer-examples#1.
try {
  const FIXTURE_PUBKEY = 'c7cdce4d15b0c175a3fec538202e1ba9f6e351e4fbb16998bb42265a1542d5bb'
  const FIXTURE_BW = [
    { chain: 'ethereum', address: '0x742d35Cc6634C0532925a3b844Bc9e7595f7E2c1', bound_at: '2026-04-10T12:00:00.000Z', binding_signature: '67859cc44214504a8a08557a84b5f94884ec8e832b0a9d9a00488a340f1d81531f470cbc9f60bc7f1002373aaebf496cc34297237224b227a9aadaa1f03ad907' },
    { chain: 'base',     address: '0x742d35Cc6634C0532925a3b844Bc9e7595f7E2c1', bound_at: '2026-04-10T12:00:01.000Z', binding_signature: '699232d9419987f63a520213249e8f79a716c2307a172ff0464319cfc5606d51dd8b2c2a992c8d907935ebe1f93f706d44d914c64cd75a82542bdf4fc493d802' },
  ]
  const rows = db.prepare(`SELECT id, metadata FROM agents WHERE agent_id = 'aeoess-bound-demo'`).all() as any[]
  let migrated = 0
  for (const row of rows) {
    let meta: any = {}
    try { meta = row.metadata ? JSON.parse(row.metadata) : {} } catch { meta = {} }
    const bw = Array.isArray(meta?.bound_wallets) ? meta.bound_wallets : []
    const hasPlaceholder = bw.some((w: any) => typeof w?.binding_signature === 'string' && w.binding_signature.includes('DEMO_FIXTURE_SIG_NOT_PRODUCTION_VALID'))
    // Drift check: also re-seed if any bound_at/binding_signature diverges from the
    // canonical fixture (caught by douglasborthwick-crypto on insumer-examples#1 —
    // one-second bound_at delta on the base entry made the per-wallet Ed25519 sig
    // fail deterministic verification).
    const hasDrift = FIXTURE_BW.some((fx) => {
      const live = bw.find((w: any) => w?.chain === fx.chain)
      return !live || live.bound_at !== fx.bound_at || live.binding_signature !== fx.binding_signature
    })
    if (!hasPlaceholder && !hasDrift) continue
    meta.bound_wallets = FIXTURE_BW
    meta.fixture_public_key = FIXTURE_PUBKEY
    db.prepare(`UPDATE agents SET metadata = ? WHERE id = ?`).run(JSON.stringify(meta), row.id)
    migrated++
  }
  if (migrated > 0) console.log(`[bound-demo-migration] replaced placeholder sigs on ${migrated} agent row(s)`)
  else console.log(`[bound-demo-migration] no placeholders found (already migrated)`)
} catch (e: any) {
  console.warn(`[bound-demo-migration] failed (will retry next boot): ${e?.message || e}`)
}

// Rebuild the wallet → agent reverse index from persisted bound_wallets
// metadata so /public/trust/by-wallet/:address resolves immediately on
// boot. Cheap (in-memory map keyed on lowercased address).
try {
  const stats = rebuildWalletReverseIndex(db)
  console.log(`[wallet-reverse-index] rebuilt: ${stats.addressesIndexed} address(es) across ${stats.agentsScanned} agent(s)`)
} catch (e: any) {
  console.warn(`[wallet-reverse-index] rebuild failed (will populate lazily): ${e?.message || e}`)
}

// Backfill evaluation receipts from existing evaluations (one-time on first deploy)
try {
  const receiptCount = (db.prepare('SELECT COUNT(*) as c FROM evaluation_receipts').get() as any).c
  if (receiptCount === 0) {
    const evals = db.prepare('SELECT * FROM policy_evaluations').all() as any[]
    if (evals.length > 0) {
      const insert = db.prepare(`
        INSERT INTO evaluation_receipts (
          tenant_id, agent_id, evaluation_id, event_type, decision_stage,
          action_type, scope_requested_json, verdict, reason_code,
          policy_hash, schema_version, receipt_hash, created_at
        ) VALUES (?, ?, ?, ?, 'gateway_authorization', ?, ?, ?, ?, ?, '1.0.0', ?, ?)
      `)
      let backfilled = 0
      for (const ev of evals) {
        try {
          const verd = (ev.verdict || '').toLowerCase() === 'permit' ? 'permit' : 'deny'
          const scopeJson = JSON.stringify(
            (ev.scope_required || '').split(',').map((s: string) => s.trim()).filter(Boolean).sort()
          )
          const eventType = verd === 'permit' ? 'authorization_permit' : 'authorization_deny'
          const reasonCode = verd === 'deny' ? (ev.reason || 'policy_deny') : null
          const policyHash = createHash('sha256')
            .update('floor-v1-scope-spend-depth-delegation')
            .digest('hex').slice(0, 16)
          const receiptHash = createHash('sha256')
            .update(JSON.stringify({ evaluation_id: ev.id, verdict: verd, agent_id: ev.agent_id }))
            .digest('hex')
          insert.run(
            ev.tenant_id, ev.agent_id, ev.id, eventType,
            ev.action_type, scopeJson, verd, reasonCode,
            policyHash, receiptHash, ev.created_at,
          )
          backfilled++
        } catch { /* skip individual failures */ }
      }
      console.log(`[receipt-mint] Backfilled ${backfilled} receipts from ${evals.length} evaluations`)
    }
  }
} catch (e: any) {
  console.error('[receipt-mint] Backfill failed:', e.message)
}

console.log(`
═══════════════════════════════════════
  AEOESS Gateway v0.4.0 (Railway)
  Port: ${PORT}
  Database: ${DB_PATH}
  Endpoints: 40 API routes + 2 public (.well-known)
═══════════════════════════════════════
`)
app.listen(PORT, () => {
  console.log(`  ✅ Listening on http://localhost:${PORT}`)
  console.log(`  Health: http://localhost:${PORT}/healthz`)
  console.log(`  Signup: POST http://localhost:${PORT}/api/v1/signup`)
})
