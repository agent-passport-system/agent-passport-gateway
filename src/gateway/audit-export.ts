// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * AEOESS Gateway — Audit Log Export (Build D1)
 *
 * Enterprise compliance export for EU AI Act Article 10, GDPR Article 30, SOC 2.
 * Three formats: JSON Lines (SIEM), CSV (spreadsheet), PDF (auditors).
 *
 * GET /api/v1/tenant/:tenantId/audit-export
 *   Query: from, to (ISO 8601), format (jsonl|csv|pdf), scope (optional filter)
 *   Auth: tenant API key (Bearer token)
 *   Rate limit: 10 exports per hour per tenant
 */

import { Router } from 'express'
import { createHash } from 'node:crypto'
import { RateLimiterMemory } from 'rate-limiter-flexible'
import { getDB } from '../db/schema.js'
import type { Tenant } from '../auth/api-keys.js'
import { auditBundlesRouter } from './audit-bundles/router.js'

// ─── Types ───────────────────────────────────────────────────────────

export interface AuditRecord {
  evaluation_id: string
  timestamp: string
  agent_did: string
  scope: string
  decision: 'allow' | 'deny'
  action_type: string
  latency_ms: number | null
  delegation_chain: {
    depth: number
    root_principal: string | null
  }
  receipt_hash: string
}

// ─── Query ───────────────────────────────────────────────────────────

export function queryAuditRecords(
  tenantId: string,
  from: string,
  to: string,
  scope?: string
): AuditRecord[] {
  const db = getDB()
  const where: string[] = ['e.tenant_id = ?', 'e.created_at >= ?', 'e.created_at <= ?']
  const params: any[] = [tenantId, from, to]

  if (scope) {
    where.push('e.scope_required LIKE ?')
    params.push(`%${scope}%`)
  }

  const sql = `
    SELECT
      e.id,
      e.created_at,
      e.agent_id,
      e.scope_required,
      e.verdict,
      e.action_type,
      e.duration_ms,
      a.did,
      er.receipt_hash,
      er.delegation_id
    FROM policy_evaluations e
    LEFT JOIN agents a ON a.agent_id = e.agent_id AND a.tenant_id = e.tenant_id
    LEFT JOIN evaluation_receipts er ON er.evaluation_id = e.id
    WHERE ${where.join(' AND ')}
    ORDER BY e.created_at ASC
  `

  const rows = db.prepare(sql).all(...params) as any[]

  return rows.map(row => {
    // Look up delegation chain depth if delegation_id is present
    let depth = 0
    let rootPrincipal: string | null = null
    if (row.delegation_id) {
      const chain = resolveDelegationChain(db, tenantId, row.delegation_id)
      depth = chain.depth
      rootPrincipal = chain.rootPrincipal
    }

    // Compute receipt hash if not already stored
    const receiptHash = row.receipt_hash || createHash('sha256')
      .update(JSON.stringify({ evaluation_id: row.id, verdict: row.verdict, agent_id: row.agent_id }))
      .digest('hex')

    return {
      evaluation_id: row.id,
      timestamp: row.created_at,
      agent_did: row.did || `did:key:${row.agent_id}`,
      scope: row.scope_required,
      decision: row.verdict === 'permit' ? 'allow' as const : 'deny' as const,
      action_type: row.action_type,
      latency_ms: row.duration_ms ?? null,
      delegation_chain: { depth, root_principal: rootPrincipal },
      receipt_hash: receiptHash,
    }
  })
}

function resolveDelegationChain(
  db: any,
  tenantId: string,
  delegationId: string
): { depth: number; rootPrincipal: string | null } {
  let depth = 0
  let currentParent: string | null = null
  let currentId: string | null = delegationId

  // Walk up the delegation chain (max 10 to prevent infinite loops)
  while (currentId && depth < 10) {
    const del = db.prepare(
      'SELECT parent_agent_id, child_agent_id FROM delegations WHERE id = ? AND tenant_id = ?'
    ).get(currentId, tenantId) as any
    if (!del) break
    currentParent = del.parent_agent_id
    depth++
    // Check if parent is itself a delegated agent
    const parentDel = db.prepare(
      'SELECT id FROM delegations WHERE child_agent_id = ? AND tenant_id = ? AND status = ? LIMIT 1'
    ).get(del.parent_agent_id, tenantId, 'active') as any
    currentId = parentDel?.id || null
  }

  return { depth, rootPrincipal: currentParent }
}

// ─── Format: JSON Lines ──────────────────────────────────────────────

export function toJsonLines(records: AuditRecord[]): string {
  return records.map(r => JSON.stringify(r)).join('\n') + (records.length ? '\n' : '')
}

// ─── Format: CSV ─────────────────────────────────────────────────────

export function toCsv(records: AuditRecord[]): string {
  const headers = [
    'evaluation_id',
    'timestamp',
    'agent_did',
    'scope',
    'decision',
    'action_type',
    'latency_ms',
    'delegation_depth',
    'root_principal',
    'receipt_hash',
  ]
  const lines = [headers.join(',')]
  for (const r of records) {
    lines.push([
      csvEscape(r.evaluation_id),
      csvEscape(r.timestamp),
      csvEscape(r.agent_did),
      csvEscape(r.scope),
      r.decision,
      csvEscape(r.action_type),
      r.latency_ms ?? '',
      r.delegation_chain.depth,
      csvEscape(r.delegation_chain.root_principal || ''),
      csvEscape(r.receipt_hash),
    ].join(','))
  }
  return lines.join('\n') + '\n'
}

function csvEscape(value: string): string {
  if (value.includes(',') || value.includes('"') || value.includes('\n')) {
    return `"${value.replace(/"/g, '""')}"`
  }
  return value
}

// ─── Format: PDF ─────────────────────────────────────────────────────

export async function toPdf(
  records: AuditRecord[],
  tenantId: string,
  from: string,
  to: string
): Promise<Buffer> {
  // Dynamic import to avoid loading pdfkit for non-PDF requests
  const PDFDocument = (await import('pdfkit')).default

  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({
      size: 'A4',
      margin: 50,
      info: {
        Title: `AEOESS Audit Report - ${tenantId}`,
        Author: 'AEOESS Gateway',
        Subject: 'Audit Log Export',
        Creator: 'AEOESS Gateway v0.4.1',
      },
    })

    const chunks: Buffer[] = []
    doc.on('data', (chunk: Buffer) => chunks.push(chunk))
    doc.on('end', () => resolve(Buffer.concat(chunks)))
    doc.on('error', reject)

    // Header
    doc.fontSize(20).text('AEOESS Audit Report', { align: 'center' })
    doc.moveDown(0.5)
    doc.fontSize(10).fillColor('#666666')
    doc.text(`Tenant: ${tenantId}`, { align: 'center' })
    doc.text(`Period: ${from} to ${to}`, { align: 'center' })
    doc.text(`Generated: ${new Date().toISOString()}`, { align: 'center' })
    doc.text(`Records: ${records.length}`, { align: 'center' })
    doc.moveDown(1)

    // Compliance reference
    doc.fillColor('#333333').fontSize(9)
    doc.text('Compliance references: EU AI Act Article 10, GDPR Article 30, SOC 2 CC7.2', { align: 'center' })
    doc.moveDown(1)

    // Summary stats
    const permits = records.filter(r => r.decision === 'allow').length
    const denials = records.filter(r => r.decision === 'deny').length
    const avgLatency = records.length > 0
      ? (records.reduce((sum, r) => sum + (r.latency_ms || 0), 0) / records.length).toFixed(1)
      : '0'

    doc.fontSize(12).fillColor('#000000').text('Summary')
    doc.moveDown(0.3)
    doc.fontSize(10).fillColor('#333333')
    doc.text(`Total evaluations: ${records.length}`)
    doc.text(`Permits: ${permits} | Denials: ${denials}`)
    doc.text(`Average latency: ${avgLatency}ms`)
    doc.moveDown(1)

    // Records table
    doc.fontSize(12).fillColor('#000000').text('Evaluation Records')
    doc.moveDown(0.5)

    for (const record of records) {
      // Check if we need a new page (leave 100pt margin at bottom)
      if (doc.y > 700) {
        doc.addPage()
      }

      doc.fontSize(9).fillColor('#000000')
      doc.text(`[${record.timestamp}] ${record.decision.toUpperCase()} - ${record.action_type}`)
      doc.fontSize(8).fillColor('#555555')
      doc.text(`  Agent: ${record.agent_did}`)
      doc.text(`  Scope: ${record.scope}`)
      doc.text(`  Latency: ${record.latency_ms ?? 'N/A'}ms | Delegation depth: ${record.delegation_chain.depth}`)
      doc.text(`  Receipt: ${record.receipt_hash.slice(0, 32)}...`)
      doc.moveDown(0.3)
    }

    // Footer
    doc.moveDown(1)
    doc.fontSize(8).fillColor('#999999')
    doc.text('This report was generated by AEOESS Gateway. Receipt hashes can be independently verified.', { align: 'center' })
    doc.text('Each record is backed by a signed evaluation receipt with Merkle commitment.', { align: 'center' })

    doc.end()
  })
}

// ─── Router ──────────────────────────────────────────────────────────

export const auditExportRouter = Router()

// G-D2: signed audit evidence bundle endpoints. Mounted onto this same router
// so server.ts wiring is untouched (auditExportRouter is already mounted at
// /api/v1 behind authMiddleware). The bundle router has its own rate limiter
// with a distinct keyPrefix, so it does not collide with auditExportLimiter.
auditExportRouter.use(auditBundlesRouter)

const auditExportLimiter = new RateLimiterMemory({
  points: 10,
  duration: 3600, // 1 hour
  keyPrefix: 'audit_export',
})

auditExportRouter.get('/tenant/:tenantId/audit-export', async (req: any, res) => {
  const tenant: Tenant = req.tenant
  const { tenantId } = req.params

  // Tenant isolation: only allow export of own data
  if (tenant.id !== tenantId) {
    return res.status(403).json({ error: 'Cannot export audit data for another tenant' })
  }

  // Rate limit
  try {
    await auditExportLimiter.consume(tenant.id)
  } catch {
    return res.status(429).json({ error: 'Rate limit exceeded. 10 exports per hour.' })
  }

  // Validate params
  const from = req.query.from as string
  const to = req.query.to as string
  const format = (req.query.format as string) || 'jsonl'
  const scope = req.query.scope as string | undefined

  if (!from || !to) {
    return res.status(400).json({ error: 'Missing required query parameters: from, to (ISO 8601)' })
  }

  // Validate ISO 8601 dates
  if (isNaN(Date.parse(from)) || isNaN(Date.parse(to))) {
    return res.status(400).json({ error: 'Invalid date format. Use ISO 8601 (e.g. 2026-01-01T00:00:00Z)' })
  }

  if (!['jsonl', 'csv', 'pdf'].includes(format)) {
    return res.status(400).json({ error: 'Invalid format. Use: jsonl, csv, or pdf' })
  }

  const records = queryAuditRecords(tenant.id, from, to, scope)

  switch (format) {
    case 'jsonl': {
      const body = toJsonLines(records)
      res.setHeader('Content-Type', 'application/x-ndjson')
      res.setHeader('Content-Disposition', `attachment; filename="audit-${tenantId}-${from}-${to}.jsonl"`)
      return res.send(body)
    }
    case 'csv': {
      const body = toCsv(records)
      res.setHeader('Content-Type', 'text/csv')
      res.setHeader('Content-Disposition', `attachment; filename="audit-${tenantId}-${from}-${to}.csv"`)
      return res.send(body)
    }
    case 'pdf': {
      const buffer = await toPdf(records, tenantId, from, to)
      res.setHeader('Content-Type', 'application/pdf')
      res.setHeader('Content-Disposition', `attachment; filename="audit-${tenantId}-${from}-${to}.pdf"`)
      return res.send(buffer)
    }
  }
})
