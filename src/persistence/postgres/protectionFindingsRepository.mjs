// PV-06 findings in Postgres: derived from a recorded evaluation, upserted and audited in one tenant transaction.
import {
  applyProtectionFindingPatch,
  dedupeProtectionFindingCandidates,
  deriveProtectionFindingCandidates,
  planProtectionFindingUpsert,
  toProtectionFindingRow,
} from '../../lib/protectionValidationFindings.mjs';
import { newId } from '../../lib/ids.mjs';
import { withTenantContext } from './tenantContext.mjs';

const PATCHABLE_ACTIONS = new Set(['escalate', 'record_observation', 'exception_retained']);

function asObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
}

function mapExisting(row) {
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    status: row.status,
    severity: row.severity,
    title: row.title,
    source: row.source,
    dedupe_key: row.dedupe_key,
    finding_class: row.finding_class,
    priority: row.priority,
    protection_validation: asObject(row.protection_validation_json),
    created_at: row.created_at,
  };
}

export function createPostgresProtectionFindingsRepository(pool, { audit = null } = {}) {
  async function appendAudit(client, ctx, action, findingId, metadata) {
    if (!audit?.appendAuditEvent) return;
    await audit.appendAuditEvent({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId ?? 'system',
      actor_role: ctx.role ?? 'system',
      action,
      resource_type: 'finding',
      resource_id: findingId,
      metadata,
    }, { client });
  }

  return {
    async upsertProtectionFindingsFromEvaluation(ctx, evaluation, {
      entryPaths = [],
      expectations = [],
      baseline = null,
      now = new Date(),
    } = {}) {
      const derived = deriveProtectionFindingCandidates({ evaluation, entryPaths, expectations, baseline });
      if (!derived.ok) return { ok: false, error: derived.error, created: [], updated: [], retained: [] };
      const candidates = dedupeProtectionFindingCandidates(derived.candidates).filter((row) => row.tenant_id === ctx.tenantId);
      if (!candidates.length) return { ok: true, error: null, created: [], updated: [], retained: [] };
      const at = new Date(now).toISOString();
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        // Serialize absent rows too: FOR UPDATE alone cannot lock a finding that has not been inserted yet.
        for (const key of [...new Set(candidates.map((row) => row.dedupe_key))].sort()) {
          await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [`protection_finding:${ctx.tenantId}:${key}`]);
        }
        const { rows } = await client.query(
          `SELECT id, tenant_id, status, severity, title, source, dedupe_key, finding_class, priority,
                  protection_validation_json, created_at::text AS created_at
           FROM findings
           WHERE tenant_id = $1 AND source = 'protection_validation' AND dedupe_key = ANY($2::text[])
           ORDER BY created_at DESC, id
           FOR UPDATE`,
          [ctx.tenantId, candidates.map((row) => row.dedupe_key)],
        );
        const existing = rows.map(mapExisting);
        const created = [];
        const updated = [];
        const retained = [];
        for (const candidate of candidates) {
          const plan = planProtectionFindingUpsert({ existingFindings: existing, candidate });
          const metadata = {
            source: 'protection_validation',
            dedupe_key: candidate.dedupe_key,
            finding_class: candidate.finding_class,
            evaluation_id: candidate.comparison_context.evaluation_id,
            upsert_action: plan.action,
          };
          if (plan.action === 'create') {
            const row = toProtectionFindingRow(candidate, { id: newId('finding'), now: at, upsert: plan });
            const inserted = await client.query(
              `INSERT INTO findings (
                 id, tenant_id, target_group_id, target_id, test_run_id, check_id, title, severity, status,
                 evidence_ids, notes, verdict_id, assignee, created_at, updated_at,
                 source, dedupe_key, finding_class, priority, protection_validation_json
               ) VALUES ($1, $2, NULL, $3, $4, $5, $6, $7, 'open', $8::text[], $9, $10, NULL,
                 $11::timestamptz, $11::timestamptz, 'protection_validation', $12, $13, $14, $15::jsonb)
               ON CONFLICT DO NOTHING
               RETURNING id`,
              [
                row.id, ctx.tenantId, row.target_id ?? null, row.test_run_id ?? null, row.check_id ?? null,
                row.title, row.severity, row.evidence_ids ?? [], row.notes ?? null, row.verdict_id ?? null,
                at, row.dedupe_key, row.finding_class, row.priority, JSON.stringify(row.protection_validation),
              ],
            );
            if (!inserted.rows[0]) continue;
            existing.unshift({ ...row, protection_validation: row.protection_validation });
            created.push(row.id);
            await appendAudit(client, ctx, 'finding.created', row.id, metadata);
            continue;
          }
          if (!PATCHABLE_ACTIONS.has(plan.action) || !plan.finding_id) continue;
          const index = existing.findIndex((row) => row.id === plan.finding_id);
          if (index < 0) continue;
          const next = applyProtectionFindingPatch(existing[index], plan.patch ?? {}, at);
          await client.query(
            `UPDATE findings
             SET severity = $3, title = $4, finding_class = $5, priority = $6,
                 protection_validation_json = $7::jsonb, updated_at = $8::timestamptz
             WHERE tenant_id = $1 AND id = $2`,
            [
              ctx.tenantId, plan.finding_id, next.severity, next.title, next.finding_class ?? null, next.priority ?? null,
              JSON.stringify(next.protection_validation), at,
            ],
          );
          existing[index] = next;
          (plan.action === 'exception_retained' ? retained : updated).push(plan.finding_id);
          await appendAudit(client, ctx, 'finding.updated', plan.finding_id, metadata);
        }
        return { ok: true, error: null, created, updated, retained, passing: derived.passing.length, skipped: derived.skipped.length };
      });
    },
  };
}
