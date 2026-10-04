import { withTenantContext } from './tenantContext.mjs';
import {
  MAX_CAPTURED_RUNS,
  MAX_DECLARED_MEMBERS,
  MAX_SNAPSHOT_EVIDENCE,
  MAX_SNAPSHOT_FINDINGS,
} from '../../lib/reportSnapshot.mjs';

export const DEFAULT_REPORT_LIST_LIMIT = 100;
export const MAX_REPORT_LIST_LIMIT = 500;
export const MAX_FINDINGS_EXPORT_LIMIT = 500;
const REPORT_COLUMNS = `id, tenant_id, kind, title, status, summary_json, run_ids, created_by, created_at`;

const TEST_RUN_EXPORT_COLUMNS = `id, tenant_id, target_group_id, target_id, check_id, vector_family, safety_class,
  status, remediation_template, summary_json, created_at`;

const VERDICT_EXPORT_COLUMNS = `id, tenant_id, test_run_id, target_id, check_id, verdict, confidence, explanation,
  evidence_ids, placement_confidence_json, created_at`;

const FINDING_EXPORT_COLUMNS = `id, tenant_id, target_group_id, target_id, test_run_id, check_id, title, severity,
  status, evidence_ids, notes, remediation_template, verdict_id, last_verdict_id, assignee, created_at, updated_at`;

function toIso(value) {
  if (value == null) return value;
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

function asStringArray(value) {
  return Array.isArray(value) ? value : [];
}

function asObject(value) {
  if (value && typeof value === 'object' && !Array.isArray(value)) return value;
  return {};
}

function normalizeReportListLimit(limit) {
  if (limit === undefined || limit === null) {
    return DEFAULT_REPORT_LIST_LIMIT;
  }
  const n = Number(limit);
  if (!Number.isFinite(n) || n < 1) {
    return DEFAULT_REPORT_LIST_LIMIT;
  }
  return Math.min(Math.floor(n), MAX_REPORT_LIST_LIMIT);
}

function mapReportRow(row) {
  if (!row) return null;
  const summary = asObject(row.summary_json);
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    kind: row.kind,
    title: row.title,
    status: row.status,
    // `reports` has no period column; the generated window rides in summary_json and is
    // projected back to the top level so dev-json and Postgres return the same shape.
    period: summary.period ?? null,
    summary,
    run_ids: asStringArray(row.run_ids),
    created_by: row.created_by ?? undefined,
    created_at: toIso(row.created_at),
  };
}

function mapReportRunRow(row) {
  if (!row) return null;
  const mapped = {
    id: row.id,
    tenant_id: row.tenant_id,
    target_group_id: row.target_group_id,
    check_id: row.check_id,
    status: row.status,
    created_at: toIso(row.created_at),
  };
  if (row.target_id != null) mapped.target_id = row.target_id;
  if (row.vector_family != null) mapped.vector_family = row.vector_family;
  if (row.safety_class != null) mapped.safety_class = row.safety_class;
  if (row.remediation_template != null) mapped.remediation_template = row.remediation_template;
  const summary = asObject(row.summary_json);
  if (Object.keys(summary).length > 0) mapped.summary = summary;
  return mapped;
}

function mapReportVerdictRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    test_run_id: row.test_run_id,
    target_id: row.target_id ?? undefined,
    check_id: row.check_id ?? undefined,
    verdict: row.verdict,
    confidence: row.confidence ?? undefined,
    explanation: row.explanation ?? undefined,
    evidence_ids: asStringArray(row.evidence_ids),
    placement_confidence: asObject(row.placement_confidence_json),
    created_at: toIso(row.created_at),
  };
}

function mapReportFindingRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    target_group_id: row.target_group_id ?? undefined,
    target_id: row.target_id ?? undefined,
    test_run_id: row.test_run_id ?? undefined,
    check_id: row.check_id ?? undefined,
    title: row.title,
    severity: row.severity,
    status: row.status,
    evidence_ids: asStringArray(row.evidence_ids),
    notes: row.notes ?? undefined,
    remediation_template: row.remediation_template ?? undefined,
    verdict_id: row.verdict_id ?? undefined,
    last_verdict_id: row.last_verdict_id ?? undefined,
    assignee: row.assignee ?? undefined,
    created_at: toIso(row.created_at),
    updated_at: row.updated_at == null ? undefined : toIso(row.updated_at),
  };
}

/**
 * @param {import('pg').Pool} pool
 */
export function createReportRepository(pool) {
  return {
    async createReport(ctx, record) {
      const tenantId = ctx.tenantId;
      const summaryJson = asObject(record.summary ?? record.summary_json);
      const period = record.period ?? summaryJson.period ?? null;
      const summaryToStore = period == null ? summaryJson : { ...summaryJson, period };
      const runIds = asStringArray(record.run_ids);

      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO reports (
             id, tenant_id, kind, title, status, summary_json, run_ids, created_by, created_at
           )
           VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9::timestamptz)
           RETURNING ${REPORT_COLUMNS}`,
          [
            record.id,
            tenantId,
            record.kind,
            record.title,
            record.status,
            JSON.stringify(summaryToStore),
            runIds,
            record.created_by ?? null,
            record.created_at,
          ],
        );
        return mapReportRow(rows[0]);
      });
    },

    async getReport(ctx, id) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${REPORT_COLUMNS}
           FROM reports
           WHERE tenant_id = $1 AND id = $2`,
          [ctx.tenantId, id],
        );
        return mapReportRow(rows[0] ?? null);
      });
    },

    async listReports(ctx, options = {}) {
      const boundedLimit = normalizeReportListLimit(options.limit);

      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${REPORT_COLUMNS}
           FROM reports
           WHERE tenant_id = $1
           ORDER BY created_at DESC
           LIMIT $2`,
          [ctx.tenantId, boundedLimit],
        );
        return rows.map(mapReportRow);
      });
    },

    async listRunsForReport(ctx, runIds) {
      const ids = asStringArray(runIds);
      if (ids.length === 0) {
        return [];
      }

      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${TEST_RUN_EXPORT_COLUMNS}
           FROM test_runs
           WHERE tenant_id = $1 AND id = ANY($2::text[])
           ORDER BY array_position($2::text[], id)`,
          [ctx.tenantId, ids],
        );
        return rows.map(mapReportRunRow);
      });
    },

    async listVerdictsForRunIds(ctx, runIds) {
      const ids = asStringArray(runIds);
      if (ids.length === 0) {
        return [];
      }

      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${VERDICT_EXPORT_COLUMNS}
           FROM verdicts
           WHERE tenant_id = $1 AND test_run_id = ANY($2::text[])
           ORDER BY array_position($2::text[], test_run_id)`,
          [ctx.tenantId, ids],
        );
        return rows.map(mapReportVerdictRow);
      });
    },

    async listFindingsForExport(ctx, options = {}) {
      const tenantId = ctx.tenantId;
      const status = options.status;

      return withTenantContext(pool, tenantId, async (client) => {
        let sql = `SELECT ${FINDING_EXPORT_COLUMNS}
           FROM findings
           WHERE tenant_id = $1`;
        const params = [tenantId];
        if (status != null && status !== '') {
          sql += ` AND status = $2`;
          params.push(status);
        }
        sql += ` ORDER BY created_at DESC LIMIT $${params.length + 1}`;
        params.push(MAX_FINDINGS_EXPORT_LIMIT);

        const { rows } = await client.query(sql, params);
        return rows.map(mapReportFindingRow);
      });
    },

    /**
     * Rows for report scope validation and the generation snapshot.
     * Shape matches `loadDevReportWorld` in src/services/reports.mjs.
     * Evidence metadata is not selected.
     */
    async readReportGenerationWorld(ctx, request) {
      const tenantId = ctx.tenantId;
      const targetIds = request.targetIds ?? null;
      const groupIds = request.targetGroupIds ?? null;
      const runIds = request.runIds ?? null;
      const bounds = request.periodBounds ?? {};
      const limits = request.limits ?? {};
      const memberLimit = limits.members ?? MAX_DECLARED_MEMBERS;
      const runLimit = limits.runs ?? MAX_CAPTURED_RUNS;
      const findingLimit = limits.findings ?? MAX_SNAPSHOT_FINDINGS;
      const evidenceLimit = limits.evidence ?? MAX_SNAPSHOT_EVIDENCE;
      const periodStart = bounds.status === 'bounded' ? bounds.start : null;
      const periodEnd = bounds.status === 'bounded' ? bounds.end : null;

      return withTenantContext(pool, tenantId, async (client) => {
        const foundTargets = targetIds
          ? (await client.query(
            `SELECT id, target_group_id, kind, value, deleted_at, declaration_json
             FROM targets
             WHERE tenant_id = $1 AND id = ANY($2::text[])`,
            [tenantId, targetIds],
          )).rows.map(mapScopeTarget)
          : null;
        const foundGroups = groupIds
          ? (await client.query(
            `SELECT id, name, deleted_at, archived_at, declaration_json
             FROM target_groups
             WHERE tenant_id = $1 AND id = ANY($2::text[])`,
            [tenantId, groupIds],
          )).rows.map(mapScopeGroup)
          : null;

        const memberFilters = ['t.tenant_id = $1', 't.deleted_at IS NULL', 'tg.deleted_at IS NULL', 'tg.archived_at IS NULL'];
        const memberParams = [tenantId];
        if (targetIds) {
          memberParams.push(targetIds);
          memberFilters.push(`t.id = ANY($${memberParams.length}::text[])`);
        } else if (groupIds) {
          memberParams.push(groupIds);
          memberFilters.push(`t.target_group_id = ANY($${memberParams.length}::text[])`);
        }
        const memberWhere = memberFilters.join(' AND ');
        const memberFrom = `FROM targets t
           JOIN target_groups tg ON tg.id = t.target_group_id AND tg.tenant_id = t.tenant_id
           WHERE ${memberWhere}`;
        const memberCount = await client.query(`SELECT COUNT(*)::int AS total ${memberFrom}`, memberParams);
        const memberRows = await client.query(
          `SELECT t.id, t.target_group_id, t.kind, t.value, t.deleted_at, t.declaration_json,
                  tg.declaration_json AS group_declaration_json
           ${memberFrom}
           ORDER BY t.id ASC
           LIMIT $${memberParams.length + 1}`,
          [...memberParams, memberLimit],
        );

        const runScope = scopeFragments({ tenantId, targetIds, groupIds, runIds: null });
        const foundRuns = runIds
          ? (await client.query(
            `SELECT ${SCOPE_RUN_COLUMNS}
             FROM test_runs
             WHERE tenant_id = $1 AND id = ANY($2::text[])`,
            [tenantId, runIds],
          )).rows.map(mapScopeRun)
          : null;

        let runs = [];
        let runTotal = runIds ? runIds.length : 0;
        let runTotalUnwindowed = runIds ? runIds.length : 0;
        if (!runIds) {
          const unwindowed = await client.query(
            `SELECT COUNT(*)::int AS total FROM test_runs WHERE ${runScope.where}`,
            runScope.params,
          );
          const windowParams = [...runScope.params, periodStart, periodEnd];
          const startParam = runScope.params.length + 1;
          const endParam = runScope.params.length + 2;
          const windowedWhere = `${runScope.where}
             AND ($${startParam}::timestamptz IS NULL OR COALESCE(started_at, created_at) >= $${startParam}::timestamptz)
             AND ($${endParam}::timestamptz IS NULL OR COALESCE(started_at, created_at) <= $${endParam}::timestamptz)`;
          const windowed = await client.query(
            `SELECT COUNT(*)::int AS total FROM test_runs WHERE ${windowedWhere}`,
            windowParams,
          );
          const listed = await client.query(
            `SELECT ${SCOPE_RUN_COLUMNS}
             FROM test_runs
             WHERE ${windowedWhere}
             ORDER BY COALESCE(started_at, created_at) DESC, id DESC
             LIMIT $${endParam + 1}`,
            [...windowParams, runLimit],
          );
          runTotalUnwindowed = unwindowed.rows[0].total;
          runTotal = windowed.rows[0].total;
          runs = listed.rows.map(mapScopeRun);
        }

        const includedRunIds = runIds ?? runs.map((run) => run.id);
        const findingScope = scopeFragments({
          tenantId,
          targetIds,
          groupIds,
          runIds,
        });
        const findingWindowParams = [...findingScope.params, periodStart, periodEnd];
        const findingStart = findingScope.params.length + 1;
        const findingEnd = findingScope.params.length + 2;
        const findingWindow = `${findingScope.where}
           AND ($${findingStart}::timestamptz IS NULL OR created_at >= $${findingStart}::timestamptz)
           AND ($${findingEnd}::timestamptz IS NULL OR created_at <= $${findingEnd}::timestamptz)`;
        const findingCount = await client.query(
          `SELECT COUNT(*)::int AS total,
                  COUNT(*) FILTER (WHERE status = 'open')::int AS open_total
           FROM findings WHERE ${findingWindow}`,
          findingWindowParams,
        );
        const findingUnwindowed = await client.query(
          `SELECT COUNT(*)::int AS total FROM findings WHERE ${findingScope.where}`,
          findingScope.params,
        );
        const findingRows = await client.query(
          `SELECT id, target_group_id, target_id, test_run_id, check_id, title, severity, status,
                  evidence_ids, created_at, updated_at
           FROM findings
           WHERE ${findingWindow}
           ORDER BY created_at DESC, id DESC
           LIMIT $${findingEnd + 1}`,
          [...findingWindowParams, findingLimit],
        );

        let evidenceTotal = 0;
        let evidence = [];
        let verdicts = [];
        if (includedRunIds.length > 0) {
          const evidenceCount = await client.query(
            `SELECT COUNT(*)::int AS total
             FROM evidence_vault
             WHERE tenant_id = $1 AND test_run_id = ANY($2::text[])`,
            [tenantId, includedRunIds],
          );
          const evidenceRows = await client.query(
            `SELECT id, test_run_id, label, created_at
             FROM evidence_vault
             WHERE tenant_id = $1 AND test_run_id = ANY($2::text[])
             ORDER BY created_at ASC, id ASC
             LIMIT $3`,
            [tenantId, includedRunIds, evidenceLimit],
          );
          const verdictRows = await client.query(
            `SELECT id, test_run_id, target_id, check_id, verdict, confidence, explanation, evidence_ids, created_at
             FROM verdicts
             WHERE tenant_id = $1 AND test_run_id = ANY($2::text[])`,
            [tenantId, includedRunIds],
          );
          evidenceTotal = evidenceCount.rows[0].total;
          evidence = evidenceRows.rows.map(mapScopeEvidence);
          verdicts = verdictRows.rows.map(mapScopeVerdict);
        }

        return {
          legacy: false,
          found_targets: foundTargets,
          found_groups: foundGroups,
          found_runs: foundRuns,
          members: memberRows.rows.map(mapScopeMember),
          member_total: memberCount.rows[0].total,
          runs,
          run_total: runTotal,
          run_total_unwindowed: runTotalUnwindowed,
          findings: findingRows.rows.map(mapScopeFinding),
          finding_total: findingCount.rows[0].total,
          finding_total_unwindowed: findingUnwindowed.rows[0].total,
          open_finding_total: findingCount.rows[0].open_total,
          verdicts,
          evidence,
          evidence_total: evidenceTotal,
        };
      });
    },
  };
}

const SCOPE_RUN_COLUMNS = `id, target_id, target_group_id, check_id, status, vector_family, safety_class,
  started_at, completed_at, created_at`;

function scopeFragments({ tenantId, targetIds, groupIds, runIds }) {
  const params = [tenantId];
  const filters = ['tenant_id = $1'];
  if (targetIds) {
    params.push(targetIds);
    filters.push(`target_id = ANY($${params.length}::text[])`);
  }
  if (groupIds) {
    params.push(groupIds);
    filters.push(`target_group_id = ANY($${params.length}::text[])`);
    if (!targetIds) {
      filters.push(`target_id IN (
        SELECT id FROM targets
        WHERE tenant_id = $1 AND deleted_at IS NULL AND target_group_id = ANY($${params.length}::text[])
      )`);
    }
  }
  if (runIds) {
    params.push(runIds);
    filters.push(`test_run_id = ANY($${params.length}::text[])`);
  }
  return { params, where: filters.join(' AND ') };
}

function mapScopeTarget(row) {
  return {
    id: row.id,
    target_group_id: row.target_group_id,
    kind: row.kind,
    value: row.value,
    deleted_at: row.deleted_at == null ? null : toIso(row.deleted_at),
    name: row.name ?? null,
    archived_at: row.archived_at == null ? null : toIso(row.archived_at),
  };
}

function mapScopeGroup(row) {
  return {
    id: row.id,
    name: row.name ?? null,
    deleted_at: row.deleted_at == null ? null : toIso(row.deleted_at),
    archived_at: row.archived_at == null ? null : toIso(row.archived_at),
    declaration: asObject(row.declaration_json),
  };
}

function mapScopeMember(row) {
  return {
    id: row.id,
    target_group_id: row.target_group_id,
    kind: row.kind ?? null,
    value: row.value ?? null,
    deleted_at: null,
    declaration: asObject(row.declaration_json),
    group_declaration: asObject(row.group_declaration_json),
  };
}

function mapScopeRun(row) {
  return {
    id: row.id,
    target_id: row.target_id ?? null,
    target_group_id: row.target_group_id ?? null,
    check_id: row.check_id ?? null,
    status: row.status,
    vector_family: row.vector_family ?? null,
    safety_class: row.safety_class ?? null,
    started_at: row.started_at == null ? null : toIso(row.started_at),
    completed_at: row.completed_at == null ? null : toIso(row.completed_at),
    created_at: toIso(row.created_at),
  };
}

function mapScopeFinding(row) {
  return {
    id: row.id,
    target_id: row.target_id ?? null,
    target_group_id: row.target_group_id ?? null,
    test_run_id: row.test_run_id ?? null,
    check_id: row.check_id ?? null,
    title: row.title ?? null,
    severity: row.severity ?? null,
    status: row.status,
    evidence_ids: asStringArray(row.evidence_ids),
    created_at: toIso(row.created_at),
    updated_at: row.updated_at == null ? null : toIso(row.updated_at),
  };
}

function mapScopeEvidence(row) {
  return {
    id: row.id,
    test_run_id: row.test_run_id ?? null,
    label: row.label ?? null,
    created_at: toIso(row.created_at),
  };
}

function mapScopeVerdict(row) {
  return {
    id: row.id,
    test_run_id: row.test_run_id,
    target_id: row.target_id ?? null,
    check_id: row.check_id ?? null,
    verdict: row.verdict,
    confidence: row.confidence ?? null,
    explanation: row.explanation ?? null,
    evidence_ids: asStringArray(row.evidence_ids),
    created_at: toIso(row.created_at),
  };
}

export { mapReportRow, mapReportRunRow, mapReportVerdictRow, mapReportFindingRow };
