import { runWithTenantClient, withTenantContext } from './tenantContext.mjs';

const REQUEST_COLUMNS = `id, tenant_id, waf_asset_id, target_group_id, objective,
  requested_suites, emergency_contacts, requested_window, stop_criteria, abort_criteria,
  staging_only, scope_confirmation, state, created_by, soc_approvals, artifacts,
  suite_results, authorization_pack_status, scheduled_window, scope_hash,
  waf_validation_run_id, rejected_at, rejected_by, rejection_reason,
  results_recorded_at, results_recorded_by, created_at, updated_at`;

const REPORT_COLUMNS = `id, tenant_id, waf_offensive_request_id, executive_summary,
  blocking_verdict, bypass_findings, remediation_notes, suite_results,
  created_by, updated_by, created_at, updated_at`;

const OFFENSIVE_RUN_COLUMNS = `id, tenant_id, test_run_id, waf_asset_id, mode, status,
  started_at, finalized_at, safety_profile_json, summary_json, created_at,
  execution_class, offensive_request_id`;

export const WAF_OFFENSIVE_REPOSITORY_METHODS = Object.freeze([
  'createOffensiveRequest',
  'listOffensiveRequests',
  'getOffensiveRequest',
  'withLockedOffensiveRequest',
  'saveOffensiveRequest',
  'getOffensiveReport',
  'upsertOffensiveReport',
  'createOffensiveWafValidationRun',
]);

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function asObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
}

function toIso(value) {
  if (value == null) return value;
  return value instanceof Date ? value.toISOString() : String(value);
}

export function mapWafOffensiveRequestRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    waf_asset_id: row.waf_asset_id,
    target_group_id: row.target_group_id,
    objective: row.objective,
    requested_suites: asArray(row.requested_suites),
    emergency_contacts: asArray(row.emergency_contacts),
    requested_window: row.requested_window ?? null,
    stop_criteria: row.stop_criteria ?? null,
    abort_criteria: row.abort_criteria ?? null,
    staging_only: row.staging_only !== false,
    scope_confirmation: row.scope_confirmation === true,
    state: row.state,
    created_by: row.created_by ?? null,
    soc_approvals: asArray(row.soc_approvals),
    artifacts: asArray(row.artifacts),
    suite_results: asArray(row.suite_results),
    authorization_pack_status: asObject(row.authorization_pack_status),
    scheduled_window: row.scheduled_window ?? null,
    scope_hash: row.scope_hash ?? null,
    waf_validation_run_id: row.waf_validation_run_id ?? null,
    rejected_at: toIso(row.rejected_at),
    rejected_by: row.rejected_by ?? null,
    rejection_reason: row.rejection_reason ?? null,
    results_recorded_at: toIso(row.results_recorded_at),
    results_recorded_by: row.results_recorded_by ?? null,
    created_at: toIso(row.created_at),
    updated_at: toIso(row.updated_at),
  };
}

export function mapWafOffensiveReportRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    waf_offensive_request_id: row.waf_offensive_request_id,
    executive_summary: row.executive_summary ?? null,
    blocking_verdict: row.blocking_verdict ?? null,
    bypass_findings: asArray(row.bypass_findings),
    remediation_notes: row.remediation_notes ?? null,
    suite_results: asArray(row.suite_results),
    created_by: row.created_by ?? null,
    updated_by: row.updated_by ?? null,
    created_at: toIso(row.created_at),
    updated_at: toIso(row.updated_at),
  };
}

export function mapOffensiveWafValidationRunRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    test_run_id: row.test_run_id ?? null,
    waf_asset_id: row.waf_asset_id,
    offensive_request_id: row.offensive_request_id,
    mode: row.mode,
    status: row.status,
    execution_class: row.execution_class,
    started_at: toIso(row.started_at),
    finalized_at: toIso(row.finalized_at),
    safety_profile_json: asObject(row.safety_profile_json),
    summary_json: asObject(row.summary_json),
    created_at: toIso(row.created_at),
  };
}

/** @param {import('pg').Pool} pool */
export function createWafOffensiveRepository(pool) {
  return {
    async createOffensiveRequest(ctx, record, options = {}) {
      return runWithTenantClient(pool, ctx.tenantId, options.client, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO waf_offensive_requests (
             id, tenant_id, waf_asset_id, target_group_id, objective,
             requested_suites, emergency_contacts, requested_window, stop_criteria,
             abort_criteria, staging_only, scope_confirmation, state, created_by,
             soc_approvals, artifacts, suite_results, authorization_pack_status,
             scheduled_window, scope_hash, waf_validation_run_id, created_at, updated_at
           ) VALUES (
             $1, $2, $3, $4, $5, $6::jsonb, $7::jsonb, $8::jsonb, $9, $10,
             $11, $12, $13, $14, $15::jsonb, $16::jsonb, $17::jsonb, $18::jsonb,
             $19::jsonb, $20, $21, $22::timestamptz, $23::timestamptz
           )
           RETURNING ${REQUEST_COLUMNS}`,
          [
            record.id,
            ctx.tenantId,
            record.waf_asset_id,
            record.target_group_id,
            record.objective,
            JSON.stringify(record.requested_suites ?? []),
            JSON.stringify(record.emergency_contacts ?? []),
            JSON.stringify(record.requested_window ?? null),
            record.stop_criteria ?? null,
            record.abort_criteria ?? null,
            record.staging_only !== false,
            record.scope_confirmation === true,
            record.state,
            record.created_by ?? null,
            JSON.stringify(record.soc_approvals ?? []),
            JSON.stringify(record.artifacts ?? []),
            JSON.stringify(record.suite_results ?? []),
            JSON.stringify(record.authorization_pack_status ?? {}),
            JSON.stringify(record.scheduled_window ?? null),
            record.scope_hash ?? null,
            record.waf_validation_run_id ?? null,
            record.created_at,
            record.updated_at ?? record.created_at,
          ],
        );
        return mapWafOffensiveRequestRow(rows[0]);
      });
    },

    async listOffensiveRequests(ctx) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${REQUEST_COLUMNS}
           FROM waf_offensive_requests
           WHERE tenant_id = $1
           ORDER BY created_at ASC, id ASC`,
          [ctx.tenantId],
        );
        return rows.map(mapWafOffensiveRequestRow);
      });
    },

    async getOffensiveRequest(ctx, id, options = {}) {
      return runWithTenantClient(pool, ctx.tenantId, options.client, async (client) => {
        const { rows } = await client.query(
          `SELECT ${REQUEST_COLUMNS}
           FROM waf_offensive_requests
           WHERE tenant_id = $1 AND id = $2`,
          [ctx.tenantId, id],
        );
        return mapWafOffensiveRequestRow(rows[0] ?? null);
      });
    },

    async withLockedOffensiveRequest(ctx, id, callback) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${REQUEST_COLUMNS}
           FROM waf_offensive_requests
           WHERE tenant_id = $1 AND id = $2
           FOR UPDATE`,
          [ctx.tenantId, id],
        );
        const request = mapWafOffensiveRequestRow(rows[0] ?? null);
        if (!request) return null;
        return callback(request, { client });
      });
    },

    async saveOffensiveRequest(ctx, record, options = {}) {
      return runWithTenantClient(pool, ctx.tenantId, options.client, async (client) => {
        const { rows } = await client.query(
          `UPDATE waf_offensive_requests
           SET state = $3,
               soc_approvals = $4::jsonb,
               artifacts = $5::jsonb,
               suite_results = $6::jsonb,
               authorization_pack_status = $7::jsonb,
               scheduled_window = $8::jsonb,
               scope_hash = $9,
               waf_validation_run_id = $10,
               rejected_at = $11::timestamptz,
               rejected_by = $12,
               rejection_reason = $13,
               results_recorded_at = $14::timestamptz,
               results_recorded_by = $15,
               updated_at = $16::timestamptz
           WHERE tenant_id = $1 AND id = $2
           RETURNING ${REQUEST_COLUMNS}`,
          [
            ctx.tenantId,
            record.id,
            record.state,
            JSON.stringify(record.soc_approvals ?? []),
            JSON.stringify(record.artifacts ?? []),
            JSON.stringify(record.suite_results ?? []),
            JSON.stringify(record.authorization_pack_status ?? {}),
            JSON.stringify(record.scheduled_window ?? null),
            record.scope_hash ?? null,
            record.waf_validation_run_id ?? null,
            record.rejected_at ?? null,
            record.rejected_by ?? null,
            record.rejection_reason ?? null,
            record.results_recorded_at ?? null,
            record.results_recorded_by ?? null,
            record.updated_at,
          ],
        );
        return mapWafOffensiveRequestRow(rows[0] ?? null);
      });
    },

    async getOffensiveReport(ctx, requestId, options = {}) {
      return runWithTenantClient(pool, ctx.tenantId, options.client, async (client) => {
        const { rows } = await client.query(
          `SELECT ${REPORT_COLUMNS}
           FROM waf_offensive_reports
           WHERE tenant_id = $1 AND waf_offensive_request_id = $2`,
          [ctx.tenantId, requestId],
        );
        return mapWafOffensiveReportRow(rows[0] ?? null);
      });
    },

    async upsertOffensiveReport(ctx, requestId, report, options = {}) {
      return runWithTenantClient(pool, ctx.tenantId, options.client, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO waf_offensive_reports (
             id, tenant_id, waf_offensive_request_id, executive_summary,
             blocking_verdict, bypass_findings, remediation_notes, suite_results,
             created_by, updated_by, created_at, updated_at
           ) VALUES (
             $1, $2, $3, $4, $5, $6::jsonb, $7, $8::jsonb,
             $9, $10, $11::timestamptz, $12::timestamptz
           )
           ON CONFLICT (tenant_id, waf_offensive_request_id)
           DO UPDATE SET
             executive_summary = EXCLUDED.executive_summary,
             blocking_verdict = EXCLUDED.blocking_verdict,
             bypass_findings = EXCLUDED.bypass_findings,
             remediation_notes = EXCLUDED.remediation_notes,
             suite_results = EXCLUDED.suite_results,
             updated_by = EXCLUDED.updated_by,
             updated_at = EXCLUDED.updated_at
           RETURNING ${REPORT_COLUMNS}`,
          [
            report.id,
            ctx.tenantId,
            requestId,
            report.executive_summary ?? null,
            report.blocking_verdict ?? null,
            JSON.stringify(report.bypass_findings ?? []),
            report.remediation_notes ?? null,
            JSON.stringify(report.suite_results ?? []),
            report.created_by ?? null,
            report.updated_by ?? null,
            report.created_at,
            report.updated_at,
          ],
        );
        return mapWafOffensiveReportRow(rows[0]);
      });
    },

    async createOffensiveWafValidationRun(ctx, record, options = {}) {
      return runWithTenantClient(pool, ctx.tenantId, options.client, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO waf_validation_runs (
             id, tenant_id, test_run_id, waf_asset_id, mode, status,
             safety_profile_json, summary_json, created_at,
             execution_class, offensive_request_id
           ) VALUES (
             $1, $2, NULL, $3, $4, $5, $6::jsonb, $7::jsonb,
             $8::timestamptz, $9, $10
           )
           RETURNING ${OFFENSIVE_RUN_COLUMNS}`,
          [
            record.id,
            ctx.tenantId,
            record.waf_asset_id,
            record.mode,
            record.status ?? 'planned',
            JSON.stringify(record.safety_profile_json ?? {}),
            JSON.stringify(record.summary_json ?? {}),
            record.created_at,
            record.execution_class ?? 'offensive_suite',
            record.offensive_request_id,
          ],
        );
        return mapOffensiveWafValidationRunRow(rows[0]);
      });
    },
  };
}
