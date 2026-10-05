import { randomBytes } from 'node:crypto';
import { prepareObservation } from '../../services/targetHistory.mjs';
import { presentFindingLineage } from '../../services/retestLineage.mjs';
import { createTargetHistoryRepository, writeObservation } from './targetHistoryRepository.mjs';
import {
  findingListGroupSql,
  findingListQSql,
  findingSeverityClassSql,
  parseFindingListQuery,
} from '../../lib/findingList.mjs';
import { runWithTenantClient, withTenantContext } from './tenantContext.mjs';

const TEST_RUN_COLUMNS = `id, tenant_id, target_group_id, target_id, policy_id, policy_dispatch_id, scan_id, scan_step_id,
  check_id, created_by, initiated_by, risk_class, safety_class, vector_family, status, probe_external_result, awaiting_external_probe,
  remediation_template, safety_constraints, correlation_json, collection_deadline_at, started_at,
  completed_at, summary_json, created_at, check_version, scenario_version, producer_kind,
  origin_binding_id, retest_of_finding_id, expected_behavior_json, provenance_json`;

const EVENT_COLUMNS = `id, tenant_id, event_id, test_run_id, target_id, check_id, agent_id, source,
  signal_type, producer_kind, nonce_hash, timestamp, metadata_json, ingested_at`;

const EVIDENCE_COLUMNS = `id, tenant_id, test_run_id, label, metadata_json, related_event_id, created_at`;

const VERDICT_COLUMNS = `id, tenant_id, test_run_id, target_id, check_id, verdict, confidence,
  explanation, evidence_ids, placement_confidence_json, created_at`;

const FINDING_COLUMNS = `id, tenant_id, target_group_id, target_id, test_run_id, check_id, title, severity,
  status, evidence_ids, notes, remediation_template, verdict_id, last_verdict_id, assignee,
  created_at, updated_at, closed_at`;

const HISTORY_TIME_SKIPS = new Set([
  'before_declaration', 'future_timestamp', 'declaration_time_unknown', 'invalid_timestamp',
]);

/**
 * Marks whether `createVerdictIfAbsent` actually inserted the verdict row it returned.
 *
 * A Symbol is used deliberately: verdict objects are spread into API responses and
 * JSON-serialized, and a symbol-keyed flag is invisible to `Object.keys`/`JSON.stringify`,
 * so it cannot leak into the wire shape. Absence of the flag must be read as "inserted"
 * so repository doubles that return plain verdict records keep working.
 */
export const VERDICT_INSERTED = Symbol('astranull.verdict.inserted');

/**
 * @param {{ [VERDICT_INSERTED]?: boolean } | null | undefined} verdict
 * @returns {boolean}
 */
export function verdictWasInserted(verdict) {
  if (!verdict) return false;
  return verdict[VERDICT_INSERTED] !== false;
}

const EXPIRED_COLLECTION_SWEEP_STATUSES = Object.freeze(['running', 'collecting']);
const DEFAULT_EXPIRED_COLLECTION_SWEEP_LIMIT = 100;
const MAX_EXPIRED_COLLECTION_SWEEP_LIMIT = 500;

/**
 * Bounded re-read of a verdict the INSERT lost the race for. `ON CONFLICT DO NOTHING`
 * does not wait on a concurrent uncommitted inserter, so the incumbent may not be
 * visible for a moment. 5 x 20ms caps the wait at ~100ms.
 */
const INCUMBENT_VERDICT_READ_ATTEMPTS = 5;
const INCUMBENT_VERDICT_READ_DELAY_MS = 20;

function sleep(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms).unref?.();
  });
}

const DEFAULT_TEST_RUN_LIST_LIMIT = 100;
// docs/api.md GET /v1/test-runs: limit default 100, max 100. Keep Postgres and dev-json aligned.
const MAX_TEST_RUN_LIST_LIMIT = 100;
const DEFAULT_RUN_EVENTS_LIST_LIMIT = 200;
const MAX_RUN_EVENTS_LIST_LIMIT = 1000;
const MAX_RUN_EVIDENCE_BATCH_IDS = 500;
const DEFAULT_EVIDENCE_LIST_LIMIT = 100;
const MAX_EVIDENCE_LIST_LIMIT = 500;

function normalizeBoundedLimit(limit, defaultLimit, maxLimit) {
  if (limit === undefined || limit === null) {
    return defaultLimit;
  }
  const n = Number(limit);
  if (!Number.isFinite(n) || n < 1) {
    return defaultLimit;
  }
  return Math.min(Math.floor(n), maxLimit);
}

function normalizeTestRunListLimit(limit) {
  return normalizeBoundedLimit(limit, DEFAULT_TEST_RUN_LIST_LIMIT, MAX_TEST_RUN_LIST_LIMIT);
}

function normalizeRunEventsListLimit(limit) {
  return normalizeBoundedLimit(limit, DEFAULT_RUN_EVENTS_LIST_LIMIT, MAX_RUN_EVENTS_LIST_LIMIT);
}

const MAX_EVENT_ID_LOOKUP = 32;

function normalizeEventLookupIds(value) {
  if (!Array.isArray(value)) return null;
  const ids = [];
  for (const item of value) {
    if (typeof item !== 'string' || !/^[A-Za-z0-9_.:-]{1,128}$/.test(item) || ids.includes(item)) continue;
    ids.push(item);
    if (ids.length >= MAX_EVENT_ID_LOOKUP) break;
  }
  return ids;
}

function normalizeRunIdBatch(runIds, label) {
  if (!Array.isArray(runIds)) return [];
  const unique = [];
  const seen = new Set();
  for (const value of runIds) {
    const runId = typeof value === 'string' ? value.trim() : '';
    if (!runId || seen.has(runId)) continue;
    seen.add(runId);
    unique.push(runId);
  }
  if (unique.length > MAX_RUN_EVIDENCE_BATCH_IDS) {
    throw new RangeError(`${label} accepts at most ${MAX_RUN_EVIDENCE_BATCH_IDS} run ids.`);
  }
  return unique;
}

function normalizeEvidenceListLimit(limit) {
  return normalizeBoundedLimit(limit, DEFAULT_EVIDENCE_LIST_LIMIT, MAX_EVIDENCE_LIST_LIMIT);
}

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

function mapTestRunRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    target_group_id: row.target_group_id,
    target_id: row.target_id ?? undefined,
    policy_id: row.policy_id ?? null,
    policy_dispatch_id: row.policy_dispatch_id ?? null,
    scan_id: row.scan_id ?? null,
    scan_step_id: row.scan_step_id ?? null,
    check_id: row.check_id,
    created_by: row.created_by ?? undefined,
    initiated_by: row.initiated_by ?? undefined,
    risk_class: row.risk_class ?? undefined,
    safety_class: row.safety_class ?? undefined,
    vector_family: row.vector_family ?? undefined,
    status: row.status,
    probe_external_result: row.probe_external_result ?? undefined,
    awaiting_external_probe: Boolean(row.awaiting_external_probe),
    remediation_template: row.remediation_template ?? undefined,
    safety_constraints: asObject(row.safety_constraints),
    correlation: asObject(row.correlation_json),
    collection_deadline_at:
      row.collection_deadline_at == null ? null : toIso(row.collection_deadline_at),
    started_at: row.started_at == null ? null : toIso(row.started_at),
    completed_at: row.completed_at == null ? null : toIso(row.completed_at),
    summary: asObject(row.summary_json),
    created_at: toIso(row.created_at),
    check_version: row.check_version ?? null,
    scenario_version: row.scenario_version ?? null,
    producer_kind: row.producer_kind ?? null,
    origin_binding_id: row.origin_binding_id ?? null,
    retest_of_finding_id: row.retest_of_finding_id ?? null,
    expected_behavior: expectedBehaviorValue(row),
    expected_behavior_json: row.expected_behavior_json ?? null,
    provenance_json: row.provenance_json ?? null,
  };
}

function expectedBehaviorValue(row) {
  const json = row?.expected_behavior_json;
  if (json && typeof json === 'object' && typeof json.value === 'string') return json.value;
  if (typeof row?.expected_behavior === 'string') return row.expected_behavior;
  return null;
}

function mapEventRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    event_id: row.event_id ?? undefined,
    test_run_id: row.test_run_id ?? undefined,
    target_id: row.target_id ?? undefined,
    check_id: row.check_id ?? undefined,
    agent_id: row.agent_id ?? undefined,
    source: row.source ?? undefined,
    signal_type: row.signal_type ?? undefined,
    producer_kind: row.producer_kind ?? undefined,
    nonce_hash: row.nonce_hash ?? undefined,
    timestamp: toIso(row.timestamp),
    metadata: asObject(row.metadata_json),
    ingested_at: toIso(row.ingested_at) ?? undefined,
  };
}

function mapEvidenceRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    test_run_id: row.test_run_id ?? undefined,
    label: row.label ?? undefined,
    metadata: asObject(row.metadata_json),
    related_event_id: row.related_event_id ?? null,
    created_at: toIso(row.created_at),
  };
}

function mapVerdictRow(row) {
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

function placementConfidenceJson(record) {
  return JSON.stringify(asObject(record.placement_confidence));
}

function mapFindingRow(row) {
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
    assignee: row.assignee ?? null,
    created_at: toIso(row.created_at),
    updated_at: row.updated_at == null ? null : toIso(row.updated_at),
    closed_at: row.closed_at == null ? null : toIso(row.closed_at),
  };
}

function findingCustomerListWhere(tenantId, query) {
  const params = [tenantId];
  const conditions = [];
  let nextIndex = 2;
  const add = (sql, value) => {
    conditions.push(sql);
    params.push(value);
    nextIndex += 1;
  };
  if (query.target_group_id) add(findingListGroupSql(`$${nextIndex}`), query.target_group_id);
  if (query.target_id) add(`f.target_id = $${nextIndex}`, query.target_id);
  if (query.test_run_id) add(`f.test_run_id = $${nextIndex}`, query.test_run_id);
  if (query.check_id) add(`f.check_id = $${nextIndex}`, query.check_id);
  // Stored status is NOT NULL but still trimmed and lowered, matching the
  // effective-row-status read used by the dev store for legacy state rows.
  if (query.status) add(`lower(btrim(f.status)) = $${nextIndex}`, query.status);
  // Severity matches the canonical class of the recorded token, so S1..S4,
  // moderate, and case variants are the same class for queries and rows.
  if (query.severity != null) add(`${findingSeverityClassSql()} = $${nextIndex}`, query.severity_class);
  if (query.q) add(findingListQSql(`$${nextIndex}`), query.q);
  return { conditions, params, nextIndex };
}

/**
 * @param {import('pg').Pool} pool
 */
export function createValidationEvidenceRepository(pool) {
  async function queryEvidenceList(client, tenantId, options = {}) {
    const boundedLimit = normalizeEvidenceListLimit(options.limit);
    const params = [tenantId];
    const conditions = ['tenant_id = $1'];
    let paramIndex = 2;

    if (options.testRunId != null && options.testRunId !== '') {
      conditions.push(`test_run_id = $${paramIndex}`);
      params.push(options.testRunId);
      paramIndex += 1;
    }
    if (options.beforeCreatedAt != null) {
      conditions.push(`created_at < $${paramIndex}::timestamptz`);
      params.push(options.beforeCreatedAt);
      paramIndex += 1;
    }

    params.push(boundedLimit);
    const limitParam = paramIndex;

    const { rows } = await client.query(
      `SELECT ${EVIDENCE_COLUMNS}
       FROM evidence_vault
       WHERE ${conditions.join(' AND ')}
       ORDER BY created_at DESC
       LIMIT $${limitParam}`,
      params,
    );
    return rows;
  }

  return {
    async listTestRuns(ctx, options = {}) {
      const boundedLimit = normalizeTestRunListLimit(options.limit);
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const params = [ctx.tenantId];
        const conditions = ['tenant_id = $1'];
        let paramIndex = 2;

        if (options.targetGroupId != null && options.targetGroupId !== '') {
          conditions.push(`target_group_id = $${paramIndex}`);
          params.push(options.targetGroupId);
          paramIndex += 1;
        }
        if (options.targetId != null && options.targetId !== '') {
          conditions.push(`target_id = $${paramIndex}`);
          params.push(options.targetId);
          paramIndex += 1;
        }
        if (options.checkId != null && options.checkId !== '') {
          conditions.push(`check_id = $${paramIndex}`);
          params.push(options.checkId);
          paramIndex += 1;
        }
        if (Array.isArray(options.statuses) && options.statuses.length > 0) {
          conditions.push(`status = ANY($${paramIndex})`);
          params.push(options.statuses);
          paramIndex += 1;
        }
        if (options.beforeCreatedAt != null) {
          conditions.push(`created_at < $${paramIndex}::timestamptz`);
          params.push(options.beforeCreatedAt);
          paramIndex += 1;
        }

        params.push(boundedLimit);
        const limitParam = paramIndex;

        const { rows } = await client.query(
          `SELECT ${TEST_RUN_COLUMNS}
           FROM test_runs
           WHERE ${conditions.join(' AND ')}
           ORDER BY COALESCE(started_at, created_at) DESC, id DESC
           LIMIT $${limitParam}`,
          params,
        );
        return rows.map(mapTestRunRow);
      });
    },

    async getTestRun(ctx, id, options = {}) {
      return runWithTenantClient(pool, ctx.tenantId, options.client, async (client) => {
        const { rows } = await client.query(
          `SELECT ${TEST_RUN_COLUMNS}
           FROM test_runs
           WHERE tenant_id = $1 AND id = $2`,
          [ctx.tenantId, id],
        );
        return mapTestRunRow(rows[0] ?? null);
      });
    },

    async getTestRunByPolicyDispatchId(ctx, policyDispatchId) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${TEST_RUN_COLUMNS}
           FROM test_runs
           WHERE tenant_id = $1 AND policy_dispatch_id = $2
           LIMIT 1`,
          [ctx.tenantId, policyDispatchId],
        );
        return mapTestRunRow(rows[0] ?? null);
      });
    },

    async getTestRunByScanStepId(ctx, scanStepId, options = {}) {
      return runWithTenantClient(pool, ctx.tenantId, options.client, async (client) => {
        const { rows } = await client.query(
          `SELECT ${TEST_RUN_COLUMNS}
           FROM test_runs
           WHERE tenant_id = $1 AND scan_step_id = $2
           LIMIT 1`,
          [ctx.tenantId, scanStepId],
        );
        return mapTestRunRow(rows[0] ?? null);
      });
    },

    async listTestRunsByIds(ctx, runIds, options = {}) {
      const ids = normalizeRunIdBatch(runIds, 'listTestRunsByIds.runIds');
      if (ids.length === 0) return [];
      return runWithTenantClient(pool, ctx.tenantId, options.client, async (client) => {
        const { rows } = await client.query(
          `SELECT ${TEST_RUN_COLUMNS}
           FROM test_runs
           WHERE tenant_id = $1 AND id = ANY($2::text[])`,
          [ctx.tenantId, ids],
        );
        return rows.map(mapTestRunRow);
      });
    },

    async createTestRun(ctx, record) {
      const tenantId = ctx.tenantId;
      const safetyConstraints = JSON.stringify(asObject(record.safety_constraints));
      const correlationJson = JSON.stringify(
        asObject(record.correlation ?? record.correlation_json),
      );
      const summaryJson = JSON.stringify(asObject(record.summary ?? record.summary_json));

      return withTenantContext(pool, tenantId, async (client) => {
        if (record.retest_of_finding_id) {
          const finding = await client.query(
            `SELECT id, target_id, check_id FROM findings WHERE tenant_id = $1 AND id = $2`,
            [tenantId, record.retest_of_finding_id],
          );
          const row = finding.rows[0];
          if (!row) return { error: 'unknown_finding', status: 404 };
          if (row.target_id !== record.target_id || row.check_id !== record.check_id) {
            return { error: 'pair_mismatch', status: 409 };
          }
        }
        if (record.origin_binding_id) {
          const binding = await client.query(
            `SELECT id, status, origin_target_id FROM origin_bindings WHERE tenant_id = $1 AND id = $2`,
            [tenantId, record.origin_binding_id],
          );
          const row = binding.rows[0];
          if (!row || row.status !== 'active' || row.origin_target_id !== record.target_id) {
            return { error: 'origin_binding_invalid', status: 409 };
          }
        }
        const { rows } = await client.query(
          `INSERT INTO test_runs (
             id, tenant_id, target_group_id, target_id, policy_id, policy_dispatch_id, scan_id, scan_step_id,
             check_id, created_by, initiated_by,
             risk_class, safety_class, vector_family, status, probe_external_result,
             awaiting_external_probe, remediation_template, safety_constraints, correlation_json,
             collection_deadline_at, started_at, completed_at, summary_json, created_at,
             check_version, scenario_version, producer_kind, origin_binding_id, retest_of_finding_id,
             expected_behavior_json, provenance_json
           )
           VALUES (
             $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19::jsonb, $20::jsonb,
             $21::timestamptz, $22::timestamptz, $23::timestamptz, $24::jsonb, $25::timestamptz,
             $26, $27, $28, $29, $30, $31::jsonb, $32::jsonb
           )
           RETURNING ${TEST_RUN_COLUMNS}`,
          [
            record.id,
            tenantId,
            record.target_group_id,
            record.target_id ?? null,
            record.policy_id ?? null,
            record.policy_dispatch_id ?? null,
            record.scan_id ?? null,
            record.scan_step_id ?? null,
            record.check_id,
            record.created_by ?? null,
            record.initiated_by ?? null,
            record.risk_class ?? null,
            record.safety_class ?? null,
            record.vector_family ?? null,
            record.status,
            record.probe_external_result ?? null,
            record.awaiting_external_probe ?? false,
            record.remediation_template ?? null,
            safetyConstraints,
            correlationJson,
            record.collection_deadline_at ?? null,
            record.started_at ?? null,
            record.completed_at ?? null,
            summaryJson,
            record.created_at,
            record.check_version ?? null,
            record.scenario_version ?? null,
            record.producer_kind ?? null,
            record.origin_binding_id ?? null,
            record.retest_of_finding_id ?? null,
            record.expected_behavior_json == null ? null : JSON.stringify(record.expected_behavior_json),
            record.provenance_json == null ? null : JSON.stringify(record.provenance_json),
          ],
        );
        const run = mapTestRunRow(rows[0]);
        if (record.retest_of_finding_id) {
          await client.query(
            `INSERT INTO finding_retest_lineage (
               id, tenant_id, finding_id, test_run_id, target_id, check_id, intent, relation, created_by, created_at
             ) VALUES ($1, $2, $3, $4, $5, $6, 'retest', 'retest', $7, $8::timestamptz)
             ON CONFLICT (tenant_id, finding_id, test_run_id) DO NOTHING`,
            [
              record.lineage_id ?? `rtln_${randomBytes(8).toString('hex')}`,
              tenantId,
              record.retest_of_finding_id,
              record.id,
              record.target_id,
              record.check_id,
              record.created_by ?? null,
              record.created_at,
            ],
          );
        }
        return run;
      });
    },

    async updateTestRun(ctx, id, patch, options = {}) {
      return runWithTenantClient(pool, ctx.tenantId, options.client, async (client) => {
        const sets = [];
        const params = [];
        let paramIndex = 1;

        if (patch.status !== undefined) {
          sets.push(`status = $${paramIndex}`);
          params.push(patch.status);
          paramIndex += 1;
        }
        if (patch.probe_external_result !== undefined) {
          sets.push(`probe_external_result = $${paramIndex}`);
          params.push(patch.probe_external_result);
          paramIndex += 1;
        }
        if (patch.awaiting_external_probe !== undefined) {
          sets.push(`awaiting_external_probe = $${paramIndex}`);
          params.push(patch.awaiting_external_probe);
          paramIndex += 1;
        }
        if (patch.correlation !== undefined) {
          sets.push(`correlation_json = $${paramIndex}::jsonb`);
          params.push(JSON.stringify(asObject(patch.correlation)));
          paramIndex += 1;
        }
        if (patch.collection_deadline_at !== undefined) {
          sets.push(`collection_deadline_at = $${paramIndex}::timestamptz`);
          params.push(patch.collection_deadline_at);
          paramIndex += 1;
        }
        if (patch.completed_at !== undefined) {
          sets.push(`completed_at = $${paramIndex}::timestamptz`);
          params.push(patch.completed_at);
          paramIndex += 1;
        }
        if (patch.summary !== undefined) {
          sets.push(`summary_json = $${paramIndex}::jsonb`);
          params.push(JSON.stringify(asObject(patch.summary)));
          paramIndex += 1;
        }
        if (patch.safety_constraints !== undefined) {
          sets.push(`safety_constraints = $${paramIndex}::jsonb`);
          params.push(JSON.stringify(asObject(patch.safety_constraints)));
          paramIndex += 1;
        }

        if (sets.length === 0) {
          const { rows } = await client.query(
            `SELECT ${TEST_RUN_COLUMNS}
             FROM test_runs
             WHERE tenant_id = $1 AND id = $2`,
            [ctx.tenantId, id],
          );
          return mapTestRunRow(rows[0] ?? null);
        }

        const expectedStatuses = Array.isArray(patch.expected_statuses)
          ? patch.expected_statuses.filter((status) => typeof status === 'string' && status)
          : [];
        let expectedStatusesParam = null;
        if (expectedStatuses.length > 0) {
          expectedStatusesParam = paramIndex;
          params.push(expectedStatuses);
          paramIndex += 1;
        }
        params.push(ctx.tenantId, id);
        const tenantParam = paramIndex;
        const idParam = paramIndex + 1;

        const { rows } = await client.query(
          `UPDATE test_runs
           SET ${sets.join(', ')}
           WHERE tenant_id = $${tenantParam} AND id = $${idParam}
             ${expectedStatusesParam ? `AND status = ANY($${expectedStatusesParam}::text[])` : ''}
           RETURNING ${TEST_RUN_COLUMNS}`,
          params,
        );
        return mapTestRunRow(rows[0] ?? null);
      });
    },

    async cancelTestRunAtomic(ctx, id, patch = {}) {
      const tenantId = ctx.tenantId;
      const completedAt = patch.completed_at ?? new Date().toISOString();
      return withTenantContext(pool, tenantId, async (client) => {
        await client.query(
          'SELECT pg_advisory_xact_lock(hashtext($1))',
          [`test_run_mutation:${id}`],
        );
        const selected = await client.query(
          `SELECT ${TEST_RUN_COLUMNS}
           FROM test_runs
           WHERE tenant_id = $1 AND id = $2
           FOR UPDATE`,
          [tenantId, id],
        );
        const current = mapTestRunRow(selected.rows[0] ?? null);
        if (!current) return null;
        if (!EXPIRED_COLLECTION_SWEEP_STATUSES.includes(current.status)
          && current.status !== 'planned') {
          return { run: current, cancelled: false, cancelled_jobs: [] };
        }

        const baseSummary = patch.summary === undefined
          ? current.summary
          : asObject(patch.summary);
        const merged = patch.summary_merge === undefined
          ? baseSummary
          : { ...asObject(baseSummary), ...asObject(patch.summary_merge) };
        const summary = patch.cancellation === undefined
          ? merged
          : {
            ...asObject(merged),
            cancellation: {
              ...asObject(patch.cancellation),
              scan_id: patch.cancellation?.scan_id ?? current.scan_id ?? null,
            },
          };
        const updated = await client.query(
          `UPDATE test_runs
           SET status = 'cancelled', completed_at = $3::timestamptz, summary_json = $4::jsonb
           WHERE tenant_id = $1 AND id = $2
           RETURNING ${TEST_RUN_COLUMNS}`,
          [tenantId, id, completedAt, JSON.stringify(summary)],
        );
        const cancelledJobs = await client.query(
          `UPDATE probe_jobs
           SET status = 'cancelled', completed_at = $3::timestamptz
           WHERE tenant_id = $1 AND test_run_id = $2
             AND ownership_verification_id IS NULL
             AND status IN ('pending', 'leased')
           RETURNING id, test_run_id`,
          [tenantId, id, completedAt],
        );
        return {
          run: mapTestRunRow(updated.rows[0]),
          cancelled: true,
          cancelled_jobs: cancelledJobs.rows,
        };
      });
    },

    async appendEvent(ctx, record, options = {}) {
      const tenantId = ctx.tenantId;
      const metadataJson = JSON.stringify(asObject(record.metadata ?? record.metadata_json));

      return runWithTenantClient(pool, tenantId, options.client, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO events (
             id, tenant_id, event_id, test_run_id, target_id, check_id, agent_id, source,
             signal_type, producer_kind, nonce_hash, timestamp, metadata_json
           )
           VALUES (
             $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::timestamptz, $13::jsonb
           )
           RETURNING ${EVENT_COLUMNS}`,
          [
            record.id,
            tenantId,
            record.event_id ?? null,
            record.test_run_id ?? null,
            record.target_id ?? null,
            record.check_id ?? null,
            record.agent_id ?? null,
            record.source ?? null,
            record.signal_type ?? null,
            record.producer_kind ?? 'legacy_untrusted',
            record.nonce_hash ?? null,
            record.timestamp,
            metadataJson,
          ],
        );
        return mapEventRow(rows[0]);
      });
    },

    async appendEventIdempotent(ctx, record) {
      if (record.event_id == null || record.event_id === '') {
        throw new Error(
          'appendEventIdempotent requires record.event_id; use appendEvent for non-idempotent local events',
        );
      }

      const tenantId = ctx.tenantId;
      const metadataJson = JSON.stringify(asObject(record.metadata ?? record.metadata_json));

      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO events (
             id, tenant_id, event_id, test_run_id, target_id, check_id, agent_id, source,
             signal_type, producer_kind, nonce_hash, timestamp, metadata_json
           )
           VALUES (
             $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::timestamptz, $13::jsonb
           )
           ON CONFLICT (tenant_id, event_id) WHERE event_id IS NOT NULL
           DO UPDATE SET
             test_run_id = EXCLUDED.test_run_id,
             target_id = EXCLUDED.target_id,
             check_id = EXCLUDED.check_id,
             agent_id = EXCLUDED.agent_id,
             source = EXCLUDED.source,
             signal_type = EXCLUDED.signal_type,
             producer_kind = EXCLUDED.producer_kind,
             nonce_hash = EXCLUDED.nonce_hash,
             timestamp = EXCLUDED.timestamp,
             metadata_json = EXCLUDED.metadata_json
           RETURNING ${EVENT_COLUMNS}`,
          [
            record.id,
            tenantId,
            record.event_id,
            record.test_run_id ?? null,
            record.target_id ?? null,
            record.check_id ?? null,
            record.agent_id ?? null,
            record.source ?? null,
            record.signal_type ?? null,
            record.producer_kind ?? 'legacy_untrusted',
            record.nonce_hash ?? null,
            record.timestamp,
            metadataJson,
          ],
        );
        return mapEventRow(rows[0]);
      });
    },

    async findEventByTenantEventId(ctx, eventId) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${EVENT_COLUMNS}
           FROM events
           WHERE tenant_id = $1 AND event_id = $2`,
          [ctx.tenantId, eventId],
        );
        return mapEventRow(rows[0] ?? null);
      });
    },

    async listRunEvents(ctx, runId, options = {}) {
      const lookupIds = normalizeEventLookupIds(options.ids);
      return runWithTenantClient(pool, ctx.tenantId, options.client, async (client) => {
        if (lookupIds) {
          if (lookupIds.length === 0) return [];
          const params = [ctx.tenantId, runId, lookupIds];
          const conditions = [
            'tenant_id = $1',
            'test_run_id = $2',
            '(id = ANY($3::text[]) OR event_id = ANY($3::text[]))',
          ];
          let paramIndex = 4;
          if (typeof options.target_id === 'string' && options.target_id !== '') {
            conditions.push(`target_id = $${paramIndex}`);
            params.push(options.target_id);
            paramIndex += 1;
          }
          if (typeof options.check_id === 'string' && options.check_id !== '') {
            conditions.push(`check_id = $${paramIndex}`);
            params.push(options.check_id);
            paramIndex += 1;
          }
          params.push(lookupIds.length);
          const { rows } = await client.query(
            `SELECT ${EVENT_COLUMNS}
             FROM events
             WHERE ${conditions.join(' AND ')}
             ORDER BY timestamp
             LIMIT $${paramIndex}`,
            params,
          );
          return rows.map(mapEventRow);
        }

        const boundedLimit = normalizeRunEventsListLimit(options.limit);
        const params = [ctx.tenantId, runId];
        const conditions = ['tenant_id = $1', 'test_run_id = $2'];
        let paramIndex = 3;

        if (options.signalType != null && options.signalType !== '') {
          conditions.push(`signal_type = $${paramIndex}`);
          params.push(options.signalType);
          paramIndex += 1;
        }
        if (options.beforeTimestamp != null) {
          conditions.push(`timestamp < $${paramIndex}::timestamptz`);
          params.push(options.beforeTimestamp);
          paramIndex += 1;
        }

        params.push(boundedLimit);
        const limitParam = paramIndex;

        const { rows } = await client.query(
          `SELECT ${EVENT_COLUMNS}
           FROM events
           WHERE ${conditions.join(' AND ')}
           ORDER BY timestamp
           LIMIT $${limitParam}`,
          params,
        );
        return rows.map(mapEventRow);
      });
    },


    /**
     * Load the state-readiness verdict/event slice without per-run repository calls.
     *
     * Both parameterized statements use one tenant transaction client. Verdict selection is
     * deterministic even for restored pre-uniqueness data: the newest `(created_at, id)` wins
     * for each requested run, while results retain requested-run order. Event rows preserve the
     * existing oldest-first per-run order and the existing 1,000-row per-run ceiling. The caller
     * remains responsible for trusted-producer filtering.
     */
    async loadRunEvidenceBatch(ctx, selection = {}, options = {}) {
      const runIds = normalizeRunIdBatch(selection.runIds, 'loadRunEvidenceBatch.runIds');
      const baseEventRunIds = normalizeRunIdBatch(
        selection.eventRunIds,
        'loadRunEvidenceBatch.eventRunIds',
      );
      const eventLimitPerRun = normalizeRunEventsListLimit(selection.eventLimitPerRun);

      return runWithTenantClient(pool, ctx.tenantId, options.client, async (client) => {
        let verdicts = [];
        if (runIds.length > 0) {
          const { rows } = await client.query(
            `WITH selected(run_id, ordinal) AS (
               SELECT run_id, ordinal
               FROM unnest($2::text[]) WITH ORDINALITY AS requested(run_id, ordinal)
             )
             SELECT latest.*
             FROM selected
             JOIN LATERAL (
               SELECT ${VERDICT_COLUMNS}
               FROM verdicts
               WHERE tenant_id = $1 AND test_run_id = selected.run_id
               ORDER BY created_at DESC, id DESC
               LIMIT 1
             ) latest ON TRUE
             ORDER BY selected.ordinal`,
            [ctx.tenantId, runIds],
          );
          verdicts = rows.map(mapVerdictRow);
        }

        const eventRunIds = new Set(baseEventRunIds);
        for (const verdict of verdicts) {
          if (verdict.evidence_ids.length > 0) eventRunIds.add(verdict.test_run_id);
        }
        if (eventRunIds.size > MAX_RUN_EVIDENCE_BATCH_IDS) {
          throw new RangeError(
            `loadRunEvidenceBatch event selection accepts at most ${MAX_RUN_EVIDENCE_BATCH_IDS} run ids.`,
          );
        }

        let events = [];
        if (eventRunIds.size > 0) {
          const orderedEventRunIds = [...baseEventRunIds];
          const orderedEventRunIdSet = new Set(orderedEventRunIds);
          for (const runId of runIds) {
            if (eventRunIds.has(runId) && !orderedEventRunIdSet.has(runId)) {
              orderedEventRunIds.push(runId);
              orderedEventRunIdSet.add(runId);
            }
          }
          const { rows } = await client.query(
            `WITH selected(run_id, ordinal) AS (
               SELECT run_id, ordinal
               FROM unnest($2::text[]) WITH ORDINALITY AS requested(run_id, ordinal)
             ), ranked AS (
               SELECT events.*, selected.ordinal,
                      ROW_NUMBER() OVER (
                        PARTITION BY events.test_run_id
                        ORDER BY events.timestamp
                      ) AS per_run_position
               FROM selected
               JOIN events
                 ON events.tenant_id = $1
                AND events.test_run_id = selected.run_id
             )
             SELECT ${EVENT_COLUMNS}
             FROM ranked
             WHERE per_run_position <= $3
             ORDER BY ordinal, timestamp`,
            [ctx.tenantId, orderedEventRunIds, eventLimitPerRun],
          );
          events = rows.map(mapEventRow);
        }

        return { verdicts, events };
      });
    },

    async appendProbeResultEventIdempotent(ctx, record, options = {}) {
      if (record.test_run_id == null || record.test_run_id === '') {
        throw new Error('appendProbeResultEventIdempotent requires record.test_run_id');
      }
      if (record.nonce_hash == null || record.nonce_hash === '') {
        throw new Error('appendProbeResultEventIdempotent requires record.nonce_hash');
      }
      if (
        record.signal_type != null &&
        record.signal_type !== '' &&
        record.signal_type !== 'probe_result'
      ) {
        throw new Error(
          'appendProbeResultEventIdempotent only accepts signal_type probe_result',
        );
      }

      const tenantId = ctx.tenantId;
      const metadataJson = JSON.stringify(asObject(record.metadata ?? record.metadata_json));
      const signalType = 'probe_result';

      return runWithTenantClient(pool, tenantId, options.client, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO events (
             id, tenant_id, event_id, test_run_id, target_id, check_id, agent_id, source,
             signal_type, producer_kind, nonce_hash, timestamp, metadata_json
           )
           VALUES (
             $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::timestamptz, $13::jsonb
           )
           ON CONFLICT (tenant_id, test_run_id, signal_type, nonce_hash)
             WHERE signal_type = 'probe_result' AND nonce_hash IS NOT NULL
           DO UPDATE SET
             event_id = COALESCE(EXCLUDED.event_id, events.event_id),
             target_id = EXCLUDED.target_id,
             check_id = EXCLUDED.check_id,
             agent_id = EXCLUDED.agent_id,
             source = EXCLUDED.source,
             producer_kind = EXCLUDED.producer_kind,
             timestamp = EXCLUDED.timestamp,
             metadata_json = EXCLUDED.metadata_json
           WHERE events.target_id IS NOT DISTINCT FROM EXCLUDED.target_id
             AND events.check_id IS NOT DISTINCT FROM EXCLUDED.check_id
             AND (
               events.metadata_json->>'probe_job_id' IS NULL
               OR events.metadata_json->>'probe_job_id'
                 = EXCLUDED.metadata_json->>'probe_job_id'
             )
           RETURNING ${EVENT_COLUMNS}`,
          [
            record.id,
            tenantId,
            record.event_id ?? null,
            record.test_run_id,
            record.target_id ?? null,
            record.check_id ?? null,
            record.agent_id ?? null,
            record.source ?? null,
            signalType,
            record.producer_kind ?? 'signed_probe',
            record.nonce_hash,
            record.timestamp,
            metadataJson,
          ],
        );
        return mapEventRow(rows[0]);
      });
    },

    /**
     * Refresh the durable WAF/CDN edge detection for a target.
     *
     * Postgres twin of `src/services/targetEdgeDetectionStore.mjs`. Runs on the probe-ingest
     * transaction client so the detection and the probe event it was derived from commit or
     * roll back together. `uniq_target_edge_detection_target` keeps exactly one current row
     * per (tenant_id, target_id); a re-run updates in place.
     *
     * Column values must come from `edgeDetectionRowFields()` — label-only evidence, never raw
     * headers, cookies, or block-page bodies.
     */
    async upsertTargetEdgeDetection(ctx, record, options = {}) {
      const tenantId = ctx.tenantId;
      if (
        !tenantId
        || !record?.id
        || !record?.target_id
        || !record?.target_group_id
        || !record?.test_run_id
      ) return null;

      return runWithTenantClient(pool, tenantId, options.client, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO target_edge_detections (
             id, tenant_id, target_group_id, target_id, test_run_id, status, reason,
             waf_status, waf_vendor, waf_type, waf_providers,
             cdn_status, cdn_provider, cdn_type, cdn_providers,
             confidence, conflicting_vendor_signals, corpus_version, evidence_json, observed_at,
             cloud_status, cloud_provider
           )
           SELECT
             $1, $2, authoritative_run.target_group_id, authoritative_run.target_id,
             authoritative_run.id, $6, $7,
             $8, $9, $10, $11,
             $12, $13, $14, $15,
             $16, $17, $18, $19::jsonb, $20::timestamptz,
             $21, $22
           FROM test_runs authoritative_run
           JOIN targets authoritative_target
             ON authoritative_target.tenant_id = authoritative_run.tenant_id
            AND authoritative_target.target_group_id = authoritative_run.target_group_id
            AND authoritative_target.id = authoritative_run.target_id
           WHERE authoritative_run.tenant_id = $2
             AND authoritative_run.id = $5
             AND authoritative_run.target_group_id = $3
             AND authoritative_run.target_id = $4
             AND ($20::timestamptz IS NULL OR authoritative_target.created_at <= $20::timestamptz)
           ON CONFLICT (tenant_id, target_id) DO UPDATE SET
             test_run_id = EXCLUDED.test_run_id,
             status = EXCLUDED.status,
             reason = EXCLUDED.reason,
             waf_status = EXCLUDED.waf_status,
             waf_vendor = EXCLUDED.waf_vendor,
             waf_type = EXCLUDED.waf_type,
             waf_providers = EXCLUDED.waf_providers,
             cdn_status = EXCLUDED.cdn_status,
             cdn_provider = EXCLUDED.cdn_provider,
             cdn_type = EXCLUDED.cdn_type,
             cdn_providers = EXCLUDED.cdn_providers,
             cloud_status = EXCLUDED.cloud_status,
             cloud_provider = EXCLUDED.cloud_provider,
             confidence = EXCLUDED.confidence,
             conflicting_vendor_signals = EXCLUDED.conflicting_vendor_signals,
             corpus_version = EXCLUDED.corpus_version,
             evidence_json = EXCLUDED.evidence_json,
             observed_at = EXCLUDED.observed_at,
             updated_at = NOW()
           WHERE target_edge_detections.target_group_id = EXCLUDED.target_group_id
             AND target_edge_detections.target_id = EXCLUDED.target_id
           RETURNING id, target_id, target_group_id, status, updated_at`,
          [
            record.id,
            tenantId,
            record.target_group_id,
            record.target_id,
            record.test_run_id ?? null,
            record.status ?? 'inconclusive',
            record.reason ?? null,
            record.waf_status ?? 'inconclusive',
            record.waf_vendor ?? null,
            record.waf_type ?? null,
            Array.isArray(record.waf_providers) ? record.waf_providers : [],
            record.cdn_status ?? 'inconclusive',
            record.cdn_provider ?? null,
            record.cdn_type ?? null,
            Array.isArray(record.cdn_providers) ? record.cdn_providers : [],
            Number(record.confidence) || 0,
            record.conflicting_vendor_signals === true,
            record.corpus_version ?? null,
            JSON.stringify(asObject(record.evidence_json)),
            record.observed_at ?? null,
            ['detected', 'not_detected', 'inconclusive'].includes(record.cloud_status)
              ? record.cloud_status
              : 'inconclusive',
            record.cloud_status === 'detected' ? record.cloud_provider ?? null : null,
          ],
        );
        return rows[0] ?? null;
      });
    },

    async appendEvidence(ctx, record, options = {}) {
      const tenantId = ctx.tenantId;
      const metadataJson = JSON.stringify(asObject(record.metadata ?? record.metadata_json));

      return runWithTenantClient(pool, tenantId, options.client, async (client) => {
        if (options.idempotentByRelatedEvent === true) {
          if (record.related_event_id == null || record.related_event_id === '') {
            throw new Error(
              'appendEvidence idempotentByRelatedEvent requires record.related_event_id',
            );
          }
          const identity = [
            tenantId,
            record.test_run_id ?? null,
            record.label ?? null,
            record.related_event_id,
          ];
          await client.query(
            'SELECT pg_advisory_xact_lock(hashtextextended($1, 0))',
            [`evidence_related_event:${JSON.stringify(identity)}`],
          );
          const existing = await client.query(
            `SELECT ${EVIDENCE_COLUMNS}
             FROM evidence_vault
             WHERE tenant_id = $1
               AND test_run_id IS NOT DISTINCT FROM $2
               AND label IS NOT DISTINCT FROM $3
               AND related_event_id = $4
             ORDER BY created_at
             LIMIT 1`,
            identity,
          );
          if (existing.rows[0]) return mapEvidenceRow(existing.rows[0]);
        }

        const { rows } = await client.query(
          `INSERT INTO evidence_vault (
             id, tenant_id, test_run_id, label, metadata_json, related_event_id, created_at
           )
           VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7::timestamptz)
           RETURNING ${EVIDENCE_COLUMNS}`,
          [
            record.id,
            tenantId,
            record.test_run_id ?? null,
            record.label ?? null,
            metadataJson,
            record.related_event_id ?? null,
            record.created_at,
          ],
        );
        return mapEvidenceRow(rows[0]);
      });
    },

    async listEvidence(ctx, options = {}) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const rows = await queryEvidenceList(client, ctx.tenantId, options);
        return rows.map(mapEvidenceRow);
      });
    },

    async listEvidenceForRun(ctx, runId, options = {}) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const rows = await queryEvidenceList(client, ctx.tenantId, {
          ...options,
          testRunId: runId,
        });
        return rows.map(mapEvidenceRow);
      });
    },

    async getEvidence(ctx, id) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${EVIDENCE_COLUMNS}
           FROM evidence_vault
           WHERE tenant_id = $1 AND id = $2`,
          [ctx.tenantId, id],
        );
        return mapEvidenceRow(rows[0] ?? null);
      });
    },

    /** Current raw edge row. Family columns stay separate; callers must not copy waf_vendor onto CDN. */
    async getTargetEdgeDetection(ctx, targetId) {
      if (!ctx?.tenantId || !targetId) return null;
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT id, tenant_id, target_group_id, target_id, test_run_id, status, reason,
                  waf_status, waf_vendor, waf_type, waf_providers,
                  cdn_status, cdn_provider, cdn_type, cdn_providers,
                  confidence, conflicting_vendor_signals, corpus_version, evidence_json, observed_at
           FROM target_edge_detections
           WHERE tenant_id = $1 AND target_id = $2
           LIMIT 1`,
          [ctx.tenantId, targetId],
        );
        const row = rows[0];
        if (!row) return null;
        return {
          ...row,
          evidence_json: asObject(row.evidence_json),
          observed_at: toIso(row.observed_at),
          waf_providers: Array.isArray(row.waf_providers) ? row.waf_providers : [],
          cdn_providers: Array.isArray(row.cdn_providers) ? row.cdn_providers : [],
        };
      });
    },

    async createVerdict(ctx, record) {
      const tenantId = ctx.tenantId;
      const evidenceIds = asStringArray(record.evidence_ids);
      const placementJson = placementConfidenceJson(record);

      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO verdicts (
             id, tenant_id, test_run_id, target_id, check_id, verdict, confidence,
             explanation, evidence_ids, placement_confidence_json, created_at
           )
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11::timestamptz)
           RETURNING ${VERDICT_COLUMNS}`,
          [
            record.id,
            tenantId,
            record.test_run_id,
            record.target_id ?? null,
            record.check_id ?? null,
            record.verdict,
            record.confidence ?? null,
            record.explanation ?? null,
            evidenceIds,
            placementJson,
            record.created_at,
          ],
        );
        return mapVerdictRow(rows[0]);
      });
    },

    /**
     * Insert a verdict only if the run has none yet.
     *
     * A published verdict is immutable: `uniq_verdict_per_test_run` is the arbiter and the
     * conflict path is DO NOTHING, never DO UPDATE. A replayed or concurrent finalization
     * therefore cannot rewrite an already-stored verdict — it gets the incumbent back,
     * tagged with `VERDICT_INSERTED === false` so callers can skip the side effects
     * (run status update, audit append, finding upsert) that belong to the winner only.
     *
     * @returns {Promise<object>} the stored verdict, never null
     */
    async createVerdictIfAbsent(ctx, record, options = {}) {
      const tenantId = ctx.tenantId;
      const evidenceIds = asStringArray(record.evidence_ids);
      const placementJson = placementConfidenceJson(record);

      return runWithTenantClient(pool, tenantId, options.client, async (client) => {
        if (options.mutationLocksHeld !== true) {
          await client.query(
            'SELECT pg_advisory_xact_lock(hashtext($1))',
            [`test_run_mutation:${record.test_run_id}`],
          );
          await client.query(
            'SELECT pg_advisory_xact_lock(hashtext($1))',
            [`kill_switch_state:${tenantId}`],
          );
        }
        const killSwitchResult = await client.query(
          `SELECT active FROM soc_kill_switch WHERE tenant_id = $1`,
          [tenantId],
        );
        if (killSwitchResult.rows[0]?.active === true) return null;
        const runResult = await client.query(
          `SELECT status
           FROM test_runs
           WHERE tenant_id = $1 AND id = $2
           FOR UPDATE`,
          [tenantId, record.test_run_id],
        );
        const runStatus = runResult.rows[0]?.status ?? null;
        if (!['running', 'collecting', 'verdicted'].includes(runStatus)) return null;

        const { rows } = await client.query(
          `INSERT INTO verdicts (
             id, tenant_id, test_run_id, target_id, check_id, verdict, confidence,
             explanation, evidence_ids, placement_confidence_json, created_at
           )
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11::timestamptz)
           ON CONFLICT (test_run_id) DO NOTHING
           RETURNING ${VERDICT_COLUMNS}`,
          [
            record.id,
            tenantId,
            record.test_run_id,
            record.target_id ?? null,
            record.check_id ?? null,
            record.verdict,
            record.confidence ?? null,
            record.explanation ?? null,
            evidenceIds,
            placementJson,
            record.created_at,
          ],
        );

        if (rows[0]) {
          await client.query(
            `UPDATE test_runs
             SET status = 'verdicted', completed_at = $3::timestamptz
             WHERE tenant_id = $1 AND id = $2
               AND status IN ('running', 'collecting')`,
            [tenantId, record.test_run_id, record.created_at],
          );
          const inserted = mapVerdictRow(rows[0]);
          inserted[VERDICT_INSERTED] = true;
          return inserted;
        }

        // DO NOTHING suppressed the insert: a verdict already exists for this run.
        // Unlike DO UPDATE, DO NOTHING does not block on a concurrent uncommitted
        // inserter, so the incumbent can be briefly invisible to us. Re-read under
        // READ COMMITTED (each statement takes a fresh snapshot) until it lands.
        for (let attempt = 0; attempt < INCUMBENT_VERDICT_READ_ATTEMPTS; attempt += 1) {
          if (attempt > 0) {
            await sleep(INCUMBENT_VERDICT_READ_DELAY_MS);
          }
          const { rows: incumbentRows } = await client.query(
            `SELECT ${VERDICT_COLUMNS}
               FROM verdicts
              WHERE tenant_id = $1 AND test_run_id = $2`,
            [tenantId, record.test_run_id],
          );
          if (incumbentRows[0]) {
            const incumbent = mapVerdictRow(incumbentRows[0]);
            incumbent[VERDICT_INSERTED] = false;
            return incumbent;
          }
        }

        // Fail loudly rather than returning null: every caller dereferences the result.
        throw new Error(
          `createVerdictIfAbsent: verdict for test_run_id=${record.test_run_id} conflicted `
          + 'but the incumbent row is not visible to this tenant context.',
        );
      });
    },

    /**
     * Runs whose bounded collection window has elapsed but which never reached a verdict.
     * Tenant-scoped by design: the sweeper must be given an explicit tenant list, since
     * cross-tenant enumeration is refused under RLS.
     *
     * @param {{ tenantId: string }} ctx
     * @param {{ limit?: number, now?: string | null }} [options]
     */
    async listExpiredCollectingRuns(ctx, options = {}) {
      const limit = normalizeBoundedLimit(
        options.limit,
        DEFAULT_EXPIRED_COLLECTION_SWEEP_LIMIT,
        MAX_EXPIRED_COLLECTION_SWEEP_LIMIT,
      );
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${TEST_RUN_COLUMNS}
             FROM test_runs
            WHERE tenant_id = $1
              AND status = ANY($2::text[])
              AND collection_deadline_at IS NOT NULL
              AND collection_deadline_at < COALESCE($3::timestamptz, now())
            ORDER BY collection_deadline_at ASC
            LIMIT $4`,
          [
            ctx.tenantId,
            [...EXPIRED_COLLECTION_SWEEP_STATUSES],
            options.now ?? null,
            limit,
          ],
        );
        return rows.map(mapTestRunRow);
      });
    },

    async withRunMutationLock(ctx, runId, callback, options = {}) {
      const lockKey = `test_run_mutation:${runId}`;
      const killSwitchLockKey = `kill_switch_state:${ctx.tenantId}`;
      return runWithTenantClient(pool, ctx.tenantId, options.client, async (client) => {
        if (options.wait === true) {
          await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [lockKey]);
        } else {
          const { rows } = await client.query(
            'SELECT pg_try_advisory_xact_lock(hashtext($1)) AS acquired',
            [lockKey],
          );
          if (rows[0]?.acquired !== true) return { acquired: false, result: null };
        }
        await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [killSwitchLockKey]);
        return { acquired: true, result: await callback(client) };
      });
    },

    /**
     * Serialize one finalization inside the transaction that already owns the tenant audit lock.
     *
     * The caller must supply that exact client. Requiring it is deliberate: falling back to the
     * pool here can deadlock a max=1 pool and would split finalization reads/writes across lock
     * scopes. The blocking run lock preserves global mutation ordering; the kill-switch lock is
     * acquired next, matching every other run mutation path. Both remain held until the outer
     * tenant-audit transaction commits or rolls back.
     *
     * @param {{ tenantId: string }} ctx
     * @param {string} runId
     * @param {(client: import('pg').PoolClient) => Promise<T>} callback
     * @param {{ client?: import('pg').PoolClient }} [options]
     * @returns {Promise<{ acquired: boolean, result: T | null }>}
     * @template T
     */
    async withRunFinalizationLock(ctx, runId, callback, options = {}) {
      if (!options.client) {
        throw new Error(
          'withRunFinalizationLock requires the tenant audit transaction client.',
        );
      }
      const client = options.client;
      await client.query(
        'SELECT pg_advisory_xact_lock(hashtext($1))',
        [`test_run_mutation:${runId}`],
      );
      await client.query(
        'SELECT pg_advisory_xact_lock(hashtext($1))',
        [`kill_switch_state:${ctx.tenantId}`],
      );
      return { acquired: true, result: await callback(client) };
    },

    async listVerdictsForRuns(ctx, runIds, options = {}) {
      const ids = normalizeRunIdBatch(runIds, 'listVerdictsForRuns.runIds');
      if (ids.length === 0) return [];
      return runWithTenantClient(pool, ctx.tenantId, options.client, async (client) => {
        const { rows } = await client.query(
          `SELECT ${VERDICT_COLUMNS}
           FROM verdicts
           WHERE tenant_id = $1 AND test_run_id = ANY($2::text[])`,
          [ctx.tenantId, ids],
        );
        return rows.map(mapVerdictRow);
      });
    },

    async getVerdictForRun(ctx, runId, options = {}) {
      return runWithTenantClient(pool, ctx.tenantId, options.client, async (client) => {
        const { rows } = await client.query(
          `SELECT ${VERDICT_COLUMNS}
           FROM verdicts
           WHERE tenant_id = $1 AND test_run_id = $2`,
          [ctx.tenantId, runId],
        );
        return mapVerdictRow(rows[0] ?? null);
      });
    },

    async findOpenFinding(ctx, { target_group_id, target_id, check_id }, options = {}) {
      return runWithTenantClient(pool, ctx.tenantId, options.client, async (client) => {
        const { rows } = await client.query(
          `SELECT ${FINDING_COLUMNS}
           FROM findings
           WHERE tenant_id = $1
             AND target_group_id = $2
             AND target_id = $3
             AND check_id = $4
             AND status = 'open'`,
          [ctx.tenantId, target_group_id, target_id, check_id],
        );
        return mapFindingRow(rows[0] ?? null);
      });
    },

    async createFinding(ctx, record) {
      const tenantId = ctx.tenantId;
      const evidenceIds = asStringArray(record.evidence_ids);

      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO findings (
             id, tenant_id, target_group_id, target_id, test_run_id, check_id, title, severity,
             status, evidence_ids, notes, remediation_template, verdict_id, last_verdict_id,
             assignee, created_at, updated_at
           )
           VALUES (
             $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
             $16::timestamptz, $17::timestamptz
           )
           RETURNING ${FINDING_COLUMNS}`,
          [
            record.id,
            tenantId,
            record.target_group_id ?? null,
            record.target_id ?? null,
            record.test_run_id ?? null,
            record.check_id ?? null,
            record.title,
            record.severity,
            record.status ?? 'open',
            evidenceIds,
            record.notes ?? null,
            record.remediation_template ?? null,
            record.verdict_id ?? null,
            record.last_verdict_id ?? null,
            record.assignee ?? null,
            record.created_at,
            record.updated_at ?? null,
          ],
        );
        return mapFindingRow(rows[0]);
      });
    },

    async upsertOpenFindingFromVerdict(ctx, record, options = {}) {
      if (record.status !== undefined && record.status !== 'open') {
        throw new Error(
          `upsertOpenFindingFromVerdict only accepts open findings; got status ${JSON.stringify(record.status)}`,
        );
      }

      const tenantId = ctx.tenantId;
      const evidenceIds = asStringArray(record.evidence_ids);
      const status = 'open';
      const updatedAt = record.updated_at ?? new Date().toISOString();

      return runWithTenantClient(pool, tenantId, options.client, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO findings (
             id, tenant_id, target_group_id, target_id, test_run_id, check_id, title, severity,
             status, evidence_ids, notes, remediation_template, verdict_id, last_verdict_id,
             assignee, created_at, updated_at
           )
           SELECT
             $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
             $16::timestamptz, $17::timestamptz
           FROM verdicts incoming
           WHERE incoming.tenant_id = $2
             AND incoming.id = $14
             AND incoming.test_run_id = $5
             AND incoming.target_id IS NOT DISTINCT FROM $4
             AND incoming.check_id IS NOT DISTINCT FROM $6
             AND NOT EXISTS (
               SELECT 1
               FROM findings prior
               LEFT JOIN verdicts prior_verdict
                 ON prior_verdict.tenant_id = prior.tenant_id
                AND prior_verdict.id = COALESCE(prior.last_verdict_id, prior.verdict_id)
               WHERE prior.tenant_id = $2
                 AND prior.target_group_id IS NOT DISTINCT FROM $3
                 AND prior.target_id IS NOT DISTINCT FROM $4
                 AND prior.check_id IS NOT DISTINCT FROM $6
                 AND (
                   prior.verdict_id = $14
                   OR prior.last_verdict_id = $14
                   OR prior_verdict.created_at > incoming.created_at
                   OR (
                     prior_verdict.created_at = incoming.created_at
                     AND prior_verdict.id >= incoming.id
                   )
                 )
             )
           ON CONFLICT (tenant_id, target_group_id, target_id, check_id) WHERE status = 'open'
           DO UPDATE SET
             test_run_id = EXCLUDED.test_run_id,
             title = EXCLUDED.title,
             severity = EXCLUDED.severity,
             evidence_ids = EXCLUDED.evidence_ids,
             notes = EXCLUDED.notes,
             remediation_template = EXCLUDED.remediation_template,
             last_verdict_id = EXCLUDED.last_verdict_id,
             updated_at = EXCLUDED.updated_at
           WHERE EXISTS (
             SELECT 1
             FROM verdicts incoming
             LEFT JOIN verdicts incumbent
               ON incumbent.tenant_id = findings.tenant_id
              AND incumbent.id = COALESCE(findings.last_verdict_id, findings.verdict_id)
             WHERE incoming.tenant_id = findings.tenant_id
               AND incoming.id = EXCLUDED.last_verdict_id
               AND (
                 incumbent.id IS NULL
                 OR incoming.created_at > incumbent.created_at
                 OR (
                   incoming.created_at = incumbent.created_at
                   AND incoming.id > incumbent.id
                 )
               )
           )
           RETURNING ${FINDING_COLUMNS}`,
          [
            record.id,
            tenantId,
            record.target_group_id ?? null,
            record.target_id ?? null,
            record.test_run_id ?? null,
            record.check_id ?? null,
            record.title,
            record.severity,
            status,
            evidenceIds,
            record.notes ?? null,
            record.remediation_template ?? null,
            record.verdict_id ?? null,
            record.last_verdict_id ?? null,
            record.assignee ?? null,
            record.created_at,
            updatedAt,
          ],
        );
        return mapFindingRow(rows[0] ?? null);
      });
    },

    async patchFinding(ctx, id, patch) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const sets = [];
        const params = [];
        let paramIndex = 1;

        if (patch.status !== undefined) {
          sets.push(`status = $${paramIndex}`);
          params.push(patch.status);
          paramIndex += 1;
        }
        if (patch.assignee !== undefined) {
          sets.push(`assignee = $${paramIndex}`);
          params.push(patch.assignee);
          paramIndex += 1;
        }
        if (patch.notes !== undefined) {
          sets.push(`notes = $${paramIndex}`);
          params.push(patch.notes);
          paramIndex += 1;
        }
        if (patch.last_verdict_id !== undefined) {
          sets.push(`last_verdict_id = $${paramIndex}`);
          params.push(patch.last_verdict_id);
          paramIndex += 1;
        }
        if (patch.evidence_ids !== undefined) {
          sets.push(`evidence_ids = $${paramIndex}`);
          params.push(asStringArray(patch.evidence_ids));
          paramIndex += 1;
        }
        if (patch.closed_at !== undefined) {
          if (patch.closed_at === null) {
            sets.push('closed_at = NULL');
          } else {
            sets.push(`closed_at = COALESCE(closed_at, $${paramIndex}::timestamptz)`);
            params.push(patch.closed_at);
            paramIndex += 1;
          }
        }
        if (patch.updated_at !== undefined) {
          sets.push(`updated_at = $${paramIndex}::timestamptz`);
          params.push(patch.updated_at);
          paramIndex += 1;
        } else if (sets.length > 0) {
          sets.push(`updated_at = $${paramIndex}::timestamptz`);
          params.push(new Date().toISOString());
          paramIndex += 1;
        }

        if (sets.length === 0) {
          const { rows } = await client.query(
            `SELECT ${FINDING_COLUMNS}
             FROM findings
             WHERE tenant_id = $1 AND id = $2`,
            [ctx.tenantId, id],
          );
          return mapFindingRow(rows[0] ?? null);
        }

        params.push(ctx.tenantId, id);
        const tenantParam = paramIndex;
        const idParam = paramIndex + 1;

        const { rows } = await client.query(
          `UPDATE findings
           SET ${sets.join(', ')}
           WHERE tenant_id = $${tenantParam} AND id = $${idParam}
           RETURNING ${FINDING_COLUMNS}`,
          params,
        );
        return mapFindingRow(rows[0] ?? null);
      });
    },

    async countOpenFindings(ctx, options = {}) {
      return runWithTenantClient(pool, ctx.tenantId, options.client, async (client) => {
        const { rows } = await client.query(
          `SELECT COUNT(*)::int AS open_count
           FROM findings
           WHERE tenant_id = $1 AND status = 'open'`,
          [ctx.tenantId],
        );
        return Number(rows[0]?.open_count ?? 0);
      });
    },

    async listFindings(ctx, options = {}) {
      if (options?.forUpdate === true) {
        return runWithTenantClient(pool, ctx.tenantId, options.client, async (client) => {
          const params = [ctx.tenantId];
          const conditions = ['tenant_id = $1'];
          let paramIndex = 2;
          if (options.target_group_id != null && options.target_group_id !== '') {
            conditions.push(`target_group_id = $${paramIndex}`);
            params.push(options.target_group_id);
            paramIndex += 1;
          }
          if (options.target_id != null && options.target_id !== '') {
            conditions.push(`target_id = $${paramIndex}`);
            params.push(options.target_id);
            paramIndex += 1;
          }
          if (options.test_run_id != null && options.test_run_id !== '') {
            conditions.push(`test_run_id = $${paramIndex}`);
            params.push(options.test_run_id);
            paramIndex += 1;
          }
          if (options.check_id != null && options.check_id !== '') {
            conditions.push(`check_id = $${paramIndex}`);
            params.push(options.check_id);
            paramIndex += 1;
          }
          const { rows } = await client.query(
            `SELECT ${FINDING_COLUMNS}
             FROM findings
             WHERE ${conditions.join(' AND ')}
             ORDER BY created_at DESC, id DESC FOR UPDATE`,
            params,
          );
          return rows.map(mapFindingRow);
        });
      }

      const query = parseFindingListQuery(options, { paginate: false });
      return runWithTenantClient(pool, ctx.tenantId, options.client, async (client) => {
        const built = findingCustomerListWhere(ctx.tenantId, query);
        const filterSql = built.conditions.length > 0
          ? ` AND ${built.conditions.join(' AND ')}`
          : '';
        const params = built.params.slice();
        let sql = `SELECT ${FINDING_COLUMNS}
           FROM findings f
           WHERE f.tenant_id = $1${filterSql}
           ORDER BY f.created_at DESC, f.id DESC`;
        if (query.limit != null) {
          params.push(query.limit);
          sql += ` LIMIT $${built.nextIndex}`;
          if (query.offset > 0) {
            params.push(query.offset);
            sql += ` OFFSET $${built.nextIndex + 1}`;
          }
        }
        const { rows } = await client.query(sql, params);
        return rows.map(mapFindingRow);
      });
    },

    async listFindingsPage(ctx, options = {}) {
      const query = parseFindingListQuery(options, { paginate: true });
      return runWithTenantClient(pool, ctx.tenantId, options.client, async (client) => {
        const built = findingCustomerListWhere(ctx.tenantId, query);
        const filterSql = built.conditions.length > 0
          ? ` AND ${built.conditions.join(' AND ')}`
          : '';
        const params = built.params.slice();
        params.push(query.limit, query.offset);
        const limitParam = built.nextIndex;
        const offsetParam = built.nextIndex + 1;
        // Count and page in one statement so a concurrent commit between two
        // statements cannot move the total away from the page rows: everything
        // below reads one READ COMMITTED statement snapshot.
        const { rows } = await client.query(
          `WITH page AS (
             SELECT ${FINDING_COLUMNS}
             FROM findings f
             WHERE f.tenant_id = $1${filterSql}
             ORDER BY f.created_at DESC, f.id DESC
             LIMIT $${limitParam} OFFSET $${offsetParam}
           ),
           total AS (
             SELECT COUNT(*)::int AS total
             FROM findings f
             WHERE f.tenant_id = $1${filterSql}
           )
           SELECT total.total, page.*
           FROM total
           LEFT JOIN page ON TRUE`,
          params,
        );
        const total = Number(rows[0]?.total ?? 0);
        return {
          items: rows.filter((row) => row.id != null).map(mapFindingRow),
          total,
        };
      });
    },

    async getFinding(ctx, id) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${FINDING_COLUMNS}
           FROM findings
           WHERE tenant_id = $1 AND id = $2`,
          [ctx.tenantId, id],
        );
        return mapFindingRow(rows[0] ?? null);
      });
    },

    async readFindingLineage(ctx, findingId) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const finding = await client.query(
          `SELECT ${FINDING_COLUMNS} FROM findings WHERE tenant_id = $1 AND id = $2`,
          [ctx.tenantId, findingId],
        );
        const mapped = mapFindingRow(finding.rows[0] ?? null);
        if (!mapped) return null;
        const lineage = await client.query(
          `SELECT id, tenant_id, finding_id, test_run_id, target_id, check_id, intent, relation, created_at
           FROM finding_retest_lineage WHERE tenant_id = $1 AND finding_id = $2`,
          [ctx.tenantId, findingId],
        );
        const runs = await client.query(
          `SELECT id, tenant_id, target_id, check_id, status, created_at
           FROM test_runs
           WHERE tenant_id = $1 AND target_id = $2 AND check_id = $3`,
          [ctx.tenantId, mapped.target_id ?? null, mapped.check_id ?? null],
        );
        const siblings = await client.query(
          `SELECT id, target_id, status, closed_at FROM findings
           WHERE tenant_id = $1 AND check_id = $2 AND id <> $3`,
          [ctx.tenantId, mapped.check_id ?? null, findingId],
        );
        return presentFindingLineage({
          finding: mapped,
          runs: runs.rows,
          lineage: lineage.rows,
          siblings: siblings.rows,
        });
      });
    },

    async loadOriginBindingProof(ctx, bindingId) {
      const history = createTargetHistoryRepository(pool);
      const binding = await history.getBinding(ctx, bindingId);
      if (!binding) {
        return {
          binding: null,
          targets: [],
          targetVerifications: [],
          wafConnectors: [],
          wafConnectorSnapshots: [],
        };
      }
      const context = await history.loadBindingContext(ctx, [binding.origin_target_id, binding.protected_target_id]);
      return { binding, ...context };
    },

    /**
     * Append accepted observations on the caller transaction when one is supplied.
     * A mismatched origin binding id is dropped. Time and idempotency results are returned
     * to the caller; this method does not move the edge current row.
     */
    async appendAcceptedEdgeHistory(ctx, spec = {}, options = {}) {
      const write = async (client) => {
        const targetRes = await client.query(
          `SELECT id, tenant_id, target_group_id, kind, value, port, deleted_at, declaration_json,
                  created_at
           FROM targets
           WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL`,
          [ctx.tenantId, spec.target_id],
        );
        const target = targetRes.rows[0];
        if (!target) return { skipped: 'unknown_target', rows: [] };
        target.created_at = toIso(target.created_at);
        let binding = null;
        let originBindingId = spec.origin_binding_id ?? null;
        if (originBindingId) {
          const bindingRes = await client.query(
            `SELECT id, tenant_id, origin_target_id, status, created_at
             FROM origin_bindings WHERE tenant_id = $1 AND id = $2`,
            [ctx.tenantId, originBindingId],
          );
          const row = bindingRes.rows[0] ?? null;
          if (!row || row.status !== 'active' || row.origin_target_id !== target.id) {
            if (spec.require_binding) return { skipped: 'binding_target_mismatch', rows: [] };
            originBindingId = null;
          } else {
            binding = { ...row, created_at: toIso(row.created_at) };
          }
        } else if (spec.require_binding) {
          return { skipped: 'binding_target_mismatch', rows: [] };
        }
        const rows = [];
        for (const family of spec.families ?? []) {
          const familyBindingId = family.origin_binding_id === undefined ? originBindingId : family.origin_binding_id;
          const prepared = prepareObservation({
            ...family,
            target_id: target.id,
            origin_binding_id: familyBindingId,
          }, {
            tenantId: ctx.tenantId,
            target,
            binding: familyBindingId ? binding : null,
            serverDerived: true,
            now: spec.now,
          });
          if (prepared.error) {
            rows.push(prepared);
            if (prepared.error === 'idempotency_conflict') {
              return { error: 'idempotency_conflict', status: 409, rows };
            }
            if (HISTORY_TIME_SKIPS.has(prepared.error)) {
              return { skipped: prepared.error, rows };
            }
            continue;
          }
          const written = await writeObservation(client, {
            ...prepared.record,
            id: family.id ?? `obs_${randomBytes(8).toString('hex')}`,
            created_at: toIso(spec.now ?? new Date()),
          });
          if (written?.error === 'idempotency_conflict') {
            return { error: 'idempotency_conflict', status: 409, rows: [...rows, written] };
          }
          rows.push(written);
        }
        return { rows };
      };
      if (options.client) return write(options.client);
      return withTenantContext(pool, ctx.tenantId, write);
    },
  };
}

export {
  mapTestRunRow,
  mapEventRow,
  mapEvidenceRow,
  mapVerdictRow,
  mapFindingRow,
};