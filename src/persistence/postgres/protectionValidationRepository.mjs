// Tenant-scoped storage for migration 0068; each write commits its row, evidence refs, and audit entry together.
import { randomBytes } from 'node:crypto';
import { isFinalizedRunStatus } from '../../contracts/protectionValidation.mjs';
import { decodeFirewallObservations, encodeFirewallObservations } from '../../lib/firewallChangeAcceptance.mjs';
import { subdomainParentId } from '../../lib/subdomainEnumeration.mjs';
import { withTenantContext } from './tenantContext.mjs';

const EXACT_TIME = `to_char(%s AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`;

function exact(column) {
  return EXACT_TIME.replace('%s', column);
}

function nullableExact(column) {
  return `CASE WHEN ${column} IS NULL THEN NULL ELSE ${exact(column)} END`;
}

function isoMillis(value) {
  if (value == null) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

function asObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
}

function refId() {
  return `pvr_${randomBytes(8).toString('hex')}`;
}

const ENTRY_PATH_COLUMNS = `id, tenant_id, anchor_target_id, entry_target_id, relation_kind, origin_binding_id, owner, purpose,
  expected_behavior, required_layers, declaration_source, declaration_version, declaration_digest, contract_version,
  provenance_json, idempotency_key, status, created_by, archived_by,
  ${exact('created_at')} AS created_at, ${nullableExact('archived_at')} AS archived_at`;

function mapEntryPath(row) {
  if (!row) return null;
  const { provenance_json: provenance, ...rest } = row;
  return { ...rest, required_layers: [...(row.required_layers ?? [])], origin_binding_id: row.origin_binding_id ?? null, provenance: asObject(provenance) };
}

const EXPECTATION_COLUMNS = `id, tenant_id, kind, scope_key, expectation_version, expectation_digest, contract_version,
  anchor_target_id, scenario, layer_outcomes_json, destination_target_id, protocol, port, service_endpoint_json,
  expected, source_perspective, change_id, pre_destination_target_id, post_destination_target_id, owner,
  provenance_json, idempotency_key, status, created_by, archived_by,
  ${exact('created_at')} AS created_at, ${nullableExact('archived_at')} AS archived_at`;

function mapExpectation(row) {
  if (!row) return null;
  const common = {
    id: row.id,
    tenant_id: row.tenant_id,
    kind: row.kind,
    scope_key: row.scope_key,
    expectation_version: row.expectation_version,
    digest: row.expectation_digest,
    contract_version: row.contract_version,
    owner: row.owner ?? null,
    status: row.status,
    provenance: asObject(row.provenance_json),
    idempotency_key: row.idempotency_key ?? null,
    created_at: row.created_at,
    created_by: row.created_by ?? null,
    archived_at: row.archived_at ?? null,
    archived_by: row.archived_by ?? null,
  };
  if (row.kind === 'path_validation') {
    return { ...common, anchor_target_id: row.anchor_target_id, scenario: row.scenario, layer_outcomes: asObject(row.layer_outcomes_json) };
  }
  const endpoint = row.service_endpoint_json;
  return {
    ...common,
    destination_target_id: row.destination_target_id,
    protocol: row.protocol,
    port: row.port ?? null,
    service_endpoint: endpoint ? { service: endpoint.service, port: endpoint.port, path: endpoint.path ?? null } : null,
    expected: row.expected,
    source_perspective: row.source_perspective,
    change_id: row.change_id,
    pre_post_mapping: row.pre_destination_target_id
      ? { pre_destination_target_id: row.pre_destination_target_id, post_destination_target_id: row.post_destination_target_id, declared_by_customer: true }
      : null,
  };
}

const BASELINE_COLUMNS = `id, tenant_id, kind, target_id, anchor_target_id, entry_path_id, expectation_id, expectation_version,
  expectation_digest, declaration_version, declaration_digest, pre_destination_target_id, post_destination_target_id,
  ${exact('captured_at')} AS captured_at, freshness_window_seconds, reference_count, baseline_digest, contract_version,
  provenance_json, idempotency_key, status, created_by, archived_by,
  ${exact('created_at')} AS created_at, ${nullableExact('archived_at')} AS archived_at`;

const REF_COLUMNS = `id, baseline_id, evaluation_id, item_index, ordinal, test_run_id, check_id, check_version, scenario_version,
  verdict_id, evidence_ids, target_id, ${exact('observed_at')} AS observed_at, run_status, source_perspective, worker_id`;

function mapReference(row) {
  return {
    test_run_id: row.test_run_id,
    check_id: row.check_id,
    check_version: row.check_version ?? null,
    scenario_version: row.scenario_version ?? null,
    verdict_id: row.verdict_id ?? null,
    evidence_ids: [...(row.evidence_ids ?? [])],
    target_id: row.target_id,
    observed_at: isoMillis(row.observed_at),
    run_status: row.run_status ?? null,
    finalized: isFinalizedRunStatus(row.run_status),
    source_perspective: row.source_perspective ?? null,
    worker_id: row.worker_id ?? null,
  };
}

function mapBaseline(row, references) {
  const provenance = asObject(row.provenance_json);
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    kind: row.kind,
    contract_version: row.contract_version,
    anchor_target_id: row.anchor_target_id ?? null,
    entry_path_id: row.entry_path_id ?? null,
    expectation_id: row.expectation_id,
    expectation_version: row.expectation_version,
    expectation_digest: row.expectation_digest,
    declaration_version: row.declaration_version ?? null,
    declaration_digest: row.declaration_digest ?? null,
    target_id: row.target_id,
    destination_mapping: row.pre_destination_target_id
      ? { pre_destination_target_id: row.pre_destination_target_id, post_destination_target_id: row.post_destination_target_id, declared_by_customer: true }
      : null,
    references,
    captured_at: isoMillis(row.captured_at),
    freshness_window_seconds: row.freshness_window_seconds,
    baseline_digest: row.baseline_digest,
    capture_id: provenance.capture_id ?? row.id,
    capture_index: Number(provenance.capture_index ?? 0),
    capture_digest: provenance.capture_digest ?? row.baseline_digest,
    capture_captured_at: provenance.capture_captured_at ?? isoMillis(row.captured_at),
    change_id: provenance.change_id ?? null,
    entry_count: Number(provenance.entry_count ?? 1),
    ...(provenance.observations_digest ? {
      classifier_version: provenance.classifier_version ?? null,
      observations: decodeFirewallObservations(provenance.observations),
      observations_digest: provenance.observations_digest,
    } : {}),
    status: row.status,
    idempotency_key: row.idempotency_key ?? null,
    created_at: row.created_at,
    created_by: row.created_by ?? null,
    archived_at: row.archived_at ?? null,
    archived_by: row.archived_by ?? null,
  };
}

const EVALUATION_COLUMNS = `id, tenant_id, kind, baseline_id, baseline_digest, anchor_target_id, primary_entry_path_id,
  reviewed_plan_digest, comparable, stale, compatibility_reasons, total_count, evaluated_count, accepted, items_json,
  summary_json, limitations, ${exact('evaluated_at')} AS evaluated_at, evaluation_digest, contract_version, provenance_json,
  idempotency_key, created_by, ${exact('created_at')} AS created_at`;

function mapEvaluation(row) {
  if (!row) return null;
  const provenance = asObject(row.provenance_json);
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    kind: row.kind,
    contract_version: row.contract_version,
    baseline_id: row.baseline_id ?? null,
    baseline_digest: row.baseline_digest ?? null,
    anchor_target_id: row.anchor_target_id ?? null,
    primary_entry_path_id: row.primary_entry_path_id ?? null,
    reviewed_plan_digest: row.reviewed_plan_digest ?? null,
    compatibility: { comparable: row.comparable, stale: row.stale, reasons: [...(row.compatibility_reasons ?? [])] },
    items: Array.isArray(row.items_json) ? row.items_json : [],
    summary: asObject(row.summary_json),
    limitations: [...(row.limitations ?? [])],
    evaluated_at: isoMillis(row.evaluated_at),
    evaluation_digest: row.evaluation_digest,
    change_id: provenance.change_id ?? null,
    provenance,
    idempotency_key: row.idempotency_key ?? null,
    created_at: row.created_at,
    created_by: row.created_by ?? null,
  };
}

function cursorClause(cursor, timeParam, idParam) {
  return cursor
    ? `AND (created_at < $${timeParam}::timestamptz OR (created_at = $${timeParam}::timestamptz AND id COLLATE "C" < $${idParam} COLLATE "C"))`
    : '';
}

async function appendAudit(audit, entry, client) {
  if (entry && audit?.appendAuditEvent) await audit.appendAuditEvent(entry, { client });
}

async function insertReferences(client, tenantId, rows) {
  for (const row of rows) {
    await client.query(
      `INSERT INTO protection_comparison_evidence_refs (
         id, tenant_id, baseline_id, evaluation_id, item_index, ordinal, expectation_id, entry_path_id, test_run_id,
         check_id, check_version, scenario_version, verdict_id, evidence_ids, target_id, origin_binding_id,
         observed_at, run_status, source_perspective, worker_id, created_at
       ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14::text[], $15, NULL,
         $16::timestamptz, $17, $18, $19, $20::timestamptz)`,
      [
        refId(), tenantId, row.baseline_id ?? null, row.evaluation_id ?? null, row.item_index ?? null, row.ordinal,
        row.expectation_id ?? null, row.entry_path_id ?? null, row.reference.test_run_id, row.reference.check_id,
        row.reference.check_version, row.reference.scenario_version, row.reference.verdict_id, row.reference.evidence_ids,
        row.reference.target_id, row.reference.observed_at, row.reference.run_status, row.reference.source_perspective,
        row.reference.worker_id, row.created_at,
      ],
    );
  }
}

class CaptureConflict extends Error {}

export function createProtectionValidationRepository(pool) {
  const run = (ctx, callback) => withTenantContext(pool, ctx.tenantId, callback);

  async function readBaselines(client, tenantId, rows) {
    if (!rows.length) return [];
    const refs = await client.query(
      `SELECT ${REF_COLUMNS} FROM protection_comparison_evidence_refs
       WHERE tenant_id = $1 AND baseline_id = ANY($2::text[])
       ORDER BY baseline_id, ordinal`,
      [tenantId, rows.map((row) => row.id)],
    );
    const byBaseline = new Map();
    for (const ref of refs.rows) {
      if (!byBaseline.has(ref.baseline_id)) byBaseline.set(ref.baseline_id, []);
      byBaseline.get(ref.baseline_id).push(mapReference(ref));
    }
    return rows.map((row) => mapBaseline(row, byBaseline.get(row.id) ?? []));
  }

  async function captureRows(client, tenantId, captureId) {
    const { rows } = await client.query(
      `SELECT ${BASELINE_COLUMNS} FROM protection_comparison_baselines
       WHERE tenant_id = $1 AND provenance_json->>'capture_id' = $2 AND (id = $2 OR starts_with(id, $2 || '.'))
       ORDER BY (provenance_json->>'capture_index')::int`,
      [tenantId, captureId],
    );
    return readBaselines(client, tenantId, rows);
  }

  const repo = {
    async loadTargetContext(ctx, ids) {
      return run(ctx, async (client) => {
        const targetSql = `SELECT id, tenant_id, target_group_id, kind, value, port, deleted_at, declaration_json, normalized_value,
                  metadata_json, ${exact('created_at')} AS created_at
           FROM targets WHERE tenant_id = $1 AND id = ANY($2::text[])`;
        const targets = await client.query(targetSql, [ctx.tenantId, ids]);
        const requested = new Set(ids);
        const parentIds = [...new Set(targets.rows
          .filter((row) => !row.deleted_at && row.kind === 'fqdn')
          .map((row) => subdomainParentId(row))
          .filter((id) => id && !requested.has(id)))];
        const parents = parentIds.length ? (await client.query(targetSql, [ctx.tenantId, parentIds])).rows : [];
        const verifications = await client.query(
          `SELECT id, tenant_id, target_id, state, source_kind, source_ref, transitioned_at, transitioned_by
           FROM target_verifications WHERE tenant_id = $1 AND target_id = ANY($2::text[])`,
          [ctx.tenantId, [...ids, ...parents.map((row) => row.id)]],
        );
        const connectors = await client.query(
          `SELECT id, tenant_id, provider, status, secret_id FROM waf_connectors WHERE tenant_id = $1`,
          [ctx.tenantId],
        );
        const snapshots = await client.query(
          `SELECT id, tenant_id, connector_id, provider, snapshot_kind, resource_ref_hash, summary_json, evidence_source, observed_at
           FROM waf_connector_snapshots WHERE tenant_id = $1`,
          [ctx.tenantId],
        );
        const live = [...targets.rows, ...parents].filter((row) => !row.deleted_at);
        return {
          targets: targets.rows,
          records: {
            targets: live,
            targetVerifications: verifications.rows,
            wafConnectors: connectors.rows.map((row) => ({ ...row, has_secret: Boolean(row.secret_id) })),
            wafConnectorSnapshots: snapshots.rows.map((row) => ({ ...row, summary: row.summary_json })),
          },
        };
      });
    },

    async getOriginBindings(ctx, ids) {
      return run(ctx, async (client) => {
        const { rows } = await client.query(
          `SELECT id, tenant_id, protected_target_id, origin_target_id, status, host, sni, port, path
           FROM origin_bindings WHERE tenant_id = $1 AND id = ANY($2::text[])`,
          [ctx.tenantId, ids],
        );
        return rows;
      });
    },

    async listEntryPathsByScope(ctx, scope) {
      return run(ctx, async (client) => {
        const { rows } = await client.query(
          `SELECT ${ENTRY_PATH_COLUMNS} FROM application_entry_paths
           WHERE tenant_id = $1 AND anchor_target_id = $2 AND entry_target_id = $3 AND relation_kind = $4
             AND COALESCE(origin_binding_id, '') = COALESCE($5::text, '')`,
          [ctx.tenantId, scope.anchor_target_id, scope.entry_target_id, scope.relation_kind, scope.origin_binding_id ?? null],
        );
        return rows.map(mapEntryPath);
      });
    },

    async findEntryPathByIdempotencyKey(ctx, key) {
      return run(ctx, async (client) => {
        const { rows } = await client.query(
          `SELECT ${ENTRY_PATH_COLUMNS} FROM application_entry_paths WHERE tenant_id = $1 AND idempotency_key = $2`,
          [ctx.tenantId, key],
        );
        return mapEntryPath(rows[0]);
      });
    },

    async insertEntryPath(ctx, record, auditEntry, audit) {
      return run(ctx, async (client) => {
        const inserted = await client.query(
          `INSERT INTO application_entry_paths (
             id, tenant_id, anchor_target_id, entry_target_id, relation_kind, origin_binding_id, owner, purpose,
             expected_behavior, required_layers, declaration_source, declaration_version, declaration_digest,
             contract_version, provenance_json, idempotency_key, status, created_by, created_at
           ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::text[], 'explicit', $11, $12, $13, $14::jsonb, $15, 'active', $16, $17::timestamptz)
           ON CONFLICT DO NOTHING
           RETURNING ${ENTRY_PATH_COLUMNS}`,
          [
            record.id, record.tenant_id, record.anchor_target_id, record.entry_target_id, record.relation_kind,
            record.origin_binding_id, record.owner, record.purpose, record.expected_behavior, record.required_layers,
            record.declaration_version, record.declaration_digest, record.contract_version,
            JSON.stringify(record.provenance ?? {}), record.idempotency_key, record.created_by, record.created_at,
          ],
        );
        if (!inserted.rows[0]) {
          const { rows } = await client.query(
            `SELECT ${ENTRY_PATH_COLUMNS} FROM application_entry_paths
             WHERE tenant_id = $1 AND (
               ($6::text IS NOT NULL AND idempotency_key = $6)
               OR (anchor_target_id = $2 AND entry_target_id = $3 AND relation_kind = $4
                   AND COALESCE(origin_binding_id, '') = COALESCE($5::text, '')
                   AND (status = 'active' OR declaration_version = $7))
             )`,
            [record.tenant_id, record.anchor_target_id, record.entry_target_id, record.relation_kind,
              record.origin_binding_id, record.idempotency_key, record.declaration_version],
          );
          return { conflictRows: rows.map(mapEntryPath) };
        }
        await appendAudit(audit, auditEntry, client);
        return { row: mapEntryPath(inserted.rows[0]) };
      });
    },

    async getEntryPath(ctx, id) {
      return run(ctx, async (client) => {
        const { rows } = await client.query(
          `SELECT ${ENTRY_PATH_COLUMNS} FROM application_entry_paths WHERE tenant_id = $1 AND id = $2`,
          [ctx.tenantId, id],
        );
        return mapEntryPath(rows[0]);
      });
    },

    async getEntryPaths(ctx, ids) {
      if (!ids.length) return [];
      return run(ctx, async (client) => {
        const { rows } = await client.query(
          `SELECT ${ENTRY_PATH_COLUMNS} FROM application_entry_paths WHERE tenant_id = $1 AND id = ANY($2::text[])`,
          [ctx.tenantId, ids],
        );
        return rows.map(mapEntryPath);
      });
    },

    async archiveEntryPath(ctx, id, patch, auditEntry, audit) {
      return run(ctx, async (client) => {
        const { rows } = await client.query(
          `UPDATE application_entry_paths SET status = 'archived', archived_at = $3::timestamptz, archived_by = $4
           WHERE tenant_id = $1 AND id = $2 AND status = 'active'
           RETURNING ${ENTRY_PATH_COLUMNS}`,
          [ctx.tenantId, id, patch.archived_at, patch.archived_by],
        );
        if (!rows[0]) return null;
        await appendAudit(audit, auditEntry, client);
        return mapEntryPath(rows[0]);
      });
    },

    async listEntryPaths(ctx, filter) {
      return run(ctx, async (client) => {
        const { rows } = await client.query(
          `SELECT ${ENTRY_PATH_COLUMNS} FROM application_entry_paths
           WHERE tenant_id = $1 AND (anchor_target_id = $2 OR entry_target_id = $2)
             AND ($3::text IS NULL OR status = $3)
             AND ($4::text IS NULL OR relation_kind = $4)
             ${cursorClause(filter.cursor, 6, 7)}
           ORDER BY created_at DESC, id COLLATE "C" DESC
           LIMIT $5`,
          [ctx.tenantId, filter.target_id, filter.status, filter.relation_kind, filter.limit,
            ...(filter.cursor ? [filter.cursor.created_at, filter.cursor.id] : [])],
        );
        return rows.map(mapEntryPath);
      });
    },

    async listExpectationsByScope(ctx, kind, scopeKey) {
      return run(ctx, async (client) => {
        const { rows } = await client.query(
          `SELECT ${EXPECTATION_COLUMNS} FROM protection_expectations WHERE tenant_id = $1 AND kind = $2 AND scope_key = $3`,
          [ctx.tenantId, kind, scopeKey],
        );
        return rows.map(mapExpectation);
      });
    },

    async findExpectationByIdempotencyKey(ctx, key) {
      return run(ctx, async (client) => {
        const { rows } = await client.query(
          `SELECT ${EXPECTATION_COLUMNS} FROM protection_expectations WHERE tenant_id = $1 AND idempotency_key = $2`,
          [ctx.tenantId, key],
        );
        return mapExpectation(rows[0]);
      });
    },

    async insertExpectation(ctx, record, auditEntry, audit, options = {}) {
      return run(ctx, async (client) => {
        const conflictRows = async () => {
          const { rows } = await client.query(
            `SELECT ${EXPECTATION_COLUMNS} FROM protection_expectations
             WHERE tenant_id = $1 AND (
               ($4::text IS NOT NULL AND idempotency_key = $4)
               OR (kind = $2 AND scope_key = $3 AND (status = 'active' OR expectation_version = $5))
             )`,
            [record.tenant_id, record.kind, record.scope_key, record.idempotency_key, record.expectation_version],
          );
          return { conflictRows: rows.map(mapExpectation) };
        };
        if (options.supersede) {
          const archived = await client.query(
            `UPDATE protection_expectations SET status = 'archived', archived_at = $3::timestamptz, archived_by = $4
             WHERE tenant_id = $1 AND id = $2 AND status = 'active' RETURNING id`,
            [ctx.tenantId, options.supersede.id, options.supersede.archived_at, options.supersede.archived_by],
          );
          if (!archived.rows[0]) return conflictRows();
        }
        const firewall = record.kind === 'firewall_change';
        const mapping = record.pre_post_mapping ?? null;
        const inserted = await client.query(
          `INSERT INTO protection_expectations (
             id, tenant_id, kind, scope_key, expectation_version, expectation_digest, contract_version,
             anchor_target_id, scenario, layer_outcomes_json, destination_target_id, protocol, port, service_endpoint_json,
             expected, source_perspective, change_id, pre_destination_target_id, post_destination_target_id, owner,
             provenance_json, idempotency_key, status, created_by, created_at
           ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11, $12, $13, $14::jsonb,
             $15, $16, $17, $18, $19, $20, $21::jsonb, $22, 'active', $23, $24::timestamptz)
           ON CONFLICT DO NOTHING
           RETURNING ${EXPECTATION_COLUMNS}`,
          [
            record.id, record.tenant_id, record.kind, record.scope_key, record.expectation_version, record.digest,
            record.contract_version,
            firewall ? null : record.anchor_target_id,
            firewall ? null : record.scenario,
            firewall ? null : JSON.stringify(record.layer_outcomes),
            firewall ? record.destination_target_id : null,
            firewall ? record.protocol : null,
            firewall ? record.port : null,
            firewall && record.service_endpoint ? JSON.stringify(record.service_endpoint) : null,
            firewall ? record.expected : null,
            firewall ? record.source_perspective : null,
            firewall ? record.change_id : null,
            mapping?.pre_destination_target_id ?? null,
            mapping?.post_destination_target_id ?? null,
            record.owner ?? null,
            JSON.stringify(record.provenance ?? {}),
            record.idempotency_key ?? null,
            record.created_by,
            record.created_at,
          ],
        );
        if (!inserted.rows[0]) {
          if (options.supersede) throw new CaptureConflict('expectation_conflict');
          return conflictRows();
        }
        await appendAudit(audit, auditEntry, client);
        return { row: mapExpectation(inserted.rows[0]) };
      }).catch(async (err) => {
        if (!(err instanceof CaptureConflict)) throw err;
        const rows = await repo.listExpectationsByScope(ctx, record.kind, record.scope_key);
        return { conflictRows: rows };
      });
    },

    async getExpectation(ctx, id) {
      return run(ctx, async (client) => {
        const { rows } = await client.query(
          `SELECT ${EXPECTATION_COLUMNS} FROM protection_expectations WHERE tenant_id = $1 AND id = $2`,
          [ctx.tenantId, id],
        );
        return mapExpectation(rows[0]);
      });
    },

    async getExpectations(ctx, ids) {
      if (!ids.length) return [];
      return run(ctx, async (client) => {
        const { rows } = await client.query(
          `SELECT ${EXPECTATION_COLUMNS} FROM protection_expectations WHERE tenant_id = $1 AND id = ANY($2::text[])`,
          [ctx.tenantId, ids],
        );
        return rows.map(mapExpectation);
      });
    },

    async archiveExpectation(ctx, id, patch, auditEntry, audit) {
      return run(ctx, async (client) => {
        const { rows } = await client.query(
          `UPDATE protection_expectations SET status = 'archived', archived_at = $3::timestamptz, archived_by = $4
           WHERE tenant_id = $1 AND id = $2 AND status = 'active'
           RETURNING ${EXPECTATION_COLUMNS}`,
          [ctx.tenantId, id, patch.archived_at, patch.archived_by],
        );
        if (!rows[0]) return null;
        await appendAudit(audit, auditEntry, client);
        return mapExpectation(rows[0]);
      });
    },

    async listExpectations(ctx, filter) {
      return run(ctx, async (client) => {
        const { rows } = await client.query(
          `SELECT ${EXPECTATION_COLUMNS} FROM protection_expectations
           WHERE tenant_id = $1 AND kind = $2
             AND ($3::text IS NULL OR status = $3)
             AND ($4::text IS NULL OR change_id = $4)
             AND ($5::text IS NULL OR destination_target_id = $5)
             AND ($6::text IS NULL OR anchor_target_id = $6)
             ${cursorClause(filter.cursor, 8, 9)}
           ORDER BY created_at DESC, id COLLATE "C" DESC
           LIMIT $7`,
          [ctx.tenantId, filter.kind, filter.status, filter.change_id, filter.destination_target_id, filter.anchor_target_id,
            filter.limit, ...(filter.cursor ? [filter.cursor.created_at, filter.cursor.id] : [])],
        );
        return rows.map(mapExpectation);
      });
    },

    async loadRunEvidence(ctx, runIds) {
      if (!runIds.length) return { runs: [], jobs: [], verdicts: [], events: [] };
      return run(ctx, async (client) => {
        const runs = await client.query(
          `SELECT id, tenant_id, target_id, check_id, status, check_version, scenario_version, producer_kind,
                  provenance_json, ${nullableExact('completed_at')} AS completed_at
           FROM test_runs WHERE tenant_id = $1 AND id = ANY($2::text[])`,
          [ctx.tenantId, runIds],
        );
        const jobs = await client.query(
          `SELECT id, test_run_id, status, leased_by, job_signature, target_descriptor_json, probe_profile,
                  worker_metadata_json, ${nullableExact('completed_at')} AS completed_at
           FROM probe_jobs WHERE tenant_id = $1 AND test_run_id = ANY($2::text[])`,
          [ctx.tenantId, runIds],
        );
        const verdicts = await client.query(
          `SELECT id, test_run_id, evidence_ids, ${exact('created_at')} AS created_at
           FROM verdicts WHERE tenant_id = $1 AND test_run_id = ANY($2::text[])`,
          [ctx.tenantId, runIds],
        );
        const events = await client.query(
          `SELECT id, test_run_id, signal_type, producer_kind, ${exact('"timestamp"')} AS "timestamp",
                  metadata_json->>'source_perspective' AS source_perspective
           FROM events WHERE tenant_id = $1 AND test_run_id = ANY($2::text[]) AND signal_type = 'probe_result'`,
          [ctx.tenantId, runIds],
        );
        return {
          runs: runs.rows.map((row) => ({ ...row, provenance: asObject(row.provenance_json) })),
          jobs: jobs.rows.map((row) => ({
            id: row.id,
            test_run_id: row.test_run_id,
            status: row.status,
            leased_by: row.leased_by ?? null,
            job_signature: row.job_signature ?? null,
            target: asObject(row.target_descriptor_json),
            probe_profile: asObject(row.probe_profile),
            worker_metadata: asObject(row.worker_metadata_json),
            completed_at: row.completed_at,
          })),
          verdicts: verdicts.rows.map((row) => ({ ...row, evidence_ids: [...(row.evidence_ids ?? [])] })),
          events: events.rows,
        };
      });
    },

    async findBaselineCaptureIdByKey(ctx, key) {
      return run(ctx, async (client) => {
        const { rows } = await client.query(
          `SELECT id, provenance_json->>'capture_id' AS capture_id FROM protection_comparison_baselines
           WHERE tenant_id = $1 AND idempotency_key = $2`,
          [ctx.tenantId, key],
        );
        return rows[0] ? rows[0].capture_id ?? rows[0].id : null;
      });
    },

    async insertBaselineCapture(ctx, rows, auditEntry, audit) {
      try {
        return await run(ctx, async (client) => {
          for (const row of rows) {
            const mapping = row.destination_mapping ?? null;
            const inserted = await client.query(
              `INSERT INTO protection_comparison_baselines (
                 id, tenant_id, kind, target_id, anchor_target_id, entry_path_id, expectation_id, expectation_version,
                 expectation_digest, declaration_version, declaration_digest, pre_destination_target_id,
                 post_destination_target_id, captured_at, freshness_window_seconds, reference_count, baseline_digest,
                 contract_version, provenance_json, idempotency_key, status, created_by, created_at
               ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14::timestamptz, $15, $16, $17, $18,
                 $19::jsonb, $20, 'active', $21, $22::timestamptz)
               ON CONFLICT DO NOTHING RETURNING id`,
              [
                row.id, row.tenant_id, row.kind, row.target_id, row.anchor_target_id ?? null, row.entry_path_id ?? null,
                row.expectation_id, row.expectation_version, row.expectation_digest, row.declaration_version ?? null,
                row.declaration_digest ?? null, mapping?.pre_destination_target_id ?? null,
                mapping?.post_destination_target_id ?? null, row.captured_at, row.freshness_window_seconds,
                row.references.length, row.baseline_digest, row.contract_version,
                JSON.stringify({
                  capture_id: row.capture_id,
                  capture_index: row.capture_index,
                  capture_digest: row.capture_digest,
                  capture_captured_at: row.capture_captured_at,
                  change_id: row.change_id ?? null,
                  entry_count: row.entry_count,
                  ...(row.observations_digest ? {
                    classifier_version: row.classifier_version ?? null,
                    observations: encodeFirewallObservations(row.observations),
                    observations_digest: row.observations_digest,
                  } : {}),
                }),
                row.idempotency_key ?? null, row.created_by, row.created_at,
              ],
            );
            if (!inserted.rows[0]) throw new CaptureConflict(row.id);
            await insertReferences(client, row.tenant_id, row.references.map((reference, ordinal) => ({
              baseline_id: row.id,
              ordinal,
              expectation_id: row.expectation_id,
              entry_path_id: row.entry_path_id ?? null,
              reference,
              created_at: row.created_at,
            })));
          }
          await appendAudit(audit, auditEntry, client);
          return { capture_id: rows[0].capture_id, replayed: false };
        });
      } catch (err) {
        if (!(err instanceof CaptureConflict)) throw err;
        const existing = rows[0].idempotency_key ? await repo.findBaselineCaptureIdByKey(ctx, rows[0].idempotency_key) : null;
        if (existing) return { capture_id: existing, replayed: true };
        return { error: 'invalid_comparison_baseline', status: 409, message: 'This evidence is already captured in another baseline.' };
      }
    },

    async getBaselineCaptureRows(ctx, captureId) {
      return run(ctx, async (client) => captureRows(client, ctx.tenantId, captureId));
    },

    async getBaselineCaptureRowsByIds(ctx, captureIds) {
      if (!captureIds.length) return [];
      return run(ctx, async (client) => {
        const { rows } = await client.query(
          `SELECT ${BASELINE_COLUMNS} FROM protection_comparison_baselines
           WHERE tenant_id = $1 AND provenance_json->>'capture_id' = ANY($2::text[])
           ORDER BY id, (provenance_json->>'capture_index')::int`,
          [ctx.tenantId, captureIds],
        );
        return readBaselines(client, ctx.tenantId, rows);
      });
    },

    async listBaselineCaptureHeads(ctx, filter) {
      return run(ctx, async (client) => {
        const { rows } = await client.query(
          `SELECT ${BASELINE_COLUMNS} FROM protection_comparison_baselines
           WHERE tenant_id = $1 AND kind = $2 AND (provenance_json->>'capture_index') = '0'
             AND ($3::text IS NULL OR status = $3)
             AND ($4::text IS NULL OR provenance_json->>'change_id' = $4)
             AND ($5::text IS NULL OR entry_path_id = $5)
             AND ($6::text IS NULL OR expectation_id = $6)
             ${cursorClause(filter.cursor, 8, 9)}
           ORDER BY created_at DESC, id COLLATE "C" DESC
           LIMIT $7`,
          [ctx.tenantId, filter.kind, filter.status, filter.change_id, filter.entry_path_id, filter.expectation_id,
            filter.limit, ...(filter.cursor ? [filter.cursor.created_at, filter.cursor.id] : [])],
        );
        return rows.map((row) => mapBaseline(row, []));
      });
    },

    async existingIds(ctx, { runs = [], verdicts = [], targets = [] }) {
      return run(ctx, async (client) => {
        const ids = async (table, values) => {
          if (!values.length) return new Set();
          const { rows } = await client.query(`SELECT id FROM ${table} WHERE tenant_id = $1 AND id = ANY($2::text[])`, [ctx.tenantId, values]);
          return new Set(rows.map((row) => row.id));
        };
        return { runs: await ids('test_runs', runs), verdicts: await ids('verdicts', verdicts), targets: await ids('targets', targets) };
      });
    },

    async findEvaluationByDigest(ctx, digest) {
      return run(ctx, async (client) => {
        const { rows } = await client.query(
          `SELECT ${EVALUATION_COLUMNS} FROM protection_comparison_evaluations WHERE tenant_id = $1 AND evaluation_digest = $2`,
          [ctx.tenantId, digest],
        );
        return mapEvaluation(rows[0]);
      });
    },

    async findEvaluationByIdempotencyKey(ctx, key) {
      return run(ctx, async (client) => {
        const { rows } = await client.query(
          `SELECT ${EVALUATION_COLUMNS} FROM protection_comparison_evaluations WHERE tenant_id = $1 AND idempotency_key = $2`,
          [ctx.tenantId, key],
        );
        return mapEvaluation(rows[0]);
      });
    },

    async insertEvaluation(ctx, record, auditEntry, audit) {
      return run(ctx, async (client) => {
        const inserted = await client.query(
          `INSERT INTO protection_comparison_evaluations (
             id, tenant_id, kind, baseline_id, baseline_digest, anchor_target_id, primary_entry_path_id,
             reviewed_plan_digest, comparable, stale, compatibility_reasons, total_count, evaluated_count, accepted,
             items_json, summary_json, limitations, evaluated_at, evaluation_digest, contract_version, provenance_json,
             idempotency_key, created_by, created_at
           ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::text[], $12, $13, $14, $15::jsonb, $16::jsonb,
             $17::text[], $18::timestamptz, $19, $20, $21::jsonb, $22, $23, $24::timestamptz)
           ON CONFLICT DO NOTHING
           RETURNING ${EVALUATION_COLUMNS}`,
          [
            record.id, record.tenant_id, record.kind, record.baseline_id ?? null, record.baseline_digest ?? null,
            record.anchor_target_id ?? null, record.primary_entry_path_id ?? null, record.reviewed_plan_digest ?? null,
            record.compatibility.comparable, record.compatibility.stale, record.compatibility.reasons,
            record.summary.total, record.summary.evaluated, record.summary.accepted,
            JSON.stringify(record.items), JSON.stringify(record.summary), record.limitations, record.evaluated_at,
            record.evaluation_digest, record.contract_version, JSON.stringify(record.provenance ?? {}),
            record.idempotency_key ?? null, record.created_by, record.created_at,
          ],
        );
        if (!inserted.rows[0]) {
          const { rows } = await client.query(
            `SELECT ${EVALUATION_COLUMNS} FROM protection_comparison_evaluations
             WHERE tenant_id = $1 AND (evaluation_digest = $2 OR ($3::text IS NOT NULL AND idempotency_key = $3))
             ORDER BY created_at LIMIT 1`,
            [record.tenant_id, record.evaluation_digest, record.idempotency_key ?? null],
          );
          if (!rows[0]) return { error: 'invalid_comparison_evaluation', status: 409 };
          return { row: mapEvaluation(rows[0]), replayed: true };
        }
        const references = record.items.flatMap((item, itemIndex) => item.evidence_refs.map((reference, ordinal) => ({
          evaluation_id: record.id,
          item_index: itemIndex,
          ordinal,
          expectation_id: item.expectation_id ?? null,
          entry_path_id: item.entry_path_id ?? null,
          reference,
          created_at: record.created_at,
        })));
        await insertReferences(client, record.tenant_id, references);
        await appendAudit(audit, auditEntry, client);
        return { row: mapEvaluation(inserted.rows[0]), replayed: false };
      });
    },

    async getEvaluation(ctx, id) {
      return run(ctx, async (client) => {
        const { rows } = await client.query(
          `SELECT ${EVALUATION_COLUMNS} FROM protection_comparison_evaluations WHERE tenant_id = $1 AND id = $2`,
          [ctx.tenantId, id],
        );
        return mapEvaluation(rows[0]);
      });
    },

    async loadEdgeDetections(ctx, targetIds) {
      if (!targetIds.length) return [];
      return run(ctx, async (client) => {
        const { rows } = await client.query(
          `SELECT tenant_id, target_id, waf_status, waf_vendor, waf_providers, cdn_status, cdn_provider, cdn_providers
           FROM target_edge_detections WHERE tenant_id = $1 AND target_id = ANY($2::text[])`,
          [ctx.tenantId, targetIds],
        );
        return rows;
      });
    },

    async loadConfigurationSnapshots(ctx, { limit = 1000 } = {}) {
      return run(ctx, async (client) => {
        const snapshots = await client.query(
          `SELECT id, tenant_id, connector_id, provider, snapshot_kind, resource_ref_hash, display_ref, summary_json,
                  config_hash, evidence_source, inventory_complete, inventory_truncated, ${exact('observed_at')} AS observed_at
           FROM waf_connector_snapshots WHERE tenant_id = $1
           ORDER BY observed_at DESC, id DESC LIMIT $2`,
          [ctx.tenantId, limit],
        );
        return { snapshots: snapshots.rows, connectors: [] };
      });
    },

    async listReportSources(ctx, { limit = 500 } = {}) {
      return run(ctx, async (client) => {
        const paths = await client.query(
          `SELECT ${ENTRY_PATH_COLUMNS} FROM application_entry_paths WHERE tenant_id = $1
           ORDER BY created_at DESC, id COLLATE "C" DESC LIMIT $2`,
          [ctx.tenantId, limit],
        );
        const expectations = await client.query(
          `SELECT ${EXPECTATION_COLUMNS} FROM protection_expectations WHERE tenant_id = $1
           ORDER BY created_at DESC, id COLLATE "C" DESC LIMIT $2`,
          [ctx.tenantId, limit],
        );
        const evaluations = await client.query(
          `SELECT ${EVALUATION_COLUMNS} FROM protection_comparison_evaluations WHERE tenant_id = $1
           ORDER BY created_at DESC, id COLLATE "C" DESC LIMIT $2`,
          [ctx.tenantId, limit],
        );
        const entryPaths = paths.rows.map(mapEntryPath);
        const expectationRows = expectations.rows.map(mapExpectation);
        const ids = [...new Set([
          ...entryPaths.flatMap((row) => [row.anchor_target_id, row.entry_target_id]),
          ...expectationRows.flatMap((row) => [row.anchor_target_id, row.destination_target_id]),
        ].filter(Boolean))];
        const targets = ids.length
          ? (await client.query(
            `SELECT id, tenant_id, target_group_id, kind, value, ${nullableExact('deleted_at')} AS deleted_at
             FROM targets WHERE tenant_id = $1 AND id = ANY($2::text[])`,
            [ctx.tenantId, ids],
          )).rows
          : [];
        return { targets, entryPaths, expectations: expectationRows, evaluations: evaluations.rows.map(mapEvaluation) };
      });
    },

    async listEvaluations(ctx, filter) {
      return run(ctx, async (client) => {
        const { rows } = await client.query(
          `SELECT ${EVALUATION_COLUMNS} FROM protection_comparison_evaluations
           WHERE tenant_id = $1 AND kind = $2
             AND ($3::text IS NULL OR provenance_json->>'change_id' = $3)
             AND ($4::text IS NULL OR baseline_id = $4)
             AND ($5::text IS NULL OR anchor_target_id = $5)
             ${cursorClause(filter.cursor, 7, 8)}
           ORDER BY created_at DESC, id COLLATE "C" DESC
           LIMIT $6`,
          [ctx.tenantId, filter.kind, filter.change_id, filter.baseline_id, filter.anchor_target_id, filter.limit,
            ...(filter.cursor ? [filter.cursor.created_at, filter.cursor.id] : [])],
        );
        return rows.map(mapEvaluation);
      });
    },
  };
  return repo;
}
