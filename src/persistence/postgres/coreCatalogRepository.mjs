import {
  normalizeTargetInput,
  targetValidationResponse,
} from '../../contracts/targetManagement.mjs';
import { newId } from '../../lib/ids.mjs';
import {
  isCurrentProviderDnsOwnershipProof,
  isProviderVerifiedDnsEvidence,
} from '../../lib/connectorProviders/domainInventory.mjs';
import { ownershipProofFromStates, ownershipSummaryFromTargetStates } from '../../lib/ownershipPolicy.mjs';
import { normalizePrivacySettings } from '../../lib/privacySettings.mjs';
import { normalizeSafetyPolicy } from '../../lib/safeTestGuards.mjs';
import { runMetadataRetentionInTransaction } from './retentionRepository.mjs';
import { withTenantContext } from './tenantContext.mjs';

function toIso(value) {
  if (value == null) return value;
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

function asObject(value) {
  if (value && typeof value === 'object' && !Array.isArray(value)) return value;
  return {};
}

function mapTenantRow(row) {
  if (!row) return null;
  const dashboardRollup = asObject(row.dashboard_rollup);
  return {
    id: row.id,
    name: row.name,
    plan: row.plan ?? undefined,
    data_region: row.data_region ?? undefined,
    status: row.status ?? 'active',
    privacy_settings: normalizePrivacySettings(row.privacy_settings),
    dashboard_rollup: dashboardRollup,
    created_at: toIso(row.created_at),
  };
}

function mapEnvironmentRow(row) {
  if (!row) return null;
  const settings = asObject(row.settings_json);
  const mapped = {
    id: row.id,
    tenant_id: row.tenant_id,
    name: row.name,
    description: settings.description ?? '',
    status: row.status ?? 'active',
    privacy_settings: normalizePrivacySettings(row.privacy_settings),
    created_at: toIso(row.created_at),
  };
  if (row.timezone) mapped.timezone = row.timezone;
  if (settings.created_by) mapped.created_by = settings.created_by;
  if (settings.updated_at) mapped.updated_at = toIso(settings.updated_at);
  return mapped;
}

const ACTIVE_RUN_STATUSES = Object.freeze(['planned', 'running', 'collecting']);

async function appendMutationAudit(auditRepository, client, ctx, event, now) {
  if (!auditRepository?.appendAuditEvent) {
    throw new Error('Postgres target management requires transactional audit persistence.');
  }
  return auditRepository.appendAuditEvent({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    ...event,
  }, { client, now: new Date(now) });
}

function mapTargetGroupRow(row) {
  if (!row) return null;
  const windows = row.safe_test_windows;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    environment_id: row.environment_id,
    name: row.name,
    description: row.description ?? '',
    expected_behavior_default: row.expected_behavior_default ?? undefined,
    timezone: row.timezone ?? 'UTC',
    safe_test_windows: Array.isArray(windows) ? windows : [],
    safety_policy: normalizeSafetyPolicy(row.safety_policy),
    created_at: toIso(row.created_at),
    ...(row.deleted_at
      ? { deleted_at: toIso(row.deleted_at), deleted_by: row.deleted_by ?? null }
      : {}),
    ...(row.archived_at ? { archived_at: toIso(row.archived_at) } : {}),
    validation_mode: row.validation_mode ?? 'external_only',
    ownership_status: row.ownership_status ?? 'unverified',
    dns_ownership: row.dns_ownership ?? null,
    // Only the list query selects these summary columns; other callers omit them entirely.
    ...(row.target_count === undefined ? {} : { target_count: Number(row.target_count) }),
    ...(row.loa_state === undefined ? {} : { loa_state: row.loa_state ?? 'required' }),
  };
}

/** Detail-page cap on recent runs, matching the dev-json reference implementation. */
const TARGET_GROUP_RUNS_RECENT_LIMIT = 6;

/** Detail-page cap on findings, matching the dev-json reference implementation. */
const TARGET_GROUP_FINDINGS_LIMIT = 50;

/**
 * Options for the lean `getTargetGroup` lookup that internal callers use.
 *
 * The enriched read carries LOA / recent-runs / findings LATERAL aggregates for the API
 * detail route. Every internal caller (run start,
 * collect, ingest, WAF orchestration, high-scale, policy enrichment, agent binding) only
 * reads the group row and its targets, so they paid for aggregates they discard. Only the
 * HTTP detail handler still asks for the enriched shape.
 */
export const LEAN_GROUP_LOOKUP = Object.freeze({ enriched: false });

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

/**
 * Detail-only enrichment for GET /v1/target-groups/:id. Mirrors the dev-json shape in
 * src/services/targetGroups.mjs `getTargetGroup` so both adapters feed the same portal panels.
 *
 * @param {Record<string, unknown> | null} row target_groups row with the detail LATERAL columns
 * @param {Array<Record<string, unknown>>} targets already-mapped target rows
 */
function mapTargetGroupDetail(row, targets) {
  const runsRecent = asArray(row?.runs_recent).map((run) => ({
    id: run.id,
    policy_id: run.policy_id ?? null,
    check_count: run.check_count ?? run.check_id ?? null,
    verdict: run.verdict ?? run.status ?? 'pending',
    started_at: toIso(run.started_at),
    agent_id: run.agent_id ?? null,
  }));
  const findingsOnGroup = asArray(row?.findings_on_group).map((finding) => ({
    id: finding.id,
    target_id: finding.target_id ?? null,
    title: finding.title,
    severity: finding.severity,
    status: finding.status ?? 'open',
  }));
  return {
    targets,
    target_count: targets.length,
    runs_recent: runsRecent,
    findings_on_group: findingsOnGroup,
    findings_on_group_total: Number(row?.findings_on_group_total ?? findingsOnGroup.length),
    loa: row?.loa_state
      ? {
          state: row.loa_state,
          signer_name: row.loa_signer_name ?? null,
          signed_at: toIso(row.loa_signed_at),
          custody_digest_sha256: row.loa_custody_digest_sha256 ?? null,
        }
      : null,
    meta: {
      targets_empty_reason: targets.length
        ? null
        : 'No targets have been declared for this group yet.',
      runs_empty_reason: runsRecent.length
        ? null
        : 'No test runs have been recorded for this target group yet.',
      findings_empty_reason: findingsOnGroup.length
        ? null
        : 'No findings are published for this target group yet.',
    },
  };
}

async function hasActiveRunForGroup(client, tenantId, targetGroupId) {
  const { rows } = await client.query(
    `SELECT 1
     FROM test_runs
     WHERE tenant_id = $1
       AND target_group_id = $2
       AND status = ANY($3::text[])
     LIMIT 1`,
    [tenantId, targetGroupId, ACTIVE_RUN_STATUSES],
  );
  return rows.length > 0;
}

async function hasActiveRunForTarget(client, tenantId, targetGroupId, targetId) {
  const { rows } = await client.query(
    `SELECT 1
     FROM test_runs
     WHERE tenant_id = $1
       AND target_group_id = $2
       AND target_id = $3
       AND status = ANY($4::text[])
     LIMIT 1`,
    [tenantId, targetGroupId, targetId, ACTIVE_RUN_STATUSES],
  );
  return rows.length > 0;
}

function mapTargetRow(row) {
  if (!row) return null;
  const mapped = {
    id: row.id,
    tenant_id: row.tenant_id,
    target_group_id: row.target_group_id,
    kind: row.kind,
    value: row.value,
    normalized_value: row.normalized_value ?? row.value,
    expected_behavior: row.expected_behavior ?? undefined,
    created_at: toIso(row.created_at),
    ...(row.deleted_at ? { deleted_at: toIso(row.deleted_at), deleted_by: row.deleted_by ?? null } : {}),
  };
  const metadata = asObject(row.metadata_json);
  if (Object.keys(metadata).length > 0) mapped.metadata = metadata;
  return mapped;
}

function mapDetailTargetRow(row) {
  const mapped = mapTargetRow(row);
  if (!mapped) return null;
  return { ...mapped, verification_state: row.verification_state ?? 'unverified' };
}

function optionalString(...values) {
  for (const value of values) {
    if (value == null) continue;
    const normalized = String(value).trim();
    if (normalized) return normalized;
  }
  return null;
}

function mapTargetInventoryRow(row) {
  const mapped = mapTargetRow(row);
  if (!mapped) return null;
  const metadata = asObject(row.metadata_json);
  const verificationState = optionalString(row.verification_state) ?? 'unverified';
  const sourceKind = optionalString(row.verification_source_kind);
  const sourceRef = row.verification_source_ref ?? null;
  const transitionedAt = toIso(row.verification_transitioned_at) ?? null;
  const managedProvenance = asObject(metadata.managed_provenance);
  const declaredImport = asObject(metadata.declared_import);
  const importIntegration = optionalString(managedProvenance.connector_id, declaredImport.label);
  const source = managedProvenance.connector_id
    ? 'connector_inventory'
    : declaredImport.label
      ? 'customer_declared_import'
      : 'manual';
  const proof = ownershipProofFromStates({
    groupState: row.ownership_status,
    targetState: verificationState,
  });
  const eligibility = proof.verified ? 'eligible' : 'not_eligible';
  const eligibilityReason = proof.verified ? null : 'verification_required';

  return {
    ...mapped,
    target_group_name: row.target_group_name,
    environment_id: row.environment_id ?? null,
    environment_name: row.environment_name ?? null,
    expected_behavior: row.expected_behavior ?? row.expected_behavior_default ?? null,
    verification_state: verificationState,
    verification: {
      state: verificationState,
      source_kind: sourceKind,
      source_ref: sourceRef,
      transitioned_at: transitionedAt,
    },
    eligibility,
    eligibility_reason: eligibilityReason,
    source,
    import_source: importIntegration,
    import_integration: importIntegration,
    created_at: toIso(row.created_at),
  };
}

/**
 * @param {import('pg').Pool} pool
 */
export function createCoreCatalogRepository(pool, options = {}) {
  const auditRepository = options.auditRepository;
  return {
    async getCurrentTenant(ctx) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT id, name, plan, data_region, status, privacy_settings, dashboard_rollup, created_at
           FROM tenants
           WHERE id = $1`,
          [ctx.tenantId],
        );
        return mapTenantRow(rows[0] ?? null);
      });
    },

    async patchCurrentTenant(ctx, body, options = {}) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const existing = await client.query(
          `SELECT id, name, plan, data_region, status, privacy_settings, created_at
           FROM tenants
           WHERE id = $1`,
          [ctx.tenantId],
        );
        if (!existing.rows[0]) return null;

        const current = existing.rows[0];
        const sets = [];
        const params = [];
        let n = 1;

        if (body.name) {
          sets.push(`name = $${n++}`);
          params.push(body.name);
        }
        if (body.privacy_settings) {
          const merged = normalizePrivacySettings({
            ...asObject(current.privacy_settings),
            ...body.privacy_settings,
          });
          sets.push(`privacy_settings = $${n++}::jsonb`);
          params.push(JSON.stringify(merged));
        }

        if (sets.length === 0) {
          return mapTenantRow(current);
        }

        params.push(ctx.tenantId);
        const idParam = n++;

        const { rows } = await client.query(
          `UPDATE tenants
           SET ${sets.join(', ')}
           WHERE id = $${idParam}
           RETURNING id, name, plan, data_region, status, privacy_settings, created_at`,
          params,
        );
        const tenantRow = rows[0] ?? null;
        if (!tenantRow) return null;
        if (body.privacy_settings) {
          await runMetadataRetentionInTransaction(
            client,
            ctx.tenantId,
            tenantRow,
            { userId: ctx.userId, role: ctx.role },
            { now: options.now },
          );
        }
        return mapTenantRow(tenantRow);
      });
    },

    async listEnvironments(ctx) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT id, tenant_id, name, status, timezone, privacy_settings, settings_json, created_at
           FROM environments
           WHERE tenant_id = $1 AND status <> $2
           ORDER BY created_at`,
          [ctx.tenantId, 'archived'],
        );
        return rows.map(mapEnvironmentRow);
      });
    },

    async createEnvironment(ctx, body, options = {}) {
      const id = options.id ?? newId('env');
      const now = options.now ?? new Date().toISOString();
      const name = body.name ?? 'Environment';
      const description = body.description ?? '';
      const privacySettings = normalizePrivacySettings(body.privacy_settings);
      const settingsJson = {
        description,
        created_by: ctx.userId,
      };

      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO environments (id, tenant_id, name, status, privacy_settings, settings_json, created_at)
           VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7::timestamptz)
           RETURNING id, tenant_id, name, status, timezone, privacy_settings, settings_json, created_at`,
          [id, ctx.tenantId, name, 'active', JSON.stringify(privacySettings), JSON.stringify(settingsJson), now],
        );
        return mapEnvironmentRow(rows[0]);
      });
    },

    async patchEnvironment(ctx, id, body, options = {}) {
      const now = options.now ?? new Date().toISOString();

      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const existing = await client.query(
          `SELECT id, tenant_id, name, status, timezone, privacy_settings, settings_json, created_at
           FROM environments
           WHERE id = $1 AND tenant_id = $2`,
          [id, ctx.tenantId],
        );
        if (!existing.rows[0]) return null;

        const current = existing.rows[0];
        const settings = { ...asObject(current.settings_json) };
        const sets = [];
        const params = [];
        let n = 1;

        if (body.name) {
          sets.push(`name = $${n++}`);
          params.push(body.name);
        }
        if (body.description !== undefined) {
          settings.description = body.description;
        }
        if (body.status) {
          sets.push(`status = $${n++}`);
          params.push(body.status);
        }
        if (body.privacy_settings) {
          const merged = normalizePrivacySettings({
            ...asObject(current.privacy_settings),
            ...body.privacy_settings,
          });
          sets.push(`privacy_settings = $${n++}::jsonb`);
          params.push(JSON.stringify(merged));
        }

        settings.updated_at = now;
        sets.push(`settings_json = $${n++}::jsonb`);
        params.push(JSON.stringify(settings));

        params.push(id, ctx.tenantId);
        const idParam = n++;
        const tenantParam = n++;

        const { rows } = await client.query(
          `UPDATE environments
           SET ${sets.join(', ')}
           WHERE id = $${idParam} AND tenant_id = $${tenantParam}
           RETURNING id, tenant_id, name, status, timezone, privacy_settings, settings_json, created_at`,
          params,
        );
        return mapEnvironmentRow(rows[0]);
      });
    },

    async listTargets(ctx) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT t.id, t.tenant_id, t.target_group_id, t.kind, t.value,
                  t.expected_behavior, t.metadata_json, t.created_at,
                  tg.name AS target_group_name, tg.environment_id,
                  tg.expected_behavior_default, tg.ownership_status,
                  environment.name AS environment_name,
                  verification.state AS verification_state,
                  verification.source_kind AS verification_source_kind,
                  verification.source_ref AS verification_source_ref,
                  verification.transitioned_at AS verification_transitioned_at
           FROM targets t
           JOIN target_groups tg
             ON tg.id = t.target_group_id AND tg.tenant_id = t.tenant_id
           LEFT JOIN environments environment
             ON environment.id = tg.environment_id AND environment.tenant_id = t.tenant_id
           LEFT JOIN target_verification_current verification
             ON verification.tenant_id = t.tenant_id AND verification.target_id = t.id
           WHERE t.tenant_id = $1
             AND t.deleted_at IS NULL
             AND tg.tenant_id = $1
             AND tg.deleted_at IS NULL
             AND tg.archived_at IS NULL
           ORDER BY t.created_at DESC, t.id`,
          [ctx.tenantId],
        );
        return rows.map(mapTargetInventoryRow);
      });
    },

    async listTargetGroups(ctx, options = {}) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const archivedOnly = options.archived === true;
        const activeFilter = archivedOnly
          ? '(tg.deleted_at IS NOT NULL OR tg.archived_at IS NOT NULL)'
          : 'tg.deleted_at IS NULL AND tg.archived_at IS NULL';
        const { rows } = await client.query(
          `SELECT tg.id, tg.tenant_id, tg.environment_id, tg.name, tg.description,
                  tg.expected_behavior_default, tg.timezone, tg.safe_test_windows,
                  tg.safety_policy, tg.deleted_at, tg.deleted_by, tg.archived_at,
                  tg.validation_mode, tg.ownership_status, tg.dns_ownership, tg.created_at,
                  COALESCE(tc.target_count, 0) AS target_count,
                  loa.state AS loa_state
           FROM target_groups tg
           LEFT JOIN (
             SELECT target_group_id, COUNT(*)::int AS target_count
             FROM targets
             WHERE tenant_id = $1 AND deleted_at IS NULL
             GROUP BY target_group_id
           ) tc ON tc.target_group_id = tg.id
           LEFT JOIN LATERAL (
             SELECT state
             FROM loa_signatures
             WHERE tenant_id = $1 AND target_group_id = tg.id AND state = 'signed'
             LIMIT 1
           ) loa ON TRUE
           WHERE tg.tenant_id = $1 AND ${activeFilter}
           ORDER BY tg.created_at`,
          [ctx.tenantId],
        );
        return rows.map(mapTargetGroupRow);
      });
    },

    /**
     * @param {{ enriched?: boolean }} [options] `{ enriched: false }` is the lean lookup: the
     *   group row plus its targets, with none of the detail aggregates.
     */
    async getTargetGroup(ctx, id, options = {}) {
      if (options.enriched === false) {
        return withTenantContext(pool, ctx.tenantId, async (client) => {
          const { rows } = await client.query(
            `SELECT tg.id, tg.tenant_id, tg.environment_id, tg.name, tg.description,
                    tg.expected_behavior_default, tg.timezone, tg.safe_test_windows,
                    tg.safety_policy, tg.archived_at, tg.validation_mode,
                    tg.ownership_status, tg.dns_ownership, tg.created_at
             FROM target_groups tg
             WHERE tg.id = $1 AND tg.tenant_id = $2
               AND tg.deleted_at IS NULL AND tg.archived_at IS NULL`,
            [id, ctx.tenantId],
          );
          const group = mapTargetGroupRow(rows[0] ?? null);
          if (!group) return null;
          const targets = await client.query(
            `SELECT t.id, t.tenant_id, t.target_group_id, t.kind, t.value, t.normalized_value,
                    t.expected_behavior, t.metadata_json, t.created_at,
                    verification.state AS verification_state
             FROM targets t
             LEFT JOIN target_verification_current verification
               ON verification.tenant_id = t.tenant_id AND verification.target_id = t.id
             WHERE t.target_group_id = $1 AND t.tenant_id = $2 AND t.deleted_at IS NULL
             ORDER BY t.created_at`,
            [id, ctx.tenantId],
          );
          const mapped = targets.rows.map(mapTargetRow);
          return { ...group, targets: mapped, target_count: mapped.length };
        });
      }
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        // Detail enrichment rides on the group read (one round trip) so the Postgres
        // payload matches the dev-json reference in src/services/targetGroups.mjs.
        const { rows } = await client.query(
          `SELECT tg.id, tg.tenant_id, tg.environment_id, tg.name, tg.description,
                  tg.expected_behavior_default, tg.timezone, tg.safe_test_windows,
                  tg.safety_policy, tg.archived_at, tg.validation_mode,
                  tg.ownership_status, tg.dns_ownership, tg.created_at,
                  loa.state AS loa_state,
                  loa.signer_name AS loa_signer_name,
                  loa.signed_at AS loa_signed_at,
                  loa.custody_digest_sha256 AS loa_custody_digest_sha256,
                  runs.items AS runs_recent,
                  findings.items AS findings_on_group,
                  findings.total AS findings_on_group_total
           FROM target_groups tg
           LEFT JOIN LATERAL (
             SELECT state, signer_name, signed_at, custody_digest_sha256
             FROM loa_signatures
             WHERE tenant_id = $2 AND target_group_id = tg.id AND state = 'signed'
             LIMIT 1
           ) loa ON TRUE
           LEFT JOIN LATERAL (
             SELECT jsonb_agg(
                      jsonb_build_object(
                        'id', run.id,
                        'policy_id', run.policy_id,
                        'check_id', run.check_id,
                        'status', run.status,
                        'started_at', run.started_at
                      )
                      ORDER BY run.started_at DESC, run.id
                    ) AS items
             FROM (
               SELECT id, policy_id, check_id, status,
                      to_char(
                        COALESCE(started_at, created_at) AT TIME ZONE 'UTC',
                        'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
                      ) AS started_at
               FROM test_runs
               WHERE tenant_id = $2 AND target_group_id = tg.id
               ORDER BY COALESCE(started_at, created_at) DESC, id
               LIMIT $3
             ) run
           ) runs ON TRUE
           LEFT JOIN LATERAL (
             SELECT
               (
                 SELECT count(*)::int
                 FROM findings
                 WHERE tenant_id = $2 AND target_group_id = tg.id
               ) AS total,
               (
                 SELECT jsonb_agg(
                          jsonb_build_object(
                            'id', finding.id,
                            'target_id', finding.target_id,
                            'title', finding.title,
                            'severity', finding.severity,
                            'status', finding.status
                          )
                          ORDER BY finding.created_at DESC, finding.id DESC
                        )
                 FROM (
                   SELECT id, target_id, title, severity, status, created_at
                   FROM findings
                   WHERE tenant_id = $2 AND target_group_id = tg.id
                   ORDER BY created_at DESC, id DESC
                   LIMIT $4
                 ) finding
               ) AS items
           ) findings ON TRUE
           WHERE tg.id = $1 AND tg.tenant_id = $2
             AND tg.deleted_at IS NULL AND tg.archived_at IS NULL`,
          [id, ctx.tenantId, TARGET_GROUP_RUNS_RECENT_LIMIT, TARGET_GROUP_FINDINGS_LIMIT],
        );
        const row = rows[0] ?? null;
        const group = mapTargetGroupRow(row);
        if (!group) return null;

        const targets = await client.query(
          `SELECT t.id, t.tenant_id, t.target_group_id, t.kind, t.value, t.normalized_value,
                  t.expected_behavior, t.metadata_json, t.created_at,
                  verification.state AS verification_state
           FROM targets t
           LEFT JOIN target_verification_current verification
             ON verification.tenant_id = t.tenant_id AND verification.target_id = t.id
           WHERE t.target_group_id = $1 AND t.tenant_id = $2 AND t.deleted_at IS NULL
           ORDER BY t.created_at`,
          [id, ctx.tenantId],
        );
        return {
          ...group,
          ...mapTargetGroupDetail(row, targets.rows.map(mapDetailTargetRow)),
        };
      });
    },

    async createTargetGroup(ctx, body = {}, options = {}) {
      const id = options.id ?? newId('tg');
      const now = options.now ?? new Date().toISOString();
      const rawEnvironmentId = typeof body.environment_id === 'string' ? body.environment_id.trim() : body.environment_id;
      const record = {
        environment_id: rawEnvironmentId || 'env_demo',
        name: String(body.name ?? 'New target group').trim() || 'New target group',
        description: String(body.description ?? ''),
        expected_behavior_default: body.expected_behavior_default ?? null,
        timezone: String(body.timezone ?? 'UTC').trim() || 'UTC',
        safe_test_windows: Array.isArray(body.safe_test_windows) ? body.safe_test_windows : [],
        safety_policy: normalizeSafetyPolicy(body.safety_policy),
        validation_mode: body.validation_mode === 'agent_assisted' ? 'agent_assisted' : 'external_only',
      };

      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const envCheck = await client.query(
          `SELECT id FROM environments WHERE tenant_id = $1 AND id = $2`,
          [ctx.tenantId, record.environment_id],
        );
        if (!envCheck.rows[0]) {
          return {
            error: 'invalid_environment',
            status: 400,
            message: `Environment "${record.environment_id}" does not exist for this tenant. Create the environment first, then declare the target group.`,
            field: 'environment_id',
          };
        }
        const duplicate = await client.query(
          `SELECT id FROM target_groups
           WHERE tenant_id = $1 AND environment_id = $2 AND lower(name) = lower($3)
             AND deleted_at IS NULL AND archived_at IS NULL
           LIMIT 1`,
          [ctx.tenantId, record.environment_id, record.name],
        );
        if (duplicate.rows[0]) return { error: 'target_group_exists', status: 409, existing_id: duplicate.rows[0].id };

        try {
          const { rows } = await client.query(
            `INSERT INTO target_groups (
               id, tenant_id, environment_id, name, description, expected_behavior_default,
               timezone, safe_test_windows, safety_policy, validation_mode, ownership_status,
               dns_ownership, created_at
             )
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9::jsonb, $10, 'unverified', NULL, $11::timestamptz)
             RETURNING id, tenant_id, environment_id, name, description, expected_behavior_default,
                       timezone, safe_test_windows, safety_policy, validation_mode, ownership_status,
                       dns_ownership, created_at`,
            [
              id, ctx.tenantId, record.environment_id, record.name, record.description,
              record.expected_behavior_default, record.timezone, JSON.stringify(record.safe_test_windows),
              JSON.stringify(record.safety_policy), record.validation_mode, now,
            ],
          );
          await appendMutationAudit(auditRepository, client, ctx, {
            action: 'target_group.created',
            resource_type: 'target_group',
            resource_id: id,
            metadata: { changed_fields: ['environment_id', 'name', 'description', 'expected_behavior_default', 'timezone', 'safe_test_windows', 'safety_policy', 'validation_mode'] },
          }, now);
          return mapTargetGroupRow(rows[0]);
        } catch (error) {
          if (error?.code === '23505') return { error: 'target_group_exists', status: 409 };
          throw error;
        }
      });
    },

    async addTarget(ctx, groupId, body = {}, options = {}) {
      const id = options.id ?? newId('target');
      const now = options.now ?? new Date().toISOString();
      let normalized;
      try {
        normalized = normalizeTargetInput(body);
      } catch (error) {
        return targetValidationResponse(error);
      }

      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const groupResult = await client.query(
          `SELECT id FROM target_groups
           WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL AND archived_at IS NULL`,
          [groupId, ctx.tenantId],
        );
        if (!groupResult.rows[0]) return null;
        const duplicate = await client.query(
          `SELECT id FROM targets
           WHERE tenant_id = $1 AND target_group_id = $2 AND kind = $3
             AND normalized_value = $4 AND deleted_at IS NULL
           LIMIT 1`,
          [ctx.tenantId, groupId, normalized.kind, normalized.normalized_value],
        );
        if (duplicate.rows[0]) return { error: 'target_exists', status: 409, existing_id: duplicate.rows[0].id };

        try {
          const { rows } = await client.query(
            `INSERT INTO targets (
               id, tenant_id, target_group_id, kind, value, normalized_value,
               expected_behavior, metadata_json, created_at
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9::timestamptz)
             RETURNING id, tenant_id, target_group_id, kind, value, normalized_value,
                       expected_behavior, metadata_json, created_at`,
            [id, ctx.tenantId, groupId, normalized.kind, normalized.value, normalized.normalized_value,
              body.expected_behavior ?? null, JSON.stringify(normalized.metadata), now],
          );
          await client.query(
            `UPDATE target_groups
             SET ownership_status = 'unverified'
             WHERE tenant_id = $1 AND id = $2
               AND deleted_at IS NULL AND archived_at IS NULL`,
            [ctx.tenantId, groupId],
          );
          await appendMutationAudit(auditRepository, client, ctx, {
            action: 'target.added',
            resource_type: 'target',
            resource_id: id,
            metadata: {
              target_group_id: groupId,
              changed_fields: ['kind', 'value', 'expected_behavior', ...(Object.keys(normalized.metadata).length ? ['metadata'] : [])],
              dropped_untrusted_fields: normalized.dropped_fields,
            },
          }, now);
          return mapTargetRow(rows[0]);
        } catch (error) {
          if (error?.code === '23505') return { error: 'target_exists', status: 409 };
          throw error;
        }
      });
    },

    async patchTargetGroup(ctx, id, body = {}, options = {}) {
      const now = options.now ?? new Date().toISOString();
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const existing = await client.query(
          `SELECT id, tenant_id, environment_id, name, description, expected_behavior_default,
                  timezone, safe_test_windows, safety_policy, archived_at, deleted_at, validation_mode,
                  ownership_status, dns_ownership, created_at
           FROM target_groups
           WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL AND archived_at IS NULL`,
          [id, ctx.tenantId],
        );
        if (!existing.rows[0]) return null;
        const current = existing.rows[0];
        if (body.safe_test_windows !== undefined && !Array.isArray(body.safe_test_windows)) {
          return { error: 'invalid_target_group', status: 400, field: 'safe_test_windows' };
        }

        const nextName = body.name === undefined ? current.name : String(body.name).trim() || current.name;
        const nextEnvironmentId = body.environment_id === undefined
          ? current.environment_id
          : String(body.environment_id ?? '').trim() || null;
        if (nextName !== current.name || nextEnvironmentId !== current.environment_id) {
          const duplicate = await client.query(
            `SELECT id FROM target_groups
             WHERE tenant_id = $1 AND COALESCE(environment_id, '') = COALESCE($2, '')
               AND lower(name) = lower($3)
               AND id <> $4 AND deleted_at IS NULL AND archived_at IS NULL
             LIMIT 1`,
            [ctx.tenantId, nextEnvironmentId, nextName, id],
          );
          if (duplicate.rows[0]) return { error: 'target_group_exists', status: 409, existing_id: duplicate.rows[0].id };
        }

        const sets = [];
        const params = [];
        const changedFields = [];
        let n = 1;
        const add = (field, value, cast = '') => {
          sets.push(`${field} = $${n++}${cast}`);
          params.push(value);
          changedFields.push(field);
        };
        if (body.name !== undefined) add('name', nextName);
        if (body.description !== undefined) add('description', String(body.description ?? ''));
        if (body.environment_id !== undefined) add('environment_id', nextEnvironmentId);
        if (body.timezone !== undefined) add('timezone', String(body.timezone).trim() || 'UTC');
        if (body.safe_test_windows !== undefined) add('safe_test_windows', JSON.stringify(body.safe_test_windows), '::jsonb');
        if (body.safety_policy !== undefined) add('safety_policy', JSON.stringify(normalizeSafetyPolicy(body.safety_policy)), '::jsonb');
        if (body.validation_mode !== undefined) add('validation_mode', body.validation_mode === 'agent_assisted' ? 'agent_assisted' : 'external_only');
        if (sets.length === 0) return mapTargetGroupRow(current);

        params.push(id, ctx.tenantId);
        const idParam = n++;
        const tenantParam = n++;
        try {
          const { rows } = await client.query(
            `UPDATE target_groups SET ${sets.join(', ')}
             WHERE id = $${idParam} AND tenant_id = $${tenantParam}
               AND deleted_at IS NULL AND archived_at IS NULL
             RETURNING id, tenant_id, environment_id, name, description, expected_behavior_default,
                       timezone, safe_test_windows, safety_policy, archived_at, validation_mode,
                       ownership_status, dns_ownership, created_at`,
            params,
          );
          if (!rows[0]) return null;
          await appendMutationAudit(auditRepository, client, ctx, {
            action: 'target_group.updated', resource_type: 'target_group', resource_id: id,
            metadata: { changed_fields: changedFields },
          }, now);
          return mapTargetGroupRow(rows[0]);
        } catch (error) {
          if (error?.code === '23505') return { error: 'target_group_exists', status: 409 };
          throw error;
        }
      });
    },

    async archiveTargetGroup(ctx, id, options = {}) {
      const now = options.now ?? new Date().toISOString();
      const deletedBy = options.deletedBy ?? ctx.userId ?? 'system';
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const existing = await client.query(
          `SELECT id
           FROM target_groups
           WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL AND archived_at IS NULL
           FOR UPDATE`,
          [id, ctx.tenantId],
        );
        if (!existing.rows[0]) return null;
        if (await hasActiveRunForGroup(client, ctx.tenantId, id)) {
          return { error: 'target_group_active_run', status: 409 };
        }

        const pausedPolicies = await client.query(
          `UPDATE test_policies
           SET state = 'paused', enabled = FALSE, next_run_at = NULL,
               lease_token = NULL, lease_owner = NULL, lease_expires_at = NULL,
               schedule_revision = schedule_revision + 1,
               updated_at = $3::timestamptz
           WHERE tenant_id = $1 AND target_group_id = $2 AND archived_at IS NULL
           RETURNING id`,
          [ctx.tenantId, id, now],
        );
        const pausedPolicyIds = pausedPolicies.rows.map((policy) => policy.id);

        const { rows } = await client.query(
          `UPDATE target_groups
           SET deleted_at = $3::timestamptz,
               deleted_by = $4,
               archived_at = $3::timestamptz
           WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL AND archived_at IS NULL
           RETURNING id`,
          [id, ctx.tenantId, now, deletedBy],
        );
        if (!rows[0]) return null;
        await appendMutationAudit(auditRepository, client, ctx, {
          action: 'target_group.archived', resource_type: 'target_group', resource_id: id,
          metadata: {
            changed_fields: ['deleted_at', 'deleted_by', 'archived_at'],
            paused_policy_ids: pausedPolicyIds,
          },
        }, now);
        return {
          archived: true,
          id,
          deleted_at: now,
          deleted_by: deletedBy,
          paused_policy_count: pausedPolicyIds.length,
        };
      });
    },

    async patchTarget(ctx, groupId, targetId, body = {}, options = {}) {
      const now = options.now ?? new Date().toISOString();
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const groupResult = await client.query(
          `SELECT id FROM target_groups
           WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL AND archived_at IS NULL`,
          [groupId, ctx.tenantId],
        );
        if (!groupResult.rows[0]) return null;

        const existing = await client.query(
          `SELECT id, tenant_id, target_group_id, kind, value, normalized_value,
                  expected_behavior, metadata_json, created_at
           FROM targets
           WHERE id = $1 AND tenant_id = $2 AND target_group_id = $3 AND deleted_at IS NULL`,
          [targetId, ctx.tenantId, groupId],
        );
        if (!existing.rows[0]) return null;
        const current = existing.rows[0];
        let normalized;
        try {
          normalized = normalizeTargetInput(body, { current });
        } catch (error) {
          return targetValidationResponse(error);
        }

        if (
          (body.kind !== undefined || body.value !== undefined)
          && (
            normalized.kind !== current.kind
            || normalized.normalized_value !== current.normalized_value
          )
        ) {
          return {
            error: 'target_identity_immutable',
            status: 409,
            message: 'Target kind and value are immutable; create a new target so ownership must be proven again.',
          };
        }

        if (body.kind !== undefined || body.value !== undefined) {
          const duplicate = await client.query(
            `SELECT id FROM targets
             WHERE tenant_id = $1 AND target_group_id = $2 AND kind = $3
               AND normalized_value = $4 AND id <> $5 AND deleted_at IS NULL
             LIMIT 1`,
            [ctx.tenantId, groupId, normalized.kind, normalized.normalized_value, targetId],
          );

          if (duplicate.rows[0]) return { error: 'target_exists', status: 409, existing_id: duplicate.rows[0].id };
        }

        const sets = [];
        const params = [];
        const changedFields = [];
        let n = 1;
        const add = (field, value, cast = '') => {
          sets.push(`${field} = $${n++}${cast}`);
          params.push(value);
          changedFields.push(field);
        };
        if (body.kind !== undefined || body.value !== undefined) {
          add('kind', normalized.kind);
          add('value', normalized.value);
          add('normalized_value', normalized.normalized_value);
        }
        if (body.metadata !== undefined || body.metadata_json !== undefined) add('metadata_json', JSON.stringify(normalized.metadata), '::jsonb');
        if (body.expected_behavior !== undefined) add('expected_behavior', body.expected_behavior ?? null);
        if (sets.length === 0) return mapTargetRow(current);

        params.push(targetId, ctx.tenantId, groupId);
        const idParam = n++;
        const tenantParam = n++;
        const groupParam = n++;
        try {
          const { rows } = await client.query(
            `UPDATE targets SET ${sets.join(', ')}
             WHERE id = $${idParam} AND tenant_id = $${tenantParam}
               AND target_group_id = $${groupParam} AND deleted_at IS NULL
             RETURNING id, tenant_id, target_group_id, kind, value, normalized_value,
                       expected_behavior, metadata_json, created_at`,
            params,
          );
          if (!rows[0]) return null;
          await appendMutationAudit(auditRepository, client, ctx, {
            action: 'target.updated', resource_type: 'target', resource_id: targetId,
            metadata: { target_group_id: groupId, changed_fields: changedFields, dropped_untrusted_fields: normalized.dropped_fields },
          }, now);
          return mapTargetRow(rows[0]);
        } catch (error) {
          if (error?.code === '23505') return { error: 'target_exists', status: 409 };
          throw error;
        }
      });
    },

    async restoreTargetGroup(ctx, groupId, options = {}) {
      const now = options.now ?? new Date().toISOString();
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT id, environment_id, name
           FROM target_groups
           WHERE id = $1 AND tenant_id = $2
             AND (deleted_at IS NOT NULL OR archived_at IS NOT NULL)
           FOR UPDATE`,
          [groupId, ctx.tenantId],
        );
        const group = rows[0];
        if (!group) return { error: 'not_found', status: 404 };
        const duplicate = await client.query(
          `SELECT id FROM target_groups
           WHERE tenant_id = $1 AND environment_id = $2 AND lower(name) = lower($3)
             AND id <> $4 AND deleted_at IS NULL AND archived_at IS NULL
           LIMIT 1`,
          [ctx.tenantId, group.environment_id, group.name, groupId],
        );
        if (duplicate.rows[0]) return { error: 'target_group_exists', status: 409, existing_id: duplicate.rows[0].id };

        await client.query(
          `UPDATE target_groups SET deleted_at = NULL, deleted_by = NULL, archived_at = NULL
           WHERE id = $1 AND tenant_id = $2`,
          [groupId, ctx.tenantId],
        );
        const auditEntry = await appendMutationAudit(auditRepository, client, ctx, {
          action: 'target_group.restored', resource_type: 'target_group', resource_id: groupId,
          metadata: { changed_fields: ['deleted_at', 'deleted_by', 'archived_at'] },
        }, now);
        return { restored: true, id: groupId, audit_entry_id: auditEntry.id };
      });
    },

    async bulkImportTargets(ctx, groupId, body = {}, options = {}) {
      const now = options.now ?? new Date().toISOString();
      const items = Array.isArray(body.items) ? body.items : [];
      const connector = options.trustedConnector ?? null;
      const connectorKeys = options.connectorInventoryKeys instanceof Set
        ? options.connectorInventoryKeys
        : new Set(options.connectorInventoryKeys ?? []);
      const connectorEvidence = options.connectorInventoryEvidence instanceof Map
        ? options.connectorInventoryEvidence
        : new Map();
      if (body.connector_id && (!connector || connector.id !== body.connector_id)) {
        return { error: 'connector_inventory_not_verified', status: 400 };
      }

      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const groupResult = await client.query(
          `SELECT id FROM target_groups
           WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL AND archived_at IS NULL`,
          [groupId, ctx.tenantId],
        );
        if (!groupResult.rows[0]) return { error: 'target_group_not_found', status: 404 };

        let authoritativeConnector = null;
        const authoritativeSnapshots = new Map();
        if (connector) {
          const feature = await client.query(
            `SELECT enabled FROM tenant_connector_features WHERE tenant_id = $1`,
            [ctx.tenantId],
          );
          if (feature.rows[0]?.enabled !== true) {
            return { error: 'connectors_feature_disabled', status: 404 };
          }
          const { rows: connectorRows } = await client.query(
            `SELECT id, provider, name, status, secret_id, last_success_at,
                    last_success_revision
             FROM waf_connectors
             WHERE tenant_id = $1 AND id = $2
             FOR UPDATE`,
            [ctx.tenantId, connector.id],
          );
          const row = connectorRows[0] ?? null;
          if (row) {
            authoritativeConnector = {
              id: row.id,
              provider: row.provider,
              name: row.name,
              status: row.status,
              secret_id: row.secret_id ?? null,
              has_secret: Boolean(row.secret_id),
              last_success_at: toIso(row.last_success_at),
              last_success_revision: Number(row.last_success_revision ?? 0),
            };
            const snapshotIds = [...new Set(
              [...connectorEvidence.values()]
                .map((evidence) => String(evidence?.snapshot_id ?? '').trim())
                .filter(Boolean),
            )];
            if (snapshotIds.length > 0) {
              const { rows: snapshotRows } = await client.query(
                `SELECT id, connector_id, provider, snapshot_kind, resource_ref_hash,
                        display_ref, observed_at, summary_json, evidence_source,
                        inventory_complete, inventory_truncated, poll_revision
                 FROM waf_connector_snapshots
                 WHERE tenant_id = $1 AND connector_id = $2
                   AND id = ANY($3::text[])`,
                [ctx.tenantId, connector.id, snapshotIds],
              );
              for (const snapshot of snapshotRows) {
                authoritativeSnapshots.set(snapshot.id, {
                  ...snapshot,
                  observed_at: toIso(snapshot.observed_at),
                  summary: asObject(snapshot.summary_json),
                  inventory_complete: snapshot.inventory_complete === true,
                  inventory_truncated: snapshot.inventory_truncated === true,
                  poll_revision: Number(snapshot.poll_revision ?? 0),
                });
              }
            }
          }
        }

        const imported = [];
        const skipped = [];
        for (const item of items) {
          let normalized;
          try {
            normalized = normalizeTargetInput(item);
          } catch (error) {
            const response = targetValidationResponse(error);
            skipped.push({ value: String(item?.value ?? ''), reason: response.error, field: response.field, message: response.message });
            continue;
          }
          const key = `${normalized.kind}\u0000${normalized.normalized_value}`;
          if (connector && !connectorKeys.has(key)) {
            skipped.push({ value: normalized.value, reason: 'connector_item_not_found' });
            continue;
          }
          const loadedEvidence = connector ? connectorEvidence.get(key) : null;
          const providerSnapshot = loadedEvidence?.snapshot_id
            ? authoritativeSnapshots.get(loadedEvidence.snapshot_id) ?? null
            : null;
          const itemEvidence = providerSnapshot && authoritativeConnector
            ? {
                kind: normalized.kind,
                value: normalized.value,
                provider: providerSnapshot.provider ?? authoritativeConnector.provider,
                snapshot_kind: providerSnapshot.snapshot_kind,
                resource_ref: providerSnapshot.resource_ref_hash,
                observed_at: providerSnapshot.observed_at,
                snapshot_id: providerSnapshot.id,
                poll_revision: providerSnapshot.poll_revision,
                poll_generation: authoritativeConnector.last_success_at,
                evidence_source: providerSnapshot.evidence_source,
                candidate_source: 'snapshot_inventory',
                inventory_complete: providerSnapshot.inventory_complete,
                inventory_truncated: providerSnapshot.inventory_truncated,
                summary: providerSnapshot.summary,
              }
            : null;
          const sourceRef = itemEvidence && authoritativeConnector
            ? {
                connector_id: authoritativeConnector.id,
                connector_secret_id: authoritativeConnector.secret_id,
                connector_revision: authoritativeConnector.last_success_revision,
                provider: itemEvidence.provider,
                snapshot_kind: itemEvidence.snapshot_kind,
                evidence_source: itemEvidence.evidence_source,
                resource_ref_hash: itemEvidence.resource_ref,
                snapshot_id: itemEvidence.snapshot_id,
                observed_at: itemEvidence.observed_at,
                poll_generation: itemEvidence.poll_generation,
              }
            : null;
          const providerVerified = Boolean(
            authoritativeConnector
            && providerSnapshot
            && isProviderVerifiedDnsEvidence(authoritativeConnector, itemEvidence)
            && isCurrentProviderDnsOwnershipProof({
              connector: authoritativeConnector,
              snapshot: providerSnapshot,
              sourceRef,
              target: normalized,
            }),
          );
          const duplicate = await client.query(
            `SELECT id FROM targets
             WHERE tenant_id = $1 AND target_group_id = $2 AND kind = $3
               AND normalized_value = $4 AND deleted_at IS NULL
             LIMIT 1`,
            [ctx.tenantId, groupId, normalized.kind, normalized.normalized_value],
          );
          if (duplicate.rows[0]) {
            skipped.push({ value: normalized.value, reason: 'already_imported' });
            continue;
          }

          const targetId = newId('target');
          const verifyState = providerVerified
            ? 'provider_verified'
            : ['fqdn', 'dns_zone'].includes(normalized.kind) ? 'pending' : 'awaiting_heartbeat';
          const declaredSource = String(body.source ?? 'customer').trim() || 'customer';
          const metadata = {
            ...normalized.metadata,
            ...(connector
              ? {
                  managed_provenance: {
                    kind: providerVerified ? 'provider_account' : 'connector_inventory',
                    connector_id: authoritativeConnector?.id ?? connector.id,
                    provider: itemEvidence?.provider ?? authoritativeConnector?.provider ?? null,
                    snapshot_kind: itemEvidence?.snapshot_kind ?? null,
                    snapshot_id: itemEvidence?.snapshot_id ?? null,
                    resource_ref_hash: itemEvidence?.resource_ref ?? null,
                    observed_at: itemEvidence?.observed_at ?? null,
                    poll_generation: itemEvidence?.poll_generation ?? null,
                    evidence_source: itemEvidence?.evidence_source ?? 'manual_metadata',
                    candidate_source: itemEvidence?.candidate_source ?? null,
                    inventory_complete: itemEvidence?.inventory_complete === true,
                    inventory_truncated: itemEvidence?.inventory_truncated === true,
                  },
                }
              : { declared_import: { label: declaredSource, trusted: false } }),
          };
          try {
            const inserted = await client.query(
              `INSERT INTO targets (
                 id, tenant_id, target_group_id, kind, value, normalized_value,
                 expected_behavior, metadata_json, created_at
               ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9::timestamptz)
               ON CONFLICT (tenant_id, target_group_id, kind, normalized_value)
                 WHERE deleted_at IS NULL
               DO NOTHING
               RETURNING id, tenant_id, target_group_id, kind, value, normalized_value,
                         expected_behavior, metadata_json, created_at`,
              [targetId, ctx.tenantId, groupId, normalized.kind, normalized.value, normalized.normalized_value,
                item.expected_behavior ?? null, JSON.stringify(metadata), now],
            );
            if (!inserted.rows[0]) {
              skipped.push({ value: normalized.value, reason: 'already_imported' });
              continue;
            }
            const auditEntry = await appendMutationAudit(auditRepository, client, ctx, {
              action: 'target.bulk_imported', resource_type: 'target', resource_id: targetId,
              metadata: {
                target_group_id: groupId,
                changed_fields: ['kind', 'value', 'expected_behavior', 'metadata'],
                provenance_trust: providerVerified ? 'provider_account' : connector ? 'connector_inventory' : 'customer_declared',
                connector_id: connector?.id ?? null,
                snapshot_id: providerVerified ? itemEvidence.snapshot_id : null,
                provider: providerVerified ? itemEvidence.provider : null,
                snapshot_kind: providerVerified ? itemEvidence.snapshot_kind : null,
                poll_generation: providerVerified ? itemEvidence.poll_generation : null,
                resource_ref_hash: providerVerified ? itemEvidence.resource_ref : null,
                dropped_untrusted_fields: normalized.dropped_fields,
              },
            }, now);
            await client.query(
              `INSERT INTO target_verifications (
                 id, tenant_id, target_id, state, source_kind, source_ref,
                 transitioned_at, transitioned_by, audit_entry_id
               ) VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::timestamptz, $8, $9)`,
              [newId('tv'), ctx.tenantId, targetId,
                verifyState === 'provider_verified' ? 'provider_verified' : verifyState === 'pending' ? 'pending' : 'unverified',
                providerVerified ? 'provider_account' : connector ? 'connector_inventory' : 'customer_declaration',
                JSON.stringify(providerVerified
                  ? {
                      connector_id: authoritativeConnector.id,
                      provider: itemEvidence.provider,
                      snapshot_kind: itemEvidence.snapshot_kind,
                      evidence_source: itemEvidence.evidence_source,
                      resource_ref_hash: itemEvidence.resource_ref,
                      snapshot_id: itemEvidence.snapshot_id,
                      observed_at: itemEvidence.observed_at,
                      poll_generation: itemEvidence.poll_generation,
                    }
                  : connector ? { connector_id: connector.id } : { declared_source: declaredSource }),
                now, ctx.userId ?? 'system', auditEntry.id],
            );
            imported.push({ ...mapTargetRow(inserted.rows[0]), verify_state: verifyState });
          } catch (error) {
            throw error;
          }
        }
        if (imported.length > 0) {
          const summaryRows = await client.query(
            `SELECT (
               SELECT tv.state
               FROM target_verifications tv
               WHERE tv.tenant_id = t.tenant_id AND tv.target_id = t.id
               ORDER BY tv.transitioned_at DESC, tv.id DESC
               LIMIT 1
             ) AS state
             FROM targets t
             WHERE t.tenant_id = $1 AND t.target_group_id = $2 AND t.deleted_at IS NULL`,
            [ctx.tenantId, groupId],
          );
          const ownershipStatus = ownershipSummaryFromTargetStates(
            summaryRows.rows.map((row) => row.state ?? 'unverified'),
          );
          await client.query(
            `UPDATE target_groups
             SET ownership_status = $3
             WHERE tenant_id = $1 AND id = $2
               AND deleted_at IS NULL AND archived_at IS NULL`,
            [ctx.tenantId, groupId, ownershipStatus],
          );
        }
        return { imported, skipped, count: imported.length };
      });
    },

    async deleteTarget(ctx, groupId, targetId, options = {}) {
      const now = options.now ?? new Date().toISOString();
      const deletedBy = options.deletedBy ?? ctx.userId ?? 'system';
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const groupResult = await client.query(
          `SELECT id FROM target_groups
           WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL AND archived_at IS NULL`,
          [groupId, ctx.tenantId],
        );
        if (!groupResult.rows[0]) return null;
        const targetResult = await client.query(
          `SELECT id FROM targets
           WHERE id = $1 AND tenant_id = $2 AND target_group_id = $3 AND deleted_at IS NULL
           FOR UPDATE`,
          [targetId, ctx.tenantId, groupId],
        );
        if (!targetResult.rows[0]) return null;
        if (await hasActiveRunForTarget(client, ctx.tenantId, groupId, targetId)) {
          return { error: 'target_active_run', status: 409 };
        }

        const { rows } = await client.query(
          `UPDATE targets
           SET deleted_at = $4::timestamptz, deleted_by = $5
           WHERE id = $1 AND tenant_id = $2 AND target_group_id = $3 AND deleted_at IS NULL
           RETURNING id`,
          [targetId, ctx.tenantId, groupId, now, deletedBy],
        );
        if (!rows[0]) return null;
        const pausedPolicies = await client.query(
          `UPDATE test_policies
           SET state = 'paused', enabled = FALSE, next_run_at = NULL,
               lease_token = NULL, lease_owner = NULL, lease_expires_at = NULL,
               schedule_revision = schedule_revision + 1,
               updated_at = $4::timestamptz
           WHERE tenant_id = $1 AND target_group_id = $2 AND target_id = $3
             AND archived_at IS NULL
           RETURNING id`,
          [ctx.tenantId, groupId, targetId, now],
        );
        const pausedPolicyIds = pausedPolicies.rows.map((policy) => policy.id);
        await appendMutationAudit(auditRepository, client, ctx, {
          action: 'target.archived', resource_type: 'target', resource_id: targetId,
          metadata: {
            target_group_id: groupId,
            changed_fields: ['deleted_at', 'deleted_by'],
            paused_policy_ids: pausedPolicyIds,
          },
        }, now);
        return {
          deleted: true,
          archived: true,
          id: targetId,
          deleted_at: now,
          deleted_by: deletedBy,
          paused_policy_count: pausedPolicyIds.length,
        };
      });
    },
  };
}

export {
  TARGET_GROUP_RUNS_RECENT_LIMIT,
  TARGET_GROUP_FINDINGS_LIMIT,
  mapTenantRow,
  mapEnvironmentRow,
  mapTargetGroupDetail,
  mapTargetGroupRow,
  mapDetailTargetRow,
  mapTargetInventoryRow,
  mapTargetRow,
};
