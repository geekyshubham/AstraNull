import { newId } from '../../lib/ids.mjs';
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
    validation_mode: row.validation_mode ?? 'agent_assisted',
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
    expected_behavior: row.expected_behavior ?? undefined,
    created_at: toIso(row.created_at),
  };
  const metadata = asObject(row.metadata_json);
  if (Object.keys(metadata).length > 0) mapped.metadata = metadata;
  return mapped;
}

/**
 * Target as the group-detail payload renders it.
 *
 * `targets` has no verification_state column, so the value rides in metadata when it exists.
 * dev-json stamps the same field with the same 'unverified' fallback
 * (src/services/targetGroups.mjs `getTargetGroup`); Postgres omitted it entirely, so the
 * portal's verify chip fell back to its own default on one backend and read a real state on
 * the other. Applied only on the detail path, matching dev-json — add/patch responses carry
 * no such field on either backend.
 */
function mapDetailTargetRow(row) {
  const mapped = mapTargetRow(row);
  if (!mapped) return null;
  const metadata = asObject(row.metadata_json);
  return {
    ...mapped,
    verification_state:
      row.verification_state ?? metadata.verification_state ?? metadata.verify_state ?? 'unverified',
  };
}

/**
 * @param {import('pg').Pool} pool
 */
export function createCoreCatalogRepository(pool) {
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
             WHERE tenant_id = $1
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
            `SELECT id, tenant_id, target_group_id, kind, value, expected_behavior, metadata_json, created_at
             FROM targets
             WHERE target_group_id = $1 AND tenant_id = $2
             ORDER BY created_at`,
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
                        'check_id', run.check_id,
                        'status', run.status,
                        'started_at', run.started_at
                      )
                      ORDER BY run.started_at DESC, run.id
                    ) AS items
             FROM (
               SELECT id, check_id, status,
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
          `SELECT id, tenant_id, target_group_id, kind, value, expected_behavior, metadata_json, created_at
           FROM targets
           WHERE target_group_id = $1 AND tenant_id = $2
           ORDER BY created_at`,
          [id, ctx.tenantId],
        );
        return {
          ...group,
          ...mapTargetGroupDetail(row, targets.rows.map(mapDetailTargetRow)),
        };
      });
    },

    async createTargetGroup(ctx, body, options = {}) {
      const id = options.id ?? newId('tg');
      const now = options.now ?? new Date().toISOString();
      const rawEnvironmentId =
        typeof body.environment_id === 'string' ? body.environment_id.trim() : body.environment_id;
      const record = {
        environment_id: rawEnvironmentId || 'env_demo',
        name: body.name ?? 'New target group',
        description: body.description ?? '',
        expected_behavior_default: body.expected_behavior_default ?? null,
        timezone: body.timezone ?? 'UTC',
        safe_test_windows: Array.isArray(body.safe_test_windows) ? body.safe_test_windows : [],
        safety_policy: normalizeSafetyPolicy(body.safety_policy),
      };

      return withTenantContext(pool, ctx.tenantId, async (client) => {
        // The (tenant_id, environment_id) FK requires the environment to exist for this tenant.
        // Validate up front so callers get an actionable 400 instead of a raw FK 500.
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

        const { rows } = await client.query(
          `INSERT INTO target_groups (
             id, tenant_id, environment_id, name, description, expected_behavior_default,
             timezone, safe_test_windows, safety_policy, validation_mode, ownership_status,
             dns_ownership, created_at
           )
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9::jsonb, $10, $11, $12::jsonb, $13::timestamptz)
           RETURNING id, tenant_id, environment_id, name, description, expected_behavior_default,
                     timezone, safe_test_windows, safety_policy, validation_mode, ownership_status,
                     dns_ownership, created_at`,
          [
            id,
            ctx.tenantId,
            record.environment_id,
            record.name,
            record.description,
            record.expected_behavior_default,
            record.timezone,
            JSON.stringify(record.safe_test_windows),
            JSON.stringify(record.safety_policy),
            body.validation_mode ?? 'agent_assisted',
            body.ownership_status ?? 'unverified',
            body.dns_ownership == null ? null : JSON.stringify(body.dns_ownership),
            now,
          ],
        );
        return mapTargetGroupRow(rows[0]);
      });
    },

    async addTarget(ctx, groupId, body, options = {}) {
      const id = options.id ?? newId('target');
      const now = options.now ?? new Date().toISOString();

      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const groupResult = await client.query(
          `SELECT id, expected_behavior_default
           FROM target_groups
           WHERE id = $1 AND tenant_id = $2 AND archived_at IS NULL`,
          [groupId, ctx.tenantId],
        );
        const group = groupResult.rows[0];
        if (!group) return null;

        const kind = body.kind ?? 'fqdn';
        const expectedBehavior = body.expected_behavior ?? null;
        const metadata = body.metadata && typeof body.metadata === 'object' ? body.metadata : {};

        const { rows } = await client.query(
          `INSERT INTO targets (id, tenant_id, target_group_id, kind, value, expected_behavior, metadata_json, created_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::timestamptz)
           RETURNING id, tenant_id, target_group_id, kind, value, expected_behavior, metadata_json, created_at`,
          [
            id,
            ctx.tenantId,
            groupId,
            kind,
            body.value,
            expectedBehavior,
            JSON.stringify(metadata),
            now,
          ],
        );
        return mapTargetRow(rows[0]);
      });
    },

    async patchTargetGroup(ctx, id, body, options = {}) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const existing = await client.query(
          `SELECT id, tenant_id, environment_id, name, description, expected_behavior_default,
                  timezone, safe_test_windows, safety_policy, archived_at, validation_mode,
                  ownership_status, dns_ownership, created_at
           FROM target_groups
           WHERE id = $1 AND tenant_id = $2 AND archived_at IS NULL`,
          [id, ctx.tenantId],
        );
        if (!existing.rows[0]) return null;

        const current = existing.rows[0];
        const sets = [];
        const params = [];
        let n = 1;

        if (body.name !== undefined) {
          sets.push(`name = $${n++}`);
          params.push(String(body.name).trim() || current.name);
        }
        if (body.description !== undefined) {
          sets.push(`description = $${n++}`);
          params.push(String(body.description ?? ''));
        }
        if (body.environment_id !== undefined) {
          sets.push(`environment_id = $${n++}`);
          params.push(String(body.environment_id).trim());
        }
        if (body.timezone !== undefined) {
          sets.push(`timezone = $${n++}`);
          params.push(String(body.timezone).trim() || 'UTC');
        }
        if (Array.isArray(body.safe_test_windows)) {
          sets.push(`safe_test_windows = $${n++}::jsonb`);
          params.push(JSON.stringify(body.safe_test_windows));
        }
        if (body.safety_policy !== undefined) {
          sets.push(`safety_policy = $${n++}::jsonb`);
          params.push(JSON.stringify(normalizeSafetyPolicy(body.safety_policy)));
        }

        if (sets.length === 0) {
          return mapTargetGroupRow(current);
        }

        params.push(id, ctx.tenantId);
        const idParam = n++;
        const tenantParam = n++;

        const { rows } = await client.query(
          `UPDATE target_groups
           SET ${sets.join(', ')}
           WHERE id = $${idParam} AND tenant_id = $${tenantParam} AND archived_at IS NULL
           RETURNING id, tenant_id, environment_id, name, description, expected_behavior_default,
                     timezone, safe_test_windows, safety_policy, archived_at, validation_mode,
                     ownership_status, dns_ownership, created_at`,
          params,
        );
        return mapTargetGroupRow(rows[0] ?? null);
      });
    },

    async archiveTargetGroup(ctx, id, options = {}) {
      const now = options.now ?? new Date().toISOString();
      const deletedBy = options.deletedBy ?? ctx.userId ?? 'system';
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const existing = await client.query(
          `SELECT id
           FROM target_groups
           WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL AND archived_at IS NULL`,
          [id, ctx.tenantId],
        );
        if (!existing.rows[0]) return null;
        if (await hasActiveRunForGroup(client, ctx.tenantId, id)) {
          return { error: 'target_group_active_run', status: 409 };
        }

        await client.query(
          `UPDATE target_groups
           SET deleted_at = $3::timestamptz,
               deleted_by = $4,
               archived_at = $3::timestamptz
           WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL AND archived_at IS NULL`,
          [id, ctx.tenantId, now, deletedBy],
        );
        return { archived: true, id, deleted_at: now, deleted_by: deletedBy };
      });
    },

    async patchTarget(ctx, groupId, targetId, body, options = {}) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const groupResult = await client.query(
          `SELECT id
           FROM target_groups
           WHERE id = $1 AND tenant_id = $2 AND archived_at IS NULL`,
          [groupId, ctx.tenantId],
        );
        if (!groupResult.rows[0]) return null;

        const existing = await client.query(
          `SELECT id, tenant_id, target_group_id, kind, value, expected_behavior, metadata_json, created_at
           FROM targets
           WHERE id = $1 AND tenant_id = $2 AND target_group_id = $3`,
          [targetId, ctx.tenantId, groupId],
        );
        if (!existing.rows[0]) return null;

        const current = existing.rows[0];
        const sets = [];
        const params = [];
        let n = 1;

        if (body.value !== undefined) {
          sets.push(`value = $${n++}`);
          params.push(String(body.value).trim());
        }
        if (body.kind !== undefined) {
          sets.push(`kind = $${n++}`);
          params.push(String(body.kind).trim() || current.kind);
        }
        if (body.metadata !== undefined && typeof body.metadata === 'object' && !Array.isArray(body.metadata)) {
          sets.push(`metadata_json = $${n++}::jsonb`);
          params.push(JSON.stringify(body.metadata));
        }

        if (sets.length === 0) {
          return mapTargetRow(current);
        }

        params.push(targetId, ctx.tenantId, groupId);
        const idParam = n++;
        const tenantParam = n++;
        const groupParam = n++;

        const { rows } = await client.query(
          `UPDATE targets
           SET ${sets.join(', ')}
           WHERE id = $${idParam} AND tenant_id = $${tenantParam} AND target_group_id = $${groupParam}
           RETURNING id, tenant_id, target_group_id, kind, value, expected_behavior, metadata_json, created_at`,
          params,
        );
        return mapTargetRow(rows[0] ?? null);
      });
    },

    async deleteTarget(ctx, groupId, targetId) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const groupResult = await client.query(
          `SELECT id
           FROM target_groups
           WHERE id = $1 AND tenant_id = $2 AND archived_at IS NULL`,
          [groupId, ctx.tenantId],
        );
        if (!groupResult.rows[0]) return null;
        if (await hasActiveRunForTarget(client, ctx.tenantId, groupId, targetId)) {
          return { error: 'target_active_run', status: 409 };
        }

        const { rows } = await client.query(
          `DELETE FROM targets
           WHERE id = $1 AND tenant_id = $2 AND target_group_id = $3
           RETURNING id`,
          [targetId, ctx.tenantId, groupId],
        );
        if (!rows[0]) return null;
        return { deleted: true, id: targetId };
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
  mapTargetRow,
};
