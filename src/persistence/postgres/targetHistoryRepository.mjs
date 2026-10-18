/**
 * Postgres storage for immutable observations, origin bindings, and retest lineage.
 * Current-pointer updates use astranull_observation_order_before, the same
 * (observed_at, source_completed_at, id) order as the dev store.
 */
import { runWithTenantClient, withTenantContext } from './tenantContext.mjs';

const EXACT_TIME = `to_char(%s AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`;

function exact(column) {
  return EXACT_TIME.replace('%s', column);
}

const OBSERVATION_RETURNING = `
  id, tenant_id, target_id, target_group_id, family, check_id, test_run_id, source_kind, source_id,
  corpus_version, scenario_version, check_version, outcome, attempt_class, producer_kind,
  provenance_json, origin_binding_id, nonce, event_id, digest,
  ${exact('observed_at')} AS observed_at,
  CASE WHEN source_completed_at IS NULL THEN NULL ELSE ${exact('source_completed_at')} END AS source_completed_at,
  ${exact('created_at')} AS created_at`;

function mapObservation(row) {
  if (!row) return null;
  return {
    ...row,
    provenance: row.provenance_json ?? {},
    test_run_id: row.test_run_id ?? null,
    source_completed_at: row.source_completed_at ?? null,
    origin_binding_id: row.origin_binding_id ?? null,
  };
}

function relationConflict(existing, record) {
  if (existing.digest !== record.digest) return true;
  if (record.nonce && existing.nonce && record.nonce !== existing.nonce) return true;
  if (record.event_id && existing.event_id && record.event_id !== existing.event_id) return true;
  return false;
}

const POINTER_UPSERT = `
  INSERT INTO target_observation_current (
    tenant_id, target_id, family,
    successful_observation_id, successful_observed_at, successful_source_completed_at,
    failed_attempt_observation_id, failed_observed_at, failed_source_completed_at,
    updated_at
  ) VALUES ($1, $2, $3, $4, $5::timestamptz, $6::timestamptz, $7, $8::timestamptz, $9::timestamptz, $10::timestamptz)
  ON CONFLICT (tenant_id, target_id, family) DO UPDATE SET
    successful_observation_id = CASE
      WHEN EXCLUDED.successful_observation_id IS NULL THEN target_observation_current.successful_observation_id
      WHEN target_observation_current.successful_observation_id IS NULL THEN EXCLUDED.successful_observation_id
      WHEN astranull_observation_order_before(
        target_observation_current.successful_observed_at,
        target_observation_current.successful_source_completed_at,
        target_observation_current.successful_observation_id,
        EXCLUDED.successful_observed_at,
        EXCLUDED.successful_source_completed_at,
        EXCLUDED.successful_observation_id
      ) THEN EXCLUDED.successful_observation_id
      ELSE target_observation_current.successful_observation_id
    END,
    successful_observed_at = CASE
      WHEN EXCLUDED.successful_observation_id IS NULL THEN target_observation_current.successful_observed_at
      WHEN target_observation_current.successful_observation_id IS NULL THEN EXCLUDED.successful_observed_at
      WHEN astranull_observation_order_before(
        target_observation_current.successful_observed_at,
        target_observation_current.successful_source_completed_at,
        target_observation_current.successful_observation_id,
        EXCLUDED.successful_observed_at,
        EXCLUDED.successful_source_completed_at,
        EXCLUDED.successful_observation_id
      ) THEN EXCLUDED.successful_observed_at
      ELSE target_observation_current.successful_observed_at
    END,
    successful_source_completed_at = CASE
      WHEN EXCLUDED.successful_observation_id IS NULL THEN target_observation_current.successful_source_completed_at
      WHEN target_observation_current.successful_observation_id IS NULL THEN EXCLUDED.successful_source_completed_at
      WHEN astranull_observation_order_before(
        target_observation_current.successful_observed_at,
        target_observation_current.successful_source_completed_at,
        target_observation_current.successful_observation_id,
        EXCLUDED.successful_observed_at,
        EXCLUDED.successful_source_completed_at,
        EXCLUDED.successful_observation_id
      ) THEN EXCLUDED.successful_source_completed_at
      ELSE target_observation_current.successful_source_completed_at
    END,
    failed_attempt_observation_id = CASE
      WHEN EXCLUDED.failed_attempt_observation_id IS NULL THEN target_observation_current.failed_attempt_observation_id
      WHEN target_observation_current.failed_attempt_observation_id IS NULL THEN EXCLUDED.failed_attempt_observation_id
      WHEN astranull_observation_order_before(
        target_observation_current.failed_observed_at,
        target_observation_current.failed_source_completed_at,
        target_observation_current.failed_attempt_observation_id,
        EXCLUDED.failed_observed_at,
        EXCLUDED.failed_source_completed_at,
        EXCLUDED.failed_attempt_observation_id
      ) THEN EXCLUDED.failed_attempt_observation_id
      ELSE target_observation_current.failed_attempt_observation_id
    END,
    failed_observed_at = CASE
      WHEN EXCLUDED.failed_attempt_observation_id IS NULL THEN target_observation_current.failed_observed_at
      WHEN target_observation_current.failed_attempt_observation_id IS NULL THEN EXCLUDED.failed_observed_at
      WHEN astranull_observation_order_before(
        target_observation_current.failed_observed_at,
        target_observation_current.failed_source_completed_at,
        target_observation_current.failed_attempt_observation_id,
        EXCLUDED.failed_observed_at,
        EXCLUDED.failed_source_completed_at,
        EXCLUDED.failed_attempt_observation_id
      ) THEN EXCLUDED.failed_observed_at
      ELSE target_observation_current.failed_observed_at
    END,
    failed_source_completed_at = CASE
      WHEN EXCLUDED.failed_attempt_observation_id IS NULL THEN target_observation_current.failed_source_completed_at
      WHEN target_observation_current.failed_attempt_observation_id IS NULL THEN EXCLUDED.failed_source_completed_at
      WHEN astranull_observation_order_before(
        target_observation_current.failed_observed_at,
        target_observation_current.failed_source_completed_at,
        target_observation_current.failed_attempt_observation_id,
        EXCLUDED.failed_observed_at,
        EXCLUDED.failed_source_completed_at,
        EXCLUDED.failed_attempt_observation_id
      ) THEN EXCLUDED.failed_source_completed_at
      ELSE target_observation_current.failed_source_completed_at
    END,
    updated_at = EXCLUDED.updated_at`;

function pointerParams(record) {
  const successful = record.attempt_class === 'successful';
  const failed = record.attempt_class === 'failed_attempt';
  return [
    record.tenant_id,
    record.target_id,
    record.family,
    successful ? record.id : null,
    successful ? record.observed_at : null,
    successful ? record.source_completed_at : null,
    failed ? record.id : null,
    failed ? record.observed_at : null,
    failed ? record.source_completed_at : null,
    record.created_at,
  ];
}

async function findRelated(client, record) {
  const { rows } = await client.query(
    `SELECT ${OBSERVATION_RETURNING}
     FROM target_observations
     WHERE tenant_id = $1
       AND (
         ($2::text IS NOT NULL AND nonce = $2)
         OR ($3::text IS NOT NULL AND event_id = $3)
         OR digest = $4
       )`,
    [record.tenant_id, record.nonce, record.event_id, record.digest],
  );
  return rows.map(mapObservation);
}

export async function writeObservation(client, record) {
  const related = await findRelated(client, record);
  const distinct = [...new Map(related.map((row) => [row.id, row])).values()];
  if (distinct.length > 1 || (distinct[0] && relationConflict(distinct[0], record))) {
    return { error: 'idempotency_conflict', status: 409 };
  }
  if (distinct[0]) return { ...distinct[0], replayed: true };
  const inserted = await client.query(
    `INSERT INTO target_observations (
       id, tenant_id, target_id, target_group_id, family, check_id, test_run_id, source_kind, source_id,
       corpus_version, scenario_version, check_version, observed_at, source_completed_at, outcome,
       attempt_class, producer_kind, provenance_json, origin_binding_id, nonce, event_id, digest, created_at
     ) VALUES (
       $1, $2, $3, $4, $5, $6, $7, $8, $9,
       $10, $11, $12, $13::timestamptz, $14::timestamptz, $15,
       $16, $17, $18::jsonb, $19, $20, $21, $22, $23::timestamptz
     ) ON CONFLICT DO NOTHING RETURNING ${OBSERVATION_RETURNING}`,
    [
      record.id, record.tenant_id, record.target_id, record.target_group_id, record.family,
      record.check_id, record.test_run_id, record.source_kind, record.source_id,
      record.corpus_version, record.scenario_version, record.check_version,
      record.observed_at, record.source_completed_at, record.outcome, record.attempt_class,
      record.producer_kind, JSON.stringify(record.provenance ?? {}), record.origin_binding_id,
      record.nonce, record.event_id, record.digest, record.created_at,
    ],
  );
  // A concurrent writer can win after the first lookup. Avoid a unique violation:
  // catching one cannot recover an already-aborted ingest transaction.
  if (!inserted.rows[0]) {
    const again = await findRelated(client, record);
    if (again.length !== 1) return { error: 'idempotency_conflict', status: 409 };
    const winner = again[0];
    if (relationConflict(winner, record)) return { error: 'idempotency_conflict', status: 409 };
    return { ...winner, replayed: true };
  }
  if (record.attempt_class !== 'retained_noncurrent') {
    await client.query(POINTER_UPSERT, pointerParams(record));
  }
  return { ...mapObservation(inserted.rows[0]), replayed: false };
}

export function createTargetHistoryRepository(pool) {
  return {
    async insertObservation(ctx, record) {
      return withTenantContext(pool, ctx.tenantId, async (client) => writeObservation(client, record));
    },

    async listObservations(ctx, query) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const cursor = query.cursor;
        const { rows } = await client.query(
          `SELECT ${OBSERVATION_RETURNING}
           FROM target_observations
           WHERE tenant_id = $1
             AND ($2::text IS NULL OR target_id = $2)
             AND ($3::text IS NULL OR family = $3)
             AND ($4::timestamptz IS NULL OR observed_at >= $4::timestamptz)
             AND ($5::timestamptz IS NULL OR observed_at <= $5::timestamptz)
             AND (
               $6::timestamptz IS NULL
               OR astranull_observation_order_before(
                 observed_at, source_completed_at, id, $6::timestamptz, $7::timestamptz, $8
               )
             )
           ORDER BY observed_at DESC, source_completed_at DESC NULLS LAST, id COLLATE "C" DESC
           LIMIT $9`,
          [
            ctx.tenantId,
            query.target_id ?? null,
            query.family ?? null,
            query.from ?? null,
            query.to ?? null,
            cursor?.observed_at ?? null,
            cursor?.source_completed_at ?? null,
            cursor?.id ?? null,
            query.limit,
          ],
        );
        return rows.map(mapObservation);
      });
    },

    async listCurrentPointers(ctx, query) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT tenant_id, target_id, family, successful_observation_id, failed_attempt_observation_id
           FROM target_observation_current
           WHERE tenant_id = $1 AND target_id = $2 AND ($3::text IS NULL OR family = $3)`,
          [ctx.tenantId, query.target_id, query.family ?? null],
        );
        return rows;
      });
    },

    async observationsByIds(ctx, ids) {
      if (!ids.length) return [];
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${OBSERVATION_RETURNING} FROM target_observations
           WHERE tenant_id = $1 AND id = ANY($2::text[])`,
          [ctx.tenantId, ids],
        );
        return rows.map(mapObservation);
      });
    },

    async listBindingEvidence(ctx, bindingId) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(`SELECT observation.*,
          ${exact('observation.observed_at')} AS observed_at,
          ${exact('observation.source_completed_at')} AS source_completed_at,
          ${exact('observation.created_at')} AS created_at, to_jsonb(run) AS binding_run
          FROM origin_bindings binding JOIN target_observations observation
            ON observation.tenant_id = binding.tenant_id AND observation.origin_binding_id = binding.id
          JOIN test_runs run ON run.tenant_id = observation.tenant_id AND run.id = observation.test_run_id
          WHERE binding.tenant_id = $1 AND binding.id = $2 AND observation.family = 'origin_hosting'
            AND observation.producer_kind = 'signed_probe' AND observation.attempt_class = 'successful'
            AND run.target_id = observation.target_id AND run.check_id = observation.check_id
            AND (run.origin_binding_id = binding.id OR run.provenance_json->'origin_lockdown'->>'binding_id' = binding.id)
            AND COALESCE(run.provenance_json->'origin_scope', run.provenance_json->'origin_lockdown')->>'host' = binding.host
            AND COALESCE(run.provenance_json->'origin_scope', run.provenance_json->'origin_lockdown')->>'sni' = binding.sni
            AND (COALESCE(run.provenance_json->'origin_scope', run.provenance_json->'origin_lockdown')->>'port') IS NOT DISTINCT FROM binding.port::text
            AND (COALESCE(run.provenance_json->'origin_scope', run.provenance_json->'origin_lockdown')->>'path') IS NOT DISTINCT FROM binding.path
          ORDER BY observation.observed_at DESC, observation.source_completed_at DESC NULLS LAST, observation.id COLLATE "C" DESC
          LIMIT 100`, [ctx.tenantId, bindingId]);
        return { observations: rows.map(mapObservation), runs: rows.map((row) => row.binding_run) };
      });
    },

    async loadBindingContext(ctx, targetIds, options = {}) {
      return runWithTenantClient(pool, ctx.tenantId, options.client, async (client) => {
        const targets = await client.query(
          `SELECT t.id, t.tenant_id, t.target_group_id, t.kind, t.value, t.port, t.protocol, t.deleted_at, t.declaration_json, t.normalized_value, t.metadata_json AS metadata,
                  ${exact('t.created_at')} AS created_at
           FROM targets t JOIN target_groups tg ON tg.tenant_id = t.tenant_id AND tg.id = t.target_group_id
           WHERE t.tenant_id = $1 AND t.deleted_at IS NULL AND tg.deleted_at IS NULL AND tg.archived_at IS NULL
             AND (t.id = ANY($2::text[]) OR EXISTS (SELECT 1 FROM targets child
               WHERE child.tenant_id = t.tenant_id AND child.id = ANY($2::text[]) AND child.target_group_id = t.target_group_id
                 AND child.metadata_json->'tags' ? ('subdomain-of:' || t.id)))`,
          [ctx.tenantId, targetIds],
        );
        const verifications = await client.query(
          `SELECT id, tenant_id, target_id, state, source_kind, source_ref,
                  ${exact('transitioned_at')} AS transitioned_at, transitioned_by
           FROM target_verifications
           WHERE tenant_id = $1 AND target_id = ANY($2::text[])`,
          [ctx.tenantId, targets.rows.map((row) => row.id)],
        );
        const connectors = await client.query(
          `SELECT * FROM waf_connectors WHERE tenant_id = $1`,
          [ctx.tenantId],
        );
        const snapshots = await client.query(
          `SELECT * FROM waf_connector_snapshots WHERE tenant_id = $1`,
          [ctx.tenantId],
        );
        return {
          targets: targets.rows,
          targetVerifications: verifications.rows,
          wafConnectors: connectors.rows.map((row) => ({ ...row, has_secret: Boolean(row.secret_id) })),
          wafConnectorSnapshots: snapshots.rows.map((row) => ({ ...row, summary: row.summary_json })),
        };
      });
    },

    async insertBinding(ctx, record, auditEntry, audit) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const readExisting = () => client.query(
          `SELECT *, ${exact('created_at')} AS created_at_exact FROM origin_bindings
           WHERE tenant_id = $1 AND status = 'active'
             AND protected_target_id = $2 AND origin_target_id = $3`,
          [record.tenant_id, record.protected_target_id, record.origin_target_id],
        );
        const replay = (row) => {
          if (!row || row.host !== record.host || row.sni !== record.sni
            || (row.port ?? null) !== (record.port ?? null)
            || (row.path ?? null) !== (record.path ?? null)) {
            return { error: 'scope_conflict', status: 409 };
          }
          return { ...row, created_at: row.created_at_exact, replayed: true };
        };
        const existing = await readExisting();
        if (existing.rows[0]) return replay(existing.rows[0]);
        const inserted = await client.query(
          `INSERT INTO origin_bindings (
             id, tenant_id, protected_target_id, protected_target_group_id, origin_target_id,
             origin_target_group_id, host, sni, port, path, status, assurance, lockdown,
             created_by, created_at
           ) VALUES (
             $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'active', 'none', 'not_tested', $11, $12::timestamptz
           ) ON CONFLICT (tenant_id, protected_target_id, origin_target_id)
             WHERE status = 'active' DO NOTHING
           RETURNING *, ${exact('created_at')} AS created_at_exact`,
          [
            record.id, record.tenant_id, record.protected_target_id, record.protected_target_group_id,
            record.origin_target_id, record.origin_target_group_id, record.host, record.sni,
            record.port, record.path, record.created_by, record.created_at,
          ],
        );
        if (!inserted.rows[0]) return replay((await readExisting()).rows[0]);
        const row = { ...inserted.rows[0], created_at: inserted.rows[0].created_at_exact };
        if (auditEntry && audit?.appendAuditEvent) await audit.appendAuditEvent(auditEntry, { client });
        return { ...row, replayed: false };
      });
    },

    async archiveBinding(ctx, id, patch, auditEntry, audit) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [ctx.tenantId]);
        const updated = await client.query(
          `UPDATE origin_bindings
           SET status = 'archived', archived_at = $3::timestamptz, archived_by = $4
           WHERE tenant_id = $1 AND id = $2 AND status = 'active'
           RETURNING *, ${exact('created_at')} AS created_at_exact,
                     ${exact('archived_at')} AS archived_at_exact`,
          [ctx.tenantId, id, patch.archived_at, patch.archived_by],
        );
        const row = updated.rows[0];
        if (!row) return null;
        const mapped = { ...row, created_at: row.created_at_exact, archived_at: row.archived_at_exact };
        const cancelled = await client.query(`UPDATE test_runs SET status = 'cancelled', completed_at = $3::timestamptz,
          summary_json = COALESCE(summary_json, '{}'::jsonb) || jsonb_build_object('cancellation',
            jsonb_build_object('reason', 'Origin binding archived', 'source', 'origin_binding', 'by', $4::text))
          WHERE tenant_id = $1 AND status IN ('planned', 'running', 'collecting')
            AND (origin_binding_id = $2 OR provenance_json->'origin_lockdown'->>'binding_id' = $2)
          RETURNING id`, [ctx.tenantId, id, patch.archived_at, patch.archived_by]);
        const cancelledIds = cancelled.rows.map((run) => run.id);
        if (cancelledIds.length) await client.query(`UPDATE probe_jobs SET status = 'cancelled', completed_at = $3::timestamptz
          WHERE tenant_id = $1 AND test_run_id = ANY($2::text[]) AND status IN ('pending', 'leased')`,
        [ctx.tenantId, cancelledIds, patch.archived_at]);
        if (auditEntry && audit?.appendAuditEvent) {
          await audit.appendAuditEvent({ ...auditEntry, metadata: { ...auditEntry.metadata, cancelled_test_run_ids: cancelledIds } }, { client });
          for (const runId of cancelledIds) await audit.appendAuditEvent({
            tenant_id: ctx.tenantId, actor_user_id: patch.archived_by, actor_role: ctx.role,
            action: 'test_run.cancelled', resource_type: 'test_run', resource_id: runId,
            metadata: { reason: 'Origin binding archived', source: 'origin_binding', origin_binding_id: id },
          }, { client });
        }
        return mapped;
      });
    },

    async getBinding(ctx, id) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT *, ${exact('created_at')} AS created_at_exact,
                  CASE WHEN archived_at IS NULL THEN NULL ELSE ${exact('archived_at')} END AS archived_at_exact
           FROM origin_bindings WHERE tenant_id = $1 AND id = $2`,
          [ctx.tenantId, id],
        );
        if (!rows[0]) return null;
        return { ...rows[0], created_at: rows[0].created_at_exact, archived_at: rows[0].archived_at_exact };
      });
    },

    async listBindings(ctx, query) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT *, ${exact('created_at')} AS created_at_exact
           FROM origin_bindings
           WHERE tenant_id = $1
             AND ($2::text IS NULL OR protected_target_id = $2)
             AND ($3::text IS NULL OR status = $3)
           ORDER BY created_at DESC, id COLLATE "C" DESC`,
          [ctx.tenantId, query.protected_target_id ?? null, query.status ?? null],
        );
        return rows.map((row) => ({ ...row, created_at: row.created_at_exact }));
      });
    },

    async getFinding(ctx, id) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT id, tenant_id, target_group_id, target_id, test_run_id, check_id, status, closed_at,
                  source, protection_validation_json
           FROM findings WHERE tenant_id = $1 AND id = $2`,
          [ctx.tenantId, id],
        );
        const row = rows[0];
        if (!row) return null;
        const { protection_validation_json: protection, ...rest } = row;
        return protection ? { ...rest, protection_validation: protection } : rest;
      });
    },

    async getRun(ctx, id) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT id, tenant_id, target_group_id, target_id, check_id, status,
                  CASE WHEN completed_at IS NULL THEN NULL ELSE ${exact('completed_at')} END AS completed_at
           FROM test_runs WHERE tenant_id = $1 AND id = $2`,
          [ctx.tenantId, id],
        );
        return rows[0] ?? null;
      });
    },

    async listRunsForTarget(ctx, targetId) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT id, tenant_id, target_id, check_id, status,
                  CASE WHEN completed_at IS NULL THEN NULL ELSE ${exact('completed_at')} END AS completed_at
           FROM test_runs WHERE tenant_id = $1 AND target_id = $2`,
          [ctx.tenantId, targetId],
        );
        return rows;
      });
    },

    async listSiblingFindings(ctx, { findingId, checkId }) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT id, tenant_id, target_id, check_id, status, closed_at
           FROM findings WHERE tenant_id = $1 AND check_id = $2 AND id <> $3`,
          [ctx.tenantId, checkId, findingId],
        );
        return rows;
      });
    },

    async findLineage(ctx, { findingId, testRunId }) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT * FROM finding_retest_lineage
           WHERE tenant_id = $1 AND finding_id = $2 AND test_run_id = $3`,
          [ctx.tenantId, findingId, testRunId],
        );
        return rows[0] ?? null;
      });
    },

    async insertLineage(ctx, record) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const inserted = await client.query(
          `INSERT INTO finding_retest_lineage (
             id, tenant_id, finding_id, test_run_id, target_id, check_id, intent, relation, created_by, created_at,
             comparison_context_json
           ) VALUES ($1, $2, $3, $4, $5, $6, 'retest', 'retest', $7, $8::timestamptz, $9::jsonb)
           ON CONFLICT (tenant_id, finding_id, test_run_id) DO NOTHING
           RETURNING *`,
          [
            record.id, record.tenant_id, record.finding_id, record.test_run_id, record.target_id,
            record.check_id, record.created_by, record.created_at,
            record.comparison_context ? JSON.stringify(record.comparison_context) : null,
          ],
        );
        if (inserted.rows[0]) return { ...inserted.rows[0], replayed: false };
        const existing = await client.query(
          `SELECT * FROM finding_retest_lineage
           WHERE tenant_id = $1 AND finding_id = $2 AND test_run_id = $3`,
          [record.tenant_id, record.finding_id, record.test_run_id],
        );
        const row = existing.rows[0];
        if (!row || row.target_id !== record.target_id || row.check_id !== record.check_id) {
          return { error: 'pair_mismatch', status: 409 };
        }
        return { ...row, replayed: true };
      });
    },

    async listLineage(ctx, findingId) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT * FROM finding_retest_lineage WHERE tenant_id = $1 AND finding_id = $2 ORDER BY created_at, id`,
          [ctx.tenantId, findingId],
        );
        return rows;
      });
    },
  };
}
