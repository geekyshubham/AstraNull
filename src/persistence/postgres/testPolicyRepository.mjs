import { policyDispatchIdempotencyKey } from '../../contracts/testPolicyManagement.mjs';
import { newId } from '../../lib/ids.mjs';
import { createAuditRepository } from './auditRepository.mjs';
import { withTenantContext } from './tenantContext.mjs';

const TEST_POLICY_COLUMNS = `id, tenant_id, target_group_id, target_id, check_id, cadence, expected_verdict,
  safe_windows, timezone, event_trigger, state, enabled, max_concurrent_runs,
  next_run_at, last_scheduled_at, last_dispatched_at, last_run_id,
  lease_token, lease_owner, lease_expires_at, schedule_revision,
  safety_policy_snapshot, archived_at, created_at, updated_at`;

function toIso(value) {
  if (value == null) return value;
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function asObject(value) {
  if (value && typeof value === 'object' && !Array.isArray(value)) return value;
  return {};
}

function mapTestPolicyRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    target_group_id: row.target_group_id,
    target_id: row.target_id ?? null,
    check_id: row.check_id,
    cadence: row.cadence,
    expected_verdict: row.expected_verdict,
    safe_windows: asArray(row.safe_windows),
    timezone: row.timezone ?? 'UTC',
    event_trigger: row.event_trigger == null ? null : asObject(row.event_trigger),
    state: row.state,
    enabled: row.enabled !== false,
    max_concurrent_runs: Number(row.max_concurrent_runs ?? 1),
    next_run_at: toIso(row.next_run_at) ?? null,
    last_scheduled_at: toIso(row.last_scheduled_at) ?? null,
    last_dispatched_at: toIso(row.last_dispatched_at) ?? null,
    last_run_id: row.last_run_id ?? null,
    lease_token: row.lease_token ?? null,
    lease_owner: row.lease_owner ?? null,
    lease_expires_at: toIso(row.lease_expires_at) ?? null,
    schedule_revision: Number(row.schedule_revision ?? 1),
    safety_policy_snapshot: asObject(row.safety_policy_snapshot),
    ...(row.archived_at ? { archived_at: toIso(row.archived_at) } : {}),
    created_at: toIso(row.created_at),
    updated_at: toIso(row.updated_at),
  };
}

function mapDispatchRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    policy_id: row.policy_id,
    scheduled_for: toIso(row.scheduled_for),
    idempotency_key: row.idempotency_key,
    state: row.state,
    lease_token: row.lease_token ?? null,
    lease_owner: row.lease_owner ?? null,
    lease_expires_at: toIso(row.lease_expires_at) ?? null,
    start_claimed_at: toIso(row.start_claimed_at) ?? null,
    run_id: row.run_id ?? null,
    error_code: row.error_code ?? null,
    created_at: toIso(row.created_at),
    updated_at: toIso(row.updated_at),
    completed_at: toIso(row.completed_at) ?? null,
  };
}

async function appendPolicyAudit(auditRepository, client, ctx, event, now) {
  if (!auditRepository?.appendAuditEvent) {
    throw new Error('Postgres test-policy management requires transactional audit persistence.');
  }
  return auditRepository.appendAuditEvent({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    ...event,
  }, { client, now: new Date(now) });
}

function auditMetadata(policy, changedFields) {
  return {
    target_group_id: policy.target_group_id,
    target_id: policy.target_id ?? null,
    check_id: policy.check_id,
    changed_fields: changedFields,
  };
}

/**
 * @param {import('pg').Pool} pool
 */
export function createPostgresTestPolicyRepository(pool, options = {}) {
  const auditRepository = options.auditRepository ?? createAuditRepository(pool);
  return {
    async listTestPolicies(ctx) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${TEST_POLICY_COLUMNS}
           FROM test_policies
           WHERE tenant_id = $1 AND archived_at IS NULL
           ORDER BY created_at`,
          [ctx.tenantId],
        );
        return rows.map(mapTestPolicyRow);
      });
    },

    async getActiveTestPolicy(ctx, id) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${TEST_POLICY_COLUMNS}
           FROM test_policies
           WHERE id = $1 AND tenant_id = $2 AND archived_at IS NULL`,
          [id, ctx.tenantId],
        );
        return mapTestPolicyRow(rows[0] ?? null);
      });
    },

    async findActivePolicyByGroupCheck(ctx, targetGroupId, targetId, checkId) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${TEST_POLICY_COLUMNS}
           FROM test_policies
           WHERE tenant_id = $1 AND target_group_id = $2 AND target_id = $3
             AND check_id = $4 AND archived_at IS NULL
           LIMIT 1`,
          [ctx.tenantId, targetGroupId, targetId, checkId],
        );
        return mapTestPolicyRow(rows[0] ?? null);
      });
    },

    async createTestPolicy(ctx, record) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        try {
          const { rows } = await client.query(
            `INSERT INTO test_policies (
               id, tenant_id, target_group_id, target_id, check_id, cadence, expected_verdict,
               safe_windows, timezone, event_trigger, state, enabled, max_concurrent_runs,
               next_run_at, schedule_revision, safety_policy_snapshot, created_at, updated_at
             ) VALUES (
               $1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10::jsonb, $11, $12, $13,
               $14::timestamptz, $15, $16::jsonb, $17::timestamptz, $18::timestamptz
             ) RETURNING ${TEST_POLICY_COLUMNS}`,
            [
              record.id, ctx.tenantId, record.target_group_id, record.target_id, record.check_id,
              record.cadence, record.expected_verdict, JSON.stringify(asArray(record.safe_windows)),
              record.timezone ?? 'UTC', record.event_trigger == null ? null : JSON.stringify(record.event_trigger),
              record.state ?? 'active', record.enabled !== false, record.max_concurrent_runs ?? 1,
              record.next_run_at ?? null, record.schedule_revision ?? 1,
              JSON.stringify(asObject(record.safety_policy_snapshot)), record.created_at, record.updated_at,
            ],
          );
          const policy = mapTestPolicyRow(rows[0]);
          await appendPolicyAudit(auditRepository, client, ctx, {
            action: 'test_policy.created', resource_type: 'test_policy', resource_id: policy.id,
            metadata: auditMetadata(policy, [
              'target_group_id', 'target_id', 'check_id', 'cadence', 'expected_verdict', 'safe_windows', 'timezone',
              'event_trigger', 'enabled', 'max_concurrent_runs', 'next_run_at', 'safety_policy_snapshot',
            ]),
          }, record.created_at);
          return policy;
        } catch (error) {
          if (error?.code === '23505') return { error: 'test_policy_exists', status: 409 };
          throw error;
        }
      });
    },

    async updateTestPolicy(ctx, id, patch) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const sets = [];
        const params = [];
        let n = 1;
        const fields = [
          ['cadence'], ['expected_verdict'], ['timezone'], ['state'], ['enabled'],
          ['max_concurrent_runs'], ['next_run_at', '::timestamptz'],
          ['lease_token'], ['lease_owner'], ['lease_expires_at', '::timestamptz'],
          ['schedule_revision'],
        ];
        for (const [field, cast = ''] of fields) {
          if (patch[field] !== undefined) {
            sets.push(`${field} = $${n++}${cast}`);
            params.push(patch[field]);
          }
        }
        for (const field of ['safe_windows', 'event_trigger']) {
          if (patch[field] !== undefined) {
            sets.push(`${field} = $${n++}::jsonb`);
            params.push(patch[field] == null ? null : JSON.stringify(patch[field]));
          }
        }
        const updatedAt = patch.updated_at ?? new Date().toISOString();
        sets.push(`updated_at = $${n++}::timestamptz`);
        params.push(updatedAt);
        params.push(id, ctx.tenantId);
        const idParam = n++;
        const tenantParam = n++;

        try {
          const { rows } = await client.query(
            `UPDATE test_policies SET ${sets.join(', ')}
             WHERE id = $${idParam} AND tenant_id = $${tenantParam} AND archived_at IS NULL
             RETURNING ${TEST_POLICY_COLUMNS}`,
            params,
          );
          const policy = mapTestPolicyRow(rows[0] ?? null);
          if (!policy) return null;
          if (patch.changed_fields?.length) {
            await appendPolicyAudit(auditRepository, client, ctx, {
              action: 'test_policy.updated', resource_type: 'test_policy', resource_id: id,
              metadata: auditMetadata(policy, patch.changed_fields),
            }, updatedAt);
          }
          return policy;
        } catch (error) {
          if (error?.code === '23505') return { error: 'test_policy_exists', status: 409 };
          throw error;
        }
      });
    },

    async archiveTestPolicy(ctx, id, options = {}) {
      const now = options.now ?? new Date().toISOString();
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE test_policies
           SET state = 'archived', enabled = FALSE, archived_at = $3::timestamptz,
               next_run_at = NULL, lease_token = NULL, lease_owner = NULL,
               lease_expires_at = NULL, updated_at = $3::timestamptz
           WHERE id = $1 AND tenant_id = $2 AND archived_at IS NULL
           RETURNING ${TEST_POLICY_COLUMNS}`,
          [id, ctx.tenantId, now],
        );
        const policy = mapTestPolicyRow(rows[0] ?? null);
        if (!policy) return null;
        await appendPolicyAudit(auditRepository, client, ctx, {
          action: 'test_policy.archived', resource_type: 'test_policy', resource_id: id,
          metadata: auditMetadata(policy, ['state', 'enabled', 'archived_at', 'next_run_at']),
        }, now);
        return policy;
      });
    },

    async listDueTestPolicies(ctx, options = {}) {
      const now = new Date(options.now ?? Date.now()).toISOString();
      const limit = Math.max(1, Math.min(100, Number(options.limit) || 25));
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${TEST_POLICY_COLUMNS}
           FROM test_policies
           WHERE tenant_id = $1 AND archived_at IS NULL AND state = 'active' AND enabled = TRUE
             AND cadence IN ('daily', 'weekly', 'monthly')
             AND next_run_at IS NOT NULL AND next_run_at <= $2::timestamptz
             AND (lease_expires_at IS NULL OR lease_expires_at <= $2::timestamptz)
           ORDER BY next_run_at, id
           LIMIT $3`,
          [ctx.tenantId, now, limit],
        );
        return rows.map(mapTestPolicyRow);
      });
    },

    async leaseDueTestPolicies(ctx, options = {}) {
      const workerId = String(options.workerId ?? '').trim();
      if (!workerId) return { error: 'missing_worker_id', status: 400 };
      const nowDate = new Date(options.now ?? Date.now());
      const now = nowDate.toISOString();
      const leaseMs = Math.max(1_000, Math.min(15 * 60_000, Number(options.leaseMs) || 60_000));
      const leaseExpiresAt = new Date(nowDate.getTime() + leaseMs).toISOString();
      const limit = Math.max(1, Math.min(100, Number(options.limit) || 25));

      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows: candidates } = await client.query(
          `SELECT ${TEST_POLICY_COLUMNS}
           FROM test_policies
           WHERE tenant_id = $1 AND archived_at IS NULL AND state = 'active' AND enabled = TRUE
             AND cadence IN ('daily', 'weekly', 'monthly')
             AND next_run_at IS NOT NULL AND next_run_at <= $2::timestamptz
             AND (lease_expires_at IS NULL OR lease_expires_at <= $2::timestamptz)
           ORDER BY next_run_at, id
           FOR UPDATE SKIP LOCKED
           LIMIT $3`,
          [ctx.tenantId, now, limit],
        );
        const leased = [];
        for (const row of candidates) {
          const policy = mapTestPolicyRow(row);
          const scheduledFor = new Date(policy.next_run_at).toISOString();
          const idempotencyKey = policyDispatchIdempotencyKey(ctx.tenantId, policy.id, scheduledFor);
          const leaseToken = newId('policy_lease');
          let dispatchResult = await client.query(
            `INSERT INTO test_policy_dispatches (
               id, tenant_id, policy_id, scheduled_for, idempotency_key, state,
               lease_token, lease_owner, lease_expires_at, created_at, updated_at
             ) VALUES ($1,$2,$3,$4::timestamptz,$5,'leased',$6,$7,$8::timestamptz,$9::timestamptz,$9::timestamptz)
             ON CONFLICT (tenant_id, idempotency_key) DO NOTHING
             RETURNING *`,
            [newId('policy_dispatch'), ctx.tenantId, policy.id, scheduledFor, idempotencyKey,
              leaseToken, workerId, leaseExpiresAt, now],
          );
          if (!dispatchResult.rows[0]) {
            dispatchResult = await client.query(
              `UPDATE test_policy_dispatches
               SET lease_token = $4, lease_owner = $5, lease_expires_at = $6::timestamptz,
                   updated_at = $7::timestamptz
               WHERE tenant_id = $1 AND policy_id = $2 AND idempotency_key = $3
                 AND state = 'leased'
                 AND lease_expires_at <= $7::timestamptz
               RETURNING *`,
              [ctx.tenantId, policy.id, idempotencyKey, leaseToken, workerId, leaseExpiresAt, now],
            );
          }
          if (!dispatchResult.rows[0]) continue;
          const updated = await client.query(
            `UPDATE test_policies
             SET lease_token = $3, lease_owner = $4, lease_expires_at = $5::timestamptz,
                 last_scheduled_at = next_run_at, updated_at = $6::timestamptz
             WHERE tenant_id = $1 AND id = $2 AND archived_at IS NULL
             RETURNING ${TEST_POLICY_COLUMNS}`,
            [ctx.tenantId, policy.id, leaseToken, workerId, leaseExpiresAt, now],
          );
          leased.push({
            ...mapTestPolicyRow(updated.rows[0]),
            dispatch_id: dispatchResult.rows[0].id,
            scheduled_for: scheduledFor,
            idempotency_key: idempotencyKey,
            lease_token: leaseToken,
            lease_expires_at: leaseExpiresAt,
          });
        }
        return leased;
      });
    },

    async claimPolicyDispatchStart(ctx, policyId, input = {}, options = {}) {
      const nowDate = new Date(options.now ?? Date.now());
      const now = nowDate.toISOString();
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const dispatchResult = await client.query(
          `SELECT * FROM test_policy_dispatches
           WHERE tenant_id = $1 AND id = $2 AND policy_id = $3
           FOR UPDATE`,
          [ctx.tenantId, input.dispatch_id, policyId],
        );
        const dispatch = mapDispatchRow(dispatchResult.rows[0] ?? null);
        if (!dispatch) return { error: 'policy_dispatch_not_found', status: 404 };
        if (dispatch.idempotency_key !== input.idempotency_key) {
          return { error: 'policy_dispatch_key_mismatch', status: 409 };
        }
        if (dispatch.start_claimed_at) {
          if (
            dispatch.state === 'leased'
            && dispatch.lease_token === input.lease_token
            && new Date(dispatch.lease_expires_at) > nowDate
          ) return dispatch;
          return { error: 'policy_dispatch_start_claimed', status: 409 };
        }
        if (
          dispatch.state !== 'leased'
          || dispatch.lease_token !== input.lease_token
          || new Date(dispatch.lease_expires_at) <= nowDate
        ) {
          return { error: 'policy_lease_lost', status: 409 };
        }
        const policyResult = await client.query(
          `SELECT ${TEST_POLICY_COLUMNS}
           FROM test_policies
           WHERE tenant_id = $1 AND id = $2 AND archived_at IS NULL
           FOR UPDATE`,
          [ctx.tenantId, policyId],
        );
        const policy = mapTestPolicyRow(policyResult.rows[0] ?? null);
        if (
          !policy
          || policy.state !== 'active'
          || policy.enabled !== true
          || policy.lease_token !== input.lease_token
          || !policy.lease_expires_at
          || new Date(policy.lease_expires_at) <= nowDate
        ) {
          return { error: 'policy_lease_lost', status: 409 };
        }
        const claimed = await client.query(
          `UPDATE test_policy_dispatches
           SET start_claimed_at = $4::timestamptz, updated_at = $4::timestamptz
           WHERE tenant_id = $1 AND id = $2 AND policy_id = $3
             AND state = 'leased' AND start_claimed_at IS NULL
           RETURNING *`,
          [ctx.tenantId, input.dispatch_id, policyId, now],
        );
        if (!claimed.rows[0]) return { error: 'policy_dispatch_start_claimed', status: 409 };
        await appendPolicyAudit(auditRepository, client, ctx, {
          action: 'test_policy.dispatch_start_claimed',
          resource_type: 'test_policy',
          resource_id: policyId,
          metadata: auditMetadata(policy, ['start_claimed_at']),
        }, now);
        return mapDispatchRow(claimed.rows[0]);
      });
    },

    async completePolicyDispatch(ctx, policyId, input = {}, options = {}) {
      const nowDate = new Date(options.now ?? Date.now());
      const now = nowDate.toISOString();
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const dispatchResult = await client.query(
          `SELECT * FROM test_policy_dispatches
           WHERE tenant_id = $1 AND id = $2 AND policy_id = $3
           FOR UPDATE`,
          [ctx.tenantId, input.dispatch_id, policyId],
        );
        const dispatch = mapDispatchRow(dispatchResult.rows[0] ?? null);
        if (!dispatch) return { error: 'policy_dispatch_not_found', status: 404 };
        if (dispatch.idempotency_key !== input.idempotency_key) return { error: 'policy_dispatch_key_mismatch', status: 409 };
        const runId = input.run_id == null ? null : String(input.run_id).trim();
        const state = input.state ?? (runId ? 'dispatched' : 'skipped');
        if (!['dispatched', 'skipped', 'failed'].includes(state)) return { error: 'invalid_policy_dispatch_state', status: 400 };
        if (state === 'dispatched' && !runId) return { error: 'missing_policy_run_id', status: 400 };
        if (state !== 'dispatched' && runId) return { error: 'invalid_policy_run_binding', status: 400 };
        if (state === 'dispatched') {
          const boundRun = await client.query(
            `SELECT run.id
             FROM test_runs run
             JOIN test_policies policy
               ON policy.tenant_id = run.tenant_id AND policy.id = run.policy_id
             WHERE run.tenant_id = $1 AND run.id = $2 AND run.policy_id = $3
               AND run.policy_dispatch_id = $4
               AND run.target_group_id = policy.target_group_id
               AND run.target_id = policy.target_id
               AND run.check_id = policy.check_id
             LIMIT 1`,
            [ctx.tenantId, runId, policyId, dispatch.id],
          );
          if (!boundRun.rows[0]) return { error: 'policy_run_binding_mismatch', status: 409 };
        }
        if (dispatch.state !== 'leased') {
          if (
            dispatch.state === state
            && (dispatch.run_id ?? null) === (runId ?? null)
            && (dispatch.error_code ?? null) === (input.error_code ?? null)
          ) return dispatch;
          return { error: 'policy_dispatch_already_settled', status: 409 };
        }
        if (dispatch.lease_token !== input.lease_token) return { error: 'policy_lease_lost', status: 409 };
        if (!dispatch.start_claimed_at) return { error: 'policy_dispatch_start_not_claimed', status: 409 };

        const policyResult = await client.query(
          `UPDATE test_policies
           SET next_run_at = $4::timestamptz,
               last_dispatched_at = CASE WHEN $5 = 'dispatched' THEN $6::timestamptz ELSE last_dispatched_at END,
               last_run_id = COALESCE($7, last_run_id),
               lease_token = NULL, lease_owner = NULL, lease_expires_at = NULL,
               updated_at = $6::timestamptz
           WHERE tenant_id = $1 AND id = $2 AND lease_token = $3 AND archived_at IS NULL
           RETURNING ${TEST_POLICY_COLUMNS}`,
          [ctx.tenantId, policyId, input.lease_token, input.next_run_at ?? null, state, now, runId ?? null],
        );
        const policy = mapTestPolicyRow(policyResult.rows[0] ?? null);
        if (!policy) return { error: 'policy_lease_lost', status: 409 };
        const completed = await client.query(
          `UPDATE test_policy_dispatches
           SET state = $4, run_id = $5, error_code = $6,
               lease_token = NULL, lease_owner = NULL, lease_expires_at = NULL,
               completed_at = $7::timestamptz, updated_at = $7::timestamptz
           WHERE tenant_id = $1 AND id = $2 AND policy_id = $3
             AND state = 'leased' AND lease_token = $8 AND start_claimed_at IS NOT NULL
           RETURNING *`,
          [
            ctx.tenantId,
            input.dispatch_id,
            policyId,
            state,
            runId ?? null,
            input.error_code ?? null,
            now,
            input.lease_token,
          ],
        );
        if (!completed.rows[0]) return { error: 'policy_lease_lost', status: 409 };
        await appendPolicyAudit(auditRepository, client, ctx, {
          action: `test_policy.dispatch_${state}`, resource_type: 'test_policy', resource_id: policyId,
          metadata: auditMetadata(policy, ['next_run_at', 'last_dispatched_at', 'last_run_id', 'lease_token']),
        }, now);
        return mapDispatchRow(completed.rows[0]);
      });
    },
  };
}

export { TEST_POLICY_COLUMNS, mapDispatchRow, mapTestPolicyRow };
