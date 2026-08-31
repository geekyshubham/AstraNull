import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';
import {
  createPostgresTestPolicyRepository,
  mapTestPolicyRow,
} from '../../src/persistence/postgres/testPolicyRepository.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, '../..');
const TEST_POLICY_REPO_SOURCE = readFileSync(
  path.join(ROOT, 'src/persistence/postgres/testPolicyRepository.mjs'),
  'utf8',
);

const CTX = { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' };
const FIXED_NOW = '2026-06-01T12:00:00.000Z';
const POLICY_ID = 'policy_1';

function createRecordingPool(handler) {
  const client = {
    queries: [],
    released: false,
    async query(text, params) {
      this.queries.push({ text, params });
      return handler(text, params, this.queries);
    },
    release() {
      this.released = true;
    },
  };
  return {
    client,
    async connect() {
      return client;
    },
  };
}

function createTestRepository(pool) {
  return createPostgresTestPolicyRepository(pool, {
    auditRepository: {
      async appendAuditEvent(entry) {
        return { id: 'audit_test', ...entry };
      },
    },
  });
}

function dataQueries(client) {
  return client.queries.filter((q) => {
    const t = q.text.trim();
    return t !== 'BEGIN' && t !== 'COMMIT' && t !== 'ROLLBACK' && !t.startsWith("SELECT set_config('app.tenant_id'");
  });
}

function assertTenantWrapped(client, tenantId) {
  assert.equal(client.queries[0].text.trim(), 'BEGIN');
  assert.equal(client.queries[1].text.trim(), "SELECT set_config('app.tenant_id', $1, true)");
  assert.deepEqual(client.queries[1].params, [tenantId]);
  assert.equal(client.queries.at(-1).text.trim(), 'COMMIT');
  assert.equal(client.released, true);
}

function assertUsesTenantPredicate(sql, params, tenantId) {
  const hasWherePredicate = /tenant_id\s*=\s*\$\d+/i.test(sql);
  const hasInsertColumn = /INSERT\s+INTO\s+\w+\s*\([^)]*tenant_id/i.test(sql);
  assert.ok(
    hasWherePredicate || hasInsertColumn,
    `expected tenant_id predicate or INSERT column in: ${sql}`,
  );
  assert.ok(params.includes(tenantId), `expected tenant id in params for: ${sql}`);
}

function assertNoInterpolatedValue(sql, value) {
  if (value == null || value === '') return;
  assert.ok(!sql.includes(String(value)), `value must not be interpolated into SQL: ${value}`);
}

function policyRow(overrides = {}) {
  return {
    id: POLICY_ID,
    tenant_id: CTX.tenantId,
    target_group_id: 'tg_1',
    target_id: 'tgt_1',
    check_id: 'dns.authoritative_response.safe',
    cadence: 'weekly',
    expected_verdict: 'pass',
    safe_windows: [{ day: 'Mon', start: '09:00', end: '11:00', timezone: 'UTC' }],
    timezone: 'UTC',
    event_trigger: null,
    state: 'active',
    enabled: true,
    max_concurrent_runs: 1,
    next_run_at: '2026-06-08T09:00:00.000Z',
    last_scheduled_at: null,
    last_dispatched_at: null,
    last_run_id: null,
    lease_token: null,
    lease_owner: null,
    lease_expires_at: null,
    schedule_revision: 1,
    safety_policy_snapshot: { target_group_safety_policy: null },
    archived_at: null,
    created_at: FIXED_NOW,
    updated_at: FIXED_NOW,
    ...overrides,
  };
}

describe('postgres test policy repository', () => {
  it('does not reference the dev store in source', () => {
    assert.equal(/\bgetStore\b/.test(TEST_POLICY_REPO_SOURCE), false);
    assert.equal(/\bpersistStore\b/.test(TEST_POLICY_REPO_SOURCE), false);
  });

  it('maps rows into normalized policy objects', () => {
    const mapped = mapTestPolicyRow(policyRow({ archived_at: null, created_at: new Date(FIXED_NOW) }));
    assert.equal(mapped.id, POLICY_ID);
    assert.equal(mapped.cadence, 'weekly');
    assert.deepEqual(mapped.safe_windows, [{ day: 'Mon', start: '09:00', end: '11:00', timezone: 'UTC' }]);
    assert.equal(mapped.created_at, FIXED_NOW);
    assert.equal('archived_at' in mapped, false);

    const archived = mapTestPolicyRow(policyRow({ archived_at: FIXED_NOW }));
    assert.equal(archived.archived_at, FIXED_NOW);
  });

  it('listTestPolicies scopes to tenant and excludes archived rows', async () => {
    const pool = createRecordingPool((text) => {
      if (text.includes('FROM test_policies')) return { rows: [policyRow()] };
      return { rows: [] };
    });
    const repo = createTestRepository(pool);
    const items = await repo.listTestPolicies(CTX);
    assert.equal(items.length, 1);
    assertTenantWrapped(pool.client, CTX.tenantId);
    const [q] = dataQueries(pool.client);
    assertUsesTenantPredicate(q.text, q.params, CTX.tenantId);
    assert.match(q.text, /archived_at IS NULL/);
  });

  it('getActiveTestPolicy filters by id, tenant, and archived_at', async () => {
    const pool = createRecordingPool((text) => {
      if (text.includes('FROM test_policies')) return { rows: [policyRow()] };
      return { rows: [] };
    });
    const repo = createTestRepository(pool);
    const policy = await repo.getActiveTestPolicy(CTX, POLICY_ID);
    assert.equal(policy.id, POLICY_ID);
    assertTenantWrapped(pool.client, CTX.tenantId);
    const [q] = dataQueries(pool.client);
    assertUsesTenantPredicate(q.text, q.params, CTX.tenantId);
    assert.match(q.text, /WHERE id = \$1 AND tenant_id = \$2 AND archived_at IS NULL/);
    assertNoInterpolatedValue(q.text, POLICY_ID);
    assert.ok(q.params.includes(POLICY_ID));
  });

  it('createTestPolicy inserts a tenant-scoped row with parameterized values', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.startsWith('INSERT INTO test_policies')) {
        assertUsesTenantPredicate(text, params, CTX.tenantId);
        assertNoInterpolatedValue(text, POLICY_ID);
        return {
          rows: [
            policyRow({
              id: params[0],
              tenant_id: params[1],
              target_group_id: params[2],
              target_id: params[3],
              check_id: params[4],
              cadence: params[5],
              expected_verdict: params[6],
              safe_windows: JSON.parse(params[7]),
              timezone: params[8],
              event_trigger: params[9] == null ? null : JSON.parse(params[9]),
              state: params[10],
              enabled: params[11],
              max_concurrent_runs: params[12],
              next_run_at: params[13],
              schedule_revision: params[14],
              safety_policy_snapshot: JSON.parse(params[15]),
              created_at: params[16],
              updated_at: params[17],
            }),
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createTestRepository(pool);
    const created = await repo.createTestPolicy(CTX, {
      id: POLICY_ID,
      tenant_id: CTX.tenantId,
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
      check_id: 'dns.authoritative_response.safe',
      cadence: 'weekly',
      expected_verdict: 'pass',
      safe_windows: [{ day: 'Mon', start: '09:00', end: '11:00', timezone: 'UTC' }],
      state: 'active',
      safety_policy_snapshot: { target_group_safety_policy: null },
      created_at: FIXED_NOW,
      updated_at: FIXED_NOW,
    });
    assert.equal(created.id, POLICY_ID);
    assert.equal(created.cadence, 'weekly');
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('updateTestPolicy sets provided fields plus updated_at under a tenant + active predicate', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.startsWith('UPDATE test_policies')) {
        assertUsesTenantPredicate(text, params, CTX.tenantId);
        assert.match(text, /cadence = \$1/);
        assert.match(text, /updated_at = \$\d+::timestamptz/);
        assert.match(text, /archived_at IS NULL/);
        return { rows: [policyRow({ cadence: 'monthly', expected_verdict: 'warn' })] };
      }
      return { rows: [] };
    });
    const repo = createTestRepository(pool);
    const updated = await repo.updateTestPolicy(CTX, POLICY_ID, {
      cadence: 'monthly',
      expected_verdict: 'warn',
      updated_at: FIXED_NOW,
    });
    assert.equal(updated.cadence, 'monthly');
    assert.equal(updated.expected_verdict, 'warn');
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('archiveTestPolicy marks archived under tenant + active predicate', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.startsWith('UPDATE test_policies')) {
        assertUsesTenantPredicate(text, params, CTX.tenantId);
        assert.match(text, /state = 'archived'/);
        assert.match(text, /archived_at = \$3::timestamptz/);
        assert.match(text, /archived_at IS NULL/);
        return { rows: [policyRow({ state: 'archived', archived_at: FIXED_NOW })] };
      }
      return { rows: [] };
    });
    const repo = createTestRepository(pool);
    const archived = await repo.archiveTestPolicy(CTX, POLICY_ID, { now: FIXED_NOW });
    assert.equal(archived.state, 'archived');
    assert.equal(archived.archived_at, FIXED_NOW);
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('returns null when update/archive affect no active row', async () => {
    const pool = createRecordingPool(() => ({ rows: [] }));
    const repo = createTestRepository(pool);
    assert.equal(await repo.updateTestPolicy(CTX, 'policy_missing', { cadence: 'daily' }), null);
    assert.equal(await repo.archiveTestPolicy(CTX, 'policy_missing'), null);
  });
});


describe('postgres test policy due leases and idempotency', () => {
  it('leases due policies with tenant scope, SKIP LOCKED, and a durable idempotency row', async () => {
    const dueRow = policyRow({
      cadence: 'daily',
      next_run_at: '2026-06-01T11:59:00.000Z',
      enabled: true,
    });
    const pool = createRecordingPool((text, params) => {
      if (text.includes('FOR UPDATE SKIP LOCKED')) return { rows: [dueRow] };
      if (text.startsWith('INSERT INTO test_policy_dispatches')) {
        return {
          rows: [{
            id: params[0], tenant_id: params[1], policy_id: params[2], scheduled_for: params[3],
            idempotency_key: params[4], state: 'leased', lease_token: params[5],
            lease_owner: params[6], lease_expires_at: params[7], created_at: params[8], updated_at: params[8],
          }],
        };
      }
      if (text.startsWith('UPDATE test_policies')) {
        return { rows: [{ ...dueRow, lease_token: params[2], lease_owner: params[3], lease_expires_at: params[4] }] };
      }
      return { rows: [] };
    });
    const repo = createTestRepository(pool);
    const leased = await repo.leaseDueTestPolicies(CTX, {
      workerId: 'scheduler-1', now: FIXED_NOW, leaseMs: 60_000, limit: 10,
    });

    assert.equal(leased.length, 1);
    assert.equal(leased[0].tenant_id, CTX.tenantId);
    assert.match(leased[0].idempotency_key, /^[a-f0-9]{64}$/);
    const queries = dataQueries(pool.client);
    assert.match(queries[0].text, /tenant_id = \$1/);
    assert.match(queries[0].text, /FOR UPDATE SKIP LOCKED/);
    assert.match(queries[1].text, /ON CONFLICT \(tenant_id, idempotency_key\) DO NOTHING/);
    assert.ok(queries.every((query) => query.params.includes(CTX.tenantId)));
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('re-leases an expired occurrence even when a prior worker already claimed start', async () => {
    const dueRow = policyRow({
      cadence: 'daily', next_run_at: '2026-06-01T11:59:00.000Z', enabled: true,
    });
    const pool = createRecordingPool((text, params) => {
      if (text.includes('FOR UPDATE SKIP LOCKED')) return { rows: [dueRow] };
      if (text.startsWith('INSERT INTO test_policy_dispatches')) return { rows: [] };
      if (text.startsWith('UPDATE test_policy_dispatches')) {
        return { rows: [{
          id: 'dispatch_existing', tenant_id: CTX.tenantId, policy_id: POLICY_ID,
          scheduled_for: dueRow.next_run_at, idempotency_key: params[2], state: 'leased',
          lease_token: params[3], lease_owner: params[4], lease_expires_at: params[5],
          start_claimed_at: null, created_at: FIXED_NOW, updated_at: params[6],
        }] };
      }
      if (text.startsWith('UPDATE test_policies')) {
        return { rows: [{ ...dueRow, lease_token: params[2], lease_owner: params[3], lease_expires_at: params[4] }] };
      }
      return { rows: [] };
    });
    const repo = createTestRepository(pool);
    const leased = await repo.leaseDueTestPolicies(CTX, {
      workerId: 'scheduler-2', now: FIXED_NOW, leaseMs: 60_000,
    });
    assert.equal(leased[0].dispatch_id, 'dispatch_existing');
    const reLease = dataQueries(pool.client).find((query) =>
      query.text.startsWith('UPDATE test_policy_dispatches'));
    assert.match(reLease.text, /state = 'leased'/);
    assert.doesNotMatch(reLease.text, /start_claimed_at IS NULL/);
    assert.match(reLease.text, /lease_expires_at <= \$7::timestamptz/);
  });

  it('claims the exact live dispatch and rejects a claim after lease expiry', async () => {
    const leaseToken = 'policy_lease_1';
    const idempotencyKey = 'a'.repeat(64);
    const dispatchId = 'policy_dispatch_1';
    const dispatchRow = {
      id: dispatchId, tenant_id: CTX.tenantId, policy_id: POLICY_ID,
      scheduled_for: '2026-06-01T11:59:00.000Z', idempotency_key: idempotencyKey,
      state: 'leased', lease_token: leaseToken, lease_owner: 'scheduler-1',
      lease_expires_at: '2026-06-01T12:01:00.000Z', start_claimed_at: null,
      created_at: FIXED_NOW, updated_at: FIXED_NOW,
    };
    const pool = createRecordingPool((text, params) => {
      if (text.startsWith('SELECT * FROM test_policy_dispatches')) return { rows: [dispatchRow] };
      if (text.includes('FROM test_policies')) {
        return { rows: [policyRow({ lease_token: leaseToken, lease_expires_at: '2026-06-01T12:01:00.000Z' })] };
      }
      if (text.startsWith('UPDATE test_policy_dispatches')) {
        return { rows: [{ ...dispatchRow, start_claimed_at: params[3], updated_at: params[3] }] };
      }
      return { rows: [] };
    });
    const repo = createTestRepository(pool);
    const claimed = await repo.claimPolicyDispatchStart(CTX, POLICY_ID, {
      dispatch_id: dispatchId, lease_token: leaseToken, idempotency_key: idempotencyKey,
    }, { now: FIXED_NOW });
    assert.equal(claimed.start_claimed_at, FIXED_NOW);
    const queries = dataQueries(pool.client);
    assert.match(queries[0].text, /tenant_id = \$1 AND id = \$2 AND policy_id = \$3/);
    assert.match(queries[2].text, /state = 'leased' AND start_claimed_at IS NULL/);

    const expiredPool = createRecordingPool((text) => text.startsWith('SELECT * FROM test_policy_dispatches')
      ? { rows: [{ ...dispatchRow, lease_expires_at: '2026-06-01T11:59:59.000Z' }] }
      : { rows: [] });
    const expiredRepo = createTestRepository(expiredPool);
    const expired = await expiredRepo.claimPolicyDispatchStart(CTX, POLICY_ID, {
      dispatch_id: dispatchId, lease_token: leaseToken, idempotency_key: idempotencyKey,
    }, { now: FIXED_NOW });
    assert.equal(expired.error, 'policy_lease_lost');
    assert.equal(dataQueries(expiredPool.client).length, 1);

    const stalePolicyPool = createRecordingPool((text) => {
      if (text.startsWith('SELECT * FROM test_policy_dispatches')) return { rows: [dispatchRow] };
      if (text.includes('FROM test_policies')) {
        return { rows: [policyRow({
          lease_token: leaseToken,
          lease_expires_at: '2026-06-01T11:59:59.000Z',
        })] };
      }
      return { rows: [] };
    });
    const stalePolicyRepo = createTestRepository(stalePolicyPool);
    const stalePolicy = await stalePolicyRepo.claimPolicyDispatchStart(CTX, POLICY_ID, {
      dispatch_id: dispatchId, lease_token: leaseToken, idempotency_key: idempotencyKey,
    }, { now: FIXED_NOW });
    assert.equal(stalePolicy.error, 'policy_lease_lost');
    assert.equal(dataQueries(stalePolicyPool.client).length, 2);
  });

  it('rejects run bindings on failed or skipped settlements before policy mutation', async () => {
    const dispatchId = 'policy_dispatch_invalid_run';
    const leaseToken = 'policy_lease_invalid_run';
    const idempotencyKey = 'b'.repeat(64);
    const pool = createRecordingPool((text) => {
      if (text.startsWith('SELECT * FROM test_policy_dispatches')) {
        return { rows: [{
          id: dispatchId, tenant_id: CTX.tenantId, policy_id: POLICY_ID,
          scheduled_for: '2026-06-01T11:59:00.000Z', idempotency_key: idempotencyKey,
          state: 'leased', lease_token: leaseToken, lease_owner: 'scheduler-1',
          lease_expires_at: '2026-06-01T12:01:00.000Z', start_claimed_at: FIXED_NOW,
          created_at: FIXED_NOW, updated_at: FIXED_NOW,
        }] };
      }
      return { rows: [] };
    });
    const repo = createTestRepository(pool);
    const rejected = await repo.completePolicyDispatch(CTX, POLICY_ID, {
      dispatch_id: dispatchId,
      lease_token: leaseToken,
      idempotency_key: idempotencyKey,
      state: 'failed',
      run_id: 'run_must_not_bind',
    }, { now: FIXED_NOW });
    assert.equal(rejected.error, 'invalid_policy_run_binding');
    assert.equal(dataQueries(pool.client).length, 1);
  });

  it('completes a lease with tenant/policy/token compare-and-set and persists run binding', async () => {
    const leaseToken = 'policy_lease_1';
    const idempotencyKey = 'a'.repeat(64);
    const dispatchId = 'policy_dispatch_1';
    const pool = createRecordingPool((text, params) => {
      if (text.startsWith('SELECT * FROM test_policy_dispatches')) {
        return { rows: [{
          id: dispatchId, tenant_id: CTX.tenantId, policy_id: POLICY_ID,
          scheduled_for: '2026-06-01T11:59:00.000Z', idempotency_key: idempotencyKey,
          state: 'leased', lease_token: leaseToken, lease_owner: 'scheduler-1',
          lease_expires_at: '2026-06-01T12:01:00.000Z', start_claimed_at: FIXED_NOW,
          created_at: FIXED_NOW, updated_at: FIXED_NOW,
        }] };
      }
      if (text.startsWith('SELECT run.id')) return { rows: [{ id: 'run_1' }] };
      if (text.startsWith('UPDATE test_policies')) {
        return { rows: [{ ...policyRow(), next_run_at: params[3], last_run_id: params[6] }] };
      }
      if (text.startsWith('UPDATE test_policy_dispatches')) {
        return { rows: [{
          id: dispatchId, tenant_id: CTX.tenantId, policy_id: POLICY_ID,
          scheduled_for: '2026-06-01T11:59:00.000Z', idempotency_key: idempotencyKey,
          state: params[3], run_id: params[4], error_code: params[5],
          completed_at: params[6], created_at: FIXED_NOW, updated_at: params[6],
        }] };
      }
      return { rows: [] };
    });
    const repo = createTestRepository(pool);
    const completed = await repo.completePolicyDispatch(CTX, POLICY_ID, {
      dispatch_id: dispatchId,
      lease_token: leaseToken,
      idempotency_key: idempotencyKey,
      state: 'dispatched',
      run_id: 'run_1',
      next_run_at: '2026-06-02T11:59:00.000Z',
    }, { now: FIXED_NOW });

    assert.equal(completed.state, 'dispatched');
    assert.equal(completed.run_id, 'run_1');
    const queries = dataQueries(pool.client);
    assert.match(queries[0].text, /tenant_id = \$1.*policy_id = \$3/s);
    assert.match(queries[1].text, /run\.policy_dispatch_id = \$4/);
    assert.match(queries[2].text, /lease_token = \$3/);
    assert.match(queries[3].text, /UPDATE test_policy_dispatches/);
    assert.ok(queries.every((query) => query.params.includes(CTX.tenantId)));
    assertTenantWrapped(pool.client, CTX.tenantId);
  });
});
