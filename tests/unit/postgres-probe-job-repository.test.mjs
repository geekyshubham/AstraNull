import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  createProbeJobRepository,
  isProbeJobLeaseStale,
  mapProbeJobRow,
  probeJobLeaseTtlSeconds,
} from '../../src/persistence/postgres/probeJobRepository.mjs';
import { metricsSnapshot } from '../../src/lib/metrics.mjs';

const CTX = { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' };
const FIXED_NOW = '2026-06-01T12:00:00.000Z';
const WORKER_ID = 'pw_worker_1';

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

function sampleRow(overrides = {}) {
  return {
    id: 'pjob_1',
    tenant_id: CTX.tenantId,
    test_run_id: 'run_1',
    target_id: 'tgt_1',
    check_id: 'origin.direct_bypass.safe',
    vector_family: 'origin',
    status: 'pending',
    nonce_hash: 'nh_abc',
    nonce_for_worker: 'nonce_plain',
    probe_profile: { kind: 'metadata_marker' },
    constraints_json: { max_requests: 1, timeout_ms: 5000 },
    target_descriptor_json: { id: 'tgt_1', kind: 'ip', value: '203.0.113.1' },
    worker_metadata_json: { check_title: 'Safe' },
    job_signature: 'sig_hex',
    leased_at: null,
    leased_by: null,
    completed_at: null,
    created_at: FIXED_NOW,
    ...overrides,
  };
}

describe('postgres probe job repository', () => {
  it('maps probe job JSON columns to worker-facing shape', () => {
    const job = mapProbeJobRow(sampleRow());
    assert.equal(job.id, 'pjob_1');
    assert.equal(job.nonce, 'nonce_plain');
    assert.equal(job.constraints.max_requests, 1);
    assert.equal(job.target.value, '203.0.113.1');
    assert.equal(job.worker_metadata.check_title, 'Safe');
  });

  it('leases one pending job with tenant context and SKIP LOCKED', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (sql.includes('WITH picked AS')) {
        // $5-$8 are the stale-lease TTL tunables; asserted in the reclaim test below.
        assert.deepEqual(params.slice(0, 4), [CTX.tenantId, 1, FIXED_NOW, WORKER_ID]);
        return { rows: [sampleRow({ status: 'leased', leased_by: WORKER_ID })] };
      }
      return { rows: [] };
    });
    const repo = createProbeJobRepository(pool);
    const jobs = await repo.leasePendingJobsForWorker(CTX, WORKER_ID, {
      limit: 25,
      leasedAt: FIXED_NOW,
    });
    assert.equal(jobs.length, 1);
    assert.equal(jobs[0].job_signature, 'sig_hex');
    assertTenantWrapped(pool.client, CTX.tenantId);
    const lease = dataQueries(pool.client).find((q) => q.text.includes('WITH picked AS'));
    assert.match(lease.text, /FOR UPDATE SKIP LOCKED/);
    assert.match(lease.text, /LIMIT \$2/);
    assert.ok(!lease.text.includes('ten_demo'));
  });

  it('lease predicate reclaims expired leases while keeping SKIP LOCKED and bound TTL params', async () => {
    let leaseSql = null;
    let leaseParams = null;
    const pool = createRecordingPool((sql, params) => {
      if (sql.includes('WITH picked AS')) {
        leaseSql = sql;
        leaseParams = params;
        return { rows: [sampleRow({ status: 'leased', leased_by: WORKER_ID })] };
      }
      return { rows: [] };
    });
    const repo = createProbeJobRepository(pool);
    await repo.leasePendingJobsForWorker(CTX, WORKER_ID, { leasedAt: FIXED_NOW });

    // Both branches present: fresh work and reclaimable work.
    assert.match(leaseSql, /candidate\.status = 'pending'/);
    assert.match(leaseSql, /candidate\.status = 'leased' AND candidate\.leased_at < now\(\) -/);
    assert.match(leaseSql, /tr\.status IN \('running', 'collecting'\)/);
    assert.match(leaseSql, /ov\.status = 'challenge_sent'/);
    // Concurrency protection must survive the widened predicate.
    assert.match(leaseSql, /FOR UPDATE SKIP LOCKED/);
    // Every TTL tunable is a bound parameter, never interpolated.
    assert.equal(leaseParams.length, 8);
    assert.match(leaseSql, /\$5::numeric/);
    assert.match(leaseSql, /\$6::numeric/);
    assert.match(leaseSql, /\$7::numeric/);
    assert.match(leaseSql, /\$8::numeric/);
    assert.ok(!leaseSql.includes('ten_demo'));
    // Staleness is judged per row against that row's own budget.
    assert.match(leaseSql, /constraints_json->>'max_duration_seconds'/);
  });

  it('counts reclaimed leases in a metric without counting ordinary pending leases', async () => {
    const before = metricsSnapshot().probe_job_leases_reclaimed_total ?? 0;
    const pool = createRecordingPool((sql) => {
      if (sql.includes('WITH picked AS')) {
        return {
          rows: [
            // Ordinary pending pickup — not a reclaim.
            { ...sampleRow({ id: 'pjob_fresh', status: 'leased' }), prior_status: 'pending' },
            // Taken from a presumed-dead worker — a reclaim.
            { ...sampleRow({ id: 'pjob_stolen', status: 'leased' }), prior_status: 'leased' },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createProbeJobRepository(pool);
    const jobs = await repo.leasePendingJobsForWorker(CTX, WORKER_ID, { leasedAt: FIXED_NOW });
    assert.equal(jobs.length, 2);
    assert.equal(metricsSnapshot().probe_job_leases_reclaimed_total - before, 1);
  });

  it('derives a lease TTL that outlives one bounded worker cycle', () => {
    // A check may legally declare max_duration_seconds as low as 1; the floor still exceeds
    // the worker's 110-second whole-cycle deadline and leaves restart/clock-skew allowance.
    assert.equal(probeJobLeaseTtlSeconds({ max_duration_seconds: 1 }), 180);
    // Malformed or absent constraints fall back rather than deriving something tiny.
    assert.equal(probeJobLeaseTtlSeconds({}), probeJobLeaseTtlSeconds({ max_duration_seconds: 120 }));
    assert.equal(
      probeJobLeaseTtlSeconds({ max_duration_seconds: 'nonsense' }),
      probeJobLeaseTtlSeconds({}),
    );
    assert.equal(probeJobLeaseTtlSeconds({ max_duration_seconds: 120 }), 180);
  });

  it('keeps the JS lease-TTL mirror in step with the SQL predicate at the edges', () => {
    // These two must agree, or the lease query could reclaim a job while the ingest guard
    // still believed the old lease live — rejecting the new holder and re-wedging the slot.
    // '0' is accepted by the SQL regex and so must NOT fall back to the default here.
    assert.equal(probeJobLeaseTtlSeconds({ max_duration_seconds: 0 }), 180);
    // Values the SQL regex rejects must fall back on BOTH sides. Number() coercion disagrees
    // with the regex on every one of these, which is the whole reason this test exists.
    const fallback = probeJobLeaseTtlSeconds({ max_duration_seconds: 120 });
    assert.equal(probeJobLeaseTtlSeconds({ max_duration_seconds: -5 }), fallback);
    assert.equal(probeJobLeaseTtlSeconds({ max_duration_seconds: '' }), fallback);
    assert.equal(probeJobLeaseTtlSeconds({ max_duration_seconds: ' 5 ' }), fallback);
    assert.equal(probeJobLeaseTtlSeconds({ max_duration_seconds: '1e3' }), fallback);
    assert.equal(probeJobLeaseTtlSeconds(null), fallback);
    // Fractional values are accepted by the regex and honoured on both sides.
    assert.equal(
      probeJobLeaseTtlSeconds({ max_duration_seconds: 30.5 }),
      Math.max(180, 30.5 + 60),
    );
  });

  it('treats a lease as stale only past TTL, and never on missing evidence', () => {
    const leasedAt = '2026-06-01T12:00:00.000Z';
    const constraints = { max_duration_seconds: 120 };
    const ttlMs = probeJobLeaseTtlSeconds(constraints) * 1000;
    const leased = { status: 'leased', leased_at: leasedAt, constraints };

    // Within TTL: a live worker still owns this job.
    assert.equal(isProbeJobLeaseStale(leased, new Date(Date.parse(leasedAt) + ttlMs - 1000)), false);
    // Past TTL: holder is presumed gone.
    assert.equal(isProbeJobLeaseStale(leased, new Date(Date.parse(leasedAt) + ttlMs + 1000)), true);
    // Fail closed — absent or unparseable evidence never authorizes a steal.
    assert.equal(
      isProbeJobLeaseStale({ status: 'leased', leased_at: null, constraints }, new Date()),
      false,
    );
    assert.equal(
      isProbeJobLeaseStale({ status: 'leased', leased_at: 'not-a-date', constraints }, new Date()),
      false,
    );
    // Non-leased statuses are never "stale".
    assert.equal(isProbeJobLeaseStale({ status: 'pending', leased_at: leasedAt }, new Date()), false);
    assert.equal(
      isProbeJobLeaseStale({ status: 'completed', leased_at: leasedAt }, new Date()),
      false,
    );
  });

  it('looks up and updates jobs with parameterized tenant-scoped SQL', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (sql.includes('FROM probe_jobs') && sql.includes('WHERE tenant_id = $1 AND id = $2')) {
        return { rows: [sampleRow()] };
      }
      if (sql.includes("status = 'leased'") && sql.includes("status = 'pending'")) {
        assert.deepEqual(params.slice(0, 4), [CTX.tenantId, 'pjob_1', WORKER_ID, FIXED_NOW]);
        assert.match(sql, /constraints_json \? 'ownership_binding'/);
        assert.match(sql, /FROM target_verification_current tvc/);
        assert.match(sql, /FROM tenant_connector_features feature/);
        assert.match(sql, /feature\.enabled = TRUE/);
        assert.match(sql, /feature\.revision =/);
        assert.match(sql, /connector\.secret_id =/);
        assert.match(sql, /connector\.last_success_revision =/);
        assert.match(sql, /connector\.last_success_at =/);
        assert.match(sql, /snapshot\.id =/);
        assert.match(sql, /snapshot\.resource_ref_hash =/);
        assert.match(sql, /snapshot\.poll_revision = connector\.last_success_revision/);
        assert.match(sql, /snapshot\.observed_at = connector\.last_success_at/);
        return { rows: [sampleRow({ status: 'leased' })] };
      }
      if (sql.includes("status = 'completed'")) {
        assert.deepEqual(params, [CTX.tenantId, 'pjob_1', FIXED_NOW, WORKER_ID, FIXED_NOW]);
        return { rows: [sampleRow({ status: 'completed' })] };
      }
      return { rows: [] };
    });
    const repo = createProbeJobRepository(pool);
    const found = await repo.getJobById(CTX, 'pjob_1');
    assert.equal(found.id, 'pjob_1');
    const claimed = await repo.claimPendingJobForWorker(CTX, 'pjob_1', WORKER_ID, FIXED_NOW);
    assert.equal(claimed.status, 'leased');
    const completed = await repo.markJobCompleted(CTX, 'pjob_1', FIXED_NOW, {
      workerId: WORKER_ID,
      leasedAt: FIXED_NOW,
    });
    assert.equal(completed.status, 'completed');
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('cancelOpenProbeJobsForTestRuns returns empty without querying when run list is empty', async () => {
    const pool = createRecordingPool(() => ({ rows: [] }));
    const repo = createProbeJobRepository(pool);
    const jobs = await repo.cancelOpenProbeJobsForTestRuns(CTX, [], FIXED_NOW);
    assert.deepEqual(jobs, []);
    assert.equal(dataQueries(pool.client).length, 0);
  });

  it('cancelOpenProbeJobsForTestRuns cancels pending and leased jobs for run IDs with tenant-scoped SQL', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (sql.includes("status = 'cancelled'") && sql.includes('ANY($2::text[])')) {
        assert.deepEqual(params, [CTX.tenantId, ['run_1', 'run_2'], FIXED_NOW]);
        assert.match(sql, /tenant_id = \$1/);
        assert.match(sql, /status IN \('pending', 'leased'\)/);
        assert.ok(!sql.includes('ten_demo'));
        return {
          rows: [
            sampleRow({ id: 'pjob_a', status: 'cancelled', test_run_id: 'run_1' }),
            sampleRow({ id: 'pjob_b', status: 'cancelled', test_run_id: 'run_2' }),
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createProbeJobRepository(pool);
    const jobs = await repo.cancelOpenProbeJobsForTestRuns(CTX, ['run_1', 'run_2'], FIXED_NOW);
    assert.equal(jobs.length, 2);
    assert.equal(jobs[0].status, 'cancelled');
    assert.equal(jobs[0].id, 'pjob_a');
    assertTenantWrapped(pool.client, CTX.tenantId);
  });


  it('finds at most one durable probe job for a tenant-scoped test run', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (sql.includes('WHERE tenant_id = $1 AND test_run_id = $2')) {
        assert.deepEqual(params, [CTX.tenantId, 'run_1']);
        assert.match(sql, /LIMIT 2/);
        return { rows: [sampleRow()] };
      }
      return { rows: [] };
    });
    const repo = createProbeJobRepository(pool);
    const job = await repo.getProbeJobByTestRun(CTX, 'run_1');
    assert.equal(job.id, 'pjob_1');
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('serializes create by tenant/run and reuses a previously committed probe job', async () => {
    let insertCalls = 0;
    const pool = createRecordingPool((sql, params) => {
      if (sql.includes('pg_advisory_xact_lock')) {
        assert.equal(params[0], JSON.stringify([CTX.tenantId, 'run_1']));
        return { rows: [{}] };
      }
      if (sql.includes('WHERE tenant_id = $1 AND test_run_id = $2')) {
        return { rows: [sampleRow()] };
      }
      if (sql.includes('INSERT INTO probe_jobs')) insertCalls += 1;
      return { rows: [] };
    });
    const repo = createProbeJobRepository(pool);
    const job = await repo.createProbeJob(CTX, {
      id: 'pjob_retry_candidate',
      test_run_id: 'run_1',
      target_id: 'tgt_1',
      check_id: 'origin.direct_bypass.safe',
      nonce_hash: 'different_retry_nonce',
      nonce: 'different-retry-nonce',
      created_at: FIXED_NOW,
    });
    assert.equal(job.id, 'pjob_1');
    assert.equal(job.nonce_hash, 'nh_abc');
    assert.equal(insertCalls, 0);
    assertTenantWrapped(pool.client, CTX.tenantId);
  });
  it('createProbeJob inserts tenant-scoped row with nonce and signature columns', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (sql.includes('INSERT INTO probe_jobs')) {
        assert.deepEqual(params[0], 'pjob_new');
        assert.equal(params[1], CTX.tenantId);
        assert.equal(params[8], 'nonce_plain');
        return { rows: [sampleRow({ id: 'pjob_new' })] };
      }
      return { rows: [] };
    });
    const repo = createProbeJobRepository(pool);
    const job = await repo.createProbeJob(CTX, {
      id: 'pjob_new',
      test_run_id: 'run_1',
      target_id: 'tgt_1',
      check_id: 'origin.direct_bypass.safe',
      nonce_hash: 'nh_abc',
      nonce: 'nonce_plain',
      job_signature: 'sig_hex',
      created_at: FIXED_NOW,
    });
    assert.equal(job.id, 'pjob_new');
    assertTenantWrapped(pool.client, CTX.tenantId);
    const insert = dataQueries(pool.client).find((q) => q.text.includes('INSERT INTO probe_jobs'));
    assert.ok(insert);
    assert.ok(!insert.text.includes('ten_demo'));
  });
});