import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createPortalRevampRepository } from '../../src/persistence/postgres/portalRevampRepository.mjs';
import { getTargetDetail as getDevTargetDetail } from '../../src/services/targetDetail.mjs';
import { resetStoreForTests } from '../../src/store.mjs';
import { resolvePostgresHarnessAvailability, withEphemeralPostgres } from '../helpers/pg-harness.mjs';

const TENANT = 'ten_target_detail_query';
const GROUP_ID = 'tg_target_detail_query';
const TARGET_ID = 'tgt_target_detail_query';
const CTX = { tenantId: TENANT, userId: 'target-detail-query-test', role: 'viewer' };
const RUN_COUNT = 120;

function runId(index) {
  return `run_td_query_${String(index).padStart(3, '0')}`;
}

async function seed(pool) {
  await pool.query('INSERT INTO tenants (id, name) VALUES ($1, $1)', [TENANT]);
  await pool.query("INSERT INTO environments (id, tenant_id, name) VALUES ('env_target_detail_query', $1, 'prod')", [TENANT]);
  await pool.query(
    `INSERT INTO target_groups (id, tenant_id, environment_id, name)
     VALUES ($1, $2, 'env_target_detail_query', 'Target detail')`,
    [GROUP_ID, TENANT],
  );
  await pool.query(
    `INSERT INTO targets (id, tenant_id, target_group_id, kind, value, normalized_value)
     VALUES ($1, $2, $3, 'fqdn', 'detail.example.test', 'detail.example.test')`,
    [TARGET_ID, TENANT, GROUP_ID],
  );
  await pool.query(
    `INSERT INTO test_runs (
       id, tenant_id, target_group_id, target_id, check_id, status, started_at, completed_at, created_at
     )
     SELECT
       'run_td_query_' || lpad(n::text, 3, '0'),
       $1,
       $2,
       $3,
       'origin.direct_bypass.safe',
       'completed',
       '2026-01-01T00:00:00.000Z'::timestamptz + n * interval '1 minute',
       '2026-01-01T00:00:30.000Z'::timestamptz + n * interval '1 minute',
       '2026-01-01T00:00:00.000Z'::timestamptz + n * interval '1 minute'
     FROM generate_series(1, $4::int) AS n`,
    [TENANT, GROUP_ID, TARGET_ID, RUN_COUNT],
  );
  await pool.query(
    `INSERT INTO findings (
       id, tenant_id, target_group_id, target_id, test_run_id, check_id,
       title, severity, status, created_at, updated_at
     ) VALUES (
       'fnd_td_query', $1, $2, $3, $4, 'origin.direct_bypass.safe',
       'Canonical status finding', 'high', 'open',
       '2026-01-02T00:00:00.000Z', '2026-01-02T00:00:00.000Z'
     )`,
    [TENANT, GROUP_ID, TARGET_ID, runId(RUN_COUNT)],
  );
}

function buildDevStore() {
  const runs = Array.from({ length: RUN_COUNT }, (_, offset) => {
    const index = offset + 1;
    const startedAt = new Date(Date.UTC(2026, 0, 1, 0, index)).toISOString();
    return {
      id: runId(index),
      tenant_id: TENANT,
      target_group_id: GROUP_ID,
      target_id: TARGET_ID,
      check_id: 'origin.direct_bypass.safe',
      status: 'completed',
      started_at: startedAt,
      completed_at: new Date(new Date(startedAt).getTime() + 30_000).toISOString(),
      created_at: startedAt,
    };
  });
  return {
    tenants: [{ id: TENANT, name: TENANT }],
    environments: [{ id: 'env_target_detail_query', tenant_id: TENANT, name: 'prod' }],
    targetGroups: [{ id: GROUP_ID, tenant_id: TENANT, environment_id: 'env_target_detail_query', name: 'Target detail' }],
    targets: [{ id: TARGET_ID, tenant_id: TENANT, target_group_id: GROUP_ID, kind: 'fqdn', value: 'detail.example.test', created_at: '2026-01-01T00:00:00.000Z' }],
    targetVerifications: [],
    agents: [],
    testRuns: runs,
    verdicts: [],
    findings: [{
      id: 'fnd_td_query',
      tenant_id: TENANT,
      target_group_id: GROUP_ID,
      target_id: TARGET_ID,
      test_run_id: runId(RUN_COUNT),
      check_id: 'origin.direct_bypass.safe',
      title: 'Canonical status finding',
      severity: 'high',
      status: 'open',
      created_at: '2026-01-02T00:00:00.000Z',
      updated_at: '2026-01-02T00:00:00.000Z',
    }],
    testPolicies: [],
    wafAssets: [],
    wafPostureSnapshots: [],
    wafValidationRuns: [],
    wafFingerprints: [],
    wafConnectors: [],
    targetEdgeDetections: [],
    loaSignatures: [],
  };
}

function assertLimits(read) {
  return Promise.all([
    read({}).then((payload) => assert.equal(payload.runs_recent.length, 5)),
    read({ runs_limit: 'not-a-number' }).then((payload) => assert.equal(payload.runs_recent.length, 5)),
    read({ runs_limit: '-1' }).then((payload) => assert.equal(payload.runs_recent.length, 1)),
    read({ runs_limit: '9999' }).then((payload) => assert.equal(payload.runs_recent.length, 100)),
  ]);
}

describe('postgres target-detail query parity', () => {
  it('bounds runs_limit and matches dev-json finding projection', { timeout: 120_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    await withEphemeralPostgres(async (pool) => {
      await seed(pool);
      const repository = createPortalRevampRepository(pool);
      await assertLimits((query) => repository.getTargetDetailBundle(CTX, TARGET_ID, query));

      const postgresPayload = await repository.getTargetDetailBundle(CTX, TARGET_ID, { findings_limit: 1 });
      assert.deepEqual(postgresPayload.findings[0], {
        id: 'fnd_td_query',
        severity: 'high',
        title: 'Canonical status finding',
        state: 'open',
        opened_at: '2026-01-02T00:00:00.000Z',
        owner_group: 'edge-sre',
      });
      assert.deepEqual(postgresPayload.counts, {
        runs_total: RUN_COUNT,
        findings_open: 1,
        findings_closed: 0,
      });

      resetStoreForTests(buildDevStore());
      await assertLimits(async (query) => getDevTargetDetail(CTX, TARGET_ID, query));
      const devPayload = getDevTargetDetail(CTX, TARGET_ID, { findings_limit: 1 });
      assert.deepEqual(devPayload.findings[0], postgresPayload.findings[0]);
      assert.deepEqual(devPayload.counts, postgresPayload.counts);
    }, availability.env ?? process.env);
  });
});
