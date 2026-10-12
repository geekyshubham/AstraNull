import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';
import {
  POSTGRES_WAF_COVERAGE_ROLLUP_SERVICE_METHODS,
  WAF_COVERAGE_ROLLUP_REPOSITORY_METHODS,
  createPostgresWafCoverageRollupServices,
} from '../../src/persistence/postgres/wafCoverageRollupServiceAdapters.mjs';

import { assuredPosture } from '../helpers/assurance-fixtures.mjs';
const envSnapshot = { ...process.env };
const CTX = { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' };

function restoreEnv() {
  for (const key of Object.keys(process.env)) {
    if (!(key in envSnapshot)) delete process.env[key];
  }
  Object.assign(process.env, envSnapshot);
}

function wafEnabledEnv() {
  return {
    ...process.env,
    ASTRANULL_WAF_POSTURE_ENABLED: '1',
  };
}

afterEach(() => {
  restoreEnv();
});

function createRepositories(overrides = {}) {
  const wafPosture = {};
  for (const method of WAF_COVERAGE_ROLLUP_REPOSITORY_METHODS) {
    wafPosture[method] = async () => [];
  }
  return {
    wafPosture: { ...wafPosture, ...overrides.wafPosture },
  };
}

describe('postgres WAF coverage rollup service adapters', () => {
  it('exposes stable repository and service method lists', () => {
    assert.deepEqual(WAF_COVERAGE_ROLLUP_REPOSITORY_METHODS, [
      'listWafAssets',
      'listCurrentPostureSnapshots',
      'upsertWafCoverageDailyRollup',

    ]);
    assert.deepEqual(POSTGRES_WAF_COVERAGE_ROLLUP_SERVICE_METHODS, [
      'runCoverageRollup',
      'runScheduledCoverageRollups',
    ]);
  });

  it('requires repository methods before wiring services', () => {
    assert.throws(
      () => createPostgresWafCoverageRollupServices({}),
      /requires repositories\.wafPosture/,
    );
    assert.throws(
      () => createPostgresWafCoverageRollupServices({
        wafPosture: { listWafAssets: async () => [] },
      }),
      /requires wafPosture\.listCurrentPostureSnapshots/,
    );
  });

  it('runs tenant rollup from current snapshots', async () => {
    Object.assign(process.env, wafEnabledEnv());
    const repositories = createRepositories({
      wafPosture: {
        listWafAssets: async () => [
          { id: 'waf_1', canonical_url: 'https://waf1.example.test', tenant_id: CTX.tenantId, created_at: '2026-07-01T00:00:00Z' },
          { id: 'waf_2', canonical_url: 'https://waf2.example.test', tenant_id: CTX.tenantId, created_at: '2026-07-01T00:00:00Z' },
          { id: 'waf_3', canonical_url: 'https://waf3.example.test', tenant_id: CTX.tenantId, created_at: '2026-07-01T00:00:00Z' },
        ],
        listCurrentPostureSnapshots: async () => [
          assuredPosture({ id: 'waf_1', canonical_url: 'https://waf1.example.test', tenant_id: CTX.tenantId }, 'protected', '2026-07-02T10:00:00Z'),
          assuredPosture({ id: 'waf_2', canonical_url: 'https://waf2.example.test', tenant_id: CTX.tenantId }, 'unprotected', '2026-07-02T10:00:00Z'),
          assuredPosture({ id: 'waf_3', canonical_url: 'https://waf3.example.test', tenant_id: CTX.tenantId }, 'edge_protected', '2026-07-02T10:00:00Z'),
        ],
        upsertWafCoverageDailyRollup: async (_ctx, record) => ({
          ...record,
          tenant_id: CTX.tenantId,
        }),
      },
    });
    const services = createPostgresWafCoverageRollupServices(repositories);
    const outcome = await services.runCoverageRollup({
      ...CTX,
      rollupDate: '2026-07-02', now: new Date('2026-07-02T12:00:00Z'),
    });
    assert.equal(outcome.rollup_result.total_assets, 3);
    assert.equal(outcome.rollup_result.protected, 1);
    assert.equal(outcome.rollup_result.edge_protected, 1);
    assert.equal(outcome.rollup_result.unprotected, 1);
    assert.equal(outcome.rollup_result.coverage_ratio, 0.3333);
  });
});
it('requires historical inputs for backdated dry-run and write alike; never counts errors as success', async () => {
  Object.assign(process.env, wafEnabledEnv()); const services = createPostgresWafCoverageRollupServices(createRepositories());
  for (const dryRun of [true,false]) {
    const result = await services.runCoverageRollup({ ...CTX, dryRun, now: new Date('2026-07-03T00:00:00Z'), rollupDate: '2026-07-02' }); assert.equal(result.error, 'historical_inputs_unavailable');
    for (const rollupDate of ['2026-07-04', '2026-02-30']) assert.equal((await services.runCoverageRollup({ ...CTX, dryRun, now: new Date('2026-07-03T00:00:00Z'), rollupDate })).status, 400);
  }
  const scheduled = await services.runScheduledCoverageRollups({ tenantIds: [CTX.tenantId], now: new Date('2026-07-03T00:00:00Z'), rollupDate: '2026-07-02' }); assert.equal(scheduled.error, 'historical_inputs_unavailable'); assert.equal(scheduled.tenants_processed, undefined);
});
it('reconstructs backdated PG coverage exactly as the pure event-time cohort projection', async () => {
  Object.assign(process.env, wafEnabledEnv()); const asset = { id: 'a', canonical_url: 'https://a.example.test', tenant_id: CTX.tenantId, created_at: '2026-07-01T00:00:00Z' }; const future = assuredPosture(asset, 'protected', '2026-07-03T00:00:00Z');
  const services = createPostgresWafCoverageRollupServices(createRepositories({ wafPosture: { listWafAssets: async () => [asset], listWafPostureSnapshotsForTenant: async () => [future], upsertWafCoverageDailyRollup: async (_,row) => row } }));
  const result = await services.runCoverageRollup({ ...CTX, now: new Date('2026-07-03T12:00:00Z'), rollupDate: '2026-07-02' }); assert.equal(result.rollup_result.protected, 0); assert.equal(result.rollup_result.unknown, 1); assert.equal(result.rollup_result.total_assets, 1); assert.equal(result.rollup_result.cutoff_at, '2026-07-02T23:59:59.999Z'); assert.equal(result.rollup_result.semantics_version, 'waf-coverage-history.v2');
});
