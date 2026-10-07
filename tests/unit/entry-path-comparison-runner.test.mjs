// Postgres comparison background work: runner tick wiring, tick isolation, and the runner-only runtime config.
import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import { loadEntryPathComparisonRunnerConfig } from '../../src/config.mjs';

it('passes the same comparison gate and source registry to the hosted API and runner', () => {
  const compose = readFileSync(new URL('../../ops/aws/docker-compose.yml', import.meta.url), 'utf8');
  for (const service of ['control-plane', 'test-policy-runner']) {
    const block = compose.split(`\n  ${service}:`)[1]?.split(/\n  [a-z][a-z-]*:/)[0];
    assert.ok(block, service);
    for (const name of ['ASTRANULL_PROTECTION_VALIDATION_ENABLED', 'ASTRANULL_PROTECTION_VALIDATION_ENABLED_TENANTS', 'ASTRANULL_APPROVED_PROBE_SOURCES']) {
      assert.ok(block.includes(`${name}: \${${name}:-}`), `${service}: ${name}`);
    }
  }
});
import { entryPathComparisonRuntimeConfigFromEnv } from '../../src/persistence/postgres/runtime.mjs';
import {
  ENTRY_PATH_COMPARISON_BACKEND_METHODS,
  createEntryPathComparisonService,
} from '../../src/services/entryPathComparisons.mjs';
import {
  advanceEntryPathComparisonsForTenant,
  runPostgresValidationScans,
} from '../../scripts/validation-scan-runner.mjs';

const RUNTIME_CONFIG = { probeMode: 'signed-worker', probeWorkerSecret: 'configured-secret' };

function fakeBackend(overrides = {}) {
  const backend = Object.fromEntries(ENTRY_PATH_COMPARISON_BACKEND_METHODS.map((name) => [name, async () => null]));
  return { ...backend, ...overrides };
}

describe('advanceDueEntryPathComparisons tick isolation', () => {
  it('records a failing comparison and still advances the next due comparison', async () => {
    const reads = [];
    const service = createEntryPathComparisonService({
      async: true,
      backend: fakeBackend({
        listDue: async () => [{ id: 'epc_poisoned', tenant_id: 'ten_r' }, { id: 'epc_next', tenant_id: 'ten_r' }],
        get: async (_tenantId, id) => {
          reads.push(id);
          if (id === 'epc_poisoned') throw new Error('new row violates check constraint "entry_path_comparison_items_bounds"');
          return { id, tenant_id: 'ten_r', status: 'completed' };
        },
      }),
    });
    const results = await service.advanceDueEntryPathComparisons({ tenantId: 'ten_r' }, {});
    assert.deepEqual(reads, ['epc_poisoned', 'epc_next']);
    assert.deepEqual(results.map((row) => [row.id, row.reason]), [['epc_poisoned', 'advance_failed'], ['epc_next', 'inactive']]);
  });
});

describe('Postgres runner tick for entry-path comparisons', () => {
  it('advances due comparisons per tenant with the gate set to pause, never cancel', async () => {
    const calls = [];
    const runtime = async () => ({
      services: {
        validationScans: {
          async listDueValidationScans() { return []; },
          async listRunnableScans() { return []; },
          async dispatchDueValidationScans() { return []; },
          async advanceScan() { return null; },
        },
        entryPathComparisons: {
          async advanceDueEntryPathComparisons(ctx, options) {
            calls.push({ tenantId: ctx.tenantId, options });
            return [{ id: `epc_${ctx.tenantId}`, advanced: true, status: 'running', waiting: true }];
          },
        },
      },
      async close() {},
    });
    const tenants = await runPostgresValidationScans({
      env: {}, tenantIds: ['ten_a', 'ten_b'], dryRun: false, limit: 7, workerId: 'runner-1', runtimeConfig: RUNTIME_CONFIG, createPostgresRuntimeFn: runtime,
    });
    assert.deepEqual(calls.map((call) => call.tenantId), ['ten_a', 'ten_b']);
    assert.deepEqual(calls[0].options, { limit: 7, pauseWhenGateOff: true });
    assert.deepEqual(tenants[0].comparisons, {
      due_count: 1,
      advanced: [{ comparison_id: 'epc_ten_a', advanced: true, status: 'running', waiting: true }],
    });
  });

  it('reports a failed comparison tick without hiding the scan results', async () => {
    const summary = await advanceEntryPathComparisonsForTenant({
      async advanceDueEntryPathComparisons() { throw Object.assign(new Error('db down'), { code: 'ECONNREFUSED' }); },
    }, { tenantId: 'ten_a' }, 5);
    assert.deepEqual(summary, { due_count: 0, advanced: [], error: 'ECONNREFUSED' });
    assert.equal(await advanceEntryPathComparisonsForTenant(undefined, { tenantId: 'ten_a' }, 5), null);
  });
});

describe('runner runtime config for comparisons', () => {
  const secret = randomBytes(32).toString('base64url');
  const runnerEnv = {
    NODE_ENV: 'production',
    ASTRANULL_PERSISTENCE_MODE: 'postgres',
    ASTRANULL_PROBE_MODE: 'signed-worker',
    ASTRANULL_PROBE_WORKER_SECRET: secret,
  };

  it('falls back to probe dispatch plus PV flags when the API auth env is absent', () => {
    const config = entryPathComparisonRuntimeConfigFromEnv({ ...runnerEnv, ASTRANULL_PROTECTION_VALIDATION_ENABLED_TENANTS: '{"ten_a":1}' });
    assert.equal(config.probeMode, 'signed-worker');
    assert.deepEqual(config.featureFlags.protectionValidationEnabledTenants, { ten_a: true });
  });

  it('keeps an explicit global off switch', () => {
    const config = loadEntryPathComparisonRunnerConfig({ ...runnerEnv, ASTRANULL_PROTECTION_VALIDATION_ENABLED: '0' });
    assert.equal(config.featureFlags.protectionValidationEnabled, false);
  });
});
