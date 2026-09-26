import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { describe, it } from 'node:test';
import {
  buildValidationScanRunnerSummary,
  loadValidationScanRuntimeConfig,
  parseValidationScanRunnerArgs,
  parseValidationScanTenantIds,
  resolveValidationScanRunnerConfig,
  resolveValidationScanRunnerIntervalSeconds,
  runPostgresValidationScans,
  runValidationScanRunner,
  summarizeScanAdvance,
  summarizeScanDispatch,
} from '../../scripts/validation-scan-runner.mjs';

const RUNTIME_CONFIG = { probeMode: 'signed-worker', probeWorkerSecret: 'configured-secret' };

function fakeRuntime(overrides = {}, recorder = {}) {
  return async (_env, options) => {
    recorder.options = options;
    recorder.closed = (recorder.closed ?? 0);
    return {
      services: {
        validationScans: {
          async listDueValidationScans() { return []; },
          async listRunnableScans() { return []; },
          async dispatchDueValidationScans() { return []; },
          async advanceScan() { return null; },
          ...overrides,
        },
      },
      async close() { recorder.closed += 1; },
    };
  };
}

describe('validation scan runner: signed-worker secret validation', () => {
  it('rejects weak worker secrets and accepts generated material', () => {
    assert.throws(
      () => loadValidationScanRuntimeConfig({
        NODE_ENV: 'test',
        ASTRANULL_PROBE_MODE: 'signed-worker',
        ASTRANULL_PROBE_WORKER_SECRET: 'q'.repeat(48),
      }),
      /hmac_secret_low_entropy/,
    );
    const generated = randomBytes(32).toString('base64url');
    assert.equal(loadValidationScanRuntimeConfig({
      NODE_ENV: 'test',
      ASTRANULL_PROBE_MODE: 'signed-worker',
      ASTRANULL_PROBE_WORKER_SECRET: generated,
    }).probeWorkerSecret, generated);
  });
});

describe('validation scan operator runner', () => {
  it('parses bounded arguments and tenant files', () => {
    assert.deepEqual(
      parseValidationScanRunnerArgs([
        'node', 'runner', '--tenant-id', 'ten_a', '--dry-run', '--limit', '4', '--out', 'result.json',
      ]),
      { tenantId: 'ten_a', tenantIdsFile: null, dryRun: true, limit: 4, out: 'result.json', help: false },
    );
    assert.deepEqual(parseValidationScanTenantIds({ tenant_ids: [' ten_a ', 'ten_a', 'ten_b'] }), ['ten_a', 'ten_b']);
    assert.deepEqual(parseValidationScanTenantIds('["ten_a"]'), ['ten_a']);
    assert.throws(() => parseValidationScanRunnerArgs(['node', 'runner', '--limit', '101']), /between 1 and 100/);
    assert.throws(() => parseValidationScanRunnerArgs(['node', 'runner', '--bogus']), /unknown argument/);
    assert.throws(() => parseValidationScanRunnerArgs(['node', 'runner', '--tenant-id']), /requires a value/);
    assert.throws(() => parseValidationScanTenantIds([]), /must not be empty/);
    assert.throws(() => parseValidationScanTenantIds({ nope: true }), /JSON array/);
  });

  it('fails closed without database, explicit tenant scope, or signed-worker mode', () => {
    const parsed = parseValidationScanRunnerArgs(['node', 'runner', '--tenant-id', 'ten_a']);
    assert.match(resolveValidationScanRunnerConfig({}, parsed).message, /DATABASE_URL/);
    assert.match(
      resolveValidationScanRunnerConfig(
        { ASTRANULL_DATABASE_URL: 'postgres://configured' },
        parseValidationScanRunnerArgs(['node', 'runner']),
      ).message,
      /explicit tenant scope/,
    );
    assert.match(
      resolveValidationScanRunnerConfig(
        { ASTRANULL_DATABASE_URL: 'postgres://configured' },
        parseValidationScanRunnerArgs(['node', 'runner', '--tenant-id', 'ten_a', '--tenant-ids-file', 'ids.json']),
      ).message,
      /exactly one source/,
    );
    assert.match(
      resolveValidationScanRunnerConfig(
        { ASTRANULL_DATABASE_URL: 'postgres://configured' },
        parsed,
        { loadRuntimeConfigFn: () => ({ probeMode: 'simulation' }) },
      ).message,
      /signed-worker mode is required/,
    );
    assert.match(
      resolveValidationScanRunnerConfig(
        { ASTRANULL_DATABASE_URL: 'postgres://configured' },
        parseValidationScanRunnerArgs(['node', 'runner', '--tenant-ids-file', 'ids.json']),
        { readTenantIdsFile: () => '[]', loadRuntimeConfigFn: () => RUNTIME_CONFIG },
      ).message,
      /must not be empty/,
    );
  });

  it('resolves a sanitized worker id, bounded interval, and redacts database URLs', () => {
    const parsed = parseValidationScanRunnerArgs(['node', 'runner', '--tenant-id', 'ten_a']);
    const env = {
      ASTRANULL_DATABASE_URL: 'postgres://user:secret@db.internal/astranull',
      ASTRANULL_VALIDATION_SCAN_RUNNER_ID: 'scan-runner-1',
      ASTRANULL_VALIDATION_SCAN_INTERVAL_SECONDS: '30',
    };
    const ok = resolveValidationScanRunnerConfig(env, parsed, { loadRuntimeConfigFn: () => RUNTIME_CONFIG });
    assert.equal(ok.ok, true);
    assert.deepEqual(ok.tenantIds, ['ten_a']);
    assert.equal(ok.workerId, 'scan-runner-1');
    assert.equal(ok.schedulerIntervalSeconds, 30);
    assert.equal(ok.runtimeConfig, RUNTIME_CONFIG);

    const badWorker = resolveValidationScanRunnerConfig(
      { ...env, ASTRANULL_VALIDATION_SCAN_RUNNER_ID: 'bad worker id!' },
      parsed,
      { loadRuntimeConfigFn: () => RUNTIME_CONFIG },
    );
    assert.match(badWorker.message, /RUNNER_ID is invalid/);

    const failed = resolveValidationScanRunnerConfig(env, parsed, {
      loadRuntimeConfigFn: () => {
        throw new Error(`could not connect to ${env.ASTRANULL_DATABASE_URL}`);
      },
    });
    assert.equal(failed.ok, false);
    assert.equal(failed.message.includes('user:secret'), false);

    assert.equal(resolveValidationScanRunnerIntervalSeconds({}), 60);
    for (const value of ['', '0', '4', '61', '1.5', 'nope']) {
      assert.throws(
        () => resolveValidationScanRunnerIntervalSeconds({ ASTRANULL_VALIDATION_SCAN_INTERVAL_SECONDS: value }),
        /integer between 5 and 60/,
        value,
      );
    }
  });

  it('dry-runs each explicit tenant without dispatching and always closes the runtime', async () => {
    const calls = [];
    const recorder = {};
    const createPostgresRuntimeFn = fakeRuntime({
      async listDueValidationScans(ctx, query) {
        calls.push({ method: 'due', ctx, query });
        return [{ id: `scan_${ctx.tenantId}`, scheduled_for: '2026-06-01T12:00:00.000Z', name: 'must-not-leak' }];
      },
      async listRunnableScans(ctx) {
        calls.push({ method: 'runnable', ctx });
        return [{ id: `scan_run_${ctx.tenantId}`, status: 'running', next_eligible_at: null, target_value: 'must-not-leak' }];
      },
      async dispatchDueValidationScans() { throw new Error('dry-run must not dispatch'); },
      async advanceScan() { throw new Error('dry-run must not advance'); },
    }, recorder);

    const tenants = await runPostgresValidationScans({
      env: {}, tenantIds: ['ten_a', 'ten_b'], dryRun: true, limit: 3,
      workerId: 'scan-runner-1', runtimeConfig: RUNTIME_CONFIG, createPostgresRuntimeFn,
    });

    assert.equal(recorder.closed, 1);
    assert.deepEqual(recorder.options, {
      autoMigrate: false,
      wafPostureServiceOptions: { connectorEncryptionKey: null },
      validationScanRuntimeConfig: RUNTIME_CONFIG,
    });
    assert.deepEqual(calls.filter((call) => call.method === 'due').map((call) => call.ctx.tenantId), ['ten_a', 'ten_b']);
    assert.deepEqual(tenants[0].due, [{ scan_id: 'scan_ten_a', scheduled_for: '2026-06-01T12:00:00.000Z' }]);
    assert.deepEqual(tenants[0].runnable, [{ scan_id: 'scan_run_ten_a', status: 'running', next_eligible_at: null }]);
    assert.equal(JSON.stringify(tenants).includes('must-not-leak'), false);
  });

  it('dispatches due scans, advances runnable scans, and emits metadata-only results', async () => {
    const calls = [];
    const recorder = {};
    const createPostgresRuntimeFn = fakeRuntime({
      async dispatchDueValidationScans(ctx, options) {
        calls.push({ method: 'dispatch', ctx, options });
        return [
          { scan_id: 'scan_1', dispatched: true, advanced: { scan_id: 'scan_1', acquired: true, waiting: true, status: 'running' } },
          { scan_id: 'scan_2', dispatched: false, denied: 'kill_switch_active' },
        ];
      },
      async listRunnableScans(ctx, options) {
        calls.push({ method: 'runnable', ctx, options });
        return [{ id: 'scan_3', status: 'running', target_value: 'must-not-leak' }];
      },
      async advanceScan(ctx, id, options) {
        calls.push({ method: 'advance', ctx, id, options });
        return { scan_id: id, acquired: true, waiting: false, status: 'completed', target_value: 'must-not-leak' };
      },
    }, recorder);

    const tenants = await runPostgresValidationScans({
      env: {}, tenantIds: ['ten_a'], dryRun: false, limit: 7,
      workerId: 'scan-runner-1', runtimeConfig: RUNTIME_CONFIG, createPostgresRuntimeFn,
    });

    assert.equal(recorder.closed, 1);
    assert.deepEqual(calls.map((call) => call.method), ['dispatch', 'runnable', 'advance']);
    assert.deepEqual(calls[0].options, { workerId: 'scan-runner-1', limit: 7, runtimeConfig: RUNTIME_CONFIG });
    assert.equal(calls[0].ctx.role, 'system');
    assert.deepEqual(calls[2].options, { runtimeConfig: RUNTIME_CONFIG });
    assert.deepEqual(tenants, [{
      tenant_id: 'ten_a',
      due_count: 2,
      runnable_count: 1,
      dispatched: [
        { scan_id: 'scan_1', dispatched: true, advanced: { scan_id: 'scan_1', acquired: true, waiting: true, status: 'running' } },
        { scan_id: 'scan_2', dispatched: false, denied: 'kill_switch_active' },
      ],
      advanced: [{ scan_id: 'scan_3', acquired: true, waiting: false, status: 'completed' }],
    }]);
    assert.equal(JSON.stringify(tenants).includes('must-not-leak'), false);
  });

  it('records tenant failures without serializing thrown details', async () => {
    const recorder = {};
    const tenants = await runPostgresValidationScans({
      env: { ASTRANULL_DATABASE_URL: 'postgres://user:secret@db.internal/astranull' },
      tenantIds: ['ten_a'], dryRun: false, limit: 1,
      workerId: 'scan-runner-1', runtimeConfig: RUNTIME_CONFIG,
      createPostgresRuntimeFn: fakeRuntime({
        async dispatchDueValidationScans() {
          throw new Error('failed for https://customer.example/private and postgres://user:secret@db');
        },
      }, recorder),
    });
    assert.equal(recorder.closed, 1);
    assert.deepEqual(tenants, [{
      tenant_id: 'ten_a', due_count: 0, runnable_count: 0, dispatched: [], advanced: [], error: 'tenant_processing_failed',
    }]);
    assert.equal(JSON.stringify(tenants).includes('customer.example'), false);
    await assert.rejects(
      () => runPostgresValidationScans({
        env: {}, tenantIds: ['ten_a'], dryRun: false, limit: 1, workerId: 'w', runtimeConfig: RUNTIME_CONFIG,
        createPostgresRuntimeFn: async () => ({ services: {}, async close() {} }),
      }),
      /validationScans\.listDueValidationScans is unavailable/,
    );
  });

  it('summarizes dispatch and advance results with sanitized codes and builds the artifact', async () => {
    assert.deepEqual(summarizeScanDispatch({ scan_id: 'scan_1', dispatched: false, denied: 'bad code with spaces' }), {
      scan_id: 'scan_1', dispatched: false, denied: 'schedule_denied',
    });
    assert.deepEqual(summarizeScanAdvance({ scan_id: 'scan_1', acquired: false, reason: 'locked' }), {
      scan_id: 'scan_1', acquired: false, waiting: false, status: null, reason: 'locked',
    });
    const written = [];
    const { summary, exitCode } = await runValidationScanRunner({}, {
      tenantIds: ['ten_a'], dryRun: false, limit: 1, out: 'out/summary.json', workerId: 'w', runtimeConfig: RUNTIME_CONFIG,
    }, {
      createPostgresRuntimeFn: fakeRuntime(),
      writeFile: (file, content) => written.push({ file, content }),
      mkdir: () => {},
    });
    assert.equal(exitCode, 0);
    assert.equal(summary.artifact_type, 'validation_scan_runner_run');
    assert.equal(summary.mode, 'apply');
    assert.equal(summary.tenant_count, 1);
    assert.equal(written.length, 1);
    assert.ok(JSON.parse(written[0].content).caveats.length >= 3);
    const built = buildValidationScanRunnerSummary({
      dryRun: true,
      startedAt: '2026-06-01T12:00:00.000Z',
      finishedAt: '2026-06-01T12:00:01.000Z',
      tenants: [{ tenant_id: 'ten_a', due_count: 2, runnable_count: 1 }],
    });
    assert.equal(built.mode, 'dry_run');
    assert.equal(built.due_count, 2);
    assert.equal(built.runnable_count, 1);
  });
});
