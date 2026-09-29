import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { describe, it } from 'node:test';
import {
  buildTestPolicyRunnerSummary,
  loadTestPolicyRuntimeConfig,
  parseTestPolicyRunnerArgs,
  parseTestPolicyTenantIds,
  resolveTestPolicyRunnerConfig,
  resolveTestPolicySchedulerIntervalSeconds,
  runPostgresTestPolicies,
  runScheduledCompanionJobs,
  runTestPolicySchedulerTick,
  summarizePolicyDispatch,
} from '../../scripts/test-policy-runner.mjs';

const RUNTIME_CONFIG = { probeMode: 'signed-worker', probeWorkerSecret: 'configured-secret' };

describe('test policy signed-worker secret validation', () => {
  it('rejects known, patterned, and repeated material but accepts generated material', () => {
    for (const [secret, error] of [
      [Buffer.from(Array.from({ length: 32 }, (_, index) => index)).toString('hex'), 'hmac_secret_known_public'],
      [Buffer.from(Array.from({ length: 32 }, (_, index) => index + 32)).toString('hex'), 'hmac_secret_patterned'],
      ['q'.repeat(48), 'hmac_secret_low_entropy'],
    ]) {
      assert.throws(
        () => loadTestPolicyRuntimeConfig({
          NODE_ENV: 'test',
          ASTRANULL_PROBE_MODE: 'signed-worker',
          ASTRANULL_PROBE_WORKER_SECRET: secret,
        }),
        new RegExp(error),
      );
    }
    const generated = randomBytes(32).toString('base64url');
    assert.equal(loadTestPolicyRuntimeConfig({
      NODE_ENV: 'test',
      ASTRANULL_PROBE_MODE: 'signed-worker',
      ASTRANULL_PROBE_WORKER_SECRET: generated,
    }).probeWorkerSecret, generated);
  });
});

describe('test policy operator runner', () => {
  it('parses bounded arguments and tenant files', () => {
    assert.deepEqual(
      parseTestPolicyRunnerArgs([
        'node', 'runner', '--tenant-id', 'ten_a', '--dry-run', '--limit', '4', '--out', 'result.json',
      ]),
      {
        tenantId: 'ten_a', tenantIdsFile: null, dryRun: true,
        limit: 4, out: 'result.json', help: false,
      },
    );
    assert.deepEqual(parseTestPolicyTenantIds({ tenant_ids: [' ten_a ', 'ten_a', 'ten_b'] }), ['ten_a', 'ten_b']);
    assert.throws(
      () => parseTestPolicyRunnerArgs(['node', 'runner', '--limit', '101']),
      /between 1 and 100/,
    );
    assert.throws(() => parseTestPolicyTenantIds([]), /must not be empty/);
  });

  it('fails closed without database, explicit tenant scope, or signed-worker mode', () => {
    const parsed = parseTestPolicyRunnerArgs(['node', 'runner', '--tenant-id', 'ten_a']);
    assert.match(resolveTestPolicyRunnerConfig({}, parsed).message, /DATABASE_URL/);
    assert.match(
      resolveTestPolicyRunnerConfig(
        { ASTRANULL_DATABASE_URL: 'postgres://configured' },
        parseTestPolicyRunnerArgs(['node', 'runner']),
      ).message,
      /explicit tenant scope/,
    );
    assert.match(
      resolveTestPolicyRunnerConfig(
        { ASTRANULL_DATABASE_URL: 'postgres://configured' },
        parsed,
        { loadRuntimeConfigFn: () => ({ probeMode: 'simulation' }) },
      ).message,
      /signed-worker mode is required/,
    );
  });

  it('resolves a sanitized worker and redacts database URLs from config failures', () => {
    const parsed = parseTestPolicyRunnerArgs(['node', 'runner', '--tenant-id', 'ten_a']);
    const env = {
      ASTRANULL_DATABASE_URL: 'postgres://user:secret@db.internal/astranull',
      ASTRANULL_TEST_POLICY_RUNNER_ID: 'scheduler-1',
      ASTRANULL_TEST_POLICY_LEASE_MS: '45000',
    };
    const ok = resolveTestPolicyRunnerConfig(env, parsed, {
      loadRuntimeConfigFn: () => RUNTIME_CONFIG,
    });
    assert.equal(ok.ok, true);
    assert.deepEqual(ok.tenantIds, ['ten_a']);
    assert.equal(ok.workerId, 'scheduler-1');
    assert.equal(ok.leaseMs, 45000);
    assert.equal(ok.schedulerIntervalSeconds, 30);

    const failed = resolveTestPolicyRunnerConfig(env, parsed, {
      loadRuntimeConfigFn: () => {
        throw new Error(`could not connect to ${env.ASTRANULL_DATABASE_URL}`);
      },
    });
    assert.equal(failed.ok, false);
    assert.equal(failed.message.includes('user:secret'), false);
  });

  it('bounds the external scheduler interval to the heartbeat-safe range', () => {
    assert.equal(resolveTestPolicySchedulerIntervalSeconds({}), 30);
    assert.equal(resolveTestPolicySchedulerIntervalSeconds({
      ASTRANULL_TEST_POLICY_INTERVAL_SECONDS: '5',
    }), 5);
    assert.equal(resolveTestPolicySchedulerIntervalSeconds({
      ASTRANULL_TEST_POLICY_INTERVAL_SECONDS: '30',
    }), 30);
    for (const value of ['', '0', '-1', '4', '1.5', 'nope', '31', '3600']) {
      assert.throws(
        () => resolveTestPolicySchedulerIntervalSeconds({
          ASTRANULL_TEST_POLICY_INTERVAL_SECONDS: value,
        }),
        /integer between 5 and 30/,
        value,
      );
    }

    const parsed = parseTestPolicyRunnerArgs(['node', 'runner', '--tenant-id', 'ten_a']);
    const rejected = resolveTestPolicyRunnerConfig({
      ASTRANULL_DATABASE_URL: 'postgres://configured',
      ASTRANULL_TEST_POLICY_INTERVAL_SECONDS: '31',
    }, parsed, {
      loadRuntimeConfigFn: () => RUNTIME_CONFIG,
    });
    assert.equal(rejected.ok, false);
    assert.match(rejected.message, /ASTRANULL_TEST_POLICY_INTERVAL_SECONDS/);
  });

  it('dry-runs each explicit tenant without leasing and always closes runtime', async () => {
    const calls = [];
    let closed = 0;
    let runtimeOptions;
    const createPostgresRuntimeFn = async (_env, options) => {
      runtimeOptions = options;
      return ({
      services: {
        testPolicies: {
          async listDueTestPolicies(ctx, query) {
            calls.push({ method: 'list', ctx, query });
            return [{ id: `pol_${ctx.tenantId}`, next_run_at: '2026-06-01T12:00:00.000Z', target: 'must-not-leak' }];
          },
          async dispatchDueTestPolicies() {
            throw new Error('dry-run must not dispatch');
          },
        },
      },
      async close() { closed += 1; },
    });
    };

    const tenants = await runPostgresTestPolicies({
      env: {}, tenantIds: ['ten_a', 'ten_b'], dryRun: true, limit: 3,
      workerId: 'scheduler-1', leaseMs: 60000, runtimeConfig: RUNTIME_CONFIG,
      createPostgresRuntimeFn,
    });

    assert.equal(closed, 1);
    assert.deepEqual(runtimeOptions, {
      autoMigrate: false,
      wafPostureServiceOptions: { connectorEncryptionKey: null },
    });
    assert.deepEqual(calls.map((call) => call.ctx.tenantId), ['ten_a', 'ten_b']);
    assert.deepEqual(tenants[0].policies, [{
      policy_id: 'pol_ten_a', next_run_at: '2026-06-01T12:00:00.000Z',
    }]);
    assert.equal(JSON.stringify(tenants).includes('must-not-leak'), false);
  });

  it('dispatches with bounded leases and emits only metadata-safe results', async () => {
    const calls = [];
    let closed = 0;
    const createPostgresRuntimeFn = async () => ({
      services: {
        testPolicies: {
          async listDueTestPolicies() { return []; },
          async dispatchDueTestPolicies(ctx, options) {
            calls.push({ ctx, options });
            return [{
              policy_id: 'pol_1',
              run: { run: { id: 'run_1', target_value: 'must-not-leak' } },
              dispatch: { id: 'dispatch_1', state: 'dispatched' },
            }];
          },
        },
      },
      async close() { closed += 1; },
    });

    const tenants = await runPostgresTestPolicies({
      env: {}, tenantIds: ['ten_a'], dryRun: false, limit: 7,
      workerId: 'scheduler-1', leaseMs: 45000, runtimeConfig: RUNTIME_CONFIG,
      createPostgresRuntimeFn,
    });

    assert.equal(closed, 1);
    assert.equal(calls[0].ctx.tenantId, 'ten_a');
    assert.deepEqual(calls[0].options, {
      workerId: 'scheduler-1', leaseMs: 45000, limit: 7, runtimeConfig: RUNTIME_CONFIG,
    });
    assert.deepEqual(tenants[0].policies, [{
      policy_id: 'pol_1', status: 'dispatched', run_id: 'run_1', dispatch_id: 'dispatch_1',
    }]);
    assert.equal(JSON.stringify(tenants).includes('must-not-leak'), false);
  });

  it('does not serialize thrown tenant or target details into runner summaries', async () => {
    let closed = 0;
    const tenants = await runPostgresTestPolicies({
      env: { ASTRANULL_DATABASE_URL: 'postgres://user:secret@db.internal/astranull' },
      tenantIds: ['ten_a'], dryRun: true, limit: 1,
      workerId: 'scheduler-1', leaseMs: 60000, runtimeConfig: RUNTIME_CONFIG,
      createPostgresRuntimeFn: async () => ({
        services: {
          testPolicies: {
            async listDueTestPolicies() {
              throw new Error('failed for https://customer.example/private and postgres://user:secret@db');
            },
            async dispatchDueTestPolicies() { return []; },
          },
        },
        async close() { closed += 1; },
      }),
    });

    assert.equal(closed, 1);
    assert.deepEqual(tenants, [{
      tenant_id: 'ten_a', due_count: 0, policies: [], error: 'tenant_processing_failed',
    }]);
    assert.equal(JSON.stringify(tenants).includes('customer.example'), false);
    assert.equal(JSON.stringify(tenants).includes('user:secret'), false);
  });

  it('marks run or completion failures and builds a metadata-only summary', () => {
    assert.deepEqual(
      summarizePolicyDispatch({ policy_id: 'pol_1', error: { error: 'ownership_not_verified' }, dispatch: { id: 'd_1' } }),
      {
        policy_id: 'pol_1', status: 'skipped', run_id: null,
        dispatch_id: 'd_1', error: 'ownership_not_verified',
      },
    );
    assert.deepEqual(
      summarizePolicyDispatch({
        policy_id: 'pol_2', error: { error: 'missing_run_id' },
        dispatch: { id: 'd_2', state: 'failed', error_code: 'missing_run_id' },
      }),
      {
        policy_id: 'pol_2', status: 'failed', run_id: null,
        dispatch_id: 'd_2', error: 'missing_run_id',
      },
    );
    assert.equal(
      summarizePolicyDispatch({
        policy_id: 'pol_3', error: { error: 'policy_dispatch_start_claimed' },
        dispatch: { error: 'policy_dispatch_start_claimed', status: 409 },
      }).status,
      'claim_failed',
    );
    const summary = buildTestPolicyRunnerSummary({
      dryRun: false,
      startedAt: '2026-06-01T12:00:00.000Z',
      finishedAt: '2026-06-01T12:00:01.000Z',
      tenants: [{ tenant_id: 'ten_a', due_count: 1, policies: [] }],
    });
    assert.equal(summary.artifact_type, 'test_policy_scheduler_runtime_run');
    assert.equal(summary.due_count, 1);
    assert.equal(JSON.stringify(summary).includes('database URL'), true);
  });
});

describe('scheduled companion jobs (hosted single-VM tick)', () => {
  const env = {
    NODE_ENV: 'test',
    ASTRANULL_DATABASE_URL: 'postgres://x@localhost/x',
    ASTRANULL_PROBE_MODE: 'signed-worker',
    ASTRANULL_PROBE_WORKER_SECRET: randomBytes(32).toString('hex'),
  };

  it('runs the sweeper and scan runner for the same tenant scope and isolates failures', async () => {
    const calls = [];
    const ok = await runScheduledCompanionJobs(env, { tenantIds: ['ten_a', 'ten_b'], dryRun: false }, {
      sweep: async (_env, cfg) => { calls.push(['sweep', cfg.tenantIds]); return { totals: { errors: 0 } }; },
      scans: async (_env, cfg) => { calls.push(['scans', cfg.tenantIds]); return { exitCode: 0 }; },
    });
    assert.deepEqual(ok, { sweep: 'ok', scans: 'ok', exitCode: 0 });
    assert.deepEqual(calls, [['sweep', ['ten_a', 'ten_b']], ['scans', ['ten_a', 'ten_b']]]);

    const failed = await runScheduledCompanionJobs(env, { tenantIds: ['ten_a'], dryRun: false }, {
      sweep: async () => { throw new Error('boom'); },
      scans: async () => ({ exitCode: 0 }),
    });
    assert.deepEqual(failed, { sweep: 'failed', scans: 'ok', exitCode: 1 });
  });

  it('does nothing in dry-run mode', async () => {
    const result = await runScheduledCompanionJobs(env, { tenantIds: ['ten_a'], dryRun: true }, {
      sweep: async () => assert.fail('sweep must not run'),
      scans: async () => assert.fail('scans must not run'),
    });
    assert.equal(result.exitCode, 0);
  });
});

describe('scheduler tick independence (finding 8)', () => {
  it('runs the sweeper and scan runner even when the policy runner throws', async () => {
    let companionsRan = false;
    const logs = [];
    const errors = [];
    const exitCode = await runTestPolicySchedulerTick(
      { ASTRANULL_DATABASE_URL: 'postgres://user:secret@db/astranull' },
      { tenantIds: ['ten_a'], dryRun: false },
      {
        policy: async () => { throw new Error('policy boom for postgres://user:secret@db'); },
        companions: async () => {
          companionsRan = true;
          return { sweep: 'ok', scans: 'ok', exitCode: 0 };
        },
        log: (msg) => logs.push(msg),
        error: (msg) => errors.push(msg),
      },
    );
    // Companions ran despite the policy-runner failure.
    assert.equal(companionsRan, true);
    // The tick still reports failure via a nonzero exit code.
    assert.notEqual(exitCode, 0);
    // The DB secret is not leaked in the error output.
    assert.equal(errors.join('\n').includes('user:secret'), false);
    assert.ok(logs.some((line) => line.includes('validation_scans: ok')));
  });

  it('exits nonzero when only the companions fail but still runs the policy runner', async () => {
    let policyRan = false;
    const exitCode = await runTestPolicySchedulerTick(
      {},
      { tenantIds: ['ten_a'], dryRun: false },
      {
        policy: async () => { policyRan = true; return { summary: { mode: 'apply', tenant_count: 1, due_count: 0 }, exitCode: 0 }; },
        companions: async () => ({ sweep: 'failed', scans: 'ok', exitCode: 1 }),
        log: () => {},
        error: () => {},
      },
    );
    assert.equal(policyRan, true);
    assert.notEqual(exitCode, 0);
  });
});
