#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { resolveProbeMode } from '../src/config.mjs';
import { redactDatabaseUrlInMessage } from '../src/lib/pgErrorRedact.mjs';
import { createPostgresRuntime } from '../src/persistence/postgres/runtime.mjs';


export const TEST_POLICY_SCHEDULER_MIN_INTERVAL_SECONDS = 5;
export const TEST_POLICY_SCHEDULER_MAX_INTERVAL_SECONDS = 30;
export const TEST_POLICY_SCHEDULER_DEFAULT_INTERVAL_SECONDS = 30;

export function resolveTestPolicySchedulerIntervalSeconds(env = process.env) {
  const raw = String(
    env.ASTRANULL_TEST_POLICY_INTERVAL_SECONDS
      ?? TEST_POLICY_SCHEDULER_DEFAULT_INTERVAL_SECONDS,
  ).trim();
  if (!/^[1-9]\d*$/.test(raw)) {
    throw new Error(
      `test-policy-runner: ASTRANULL_TEST_POLICY_INTERVAL_SECONDS must be an integer between ${TEST_POLICY_SCHEDULER_MIN_INTERVAL_SECONDS} and ${TEST_POLICY_SCHEDULER_MAX_INTERVAL_SECONDS}.`,
    );
  }
  const interval = Number(raw);
  if (
    !Number.isSafeInteger(interval)
    || interval < TEST_POLICY_SCHEDULER_MIN_INTERVAL_SECONDS
    || interval > TEST_POLICY_SCHEDULER_MAX_INTERVAL_SECONDS
  ) {
    throw new Error(
      `test-policy-runner: ASTRANULL_TEST_POLICY_INTERVAL_SECONDS must be an integer between ${TEST_POLICY_SCHEDULER_MIN_INTERVAL_SECONDS} and ${TEST_POLICY_SCHEDULER_MAX_INTERVAL_SECONDS}.`,
    );
  }
  return interval;
}
const USAGE = `test-policy-runner: dispatch due per-group validation rules (Postgres mode).

This operator CLI is not a daemon. Schedule it externally (cron, Kubernetes CronJob, CI job).
It requires signed-worker mode and delegates only through the validated test-run service.

Environment:
  ASTRANULL_DATABASE_URL (required)
  ASTRANULL_PROBE_MODE=signed-worker (required)
  ASTRANULL_PROBE_WORKER_SECRET (required)
  ASTRANULL_TEST_POLICY_RUNNER_ID (optional; safe worker label)
  ASTRANULL_TEST_POLICY_LEASE_MS (optional; 1000-900000, default 60000)
  ASTRANULL_TEST_POLICY_INTERVAL_SECONDS (optional; 5-30, default 30)

Options:
  --tenant-id <id>           Run for one tenant (mutually exclusive with --tenant-ids-file)
  --tenant-ids-file <path>   JSON file: string[] or { "tenant_ids": string[] }
  --dry-run                  List due policy IDs without leasing or dispatching
  --limit <n>                Cap policies per tenant (1-100, default 25)
  --out <path>               Write a metadata-only JSON summary
  --help                     Show this message
`;

/** @param {string[]} argv */
export function parseTestPolicyRunnerArgs(argv) {
  const parsed = {
    tenantId: null,
    tenantIdsFile: null,
    dryRun: false,
    limit: 25,
    out: null,
    help: false,
  };
  const args = argv.slice(2);
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === '--help' || arg === '-h') {
      parsed.help = true;
    } else if (arg === '--dry-run') {
      parsed.dryRun = true;
    } else if (['--tenant-id', '--tenant-ids-file', '--limit', '--out'].includes(arg)) {
      const value = args[i + 1];
      if (!value || value.startsWith('--')) {
        throw new Error(`test-policy-runner: ${arg} requires a value.`);
      }
      if (arg === '--tenant-id') parsed.tenantId = value.trim();
      if (arg === '--tenant-ids-file') parsed.tenantIdsFile = value;
      if (arg === '--out') parsed.out = value;
      if (arg === '--limit') {
        const limit = Number(value);
        if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) {
          throw new Error('test-policy-runner: --limit must be an integer between 1 and 100.');
        }
        parsed.limit = limit;
      }
      i += 1;
    } else {
      throw new Error(`test-policy-runner: unknown argument "${arg}".`);
    }
  }
  return parsed;
}

/** @param {unknown} raw */
export function parseTestPolicyTenantIds(raw) {
  const text = typeof raw === 'string' ? raw.trim() : null;
  const payload = text == null ? raw : (text.startsWith('[') || text.startsWith('{') ? JSON.parse(text) : text.split(','));
  const ids = Array.isArray(payload)
    ? payload
    : payload && typeof payload === 'object' && Array.isArray(payload.tenant_ids)
      ? payload.tenant_ids
      : null;
  if (!ids) {
    throw new Error('test-policy-runner: tenant id file must be a JSON array or { "tenant_ids": [] }.');
  }
  const normalized = [...new Set(ids.map((id) => String(id ?? '').trim()).filter(Boolean))];
  if (!normalized.length) throw new Error('test-policy-runner: tenant id list must not be empty.');
  return normalized;
}

export function loadTestPolicyRuntimeConfig(env) {
  const probeMode = resolveProbeMode(env);
  const probeWorkerSecret = String(env.ASTRANULL_PROBE_WORKER_SECRET ?? '');
  if (probeMode === 'signed-worker' && probeWorkerSecret.length < 32) {
    throw new Error(
      'ASTRANULL_PROBE_WORKER_SECRET must be at least 32 characters when probe mode is signed-worker.',
    );
  }
  return { probeMode, probeWorkerSecret };
}

/**
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} env
 * @param {ReturnType<typeof parseTestPolicyRunnerArgs>} parsed
 * @param {{ readTenantIdsFile?: (path: string) => string, loadRuntimeConfigFn?: typeof loadTestPolicyRuntimeConfig }} [deps]
 */
export function resolveTestPolicyRunnerConfig(env, parsed, deps = {}) {
  if (!String(env.ASTRANULL_DATABASE_URL ?? '').trim()) {
    return { ok: false, message: 'test-policy-runner: ASTRANULL_DATABASE_URL must be set.' };
  }
  const envTenantIds = String(env.ASTRANULL_TEST_POLICY_TENANT_IDS ?? '').trim();
  const scopeCount = Number(Boolean(parsed.tenantId)) + Number(Boolean(parsed.tenantIdsFile)) + Number(Boolean(envTenantIds));
  if (scopeCount !== 1) {
    return { ok: false, message: 'test-policy-runner: explicit tenant scope required; provide exactly one source (--tenant-id, --tenant-ids-file, or ASTRANULL_TEST_POLICY_TENANT_IDS).' };
  }

  let tenantIds;
  try {
    const readTenantIdsFile = deps.readTenantIdsFile ?? ((filePath) => readFileSync(filePath, 'utf8'));
    tenantIds = parseTestPolicyTenantIds(
      parsed.tenantId ? [parsed.tenantId] : parsed.tenantIdsFile ? readTenantIdsFile(parsed.tenantIdsFile) : envTenantIds,
    );
  } catch (error) {
    return { ok: false, message: error instanceof Error ? error.message : String(error) };
  }

  let runtimeConfig;
  try {
    runtimeConfig = (deps.loadRuntimeConfigFn ?? loadTestPolicyRuntimeConfig)(env);
  } catch (error) {
    return {
      ok: false,
      message: `test-policy-runner: ${redactDatabaseUrlInMessage(error, env)}`,
    };
  }
  if (runtimeConfig.probeMode !== 'signed-worker') {
    return {
      ok: false,
      message: 'test-policy-runner: signed-worker mode is required (set ASTRANULL_PROBE_MODE=signed-worker).',
    };
  }

  const workerId = String(env.ASTRANULL_TEST_POLICY_RUNNER_ID ?? 'test-policy-runner').trim();
  if (!/^[a-z0-9._:-]{1,128}$/i.test(workerId)) {
    return { ok: false, message: 'test-policy-runner: ASTRANULL_TEST_POLICY_RUNNER_ID is invalid.' };
  }
  const leaseMs = Number(env.ASTRANULL_TEST_POLICY_LEASE_MS ?? 60_000);
  if (!Number.isSafeInteger(leaseMs) || leaseMs < 1_000 || leaseMs > 15 * 60_000) {
    return {
      ok: false,
      message: 'test-policy-runner: ASTRANULL_TEST_POLICY_LEASE_MS must be 1000-900000.',
    };
  }
  let schedulerIntervalSeconds;
  try {
    schedulerIntervalSeconds = resolveTestPolicySchedulerIntervalSeconds(env);
  } catch (error) {
    return { ok: false, message: error instanceof Error ? error.message : String(error) };
  }
  return {
    ok: true,
    tenantIds,
    dryRun: parsed.dryRun,
    limit: parsed.limit,
    out: parsed.out,
    workerId,
    leaseMs,
    schedulerIntervalSeconds,
    runtimeConfig,
  };
}

function safeErrorCode(value, fallback) {
  if (value == null) return null;
  const code = String(value).trim();
  return /^[a-z0-9_.:-]{1,128}$/i.test(code) ? code : fallback;
}

/** @param {unknown} result */
export function summarizePolicyDispatch(result) {
  const row = result && typeof result === 'object' ? result : {};
  const runError = safeErrorCode(row.error?.error, 'run_dispatch_failed');
  const completionError = safeErrorCode(row.dispatch?.error, 'dispatch_completion_failed');
  const terminalState = ['dispatched', 'skipped', 'failed'].includes(row.dispatch?.state)
    ? row.dispatch.state
    : null;
  const claimFailed = Boolean(runError && completionError && !row.dispatch?.id);
  return {
    policy_id: row.policy_id ?? null,
    status: terminalState
      ?? (claimFailed ? 'claim_failed' : runError ? 'skipped' : completionError ? 'completion_failed' : 'dispatched'),
    run_id: row.run?.run?.id ?? row.run?.id ?? null,
    dispatch_id: row.dispatch?.id ?? null,
    ...(runError || completionError ? { error: String(runError ?? completionError) } : {}),
  };
}

/**
 * @param {{
 *   env: NodeJS.ProcessEnv | Record<string, string | undefined>,
 *   tenantIds: string[], dryRun: boolean, limit: number, workerId: string,
 *   leaseMs: number, runtimeConfig: Record<string, unknown>,
 *   createPostgresRuntimeFn?: typeof createPostgresRuntime,
 * }} options
 */
export async function runPostgresTestPolicies(options) {
  const runtime = await (options.createPostgresRuntimeFn ?? createPostgresRuntime)(options.env, {
    autoMigrate: false,
  });
  try {
    const service = runtime.services?.testPolicies;
    if (!service?.listDueTestPolicies || !service?.dispatchDueTestPolicies) {
      throw new Error('test-policy-runner: runtime testPolicies service is unavailable.');
    }
    const tenants = [];
    for (const tenantId of options.tenantIds) {
      const ctx = { tenantId, userId: options.workerId, role: 'system' };
      try {
        if (options.dryRun) {
          const due = await service.listDueTestPolicies(ctx, { limit: options.limit });
          if (!Array.isArray(due)) {
            tenants.push({ tenant_id: tenantId, due_count: 0, policies: [], error: safeErrorCode(due?.error, 'due_query_failed') ?? 'due_query_failed' });
            continue;
          }
          tenants.push({
            tenant_id: tenantId,
            due_count: due.length,
            policies: due.map((policy) => ({ policy_id: policy.id, next_run_at: policy.next_run_at })),
          });
          continue;
        }
        const dispatched = await service.dispatchDueTestPolicies(ctx, {
          workerId: options.workerId,
          leaseMs: options.leaseMs,
          limit: options.limit,
          runtimeConfig: options.runtimeConfig,
        });
        if (!Array.isArray(dispatched)) {
          tenants.push({ tenant_id: tenantId, due_count: 0, policies: [], error: safeErrorCode(dispatched?.error, 'dispatch_failed') ?? 'dispatch_failed' });
          continue;
        }
        tenants.push({
          tenant_id: tenantId,
          due_count: dispatched.length,
          policies: dispatched.map(summarizePolicyDispatch),
        });
      } catch (error) {
        tenants.push({
          tenant_id: tenantId,
          due_count: 0,
          policies: [],
          error: 'tenant_processing_failed',
        });
      }
    }
    return tenants;
  } finally {
    await runtime.close();
  }
}

/** @param {{ dryRun: boolean, startedAt: string, finishedAt: string, tenants: Record<string, unknown>[] }} input */
export function buildTestPolicyRunnerSummary(input) {
  return {
    schema_version: 1,
    artifact_type: 'test_policy_scheduler_runtime_run',
    mode: input.dryRun ? 'dry_run' : 'apply',
    started_at: input.startedAt,
    finished_at: input.finishedAt,
    tenant_count: input.tenants.length,
    due_count: input.tenants.reduce((sum, tenant) => sum + Number(tenant.due_count ?? 0), 0),
    tenants: input.tenants,
    caveats: [
      'Invoke from an external scheduler; this CLI is not started by the API server.',
      'Explicit tenant scope is mandatory; cross-tenant enumeration is not performed.',
      'Apply mode requires signed-worker dispatch and revalidates rule, target, ownership, and lease before egress.',
      'Output is metadata-only and omits target values, credentials, probe payloads, and database URLs.',
    ],
  };
}

/**
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} env
 * @param {ReturnType<typeof resolveTestPolicyRunnerConfig> & { ok: true }} config
 * @param {{ createPostgresRuntimeFn?: typeof createPostgresRuntime, writeFile?: typeof writeFileSync, mkdir?: typeof mkdirSync }} [deps]
 */
export async function runTestPolicyRunner(env, config, deps = {}) {
  const startedAt = new Date().toISOString();
  const tenants = await runPostgresTestPolicies({
    env,
    tenantIds: config.tenantIds,
    dryRun: config.dryRun,
    limit: config.limit,
    workerId: config.workerId,
    leaseMs: config.leaseMs,
    runtimeConfig: config.runtimeConfig,
    createPostgresRuntimeFn: deps.createPostgresRuntimeFn,
  });
  const summary = buildTestPolicyRunnerSummary({
    dryRun: config.dryRun,
    startedAt,
    finishedAt: new Date().toISOString(),
    tenants,
  });
  if (config.out) {
    (deps.mkdir ?? mkdirSync)(path.dirname(path.resolve(config.out)), { recursive: true });
    (deps.writeFile ?? writeFileSync)(config.out, `${JSON.stringify(summary, null, 2)}\n`);
  }
  const failed = tenants.some((tenant) =>
    tenant.error || tenant.policies?.some((policy) => policy.error),
  );
  return { summary, exitCode: failed ? 1 : 0 };
}

async function main() {
  let parsed;
  try {
    parsed = parseTestPolicyRunnerArgs(process.argv);
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
    return;
  }
  if (parsed.help) {
    console.log(USAGE.trimEnd());
    return;
  }
  const config = resolveTestPolicyRunnerConfig(process.env, parsed);
  if (!config.ok) {
    console.error(config.message);
    process.exitCode = 1;
    return;
  }
  try {
    const { summary, exitCode } = await runTestPolicyRunner(process.env, config);
    console.log('test-policy-runner: ok');
    console.log(`  mode: ${summary.mode}`);
    console.log(`  tenant_count: ${summary.tenant_count}`);
    console.log(`  due_count: ${summary.due_count}`);
    if (config.out) console.log(`  out: ${config.out}`);
    process.exitCode = exitCode;
  } catch (error) {
    console.error(`test-policy-runner: failed: ${redactDatabaseUrlInMessage(error, process.env)}`);
    process.exitCode = 1;
  }
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) main();
