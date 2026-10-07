#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadProbeDispatchConfig } from '../src/config.mjs';
import { redactDatabaseUrlInMessage } from '../src/lib/pgErrorRedact.mjs';
import { assertRunnerTenantScope } from '../src/lib/scheduledTenantScope.mjs';
import { createPostgresRuntime } from '../src/persistence/postgres/runtime.mjs';

const RUNNER_NAME = 'validation-scan-runner';

export const VALIDATION_SCAN_RUNNER_MIN_INTERVAL_SECONDS = 5;
export const VALIDATION_SCAN_RUNNER_MAX_INTERVAL_SECONDS = 60;
export const VALIDATION_SCAN_RUNNER_DEFAULT_INTERVAL_SECONDS = 60;

export function resolveValidationScanRunnerIntervalSeconds(env = process.env) {
  const raw = String(
    env.ASTRANULL_VALIDATION_SCAN_INTERVAL_SECONDS ?? VALIDATION_SCAN_RUNNER_DEFAULT_INTERVAL_SECONDS,
  ).trim();
  const message = `${RUNNER_NAME}: ASTRANULL_VALIDATION_SCAN_INTERVAL_SECONDS must be an integer between ${VALIDATION_SCAN_RUNNER_MIN_INTERVAL_SECONDS} and ${VALIDATION_SCAN_RUNNER_MAX_INTERVAL_SECONDS}.`;
  if (!/^[1-9]\d*$/.test(raw)) throw new Error(message);
  const interval = Number(raw);
  if (
    !Number.isSafeInteger(interval)
    || interval < VALIDATION_SCAN_RUNNER_MIN_INTERVAL_SECONDS
    || interval > VALIDATION_SCAN_RUNNER_MAX_INTERVAL_SECONDS
  ) {
    throw new Error(message);
  }
  return interval;
}

const USAGE = `${RUNNER_NAME}: dispatch due validation scans, advance running scans, and resume due entry-path comparisons (Postgres mode).

This operator CLI is not a daemon. Schedule it externally (cron, Kubernetes CronJob, CI job).
It requires signed-worker mode and delegates every step start through the validated test-run service.

Environment:
  ASTRANULL_DATABASE_URL (required)
  ASTRANULL_PROBE_MODE=signed-worker (required)
  ASTRANULL_PROBE_WORKER_SECRET (required)
  ASTRANULL_VALIDATION_SCAN_RUNNER_ID (optional; safe worker label)
  ASTRANULL_VALIDATION_SCAN_INTERVAL_SECONDS (optional; 5-60, default 60)

Options:
  --tenant-id <id>           Run for one tenant (mutually exclusive with --tenant-ids-file)
  --tenant-ids-file <path>   JSON file: string[] or { "tenant_ids": string[] }
  --dry-run                  List due and runnable scan ids without dispatching or advancing
  --limit <n>                Cap scans per tenant per phase (1-100, default 25)
  --out <path>               Write a metadata-only JSON summary
  --help                     Show this message
`;

/** @param {string[]} argv */
export function parseValidationScanRunnerArgs(argv) {
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
        throw new Error(`${RUNNER_NAME}: ${arg} requires a value.`);
      }
      if (arg === '--tenant-id') parsed.tenantId = value.trim();
      if (arg === '--tenant-ids-file') parsed.tenantIdsFile = value;
      if (arg === '--out') parsed.out = value;
      if (arg === '--limit') {
        const limit = Number(value);
        if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) {
          throw new Error(`${RUNNER_NAME}: --limit must be an integer between 1 and 100.`);
        }
        parsed.limit = limit;
      }
      i += 1;
    } else {
      throw new Error(`${RUNNER_NAME}: unknown argument "${arg}".`);
    }
  }
  return parsed;
}

/** @param {unknown} raw */
export function parseValidationScanTenantIds(raw) {
  const text = typeof raw === 'string' ? raw.trim() : null;
  const payload = text == null
    ? raw
    : (text.startsWith('[') || text.startsWith('{') ? JSON.parse(text) : text.split(','));
  const ids = Array.isArray(payload)
    ? payload
    : payload && typeof payload === 'object' && Array.isArray(payload.tenant_ids)
      ? payload.tenant_ids
      : null;
  if (!ids) {
    throw new Error(`${RUNNER_NAME}: tenant id file must be a JSON array or { "tenant_ids": [] }.`);
  }
  const normalized = [...new Set(ids.map((id) => String(id ?? '').trim()).filter(Boolean))];
  if (!normalized.length) throw new Error(`${RUNNER_NAME}: tenant id list must not be empty.`);
  return normalized;
}

export function loadValidationScanRuntimeConfig(env) {
  return loadProbeDispatchConfig(env);
}

/**
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} env
 * @param {ReturnType<typeof parseValidationScanRunnerArgs>} parsed
 * @param {{ readTenantIdsFile?: (path: string) => string, loadRuntimeConfigFn?: typeof loadValidationScanRuntimeConfig }} [deps]
 */
export function resolveValidationScanRunnerConfig(env, parsed, deps = {}) {
  if (!String(env.ASTRANULL_DATABASE_URL ?? '').trim()) {
    return { ok: false, message: `${RUNNER_NAME}: ASTRANULL_DATABASE_URL must be set.` };
  }
  const envTenantIds = String(env.ASTRANULL_VALIDATION_SCAN_TENANT_IDS ?? '').trim();
  const scopeCount = Number(Boolean(parsed.tenantId)) + Number(Boolean(parsed.tenantIdsFile)) + Number(Boolean(envTenantIds));
  if (scopeCount !== 1) {
    return {
      ok: false,
      message: `${RUNNER_NAME}: explicit tenant scope required; provide exactly one source (--tenant-id, --tenant-ids-file, or ASTRANULL_VALIDATION_SCAN_TENANT_IDS).`,
    };
  }

  let tenantIds;
  try {
    const readTenantIdsFile = deps.readTenantIdsFile ?? ((filePath) => readFileSync(filePath, 'utf8'));
    tenantIds = parseValidationScanTenantIds(
      parsed.tenantId ? [parsed.tenantId] : parsed.tenantIdsFile ? readTenantIdsFile(parsed.tenantIdsFile) : envTenantIds,
    );
  } catch (error) {
    return { ok: false, message: error instanceof Error ? error.message : String(error) };
  }
  const scope = assertRunnerTenantScope(tenantIds, 'postgres', RUNNER_NAME);
  if (!scope?.ok) {
    return { ok: false, message: scope?.message ?? `${RUNNER_NAME}: tenant scope required.` };
  }

  let runtimeConfig;
  try {
    runtimeConfig = (deps.loadRuntimeConfigFn ?? loadValidationScanRuntimeConfig)(env);
  } catch (error) {
    return { ok: false, message: `${RUNNER_NAME}: ${redactDatabaseUrlInMessage(error, env)}` };
  }
  if (runtimeConfig.probeMode !== 'signed-worker') {
    return {
      ok: false,
      message: `${RUNNER_NAME}: signed-worker mode is required (set ASTRANULL_PROBE_MODE=signed-worker).`,
    };
  }

  const workerId = String(env.ASTRANULL_VALIDATION_SCAN_RUNNER_ID ?? RUNNER_NAME).trim();
  if (!/^[a-z0-9._:-]{1,128}$/i.test(workerId)) {
    return { ok: false, message: `${RUNNER_NAME}: ASTRANULL_VALIDATION_SCAN_RUNNER_ID is invalid.` };
  }
  let schedulerIntervalSeconds;
  try {
    schedulerIntervalSeconds = resolveValidationScanRunnerIntervalSeconds(env);
  } catch (error) {
    return { ok: false, message: error instanceof Error ? error.message : String(error) };
  }
  return {
    ok: true,
    tenantIds: scope.tenantIds,
    dryRun: parsed.dryRun,
    limit: parsed.limit,
    out: parsed.out,
    workerId,
    schedulerIntervalSeconds,
    runtimeConfig,
  };
}

function safeCode(value, fallback = null) {
  if (value == null) return fallback;
  const code = String(value).trim();
  return /^[a-z0-9_.:-]{1,128}$/i.test(code) ? code : fallback;
}

/** @param {unknown} result */
export function summarizeScanDispatch(result) {
  const row = result && typeof result === 'object' ? result : {};
  return {
    scan_id: safeCode(row.scan_id, null),
    dispatched: row.dispatched === true,
    ...(row.denied ? { denied: safeCode(row.denied, 'schedule_denied') } : {}),
    ...(row.reason ? { reason: safeCode(row.reason, 'dispatch_skipped') } : {}),
    ...(row.advanced ? { advanced: summarizeScanAdvance(row.advanced) } : {}),
  };
}

/** @param {unknown} result */
export function summarizeScanAdvance(result) {
  const row = result && typeof result === 'object' ? result : {};
  return {
    scan_id: safeCode(row.scan_id, null),
    acquired: row.acquired === true,
    waiting: row.waiting === true,
    status: safeCode(row.status, null),
    ...(row.reason ? { reason: safeCode(row.reason, 'advance_skipped') } : {}),
    ...(row.abort_reason ? { abort_reason: safeCode(row.abort_reason, 'aborted') } : {}),
    ...(row.error ? { error: safeCode(row.error, 'advance_failed') ?? 'advance_failed' } : {}),
    ...(row.deferred_until ? { deferred_until: String(row.deferred_until) } : {}),
  };
}

/** @param {unknown} result */
export function summarizeComparisonAdvance(result) {
  const row = result && typeof result === 'object' ? result : {};
  return {
    comparison_id: safeCode(row.id, null),
    advanced: row.advanced === true,
    status: safeCode(row.status, null),
    ...(row.waiting ? { waiting: true } : {}),
    ...(row.reason ? { reason: safeCode(row.reason, 'advance_skipped') } : {}),
  };
}

/** Postgres comparisons have no in-process ticker: resume due comparisons per tenant, pausing (never cancelling) on the gate. */
export async function advanceEntryPathComparisonsForTenant(service, ctx, limit) {
  if (typeof service?.advanceDueEntryPathComparisons !== 'function') return null;
  try {
    const results = await service.advanceDueEntryPathComparisons(ctx, { limit, pauseWhenGateOff: true });
    const rows = Array.isArray(results) ? results.filter(Boolean).map(summarizeComparisonAdvance) : [];
    return { due_count: rows.length, advanced: rows };
  } catch (err) {
    return { due_count: 0, advanced: [], error: safeCode(err?.code, 'comparison_advance_failed') ?? 'comparison_advance_failed' };
  }
}

/**
 * @param {{
 *   env: NodeJS.ProcessEnv | Record<string, string | undefined>,
 *   tenantIds: string[], dryRun: boolean, limit: number, workerId: string,
 *   runtimeConfig: Record<string, unknown>,
 *   createPostgresRuntimeFn?: typeof createPostgresRuntime,
 * }} options
 */
export async function runPostgresValidationScans(options) {
  const runtime = await (options.createPostgresRuntimeFn ?? createPostgresRuntime)(options.env, {
    autoMigrate: false,
    wafPostureServiceOptions: { connectorEncryptionKey: null },
    validationScanRuntimeConfig: options.runtimeConfig,
  });
  try {
    const service = runtime.services?.validationScans;
    for (const method of ['listDueValidationScans', 'listRunnableScans', 'dispatchDueValidationScans', 'advanceScan']) {
      if (typeof service?.[method] !== 'function') {
        throw new Error(`${RUNNER_NAME}: runtime validationScans.${method} is unavailable.`);
      }
    }
    const tenants = [];
    for (const tenantId of options.tenantIds) {
      const ctx = { tenantId, userId: options.workerId, role: 'system' };
      try {
        if (options.dryRun) {
          const due = await service.listDueValidationScans(ctx, { limit: options.limit });
          const runnable = await service.listRunnableScans(ctx, { limit: options.limit });
          tenants.push({
            tenant_id: tenantId,
            due_count: Array.isArray(due) ? due.length : 0,
            runnable_count: Array.isArray(runnable) ? runnable.length : 0,
            due: (Array.isArray(due) ? due : []).map((scan) => ({ scan_id: scan.id, scheduled_for: scan.scheduled_for })),
            runnable: (Array.isArray(runnable) ? runnable : []).map((scan) => ({
              scan_id: scan.id,
              status: scan.status,
              next_eligible_at: scan.next_eligible_at ?? null,
            })),
            dispatched: [],
            advanced: [],
          });
          continue;
        }
        const dispatched = await service.dispatchDueValidationScans(ctx, {
          workerId: options.workerId,
          limit: options.limit,
          runtimeConfig: options.runtimeConfig,
        });
        const dispatchRows = Array.isArray(dispatched) ? dispatched.map(summarizeScanDispatch) : [];
        const runnable = await service.listRunnableScans(ctx, { limit: options.limit });
        const advancedRows = [];
        for (const scan of Array.isArray(runnable) ? runnable : []) {
          // Isolate each scan: one scan throwing must not abort the remaining runnable scans (they
          // would otherwise fall through to the per-tenant catch and be dropped as a batch).
          try {
            const advanced = await service.advanceScan(ctx, scan.id, { runtimeConfig: options.runtimeConfig });
            advancedRows.push(summarizeScanAdvance(advanced ?? { scan_id: scan.id }));
          } catch (err) {
            advancedRows.push(summarizeScanAdvance({ scan_id: scan.id, error: safeCode(err?.code ?? err?.message, 'advance_failed') ?? 'advance_failed' }));
          }
        }
        const comparisons = await advanceEntryPathComparisonsForTenant(runtime.services?.entryPathComparisons, ctx, options.limit);
        tenants.push({
          tenant_id: tenantId,
          due_count: dispatchRows.length,
          runnable_count: advancedRows.length,
          dispatched: dispatchRows,
          advanced: advancedRows,
          ...(comparisons ? { comparisons } : {}),
          ...(Array.isArray(dispatched) ? {} : { error: safeCode(dispatched?.error, 'dispatch_failed') ?? 'dispatch_failed' }),
        });
      } catch {
        tenants.push({
          tenant_id: tenantId,
          due_count: 0,
          runnable_count: 0,
          dispatched: [],
          advanced: [],
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
export function buildValidationScanRunnerSummary(input) {
  return {
    schema_version: 1,
    artifact_type: 'validation_scan_runner_run',
    mode: input.dryRun ? 'dry_run' : 'apply',
    started_at: input.startedAt,
    finished_at: input.finishedAt,
    tenant_count: input.tenants.length,
    due_count: input.tenants.reduce((sum, tenant) => sum + Number(tenant.due_count ?? 0), 0),
    runnable_count: input.tenants.reduce((sum, tenant) => sum + Number(tenant.runnable_count ?? 0), 0),
    tenants: input.tenants,
    caveats: [
      'Invoke from an external scheduler; this CLI is not started by the API server.',
      'Explicit tenant scope is mandatory; cross-tenant enumeration is not performed.',
      'Apply mode requires signed-worker dispatch; every step start passes through the validated test-run service and its safety gates.',
      'Output is metadata-only and omits target values, credentials, probe payloads, and database URLs.',
    ],
  };
}

/**
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} env
 * @param {ReturnType<typeof resolveValidationScanRunnerConfig> & { ok: true }} config
 * @param {{ createPostgresRuntimeFn?: typeof createPostgresRuntime, writeFile?: typeof writeFileSync, mkdir?: typeof mkdirSync }} [deps]
 */
export async function runValidationScanRunner(env, config, deps = {}) {
  const startedAt = new Date().toISOString();
  const tenants = await runPostgresValidationScans({
    env,
    tenantIds: config.tenantIds,
    dryRun: config.dryRun,
    limit: config.limit,
    workerId: config.workerId,
    runtimeConfig: config.runtimeConfig,
    createPostgresRuntimeFn: deps.createPostgresRuntimeFn,
  });
  const summary = buildValidationScanRunnerSummary({
    dryRun: config.dryRun,
    startedAt,
    finishedAt: new Date().toISOString(),
    tenants,
  });
  if (config.out) {
    (deps.mkdir ?? mkdirSync)(path.dirname(path.resolve(config.out)), { recursive: true });
    (deps.writeFile ?? writeFileSync)(config.out, `${JSON.stringify(summary, null, 2)}\n`);
  }
  const failed = tenants.some((tenant) => tenant.error || tenant.comparisons?.error);
  return { summary, exitCode: failed ? 1 : 0 };
}

async function main() {
  let parsed;
  try {
    parsed = parseValidationScanRunnerArgs(process.argv);
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
    return;
  }
  if (parsed.help) {
    console.log(USAGE.trimEnd());
    return;
  }
  const config = resolveValidationScanRunnerConfig(process.env, parsed);
  if (!config.ok) {
    console.error(config.message);
    process.exitCode = 1;
    return;
  }
  try {
    const { summary, exitCode } = await runValidationScanRunner(process.env, config);
    console.log(`${RUNNER_NAME}: ok`);
    console.log(`  mode: ${summary.mode}`);
    console.log(`  tenant_count: ${summary.tenant_count}`);
    console.log(`  due_count: ${summary.due_count}`);
    console.log(`  runnable_count: ${summary.runnable_count}`);
    if (config.out) console.log(`  out: ${config.out}`);
    process.exitCode = exitCode;
  } catch (error) {
    console.error(`${RUNNER_NAME}: failed: ${redactDatabaseUrlInMessage(error, process.env)}`);
    process.exitCode = 1;
  }
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) main();
