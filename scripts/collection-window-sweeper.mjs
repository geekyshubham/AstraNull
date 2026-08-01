#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { assertRunnerTenantScope } from '../src/lib/scheduledTenantScope.mjs';
import { redactDatabaseUrlInMessage } from '../src/lib/pgErrorRedact.mjs';
import { createPostgresRuntime } from '../src/persistence/postgres/runtime.mjs';

const RUNNER_NAME = 'collection-window-sweeper';

const DEFAULT_SWEEP_LIMIT = 100;
const MAX_SWEEP_LIMIT = 500;
const MIN_INTERVAL_MS = 1_000;

const USAGE = `${RUNNER_NAME}: finalize test runs whose bounded collection window expired.

Postgres mode has no read-path auto-finalizer, so a run whose collection deadline passes
with no client call stays 'collecting' forever and keeps holding its uniq_active_test_run
slot, blocking every later run for the same (tenant_id, target_group_id). This sweeper is
the client-independent finalizer for those runs.

Single-shot by default so it can be scheduled externally (cron, Kubernetes CronJob).
Pass --interval-ms to run as a long-lived periodic loop instead.

Environment:
  ASTRANULL_DATABASE_URL (required)

Options:
  --tenant-id <id>           Sweep one tenant (mutually exclusive with --tenant-ids-file)
  --tenant-ids-file <path>   JSON file: string[] or { "tenant_ids": string[] }
  --limit <n>                Max expired runs per tenant per pass (default: ${DEFAULT_SWEEP_LIMIT}, max: ${MAX_SWEEP_LIMIT})
  --interval-ms <n>          Run continuously, sweeping every <n> ms (min: ${MIN_INTERVAL_MS})
  --out <path>               Write metadata-only JSON summary to this path
  --help                     Show this message

Cross-tenant enumeration is refused under RLS, so an explicit tenant scope is required.
`;

/**
 * @param {string[]} argv
 */
export function parseCollectionWindowSweeperArgs(argv) {
  const args = argv.slice(2);
  /** @type {{ tenantId: string | null, tenantIdsFile: string | null, limit: number | null, intervalMs: number | null, out: string | null, help: boolean }} */
  const parsed = {
    tenantId: null,
    tenantIdsFile: null,
    limit: null,
    intervalMs: null,
    out: null,
    help: false,
  };

  const requireValue = (value, flag, kind) => {
    if (!value || value.startsWith('--')) {
      throw new Error(`${RUNNER_NAME}: ${flag} requires ${kind}.`);
    }
    return value;
  };

  const requireBoundedInt = (raw, flag, { min, max }) => {
    const n = Number(raw);
    if (!Number.isInteger(n) || n < min || (max != null && n > max)) {
      const bound = max == null ? `>= ${min}` : `between ${min} and ${max}`;
      throw new Error(`${RUNNER_NAME}: ${flag} must be an integer ${bound}.`);
    }
    return n;
  };

  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === '--help' || arg === '-h') {
      parsed.help = true;
      continue;
    }
    if (arg === '--tenant-id') {
      parsed.tenantId = requireValue(args[i + 1], arg, 'a value').trim();
      i += 1;
      continue;
    }
    if (arg === '--tenant-ids-file') {
      parsed.tenantIdsFile = requireValue(args[i + 1], arg, 'a path');
      i += 1;
      continue;
    }
    if (arg === '--limit') {
      parsed.limit = requireBoundedInt(requireValue(args[i + 1], arg, 'a value'), arg, {
        min: 1,
        max: MAX_SWEEP_LIMIT,
      });
      i += 1;
      continue;
    }
    if (arg === '--interval-ms') {
      parsed.intervalMs = requireBoundedInt(requireValue(args[i + 1], arg, 'a value'), arg, {
        min: MIN_INTERVAL_MS,
        max: null,
      });
      i += 1;
      continue;
    }
    if (arg === '--out') {
      parsed.out = requireValue(args[i + 1], arg, 'a path');
      i += 1;
      continue;
    }
    throw new Error(`${RUNNER_NAME}: unknown argument "${arg}".`);
  }

  return parsed;
}

/**
 * @param {unknown} raw
 * @returns {string[]}
 */
export function parseTenantIdsFromJson(raw) {
  let payload = raw;
  if (typeof raw === 'string') {
    payload = JSON.parse(raw);
  }
  let ids;
  if (Array.isArray(payload)) {
    ids = payload;
  } else if (payload && typeof payload === 'object' && Array.isArray(payload.tenant_ids)) {
    ids = payload.tenant_ids;
  } else {
    throw new Error(
      `${RUNNER_NAME}: tenant id file must be a JSON array or { "tenant_ids": [] }.`,
    );
  }

  const normalized = ids.map((id) => String(id ?? '').trim()).filter(Boolean);
  if (normalized.length === 0) {
    throw new Error(`${RUNNER_NAME}: tenant id list must not be empty.`);
  }
  return normalized;
}

/**
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} env
 * @param {ReturnType<typeof parseCollectionWindowSweeperArgs>} parsed
 * @param {{ readTenantIdsFile?: (path: string) => string }} [deps]
 */
export function resolveCollectionWindowSweeperConfig(env, parsed, deps = {}) {
  const readTenantIdsFile =
    deps.readTenantIdsFile ?? ((filePath) => readFileSync(filePath, 'utf8'));

  const databaseUrl = String(env.ASTRANULL_DATABASE_URL ?? '').trim();
  if (!databaseUrl) {
    return { ok: false, message: `${RUNNER_NAME}: ASTRANULL_DATABASE_URL must be set.` };
  }

  const hasTenantId = Boolean(parsed.tenantId);
  const hasFile = Boolean(parsed.tenantIdsFile);
  if (hasTenantId && hasFile) {
    return {
      ok: false,
      message: `${RUNNER_NAME}: use either --tenant-id or --tenant-ids-file, not both.`,
    };
  }

  /** @type {string[]} */
  let tenantIds = [];
  if (hasTenantId || hasFile) {
    try {
      tenantIds = hasTenantId
        ? parseTenantIdsFromJson([parsed.tenantId])
        : parseTenantIdsFromJson(readTenantIdsFile(parsed.tenantIdsFile));
    } catch (err) {
      return { ok: false, message: err instanceof Error ? err.message : String(err) };
    }
  }

  // Postgres mode refuses implicit cross-tenant enumeration under RLS.
  const scope = assertRunnerTenantScope(tenantIds, 'postgres', RUNNER_NAME);
  if (!scope?.ok) {
    return { ok: false, message: scope?.message ?? `${RUNNER_NAME}: tenant scope required.` };
  }

  return {
    ok: true,
    tenantIds: scope.tenantIds,
    limit: parsed.limit ?? DEFAULT_SWEEP_LIMIT,
    intervalMs: parsed.intervalMs ?? null,
    out: parsed.out ?? null,
  };
}

/**
 * @param {unknown} message
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} [env]
 */
export function redactCollectionWindowSweeperMessage(message, env = process.env) {
  return redactDatabaseUrlInMessage(message, env);
}

/**
 * One sweep pass over every tenant in scope. Never throws for a single tenant:
 * a failing tenant is recorded and the pass continues.
 *
 * @param {{
 *   services: Record<string, any>,
 *   tenantIds: string[],
 *   limit?: number,
 *   env?: NodeJS.ProcessEnv | Record<string, string | undefined>,
 * }} options
 */
export async function sweepExpiredCollectionWindows(options) {
  const { services, tenantIds } = options;
  const limit = options.limit ?? DEFAULT_SWEEP_LIMIT;
  /** @type {Record<string, unknown>[]} */
  const tenantResults = [];

  for (const tenantId of tenantIds) {
    const ctx = { tenantId, userId: RUNNER_NAME, role: 'system' };
    try {
      const summary = await services.testRuns.sweepExpiredCollectingRuns(ctx, { limit });
      tenantResults.push(summary);
    } catch (err) {
      tenantResults.push({
        tenant_id: tenantId,
        examined: 0,
        finalized: 0,
        skipped_locked: 0,
        skipped_not_finalizable: 0,
        errors: [
          { message: redactCollectionWindowSweeperMessage(err, options.env ?? process.env) },
        ],
        finalized_runs: [],
      });
    }
  }

  return tenantResults;
}

/**
 * @param {{ tenantResults: Record<string, any>[], startedAt: string, finishedAt: string, passes?: number }} input
 */
export function buildCollectionWindowSweeperSummary(input) {
  const totals = input.tenantResults.reduce(
    (acc, row) => ({
      examined: acc.examined + (row.examined ?? 0),
      finalized: acc.finalized + (row.finalized ?? 0),
      skipped_locked: acc.skipped_locked + (row.skipped_locked ?? 0),
      skipped_not_finalizable:
        acc.skipped_not_finalizable + (row.skipped_not_finalizable ?? 0),
      errors: acc.errors + (row.errors?.length ?? 0),
    }),
    { examined: 0, finalized: 0, skipped_locked: 0, skipped_not_finalizable: 0, errors: 0 },
  );

  return {
    schema_version: 1,
    artifact_type: 'collection_window_sweep_run',
    started_at: input.startedAt,
    finished_at: input.finishedAt,
    passes: input.passes ?? 1,
    tenant_count: input.tenantResults.length,
    totals,
    tenants: input.tenantResults,
    caveats: [
      'Summary contains metadata-only run ids and verdict labels.',
      'Exactly one verdict per run is guaranteed by uniq_verdict_per_test_run plus '
      + 'ON CONFLICT DO NOTHING; the advisory lock only avoids redundant work.',
    ],
  };
}

/**
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} env
 * @param {{ tenantIds: string[], limit: number, intervalMs: number | null, out: string | null }} config
 * @param {{
 *   createPostgresRuntimeFn?: typeof createPostgresRuntime,
 *   writeFile?: typeof writeFileSync,
 *   mkdir?: typeof mkdirSync,
 *   signal?: AbortSignal,
 * }} [deps]
 */
export async function runCollectionWindowSweeper(env, config, deps = {}) {
  const createRuntime = deps.createPostgresRuntimeFn ?? createPostgresRuntime;
  const writeFile = deps.writeFile ?? writeFileSync;
  const mkdir = deps.mkdir ?? mkdirSync;
  const startedAt = new Date().toISOString();

  const runtime = await createRuntime(env, { autoMigrate: false });
  /** @type {Record<string, unknown>[]} */
  let tenantResults = [];
  let passes = 0;

  try {
    const onePass = async () => {
      passes += 1;
      tenantResults = await sweepExpiredCollectionWindows({
        services: runtime.services,
        tenantIds: config.tenantIds,
        limit: config.limit,
        env,
      });
    };

    await onePass();

    if (config.intervalMs) {
      // Periodic mode: keep sweeping until aborted (SIGTERM/SIGINT).
      while (!deps.signal?.aborted) {
        const interrupted = await new Promise((resolve) => {
          const timer = setTimeout(() => resolve(false), config.intervalMs);
          deps.signal?.addEventListener(
            'abort',
            () => {
              clearTimeout(timer);
              resolve(true);
            },
            { once: true },
          );
        });
        if (interrupted) break;
        await onePass();
      }
    }
  } finally {
    await runtime.close();
  }

  const summary = buildCollectionWindowSweeperSummary({
    tenantResults,
    startedAt,
    finishedAt: new Date().toISOString(),
    passes,
  });

  if (config.out) {
    const target = path.resolve(config.out);
    mkdir(path.dirname(target), { recursive: true });
    writeFile(target, `${JSON.stringify(summary, null, 2)}\n`, 'utf8');
  }

  return summary;
}

async function main() {
  /** @type {ReturnType<typeof parseCollectionWindowSweeperArgs>} */
  let parsed;
  try {
    parsed = parseCollectionWindowSweeperArgs(process.argv);
  } catch (err) {
    console.error(redactCollectionWindowSweeperMessage(err, process.env));
    process.exitCode = 1;
    return;
  }

  if (parsed.help) {
    console.log(USAGE);
    return;
  }

  const config = resolveCollectionWindowSweeperConfig(process.env, parsed);
  if (!config.ok) {
    console.error(config.message);
    process.exitCode = 1;
    return;
  }

  const controller = new AbortController();
  const stop = () => controller.abort();
  process.on('SIGTERM', stop);
  process.on('SIGINT', stop);

  try {
    const summary = await runCollectionWindowSweeper(
      process.env,
      {
        tenantIds: config.tenantIds,
        limit: config.limit,
        intervalMs: config.intervalMs,
        out: config.out,
      },
      { signal: controller.signal },
    );

    console.log(`${RUNNER_NAME}: ok`);
    console.log(`  tenant_count: ${summary.tenant_count}`);
    console.log(`  examined: ${summary.totals.examined}`);
    console.log(`  finalized: ${summary.totals.finalized}`);
    console.log(`  skipped_locked: ${summary.totals.skipped_locked}`);
    if (summary.totals.errors > 0) {
      console.error(`  errors: ${summary.totals.errors}`);
      process.exitCode = 1;
    }
    if (config.out) {
      console.log(`  out: ${config.out}`);
    }
  } catch (err) {
    console.error(
      `${RUNNER_NAME}: failed: ${redactCollectionWindowSweeperMessage(err, process.env)}`,
    );
    process.exitCode = 1;
  }
}

const isMain =
  process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) {
  main();
}
