#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { isConnectorsEnabledForTenant, loadConnectorWorkerConfig } from '../src/config.mjs';
import { CONNECTOR_POLL_MAX_ATTEMPTS } from '../src/lib/connectorProviders/common.mjs';
import { shouldAttemptOutboundConnectorPoll } from '../src/lib/connectorProviders/pollWorker.mjs';
import { redactDatabaseUrlInMessage } from '../src/lib/pgErrorRedact.mjs';
import { createPostgresRuntime } from '../src/persistence/postgres/runtime.mjs';
import { pollConnector } from '../src/services/wafPosture.mjs';
import { getStore, persistStore } from '../src/store.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const DEFAULT_CONNECTOR_POLL_CONCURRENCY = 4;
const MIN_CONNECTOR_POLL_CONCURRENCY = 1;
const MAX_CONNECTOR_POLL_CONCURRENCY = 32;
const MAX_CONNECTOR_POLL_TENANTS = 32;

const USAGE = `connector-poll-runner: scheduled outbound read-only WAF/CDN connector polls.

This operator CLI is not a daemon. Schedule it externally (cron, Kubernetes CronJob, CI job).
Polls enabled connectors with vault-backed credentials and outbound provider workers only.

Environment (dev-json mode, default):
  ASTRANULL_WAF_POSTURE_ENABLED=1 (required)
  ASTRANULL_SECRET_ENCRYPTION_KEY (required for outbound polls with secret_id)
  ASTRANULL_DEV_DATA_DIR (optional; defaults to .data/)
  ASTRANULL_NO_PERSIST=1 (optional; skip persisting dev store)
  ASTRANULL_CONNECTOR_POLL_CONCURRENCY (optional; default ${DEFAULT_CONNECTOR_POLL_CONCURRENCY})
  ASTRANULL_CONNECTOR_POLL_MAX_ATTEMPTS (optional; default ${CONNECTOR_POLL_MAX_ATTEMPTS})

Environment (Postgres mode, when ASTRANULL_DATABASE_URL is set):
  ASTRANULL_DATABASE_URL (required for Postgres mode)
  ASTRANULL_WAF_POSTURE_ENABLED=1 (required)
  ASTRANULL_SECRET_ENCRYPTION_KEY (required for outbound polls with secret_id)

Options:
  --tenant-id <id>           Run for one tenant (mutually exclusive with --tenant-ids-file)
  --tenant-ids-file <path>   JSON file: string[] or { "tenant_ids": string[] }
  --all-tenants              Poll every tenant in dev-json store (default when tenant scope omitted; Postgres requires explicit scope)
  --concurrency <n>          Bounded parallel connector polls (default: env or ${DEFAULT_CONNECTOR_POLL_CONCURRENCY})
  --dry-run                  Summarize eligible connectors without outbound provider calls
  --queue-only               Reserve and sign durable jobs; never claim or perform provider egress
  --out <path>               Write metadata-only JSON summary to this path
  --help                     Show this message
`;

/**
 * @param {string[]} argv
 */
export function parseConnectorPollRunnerArgs(argv) {
  const args = argv.slice(2);
  /** @type {{ tenantId: string | null, tenantIdsFile: string | null, allTenants: boolean, concurrency: number | null, dryRun: boolean, queueOnly: boolean, out: string | null, help: boolean }} */
  const parsed = {
    tenantId: null,
    tenantIdsFile: null,
    allTenants: false,
    concurrency: null,
    dryRun: false,
    queueOnly: false,
    out: null,
    help: false,
  };

  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === '--help' || arg === '-h') {
      parsed.help = true;
      continue;
    }
    if (arg === '--dry-run') {
      parsed.dryRun = true;
      continue;
    }
    if (arg === '--queue-only') {
      parsed.queueOnly = true;
      continue;
    }
    if (arg === '--all-tenants') {
      parsed.allTenants = true;
      continue;
    }
    if (arg === '--tenant-id') {
      const value = args[i + 1];
      if (!value || value.startsWith('--')) {
        throw new Error('connector-poll-runner: --tenant-id requires a value.');
      }
      parsed.tenantId = value.trim();
      i += 1;
      continue;
    }
    if (arg === '--tenant-ids-file') {
      const value = args[i + 1];
      if (!value || value.startsWith('--')) {
        throw new Error('connector-poll-runner: --tenant-ids-file requires a path.');
      }
      parsed.tenantIdsFile = value;
      i += 1;
      continue;
    }
    if (arg === '--concurrency') {
      const value = args[i + 1];
      if (!value || value.startsWith('--')) {
        throw new Error('connector-poll-runner: --concurrency requires a positive integer.');
      }
      const concurrency = Number.parseInt(value, 10);
      if (!Number.isInteger(concurrency) || concurrency < MIN_CONNECTOR_POLL_CONCURRENCY) {
        throw new Error('connector-poll-runner: --concurrency must be a positive integer.');
      }
      parsed.concurrency = concurrency;
      i += 1;
      continue;
    }
    if (arg === '--out') {
      const value = args[i + 1];
      if (!value || value.startsWith('--')) {
        throw new Error('connector-poll-runner: --out requires a path.');
      }
      parsed.out = value;
      i += 1;
      continue;
    }
    throw new Error(`connector-poll-runner: unknown argument "${arg}".`);
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
      'connector-poll-runner: tenant id file must be a JSON array or { "tenant_ids": [] }.',
    );
  }

  const normalized = ids.map((id) => String(id ?? '').trim()).filter(Boolean);
  const unique = [...new Set(normalized)];
  if (unique.length === 0) {
    throw new Error('connector-poll-runner: tenant id list must not be empty.');
  }
  if (unique.length > MAX_CONNECTOR_POLL_TENANTS) {
    throw new Error(`connector-poll-runner: tenant id list must contain at most ${MAX_CONNECTOR_POLL_TENANTS} tenants.`);
  }
  return unique;
}

/**
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} env
 * @param {number | null} cliConcurrency
 */
export function resolveConnectorPollConcurrency(env, cliConcurrency = null) {
  if (cliConcurrency != null) {
    if (
      !Number.isInteger(cliConcurrency)
      || cliConcurrency < MIN_CONNECTOR_POLL_CONCURRENCY
      || cliConcurrency > MAX_CONNECTOR_POLL_CONCURRENCY
    ) {
      throw new Error(
        `connector-poll-runner: concurrency must be an integer between ${MIN_CONNECTOR_POLL_CONCURRENCY} and ${MAX_CONNECTOR_POLL_CONCURRENCY}.`,
      );
    }
    return cliConcurrency;
  }

  const raw = String(env.ASTRANULL_CONNECTOR_POLL_CONCURRENCY ?? '').trim();
  if (!raw) return DEFAULT_CONNECTOR_POLL_CONCURRENCY;
  const parsed = Number.parseInt(raw, 10);
  if (
    !Number.isInteger(parsed)
    || parsed < MIN_CONNECTOR_POLL_CONCURRENCY
    || parsed > MAX_CONNECTOR_POLL_CONCURRENCY
  ) {
    throw new Error(
      `connector-poll-runner: ASTRANULL_CONNECTOR_POLL_CONCURRENCY must be an integer between ${MIN_CONNECTOR_POLL_CONCURRENCY} and ${MAX_CONNECTOR_POLL_CONCURRENCY}.`,
    );
  }
  return parsed;
}

/**
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} env
 */
export function resolveConnectorPollMaxAttempts(env) {
  const raw = String(env.ASTRANULL_CONNECTOR_POLL_MAX_ATTEMPTS ?? '').trim();
  if (!raw) return CONNECTOR_POLL_MAX_ATTEMPTS;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > CONNECTOR_POLL_MAX_ATTEMPTS) {
    throw new Error(`connector-poll-runner: ASTRANULL_CONNECTOR_POLL_MAX_ATTEMPTS must be an integer between 1 and ${CONNECTOR_POLL_MAX_ATTEMPTS}.`);
  }
  return parsed;
}

/**
 * @param {unknown} connector
 */
export function isOutboundPollEligibleConnector(connector) {
  return shouldAttemptOutboundConnectorPoll(connector, {});
}

/**
 * @param {unknown} store
 * @param {string[]} tenantIds
 */
export function listEligibleConnectorsFromStore(store, tenantIds) {
  return (store?.wafConnectors ?? []).filter((connector) => {
    if (tenantIds.length > 0 && !tenantIds.includes(connector.tenant_id)) return false;
    return isOutboundPollEligibleConnector(connector);
  });
}

/**
 * @param {string[]} tenantIds
 * @param {unknown} store
 */
export function resolveTenantIdsFromConnectors(tenantIds, store) {
  if (tenantIds.length > 0) return tenantIds;
  return [...new Set(
    (store?.wafConnectors ?? [])
      .filter((connector) => isOutboundPollEligibleConnector(connector))
      .map((connector) => connector.tenant_id)
      .filter(Boolean),
  )];
}

/**
 * @param {unknown} store
 * @param {string} tenantId
 */
export function summarizeTenantConnectorPollScope(store, tenantId) {
  const eligible = listEligibleConnectorsFromStore(store, [tenantId]);
  const providers = [...new Set(eligible.map((connector) => connector.provider).filter(Boolean))].sort();
  return {
    tenant_id: tenantId,
    eligible_connectors_count: eligible.length,
    providers,
  };
}

/**
 * @param {unknown} outcome
 */
export function toMetadataOnlyPollOutcome(outcome) {
  if (!outcome || typeof outcome !== 'object') return null;
  if (outcome.error) {
    return {
      error: outcome.error,
      status: outcome.status ?? null,
      health_status: outcome.health?.status ?? null,
      health_code: outcome.health?.health_code ?? outcome.error,
      attempts: outcome.health?.attempts ?? null,
    };
  }
  const pollJob = outcome.poll_job ?? null;
  return {
    poll_status: pollJob?.status ?? null,
    snapshot_count: pollJob?.snapshot_count ?? (Array.isArray(outcome.snapshots) ? outcome.snapshots.length : 0),
    health_status: pollJob?.health?.status ?? null,
    health_code: pollJob?.health?.health_code ?? null,
    attempts: pollJob?.health?.attempts ?? pollJob?.attempts ?? null,
  };
}

/**
 * @param {Record<string, unknown>} connectorResult
 */
export function toMetadataOnlyConnectorPollResult(connectorResult) {
  return {
    tenant_id: connectorResult.tenant_id,
    connector_id: connectorResult.connector_id,
    provider: connectorResult.provider,
    dry_run: connectorResult.dry_run ?? false,
    scope: connectorResult.scope ?? null,
    poll_result: connectorResult.poll_result ?? null,
    ...(connectorResult.error ? { error: connectorResult.error } : {}),
  };
}

/**
 * @param {Array<unknown>} items
 * @param {number} concurrency
 * @param {(item: unknown, index: number) => Promise<unknown>} worker
 */
export async function runWithBoundedConcurrency(items, concurrency, worker) {
  if (!Array.isArray(items) || items.length === 0) return [];
  const limit = Math.max(
    MIN_CONNECTOR_POLL_CONCURRENCY,
    Math.min(MAX_CONNECTOR_POLL_CONCURRENCY, Math.floor(concurrency)),
  );
  /** @type {unknown[]} */
  const results = new Array(items.length);
  let nextIndex = 0;

  async function runSlot() {
    while (true) {
      const index = nextIndex;
      nextIndex += 1;
      if (index >= items.length) return;
      results[index] = await worker(items[index], index);
    }
  }

  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, () => runSlot()),
  );
  return results;
}

/**
 * @param {{
 *   dryRun: boolean,
 *   connectorResults: Record<string, unknown>[],
 *   startedAt: string,
 *   finishedAt: string,
 *   persistenceMode: string,
 *   concurrency: number,
 *   queueOnly?: boolean,
 * }} input
 */
export function buildConnectorPollRunnerSummary(input) {
  const polled = input.connectorResults.filter((row) => !row.dry_run);
  const pollOutcomes = polled
    .map((row) => row.poll_result)
    .filter(Boolean);
  const queued = pollOutcomes.filter((row) => row?.poll_status === 'pending');
  const completed = pollOutcomes.filter((row) => row?.poll_status === 'completed');
  return {
    schema_version: 1,
    artifact_type: 'connector_poll_runtime_run',
    persistence_mode: input.persistenceMode,
    dry_run: input.dryRun,
    queue_only: Boolean(input.queueOnly),
    no_work: !input.dryRun && input.connectorResults.length === 0,
    started_at: input.startedAt,
    finished_at: input.finishedAt,
    concurrency: input.concurrency,
    tenant_count: new Set(input.connectorResults.map((row) => row.tenant_id).filter(Boolean)).size,
    connector_count: input.connectorResults.length,
    connectors_polled: input.dryRun || input.queueOnly ? 0 : polled.length,
    connectors_queued: input.dryRun ? 0 : queued.length,
    connectors_completed: input.dryRun ? 0 : completed.length,
    connectors_failed: input.dryRun
      ? 0
      : polled.filter((row) => row.error || row.poll_result?.error).length,
    total_snapshots: input.dryRun
      ? 0
      : pollOutcomes.reduce((sum, row) => sum + Number(row?.snapshot_count ?? 0), 0),
    connectors: input.connectorResults.map((row) => toMetadataOnlyConnectorPollResult(row)),
    caveats: [
      'Invoke this CLI from external scheduling only; it is not started with the API server.',
      'Outbound polls use read-only provider workers with bounded retry/backoff and metadata-only snapshots.',
      'Summary is metadata-only: no target URLs, raw config, secrets, tokens, or database URLs.',
      'Dry-run reports eligible connector scope without outbound provider calls.',
      'Postgres mode requires runtime.services.wafPosture.pollConnector(); otherwise use dev-json store mode.',
    ],
  };
}

/**
 * @param {unknown} message
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} [env]
 */
export function redactConnectorPollRunnerMessage(message, env = process.env) {
  return redactDatabaseUrlInMessage(message, env);
}

/**
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} env
 * @param {ReturnType<typeof parseConnectorPollRunnerArgs>} parsed
 * @param {{ readTenantIdsFile?: (path: string) => string, loadRuntimeConfigFn?: typeof loadConnectorWorkerConfig }} [deps]
 */
export function resolveConnectorPollRunnerConfig(env, parsed, deps = {}) {
  const readTenantIdsFile = deps.readTenantIdsFile ?? ((filePath) => readFileSync(filePath, 'utf8'));
  const loadConfig = deps.loadRuntimeConfigFn ?? loadConnectorWorkerConfig;

  const hasTenantId = Boolean(parsed.tenantId);
  const hasFile = Boolean(parsed.tenantIdsFile);
  if (hasTenantId && hasFile) {
    return {
      ok: false,
      message: 'connector-poll-runner: use either --tenant-id or --tenant-ids-file, not both.',
    };
  }

  /** @type {string[] | null} */
  let tenantIds = null;
  if (hasTenantId) {
    try {
      tenantIds = parseTenantIdsFromJson([parsed.tenantId]);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return { ok: false, message };
    }
  } else if (hasFile) {
    try {
      tenantIds = parseTenantIdsFromJson(readTenantIdsFile(parsed.tenantIdsFile));
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return { ok: false, message };
    }
  } else if (String(env.ASTRANULL_CONNECTOR_POLL_TENANT_IDS ?? '').trim()) {
    try {
      tenantIds = parseTenantIdsFromJson(
        String(env.ASTRANULL_CONNECTOR_POLL_TENANT_IDS).split(',').map((value) => value.trim()),
      );
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return { ok: false, message };
    }
  }

  /** @type {Record<string, unknown>} */
  let runtimeConfig;
  try {
    runtimeConfig = loadConfig(env, {
      verificationOnly: !parsed.queueOnly,
      signingOnly: parsed.queueOnly,
    });
  } catch (err) {
    const message = redactConnectorPollRunnerMessage(err, env);
    return {
      ok: false,
      message: `connector-poll-runner: ${message}`,
    };
  }

  if (runtimeConfig.featureFlags?.wafPostureEnabled !== true) {
    return {
      ok: false,
      message: 'connector-poll-runner: WAF posture feature must be enabled (ASTRANULL_WAF_POSTURE_ENABLED=1).',
    };
  }

  let concurrency;
  let maxAttempts;
  try {
    concurrency = resolveConnectorPollConcurrency(env, parsed.concurrency);
    maxAttempts = resolveConnectorPollMaxAttempts(env);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { ok: false, message };
  }

  const databaseUrl = String(env.ASTRANULL_DATABASE_URL ?? '').trim();
  const persistenceMode = databaseUrl ? 'postgres' : 'dev-json';
  const workerId = String(env.ASTRANULL_CONNECTOR_WORKER_ID ?? '').trim();

  if (parsed.queueOnly && persistenceMode !== 'postgres') {
    return {
      ok: false,
      message: 'connector-poll-runner: --queue-only requires Postgres durable job persistence.',
    };
  }

  if (persistenceMode === 'postgres' && env.NODE_ENV === 'production' && !parsed.queueOnly && !workerId) {
    return {
      ok: false,
      message: 'connector-poll-runner: ASTRANULL_CONNECTOR_WORKER_ID is required in production Postgres mode.',
    };
  }

  if (persistenceMode === 'postgres' && (tenantIds === null || tenantIds.length === 0)) {
    return {
      ok: false,
      message:
        'connector-poll-runner: Postgres mode requires explicit tenant scope '
        + '(--tenant-id or --tenant-ids-file). Cross-tenant enumeration is not permitted under RLS.',
    };
  }

  return {
    ok: true,
    tenantIds,
    allTenants: parsed.allTenants || tenantIds === null,
    dryRun: Boolean(parsed.dryRun),
    queueOnly: Boolean(parsed.queueOnly),
    out: parsed.out ?? null,
    runtimeConfig,
    persistenceMode,
    databaseUrl: databaseUrl || null,
    workerId: workerId || 'connector-poll-runner',
    concurrency,
    maxAttempts,
  };
}

/**
 * @param {{
 *   tenantIds: string[],
 *   dryRun: boolean,
 *   concurrency: number,
 *   maxAttempts: number,
 *   getStoreFn?: typeof getStore,
 *   pollConnectorFn?: typeof pollConnector,
 *   fetchFn?: typeof fetch,
 *   secretResolver?: (ctx: unknown, secretId: string, provider: string) => Promise<unknown>,
 * }} options
 */
export async function runDevJsonConnectorPolls(options) {
  const getStoreImpl = options.getStoreFn ?? getStore;
  const pollConnectorImpl = options.pollConnectorFn ?? pollConnector;
  const store = getStoreImpl();
  const tenantIds = resolveTenantIdsFromConnectors(options.tenantIds, store);
  const auditContext = { userId: 'connector-poll-runner', role: 'system' };

  if (options.dryRun) {
    return tenantIds.map((tenantId) => ({
      tenant_id: tenantId,
      connector_id: null,
      provider: null,
      dry_run: true,
      scope: summarizeTenantConnectorPollScope(store, tenantId),
      poll_result: null,
    }));
  }

  const eligible = listEligibleConnectorsFromStore(store, tenantIds);
  const tasks = eligible.map((connector) => ({
    tenant_id: connector.tenant_id,
    connector_id: connector.id,
    provider: connector.provider,
  }));

  return runWithBoundedConcurrency(tasks, options.concurrency, async (task) => {
    const ctx = { ...auditContext, tenantId: task.tenant_id };
    try {
      const outcome = await pollConnectorImpl(ctx, task.connector_id, {}, {
        maxAttempts: options.maxAttempts,
        fetchFn: options.fetchFn,
        secretResolver: options.secretResolver,
        executeOutbound: true,
      });
      if (outcome?.error) {
        return {
          tenant_id: task.tenant_id,
          connector_id: task.connector_id,
          provider: task.provider,
          dry_run: false,
          error: outcome.error,
          poll_result: toMetadataOnlyPollOutcome(outcome),
        };
      }
      return {
        tenant_id: task.tenant_id,
        connector_id: task.connector_id,
        provider: task.provider,
        dry_run: false,
        poll_result: toMetadataOnlyPollOutcome(outcome),
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        tenant_id: task.tenant_id,
        connector_id: task.connector_id,
        provider: task.provider,
        dry_run: false,
        error: message,
        poll_result: null,
      };
    }
  });
}

/**
 * @param {string[]} tenantIds
 * @param {'postgres' | 'dev-json'} persistenceMode
 */
export function resolveConnectorPollTenantIds(tenantIds, persistenceMode) {
  if (persistenceMode !== 'postgres') return tenantIds;
  if (tenantIds.length > 0) return tenantIds;
  throw new Error(
    'connector-poll-runner: Postgres mode requires explicit tenant scope '
    + '(--tenant-id or --tenant-ids-file). Cross-tenant enumeration is not permitted under RLS.',
  );
}

/**
 * @param {string[]} tenantIds
 * @param {number} seed
 */
export function rotateConnectorPollTenantIds(tenantIds, seed) {
  if (tenantIds.length < 2) return [...tenantIds];
  const offset = Math.abs(Math.trunc(seed)) % tenantIds.length;
  return [...tenantIds.slice(offset), ...tenantIds.slice(0, offset)];
}

/**
 * @param {{ tenant_id: string, connector_id: string, provider: string }[][]} perTenant
 * @param {number} limit
 */
export function interleaveConnectorPollTasks(perTenant, limit) {
  const tasks = [];
  for (let index = 0; tasks.length < limit; index += 1) {
    let added = false;
    for (const candidates of perTenant) {
      if (candidates[index]) {
        tasks.push(candidates[index]);
        added = true;
        if (tasks.length >= limit) break;
      }
    }
    if (!added) break;
  }
  return tasks;
}

/**
 * @param {{
 *   env: NodeJS.ProcessEnv | Record<string, string | undefined>,
 *   tenantIds: string[],
 *   dryRun: boolean,
 *   queueOnly?: boolean,
 *   concurrency: number,
 *   maxAttempts: number,
 *   workerId?: string,
 *   runtimeConfig?: Record<string, unknown>,
 *   rotationSeed?: number,
 *   createPostgresRuntimeFn?: typeof createPostgresRuntime,
 *   fetchFn?: typeof fetch,
 *   secretResolver?: (ctx: unknown, secretId: string, provider: string) => Promise<unknown>,
 * }} options
 */
export async function runPostgresConnectorPolls(options) {
  const scopedTenantIds = resolveConnectorPollTenantIds(options.tenantIds, 'postgres');
  let tenantIds = options.runtimeConfig
    ? scopedTenantIds.filter((tenantId) => isConnectorsEnabledForTenant(options.runtimeConfig, tenantId))
    : scopedTenantIds;
  if (scopedTenantIds.length === 0 || (!options.queueOnly && tenantIds.length === 0)) return [];

  const createRuntime = options.createPostgresRuntimeFn ?? createPostgresRuntime;
  const runtime = await createRuntime(options.env, {
    autoMigrate: false,
    wafPostureServiceOptions: options.queueOnly
      ? {
          connectorEncryptionKey: null,
          requireConnectorJobSigner: true,
          requireConnectorJobVerifier: false,
        }
      : {
          requireConnectorJobSigner: false,
          requireConnectorJobVerifier: true,
        },
  });

  try {
    const wafPosture = runtime.services?.wafPosture;
    if (!wafPosture || typeof wafPosture.pollConnector !== 'function') {
      throw new Error('postgres runtime is missing services.wafPosture.pollConnector().');
    }
    if (options.dryRun && typeof wafPosture.listConnectors !== 'function') {
      throw new Error('postgres runtime is missing services.wafPosture.listConnectors().');
    }
    if (!options.dryRun && options.queueOnly
      && typeof wafPosture.listConnectorPollScheduleCandidates !== 'function') {
      throw new Error('postgres runtime is missing services.wafPosture.listConnectorPollScheduleCandidates().');
    }
    if (!options.dryRun && options.queueOnly
      && typeof wafPosture.setConnectorFeatureState !== 'function') {
      throw new Error('postgres runtime is missing services.wafPosture.setConnectorFeatureState().');
    }
    if (!options.dryRun && !options.queueOnly
      && typeof wafPosture.listPendingConnectorPollConnectors !== 'function') {
      throw new Error('postgres runtime is missing services.wafPosture.listPendingConnectorPollConnectors().');
    }

    const auditContext = { userId: 'connector-poll-runner', role: 'system' };

    if (!options.dryRun && options.queueOnly && options.runtimeConfig) {
      for (const tenantId of scopedTenantIds) {
        const enabled = isConnectorsEnabledForTenant(options.runtimeConfig, tenantId);
        await wafPosture.setConnectorFeatureState(
          { ...auditContext, tenantId },
          enabled,
        );
      }
      tenantIds = scopedTenantIds.filter(
        (tenantId) => isConnectorsEnabledForTenant(options.runtimeConfig, tenantId),
      );
      if (tenantIds.length === 0) return [];
    }

    if (options.dryRun) {
      /** @type {Record<string, unknown>[]} */
      const connectorResults = [];
      for (const tenantId of tenantIds) {
        const ctx = { ...auditContext, tenantId };
        const connectors = await wafPosture.listConnectors(ctx);
        const eligible = connectors.filter((connector) => isOutboundPollEligibleConnector(connector));
        connectorResults.push({
          tenant_id: tenantId,
          connector_id: null,
          provider: null,
          dry_run: true,
          scope: {
            tenant_id: tenantId,
            eligible_connectors_count: eligible.length,
            providers: [...new Set(eligible.map((connector) => connector.provider).filter(Boolean))].sort(),
          },
          poll_result: null,
        });
      }
      return connectorResults;
    }

    const rotationSeed = options.rotationSeed ?? Math.floor(Date.now() / 60_000);
    const orderedTenantIds = rotateConnectorPollTenantIds(tenantIds, rotationSeed);
    const listCandidates = options.queueOnly
      ? wafPosture.listConnectorPollScheduleCandidates.bind(wafPosture)
      : wafPosture.listPendingConnectorPollConnectors.bind(wafPosture);
    /** @type {{ tenant_id: string, connector_id: string, provider: string }[][]} */
    const perTenant = [];
    for (const tenantId of orderedTenantIds) {
      const ctx = { ...auditContext, tenantId };
      const candidates = await listCandidates(ctx, { limit: options.concurrency });
      perTenant.push(candidates.map((connector) => ({
        tenant_id: tenantId,
        connector_id: connector.connector_id,
        provider: connector.provider,
      })));
    }
    const tasks = interleaveConnectorPollTasks(perTenant, options.concurrency);

    return runWithBoundedConcurrency(tasks, options.concurrency, async (task) => {
      const ctx = { ...auditContext, tenantId: task.tenant_id };
      try {
        const pollOptions = options.queueOnly
          ? { executeOutbound: false, scheduled: true, maxAttempts: options.maxAttempts }
          : {
              maxAttempts: options.maxAttempts,
              fetchFn: options.fetchFn,
              secretResolver: options.secretResolver,
              executeOutbound: true,
              workerId: options.workerId ?? 'connector-poll-runner',
            };
        const outcome = await wafPosture.pollConnector(ctx, task.connector_id, {}, pollOptions);
        if (['connector_poll_in_progress', 'connector_poll_deferred'].includes(outcome?.error)) {
          return {
            tenant_id: task.tenant_id,
            connector_id: task.connector_id,
            provider: task.provider,
            dry_run: false,
            poll_result: {
              poll_status: 'idle',
              snapshot_count: 0,
              health_status: null,
              health_code: null,
              attempts: null,
            },
          };
        }
        if (outcome?.error) {
          return {
            tenant_id: task.tenant_id,
            connector_id: task.connector_id,
            provider: task.provider,
            dry_run: false,
            error: outcome.error,
            poll_result: toMetadataOnlyPollOutcome(outcome),
          };
        }
        return {
          tenant_id: task.tenant_id,
          connector_id: task.connector_id,
          provider: task.provider,
          dry_run: false,
          poll_result: toMetadataOnlyPollOutcome(outcome),
        };
      } catch (err) {
        const message = redactConnectorPollRunnerMessage(err, options.env);
        return {
          tenant_id: task.tenant_id,
          connector_id: task.connector_id,
          provider: task.provider,
          dry_run: false,
          error: message,
          poll_result: null,
        };
      }
    });
  } finally {
    await runtime.close();
  }
}

/**
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} env
 * @param {{
 *   dryRun: boolean,
 *   tenantIds: string[] | null,
 *   allTenants: boolean,
 *   out: string | null,
 *   persistenceMode: string,
 *   queueOnly?: boolean,
 *   concurrency: number,
 *   maxAttempts: number,
 *   workerId?: string,
 *   runtimeConfig?: Record<string, unknown>,
 * }} config
 * @param {{
 *   createPostgresRuntimeFn?: typeof createPostgresRuntime,
 *   getStoreFn?: typeof getStore,
 *   pollConnectorFn?: typeof pollConnector,
 *   persistStoreFn?: typeof persistStore,
 *   writeFile?: typeof writeFileSync,
 *   mkdir?: typeof mkdirSync,
 *   fetchFn?: typeof fetch,
 *   secretResolver?: (ctx: unknown, secretId: string, provider: string) => Promise<unknown>,
 * }} [deps]
 */
export async function runConnectorPollRunner(env, config, deps = {}) {
  const writeFile = deps.writeFile ?? writeFileSync;
  const mkdir = deps.mkdir ?? mkdirSync;
  const startedAt = new Date().toISOString();
  const tenantIds = config.tenantIds ?? [];

  let connectorResults;
  if (config.persistenceMode === 'postgres') {
    connectorResults = await runPostgresConnectorPolls({
      env,
      tenantIds: config.allTenants ? [] : tenantIds,
      dryRun: config.dryRun,
      queueOnly: config.queueOnly,
      concurrency: config.concurrency,
      maxAttempts: config.maxAttempts,
      workerId: config.workerId,
      runtimeConfig: config.runtimeConfig,
      createPostgresRuntimeFn: deps.createPostgresRuntimeFn,
      fetchFn: deps.fetchFn,
      secretResolver: deps.secretResolver,
    });
  } else {
    connectorResults = await runDevJsonConnectorPolls({
      tenantIds: config.allTenants ? [] : tenantIds,
      dryRun: config.dryRun,
      concurrency: config.concurrency,
      maxAttempts: config.maxAttempts,
      getStoreFn: deps.getStoreFn,
      pollConnectorFn: deps.pollConnectorFn,
      fetchFn: deps.fetchFn,
      secretResolver: deps.secretResolver,
    });
    if (!config.dryRun) {
      (deps.persistStoreFn ?? persistStore)();
    }
  }

  const finishedAt = new Date().toISOString();
  const summary = buildConnectorPollRunnerSummary({
    dryRun: config.dryRun,
    connectorResults,
    startedAt,
    finishedAt,
    persistenceMode: config.persistenceMode,
    concurrency: config.concurrency,
    queueOnly: config.queueOnly,
  });

  if (config.out) {
    mkdir(path.dirname(path.resolve(config.out)), { recursive: true });
    writeFile(config.out, `${JSON.stringify(summary, null, 2)}\n`);
  }

  const connectorFailures = connectorResults.some((row) => row.error || row.poll_result?.error);

  return {
    summary,
    exitCode: connectorFailures ? 1 : 0,
  };
}

/**
 * @param {{
 *   argv?: string[],
 *   env?: NodeJS.ProcessEnv | Record<string, string | undefined>,
 *   runConnectorPollRunnerFn?: typeof runConnectorPollRunner,
 *   log?: (...args: unknown[]) => void,
 *   error?: (...args: unknown[]) => void,
 *   setExitCode?: (code: number) => void,
 * }} [deps]
 */
export async function main(deps = {}) {
  const argv = deps.argv ?? process.argv;
  const env = deps.env ?? process.env;
  const runRunner = deps.runConnectorPollRunnerFn ?? runConnectorPollRunner;
  const log = deps.log ?? console.log;
  const logError = deps.error ?? console.error;
  const setExitCode = deps.setExitCode ?? ((code) => { process.exitCode = code; });
  const parsed = parseConnectorPollRunnerArgs(argv);
  if (parsed.help) {
    log(USAGE.trimEnd());
    return;
  }

  const config = resolveConnectorPollRunnerConfig(env, parsed);
  if (!config.ok) {
    logError(config.message);
    setExitCode(1);
    return;
  }

  try {
    const { summary, exitCode } = await runRunner(env, {
      dryRun: config.dryRun,
      tenantIds: config.tenantIds,
      allTenants: config.allTenants,
      out: config.out,
      persistenceMode: config.persistenceMode,
      queueOnly: config.queueOnly,
      runtimeConfig: config.runtimeConfig,
      concurrency: config.concurrency,
      maxAttempts: config.maxAttempts,
      workerId: config.workerId,
    });

    log('connector-poll-runner: ok');
    log(`  mode: ${summary.dry_run ? 'dry_run' : summary.queue_only ? 'queue_only' : 'worker'}`);
    log(`  persistence: ${summary.persistence_mode}`);
    log(`  concurrency: ${summary.concurrency}`);
    log(`  connector_count: ${summary.connector_count}`);
    if (!summary.dry_run) {
      log(`  no_work: ${summary.no_work}`);
      log(`  connectors_queued: ${summary.connectors_queued}`);
      log(`  connectors_completed: ${summary.connectors_completed}`);
      log(`  connectors_polled: ${summary.connectors_polled}`);
      log(`  connectors_failed: ${summary.connectors_failed}`);
      log(`  total_snapshots: ${summary.total_snapshots}`);
    }
    if (config.out) {
      log(`  out: ${config.out}`);
    }
    setExitCode(exitCode);
  } catch (err) {
    const message = redactConnectorPollRunnerMessage(err, env);
    logError(`connector-poll-runner: failed: ${message}`);
    setExitCode(1);
  }
}

const isMain =
  process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) {
  main();
}