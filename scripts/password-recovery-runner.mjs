#!/usr/bin/env node
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { writeFileSync } from 'node:fs';
import { redactDatabaseUrlInMessage } from '../src/lib/pgErrorRedact.mjs';
import { loadSecretEncryptionKey } from '../src/lib/secrets.mjs';
import { createPostgresRuntime } from '../src/persistence/postgres/runtime.mjs';

export const PASSWORD_RECOVERY_RUNNER_MIN_INTERVAL_MS = 250;
export const PASSWORD_RECOVERY_RUNNER_MAX_INTERVAL_MS = 60_000;
export const PASSWORD_RECOVERY_RUNNER_DEFAULT_INTERVAL_MS = 5_000;
const PASSWORD_RECOVERY_CYCLE_TIMEOUT_MS = 30_000;
export const PASSWORD_RECOVERY_CYCLE_TIMEOUT_CODE = 'password_recovery_cycle_timeout';

const USAGE = `password-recovery-runner: deliver explicitly scoped encrypted password reset outboxes.

Environment:
  Required:
    ASTRANULL_DATABASE_URL
    ASTRANULL_SECRET_ENCRYPTION_KEY
    ASTRANULL_PUBLIC_BASE_URL
  Tenant scope:
    ASTRANULL_PASSWORD_RECOVERY_TENANT_IDS (comma-separated; optional when --tenant-id is used)
  SMTP delivery:
    ASTRANULL_SMTP_HOST (blank/unset keeps retryable queue-only provider-unconfigured mode;
                         a real host enables delivery)

Options:
  --tenant-id <id>      Explicit tenant scope (repeatable; overrides the environment list)
  --once                Process at most one due item for each configured tenant, then exit
  --interval-ms <n>     Poll interval (${PASSWORD_RECOVERY_RUNNER_MIN_INTERVAL_MS}-${PASSWORD_RECOVERY_RUNNER_MAX_INTERVAL_MS}; default ${PASSWORD_RECOVERY_RUNNER_DEFAULT_INTERVAL_MS})
  --help                Show this message
`;

export function parsePasswordRecoveryRunnerArgs(argv) {
  const parsed = { tenantIds: [], once: false, intervalMs: null, help: false };
  const args = argv.slice(2);
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === '--help' || arg === '-h') {
      parsed.help = true;
      continue;
    }
    if (arg === '--once') {
      parsed.once = true;
      continue;
    }
    if (arg === '--tenant-id') {
      const value = args[index + 1];
      if (!value || value.startsWith('--')) {
        throw new Error('password-recovery-runner: --tenant-id requires a value.');
      }
      parsed.tenantIds.push(value.trim());
      index += 1;
      continue;
    }
    if (arg === '--interval-ms') {
      const value = args[index + 1];
      if (!value || value.startsWith('--')) {
        throw new Error('password-recovery-runner: --interval-ms requires an integer.');
      }
      parsed.intervalMs = Number(value);
      index += 1;
      continue;
    }
    throw new Error(`password-recovery-runner: unknown argument "${arg}".`);
  }
  return parsed;
}

export function parsePasswordRecoveryTenantIds(raw) {
  const values = Array.isArray(raw) ? raw : String(raw ?? '').split(',');
  const tenantIds = [];
  const seen = new Set();
  for (const value of values) {
    const tenantId = String(value ?? '').trim();
    if (!tenantId) continue;
    if (tenantId.length > 128 || !/^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(tenantId)) {
      throw new Error('password-recovery-runner: tenant ids must be 1-128 safe identifier characters.');
    }
    if (seen.has(tenantId)) continue;
    seen.add(tenantId);
    tenantIds.push(tenantId);
  }
  if (tenantIds.length === 0) {
    throw new Error(
      'password-recovery-runner: explicit tenant scope is required '
      + '(repeat --tenant-id or set ASTRANULL_PASSWORD_RECOVERY_TENANT_IDS).',
    );
  }
  if (tenantIds.length > 1_000) {
    throw new Error('password-recovery-runner: at most 1000 explicit tenant ids are allowed.');
  }
  return tenantIds;
}

function validPublicBaseUrl(raw) {
  try {
    const url = new URL(raw);
    const localHttp = url.protocol === 'http:'
      && (url.hostname === 'localhost' || url.hostname === '127.0.0.1');
    return (url.protocol === 'https:' || localHttp) && !url.username && !url.password;
  } catch {
    return false;
  }
}

function resolveIntervalMs(env, parsed) {
  const raw = parsed.intervalMs
    ?? (String(env.ASTRANULL_PASSWORD_RECOVERY_INTERVAL_MS ?? '').trim()
      || PASSWORD_RECOVERY_RUNNER_DEFAULT_INTERVAL_MS);
  const intervalMs = Number(raw);
  if (
    !Number.isInteger(intervalMs)
    || intervalMs < PASSWORD_RECOVERY_RUNNER_MIN_INTERVAL_MS
    || intervalMs > PASSWORD_RECOVERY_RUNNER_MAX_INTERVAL_MS
  ) {
    return null;
  }
  return intervalMs;
}

export function resolvePasswordRecoveryRunnerConfig(env, parsed) {
  if (!String(env.ASTRANULL_DATABASE_URL ?? '').trim()) {
    return { ok: false, message: 'password-recovery-runner: ASTRANULL_DATABASE_URL must be set.' };
  }
  try {
    loadSecretEncryptionKey(env, { required: true });
  } catch {
    return {
      ok: false,
      message: 'password-recovery-runner: ASTRANULL_SECRET_ENCRYPTION_KEY must be a valid 32-byte key.',
    };
  }
  const publicBaseUrl = String(env.ASTRANULL_PUBLIC_BASE_URL ?? '').trim();
  if (!publicBaseUrl || !validPublicBaseUrl(publicBaseUrl)) {
    return {
      ok: false,
      message: 'password-recovery-runner: ASTRANULL_PUBLIC_BASE_URL must be a valid HTTPS URL.',
    };
  }
  let tenantIds;
  try {
    tenantIds = parsePasswordRecoveryTenantIds(
      parsed.tenantIds?.length > 0
        ? parsed.tenantIds
        : env.ASTRANULL_PASSWORD_RECOVERY_TENANT_IDS,
    );
  } catch (error) {
    return {
      ok: false,
      message: error instanceof Error ? error.message : String(error),
    };
  }
  const intervalMs = resolveIntervalMs(env, parsed);
  if (intervalMs == null) {
    return {
      ok: false,
      message: `password-recovery-runner: interval must be an integer between ${PASSWORD_RECOVERY_RUNNER_MIN_INTERVAL_MS} and ${PASSWORD_RECOVERY_RUNNER_MAX_INTERVAL_MS}.`,
    };
  }
  return {
    ok: true,
    tenantIds,
    once: parsed.once === true,
    intervalMs,
    heartbeatFile: String(env.ASTRANULL_WORKER_HEARTBEAT_FILE ?? '').trim() || null,
    cycleTimeoutMs: PASSWORD_RECOVERY_CYCLE_TIMEOUT_MS,
  };
}

function withCycleDeadline(promise, timeoutMs) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      timer = setTimeout(() => {
        const error = new Error('password-recovery-runner: tenant cycle timed out.');
        error.code = PASSWORD_RECOVERY_CYCLE_TIMEOUT_CODE;
        reject(error);
      }, timeoutMs);
    }),
  ]).finally(() => clearTimeout(timer));
}

export function redactPasswordRecoveryRunnerError(error, env = process.env) {
  return redactDatabaseUrlInMessage(error, env);
}

/**
 * Runs an explicit set of tenant workers. Each processor call remains independently
 * tenant-scoped so FORCE RLS, rather than a cross-tenant worker query, guards every lease.
 * The signal target and runtime factory are injectable for unit tests.
 */
export async function runPasswordRecoveryRunner(env, config, deps = {}) {
  const tenantIds = parsePasswordRecoveryTenantIds(config.tenantIds);
  const createRuntime = deps.createPostgresRuntimeFn ?? createPostgresRuntime;
  const writeHeartbeat = deps.writeHeartbeatFn ?? writeFileSync;
  const signalTarget = deps.signalTarget ?? process;
  let stopping = false;
  let wake = null;
  const stop = () => {
    stopping = true;
    wake?.();
  };
  signalTarget.on?.('SIGTERM', stop);

  let runtime;
  let fatalCycleTimeout = false;
  try {
    runtime = await createRuntime(env, { autoMigrate: false });
    const processor = runtime.services?.passwordRecoveryDelivery?.processNext;
    if (typeof processor !== 'function') {
      throw new Error('password-recovery-runner: delivery processor is unavailable.');
    }

    let iterations = 0;
    let processed = 0;
    let lastStatus = 'idle';
    while (!stopping) {
      let cycleLastStatus = 'idle';
      for (const tenantId of tenantIds) {
        if (stopping) break;
        const result = await withCycleDeadline(
          processor(tenantId),
          config.cycleTimeoutMs ?? PASSWORD_RECOVERY_CYCLE_TIMEOUT_MS,
        );
        iterations += 1;
        const status = result?.status ?? 'unknown';
        if (status !== 'idle') {
          processed += 1;
          cycleLastStatus = status;
        }
        if (config.heartbeatFile) {
          writeHeartbeat(config.heartbeatFile, `${new Date().toISOString()}\n`, { mode: 0o600 });
        }
      }
      lastStatus = cycleLastStatus;
      if (config.once || stopping) break;

      if (typeof deps.sleep === 'function') {
        await deps.sleep(config.intervalMs);
      } else {
        await new Promise((resolve) => {
          const timer = setTimeout(() => {
            wake = null;
            resolve();
          }, config.intervalMs);
          wake = () => {
            clearTimeout(timer);
            wake = null;
            resolve();
          };
        });
      }
    }
    return { iterations, processed, lastStatus, stopped: stopping };
  } catch (error) {
    fatalCycleTimeout = error?.code === PASSWORD_RECOVERY_CYCLE_TIMEOUT_CODE;
    throw error;
  } finally {
    signalTarget.off?.('SIGTERM', stop);
    // The timed-out processor may still own a socket/client. Awaiting pool shutdown here can
    // keep the dead process alive indefinitely; the CLI's fatal handler exits immediately.
    if (!fatalCycleTimeout) await runtime?.close?.();
  }
}

async function main() {
  let parsed;
  try {
    parsed = parsePasswordRecoveryRunnerArgs(process.argv);
  } catch (error) {
    console.error(redactPasswordRecoveryRunnerError(error));
    process.exitCode = 1;
    return;
  }
  if (parsed.help) {
    console.log(USAGE.trimEnd());
    return;
  }
  const config = resolvePasswordRecoveryRunnerConfig(process.env, parsed);
  if (!config.ok) {
    console.error(config.message);
    process.exitCode = 1;
    return;
  }
  try {
    const summary = await runPasswordRecoveryRunner(process.env, config);
    console.log(`password-recovery-runner: stopped (${summary.lastStatus}, ${summary.processed} processed)`);
  } catch (error) {
    console.error(`password-recovery-runner: failed: ${redactPasswordRecoveryRunnerError(error)}`);
    if (error?.code === PASSWORD_RECOVERY_CYCLE_TIMEOUT_CODE) {
      process.exit(1);
    }
    process.exitCode = 1;
  }
}

const isMain = process.argv[1]
  && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) main();
