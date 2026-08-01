#!/usr/bin/env node
/**
 * Railway hosted-staging bootstrap: migrate Postgres, seed demo tenant, start probe worker + API.
 */
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { applyBundledStagingOidcEnvDefaults } from '../src/lib/bundledStagingOidc.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');

/**
 * @param {string[]} args
 */
function runNode(args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, args, {
      cwd: REPO_ROOT,
      env: options.env ?? process.env,
      stdio: options.stdio ?? 'inherit',
      detached: options.detached === true,
    });
    child.on('error', reject);
    if (options.detached) {
      child.unref();
      resolve(child);
      return;
    }
    child.on('exit', (code, signal) => {
      if (code === 0) {
        resolve();
        return;
      }
      reject(new Error(`node ${args.join(' ')} failed (code=${code ?? 'null'}, signal=${signal ?? 'null'})`));
    });
  });
}

export function resolveProbeWorkerApiUrl(env, port) {
  const loopback = `http://127.0.0.1:${port}`;
  const explicit = String(env.ASTRANULL_PROBE_WORKER_API_URL ?? '').trim().replace(/\/$/, '');
  if (explicit) return explicit;
  return loopback;
}

function buildProbeWorkerEnv(env, port) {
  return {
    ...env,
    ASTRANULL_API_URL: resolveProbeWorkerApiUrl(env, port),
    ASTRANULL_PROBE_TENANT_ID: env.ASTRANULL_PROBE_TENANT_ID ?? 'ten_demo',
    ASTRANULL_PROBE_POLL_INTERVAL_MS: env.ASTRANULL_PROBE_POLL_INTERVAL_MS ?? '5000',
  };
}

async function waitForHealth(port, options = {}) {
  const maxMs = options.maxMs ?? 120_000;
  const url = `http://127.0.0.1:${port}/health`;
  const start = Date.now();
  while (Date.now() - start < maxMs) {
    // Bail out if a stop arrived mid-startup: the child has already been signalled, so it will
    // never answer, and polling on to the 120s ceiling would stall the container's shutdown and
    // then report a spurious timeout failure for what is an ordinary stop.
    if (shuttingDown) return;
    try {
      const res = await fetch(url);
      if (res.ok) return;
    } catch {
      /* API not listening yet */
    }
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  if (shuttingDown) return;
  throw new Error(`railway-staging-start: timed out waiting for ${url}`);
}

/**
 * Set once a stop signal has been forwarded to the children.
 *
 * Guards two things during a drain: the probe worker's supervisor must not relaunch a worker that
 * exited because we asked it to, and `waitForHealth` must not keep polling a process that is on
 * its way out.
 */
let shuttingDown = false;

/**
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} env
 * @param {string} port
 * @param {(child: import('node:child_process').ChildProcess) => void} [onChild]
 *   Called with each launched worker, including after a restart. The supervisor replaces the child
 *   object on every relaunch, so a caller that captured only the first one would hold a stale
 *   reference and signal a dead pid on shutdown.
 */
function startProbeWorkerSupervised(env, port, onChild) {
  if (env.ASTRANULL_PROBE_MODE !== 'signed-worker') return null;
  const workerEnv = buildProbeWorkerEnv(env, port);

  const launch = () => {
    const child = spawn(process.execPath, ['workers/probe-worker.mjs'], {
      cwd: REPO_ROOT,
      env: workerEnv,
      stdio: 'inherit',
    });
    onChild?.(child);
    child.on('exit', (code, signal) => {
      if (code === 0 && !signal) return;
      // A worker that stopped because we forwarded SIGTERM must stay stopped: relaunching here
      // would start fresh work in the middle of the drain and outlive the API it polls.
      if (shuttingDown) return;
      console.error(
        `railway-staging-start: probe worker exited (code=${code ?? 'null'}, signal=${signal ?? 'null'}); restarting in 5s…`,
      );
      setTimeout(launch, 5000).unref();
    });
    return child;
  };

  console.log(
    `railway-staging-start: probe worker API base ${workerEnv.ASTRANULL_API_URL} (tenant=${workerEnv.ASTRANULL_PROBE_TENANT_ID})`,
  );
  return launch();
}

/**
 * Build the signal handler that hands a stop down to the child processes.
 *
 * Extracted and exported so the forwarding itself is testable: the bug this exists to prevent
 * (PID 1 dying without ever signalling the API child, so the drain in src/startup.mjs never ran in
 * the container) is invisible to a test that only reads source text.
 *
 * `children` is read at signal time rather than destructured, because the probe-worker supervisor
 * replaces its child object on every relaunch — a captured reference would signal a dead pid.
 *
 * @param {{ api: import('node:child_process').ChildProcess | null,
 *           worker: import('node:child_process').ChildProcess | null }} children
 * @param {{ onShuttingDown?: () => void, exit?: (code: number) => void,
 *           log?: (line: string) => void, logError?: (line: string) => void }} [options]
 */
export function createShutdownForwarder(children, options = {}) {
  const exit = options.exit ?? ((code) => process.exit(code));
  const log = options.log ?? ((line) => console.log(line));
  const logError = options.logError ?? ((line) => console.error(line));
  let forwarded = false;

  /** @param {NodeJS.Signals} signal */
  return function forward(signal) {
    // Repeated signals (an impatient orchestrator sending SIGTERM twice) must not re-signal a
    // child that is already draining.
    if (forwarded) return;
    forwarded = true;
    options.onShuttingDown?.();

    const targets = [children.api, children.worker].filter(
      (child) => child && child.exitCode === null && child.signalCode === null,
    );
    if (targets.length === 0) {
      // The children are already gone (a stop racing their own exit). Registering the handler
      // suppressed Node's default disposition, so PID 1 has to exit explicitly or it would hang
      // until the platform's kill timeout.
      //
      // Note the handler is installed after migrate/seed, so a stop during those still takes the
      // default disposition and can orphan the migration child. That is unchanged from before and
      // deliberately out of scope: covering it means threading the child out of runNode, and an
      // interrupted migration needs its own handling rather than a signal forward.
      log(`railway-staging-start: ${signal} with no running child; exiting`);
      exit(0);
      return;
    }

    log(`railway-staging-start: forwarding ${signal} to ${targets.length} child process(es)`);
    for (const child of targets) {
      try {
        child.kill(signal);
      } catch (err) {
        // One unkillable child must not stop the others from draining.
        logError(
          `railway-staging-start: could not signal pid ${child.pid}: ${err instanceof Error ? err.message : String(err)}`,
        );
      }
    }
  };
}

async function main() {
  const env = { ...process.env };
  if (!String(env.ASTRANULL_DATABASE_URL ?? '').trim()) {
    console.error('hosted-control-plane-start: ASTRANULL_DATABASE_URL is required (link managed Postgres).');
    process.exitCode = 1;
    return;
  }

  env.ASTRANULL_BUNDLED_STAGING_OIDC = env.ASTRANULL_BUNDLED_STAGING_OIDC ?? '1';
  env.ASTRANULL_DEPLOYMENT_PROFILE = env.ASTRANULL_DEPLOYMENT_PROFILE ?? 'hosted-staging';
  env.ASTRANULL_PERSISTENCE_MODE = env.ASTRANULL_PERSISTENCE_MODE ?? 'postgres';
  env.ASTRANULL_PROBE_MODE = env.ASTRANULL_PROBE_MODE ?? 'signed-worker';
  env.ASTRANULL_HIGH_SCALE_ADAPTER_MODE = env.ASTRANULL_HIGH_SCALE_ADAPTER_MODE ?? 'disabled';
  env.ASTRANULL_AGENT_IDENTITY_MODE = env.ASTRANULL_AGENT_IDENTITY_MODE ?? 'bearer';
  applyBundledStagingOidcEnvDefaults(env);
  Object.assign(process.env, env);

  console.log('railway-staging-start: applying migrations…');
  await runNode(['scripts/migrate-postgres.mjs'], { env });

  console.log('railway-staging-start: seeding demo tenant (idempotent)…');
  await runNode(['scripts/seed-local-staging-tenant.mjs'], { env });

  const port = env.PORT ?? '3000';

  /**
   * Forward a stop signal to the children and let them drain.
   *
   * This wrapper is PID 1 in the container. Without a handler here Node applies the default
   * disposition and PID 1 dies immediately, so SIGTERM never reached `src/index.mjs` and the drain
   * in src/startup.mjs — flip /ready to 503, finish in-flight requests, then close — never ran in
   * production at all. It only executed when src/index.mjs was launched directly, which is why
   * local runs and tests exercised it and the deployed container did not.
   *
   * Registering the handler is itself the fix for the instant death; once registered, the exit
   * promise below keeps PID 1 alive until the API child has finished its own shutdown.
   *
   * @type {{ api: import('node:child_process').ChildProcess | null,
   *          worker: import('node:child_process').ChildProcess | null }}
   */
  const children = { api: null, worker: null };

  const forward = createShutdownForwarder(children, {
    onShuttingDown: () => {
      shuttingDown = true;
    },
  });

  process.on('SIGTERM', () => forward('SIGTERM'));
  process.on('SIGINT', () => forward('SIGINT'));

  console.log('railway-staging-start: starting control plane…');
  const apiChild = spawn(process.execPath, ['src/index.mjs'], {
    cwd: REPO_ROOT,
    env,
    stdio: 'inherit',
  });
  children.api = apiChild;

  await waitForHealth(port);
  if (shuttingDown) {
    // Stopped while still coming up; the signal is already forwarded, so just wait for the exit.
    console.log('railway-staging-start: shutdown requested during startup');
  } else {
    console.log('railway-staging-start: control plane healthy');

    if (env.ASTRANULL_PROBE_MODE === 'signed-worker') {
      console.log('railway-staging-start: starting signed probe worker…');
      // Reassigned on every relaunch: the supervisor creates a new child object each restart, so
      // capturing only the first would leave `forward` signalling a pid that no longer exists.
      startProbeWorkerSupervised(env, port, (child) => {
        children.worker = child;
      });
    }
  }

  await new Promise((resolve, reject) => {
    apiChild.on('error', reject);
    apiChild.on('exit', (code, signal) => {
      if (code === 0) {
        resolve();
        return;
      }
      if (shuttingDown) {
        // We asked it to stop, so this is an ordinary stop even if the child's own grace timer
        // fired (src/startup.mjs exits 1 on drain timeout). Report it in the log rather than as a
        // container crash, which the platform would treat as a failed deploy and restart.
        console.error(
          `railway-staging-start: control plane exited during shutdown (code=${code ?? 'null'}, signal=${signal ?? 'null'})`,
        );
        resolve();
        return;
      }
      reject(
        new Error(
          `node src/index.mjs failed (code=${code ?? 'null'}, signal=${signal ?? 'null'})`,
        ),
      );
    });
  });
}

const startEntry = fileURLToPath(import.meta.url);
const invokedAsMain =
  process.argv[1] != null && path.resolve(process.argv[1]) === startEntry;

if (invokedAsMain) {
  main().catch((err) => {
    console.error(`railway-staging-start: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  });
}