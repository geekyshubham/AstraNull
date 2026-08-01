import { loadRuntimeConfig } from './config.mjs';
import { beginDraining, createServer } from './server.mjs';
import { createPostgresRuntime } from './persistence/postgres/runtime.mjs';
import { redactDatabaseUrlInMessage } from './lib/pgErrorRedact.mjs';

export { redactDatabaseUrlInMessage as redactStartupErrorMessage };

/**
 * @param {{
 *   env?: NodeJS.ProcessEnv | Record<string, string | undefined>,
 *   runtimeConfig?: ReturnType<typeof loadRuntimeConfig>,
 *   services?: Record<string, unknown>,
 *   createPostgresRuntime?: typeof createPostgresRuntime,
 *   createServer?: typeof createServer,
 *   postgresRuntimeOptions?: Parameters<typeof createPostgresRuntime>[1],
 *   listen?: boolean,
 *   port?: number,
 * }} [options]
 */
export async function startControlPlane(options = {}) {
  const env = options.env ?? process.env;
  const runtimeConfig = options.runtimeConfig ?? loadRuntimeConfig(env);
  const createPostgresRuntimeFn = options.createPostgresRuntime ?? createPostgresRuntime;
  const createServerFn = options.createServer ?? createServer;

  /** @type {Awaited<ReturnType<typeof createPostgresRuntime>> | null} */
  let persistenceRuntime = null;
  /** @type {Record<string, unknown> | undefined} */
  let services = options.services;

  try {
    if (runtimeConfig.persistenceMode === 'postgres') {
      persistenceRuntime = await createPostgresRuntimeFn(env, options.postgresRuntimeOptions);
      services = { ...persistenceRuntime.services, ...(options.services ?? {}) };
    }

    const server = createServerFn({
      env,
      runtimeConfig,
      services,
      runtimeHealth: persistenceRuntime?.health ?? options.runtimeHealth,
    });

    const close = async () => {
      await new Promise((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
      if (persistenceRuntime) {
        await persistenceRuntime.close();
      }
    };

    return {
      server,
      runtimeConfig,
      persistenceRuntime,
      close,
    };
  } catch (err) {
    if (persistenceRuntime) {
      try {
        await persistenceRuntime.close();
      } catch {
        // ignore cleanup errors; preserve original failure
      }
    }
    throw err;
  }
}

/**
 * CLI entry: load config, bootstrap persistence + HTTP server, register signal handlers.
 *
 * @param {{
 *   env?: NodeJS.ProcessEnv | Record<string, string | undefined>,
 *   port?: number,
 *   createPostgresRuntime?: typeof createPostgresRuntime,
 *   createServer?: typeof createServer,
 * }} [options]
 */
export async function runControlPlaneProcess(options = {}) {
  const env = options.env ?? process.env;
  const port = Number(options.port ?? env.PORT ?? 3000);
  const app = await startControlPlane({
    env,
    createPostgresRuntime: options.createPostgresRuntime,
    createServer: options.createServer,
  });

  let shuttingDown = false;

  // How long to keep serving while reporting NOT ready, so the load balancer can
  // take this instance out of rotation before it stops accepting connections.
  // Defaults to one DigitalOcean health-check period (15s, per
  // ops/digitalocean/app.yaml). Clamped to half the shutdown grace so the drain
  // can never consume the budget that app.close() needs — otherwise the
  // grace-exceeded timer would hard-exit the process mid-close and drop
  // in-flight requests, which is the opposite of a graceful drain.
  const drainDelayMs = Math.min(
    Math.max(Number.parseInt(String(env.ASTRANULL_DRAIN_DELAY_MS ?? '').trim(), 10) || 15_000, 0),
    Math.floor(app.runtimeConfig.shutdownGraceMs / 2),
  );

  const shutdown = (signal) => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`AstraNull shutting down (${signal})`);

    // Flip /ready to 503 first; the server keeps serving during the drain.
    beginDraining();

    const closeAndExit = () => {
      app
        .close()
        .then(() => {
          console.log('AstraNull stopped');
          process.exit(0);
        })
        .catch((err) => {
          console.error(`AstraNull shutdown error: ${redactDatabaseUrlInMessage(err, env)}`);
          process.exit(1);
        });
    };

    // The overall grace timer starts NOW, covering drain + close together.
    setTimeout(() => {
      console.error('AstraNull shutdown grace exceeded; exiting');
      process.exit(1);
    }, app.runtimeConfig.shutdownGraceMs).unref();

    if (drainDelayMs > 0) {
      console.log(`AstraNull draining for ${drainDelayMs}ms (readiness now failing)`);
      setTimeout(closeAndExit, drainDelayMs);
      return;
    }
    closeAndExit();
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));

  await new Promise((resolve, reject) => {
    app.server.once('error', reject);
    app.server.listen(port, () => {
      app.server.off('error', reject);
      resolve();
    });
  });

  console.log(
    `AstraNull listening on http://localhost:${port} (auth_mode=${app.runtimeConfig.authMode})`,
  );

  return app;
}