/**
 * Availability hardening for the unauthenticated control-plane surface.
 *
 * These endpoints are reachable without credentials, so the properties asserted
 * here are the ones that decide whether anonymous traffic can take the control
 * plane down: how much database work a probe flood can cause, whether the
 * restart probe can be starved, and whether metrics leak.
 */
import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';
import { createServer, resetDrainingState, beginDraining } from '../../src/server.mjs';
import { demoHeaders, request } from '../helpers/http.mjs';
import { freshStore } from '../helpers/reset.mjs';

/** Minimal postgres-mode config, mirroring tests/unit/server-postgres-mode.test.mjs. */
function postgresRuntimeConfig(overrides = {}) {
  return {
    authMode: 'dev-headers',
    sessionSecret: null,
    oidc: null,
    nodeEnv: 'test',
    maxJsonBodyBytes: 65536,
    shutdownGraceMs: 30_000,
    persistenceMode: 'postgres',
    databaseUrlConfigured: true,
    probeMode: 'simulation',
    probeWorkerSecret: null,
    probeWorkerSecretConfigured: false,
    rateLimit: { windowMs: 60_000, maxRequests: 600, disabled: false, trustProxyHeaders: false },
    secretEncryptionKey: null,
    secretEncryptionConfigured: false,
    ...overrides,
  };
}

const openServers = [];

function listen(server) {
  server.listen(0);
  openServers.push(server);
  const { port } = server.address();
  return `http://127.0.0.1:${port}`;
}

afterEach(async () => {
  // `draining` is module-level state; leaking it would make every later /ready
  // in this file return 503.
  resetDrainingState();
  while (openServers.length) {
    const server = openServers.pop();
    await new Promise((resolve) => server.close(resolve));
  }
});

describe('/ready readiness caching', () => {
  it('collapses N concurrent probes to a single database check', async () => {
    let healthCalls = 0;
    const server = createServer({
      env: { ...process.env, ASTRANULL_NO_PERSIST: '1' },
      runtimeConfig: postgresRuntimeConfig(),
      services: { tenants: { getCurrentTenant: async () => ({ id: 'ten_demo' }) } },
      runtimeHealth: async () => {
        healthCalls += 1;
        // Hold the check open briefly so all probes genuinely overlap.
        await new Promise((resolve) => setTimeout(resolve, 25));
        return { ok: true, persistence: 'postgres' };
      },
    });
    const baseUrl = listen(server);

    const responses = await Promise.all(
      Array.from({ length: 25 }, () => request(baseUrl, 'GET', '/ready')),
    );

    for (const res of responses) {
      assert.equal(res.status, 200);
      assert.equal(res.json.status, 'ready');
    }
    // 25 unauthenticated probes previously meant 25 x 2 = 50 pool acquisitions.
    assert.equal(healthCalls, 1);
  });

  it('serves repeat probes from cache within the TTL and re-checks after it', async () => {
    let healthCalls = 0;
    const server = createServer({
      env: {
        ...process.env,
        ASTRANULL_NO_PERSIST: '1',
        ASTRANULL_READINESS_CACHE_TTL_MS: '500',
      },
      runtimeConfig: postgresRuntimeConfig(),
      services: { tenants: { getCurrentTenant: async () => ({ id: 'ten_demo' }) } },
      runtimeHealth: async () => {
        healthCalls += 1;
        return { ok: true, persistence: 'postgres' };
      },
    });
    const baseUrl = listen(server);

    for (let i = 0; i < 5; i++) {
      assert.equal((await request(baseUrl, 'GET', '/ready')).status, 200);
    }
    assert.equal(healthCalls, 1, 'sequential probes inside the TTL must reuse the verdict');

    await new Promise((resolve) => setTimeout(resolve, 600));
    assert.equal((await request(baseUrl, 'GET', '/ready')).status, 200);
    assert.equal(healthCalls, 2, 'a probe after the TTL must re-check');
  });

  it('reports 503 not_ready when the cached verdict is unhealthy', async () => {
    const server = createServer({
      env: { ...process.env, ASTRANULL_NO_PERSIST: '1' },
      runtimeConfig: postgresRuntimeConfig(),
      services: { tenants: { getCurrentTenant: async () => null } },
      runtimeHealth: async () => {
        throw new Error('connection refused');
      },
    });
    const baseUrl = listen(server);

    const res = await request(baseUrl, 'GET', '/ready');
    assert.equal(res.status, 503);
    assert.equal(res.json.status, 'not_ready');
    assert.equal(res.json.reason, 'postgres_unhealthy');
  });

  it('returns 503 draining once the drain flag is set, before close()', async () => {
    freshStore();
    const server = createServer({ env: { ...process.env, ASTRANULL_NO_PERSIST: '1' } });
    const baseUrl = listen(server);

    assert.equal((await request(baseUrl, 'GET', '/ready')).status, 200);

    beginDraining();

    const res = await request(baseUrl, 'GET', '/ready');
    assert.equal(res.status, 503);
    assert.equal(res.json.reason, 'draining');
    // Still serving real customer traffic during the drain window: the point of
    // the delay is to keep answering in-flight work while the balancer removes
    // this instance. Asserted against an actual API route, not against a probe.
    assert.equal(
      (await request(baseUrl, 'GET', '/v1/environments', { headers: demoHeaders('viewer') })).status,
      200,
    );
  });

  it('reports the drain on /health, the path the orchestrator actually polls', async () => {
    freshStore();
    const baseUrl = listen(
      createServer({ env: { ...process.env, ASTRANULL_NO_PERSIST: '1' } }),
    );

    assert.equal((await request(baseUrl, 'GET', '/health')).status, 200);

    beginDraining();

    // Both App Platform specs point health_check at /health, so a drain only
    // visible on /ready never reaches the component that routes traffic: the
    // balancer would keep sending new work to a process committed to exiting.
    const res = await request(baseUrl, 'GET', '/health');
    assert.equal(res.status, 503, '/health must observe the drain flag');
    assert.equal(res.json.reason, 'draining');
  });
});

describe('/health restart-probe hysteresis', () => {
  /** Inject a cache stub so hysteresis is deterministic rather than timing-based. */
  function serverWithCache(peekValue) {
    return createServer({
      env: { ...process.env, ASTRANULL_NO_PERSIST: '1' },
      runtimeConfig: postgresRuntimeConfig(),
      services: { tenants: { getCurrentTenant: async () => null } },
      readinessCache: {
        get: async () => peekValue.verdict ?? { ok: true, persistence: 'postgres' },
        peek: () => peekValue,
        checkCount: () => 0,
      },
    });
  }

  it('stays 200 while failures are below the threshold', async () => {
    const baseUrl = listen(
      serverWithCache({ verdict: { ok: false, reason: 'postgres_unhealthy' }, consecutiveFailures: 2 }),
    );
    const res = await request(baseUrl, 'GET', '/health');
    // A single transient failover must NOT restart the instance.
    assert.equal(res.status, 200);
    assert.equal(res.json.status, 'ok');
  });

  it('reports 503 degraded once failures reach the threshold', async () => {
    const baseUrl = listen(
      serverWithCache({ verdict: { ok: false, reason: 'postgres_unhealthy' }, consecutiveFailures: 3 }),
    );
    const res = await request(baseUrl, 'GET', '/health');
    assert.equal(res.status, 503);
    assert.equal(res.json.status, 'degraded');
    assert.equal(res.json.reason, 'postgres_unhealthy');
  });

  it('stays 200 before any readiness verdict exists', async () => {
    const baseUrl = listen(serverWithCache({ verdict: null, consecutiveFailures: 0 }));
    assert.equal((await request(baseUrl, 'GET', '/health')).status, 200);
  });
});

describe('/metrics authentication', () => {
  it('returns 401 without a bearer token when a token is configured', async () => {
    freshStore();
    const baseUrl = listen(
      createServer({
        env: {
          ...process.env,
          ASTRANULL_NO_PERSIST: '1',
          ASTRANULL_METRICS_TOKEN: 'metrics-scrape-token-value',
        },
      }),
    );
    const res = await request(baseUrl, 'GET', '/metrics');
    assert.equal(res.status, 401);
    assert.equal(res.json.error, 'unauthorized');
  });

  it('returns 401 for a wrong token', async () => {
    freshStore();
    const baseUrl = listen(
      createServer({
        env: {
          ...process.env,
          ASTRANULL_NO_PERSIST: '1',
          ASTRANULL_METRICS_TOKEN: 'metrics-scrape-token-value',
        },
      }),
    );
    const res = await request(baseUrl, 'GET', '/metrics', {
      headers: { Authorization: 'Bearer wrong-token' },
    });
    assert.equal(res.status, 401);
  });

  it('serves counters for the correct token and counts the request', async () => {
    freshStore();
    const baseUrl = listen(
      createServer({
        env: {
          ...process.env,
          ASTRANULL_NO_PERSIST: '1',
          ASTRANULL_METRICS_TOKEN: 'metrics-scrape-token-value',
        },
      }),
    );
    const res = await request(baseUrl, 'GET', '/metrics', {
      headers: { Authorization: 'Bearer metrics-scrape-token-value' },
    });
    assert.equal(res.status, 200);
    assert.match(res.text, /http_requests_total/);
  });

  it('fails closed in production when no token is configured', async () => {
    freshStore();
    const env = { ...process.env, ASTRANULL_NO_PERSIST: '1', NODE_ENV: 'production' };
    delete env.ASTRANULL_METRICS_TOKEN;
    // runtimeConfig is supplied directly: loadRuntimeConfig imposes unrelated
    // production requirements (oidc-jwt, postgres) that are not what we test here.
    const baseUrl = listen(
      createServer({ env, runtimeConfig: postgresRuntimeConfig({ nodeEnv: 'production' }) }),
    );
    const res = await request(baseUrl, 'GET', '/metrics');
    assert.equal(res.status, 401);
    assert.equal(res.json.reason, 'metrics_token_not_configured');
  });
});

describe('probe endpoints are rate limited but not starved', () => {
  it('keeps /health available after the API budget is exhausted', async () => {
    freshStore();
    const baseUrl = listen(
      createServer({
        env: {
          ...process.env,
          ASTRANULL_NO_PERSIST: '1',
          ASTRANULL_RATE_LIMIT_MAX_REQUESTS: '2',
          ASTRANULL_RATE_LIMIT_WINDOW_MS: '60000',
        },
      }),
    );
    const headers = demoHeaders('viewer');
    for (let i = 0; i < 4; i++) await request(baseUrl, 'GET', '/v1/environments', { headers });

    // The orchestrator probe must not be collateral damage of an API flood.
    assert.equal((await request(baseUrl, 'GET', '/health')).status, 200);
  });

  it('eventually rate limits a probe flood instead of exempting it', async () => {
    freshStore();
    const baseUrl = listen(
      createServer({
        env: {
          ...process.env,
          ASTRANULL_NO_PERSIST: '1',
          // A one-hour window (the configured maximum) guarantees the whole flood
          // lands in a SINGLE bucket. With a 60s window this test was flaky under
          // load: if the window rolled mid-flood, the requests split into two
          // sub-limit halves and no 429 was ever produced.
          ASTRANULL_RATE_LIMIT_WINDOW_MS: '3600000',
          ASTRANULL_RATE_LIMIT_MAX_REQUESTS: '600',
        },
      }),
    );

    // The probe bucket is deliberately generous (>=1200/window) so the
    // orchestrator is never throttled, so prove the gate exists by exhausting it
    // rather than by assuming a small limit. Batched to keep the test quick.
    let sawLimited = false;
    for (let batch = 0; batch < 16 && !sawLimited; batch++) {
      const statuses = await Promise.all(
        Array.from({ length: 100 }, () => request(baseUrl, 'GET', '/health').then((r) => r.status)),
      );
      sawLimited = statuses.includes(429);
    }
    assert.ok(sawLimited, '/health must not be exempt from rate limiting');
  });

  it('does not let a /ready flood throttle the restart probe', async () => {
    freshStore();
    const baseUrl = listen(
      createServer({
        env: {
          ...process.env,
          ASTRANULL_NO_PERSIST: '1',
          // One-hour window for the same reason as the test above: the whole flood
          // must land in a single bucket or no 429 is ever produced.
          ASTRANULL_RATE_LIMIT_WINDOW_MS: '3600000',
          ASTRANULL_RATE_LIMIT_MAX_REQUESTS: '600',
        },
      }),
    );

    // Exhaust the OTHER probe bucket. Establishing that it is exhaustible is what
    // makes the /health assertion below meaningful rather than vacuous.
    let readyLimited = false;
    for (let batch = 0; batch < 16 && !readyLimited; batch++) {
      const statuses = await Promise.all(
        Array.from({ length: 100 }, () => request(baseUrl, 'GET', '/ready').then((r) => r.status)),
      );
      readyLimited = statuses.includes(429);
    }
    assert.ok(readyLimited, 'the /ready budget must be exhaustible or this test proves nothing');

    // The actual property: /health holds its own budget. While one bucket was
    // shared, ~20 anonymous req/s of /ready drained it, the orchestrator's next
    // five /health polls got 429, and App Platform restarted the only instance —
    // a remote unauthenticated restart loop that also wiped the limiter state.
    const health = await request(baseUrl, 'GET', '/health');
    assert.equal(health.status, 200, 'a /ready flood must not 429 /health');
    assert.equal(health.json.status, 'ok');
  });

  it('rate limits the unauthenticated credential-exchange POST', async () => {
    freshStore();
    const baseUrl = listen(
      createServer({
        env: {
          ...process.env,
          ASTRANULL_NO_PERSIST: '1',
          ASTRANULL_RATE_LIMIT_WINDOW_MS: '3600000',
          ASTRANULL_RATE_LIMIT_MAX_REQUESTS: '600',
        },
      }),
    );

    // The exchange is not configured here, so the handler's own answer is 404.
    // That is the point: the limiter must sit ABOVE the handler, so the 429 has to
    // displace the 404 rather than appear after it.
    const first = await request(baseUrl, 'POST', '/guardianbot/session', {
      headers: { Authorization: 'Bearer wrong-exchange-token' },
      body: { schemaVersion: '1.0.0' },
    });
    assert.equal(first.status, 404);

    const statuses = [first.status];
    // 200 attempts is far above the credential budget but far BELOW the probe
    // budget (>=1200/window), so reaching a 429 inside this loop also proves the
    // route is not riding on a probe-sized allowance.
    for (let i = 0; i < 200 && !statuses.includes(429); i++) {
      const res = await request(baseUrl, 'POST', '/guardianbot/session', {
        headers: { Authorization: 'Bearer wrong-exchange-token' },
        body: { schemaVersion: '1.0.0' },
      });
      statuses.push(res.status);
    }
    // A credential-minting surface must have a request budget. Its bucket is
    // deliberately tight (tens per window), unlike the generous probe buckets.
    assert.ok(
      statuses.includes(429),
      'POST /guardianbot/session must not sit above every limiter',
    );
    assert.ok(
      statuses.indexOf(429) <= 100,
      `the credential budget must be tight, not probe-sized (first 429 at ${statuses.indexOf(429)})`,
    );
  });
});

describe('socket-level ceilings', () => {
  it('sets maxConnections, headersTimeout and requestTimeout', () => {
    freshStore();
    const server = createServer({ env: { ...process.env, ASTRANULL_NO_PERSIST: '1' } });
    openServers.push(server);
    assert.ok(server.maxConnections > 0, 'maxConnections must be bounded');
    assert.ok(server.headersTimeout > 0, 'headersTimeout guards slowloris header stalls');
    assert.ok(server.requestTimeout > 0, 'requestTimeout bounds whole-request duration');
  });

  it('honours explicit overrides', () => {
    freshStore();
    const server = createServer({
      env: {
        ...process.env,
        ASTRANULL_NO_PERSIST: '1',
        ASTRANULL_MAX_CONNECTIONS: '256',
        ASTRANULL_HEADERS_TIMEOUT_MS: '5000',
        ASTRANULL_REQUEST_TIMEOUT_MS: '9000',
      },
    });
    openServers.push(server);
    assert.equal(server.maxConnections, 256);
    assert.equal(server.headersTimeout, 5_000);
    assert.equal(server.requestTimeout, 9_000);
  });
});

describe('security headers on real responses', () => {
  it('sets hardening headers on the portal shell at GET /app', async () => {
    freshStore();
    const baseUrl = listen(createServer({ env: { ...process.env, ASTRANULL_NO_PERSIST: '1' } }));
    const res = await request(baseUrl, 'GET', '/app');
    assert.equal(res.status, 200);
    assert.equal(res.headers['x-content-type-options'], 'nosniff');
    assert.equal(res.headers['x-frame-options'], 'DENY');
    assert.equal(res.headers['referrer-policy'], 'no-referrer');
    assert.match(res.headers['content-security-policy'], /frame-ancestors 'none'/);
    assert.ok(res.headers['content-security-policy-report-only'], 'full CSP ships report-only');
    // TLS terminates upstream; the app must not pin HSTS itself.
    assert.equal(res.headers['strict-transport-security'], undefined);
  });

  it('sets hardening headers and no-store on a /v1 JSON response', async () => {
    freshStore();
    const baseUrl = listen(createServer({ env: { ...process.env, ASTRANULL_NO_PERSIST: '1' } }));
    const res = await request(baseUrl, 'GET', '/v1/environments', {
      headers: demoHeaders('viewer'),
    });
    assert.equal(res.status, 200);
    assert.equal(res.headers['x-content-type-options'], 'nosniff');
    assert.equal(res.headers['x-frame-options'], 'DENY');
    // Tenant-scoped payloads must never sit in a shared cache.
    assert.equal(res.headers['cache-control'], 'no-store');
  });

  it('sets hardening headers on /health and /ready', async () => {
    freshStore();
    const baseUrl = listen(createServer({ env: { ...process.env, ASTRANULL_NO_PERSIST: '1' } }));
    for (const path of ['/health', '/ready']) {
      const res = await request(baseUrl, 'GET', path);
      assert.equal(res.headers['x-content-type-options'], 'nosniff', `${path} missing nosniff`);
    }
  });
});
