import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { decryptSecret, encryptSecret } from '../../src/lib/secrets.mjs';
import {
  buildPasswordRecoveryDeliveryAad,
  classifyPasswordRecoveryDeliveryResult,
  createPasswordRecoveryDelivery,
  passwordRecoveryRetryDelayMs,
} from '../../src/persistence/postgres/passwordRecoveryDelivery.mjs';
import {
  PASSWORD_RECOVERY_CYCLE_TIMEOUT_CODE,
  parsePasswordRecoveryRunnerArgs,
  parsePasswordRecoveryTenantIds,
  resolvePasswordRecoveryRunnerConfig,
  runPasswordRecoveryRunner,
} from '../../scripts/password-recovery-runner.mjs';

const KEY = Buffer.from(Array.from({ length: 32 }, (_, index) => index + 1));
const KEY_HEX = KEY.toString('hex');
const NOW = '2026-08-30T01:00:00.000Z';
const PAYLOAD = {
  idempotency_key: 'pwr_reset_1',
  kind: 'password_reset',
  tenant_id: 'ten_1',
  user_id: 'usr_1',
  email: 'owner@example.test',
  reset_token: 'pwr_secret-token',
  expires_at: '2026-08-30T02:00:00.000Z',
};

function runnerEnv(overrides = {}) {
  return {
    ASTRANULL_DATABASE_URL: 'postgresql://astranull:password@db.test/astranull',
    ASTRANULL_SECRET_ENCRYPTION_KEY: KEY_HEX,
    ASTRANULL_PUBLIC_BASE_URL: 'https://astranull.example.test',
    ASTRANULL_SMTP_HOST: 'smtp.example.test',
    ...overrides,
  };
}

describe('password recovery delivery outbox', () => {
  it('requires the reset transaction and inserts only an AAD-bound encrypted envelope', async () => {
    const queries = [];
    const client = {
      async query(text, params) {
        queries.push({ text, params });
        return { rowCount: 1, rows: [{ id: 'pwrd_fixed' }] };
      },
    };
    const service = createPasswordRecoveryDelivery({}, {
      env: { ASTRANULL_SECRET_ENCRYPTION_KEY: KEY_HEX },
      now: () => new Date(NOW),
      randomUUID: () => 'fixed-uuid',
    });

    await assert.rejects(
      () => service.enqueuePasswordReset(PAYLOAD),
      (error) => error.code === 'password_recovery_delivery_transaction_required',
    );
    const result = await service.enqueuePasswordReset(PAYLOAD, { client });
    assert.equal(result.status, 'queued');
    assert.equal(queries.length, 1);

    const insert = queries[0];
    assert.match(insert.text, /INSERT INTO password_recovery_delivery_outbox/);
    assert.match(insert.text, /envelope/);
    assert.match(insert.text, /ON CONFLICT \(tenant_id, kind, idempotency_key\) DO NOTHING/);
    assert.doesNotMatch(insert.text, /\bemail\b|reset_token/i);

    const serializedParams = JSON.stringify(insert.params);
    assert.equal(serializedParams.includes(PAYLOAD.email), false);
    assert.equal(serializedParams.includes(PAYLOAD.reset_token), false);

    const aad = buildPasswordRecoveryDeliveryAad(PAYLOAD);
    assert.deepEqual(aad, {
      tenant_id: PAYLOAD.tenant_id,
      user_id: PAYLOAD.user_id,
      idempotency_key: PAYLOAD.idempotency_key,
      kind: PAYLOAD.kind,
    });
    const envelope = JSON.parse(insert.params[5]);
    assert.equal(envelope.algorithm, 'AES-256-GCM');
    assert.deepEqual(JSON.parse(decryptSecret(envelope, KEY, aad)), {
      email: PAYLOAD.email,
      reset_token: PAYLOAD.reset_token,
      expires_at: PAYLOAD.expires_at,
    });
    assert.throws(
      () => decryptSecret(envelope, KEY, { ...aad, tenant_id: 'ten_other' }),
    );
  });

  it('commits a tenant-scoped SKIP LOCKED lease before delivery and CAS-schedules retry', async () => {
    const token = 'pwr_needs&escaping"<';
    const aadRecord = {
      tenant_id: 'ten_1',
      user_id: 'usr_1',
      idempotency_key: 'pwr_reset_2',
      kind: 'password_reset',
    };
    const envelope = encryptSecret(JSON.stringify({
      email: 'owner@example.test',
      reset_token: token,
      expires_at: '2026-08-30T02:00:00.000Z',
    }), KEY, buildPasswordRecoveryDeliveryAad(aadRecord));
    const leasedRow = {
      id: 'pwrd_2',
      ...aadRecord,
      envelope,
      attempt_count: 1,
      max_attempts: 5,
      lease_expires_at: '2026-08-30T01:00:30.000Z',
    };
    const events = [];
    const queries = [];
    const client = {
      async query(text, params = []) {
        queries.push({ text, params });
        if (text === 'COMMIT') events.push('commit');
        if (text.includes('WITH candidate AS')) {
          return { rowCount: 1, rows: [leasedRow] };
        }
        if (text.includes('SET status = $5')) {
          return { rowCount: 1, rows: [{ id: leasedRow.id }] };
        }
        return { rowCount: 0, rows: [] };
      },
      release() {},
    };
    const pool = { async connect() { return client; } };
    let deliveredEnvelope;
    const service = createPasswordRecoveryDelivery(pool, {
      env: runnerEnv(),
      now: () => new Date(NOW),
      deliverEmail: async (email) => {
        events.push('deliver');
        deliveredEnvelope = email;
        return { status: 'provider_retry_scheduled', reason: 'secret provider detail' };
      },
    });

    const result = await service.processNext('ten_1');
    assert.deepEqual(result, {
      status: 'retry',
      id: leasedRow.id,
      attempt_count: 1,
      error_code: 'smtp_transient_failure',
    });

    const lease = queries.find((query) => query.text.includes('WITH candidate AS'));
    assert.ok(lease);
    assert.match(lease.text, /FOR UPDATE SKIP LOCKED/);
    assert.match(lease.text, /tenant_id = \$1/);
    assert.equal(lease.params[0], 'ten_1');
    assert.ok(events.indexOf('commit') < events.indexOf('deliver'));

    assert.equal(deliveredEnvelope.to, 'owner@example.test');
    assert.match(deliveredEnvelope.html_body, /token=pwr_needs%26escaping%22%3C/);
    assert.equal(deliveredEnvelope.html_body.includes('href="https://astranull.example.test/login?flow=password-reset&amp;token='), true);

    const cas = queries.find((query) => query.text.includes('SET status = $5'));
    assert.ok(cas);
    assert.match(cas.text, /status = 'leased'/);
    assert.match(cas.text, /attempt_count = \$3/);
    assert.match(cas.text, /lease_expires_at = \$4::timestamptz/);
    assert.deepEqual(cas.params.slice(0, 5), [
      'ten_1',
      leasedRow.id,
      1,
      leasedRow.lease_expires_at,
      'retry',
    ]);
    assert.equal(cas.params[5], '2026-08-30T01:01:00.000Z');
    assert.equal(cas.params[6], 'smtp_transient_failure');
    assert.equal(JSON.stringify(cas.params).includes(token), false);
    assert.equal(JSON.stringify(cas.params).includes('secret provider detail'), false);
  });

  it('classifies provider outcomes without retaining provider errors and bounds exponential retry', () => {
    assert.deepEqual(classifyPasswordRecoveryDeliveryResult({ status: 'delivered_provider' }), {
      delivered: true,
      retryable: false,
      errorCode: null,
    });
    assert.deepEqual(classifyPasswordRecoveryDeliveryResult({
      status: 'queued_provider_not_configured',
      reason: 'smtp_host_not_configured',
    }), {
      delivered: false,
      retryable: true,
      errorCode: 'smtp_not_configured',
    });
    assert.deepEqual(classifyPasswordRecoveryDeliveryResult({
      status: 'provider_retry_scheduled',
      reason: 'may contain a provider secret',
    }), {
      delivered: false,
      retryable: true,
      errorCode: 'smtp_transient_failure',
    });
    assert.deepEqual(classifyPasswordRecoveryDeliveryResult({
      status: 'provider_retry_scheduled',
      reason: 'smtp_unexpected_response_550',
    }), {
      delivered: false,
      retryable: false,
      errorCode: 'smtp_permanent_rejection',
    });
    assert.equal(passwordRecoveryRetryDelayMs(1), 60_000);
    assert.equal(passwordRecoveryRetryDelayMs(2), 120_000);
    assert.equal(passwordRecoveryRetryDelayMs(20), 3_600_000);
  });
});

describe('password recovery runner configuration', () => {
  const parsed = parsePasswordRecoveryRunnerArgs([
    'node',
    'scripts/password-recovery-runner.mjs',
    '--tenant-id',
    'ten_1',
    '--once',
  ]);

  it('fails closed when any required production setting or tenant scope is absent', () => {
    for (const name of [
      'ASTRANULL_DATABASE_URL',
      'ASTRANULL_SECRET_ENCRYPTION_KEY',
      'ASTRANULL_PUBLIC_BASE_URL',
    ]) {
      const env = runnerEnv();
      delete env[name];
      const config = resolvePasswordRecoveryRunnerConfig(env, parsed);
      assert.equal(config.ok, false, name);
      assert.match(config.message, new RegExp(name));
      assert.equal(config.message.includes(KEY_HEX), false);
    }
    const noTenant = resolvePasswordRecoveryRunnerConfig(
      runnerEnv({ ASTRANULL_PASSWORD_RECOVERY_TENANT_IDS: '' }),
      { ...parsed, tenantIds: [] },
    );
    assert.equal(noTenant.ok, false);
    assert.match(noTenant.message, /explicit tenant scope/);
  });

  it('accepts blank or missing SMTP host for queue-only provider-unconfigured processing', () => {
    const missingSmtp = runnerEnv();
    delete missingSmtp.ASTRANULL_SMTP_HOST;
    for (const env of [runnerEnv({ ASTRANULL_SMTP_HOST: '   ' }), missingSmtp]) {
      const config = resolvePasswordRecoveryRunnerConfig(env, parsed);
      assert.equal(config.ok, true);
      assert.deepEqual(config.tenantIds, ['ten_1']);
    }
  });

  it('accepts --once and rejects poll intervals outside the bounded range', () => {
    const valid = resolvePasswordRecoveryRunnerConfig(runnerEnv(), parsed);
    assert.deepEqual(valid, {
      ok: true,
      tenantIds: ['ten_1'],
      once: true,
      intervalMs: 5_000,
      heartbeatFile: null,
      cycleTimeoutMs: 30_000,
    });
    assert.equal(resolvePasswordRecoveryRunnerConfig(runnerEnv(), {
      ...parsed,
      intervalMs: 249,
    }).ok, false);
    assert.equal(resolvePasswordRecoveryRunnerConfig(runnerEnv(), {
      ...parsed,
      intervalMs: 60_001,
    }).ok, false);
  });
});


describe('password recovery multi-tenant runner', () => {
  it('deduplicates bounded explicit tenant scopes from CLI or recovery-specific env', () => {
    const parsed = parsePasswordRecoveryRunnerArgs([
      'node',
      'scripts/password-recovery-runner.mjs',
      '--tenant-id',
      'ten_a',
      '--tenant-id',
      'ten_b',
      '--tenant-id',
      'ten_a',
    ]);
    assert.deepEqual(parsed.tenantIds, ['ten_a', 'ten_b', 'ten_a']);
    assert.deepEqual(parsePasswordRecoveryTenantIds(parsed.tenantIds), ['ten_a', 'ten_b']);

    const fromEnv = resolvePasswordRecoveryRunnerConfig(
      runnerEnv({ ASTRANULL_PASSWORD_RECOVERY_TENANT_IDS: 'ten_a, ten_b,ten_a' }),
      parsePasswordRecoveryRunnerArgs(['node', 'scripts/password-recovery-runner.mjs', '--once']),
    );
    assert.equal(fromEnv.ok, true);
    assert.deepEqual(fromEnv.tenantIds, ['ten_a', 'ten_b']);
    assert.throws(
      () => parsePasswordRecoveryTenantIds(['ten_ok', 'bad tenant']),
      /safe identifier/,
    );
  });

  it('calls the processor once per explicit tenant without a cross-tenant lease call', async () => {
    const calls = [];
    let closed = false;
    const summary = await runPasswordRecoveryRunner(
      runnerEnv(),
      { tenantIds: ['ten_a', 'ten_b'], once: true, intervalMs: 250 },
      {
        signalTarget: { on() {}, off() {} },
        createPostgresRuntimeFn: async () => ({
          services: {
            passwordRecoveryDelivery: {
              async processNext(tenantId) {
                calls.push(tenantId);
                return { status: tenantId === 'ten_b' ? 'delivered' : 'idle' };
              },
            },
          },
          async close() { closed = true; },
        }),
      },
    );

    assert.deepEqual(calls, ['ten_a', 'ten_b']);
    assert.deepEqual(summary, {
      iterations: 2,
      processed: 1,
      lastStatus: 'delivered',
      stopped: false,
    });
    assert.equal(closed, true);
  });

  it('refreshes the heartbeat after every successful call across a large tenant scope', async () => {
    const tenantIds = Array.from({ length: 250 }, (_, index) => `ten_${index}`);
    const events = [];
    const summary = await runPasswordRecoveryRunner(
      runnerEnv(),
      {
        tenantIds,
        once: true,
        intervalMs: 250,
        cycleTimeoutMs: 100,
        heartbeatFile: '/tmp/unused-password-recovery-heartbeat',
      },
      {
        signalTarget: { on() {}, off() {} },
        writeHeartbeatFn: (_path, value, options) => {
          events.push({ type: 'heartbeat', value, options });
        },
        createPostgresRuntimeFn: async () => ({
          services: {
            passwordRecoveryDelivery: {
              async processNext(tenantId) {
                events.push({ type: 'tenant', tenantId });
                return { status: 'idle' };
              },
            },
          },
          async close() {},
        }),
      },
    );

    assert.equal(summary.iterations, tenantIds.length);
    assert.equal(events.filter((event) => event.type === 'heartbeat').length, tenantIds.length);
    for (let index = 0; index < tenantIds.length; index += 1) {
      assert.equal(events[index * 2].tenantId, tenantIds[index]);
      assert.equal(events[index * 2 + 1].type, 'heartbeat');
      assert.equal(events[index * 2 + 1].options.mode, 0o600);
      assert.match(events[index * 2 + 1].value, /^\d{4}-\d{2}-\d{2}T/);
    }
  });

  it('keeps prior successful heartbeats but exits when a later tenant times out', async () => {
    const tenantIds = [...Array.from({ length: 40 }, (_, index) => `ten_ok_${index}`), 'ten_hung'];
    let heartbeatWrites = 0;
    let closeCalls = 0;
    const run = runPasswordRecoveryRunner(
      runnerEnv(),
      {
        tenantIds,
        once: true,
        intervalMs: 250,
        cycleTimeoutMs: 5,
        heartbeatFile: '/tmp/unused-password-recovery-heartbeat',
      },
      {
        signalTarget: { on() {}, off() {} },
        writeHeartbeatFn: () => { heartbeatWrites += 1; },
        createPostgresRuntimeFn: async () => ({
          services: {
            passwordRecoveryDelivery: {
              async processNext(tenantId) {
                if (tenantId === 'ten_hung') return new Promise(() => {});
                return { status: 'idle' };
              },
            },
          },
          async close() { closeCalls += 1; },
        }),
      },
    );

    await assert.rejects(
      () => run,
      (error) => error?.code === PASSWORD_RECOVERY_CYCLE_TIMEOUT_CODE,
    );
    assert.equal(heartbeatWrites, 40);
    assert.equal(closeCalls, 0, 'fatal timeout must exit without waiting on a held pool');
  });

  it('fails a hung processor promptly and never heartbeats after its late resolution', async () => {
    let resolveProcessor;
    let heartbeatWrites = 0;
    let closeCalls = 0;
    const processorPromise = new Promise((resolve) => {
      resolveProcessor = resolve;
    });
    const run = runPasswordRecoveryRunner(
      runnerEnv(),
      {
        tenantIds: ['ten_a'],
        once: false,
        intervalMs: 250,
        cycleTimeoutMs: 5,
        heartbeatFile: '/tmp/unused-password-recovery-heartbeat',
      },
      {
        signalTarget: { on() {}, off() {} },
        writeHeartbeatFn: () => { heartbeatWrites += 1; },
        createPostgresRuntimeFn: async () => ({
          services: {
            passwordRecoveryDelivery: {
              processNext: async () => processorPromise,
            },
          },
          close: async () => {
            closeCalls += 1;
            return new Promise(() => {});
          },
        }),
      },
    );

    await assert.rejects(
      () => run,
      (error) => error?.code === PASSWORD_RECOVERY_CYCLE_TIMEOUT_CODE,
    );
    assert.equal(closeCalls, 0, 'fatal timeout must not await a pool held by the hung processor');
    assert.equal(heartbeatWrites, 0);

    resolveProcessor({ status: 'delivered' });
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(heartbeatWrites, 0, 'late processor completion must not resume the worker loop');
  });
});
