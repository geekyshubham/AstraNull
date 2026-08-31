import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { describe, it } from 'node:test';
import {
  CONNECTOR_POLL_JOB_MAX_DURATION_MS,
  CONNECTOR_POLL_JOB_MAX_REQUESTS,
  CONNECTOR_POLL_JOB_SIGNATURE_ALGORITHM,
  CONNECTOR_POLL_JOB_TTL_MS,
  buildSignedConnectorPollJob,
  connectorJobPublicKeyFromPrivate,
  connectorPollJobId,
  createConnectorPollBudgetedFetch,
  isConnectorJobPrivateKeyValid,
  isConnectorJobPublicKeyValid,
  resolveConnectorJobPrivateKey,
  resolveConnectorJobPublicKey,
  signConnectorPollJob,
  verifySignedConnectorPollJob,
} from '../../src/lib/connectorPollJobs.mjs';
import {
  CONNECTOR_POLL_FETCH_MAX_TIMEOUT_MS,
  CONNECTOR_POLL_MAX_ATTEMPTS,
} from '../../src/lib/connectorProviders/common.mjs';

function keyPair() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return {
    privateKey: privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64'),
    publicKey: publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
  };
}

const KEYS = keyPair();
const OTHER_KEYS = keyPair();
const ISSUED_AT = '2026-07-10T12:00:00.000Z';
const EXPIRES_AT = '2026-07-10T12:10:00.000Z';

function signedJob(overrides = {}) {
  return buildSignedConnectorPollJob({
    tenantId: 'ten_demo',
    connectorId: 'conn_cf_1',
    provider: 'cloudflare',
    pollRevision: 7,
    secretId: 'secret_cf_1',
    secretRotation: 4,
    issuedAt: ISSUED_AT,
    expiresAt: EXPIRES_AT,
    ...overrides,
  }, KEYS.privateKey);
}

describe('signed connector poll jobs', () => {
  it('binds immutable tenant, connector, provider, secret generation, expiry, algorithm, and constraints', () => {
    const job = signedJob();
    assert.equal(job.envelope.job_id, connectorPollJobId('conn_cf_1', 7));
    assert.equal(job.envelope.signature_algorithm, CONNECTOR_POLL_JOB_SIGNATURE_ALGORITHM);
    assert.equal(job.envelope.secret_id, 'secret_cf_1');
    assert.equal(job.envelope.secret_rotation, 4);
    assert.equal(job.envelope.operation, 'read_only_provider_inventory');
    assert.equal(job.envelope.constraints.redirects, 'manual');
    assert.equal(job.envelope.constraints.private_networks, 'deny');
    assert.equal(job.envelope.constraints.max_requests, CONNECTOR_POLL_JOB_MAX_REQUESTS);
    assert.equal(verifySignedConnectorPollJob(job, KEYS.publicKey, {
      tenantId: 'ten_demo',
      connectorId: 'conn_cf_1',
      provider: 'cloudflare',
      pollRevision: 7,
      secretId: 'secret_cf_1',
      secretRotation: 4,
      expiresAt: EXPIRES_AT,
    }, new Date('2026-07-10T12:05:00.000Z')), true);
  });

  it('rejects tampering, another verifier, and replay against another binding', () => {
    const job = signedJob();
    const tampered = structuredClone(job);
    tampered.envelope.provider = 'akamai_edgedns';
    assert.equal(verifySignedConnectorPollJob(tampered, KEYS.publicKey, {}, new Date('2026-07-10T12:05:00.000Z')), false);
    assert.equal(verifySignedConnectorPollJob(job, OTHER_KEYS.publicKey, {}, new Date('2026-07-10T12:05:00.000Z')), false);
    for (const expected of [
      { tenantId: 'ten_other' },
      { connectorId: 'conn_other' },
      { provider: 'namecheap' },
      { pollRevision: 8 },
      { secretId: 'secret_new' },
      { secretRotation: 5 },
      { expiresAt: '2026-07-10T12:09:59.000Z' },
    ]) {
      assert.equal(verifySignedConnectorPollJob(
        job,
        KEYS.publicKey,
        expected,
        new Date('2026-07-10T12:05:00.000Z'),
      ), false);
    }
  });

  it('rejects correctly signed retry and timeout constraints outside hard ceilings', () => {
    const valid = signedJob();
    for (const constraints of [
      { max_attempts: 0 },
      { max_attempts: CONNECTOR_POLL_MAX_ATTEMPTS + 1 },
      { request_timeout_ms: 0 },
      { request_timeout_ms: CONNECTOR_POLL_FETCH_MAX_TIMEOUT_MS + 1 },
      { max_duration_ms: 0 },
      { max_duration_ms: CONNECTOR_POLL_JOB_MAX_DURATION_MS + 1 },
    ]) {
      const envelope = structuredClone(valid.envelope);
      Object.assign(envelope.constraints, constraints);
      const record = { envelope, signature: signConnectorPollJob(envelope, KEYS.privateKey) };
      assert.equal(
        verifySignedConnectorPollJob(record, KEYS.publicKey, {}, new Date('2026-07-10T12:05:00.000Z')),
        false,
      );
    }
  });

  it('validates DER key type and derives only the public verifier from signer material', () => {
    assert.equal(isConnectorJobPrivateKeyValid(KEYS.privateKey), true);
    assert.equal(isConnectorJobPublicKeyValid(KEYS.publicKey), true);
    assert.equal(isConnectorJobPrivateKeyValid(KEYS.publicKey), false);
    assert.equal(isConnectorJobPublicKeyValid(KEYS.privateKey), false);
    assert.equal(connectorJobPublicKeyFromPrivate(KEYS.privateKey), KEYS.publicKey);
    assert.throws(() => resolveConnectorJobPrivateKey({
      privateKey: 'invalid', required: true, env: { NODE_ENV: 'production' },
    }), /PKCS8/);
    assert.throws(() => resolveConnectorJobPublicKey({
      publicKey: 'invalid', required: true, env: { NODE_ENV: 'production' },
    }), /SPKI/);
  });

  it('rejects jobs before issuance, at expiry, and beyond the hard TTL', () => {
    const job = signedJob();
    assert.equal(verifySignedConnectorPollJob(job, KEYS.publicKey, {}, new Date('2026-07-10T11:59:59.999Z')), false);
    assert.equal(verifySignedConnectorPollJob(job, KEYS.publicKey, {}, new Date(EXPIRES_AT)), false);
    assert.throws(() => signedJob({
      expiresAt: new Date(Date.parse(ISSUED_AT) + CONNECTOR_POLL_JOB_TTL_MS + 1).toISOString(),
    }), /hard TTL/);
  });

  it('enforces the signed request budget before transport invocation', async () => {
    const { envelope } = signedJob();
    let calls = 0;
    const fetchFn = async () => {
      calls += 1;
      return new Response('{}', { status: 200 });
    };
    const budgeted = createConnectorPollBudgetedFetch(fetchFn, envelope);
    for (let i = 0; i < CONNECTOR_POLL_JOB_MAX_REQUESTS; i += 1) {
      await budgeted('https://api.cloudflare.com/client/v4/zones');
    }

    await assert.rejects(
      budgeted('https://api.cloudflare.com/client/v4/zones'),
      (err) => err?.code === 'connector_request_budget_exceeded',
    );
    assert.equal(calls, CONNECTOR_POLL_JOB_MAX_REQUESTS);
    assert.equal(budgeted.requestCount(), CONNECTOR_POLL_JOB_MAX_REQUESTS + 1);
  });

  it('checks authoritative lease state before transport invocation', async () => {
    const { envelope } = signedJob();
    let transportCalls = 0;
    let guardCalls = 0;
    const budgeted = createConnectorPollBudgetedFetch(async () => {
      transportCalls += 1;
      return new Response('{}');
    }, envelope, {
      guard: async () => {
        guardCalls += 1;
        return false;
      },
    });
    await assert.rejects(
      budgeted('https://api.cloudflare.com/client/v4/zones'),
      (err) => err?.code === 'connector_poll_lease_lost',
    );
    assert.equal(guardCalls, 1);
    assert.equal(transportCalls, 0);
  });

  it('aborts transport at the signed per-request timeout', async () => {
    const { envelope } = signedJob();
    envelope.constraints.request_timeout_ms = 10;
    let receivedSignal;
    const budgeted = createConnectorPollBudgetedFetch((_url, init) => {
      receivedSignal = init.signal;
      return new Promise((_resolve, reject) => {
        init.signal.addEventListener('abort', () => reject(init.signal.reason), { once: true });
      });
    }, envelope);

    await assert.rejects(
      budgeted('https://api.cloudflare.com/client/v4/zones'),
      (err) => err?.name === 'TimeoutError',
    );
    assert.equal(receivedSignal.aborted, true);
  });

  it('enforces the overall signed deadline before transport invocation', async () => {
    const { envelope } = signedJob();
    let called = false;
    const budgeted = createConnectorPollBudgetedFetch(async () => {
      called = true;
      return new Response('{}');
    }, envelope, { startedAtMs: Date.now() - envelope.constraints.max_duration_ms - 1 });
    await assert.rejects(
      budgeted('https://api.cloudflare.com/client/v4/zones'),
      (err) => err?.code === 'connector_poll_deadline_exceeded',
    );
    assert.equal(called, false);
  });
});
