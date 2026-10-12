// HTTP regressions for inert endpoint review. Fixture URLs are declarations only;
// these tests never start a run, lease a probe, or contact a declared endpoint.
import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { after, before, beforeEach, describe, it } from 'node:test';
import { loadRuntimeConfig } from '../../src/config.mjs';
import { mintSignedSessionToken } from '../../src/context.mjs';
import { createServer } from '../../src/server.mjs';
import { getStore } from '../../src/store.mjs';
import { dnsOwnershipTargetBinding } from '../../src/lib/dnsOwnershipTarget.mjs';
import { closeServer, demoHeaders, request, signedSessionHeaders } from '../helpers/http.mjs';
import { freshStore } from '../helpers/reset.mjs';

const TENANT = 'ten_demo';
const FOREIGN_TENANT = 'ten_review_other';
const SECRET = 'reviewed-operation-local-http-test-secret';
const ROOT = '/v1/reviewed-operations';
const TARGET = {
  id: 'tgt_review_http', tenant_id: TENANT, target_group_id: 'tg_1',
  kind: 'url', value: 'https://owned.example.test/diagnostics',
  declaration_json: {}, created_at: '2026-10-09T00:00:00.000Z', deleted_at: null,
};
const env = {
  NODE_ENV: 'test',
  ASTRANULL_AUTH_MODE: 'signed-session',
  ASTRANULL_SESSION_SECRET: SECRET,
  ASTRANULL_PERSISTENCE_MODE: 'dev-json',
  ASTRANULL_PROBE_MODE: 'simulation',
  ASTRANULL_HIGH_SCALE_ADAPTER_MODE: 'disabled',
  ASTRANULL_NO_PERSIST: '1',
  ASTRANULL_RATE_LIMIT_DISABLED: '1',
};
const headersFor = (role = 'admin', tenant = TENANT) =>
  signedSessionHeaders(role, tenant, `usr_review_${role}`, SECRET, mintSignedSessionToken);
const operationAudit = (action) => getStore().auditLog.filter((entry) => entry.action === `reviewed_operation.${action}`);

let server;
let baseUrl;
let expiresAt;
const originalNoPersist = process.env.ASTRANULL_NO_PERSIST;

before(async () => {
  freshStore();
  server = createServer({ env, runtimeConfig: loadRuntimeConfig(env) });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  await closeServer(server);
  if (originalNoPersist === undefined) delete process.env.ASTRANULL_NO_PERSIST;
  else process.env.ASTRANULL_NO_PERSIST = originalNoPersist;
});

beforeEach(() => {
  freshStore();
  const store = getStore();
  store.tenants.push({ id: FOREIGN_TENANT, name: 'Other review tenant' });
  store.targets.push(structuredClone(TARGET));
  store.reviewedOperations = [];
  store.targetVerifications = [];
  store.targetVerifications.push({
    id: 'tv_review_http', tenant_id: TENANT, target_id: TARGET.id,
    state: 'dns_verified', source_kind: 'dns_txt',
    source_ref: { dns_target_binding: dnsOwnershipTargetBinding(TARGET) },
    transitioned_at: TARGET.created_at, transitioned_by: 'fixture',
  });
  expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();
});

function body(overrides = {}) {
  return {
    target_id: TARGET.id, check_id: 'waf.evasion_alt_charset.safe', template: 'inert-json-v1',
    semantics: 'inert_diagnostic', side_effects: 'none', expires_at: expiresAt, ...overrides,
  };
}

function assertInert(result) {
  assert.equal(result.grants_execution, false);
  assert.equal(result.execution_available, false);
  assert.equal(getStore().testRuns.length, 0, 'review never starts a test run');
  assert.equal(getStore().probeJobs.length, 0, 'review never queues a probe');
}

async function preview(headers = headersFor(), value = body()) {
  const res = await request(baseUrl, 'POST', `${ROOT}/preview`, { headers, body: value });
  assert.equal(res.status, 200, res.text);
  assert.match(res.json.plan_digest, /^[a-f0-9]{64}$/);
  assertInert(res.json);
  return res.json;
}

async function create(headers = headersFor(), value = body()) {
  const proposal = await preview(headers, value);
  const reviewedBody = { ...value, reviewed_plan_digest: proposal.plan_digest };
  const res = await request(baseUrl, 'POST', ROOT, { headers, body: reviewedBody });
  assert.equal(res.status, 201, res.text);
  assert.equal(res.json.replayed, false);
  assertInert(res.json);
  return { row: res.json, reviewedBody };
}

async function serviceAccountHeaders(scopes, role = 'admin') {
  const res = await request(baseUrl, 'POST', '/v1/service-accounts', {
    headers: headersFor(), body: { name: 'review-http-fixture', role, scopes },
  });
  assert.equal(res.status, 201, res.text);
  assert.match(res.json.secret, /^svc_/);
  return { Authorization: `Bearer ${res.json.secret}` };
}

const routes = (id = 'rop_http_unknown') => [
  ['POST', `${ROOT}/preview`, body()],
  ['POST', ROOT, body({ reviewed_plan_digest: '0'.repeat(64) })],
  ['GET', `${ROOT}/${id}`, undefined],
  ['POST', `${ROOT}/${id}/revoke`, undefined],
];

describe('reviewed-operation HTTP authentication and lifecycle', () => {
  for (const [name, headers] of [
    ['missing bearer', {}],
    ['spoofed dev headers', demoHeaders('admin')],
    ['invalid bearer plus spoofed admin headers', { ...demoHeaders('admin'), Authorization: 'Bearer asn1.invalid.invalid' }],
    ['expired signed session', { Authorization: `Bearer ${mintSignedSessionToken({
      tenantId: TENANT, userId: 'usr_expired', role: 'admin', exp: Math.floor(Date.now() / 1000) - 60,
    }, SECRET)}` }],
  ]) {
    it(`requires authentication for every route with ${name}`, async () => {
      for (const [method, path, value] of routes()) {
        const res = await request(baseUrl, method, path, { headers, body: value });
        assert.equal(res.status, 401, `${method} ${path}: ${res.text}`);
        assert.equal(res.json.error, 'unauthorized');
      }
      assert.equal(getStore().reviewedOperations.length, 0);
      assert.equal(operationAudit('approved').length, 0);
    });
  }

  for (const role of ['admin', 'owner']) {
    it(`supports preview, create, replay, get and terminal revoke for a signed ${role}`, async () => {
      const headers = headersFor(role);
      const proposal = await preview(headers);
      assert.equal(proposal.plan.tenant_id, TENANT);
      assert.equal(proposal.plan.target_id, TARGET.id);
      assert.equal(proposal.plan.endpoint, TARGET.value);
      assert.equal(proposal.plan.method, 'POST');
      assert.equal(proposal.plan.request_schema, 'fixed-asn-marker-json.v1');
      assert.equal(proposal.plan.maximum_body_bytes, 1024);
      assert.equal(proposal.plan.maximum_probe_operations, 4);
      assert.equal(proposal.plan.expires_at, expiresAt);
      assert.equal(getStore().reviewedOperations.length, 0, 'preview does not persist a review');
      assert.equal(operationAudit('approved').length, 0, 'preview does not audit an approval');

      const { row, reviewedBody } = await create(headers);
      assert.match(row.id, /^rop_[a-f0-9]{16}$/);
      assert.equal(row.approved_by, `usr_review_${role}`);
      assert.equal(row.approved_role, role);
      assert.equal(row.current_review_gap, null);
      assert.equal(row.revoked_at, null);
      assert.deepEqual(row.plan, proposal.plan);
      assert.equal(row.plan_digest, proposal.plan_digest);

      const replay = await request(baseUrl, 'POST', ROOT, { headers, body: reviewedBody });
      assert.equal(replay.status, 200, replay.text);
      assert.equal(replay.json.id, row.id);
      assert.equal(replay.json.replayed, true);
      assert.equal(replay.json.approved_at, row.approved_at);
      assert.equal(getStore().reviewedOperations.length, 1);
      assert.equal(operationAudit('approved').length, 1, 'replay does not duplicate approval audit');
      const approval = operationAudit('approved')[0];
      assert.equal(approval.tenant_id, TENANT);
      assert.equal(approval.actor_user_id, `usr_review_${role}`);
      assert.equal(approval.resource_id, row.id);
      assert.equal(approval.metadata.plan_digest, row.plan_digest);

      const fetched = await request(baseUrl, 'GET', `${ROOT}/${row.id}`, { headers });
      assert.equal(fetched.status, 200, fetched.text);
      assert.equal(fetched.json.id, row.id);
      assert.equal(fetched.json.plan_digest, row.plan_digest);
      assert.equal(fetched.json.current_review_gap, null);
      assertInert(fetched.json);

      const revoked = await request(baseUrl, 'POST', `${ROOT}/${row.id}/revoke`, { headers });
      assert.equal(revoked.status, 200, revoked.text);
      assert.equal(revoked.json.revoked_by, `usr_review_${role}`);
      assert.ok(Number.isFinite(Date.parse(revoked.json.revoked_at)));
      assert.equal(revoked.json.current_review_gap, 'operation_revoked');
      assertInert(revoked.json);
      assert.equal(operationAudit('revoked').length, 1);
      assert.equal(operationAudit('revoked')[0].resource_id, row.id);

      const again = await request(baseUrl, 'POST', `${ROOT}/${row.id}/revoke`, { headers });
      assert.equal(again.status, 409, again.text);
      assert.equal(again.json.error, 'operation_revoked');
      const replayRevoked = await request(baseUrl, 'POST', ROOT, { headers, body: reviewedBody });
      assert.equal(replayRevoked.status, 409, replayRevoked.text);
      assert.equal(replayRevoked.json.error, 'operation_revoked');
      assert.equal(operationAudit('revoked').length, 1);
      const history = await request(baseUrl, 'GET', `${ROOT}/${row.id}`, { headers });
      assert.equal(history.status, 200, history.text);
      assert.equal(history.json.current_review_gap, 'operation_revoked');
      assert.deepEqual(history.json.plan, row.plan);
      assertInert(history.json);
    });
  }

  it('supports the fixed GET marker template without authorizing execution', async () => {
    const proposal = await preview(headersFor(), body({ template: 'marker-query-v1' }));
    assert.equal(proposal.plan.method, 'GET');
    assert.equal(proposal.plan.request_schema, 'fixed-asn-probe-query.v1');
    assert.equal(proposal.plan.maximum_body_bytes, 0);
  });

  it('requires the exact reviewed plan digest and rejects stale previews', async () => {
    const proposal = await preview();
    for (const value of [body(), body({ reviewed_plan_digest: '0'.repeat(64) }),
      body({ template: 'marker-query-v1', reviewed_plan_digest: proposal.plan_digest })]) {
      const res = await request(baseUrl, 'POST', ROOT, { headers: headersFor(), body: value });
      assert.equal(res.status, 409, res.text);
      assert.equal(res.json.error, 'reviewed_plan_digest_mismatch');
    }
    assert.equal(getStore().reviewedOperations.length, 0);
    assert.equal(operationAudit('approved').length, 0);
  });
});

describe('reviewed-operation HTTP RBAC and service-account scopes', () => {
  it('denies forbidden actors before parsing malformed review or preview JSON', async () => {
    const actors = ['viewer', 'auditor', 'engineer', 'soc'].map((role) => headersFor(role));
    actors.push(await serviceAccountHeaders(['*']));
    for (const headers of actors) {
      for (const path of [ROOT, `${ROOT}/rop_missing/revoke`]) {
        const res = await request(baseUrl, 'POST', path, { headers, rawBody: '{"target_id":' });
        assert.equal(res.status, 403, res.text);
        assert.equal(res.json.error, 'forbidden');
      }
    }
    const unscoped = await serviceAccountHeaders(['target_group:read']);
    const deniedPreview = await request(baseUrl, 'POST', `${ROOT}/preview`, {
      headers: unscoped, rawBody: '{"target_id":',
    });
    assert.equal(deniedPreview.status, 403, deniedPreview.text);
    assert.equal(deniedPreview.json.error, 'forbidden');
    assert.equal(getStore().reviewedOperations.length, 0);
    assert.equal(operationAudit('approved').length, 0);
  });

  for (const role of ['viewer', 'auditor', 'engineer', 'soc']) {
    it(`allows ${role} preview/read but forbids human approval and revocation`, async () => {
      const { row, reviewedBody } = await create();
      const headers = { ...headersFor(role), ...demoHeaders('admin') };
      await preview(headers);
      const fetched = await request(baseUrl, 'GET', `${ROOT}/${row.id}`, { headers });
      assert.equal(fetched.status, 200, fetched.text);
      assertInert(fetched.json);
      for (const [path, value] of [[ROOT, reviewedBody], [`${ROOT}/${row.id}/revoke`, undefined]]) {
        const denied = await request(baseUrl, 'POST', path, { headers, body: value });
        assert.equal(denied.status, 403, denied.text);
        assert.equal(denied.json.error, 'forbidden');
      }
      assert.equal(getStore().reviewedOperations.length, 1);
      assert.equal(getStore().reviewedOperations[0].revoked_at, null);
      assert.equal(operationAudit('approved').length, 1);
      assert.equal(operationAudit('revoked').length, 0);
    });
  }

  for (const scopes of [['test_run:read'], ['test_run:read', 'test_run:start'], ['*']]) {
    it(`permits scoped read but never human review via a service account with ${scopes.join(',')}`, async () => {
      const { row, reviewedBody } = await create();
      const headers = await serviceAccountHeaders(scopes);
      await preview(headers);
      const fetched = await request(baseUrl, 'GET', `${ROOT}/${row.id}`, { headers });
      assert.equal(fetched.status, 200, fetched.text);
      assertInert(fetched.json);
      for (const [path, value] of [[ROOT, reviewedBody], [`${ROOT}/${row.id}/revoke`, undefined]]) {
        const denied = await request(baseUrl, 'POST', path, { headers, body: value });
        assert.equal(denied.status, 403, denied.text);
        assert.equal(denied.json.error, 'forbidden');
      }
      assert.equal(getStore().reviewedOperations[0].revoked_at, null);
      assert.equal(operationAudit('approved').length, 1);
      assert.equal(operationAudit('revoked').length, 0);
    });
  }

  for (const scopes of [['target_group:read'], ['test_run:start']]) {
    it(`denies preview/read without test_run:read even for admin scope ${scopes.join(',')}`, async () => {
      const { row } = await create();
      const headers = { ...await serviceAccountHeaders(scopes), ...demoHeaders('owner') };
      for (const [method, path, value] of routes(row.id)) {
        const denied = await request(baseUrl, method, path, { headers, body: value });
        assert.equal(denied.status, 403, `${method} ${path}: ${denied.text}`);
        assert.equal(denied.json.error, 'forbidden');
      }
      assert.equal(getStore().reviewedOperations[0].revoked_at, null);
      assert.equal(operationAudit('approved').length, 1);
      assert.equal(operationAudit('revoked').length, 0);
    });
  }
});

describe('reviewed-operation HTTP input and tenant boundaries', () => {
  for (const [field, value] of [
    ['approved_by', 'usr_forged'], ['approved_role', 'owner'], ['soc_approved', true],
    ['raw_body', 'arbitrary-body'], ['headers', { 'X-Custom': 'value' }],
    ['endpoint', 'https://foreign.example.test/other'], ['method', 'DELETE'],
    ['callback', 'https://foreign.example.test/callback'], ['credentials', {}],
    ['grants_execution', true],
  ]) {
    it(`rejects unknown/server-owned ${field} on both preview and create without side effects`, async () => {
      const proposal = await preview();
      for (const path of [`${ROOT}/preview`, ROOT]) {
        const res = await request(baseUrl, 'POST', path, {
          headers: headersFor(), body: body({ reviewed_plan_digest: proposal.plan_digest, [field]: value }),
        });
        assert.equal(res.status, 400, res.text);
        assert.equal(res.json.error, 'operation_field_not_allowed');
      }
      assert.equal(getStore().reviewedOperations.length, 0);
      assert.equal(operationAudit('approved').length, 0);
    });
  }

  it('does not disclose or mutate a foreign tenant target or operation even with spoofed tenant headers', async () => {
    const { row, reviewedBody } = await create();
    const headers = { ...headersFor('admin', FOREIGN_TENANT), ...demoHeaders('admin', TENANT) };
    for (const [method, path, value] of [
      ['POST', `${ROOT}/preview`, body()], ['POST', ROOT, reviewedBody],
      ['GET', `${ROOT}/${row.id}`, undefined], ['POST', `${ROOT}/${row.id}/revoke`, undefined],
    ]) {
      const res = await request(baseUrl, method, path, { headers, body: value });
      assert.equal(res.status, 404, `${method} ${path}: ${res.text}`);
      assert.equal(res.json.error, method === 'POST' && [ROOT, `${ROOT}/preview`].includes(path)
        ? 'target_not_found' : 'operation_not_found');
      assert.equal(res.json.plan, undefined);
      assert.equal(res.json.approved_by, undefined);
    }
    assert.equal(getStore().reviewedOperations.length, 1);
    assert.equal(getStore().reviewedOperations[0].revoked_at, null);
    assert.equal(operationAudit('approved').length, 1);
    assert.equal(operationAudit('revoked').length, 0);
  });

  it('returns scoped not-found errors for unknown targets and operation IDs', async () => {
    for (const path of [`${ROOT}/preview`, ROOT]) {
      const res = await request(baseUrl, 'POST', path, { headers: headersFor(), body: body({ target_id: 'tgt_missing' }) });
      assert.equal(res.status, 404, res.text);
      assert.equal(res.json.error, 'target_not_found');
    }
    for (const [method, path] of [['GET', `${ROOT}/rop_missing`], ['POST', `${ROOT}/rop_missing/revoke`]]) {
      const res = await request(baseUrl, method, path, { headers: headersFor() });
      assert.equal(res.status, 404, res.text);
      assert.equal(res.json.error, 'operation_not_found');
    }
  });

  it('requires current ownership for preview and create', async () => {
    const proposal = await preview();
    getStore().targetVerifications.find((row) => row.target_id === TARGET.id).state = 'unverified';
    for (const path of [`${ROOT}/preview`, ROOT]) {
      const res = await request(baseUrl, 'POST', path, {
        headers: headersFor(), body: body({ reviewed_plan_digest: proposal.plan_digest }),
      });
      assert.equal(res.status, 409, res.text);
      assert.equal(res.json.error, 'ownership_not_verified');
    }
    assert.equal(getStore().reviewedOperations.length, 0);
    assert.equal(operationAudit('approved').length, 0);
  });

  it('rejects malformed JSON on preview and create', async () => {
    for (const path of [`${ROOT}/preview`, ROOT]) {
      const res = await request(baseUrl, 'POST', path, { headers: headersFor(), rawBody: '{"target_id":' });
      assert.equal(res.status, 400, res.text);
      assert.equal(res.json.error, 'invalid_json');
    }
    assert.equal(getStore().reviewedOperations.length, 0);
  });

  it('returns method_not_allowed for unsupported collection, item and revoke methods', async () => {
    for (const [method, path] of [
      ['GET', ROOT], ['PUT', `${ROOT}/preview`], ['POST', `${ROOT}/rop_missing`],
      ['PATCH', `${ROOT}/rop_missing`], ['DELETE', `${ROOT}/rop_missing`], ['GET', `${ROOT}/rop_missing/revoke`],
    ]) {
      const res = await request(baseUrl, method, path, { headers: headersFor() });
      assert.equal(res.status, 405, `${method} ${path}: ${res.text}`);
      assert.equal(res.json.error, 'method_not_allowed');
    }
  });
});

describe('reviewed-operation HTTP PostgreSQL wiring (no database or external I/O)', () => {
  for (const missing of ['preview', 'approve', 'get', 'revoke']) {
    it(`returns 503 rather than 500 or dev fallback when injected PostgreSQL service lacks ${missing}`, async () => {
      let calls = 0;
      const reviewedOperations = Object.fromEntries(['preview', 'approve', 'get', 'revoke']
        .filter((name) => name !== missing)
        .map((name) => [name, async () => { calls += 1; return {}; }]));
      const before = structuredClone(getStore());
      const pgEnv = { ...env, ASTRANULL_PERSISTENCE_MODE: 'postgres' };
      const pgServer = createServer({ env: pgEnv, runtimeConfig: loadRuntimeConfig(pgEnv), services: { reviewedOperations } });
      await new Promise((resolve) => pgServer.listen(0, '127.0.0.1', resolve));
      const pgUrl = `http://127.0.0.1:${pgServer.address().port}`;
      try {
        for (const [method, path, value] of routes()) {
          const res = await request(pgUrl, method, path, { headers: headersFor(), body: value });
          assert.equal(res.status, 503, `${method} ${path}: ${res.text}`);
          assert.deepEqual(res.json, { error: 'postgres_route_not_wired' });
        }
        assert.equal(calls, 0, 'an incomplete injected service is never invoked');
        assert.deepEqual(getStore(), before, 'partial service wiring does not fall back to the dev store');
      } finally {
        await closeServer(pgServer);
      }
    });
  }

  it('fails closed on every route when the PostgreSQL service is missing instead of falling back to seeded dev data', async () => {
    const { row, reviewedBody } = await create();
    const before = structuredClone(getStore());
    const pgEnv = { ...env, ASTRANULL_PERSISTENCE_MODE: 'postgres' };
    const pgServer = createServer({ env: pgEnv, runtimeConfig: loadRuntimeConfig(pgEnv), services: {} });
    await new Promise((resolve) => pgServer.listen(0, '127.0.0.1', resolve));
    const pgUrl = `http://127.0.0.1:${pgServer.address().port}`;
    try {
      for (const [method, path, value] of [
        ['POST', `${ROOT}/preview`, body()], ['POST', ROOT, reviewedBody],
        ['GET', `${ROOT}/${row.id}`, undefined], ['POST', `${ROOT}/${row.id}/revoke`, undefined],
      ]) {
        const unauthenticated = await request(pgUrl, method, path, { body: value });
        assert.equal(unauthenticated.status, 401, unauthenticated.text);
        const res = await request(pgUrl, method, path, { headers: headersFor(), body: value });
        assert.equal(res.status, 503, `${method} ${path}: ${res.text}`);
        assert.deepEqual(res.json, { error: 'postgres_route_not_wired' });
      }
      assert.deepEqual(getStore(), before, 'PostgreSQL routing never reads/mutates the seeded dev review');
    } finally {
      await closeServer(pgServer);
    }
  });

  it('dispatches each PostgreSQL route only to the injected service with authenticated context and preserves replay status', async () => {
    const calls = [];
    const row = { id: 'rop_injected', grants_execution: false, execution_available: false };
    let approvals = 0;
    const reviewedOperations = Object.fromEntries(['preview', 'approve', 'get', 'revoke'].map((method) => [method,
      async (ctx, input) => {
        calls.push({ method, ctx, input });
        return method === 'approve' ? { ...row, replayed: approvals++ > 0 } : row;
      },
    ]));
    const before = structuredClone(getStore());
    const pgEnv = { ...env, ASTRANULL_PERSISTENCE_MODE: 'postgres' };
    const pgServer = createServer({ env: pgEnv, runtimeConfig: loadRuntimeConfig(pgEnv), services: { reviewedOperations } });
    await new Promise((resolve) => pgServer.listen(0, '127.0.0.1', resolve));
    const pgUrl = `http://127.0.0.1:${pgServer.address().port}`;
    const reviewedBody = body({ reviewed_plan_digest: 'a'.repeat(64) });
    try {
      for (const [method, path, value, status] of [
        ['POST', `${ROOT}/preview`, body(), 200], ['POST', ROOT, reviewedBody, 201],
        ['POST', ROOT, reviewedBody, 200], ['GET', `${ROOT}/${row.id}`, undefined, 200],
        ['POST', `${ROOT}/${row.id}/revoke`, undefined, 200],
      ]) {
        const res = await request(pgUrl, method, path, { headers: headersFor(), body: value });
        assert.equal(res.status, status, res.text);
        assert.equal(res.json.id, row.id);
      }
      assert.deepEqual(calls.map((call) => call.method), ['preview', 'approve', 'approve', 'get', 'revoke']);
      for (const { ctx } of calls) {
        assert.equal(ctx.tenantId, TENANT);
        assert.equal(ctx.userId, 'usr_review_admin');
        assert.equal(ctx.role, 'admin');
        assert.equal(ctx.persistenceMode, 'postgres');
      }
      assert.deepEqual(calls[0].input, body());
      assert.deepEqual(calls[1].input, reviewedBody);
      assert.deepEqual(calls[2].input, reviewedBody);
      assert.equal(calls[3].input, row.id);
      assert.equal(calls[4].input, row.id);
      assert.deepEqual(getStore(), before, 'injected PostgreSQL route dispatch does not use the dev backend');
    } finally {
      await closeServer(pgServer);
    }
  });
});
