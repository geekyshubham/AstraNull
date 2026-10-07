import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { after, before, beforeEach, describe, it } from 'node:test';
import { PROTECTION_VALIDATION_ROUTES } from '../../src/contracts/protectionValidation.mjs';
import { roleHasPermission } from '../../src/contracts/roles.mjs';
import { HttpBodyError } from '../../src/lib/http.mjs';
import {
  DELEGATED_PROTECTION_VALIDATION_OPERATIONS,
  isProtectionValidationRoute,
  tryHandleProtectionValidationRoutes,
} from '../../src/routes/protectionValidationRoutes.mjs';
import {
  createDevProtectionValidationBackend,
  createProtectionValidationService,
  PROTECTION_VALIDATION_STORE_KEYS,
} from '../../src/services/protectionValidation.mjs';
import { getStore } from '../../src/store.mjs';
import { closeServer, request } from '../helpers/http.mjs';

const TENANT = 'ten_pv_routes';
const OTHER = 'ten_pv_routes_other';
const GROUP = 'tg_pv_routes';
const DECLARED = '2026-09-01T00:00:00.000Z';

let server;
let baseUrl;
const BASE_CONFIG = Object.freeze({ maxJsonBodyBytes: 1_048_576, featureFlags: { protectionValidationEnabledDefault: true } });
let runtimeConfig = BASE_CONFIG;
let serviceDeps = {};

function headers(role, tenant = TENANT, extra = {}) {
  return { 'x-test-role': role, 'x-test-tenant': tenant, 'x-test-user': `usr_${role}`, ...extra };
}

function scrub() {
  const store = getStore();
  for (const key of ['targets', 'targetVerifications', 'testRuns', 'probeJobs', 'events', 'verdicts', 'auditLog', ...Object.values(PROTECTION_VALIDATION_STORE_KEYS)]) {
    if (!Array.isArray(store[key])) continue;
    store[key] = store[key].filter((row) => row.tenant_id !== TENANT && row.tenant_id !== OTHER);
  }
}

function seed() {
  scrub();
  const store = getStore();
  for (const [id, tenant, kind, value] of [
    ['tgt_r_app', TENANT, 'fqdn', 'app.example.test'],
    ['tgt_r_alt', TENANT, 'fqdn', 'alt.example.test'],
    ['tgt_r_fw', TENANT, 'ip', '198.51.100.5'],
    ['tgt_r_foreign', OTHER, 'fqdn', 'foreign.example.test'],
  ]) {
    store.targets.push({ id, tenant_id: tenant, target_group_id: GROUP, kind, value, created_at: DECLARED });
    store.targetVerifications.push({ id: `tv_${id}`, tenant_id: tenant, target_id: id, state: 'dns_verified', transitioned_at: DECLARED });
  }
  store.testRuns.push({
    id: 'run_r_pre', tenant_id: TENANT, target_group_id: GROUP, target_id: 'tgt_r_fw', check_id: 'l3.basic_deny_rule.safe',
    status: 'verdicted', producer_kind: 'signed_probe', check_version: 'v1', scenario_version: null, completed_at: '2026-10-05T00:00:00.000Z', provenance_json: {},
  });
  store.probeJobs.push({
    id: 'job_r_pre', tenant_id: TENANT, test_run_id: 'run_r_pre', status: 'completed', leased_by: 'worker_eu_1', job_signature: 'sig',
    target: { id: 'tgt_r_fw', port: 443 }, worker_metadata: { source_perspective: 'public-worker-eu' }, completed_at: '2026-10-05T00:00:00.000Z',
  });
  store.events.push({ id: 'evt_r_pre', tenant_id: TENANT, test_run_id: 'run_r_pre', signal_type: 'probe_result', producer_kind: 'signed_probe', timestamp: '2026-10-05T00:00:00.000Z', metadata: {} });
  store.verdicts.push({ id: 'vrd_r_pre', tenant_id: TENANT, test_run_id: 'run_r_pre', evidence_ids: ['ev_r_pre'], created_at: '2026-10-05T00:00:00.000Z' });
}

before(async () => {
  server = createServer(async (req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    const ctx = req.headers['x-test-tenant']
      ? { tenantId: req.headers['x-test-tenant'], role: req.headers['x-test-role'], userId: req.headers['x-test-user'] }
      : {};
    try {
      const handled = await tryHandleProtectionValidationRoutes(req, res, url, ctx, runtimeConfig, serviceDeps);
      if (!handled) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'unhandled' }));
      }
    } catch (err) {
      const status = err instanceof HttpBodyError ? err.status : 500;
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: err.code ?? 'internal_error' }));
    }
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  await closeServer(server);
});

beforeEach(() => {
  runtimeConfig = BASE_CONFIG;
  serviceDeps = {};
  seed();
});

const ALT = {
  entry_target_id: 'tgt_r_alt',
  relation_kind: 'alternate_hostname',
  owner: 'App Team',
  purpose: 'Partner hostname',
  expected_behavior: 'must_be_protected_by_layers',
  required_layers: ['waf'],
};

const FW = {
  destination_target_id: 'tgt_r_fw',
  protocol: 'tcp',
  port: 443,
  expected: 'allow',
  source_perspective: 'public-worker-eu',
  change_id: 'CHG-2001',
};

function concretePath(path) {
  return path.replace(/:[A-Za-z]+/g, 'x_1');
}

describe('protection validation route contract', () => {
  it('claims exactly the contract route table and rejects other methods with 405', async () => {
    for (const route of PROTECTION_VALIDATION_ROUTES) {
      assert.equal(isProtectionValidationRoute(concretePath(route.path)), true, route.path);
    }
    assert.equal(isProtectionValidationRoute('/v1/entry-paths'), false);
    assert.equal(isProtectionValidationRoute('/v1/targets/x/origin-bindings'), false);
    const res = await request(baseUrl, 'DELETE', '/v1/entry-paths/ep_1', { headers: headers('owner') });
    assert.equal(res.status, 405);
  });

  it('enforces the per-route permission before any service call', async () => {
    for (const route of PROTECTION_VALIDATION_ROUTES) {
      const res = await request(baseUrl, route.method, concretePath(route.path), {
        headers: headers('soc'),
        body: route.method === 'POST' ? {} : undefined,
      });
      if (roleHasPermission('soc', route.permission)) assert.notEqual(res.status, 403, route.path);
      else assert.equal(res.status, 403, `${route.method} ${route.path}`);
      if (route.mutates) assert.equal(res.status, 403, `SOC holds no write here: ${route.path}`);
    }
    const anon = await request(baseUrl, 'GET', '/v1/firewall-expectations');
    assert.equal(anon.status, 401);
  });

  it('declares, replays, lists, reads, and archives entry paths', async () => {
    const created = await request(baseUrl, 'POST', '/v1/targets/tgt_r_app/entry-paths', { headers: headers('engineer'), body: ALT });
    assert.equal(created.status, 201);
    assert.equal(created.json.replayed, false);
    assert.equal(created.json.anchor_target_id, 'tgt_r_app');
    assert.equal(created.json.currently_authorized, true);
    const replay = await request(baseUrl, 'POST', '/v1/targets/tgt_r_app/entry-paths', { headers: headers('engineer'), body: ALT });
    assert.equal(replay.status, 200);
    assert.equal(replay.json.replayed, true);
    const conflict = await request(baseUrl, 'POST', '/v1/targets/tgt_r_app/entry-paths', { headers: headers('engineer'), body: { ...ALT, purpose: 'other' } });
    assert.equal(conflict.status, 409);
    assert.equal(conflict.json.error, 'entry_path_conflict');
    const banned = await request(baseUrl, 'POST', '/v1/targets/tgt_r_app/entry-paths', { headers: headers('engineer'), body: { ...ALT, destination: '10.0.0.1' } });
    assert.equal(banned.status, 400);
    assert.equal(banned.json.error, 'scope_not_declared');
    assert.equal(banned.text.includes('10.0.0.1'), false);
    const foreign = await request(baseUrl, 'POST', '/v1/targets/tgt_r_app/entry-paths', { headers: headers('engineer'), body: { ...ALT, entry_target_id: 'tgt_r_foreign' } });
    assert.equal(foreign.status, 404);
    assert.deepEqual(Object.keys(foreign.json).sort(), ['error', 'field']);

    const listed = await request(baseUrl, 'GET', '/v1/targets/tgt_r_app/entry-paths?limit=1', { headers: headers('viewer') });
    assert.equal(listed.status, 200);
    assert.deepEqual(Object.keys(listed.json).sort(), ['count', 'items', 'next_cursor']);
    assert.equal(listed.json.count, 1);
    const read = await request(baseUrl, 'GET', `/v1/entry-paths/${created.json.id}`, { headers: headers('auditor') });
    assert.equal(read.status, 200);
    const hidden = await request(baseUrl, 'GET', `/v1/entry-paths/${created.json.id}`, { headers: headers('owner', OTHER) });
    assert.equal(hidden.status, 404);
    const archived = await request(baseUrl, 'POST', `/v1/entry-paths/${created.json.id}/archive`, { headers: headers('admin') });
    assert.equal(archived.status, 200);
    assert.equal(archived.json.status, 'archived');
    const again = await request(baseUrl, 'POST', `/v1/entry-paths/${created.json.id}/archive`, { headers: headers('admin') });
    assert.equal(again.status, 409);
    assert.equal(again.json.error, 'already_archived');
  });

  it('declares firewall expectations and captures and reads a baseline without dispatching traffic', async () => {
    const before = { runs: getStore().testRuns.length, jobs: getStore().probeJobs.length };
    const expectation = await request(baseUrl, 'POST', '/v1/firewall-expectations', { headers: headers('owner', TENANT, { 'Idempotency-Key': 'fw-1' }), body: FW });
    assert.equal(expectation.status, 201);
    const replay = await request(baseUrl, 'POST', '/v1/firewall-expectations', { headers: headers('owner', TENANT, { 'Idempotency-Key': 'fw-1' }), body: FW });
    assert.equal(replay.status, 200);
    const server = await request(baseUrl, 'POST', '/v1/firewall-expectations', { headers: headers('owner'), body: { ...FW, digest: 'x' } });
    assert.equal(server.json.error, 'server_owned_field');
    const listed = await request(baseUrl, 'GET', '/v1/firewall-expectations?change_id=CHG-2001', { headers: headers('viewer') });
    assert.equal(listed.json.count, 1);

    const capture = await request(baseUrl, 'POST', '/v1/firewall-baselines', {
      headers: headers('owner'),
      body: { change_id: 'CHG-2001', expectation_ids: [expectation.json.id], test_run_ids: ['run_r_pre'] },
    });
    assert.equal(capture.status, 201, capture.text);
    assert.equal(capture.json.immutable, true);
    assert.equal(capture.json.entries[0].references[0].test_run_id, 'run_r_pre');
    const replayCapture = await request(baseUrl, 'POST', '/v1/firewall-baselines', {
      headers: headers('owner'),
      body: { change_id: 'CHG-2001', expectation_ids: [expectation.json.id], test_run_ids: ['run_r_pre'] },
    });
    assert.equal(replayCapture.status, 200);
    assert.equal(replayCapture.json.replayed, true);
    const read = await request(baseUrl, 'GET', `/v1/firewall-baselines/${capture.json.id}`, { headers: headers('viewer') });
    assert.equal(read.status, 200);
    assert.equal(read.json.baseline_digest, capture.json.baseline_digest);
    const list = await request(baseUrl, 'GET', '/v1/firewall-baselines?change_id=CHG-2001', { headers: headers('viewer') });
    assert.equal(list.json.count, 1);
    const foreignRun = await request(baseUrl, 'POST', '/v1/firewall-baselines', {
      headers: headers('owner'),
      body: { change_id: 'CHG-2001', expectation_ids: [expectation.json.id], test_run_ids: ['run_other_tenant'] },
    });
    assert.equal(foreignRun.status, 404);
    const comparisons = await request(baseUrl, 'GET', '/v1/firewall-comparisons', { headers: headers('viewer') });
    assert.deepEqual(comparisons.json, { items: [], count: 0, next_cursor: null });
    const missing = await request(baseUrl, 'GET', '/v1/firewall-comparisons/fwc_missing', { headers: headers('viewer') });
    assert.equal(missing.status, 404);
    const archived = await request(baseUrl, 'POST', `/v1/firewall-expectations/${expectation.json.id}/archive`, { headers: headers('owner') });
    assert.equal(archived.status, 200);
    assert.deepEqual({ runs: getStore().testRuns.length, jobs: getStore().probeJobs.length }, before);
  });

  it('reports unwired delegated operations and fails closed in postgres mode', async () => {
    for (const operation of Object.keys(DELEGATED_PROTECTION_VALIDATION_OPERATIONS)) {
      const route = PROTECTION_VALIDATION_ROUTES.find((entry) => entry.operation === operation);
      const res = await request(baseUrl, route.method, concretePath(route.path), {
        headers: headers('owner'),
        body: route.method === 'POST' ? {} : undefined,
      });
      assert.equal(res.status, 503, operation);
      assert.equal(res.json.error, 'route_not_wired');
    }
    runtimeConfig = { ...BASE_CONFIG, persistenceMode: 'postgres' };
    const pg = await request(baseUrl, 'GET', '/v1/firewall-expectations', { headers: headers('owner') });
    assert.equal(pg.status, 503);
    assert.equal(pg.json.error, 'postgres_route_not_wired');
    runtimeConfig = { ...BASE_CONFIG, featureFlags: { protectionValidationEnabled: false } };
    const disabled = await request(baseUrl, 'GET', '/v1/firewall-expectations', { headers: headers('owner') });
    assert.equal(disabled.status, 404);
    assert.equal(disabled.json.error, 'protection_validation_disabled');
    runtimeConfig = { ...BASE_CONFIG, featureFlags: { protectionValidationEnabledDefault: false, protectionValidationEnabledTenants: { [OTHER]: true } } };
    const offForTenant = await request(baseUrl, 'GET', '/v1/firewall-expectations', { headers: headers('owner') });
    assert.equal(offForTenant.status, 404);
    assert.equal(offForTenant.json.error, 'protection_validation_disabled');
    const onForOther = await request(baseUrl, 'GET', '/v1/firewall-expectations', { headers: headers('owner', OTHER) });
    assert.equal(onForOther.status, 200);
    runtimeConfig = { ...BASE_CONFIG, featureFlags: {} };
    const defaultOff = await request(baseUrl, 'GET', '/v1/firewall-expectations', { headers: headers('owner') });
    assert.equal(defaultOff.status, 404);
  });

  it('binds delegated operations to the path parameter and rejects a conflicting body or query value', async () => {
    const calls = [];
    serviceDeps = {
      protectionValidation: {
        ...createProtectionValidationService({ backend: createDevProtectionValidationBackend() }),
        async cancelEntryPathComparison(ctx, input) {
          calls.push(['cancel', input.comparisonId, input.reason ?? null]);
          return { id: input.comparisonId, status: 'cancelled' };
        },
        async getEntryPathComparison(ctx, input) {
          calls.push(['get', input.comparisonId]);
          return { id: input.comparisonId };
        },
        async getProtectionMatrix(ctx, input) {
          calls.push(['matrix', input.targetId]);
          return { target_id: input.targetId, paths: [] };
        },
      },
    };
    const conflict = await request(baseUrl, 'POST', '/v1/entry-path-comparisons/epc_A/cancel', { headers: headers('engineer'), body: { comparisonId: 'epc_B' } });
    assert.equal(conflict.status, 400);
    assert.equal(conflict.json.error, 'path_parameter_mismatch');
    assert.equal(conflict.json.field, 'comparisonId');
    const queryConflict = await request(baseUrl, 'GET', '/v1/entry-path-comparisons/epc_A?comparisonId=epc_B', { headers: headers('engineer') });
    assert.equal(queryConflict.status, 400);
    const matrixConflict = await request(baseUrl, 'GET', '/v1/targets/tgt_r_app/protection-validation?targetId=tgt_r_alt', { headers: headers('viewer') });
    assert.equal(matrixConflict.status, 400);
    assert.deepEqual(calls, []);
    const cancel = await request(baseUrl, 'POST', '/v1/entry-path-comparisons/epc_A/cancel', { headers: headers('engineer'), body: { reason: 'operator stop' } });
    assert.equal(cancel.status, 200);
    assert.equal(cancel.json.id, 'epc_A');
    const same = await request(baseUrl, 'GET', '/v1/entry-path-comparisons/epc_A?comparisonId=epc_A', { headers: headers('engineer') });
    assert.equal(same.status, 200);
    const matrix = await request(baseUrl, 'GET', '/v1/targets/tgt_r_app/protection-validation', { headers: headers('viewer') });
    assert.equal(matrix.json.target_id, 'tgt_r_app');
    assert.deepEqual(calls, [['cancel', 'epc_A', 'operator stop'], ['get', 'epc_A'], ['matrix', 'tgt_r_app']]);
  });

  it('dispatches delegated operations to an injected service and keeps plan passive', async () => {
    const calls = [];
    serviceDeps = {
      protectionValidation: {
        ...createProtectionValidationService({ backend: createDevProtectionValidationBackend() }),
        async planOrStartEntryPathComparison(ctx, input) {
          calls.push(input.mode);
          return { mode: input.mode ?? 'plan', plan_digest: 'a'.repeat(64) };
        },
      },
    };
    const plan = await request(baseUrl, 'POST', '/v1/entry-path-comparisons', { headers: headers('engineer'), body: { mode: 'plan' } });
    assert.equal(plan.status, 200);
    const start = await request(baseUrl, 'POST', '/v1/entry-path-comparisons', { headers: headers('engineer'), body: { mode: 'start' } });
    assert.equal(start.status, 202);
    assert.deepEqual(calls, ['plan', 'start']);
    const viewer = await request(baseUrl, 'POST', '/v1/entry-path-comparisons', { headers: headers('viewer'), body: { mode: 'plan' } });
    assert.equal(viewer.status, 403);
  });
});
