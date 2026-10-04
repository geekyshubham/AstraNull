import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';
import { loadRuntimeConfig } from '../../src/config.mjs';
import { closePgPool, createPgPool } from '../../src/persistence/postgres/pool.mjs';
import { createPostgresRuntime } from '../../src/persistence/postgres/runtime.mjs';
import { createServer } from '../../src/server.mjs';
import { withTenantContext } from '../../src/persistence/postgres/tenantContext.mjs';
import { getStore } from '../../src/store.mjs';
import { closeServer, demoHeaders, request } from '../helpers/http.mjs';
import {
  databaseUrlWithDatabase,
  ensureHarnessAppRole,
  resolvePostgresHarnessAvailability,
  withEphemeralPostgres,
} from '../helpers/pg-harness.mjs';
import { freshStore } from '../helpers/reset.mjs';

const TENANT = 'ten_hist_api';
const OTHER = 'ten_hist_api_other';
const GROUP = 'tg_hist_api';
const OTHER_GROUP = 'tg_hist_api_other';
const PROTECTED = 'tgt_hist_api_protected';
const ORIGIN = 'tgt_hist_api_origin';
const ORIGIN_UNVERIFIED = 'tgt_hist_api_origin_unverified';
const FOREIGN = 'tgt_hist_api_foreign';
const DECLARED = '2026-09-01T00:00:00.000000Z';
const T_OLD = '2026-10-01T12:00:00.100001Z';
const T_MID = '2026-10-02T12:00:00.100002Z';
const T_NEW = '2026-10-03T12:00:00.100003Z';
const ADMIN = { role: 'admin' };

const APP_ROLE_NAME = 'astranull_app';
const APP_ROLE_PASSWORD = 'astranull_app_local_dev';

function adminHeaders(tenant = TENANT) {
  return demoHeaders(ADMIN.role, tenant, `usr_${ADMIN.role}`);
}

function viewerHeaders(tenant = TENANT) {
  return demoHeaders('viewer', tenant, 'usr_viewer');
}

function protectedDeclaration() {
  return {
    purpose: 'storefront',
    service_roles: ['website'],
    allowed_scope: { ports: [443, 8443], paths: ['/health', '/ready'] },
  };
}

function observationRow(overrides = {}) {
  return {
    id: `obs_${Math.random().toString(16).slice(2, 10)}`,
    tenant_id: TENANT,
    target_id: PROTECTED,
    target_group_id: GROUP,
    family: 'waf',
    check_id: 'waf.fingerprint.safe',
    test_run_id: null,
    source_kind: 'explicit_record',
    source_id: null,
    corpus_version: 'corpus-1',
    scenario_version: 'scenario-1',
    check_version: 'check-1',
    observed_at: T_NEW,
    source_completed_at: T_NEW,
    outcome: 'detected',
    attempt_class: 'successful',
    producer_kind: 'manual',
    origin_binding_id: null,
    provenance: { provider: 'cloudflare', status: 'detected' },
    nonce: `nonce_${Math.random().toString(16).slice(2)}`,
    created_at: T_NEW,
    ...overrides,
  };
}

describe('current-release backend history HTTP API', () => {
  it('serves observations, bindings, pagination, scope, and passive reads on the dev HTTP surface with zero side effects', async () => {
    freshStore();
    const store = getStore();
    const group = store.targetGroups.find((row) => row.id === 'tg_1');
    assert.ok(group, 'demo fixture group');
    const tenant = { id: TENANT, name: 'History API' };
    store.tenants.push(tenant);
    const otherTenant = { id: OTHER, name: 'History API Other' };
    store.tenants.push(otherTenant);
    store.targetGroups.push(
      {
        id: GROUP, tenant_id: TENANT, environment_id: 'env_demo', name: 'History',
        ownership_status: 'dns_verified', validation_mode: 'external_only',
        expected_behavior_default: 'must_block_before_origin',
      },
      { id: OTHER_GROUP, tenant_id: OTHER, environment_id: 'env_demo', name: 'Foreign', validation_mode: 'external_only' },
    );
    store.targets.push(
      {
        id: PROTECTED, tenant_id: TENANT, target_group_id: GROUP, kind: 'fqdn',
        value: 'app.example.test', declaration_json: protectedDeclaration(),
        created_at: DECLARED, deleted_at: null,
      },
      {
        id: ORIGIN, tenant_id: TENANT, target_group_id: GROUP, kind: 'ip',
        value: '203.0.113.10', created_at: DECLARED, deleted_at: null,
      },
      {
        id: ORIGIN_UNVERIFIED, tenant_id: TENANT, target_group_id: GROUP, kind: 'ip',
        value: '203.0.113.11', created_at: DECLARED, deleted_at: null,
      },
      {
        id: FOREIGN, tenant_id: OTHER, target_group_id: OTHER_GROUP, kind: 'fqdn',
        value: 'foreign.example.test', created_at: DECLARED, deleted_at: null,
      },
    );
    store.targetVerifications = [{
      id: 'tv_hist_api_origin',
      tenant_id: TENANT,
      target_id: ORIGIN,
      state: 'dns_verified',
      source_kind: 'dns_txt',
      source_ref: {},
      transitioned_at: DECLARED,
      transitioned_by: 'usr_admin',
    }];
    store.targetObservations = [
      observationRow({ id: 'obs_hist_new', observed_at: T_NEW, source_completed_at: T_NEW, outcome: 'detected' }),
      observationRow({
        id: 'obs_hist_mid', observed_at: T_MID, source_completed_at: T_MID, outcome: 'not_detected',
      }),
      observationRow({
        id: 'obs_hist_failed', observed_at: T_OLD, source_completed_at: T_OLD, outcome: 'timeout',
        attempt_class: 'failed_attempt',
      }),
      observationRow({
        id: 'obs_hist_foreign', tenant_id: OTHER, target_id: FOREIGN,
        target_group_id: OTHER_GROUP, observed_at: T_NEW,
      }),
    ];
    store.targetObservationCurrents = [{
      tenant_id: TENANT,
      target_id: PROTECTED,
      family: 'waf',
      successful_observation_id: 'obs_hist_new',
      successful_observed_at: T_NEW,
      successful_source_completed_at: T_NEW,
      failed_attempt_observation_id: 'obs_hist_failed',
      failed_observed_at: T_OLD,
      failed_source_completed_at: T_OLD,
      updated_at: T_NEW,
    }];

    const env = {
      ...process.env,
      ASTRANULL_NO_PERSIST: '1',
      ASTRANULL_RATE_LIMIT_DISABLED: '1',
    };
    const server = createServer({ runtimeConfig: loadRuntimeConfig(env), env });
    server.listen(0);
    const baseUrl = `http://127.0.0.1:${server.address().port}`;
    try {
    const passiveBefore = {
      runs: store.testRuns.length,
      audit: store.auditLog.length,
      observations: store.targetObservations.length,
      currents: store.targetObservationCurrents.length,
      bindings: (store.originBindings ?? []).length,
    };

      // Passive observation list read: newest-first page, no side effects.
      const listed = await request(baseUrl, 'GET', `/v1/targets/${PROTECTED}/observations`, { headers: adminHeaders() });
      assert.equal(listed.status, 200, listed.text);
      assert.deepEqual(listed.json.items.map((row) => row.id), ['obs_hist_new', 'obs_hist_mid', 'obs_hist_failed']);
      assert.equal(listed.json.count, 3);
      assert.equal(listed.json.next_cursor, null);
      assert.equal(listed.json.filters.target_id, PROTECTED);
      assert.equal(listed.json.current.length, 1);
      assert.equal(listed.json.current[0].family, 'waf');
      assert.equal(listed.json.current[0].last_successful.id, 'obs_hist_new');
      assert.equal(listed.json.current[0].latest_failed_attempt.id, 'obs_hist_failed');
      // Adjacent successful pair only: failed attempts never compare.
      assert.equal(listed.json.comparison.scope, 'newest_page');
      assert.equal(listed.json.comparison.comparable_changes.length, 1);
      assert.equal(listed.json.comparison.comparable_changes[0].family, 'waf');
      assert.equal(listed.json.comparison.comparable_changes[0].previous_id, 'obs_hist_mid');
      assert.equal(listed.json.comparison.comparable_changes[0].change, 'changed');
      assert.equal(listed.json.comparison.comparable_changes[0].direction, 'appeared');

      // The page boundary is truthful: one record per page, cursor resumes exactly there.
      const firstPage = await request(
        baseUrl,
        'GET',
        `/v1/targets/${PROTECTED}/observations?limit=1`,
        { headers: adminHeaders() },
      );
      assert.equal(firstPage.status, 200, firstPage.text);
      assert.deepEqual(firstPage.json.items.map((row) => row.id), ['obs_hist_new']);
      assert.equal(typeof firstPage.json.next_cursor, 'string');
      const secondPage = await request(
        baseUrl,
        'GET',
        `/v1/targets/${PROTECTED}/observations?limit=1&cursor=${encodeURIComponent(firstPage.json.next_cursor)}`,
        { headers: adminHeaders() },
      );
      assert.equal(secondPage.status, 200, secondPage.text);
      assert.deepEqual(secondPage.json.items.map((row) => row.id), ['obs_hist_mid']);

      // Family and timestamp filters pass through and the service rejects bad ones.
      const familyOnly = await request(
        baseUrl,
        'GET',
        `/v1/targets/${PROTECTED}/observations?family=waf&limit=50`,
        { headers: adminHeaders() },
      );
      assert.equal(familyOnly.json.count, 3);
      const badFamily = await request(
        baseUrl,
        'GET',
        `/v1/targets/${PROTECTED}/observations?family=nope`,
        { headers: adminHeaders() },
      );
      assert.equal(badFamily.status, 400);
      assert.equal(badFamily.json.error, 'invalid_family');

      // Permission and tenant scope: viewer may read, foreign tenant gets 404.
      const viewerRead = await request(baseUrl, 'GET', `/v1/targets/${PROTECTED}/observations`, { headers: viewerHeaders() });
      assert.equal(viewerRead.status, 200, viewerRead.text);
      const otherTenantRead = await request(
        baseUrl,
        'GET',
        `/v1/targets/${PROTECTED}/observations`,
        { headers: adminHeaders(OTHER) },
      );
      assert.equal(otherTenantRead.status, 404);
      // A missing/foreign target is unknown_target so the portal can tell it apart
      // from the router's not_found (route not supported on this server).
      assert.equal(otherTenantRead.json.error, 'unknown_target');
      const missingTargetRead = await request(
        baseUrl,
        'GET',
        '/v1/targets/tgt_hist_missing/observations',
        { headers: adminHeaders() },
      );
      assert.equal(missingTargetRead.status, 404);
      assert.equal(missingTargetRead.json.error, 'unknown_target');

      // Origin bindings are read-only routes and bound to real declared targets.
      const bindings = await request(baseUrl, 'GET', `/v1/targets/${PROTECTED}/origin-bindings`, { headers: adminHeaders() });
      assert.equal(bindings.status, 200, bindings.text);
      assert.deepEqual(bindings.json, { items: [], count: 0 });
      const missingTargetBindings = await request(
        baseUrl,
        'GET',
        `/v1/targets/tgt_hist_missing/origin-bindings`,
        { headers: adminHeaders() },
      );
      assert.equal(missingTargetBindings.status, 404);
      assert.equal(missingTargetBindings.json.error, 'unknown_target');
      // An unsupported global route stays not_found so the frontend distinguishes it.
      const unknownRoute = await request(baseUrl, 'GET', '/v1/targets/tgt_hist_missing/observation-history', { headers: adminHeaders() });
      assert.equal(unknownRoute.status, 404);
      assert.equal(unknownRoute.json.error, 'not_found');

      const deniedCreate = await request(baseUrl, 'POST', '/v1/origin-bindings', {
        headers: viewerHeaders(),
        body: { protected_target_id: PROTECTED, origin_target_id: ORIGIN, scope: { port: 443, path: '/health' } },
      });
      assert.equal(deniedCreate.status, 403);

      const created = await request(baseUrl, 'POST', '/v1/origin-bindings', {
        headers: adminHeaders(),
        body: { protected_target_id: PROTECTED, origin_target_id: ORIGIN, scope: { port: 443, path: '/health' } },
      });
      assert.equal(created.status, 201, created.text);
      assert.equal(created.json.replayed, false);
      assert.equal(created.json.protected_target_id, PROTECTED);
      assert.equal(created.json.origin_target_id, ORIGIN);
      assert.equal(created.json.host, 'app.example.test');
      assert.equal(created.json.sni, 'app.example.test');
      assert.equal(created.json.port, 443);
      assert.equal(created.json.path, '/health');
      assert.equal(created.json.status, 'active');
      assert.equal(created.json.assurance, 'none');
      assert.equal(created.json.lockdown, 'not_tested');
      assert.equal(created.json.currently_authorized, true);

      // Replay is idempotent: same pair returns the active row without a second audit.
      const replayed = await request(baseUrl, 'POST', '/v1/origin-bindings', {
        headers: adminHeaders(),
        body: { protected_target_id: PROTECTED, origin_target_id: ORIGIN, scope: { port: 443, path: '/health' } },
      });
      assert.equal(replayed.status, 200);
      assert.equal(replayed.json.replayed, true);
      assert.equal(replayed.json.id, created.json.id);
      assert.equal(store.auditLog.filter((row) => row.action === 'origin_binding.created').length, 1);

      // Scope and existence guards.
      const undeclared = await request(baseUrl, 'POST', '/v1/origin-bindings', {
        headers: adminHeaders(),
        body: {
          protected_target_id: PROTECTED, origin_target_id: ORIGIN,
          scope: { port: 8080, path: '/health' },
        },
      });
      assert.equal(undeclared.status, 400);
      assert.equal(undeclared.json.error, 'scope_mismatch');
      const metadataRetarget = await request(baseUrl, 'POST', '/v1/origin-bindings', {
        headers: adminHeaders(),
        body: {
          protected_target_id: PROTECTED, origin_target_id: ORIGIN,
          direct_ip: '203.0.113.99',
        },
      });
      assert.equal(metadataRetarget.status, 400);
      assert.equal(metadataRetarget.json.error, 'scope_not_declared');
      const unverifiedOrigin = await request(baseUrl, 'POST', '/v1/origin-bindings', {
        headers: adminHeaders(),
        body: {
          protected_target_id: PROTECTED, origin_target_id: ORIGIN_UNVERIFIED,
          scope: { port: 443, path: '/health' },
        },
      });
      assert.equal(unverifiedOrigin.status, 409);
      assert.equal(unverifiedOrigin.json.error, 'ownership_not_verified');
      assert.equal((await request(baseUrl, 'POST', '/v1/origin-bindings', {
        headers: adminHeaders(),
        body: { protected_target_id: 'tgt_hist_missing', origin_target_id: ORIGIN, scope: {} },
      })).status, 404);
      assert.equal((await request(baseUrl, 'POST', '/v1/origin-bindings', {
        headers: adminHeaders(),
        body: { protected_target_id: FOREIGN, origin_target_id: ORIGIN, scope: {} },
      })).status, 404, 'a foreign protected target must not be bindable from this tenant');

      // Exact read and tenant isolation.
      const readOne = await request(baseUrl, 'GET', `/v1/origin-bindings/${created.json.id}`, { headers: adminHeaders() });
      assert.equal(readOne.status, 200, readOne.text);
      assert.equal(readOne.json.id, created.json.id);
      assert.equal(readOne.json.currently_authorized, true);
      assert.equal((await request(baseUrl, 'GET', `/v1/origin-bindings/${created.json.id}`, { headers: adminHeaders(OTHER) })).status, 404);
      assert.equal((await request(baseUrl, 'GET', '/v1/origin-bindings/obind_missing', { headers: adminHeaders() })).status, 404);

      // List includes both roles of the target and excludes unrelated pairs.
      const protectedList = await request(baseUrl, 'GET', `/v1/targets/${PROTECTED}/origin-bindings`, { headers: adminHeaders() });
      assert.equal(protectedList.status, 200, protectedList.text);
      assert.deepEqual(protectedList.json.items.map((row) => row.id), [created.json.id]);
      assert.equal(protectedList.json.count, 1);
      const originList = await request(baseUrl, 'GET', `/v1/targets/${ORIGIN}/origin-bindings`, { headers: adminHeaders() });
      assert.deepEqual(originList.json.items.map((row) => row.id), [created.json.id]);
      const unrelatedList = await request(baseUrl, 'GET', `/v1/targets/${FOREIGN}/origin-bindings`, { headers: adminHeaders(OTHER) });
      assert.equal(unrelatedList.status, 200, unrelatedList.text);
      assert.deepEqual(unrelatedList.json.items.map((row) => row.id), []);

      // Archive is audited, exactly once, and the archived row is no longer bindable-active.
      const archived = await request(baseUrl, 'POST', `/v1/origin-bindings/${created.json.id}/archive`, {
        headers: adminHeaders(),
        body: {},
      });
      assert.equal(archived.status, 200, archived.text);
      assert.equal(archived.json.status, 'archived');
      assert.equal(typeof archived.json.archived_at, 'string');
      const archivedAgain = await request(baseUrl, 'POST', `/v1/origin-bindings/${created.json.id}/archive`, {
        headers: adminHeaders(),
        body: {},
      });
      assert.equal(archivedAgain.status, 409);
      assert.equal(archivedAgain.json.error, 'already_archived');
      const readArchived = await request(baseUrl, 'GET', `/v1/origin-bindings/${created.json.id}`, { headers: adminHeaders() });
      assert.equal(readArchived.json.status, 'archived');
      assert.equal(readArchived.json.currently_authorized, false);
      assert.equal(store.auditLog.filter((row) => row.action === 'origin_binding.created').length, 1);
      assert.equal(store.auditLog.filter((row) => row.action === 'origin_binding.archived').length, 1);
      assert.equal((await request(baseUrl, 'POST', '/v1/origin-bindings/obind_missing/archive', {
        headers: adminHeaders(), body: {},
      })).status, 404);

      // Findings PATCH maps lifecycle errors to 400, never a false 200.
      store.findings.push({
        id: 'fnd_hist_api', tenant_id: TENANT, target_group_id: GROUP, target_id: PROTECTED,
        check_id: 'waf.fingerprint.safe', status: 'open', title: 'Edge gap', severity: 'high',
        created_at: T_OLD, updated_at: T_OLD,
      });
      const badPatch = await request(baseUrl, 'PATCH', '/v1/findings/fnd_hist_api', {
        headers: adminHeaders(),
        body: { status: 'bogus_lifecycle' },
      });
      assert.equal(badPatch.status, 400);
      assert.equal(badPatch.json.error, 'invalid_lifecycle');
      const goodPatch = await request(baseUrl, 'PATCH', '/v1/findings/fnd_hist_api', {
        headers: adminHeaders(),
        body: { status: 'resolved' },
      });
      assert.equal(goodPatch.status, 200, goodPatch.text);
      assert.equal(goodPatch.json.status, 'resolved');
      assert.equal(typeof goodPatch.json.closed_at, 'string');
      assert.equal((await request(baseUrl, 'PATCH', '/v1/findings/fnd_missing', {
        headers: adminHeaders(), body: { status: 'resolved' },
      })).status, 404);

      // A passive pending-scan GET dispatches nothing: no run, no audit, no state change.
      const scan = await request(baseUrl, 'POST', '/v1/validation-scans', {
        headers: adminHeaders(),
        body: {
          target_group_id: GROUP, target_id: PROTECTED,
          check_ids: ['dns.authoritative_response.safe'],
        },
      });
      assert.equal(scan.status, 201, scan.text);
      const scanBefore = {
        runs: store.testRuns.length,
        audit: store.auditLog.length,
        steps: JSON.stringify(scan.json.steps.map((step) => step.status)),
        status: scan.json.status,
      };
      const passiveScan = await request(baseUrl, 'GET', `/v1/validation-scans/${scan.json.id}`, { headers: adminHeaders() });
      assert.equal(passiveScan.status, 200, passiveScan.text);
      assert.deepEqual(JSON.stringify(passiveScan.json.steps.map((step) => step.status)), scanBefore.steps);
      assert.equal(passiveScan.json.status, scanBefore.status);
      const passiveActivity = await request(
        baseUrl,
        'GET',
        `/v1/validation-scans/${scan.json.id}/activity`,
        { headers: adminHeaders() },
      );
      assert.equal(passiveActivity.status, 200, passiveActivity.text);
      assert.equal(store.testRuns.length, scanBefore.runs, 'passive scan GET must not start child runs');
      assert.equal(store.auditLog.length, scanBefore.audit, 'passive scan GET must not audit');

      // Every authorized passive history GET was mutation-free on both stores.
      // Runs are compared to the post-scan-create snapshot: the scan POST itself
      // legitimately seeds child runs, and none of the history reads added more.
      assert.equal(store.testRuns.length, scanBefore.runs);
      assert.equal(store.targetObservations.length, passiveBefore.observations);
      assert.equal(store.targetObservationCurrents.length, passiveBefore.currents);
      // The audited deltas are exactly the authorized binding mutations, plus the
      // audited denial of the viewer's create attempt.
      const deniedAudits = store.auditLog
        .slice(passiveBefore.audit)
        .filter((row) => row.action === 'rbac.denied'
          && row.resource_type === 'origin_binding'
          && row.metadata?.permission === 'target_group:write');
      assert.equal(deniedAudits.length, 1, 'the denied viewer create is audited');
      const mutationAudits = store.auditLog
        .slice(passiveBefore.audit)
        .filter((row) => row.resource_type === 'origin_binding'
          && row.action.startsWith('origin_binding.'))
        .map((row) => row.action);
      assert.deepEqual(mutationAudits.sort(), ['origin_binding.archived', 'origin_binding.created']);
    } finally {
      await closeServer(server);
    }
  });

  it('fails closed with 503 on Postgres routes when the history service or a method is missing', async () => {
    const env = {
      ...process.env,
      ASTRANULL_PERSISTENCE_MODE: 'postgres',
      ASTRANULL_RATE_LIMIT_DISABLED: '1',
    };
    const runtimeConfig = loadRuntimeConfig(env);
    const partialServices = {
      targetGroups: { getTarget: async () => null },
      targetHistory: { listTargetObservations: async () => ({ items: [], count: 0 }) },
    };
    const server = createServer({ runtimeConfig, env, services: partialServices });
    server.listen(0);
    const baseUrl = `http://127.0.0.1:${server.address().port}`;
    try {
      const notWired = { error: 'postgres_route_not_wired' };
      const noService = createServer({
        runtimeConfig,
        env,
        services: { targetGroups: { getTarget: async () => null } },
      });
      noService.listen(0);
      const noServiceUrl = `http://127.0.0.1:${noService.address().port}`;
      try {
        for (const [url, method, body] of [
          ['/v1/targets/tgt_x/observations', 'GET', undefined],
          ['/v1/targets/tgt_x/origin-bindings', 'GET', undefined],
          ['/v1/origin-bindings', 'POST', { protected_target_id: 'a', origin_target_id: 'b' }],
          ['/v1/origin-bindings/obind_x', 'GET', undefined],
          ['/v1/origin-bindings/obind_x/archive', 'POST', {}],
        ]) {
          const res = await request(noServiceUrl, method, url, { headers: adminHeaders(), body });
          assert.deepEqual(res.json, notWired, `${method} ${url} without the service must fail closed`);
          assert.equal(res.status, 503, `${method} ${url} without the service must be 503`);
        }
      } finally {
        await closeServer(noService);
      }

      for (const [url, method, body] of [
        ['/v1/targets/tgt_x/origin-bindings', 'GET', undefined],
        ['/v1/origin-bindings', 'POST', { protected_target_id: 'a', origin_target_id: 'b' }],
        ['/v1/origin-bindings/obind_x', 'GET', undefined],
        ['/v1/origin-bindings/obind_x/archive', 'POST', {}],
      ]) {
        const res = await request(baseUrl, method, url, { headers: adminHeaders(), body });
        assert.deepEqual(res.json, notWired, `${method} ${url} with a partial service must fail closed`);
        assert.equal(res.status, 503, `${method} ${url} with a partial service must be 503`);
      }
      const partialList = await request(baseUrl, 'GET', '/v1/targets/tgt_x/observations', { headers: adminHeaders() });
      assert.equal(partialList.status, 503, 'missing getCurrentFamilyState must still fail the list route closed');
    } finally {
      await closeServer(server);
    }
  });

  it('serves the same history routes through the ephemeral Postgres app role with real RLS', { timeout: 180_000 }, async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env, { tryDocker: false });
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }
    await withEphemeralPostgres(async (ownerPool, { databaseName }) => {
      await withTenantContext(ownerPool, TENANT, async (client) => {
        await client.query(`INSERT INTO tenants (id, name) VALUES ($1, 'History API')`, [TENANT]);
        await client.query(
          `INSERT INTO environments (id, tenant_id, name) VALUES ('env_hist_api', $1, 'prod')`,
          [TENANT],
        );
        await client.query(
          `INSERT INTO target_groups (id, tenant_id, environment_id, name, ownership_status, validation_mode)
           VALUES ($1, $2, 'env_hist_api', 'History', 'dns_verified', 'external_only')`,
          [GROUP, TENANT],
        );
        await client.query(
          `INSERT INTO targets (id, tenant_id, target_group_id, kind, value, normalized_value, created_at, declaration_json)
           VALUES
             ($1, $2, $3, 'fqdn', 'app.example.test', 'app.example.test', $4::timestamptz, $5::jsonb),
             ($6, $2, $3, 'ip', '203.0.113.10', '203.0.113.10', $4::timestamptz, '{}'::jsonb),
             ($7, $2, $3, 'ip', '203.0.113.11', '203.0.113.11', $4::timestamptz, '{}'::jsonb)`,
          [PROTECTED, TENANT, GROUP, DECLARED, JSON.stringify(protectedDeclaration()), ORIGIN, ORIGIN_UNVERIFIED],
        );
        await client.query(
          `INSERT INTO target_verifications (
             id, tenant_id, target_id, state, source_kind, source_ref, transitioned_at, transitioned_by, audit_entry_id
           ) VALUES ('tv_hist_api_origin', $1, $2, 'dns_verified', 'dns_txt', '{}'::jsonb, $3::timestamptz, 'usr_admin', 'aud_seed')`,
          [TENANT, ORIGIN, DECLARED],
        );
      });
      await withTenantContext(ownerPool, OTHER, async (client) => {
        await client.query(`INSERT INTO tenants (id, name) VALUES ($1, 'Other')`, [OTHER]);
        await client.query(
          `INSERT INTO environments (id, tenant_id, name) VALUES ('env_hist_api_other', $1, 'prod')`,
          [OTHER],
        );
        await client.query(
          `INSERT INTO target_groups (id, tenant_id, environment_id, name, validation_mode)
           VALUES ($1, $2, 'env_hist_api_other', 'Foreign', 'external_only')`,
          [OTHER_GROUP, OTHER],
        );
        await client.query(
          `INSERT INTO targets (id, tenant_id, target_group_id, kind, value, normalized_value, created_at)
           VALUES ($1, $2, $3, 'fqdn', 'foreign.example.test', 'foreign.example.test', $4::timestamptz)`,
          [FOREIGN, OTHER, OTHER_GROUP, DECLARED],
        );
      });
      await withTenantContext(ownerPool, TENANT, async (client) => {
        await client.query(
          `INSERT INTO target_observations (
             id, tenant_id, target_id, target_group_id, family, check_id, source_kind,
             corpus_version, scenario_version, check_version, observed_at, source_completed_at,
             outcome, attempt_class, producer_kind, provenance_json, nonce, digest, created_at
           ) VALUES
             ('obs_hist_api_new', $1, $2, $3, 'waf', 'waf.fingerprint.safe', 'explicit_record',
              'corpus-1', 'scenario-1', 'check-1', $4::timestamptz, $4::timestamptz,
              'detected', 'successful', 'manual', $5::jsonb, 'nonce_hist_api_new', 'digest_hist_api_new', $4::timestamptz),
             ('obs_hist_api_mid', $1, $2, $3, 'waf', 'waf.fingerprint.safe', 'explicit_record',
              'corpus-1', 'scenario-1', 'check-1', $6::timestamptz, $6::timestamptz,
              'not_detected', 'successful', 'manual', $5::jsonb, 'nonce_hist_api_mid', 'digest_hist_api_mid', $6::timestamptz)`,
          [TENANT, PROTECTED, GROUP, T_NEW, JSON.stringify({ provider: 'cloudflare' }), T_MID],
        );
        await client.query(
          `INSERT INTO target_observation_current (
             tenant_id, target_id, family, successful_observation_id,
             successful_observed_at, successful_source_completed_at, updated_at
           ) VALUES ($1, $2, 'waf', 'obs_hist_api_new', $3::timestamptz, $3::timestamptz, $3::timestamptz)`,
          [TENANT, PROTECTED, T_NEW],
        );
      });

      await ensureHarnessAppRole(ownerPool);
      await ownerPool.query(
        `ALTER ROLE ${APP_ROLE_NAME} WITH LOGIN PASSWORD '${APP_ROLE_PASSWORD}' NOSUPERUSER NOBYPASSRLS`,
      );
      const url = new URL(databaseUrlWithDatabase(
        ownerPool.options.connectionString,
        databaseName,
      ).replace(/^postgresql:/i, 'postgres:'));
      url.username = APP_ROLE_NAME;
      url.password = APP_ROLE_PASSWORD;
      const appUrl = url.toString().replace(/^postgres:/i, 'postgresql:');
      const appPool = createPgPool({ ASTRANULL_DATABASE_URL: appUrl });
      const check = await appPool.query(
        'SELECT current_user AS role, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user',
      );
      assert.equal(check.rows[0].role, APP_ROLE_NAME);
      assert.equal(check.rows[0].rolsuper, false);
      assert.equal(check.rows[0].rolbypassrls, false);

      const env = {
        ...process.env,
        NODE_ENV: 'test',
        ASTRANULL_PERSISTENCE_MODE: 'postgres',
        ASTRANULL_DATABASE_URL: appUrl,
        ASTRANULL_RATE_LIMIT_DISABLED: '1',
      };
      delete env.ASTRANULL_NO_PERSIST;
      const runtime = await createPostgresRuntime(env, { createPool: () => appPool, closePool: async () => {} });
      const server = createServer({
        runtimeConfig: loadRuntimeConfig(env),
        env,
        services: runtime.services,
        runtimeHealth: runtime.health,
      });
      server.listen(0);
      const baseUrl = `http://127.0.0.1:${server.address().port}`;
      try {
        const listed = await request(baseUrl, 'GET', `/v1/targets/${PROTECTED}/observations`, { headers: adminHeaders() });
        assert.equal(listed.status, 200, listed.text);
        assert.deepEqual(listed.json.items.map((row) => row.id), ['obs_hist_api_new', 'obs_hist_api_mid']);
        assert.equal(listed.json.current.length, 1);
        assert.equal(listed.json.current[0].family, 'waf');
        assert.equal(listed.json.current[0].last_successful.id, 'obs_hist_api_new');
        assert.equal(listed.json.comparison.comparable_changes.length, 1);
        assert.equal(listed.json.comparison.comparable_changes[0].change, 'changed');
        assert.equal(listed.json.comparison.comparable_changes[0].direction, 'appeared');
        assert.equal(JSON.stringify(listed.json).includes('nonce_hist_api'), false, 'internal nonce columns are not projected');

        const viewerRead = await request(baseUrl, 'GET', `/v1/targets/${PROTECTED}/observations`, { headers: viewerHeaders() });
        assert.equal(viewerRead.status, 200, viewerRead.text);
        const otherRead = await request(
          baseUrl,
          'GET',
          `/v1/targets/${PROTECTED}/observations`,
          { headers: adminHeaders(OTHER) },
        );
        assert.equal(otherRead.status, 404);
        assert.equal((await request(baseUrl, 'GET', `/v1/targets/${FOREIGN}/observations`, { headers: adminHeaders() })).status, 404);

        const created = await request(baseUrl, 'POST', '/v1/origin-bindings', {
          headers: adminHeaders(),
          body: { protected_target_id: PROTECTED, origin_target_id: ORIGIN, scope: { port: 443, path: '/health' } },
        });
        assert.equal(created.status, 201, created.text);
        assert.equal(created.json.replayed, false);
        assert.equal(created.json.host, 'app.example.test');
        assert.equal(created.json.port, 443);
        assert.equal(created.json.currently_authorized, true);
        const replayed = await request(baseUrl, 'POST', '/v1/origin-bindings', {
          headers: adminHeaders(),
          body: { protected_target_id: PROTECTED, origin_target_id: ORIGIN, scope: { port: 443, path: '/health' } },
        });
        assert.equal(replayed.status, 200);
        assert.equal(replayed.json.replayed, true);
        assert.equal(replayed.json.id, created.json.id);
        assert.equal((await request(baseUrl, 'POST', '/v1/origin-bindings', {
          headers: adminHeaders(),
          body: {
            protected_target_id: PROTECTED, origin_target_id: ORIGIN_UNVERIFIED,
            scope: { port: 443, path: '/health' },
          },
        })).status, 409, 'the unverified origin IP must not bind');
        assert.equal((await request(baseUrl, 'POST', '/v1/origin-bindings', {
          headers: adminHeaders(),
          body: { protected_target_id: FOREIGN, origin_target_id: ORIGIN, scope: {} },
        })).status, 404, 'the foreign protected target must not bind');

        const readOne = await request(baseUrl, 'GET', `/v1/origin-bindings/${created.json.id}`, { headers: adminHeaders() });
        assert.equal(readOne.status, 200, readOne.text);
        assert.equal((await request(baseUrl, 'GET', `/v1/origin-bindings/${created.json.id}`, { headers: adminHeaders(OTHER) })).status, 404);
        const protectedList = await request(baseUrl, 'GET', `/v1/targets/${PROTECTED}/origin-bindings`, { headers: adminHeaders() });
        assert.deepEqual(protectedList.json.items.map((row) => row.id), [created.json.id]);

        const archived = await request(baseUrl, 'POST', `/v1/origin-bindings/${created.json.id}/archive`, {
          headers: adminHeaders(), body: {},
        });
        assert.equal(archived.status, 200, archived.text);
        assert.equal(archived.json.status, 'archived');
        assert.equal((await request(baseUrl, 'POST', `/v1/origin-bindings/${created.json.id}/archive`, {
          headers: adminHeaders(), body: {},
        })).status, 409);

        const audits = await ownerPool.query(
          `SELECT action, count(*)::int AS n FROM audit_logs WHERE tenant_id = $1 AND action LIKE 'origin_binding.%' GROUP BY action`,
          [TENANT],
        );
        const byAction = Object.fromEntries(audits.rows.map((row) => [row.action, row.n]));
        assert.equal(byAction['origin_binding.created'], 1, 'created is audited exactly once on replay');
        assert.equal(byAction['origin_binding.archived'], 1, 'archive is audited exactly once');

        const passiveBefore = await ownerPool.query(
          `SELECT
             (SELECT count(*)::int FROM target_observations) AS observations,
             (SELECT count(*)::int FROM origin_bindings) AS bindings,
             (SELECT count(*)::int FROM finding_retest_lineage) AS lineage`,
        );
        const passive = await request(baseUrl, 'GET', `/v1/targets/${PROTECTED}/observations?limit=1`, { headers: adminHeaders() });
        assert.equal(passive.status, 200, passive.text);
        const passiveAfter = await ownerPool.query(
          `SELECT
             (SELECT count(*)::int FROM target_observations) AS observations,
             (SELECT count(*)::int FROM origin_bindings) AS bindings,
             (SELECT count(*)::int FROM finding_retest_lineage) AS lineage`,
        );
        assert.deepEqual(passiveAfter.rows[0], passiveBefore.rows[0], 'passive history GETs write nothing');
      } finally {
        await closeServer(server);
        await runtime.close();
        await closePgPool(appPool);
      }
    }, availability.env);
  });
});
